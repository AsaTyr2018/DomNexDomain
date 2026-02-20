package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Provider interface {
	UpsertARecord(ctx context.Context, zoneID, name, ip string, proxied bool) error
}

type Cloudflare struct {
	client *http.Client
	token  string
}

func NewCloudflare(token string) *Cloudflare {
	return &Cloudflare{
		client: &http.Client{Timeout: 15 * time.Second},
		token:  token,
	}
}

func (c *Cloudflare) UpsertARecord(ctx context.Context, zoneID, name, ip string, proxied bool) error {
	if c.token == "" || zoneID == "" {
		return fmt.Errorf("cloudflare not configured")
	}
	rec, err := c.lookupARecord(ctx, zoneID, name)
	if err != nil {
		return err
	}
	if rec != nil && rec.Content == ip && rec.Proxied == proxied {
		return nil
	}
	payload := map[string]any{"type": "A", "name": name, "content": ip, "ttl": 120, "proxied": proxied}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	method := http.MethodPost
	if rec != nil {
		method = http.MethodPut
		endpoint = endpoint + "/" + rec.ID
	}
	req, _ := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("cloudflare status=%d", resp.StatusCode)
	}
	return nil
}

type cfRecord struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

type cfLookupResp struct {
	Success bool       `json:"success"`
	Result  []cfRecord `json:"result"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfZoneLookupResp struct {
	Success bool     `json:"success"`
	Result  []cfZone `json:"result"`
}

func (c *Cloudflare) lookupARecord(ctx context.Context, zoneID, name string) (*cfRecord, error) {
	q := url.Values{}
	q.Set("type", "A")
	q.Set("name", name)
	endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?%s", zoneID, q.Encode())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("cloudflare lookup status=%d", resp.StatusCode)
	}
	var out cfLookupResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Result) == 0 {
		return nil, nil
	}
	return &out.Result[0], nil
}

func (c *Cloudflare) HasRecord(ctx context.Context, zoneID, name string) (bool, error) {
	q := url.Values{}
	q.Set("name", name)
	endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?%s", zoneID, q.Encode())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false, fmt.Errorf("cloudflare lookup status=%d", resp.StatusCode)
	}
	var out cfLookupResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return len(out.Result) > 0, nil
}

func (c *Cloudflare) CheckZoneAccess(ctx context.Context, zoneID string) error {
	endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s", zoneID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("cloudflare zone access status=%d", resp.StatusCode)
	}
	return nil
}

func (c *Cloudflare) ResolveZoneIDByName(ctx context.Context, zoneName string) (string, error) {
	if c.token == "" {
		return "", fmt.Errorf("cloudflare not configured")
	}
	q := url.Values{}
	q.Set("name", zoneName)
	q.Set("match", "all")
	endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?%s", q.Encode())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("cloudflare zone lookup status=%d", resp.StatusCode)
	}
	var out cfZoneLookupResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Result) == 0 {
		return "", fmt.Errorf("cloudflare zone not found for %s", zoneName)
	}
	return out.Result[0].ID, nil
}
