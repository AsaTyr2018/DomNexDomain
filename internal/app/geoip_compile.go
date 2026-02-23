package app

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/model"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

var geoCompileMu sync.Mutex

func (s *Service) geoIPCompiledDir() string {
	return filepath.Join(s.cfg.DataDir, "geoip-compiled")
}

func (s *Service) geoIPCompiledMMDBPath() string {
	return filepath.Join(s.geoIPCompiledDir(), "domnex-country.mmdb")
}

func (s *Service) geoIPCompiledFingerprintPath() string {
	return filepath.Join(s.geoIPCompiledDir(), "sources.sha256")
}

func (s *Service) geoIPSourcePaths(ctx context.Context) ([]string, string, error) {
	items, err := s.ListGeoIPSources(ctx)
	if err != nil {
		return nil, "", err
	}
	paths := make([]string, 0, len(items))
	fpParts := make([]string, 0, len(items))
	base := s.geoIPSourcesDir()
	for _, it := range items {
		paths = append(paths, filepath.Join(base, it.Name))
		fpParts = append(fpParts, fmt.Sprintf("%s|%d|%d", it.Name, it.Size, it.ModTime.UnixNano()))
	}
	sort.Strings(paths)
	sort.Strings(fpParts)
	sum := sha256.Sum256([]byte(strings.Join(fpParts, "\n")))
	return paths, hex.EncodeToString(sum[:]), nil
}

func (s *Service) CompileGeoIPSources(ctx context.Context, force bool) (bool, error) {
	geoCompileMu.Lock()
	defer geoCompileMu.Unlock()

	paths, fp, err := s.geoIPSourcePaths(ctx)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(s.geoIPCompiledDir(), 0o750); err != nil {
		return false, err
	}
	if !force {
		if b, err := os.ReadFile(s.geoIPCompiledFingerprintPath()); err == nil && strings.TrimSpace(string(b)) == fp {
			return false, nil
		}
	}
	if len(paths) == 0 {
		_ = os.Remove(s.geoIPCompiledMMDBPath())
		_ = os.WriteFile(s.geoIPCompiledFingerprintPath(), []byte(fp+"\n"), 0o640)
		return true, nil
	}

	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-Country",
		Description:  map[string]string{"en": "DomNex compiled GeoIP country database"},
		IPVersion:    6,
		RecordSize:   28,
	})
	if err != nil {
		return false, err
	}
	added := 0
	for _, p := range paths {
		ext := strings.ToLower(filepath.Ext(p))
		switch ext {
		case ".mmdb":
			n, e := compileFromMMDB(p, tree)
			if e != nil {
				s.log.Warn("geoip compile source mmdb failed", map[string]any{"path": p, "err": e.Error()})
				continue
			}
			added += n
		case ".csv":
			n, e := compileFromCSV(p, tree)
			if e != nil {
				s.log.Warn("geoip compile source csv failed", map[string]any{"path": p, "err": e.Error()})
				continue
			}
			added += n
		}
	}

	tmp := s.geoIPCompiledMMDBPath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return false, err
	}
	if _, err := tree.WriteTo(f); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return false, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, s.geoIPCompiledMMDBPath()); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.WriteFile(s.geoIPCompiledFingerprintPath(), []byte(fp+"\n"), 0o640); err != nil {
		return false, err
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "geoip.compile.success", Target: "geoip", Meta: fmt.Sprintf("sources=%d;records=%d", len(paths), added)})
	return true, nil
}

func (s *Service) StartGeoIPCompiler(ctx context.Context) {
	run := func(force bool) {
		changed, err := s.CompileGeoIPSources(ctx, force)
		if err != nil {
			s.log.Warn("geoip compile failed", map[string]any{"err": err.Error()})
			return
		}
		if changed {
			s.log.Info("geoip compiled source updated", map[string]any{"path": s.geoIPCompiledMMDBPath()})
		}
	}
	run(false)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	lastNight := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			day := time.Now().UTC().Format("2006-01-02")
			force := false
			if day != lastNight && time.Now().UTC().Hour() == 2 {
				lastNight = day
				force = true
			}
			run(force)
		}
	}
}

func compileFromMMDB(path string, tree *mmdbwriter.Tree) (int, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	iter := db.Networks(maxminddb.SkipAliasedNetworks)
	added := 0
	for iter.Next() {
		var payload struct {
			Country struct {
				ISOCode     string `maxminddb:"iso_code"`
				CountryCode string `maxminddb:"country_code"`
			} `maxminddb:"country"`
			RegisteredCountry struct {
				ISOCode     string `maxminddb:"iso_code"`
				CountryCode string `maxminddb:"country_code"`
			} `maxminddb:"registered_country"`
			CountryCode string `maxminddb:"country_code"`
		}
		network, err := iter.Network(&payload)
		if err != nil || network == nil {
			continue
		}
		code := normalizeCountry(payload.Country.ISOCode)
		if code == "" {
			code = normalizeCountry(payload.Country.CountryCode)
		}
		if code == "" {
			code = normalizeCountry(payload.RegisteredCountry.ISOCode)
		}
		if code == "" {
			code = normalizeCountry(payload.RegisteredCountry.CountryCode)
		}
		if code == "" {
			code = normalizeCountry(payload.CountryCode)
		}
		if code == "" {
			continue
		}
		if err := tree.Insert(network, countryRecord(code)); err == nil {
			added++
		}
	}
	return added, iter.Err()
}

func compileFromCSV(path string, tree *mmdbwriter.Tree) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	added := 0
	headerSeen := false
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return added, err
		}
		if len(rec) == 0 {
			continue
		}
		for i := range rec {
			rec[i] = strings.TrimSpace(rec[i])
		}
		if !headerSeen {
			headerSeen = true
			joined := strings.ToLower(strings.Join(rec, ","))
			if strings.Contains(joined, "country") && (strings.Contains(joined, "cidr") || strings.Contains(joined, "start")) {
				continue
			}
		}
		if len(rec) >= 2 && strings.Contains(rec[0], "/") {
			code := normalizeCountry(rec[1])
			if code == "" {
				continue
			}
			_, n, err := net.ParseCIDR(rec[0])
			if err != nil || n == nil {
				continue
			}
			if err := tree.Insert(n, countryRecord(code)); err == nil {
				added++
			}
			continue
		}
		if len(rec) >= 3 {
			start := net.ParseIP(rec[0])
			end := net.ParseIP(rec[1])
			code := normalizeCountry(rec[2])
			if start == nil || end == nil || code == "" {
				continue
			}
			if err := tree.InsertRange(start, end, countryRecord(code)); err == nil {
				added++
			}
		}
	}
	return added, nil
}

func normalizeCountry(raw string) string {
	cc := strings.ToUpper(strings.TrimSpace(raw))
	if len(cc) != 2 || cc == "XX" || cc == "T1" {
		return ""
	}
	return cc
}

func countryRecord(code string) mmdbtype.DataType {
	return mmdbtype.Map{
		mmdbtype.String("country"): mmdbtype.Map{
			mmdbtype.String("iso_code"): mmdbtype.String(code),
		},
	}
}
