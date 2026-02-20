package traffic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/logx"
)

type Sink interface {
	UpsertHostTrafficMinute(ctx context.Context, hostID int64, fqdn, country, bucketStart string, requests, bytesIn, bytesOut, blocked, status2xx, status3xx, status4xx, status5xx int64) error
	UpsertHostTrafficClassMinute(ctx context.Context, hostID int64, fqdn, country, class, bucketStart string, requests, bytesIn, bytesOut, blocked, status2xx, status3xx, status4xx, status5xx int64) error
	UpsertHostVisitorDaily(ctx context.Context, hostID int64, day, ipHash string) error
}

type Event struct {
	HostID    int64
	FQDN      string
	Country   string
	UserAgent string
	ClientIP  string
	Status    int
	BytesIn   int64
	BytesOut  int64
	Blocked   bool
	Timestamp time.Time
}

type Recorder struct {
	sink Sink
	log  *logx.Logger
	ch   chan Event
}

type trafficAgg struct {
	hostID      int64
	fqdn        string
	country     string
	bucketStart string
	requests    int64
	bytesIn     int64
	bytesOut    int64
	blocked     int64
	status2xx   int64
	status3xx   int64
	status4xx   int64
	status5xx   int64
}

type trafficClassAgg struct {
	hostID      int64
	fqdn        string
	country     string
	class       string
	bucketStart string
	requests    int64
	bytesIn     int64
	bytesOut    int64
	blocked     int64
	status2xx   int64
	status3xx   int64
	status4xx   int64
	status5xx   int64
}

func NewRecorder(sink Sink, log *logx.Logger) *Recorder {
	return &Recorder{
		sink: sink,
		log:  log,
		ch:   make(chan Event, 8192),
	}
}

func (r *Recorder) Record(ev Event) {
	if ev.HostID <= 0 || strings.TrimSpace(ev.FQDN) == "" {
		return
	}
	ev.FQDN = strings.ToLower(strings.TrimSpace(ev.FQDN))
	ev.Country = strings.ToUpper(strings.TrimSpace(ev.Country))
	if ev.Country == "" {
		ev.Country = "ZZ"
	}
	// Local/LAN-origin traffic is intentionally excluded from persisted traffic stats.
	if ev.Country == "LOCAL" {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	select {
	case r.ch <- ev:
	default:
		if r.log != nil {
			r.log.Warn("traffic recorder channel full, dropping event", map[string]any{"fqdn": ev.FQDN})
		}
	}
}

func (r *Recorder) Start(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	trafficMap := map[string]*trafficAgg{}
	classMap := map[string]*trafficClassAgg{}
	visitors := map[string]struct{}{}

	flush := func() {
		if len(trafficMap) == 0 && len(classMap) == 0 && len(visitors) == 0 {
			return
		}
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		for _, ag := range trafficMap {
			err := r.sink.UpsertHostTrafficMinute(writeCtx, ag.hostID, ag.fqdn, ag.country, ag.bucketStart, ag.requests, ag.bytesIn, ag.bytesOut, ag.blocked, ag.status2xx, ag.status3xx, ag.status4xx, ag.status5xx)
			if err != nil && r.log != nil {
				r.log.Warn("traffic flush failed", map[string]any{"fqdn": ag.fqdn, "err": err.Error()})
			}
		}
		for _, ag := range classMap {
			err := r.sink.UpsertHostTrafficClassMinute(writeCtx, ag.hostID, ag.fqdn, ag.country, ag.class, ag.bucketStart, ag.requests, ag.bytesIn, ag.bytesOut, ag.blocked, ag.status2xx, ag.status3xx, ag.status4xx, ag.status5xx)
			if err != nil && r.log != nil {
				r.log.Warn("traffic class flush failed", map[string]any{"fqdn": ag.fqdn, "class": ag.class, "err": err.Error()})
			}
		}
		for key := range visitors {
			parts := strings.SplitN(key, "|", 3)
			if len(parts) != 3 {
				continue
			}
			hostID, day, ipHash := parts[0], parts[1], parts[2]
			_ = hostID
			// Parse host ID without bringing strconv into hot path map key creation.
			var id int64
			for _, ch := range hostID {
				if ch < '0' || ch > '9' {
					id = 0
					break
				}
				id = id*10 + int64(ch-'0')
			}
			if id <= 0 {
				continue
			}
			err := r.sink.UpsertHostVisitorDaily(writeCtx, id, day, ipHash)
			if err != nil && r.log != nil {
				r.log.Warn("visitor flush failed", map[string]any{"hostID": id, "err": err.Error()})
			}
		}
		trafficMap = map[string]*trafficAgg{}
		classMap = map[string]*trafficClassAgg{}
		visitors = map[string]struct{}{}
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-ticker.C:
			flush()
		case ev := <-r.ch:
			bucket := ev.Timestamp.UTC().Truncate(time.Minute).Format(time.RFC3339)
			key := strings.Join([]string{itoa(ev.HostID), ev.FQDN, ev.Country, bucket}, "|")
			ag, ok := trafficMap[key]
			if !ok {
				ag = &trafficAgg{
					hostID:      ev.HostID,
					fqdn:        ev.FQDN,
					country:     ev.Country,
					bucketStart: bucket,
				}
				trafficMap[key] = ag
			}
			ag.requests++
			ag.bytesIn += max64(0, ev.BytesIn)
			ag.bytesOut += max64(0, ev.BytesOut)
			if ev.Blocked {
				ag.blocked++
			}
			switch {
			case ev.Status >= 200 && ev.Status < 300:
				ag.status2xx++
			case ev.Status >= 300 && ev.Status < 400:
				ag.status3xx++
			case ev.Status >= 400 && ev.Status < 500:
				ag.status4xx++
			case ev.Status >= 500:
				ag.status5xx++
			}
			class := classifyTrafficClass(ev.UserAgent)
			classKey := strings.Join([]string{itoa(ev.HostID), ev.FQDN, ev.Country, class, bucket}, "|")
			cag, ok := classMap[classKey]
			if !ok {
				cag = &trafficClassAgg{
					hostID:      ev.HostID,
					fqdn:        ev.FQDN,
					country:     ev.Country,
					class:       class,
					bucketStart: bucket,
				}
				classMap[classKey] = cag
			}
			cag.requests++
			cag.bytesIn += max64(0, ev.BytesIn)
			cag.bytesOut += max64(0, ev.BytesOut)
			if ev.Blocked {
				cag.blocked++
			}
			switch {
			case ev.Status >= 200 && ev.Status < 300:
				cag.status2xx++
			case ev.Status >= 300 && ev.Status < 400:
				cag.status3xx++
			case ev.Status >= 400 && ev.Status < 500:
				cag.status4xx++
			case ev.Status >= 500:
				cag.status5xx++
			}
			if ipHash := hashIP(ev.ClientIP); ipHash != "" {
				day := ev.Timestamp.UTC().Format("2006-01-02")
				visitors[itoa(ev.HostID)+"|"+day+"|"+ipHash] = struct{}{}
			}
		}
	}
}

func classifyTrafficClass(userAgent string) string {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	if ua == "" {
		return "unknown"
	}
	botHints := []string{
		"bot", "crawler", "spider", "slurp", "mediapartners-google",
		"googlebot", "bingbot", "duckduckbot", "yandexbot", "baiduspider",
		"semrush", "ahrefs", "mj12bot", "dotbot", "petalbot", "facebookexternalhit",
		"curl/", "wget/", "python-requests", "go-http-client",
	}
	for _, hint := range botHints {
		if strings.Contains(ua, hint) {
			return "crawler"
		}
	}
	return "human"
}

func hashIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + (v % 10))
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
