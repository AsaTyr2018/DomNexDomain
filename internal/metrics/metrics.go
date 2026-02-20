package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Collector struct {
	Requests      *prometheus.CounterVec
	Failures      *prometheus.CounterVec
	ProxyRequests *prometheus.CounterVec
	GeoBlocks     *prometheus.CounterVec
}

func New() *Collector {
	c := &Collector{
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "domnex_requests_total",
			Help: "Total HTTP requests by component and status.",
		}, []string{"component", "status"}),
		Failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "domnex_failures_total",
			Help: "Failures by subsystem.",
		}, []string{"subsystem"}),
		ProxyRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "domnex_proxy_requests_total",
			Help: "Reverse proxy HTTP requests per host and status code.",
		}, []string{"fqdn", "status"}),
		GeoBlocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "domnex_geo_blocks_total",
			Help: "Blocked requests by host, country, and policy mode.",
		}, []string{"fqdn", "country", "mode"}),
	}
	prometheus.MustRegister(c.Requests, c.Failures, c.ProxyRequests, c.GeoBlocks)
	return c
}

func Handler() http.Handler {
	return promhttp.Handler()
}
