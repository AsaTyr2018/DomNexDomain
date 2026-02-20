package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Collector struct {
	Requests *prometheus.CounterVec
	Failures *prometheus.CounterVec
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
	}
	prometheus.MustRegister(c.Requests, c.Failures)
	return c
}

func Handler() http.Handler {
	return promhttp.Handler()
}
