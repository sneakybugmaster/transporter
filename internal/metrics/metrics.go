// Package metrics holds the coordinator's Prometheus metrics. They are
// served on a separate listener (--metrics-listen), never on the public port.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry holds every metric below plus Go runtime and process metrics.
var Registry = prometheus.NewRegistry()

var (
	// Control plane.
	Registrations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "transporter_registrations_total",
		Help: "Node registrations by result (ok, invalid_key, exhausted, error).",
	}, []string{"result"})
	ControlStreams = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "transporter_control_streams",
		Help: "Open netmap streams.",
	})
	NetmapsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "transporter_netmaps_sent_total",
		Help: "Netmaps sent to nodes (keepalives excluded).",
	})
	NetmapBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "transporter_netmap_bytes_total",
		Help: "Encoded size of the netmaps sent.",
	})
	SnapshotBuild = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "transporter_snapshot_build_seconds",
		Help:    "Time to rebuild the shared mesh snapshot netmaps are cut from.",
		Buckets: prometheus.ExponentialBuckets(0.0005, 2, 14),
	})

	// HTTP.
	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "transporter_http_requests_total",
		Help: "HTTP requests by area (api, control, relay, ui) and status class.",
	}, []string{"area", "code"})
)

func init() {
	Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		Registrations, ControlStreams, NetmapsSent, NetmapBytes, SnapshotBuild,
		HTTPRequests,
	)
}

// Gauge registers a gauge computed at scrape time, e.g. node counts.
func Gauge(name, help string, f func() float64) {
	Registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, f))
}

// Counter registers a counter read at scrape time from a monotonic source.
func Counter(name, help string, f func() float64) {
	Registry.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help}, f))
}

// Handler serves the metrics in the Prometheus text format.
func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{})
}
