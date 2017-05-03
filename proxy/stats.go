//
// stats.go
// Copyright (C) 2017 Karol Będkowski
//

package proxy
	
import "github.com/prometheus/client_golang/prometheus"

var (
	metricsLabels = []string{"method", "code", "code_group", "endpoint", "port"}

	metricsOpts = prometheus.SummaryOpts{
		Subsystem: "proxy",
		Namespace: "secproxy",
	}

	metricReqCnt = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   metricsOpts.Namespace,
			Subsystem:   metricsOpts.Subsystem,
			Name:        "requests_total",
			Help:        "Total number of HTTP requests made per url.",
			ConstLabels: metricsOpts.ConstLabels,
		},
		metricsLabels,
	)

	metricReqDur = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace:   metricsOpts.Namespace,
			Subsystem:   metricsOpts.Subsystem,
			Name:        "request_duration_seconds",
			Help:        "The HTTP request latencies in seconds.",
			ConstLabels: metricsOpts.ConstLabels,
		},
		metricsLabels,
	)
)

func init() {
	prometheus.MustRegister(metricReqCnt)
	prometheus.MustRegister(metricReqDur)
}

