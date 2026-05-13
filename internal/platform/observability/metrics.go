package observability

import (
	"expvar"
	"net/http"
	"sync/atomic"
	"time"
)

type HTTPMetrics struct {
	requests  atomic.Uint64
	errors    atomic.Uint64
	latencyMS atomic.Uint64
}

func NewHTTPMetrics() *HTTPMetrics {
	m := &HTTPMetrics{}
	expvar.Publish("oauth_http_requests_total", expvar.Func(func() any { return m.requests.Load() }))
	expvar.Publish("oauth_http_errors_total", expvar.Func(func() any { return m.errors.Load() }))
	expvar.Publish("oauth_http_latency_ms_total", expvar.Func(func() any { return m.latencyMS.Load() }))
	return m
}

func (m *HTTPMetrics) Observe(status int, dur time.Duration) {
	m.requests.Add(1)
	m.latencyMS.Add(uint64(dur.Milliseconds()))
	if status >= http.StatusBadRequest {
		m.errors.Add(1)
	}
}
