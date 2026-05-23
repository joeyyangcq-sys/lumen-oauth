package observability

import (
	"expvar"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type HTTPMetrics struct {
	requests  atomic.Uint64
	errors    atomic.Uint64
	latencyMS atomic.Uint64

	mu     sync.RWMutex
	routes map[string]*routeMetrics
}

type HTTPRouteMetrics struct {
	Method         string `json:"method"`
	Route          string `json:"route"`
	StatusClass    string `json:"status_class"`
	Requests       uint64 `json:"requests"`
	Errors         uint64 `json:"errors"`
	LatencyMSTotal uint64 `json:"latency_ms_total"`
}

type routeMetrics struct {
	method      string
	route       string
	statusClass string
	requests    atomic.Uint64
	errors      atomic.Uint64
	latencyMS   atomic.Uint64
}

func NewHTTPMetrics() *HTTPMetrics {
	m := &HTTPMetrics{routes: make(map[string]*routeMetrics)}
	currentHTTPMetrics.Store(m)
	publishHTTPMetricsOnce.Do(func() {
		expvar.Publish("oauth_http_requests_total", expvar.Func(func() any {
			return currentMetrics().requests.Load()
		}))
		expvar.Publish("oauth_http_errors_total", expvar.Func(func() any {
			return currentMetrics().errors.Load()
		}))
		expvar.Publish("oauth_http_latency_ms_total", expvar.Func(func() any {
			return currentMetrics().latencyMS.Load()
		}))
		expvar.Publish("oauth_http_routes", expvar.Func(func() any {
			return currentMetrics().RouteSnapshot()
		}))
	})
	return m
}

var (
	publishHTTPMetricsOnce sync.Once
	currentHTTPMetrics     atomic.Pointer[HTTPMetrics]
)

func currentMetrics() *HTTPMetrics {
	if m := currentHTTPMetrics.Load(); m != nil {
		return m
	}
	return &HTTPMetrics{routes: make(map[string]*routeMetrics)}
}

func (m *HTTPMetrics) Observe(method, route string, status int, dur time.Duration) {
	m.requests.Add(1)
	m.latencyMS.Add(uint64(dur.Milliseconds()))
	statusClass := statusClass(status)
	if status >= http.StatusBadRequest {
		m.errors.Add(1)
	}
	routeMetric := m.routeMetric(method, route, statusClass)
	routeMetric.requests.Add(1)
	routeMetric.latencyMS.Add(uint64(dur.Milliseconds()))
	if status >= http.StatusBadRequest {
		routeMetric.errors.Add(1)
	}
}

func (m *HTTPMetrics) RouteSnapshot() []HTTPRouteMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.routes))
	for key := range m.routes {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]HTTPRouteMetrics, 0, len(keys))
	for _, key := range keys {
		rm := m.routes[key]
		out = append(out, HTTPRouteMetrics{
			Method:         rm.method,
			Route:          rm.route,
			StatusClass:    rm.statusClass,
			Requests:       rm.requests.Load(),
			Errors:         rm.errors.Load(),
			LatencyMSTotal: rm.latencyMS.Load(),
		})
	}
	return out
}

func (m *HTTPMetrics) routeMetric(method, route, statusClass string) *routeMetrics {
	key := fmt.Sprintf("%s %s %s", method, route, statusClass)
	m.mu.RLock()
	rm := m.routes[key]
	m.mu.RUnlock()
	if rm != nil {
		return rm
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if rm = m.routes[key]; rm != nil {
		return rm
	}
	rm = &routeMetrics{method: method, route: route, statusClass: statusClass}
	m.routes[key] = rm
	return rm
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	case status >= 100:
		return "1xx"
	default:
		return "unknown"
	}
}
