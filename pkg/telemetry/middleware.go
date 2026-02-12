package telemetry

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// WrapHandler wraps an http.Handler with OpenTelemetry instrumentation.
// Health and readiness endpoints are excluded from tracing to reduce noise.
func WrapHandler(handler http.Handler, serverName string) http.Handler {
	return otelhttp.NewHandler(handler, serverName,
		otelhttp.WithFilter(func(r *http.Request) bool {
			switch r.URL.Path {
			case "/health", "/ready", "/healthz", "/readyz", "/metrics":
				return false
			}
			return true
		}),
	)
}

// WrapTransport wraps an http.RoundTripper with OpenTelemetry instrumentation
// so that outbound HTTP requests propagate trace context.
func WrapTransport(transport http.RoundTripper) http.RoundTripper {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return otelhttp.NewTransport(transport)
}
