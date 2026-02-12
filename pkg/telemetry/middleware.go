package telemetry

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// WrapHandler wraps an http.Handler with OpenTelemetry instrumentation.
func WrapHandler(handler http.Handler, serverName string) http.Handler {
	return otelhttp.NewHandler(handler, serverName)
}

// WrapTransport wraps an http.RoundTripper with OpenTelemetry instrumentation
// so that outbound HTTP requests propagate trace context.
func WrapTransport(transport http.RoundTripper) http.RoundTripper {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return otelhttp.NewTransport(transport)
}
