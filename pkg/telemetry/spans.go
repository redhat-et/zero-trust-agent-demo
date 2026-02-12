package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/redhat-et/zero-trust-agent-demo"

// Span attribute keys for the zero-trust demo domain.
var (
	AttrUserID         = attribute.Key("ztdemo.user.id")
	AttrAgentID        = attribute.Key("ztdemo.agent.id")
	AttrDocumentID     = attribute.Key("ztdemo.document.id")
	AttrUserSPIFFEID   = attribute.Key("ztdemo.user.spiffe_id")
	AttrAgentSPIFFEID  = attribute.Key("ztdemo.agent.spiffe_id")
	AttrCallerSPIFFEID = attribute.Key("ztdemo.caller.spiffe_id")
	AttrDecision       = attribute.Key("ztdemo.decision")
	AttrReason         = attribute.Key("ztdemo.reason")
	AttrCallerType     = attribute.Key("ztdemo.caller.type")
	AttrJWTIssuer      = attribute.Key("ztdemo.jwt.issuer")
	AttrJWTAudience    = attribute.Key("ztdemo.jwt.audience")
	AttrJWTGroups      = attribute.Key("ztdemo.jwt.groups")
	AttrAccessGranted  = attribute.Key("ztdemo.access.granted")
)

// Tracer returns the project-wide OTel tracer.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// StartSpan creates a new span with the given name and optional attributes.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	ctx, span := Tracer().Start(ctx, name)
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
	return ctx, span
}

// SetSpanError records an error on the span and sets its status to Error.
func SetSpanError(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// SetSpanOK sets the span status to OK.
func SetSpanOK(span trace.Span) {
	span.SetStatus(codes.Ok, "")
}
