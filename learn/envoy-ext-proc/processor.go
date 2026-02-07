// Package main contains the ext-proc implementation.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// HeaderProcessor implements the Envoy External Processor service.
type HeaderProcessor struct {
	extproc.UnimplementedExternalProcessorServer
	logger *slog.Logger
	// TODO: Add any fields you need (e.g., logger, config)
}

func NewHeaderProcessor(logger *slog.Logger) *HeaderProcessor {
	return &HeaderProcessor{
		logger: logger,
	}
}

// Process handles the bidirectional stream from Envoy.
//
// This is the main method of ext-proc. Envoy sends ProcessingRequest messages
// and expects ProcessingResponse messages back.
//
// The stream stays open for the duration of a single HTTP request/response.
func (p *HeaderProcessor) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil // Stream closed normally
		}
		if err != nil {
			return err // Stream error
		}
		switch v := req.Request.(type) {
		case *extproc.ProcessingRequest_RequestHeaders:
			resp := p.handleRequestHeaders(v.RequestHeaders)
			if err := stream.Send(resp); err != nil {
				return err
			}
			p.logger.Info("request headers processed", "headers", v.RequestHeaders)
		default:
			return fmt.Errorf("unsupported request type: %T", v)
		}
	}
}

// Steps:
// 1. Log the headers for debugging
// 2. Look for the Authorization header
// 3. Build a response that adds X-Processed-By header
// 4. Optionally modify the Authorization header
func (p *HeaderProcessor) handleRequestHeaders(headers *extproc.HttpHeaders) *extproc.ProcessingResponse {
	for _, h := range headers.Headers.Headers {
		p.logger.Info("received header", "key", h.Key, "value", string(h.RawValue))
	}

	var authHeader string
	for _, h := range headers.Headers.Headers {
		if h.Key == "authorization" {
			authHeader = string(h.RawValue)
			break
		}
	}
	if authHeader != "" {
		p.logger.Info("found authorization header", "value", authHeader[:min(50, len(authHeader))]+"...")
	}

	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extproc.HeadersResponse{
				Response: &extproc.CommonResponse{
					HeaderMutation: &extproc.HeaderMutation{
						SetHeaders: []*corev3.HeaderValueOption{
							{
								Header: &corev3.HeaderValue{
									Key:      "x-processed-by",
									RawValue: []byte("ext-proc-learning"),
								},
							},
						},
					},
				},
			},
		},
	}
}

// findHeader looks for a header by name (case-insensitive).
// Returns the value and true if found, empty string and false if not.
func findHeader(headers *extproc.HttpHeaders, name string) (string, bool) {
	for _, h := range headers.Headers.Headers {
		if strings.EqualFold(h.Key, name) {
			return string(h.RawValue), true
		}
	}
	return "", false
}
