// Package main contains the ext-proc implementation.
package main

import (
	"io"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// Ensure these imports are used (remove when you use them)
var (
	_ = io.EOF
	_ = slog.Info
	_ = corev3.HeaderValue{}
)

// TODO: Task 2 - Create HeaderProcessor struct
//
// The struct should embed UnimplementedExternalProcessorServer to satisfy
// the interface with default implementations for methods you don't override.
//
// type HeaderProcessor struct {
//     extproc.UnimplementedExternalProcessorServer
// }

// HeaderProcessor implements the Envoy External Processor service.
type HeaderProcessor struct {
	extproc.UnimplementedExternalProcessorServer
	// TODO: Add any fields you need (e.g., logger, config)
}

// Process handles the bidirectional stream from Envoy.
//
// This is the main method of ext-proc. Envoy sends ProcessingRequest messages
// and expects ProcessingResponse messages back.
//
// The stream stays open for the duration of a single HTTP request/response.
func (p *HeaderProcessor) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	// TODO: Task 2 - Implement the processing loop
	//
	// Basic structure:
	//
	// for {
	//     req, err := stream.Recv()
	//     if err == io.EOF {
	//         return nil  // Stream closed normally
	//     }
	//     if err != nil {
	//         return err  // Stream error
	//     }
	//
	//     // Handle the request based on its type
	//     switch v := req.Request.(type) {
	//     case *extproc.ProcessingRequest_RequestHeaders:
	//         // Handle request headers
	//         resp := p.handleRequestHeaders(v.RequestHeaders)
	//         if err := stream.Send(resp); err != nil {
	//             return err
	//         }
	//     }
	// }

	slog.Info("Process called - implement me!")
	return nil
}

// handleRequestHeaders processes incoming request headers.
//
// TODO: Task 3 - Implement header mutation
//
// Steps:
// 1. Log the headers for debugging
// 2. Look for the Authorization header
// 3. Build a response that adds X-Processed-By header
// 4. Optionally modify the Authorization header
func (p *HeaderProcessor) handleRequestHeaders(headers *extproc.HttpHeaders) *extproc.ProcessingResponse {
	// TODO: Log received headers
	//
	// for _, h := range headers.Headers.Headers {
	//     slog.Info("received header", "key", h.Key, "value", h.Value)
	// }

	// TODO: Find Authorization header
	//
	// var authHeader string
	// for _, h := range headers.Headers.Headers {
	//     if h.Key == "authorization" {
	//         authHeader = h.Value
	//         break
	//     }
	// }
	// if authHeader != "" {
	//     slog.Info("found authorization header", "value", authHeader[:min(50, len(authHeader))]+"...")
	// }

	// TODO: Build response with header mutation
	//
	// return &extproc.ProcessingResponse{
	//     Response: &extproc.ProcessingResponse_RequestHeaders{
	//         RequestHeaders: &extproc.HeadersResponse{
	//             Response: &extproc.CommonResponse{
	//                 HeaderMutation: &extproc.HeaderMutation{
	//                     SetHeaders: []*corev3.HeaderValueOption{
	//                         {
	//                             Header: &corev3.HeaderValue{
	//                                 Key:   "x-processed-by",
	//                                 Value: "ext-proc-learning",
	//                             },
	//                         },
	//                     },
	//                 },
	//             },
	//         },
	//     },
	// }

	// Placeholder - returns empty response (continue without modification)
	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extproc.HeadersResponse{},
		},
	}
}

// findHeader looks for a header by name (case-insensitive).
// Returns the value and true if found, empty string and false if not.
func findHeader(headers *extproc.HttpHeaders, name string) (string, bool) {
	// TODO: Implement header lookup
	//
	// Hints:
	// - Header names in HTTP/2 are lowercase
	// - headers.Headers.Headers is the slice of HeaderValue
	// - Compare using strings.EqualFold for case-insensitivity

	_ = headers // Remove when you use
	_ = name    // Remove when you use

	return "", false
}
