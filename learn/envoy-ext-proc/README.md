# Envoy ext-proc learning project

Learn how to write an Envoy External Processing filter in Go. This project focuses on understanding the ext-proc protocol - the actual token exchange logic is covered in the sts-token-exchange project.

## Learning objectives

By completing this project, you will understand:

1. What Envoy External Processing (ext-proc) is and why it exists
2. How the ext-proc gRPC protocol works
3. How to receive and inspect request headers
4. How to modify headers before forwarding to upstream
5. The bidirectional streaming nature of ext-proc

## Prerequisites

- Completed: jwt-validation project
- Completed: sts-token-exchange project
- Basic understanding of gRPC
- Docker or Podman (for running Envoy)

## Project structure

```text
envoy-ext-proc/
├── main.go              # gRPC server entry point (Task 4) - SOLUTION
├── processor.go         # ExternalProcessor implementation (Tasks 2, 3) - SOLUTION
├── envoy.yaml           # Envoy configuration (Task 5)
├── docker-compose.yaml  # Local test environment
├── *_test.go            # Unit tests
├── go.mod
├── Makefile
├── README.md
└── scaffolding/         # Original TODO files for starting fresh
    ├── main.go
    ├── processor.go
    └── envoy.yaml
```

### For learners starting fresh

Copy the scaffolding files to start with TODO markers:

```bash
cp scaffolding/*.go .
cp scaffolding/envoy.yaml .
```

## Getting started

```bash
cd learn/envoy-ext-proc
go mod tidy
```

---

## Background: What is ext-proc?

Envoy's External Processing filter allows you to offload request/response processing to an external gRPC service. This is powerful because:

1. **Language agnostic**: Write processing logic in any language
2. **Hot reloadable**: Update processing without restarting Envoy
3. **Separation of concerns**: Keep complex logic out of Envoy config

### The ext-proc flow

```text
┌────────┐      ┌─────────┐      ┌──────────┐      ┌──────────┐
│ Client │─────▶│  Envoy  │─────▶│ ext-proc │      │ Upstream │
│        │      │         │◀─────│ (your Go │      │          │
│        │      │         │      │  server) │      │          │
│        │◀─────│         │───────────────────────▶│          │
└────────┘      └─────────┘                        └──────────┘

1. Client sends request to Envoy
2. Envoy sends headers to ext-proc via gRPC stream
3. ext-proc responds with header mutations
4. Envoy applies mutations and forwards to upstream
5. Response flows back (optionally through ext-proc)
```

Envoy is not a standalone HTTP server -- it's a **reverse proxy** that
sits in front of the real service. The upstream service receives
requests after Envoy (and ext-proc) have processed them. The upstream
is unaware that any processing happened.

### Learning setup vs production

In the exercises, we use [httpbin.org][httpbin] as the upstream. httpbin
is an HTTP echo service -- its `/headers` endpoint returns all the
request headers it received as JSON. This makes it useful for verifying
that ext-proc mutations actually reach the upstream (e.g., seeing
`X-Processed-By` in the response confirms the header was added).

In the real AuthBridge scenario, the setup translates directly:

```text
Learning exercise:
  curl → Envoy → ext-proc (adds X-Processed-By) → httpbin.org

Production (AuthBridge):
  Agent → Envoy → ext-proc (exchanges token) → document-service
```

The ext-proc replaces the `Authorization` header with a token scoped
to the upstream's audience. The upstream service (document-service)
just sees a token already intended for it -- no token exchange logic
needed in the application code.

[httpbin]: https://httpbin.org/

### The gRPC protocol

ext-proc uses bidirectional streaming:

```protobuf
service ExternalProcessor {
  rpc Process(stream ProcessingRequest) returns (stream ProcessingResponse);
}

message ProcessingRequest {
  oneof request {
    HttpHeaders request_headers = 2;
    HttpBody request_body = 3;
    HttpHeaders response_headers = 6;
    HttpBody response_body = 7;
  }
}

message ProcessingResponse {
  oneof response {
    HeadersResponse request_headers = 1;
    BodyResponse request_body = 2;
    HeadersResponse response_headers = 5;
    BodyResponse response_body = 6;
  }
}
```

---

## Tasks

### Task 1: Generate the gRPC code

**Objective**: Set up the project with the required protobuf definitions.

**Steps**:

1. Install protoc and Go plugins:

   ```bash
   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
   ```

2. The Envoy ext-proc protos are available as a Go module. Add to go.mod:

   ```bash
   go get github.com/envoyproxy/go-control-plane@latest
   ```

3. Verify you can import the types:

   ```go
   import (
       extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
   )
   ```

**Success criteria**:

- [ ] Can import `envoy/service/ext_proc/v3` package
- [ ] Can import `envoy/config/core/v3` for HeaderValue types
- [ ] `go mod tidy` succeeds

**Hints**:

- You don't need to run protoc yourself - the go-control-plane module provides pre-generated code
- The package path is `github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3`

---

### Task 2: Implement the Process method (basic)

**Objective**: Create a minimal ext-proc server that logs headers and passes through.

**File**: `processor.go`

**Function signature**:

```go
type HeaderProcessor struct {
    extproc.UnimplementedExternalProcessorServer
}

func (p *HeaderProcessor) Process(stream extproc.ExternalProcessor_ProcessServer) error
```

**Steps**:

1. Create a struct that embeds `UnimplementedExternalProcessorServer`
2. Implement the `Process` method
3. In a loop:
   - Call `stream.Recv()` to get requests
   - Log what you receive
   - Send an empty response (continue without modification)

**Hints**:

- The stream is bidirectional - you receive AND send on it
- Handle `io.EOF` from Recv() as normal termination
- For now, just log and respond with `ImmediateResponse` or empty headers response

**Success criteria**:

- [ ] Server compiles and starts
- [ ] Logs when it receives request headers
- [ ] Sends a valid response back

---

### Task 3: Implement header mutation

**Objective**: Modify a header before the request is forwarded.

**File**: `processor.go`

**Add this logic**:

When you receive request headers:

1. Log the original `Authorization` header (if present)
2. Add a new header: `X-Processed-By: ext-proc-learning`
3. Optionally: modify the `Authorization` header (simulate token exchange)

**Header mutation response structure**:

```go
&extproc.ProcessingResponse{
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
```

**Pitfall -- `RawValue` vs `Value`:**

The `HeaderValue` proto has both a `Value` (string) and `RawValue`
(bytes) field. Newer Envoy versions populate `RawValue` and leave
`Value` empty. Many online examples still use `Value`, which results
in empty header values in both directions (reading and writing).
Always use `RawValue` (converting with `string(h.RawValue)` when
reading, `[]byte("...")` when writing).

**Success criteria**:

- [ ] Adds custom header to requests
- [ ] Original request continues to upstream
- [ ] Logs show header values

---

### Task 4: Create the gRPC server

**Objective**: Set up the gRPC server to listen for ext-proc connections.

**File**: `main.go`

**Steps**:

1. Create a TCP listener on a configurable port (default: 50051)
2. Create a gRPC server
3. Register your HeaderProcessor
4. Handle graceful shutdown on SIGINT/SIGTERM

**Hints**:

```go
lis, err := net.Listen("tcp", ":50051")
grpcServer := grpc.NewServer()
extproc.RegisterExternalProcessorServer(grpcServer, &HeaderProcessor{})
grpcServer.Serve(lis)
```

**Success criteria**:

- [ ] Server starts and listens on port 50051
- [ ] Logs "listening on :50051" message
- [ ] Graceful shutdown on Ctrl+C

---

### Task 5: Configure Envoy to use ext-proc

**Objective**: Create an Envoy configuration that routes requests through your ext-proc.

**File**: `envoy.yaml`

**Key configuration sections**:

1. **Listener**: Accept HTTP requests on port 8080
2. **ext_proc filter**: Call your gRPC server for processing
3. **Cluster**: Define the upstream service (e.g., httpbin.org)
4. **ext_proc cluster**: Define how to reach your processor

**Envoy config structure**:

```yaml
static_resources:
  listeners:
    - name: listener_0
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                http_filters:
                  - name: envoy.filters.http.ext_proc
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
                      grpc_service:
                        envoy_grpc:
                          cluster_name: ext_proc_cluster
                      processing_mode:
                        request_header_mode: SEND
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route: { cluster: upstream_cluster }

  clusters:
    - name: ext_proc_cluster
      type: STATIC
      lb_policy: ROUND_ROBIN
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {}
      load_assignment:
        cluster_name: ext_proc_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: host.docker.internal, port_value: 50051 }

    - name: upstream_cluster
      type: LOGICAL_DNS
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: upstream_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: httpbin.org, port_value: 443 }
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
```

**Success criteria**:

- [ ] Envoy starts without errors
- [ ] Requests to Envoy (port 8080) trigger ext-proc calls
- [ ] Responses include your custom header

---

### Task 6: End-to-end test

**Objective**: Test the complete flow from client through Envoy and ext-proc.

**Steps**:

1. Start your ext-proc server:

   ```bash
   go run .
   ```

2. Start Envoy with your config:

   ```bash
   docker run --rm -p 8080:8080 \
     -v $(pwd)/envoy.yaml:/etc/envoy/envoy.yaml:ro \
     --add-host=host.docker.internal:host-gateway \
     envoyproxy/envoy:v1.28-latest \
     -c /etc/envoy/envoy.yaml
   ```

   Or, for Podman:

   ```bash
   podman run --rm -p 8080:8080 \
     -v $(pwd)/envoy.yaml:/etc/envoy/envoy.yaml:ro \
     --add-host=host.containers.internal:host-gateway \
     --entrypoint envoy \
     envoyproxy/envoy:v1.28-latest \
     -c /etc/envoy/envoy.yaml
   ```

3. Send a test request:

   ```bash
   curl -v http://localhost:8080/headers \
     -H "Authorization: Bearer test-token"
   ```

4. Verify:
   - ext-proc logs show the Authorization header
   - Response includes `X-Processed-By: ext-proc-learning`
   - Request reaches httpbin and returns successfully

**Pitfalls:**

- **Podman on macOS**: The Envoy container entrypoint runs `chown` on
  stdout/stderr, which fails in Podman's rootless mode. Use
  `--entrypoint envoy` to bypass the shell entrypoint (already shown
  in the Podman command above).
- **`host.containers.internal` with STATIC cluster**: Podman provides
  `host.containers.internal` as a hostname, but Envoy's `STATIC` cluster
  type requires a literal IP address. Use `type: STRICT_DNS` for the
  ext-proc cluster when using hostnames.
- **Empty header values**: See the `RawValue` vs `Value` note in Task 3.

**Success criteria**:

- [ ] Request flows through Envoy → ext-proc → upstream
- [ ] Custom header appears in response
- [ ] ext-proc logs show intercepted headers
- [ ] No errors in Envoy or ext-proc logs

---

## Stretch goals

1. **Token exchange integration**: Combine with sts-token-exchange to actually exchange tokens
2. **Response processing**: Also process response headers
3. **Conditional processing**: Only process requests to specific paths
4. **Metrics**: Add Prometheus metrics for processing latency
5. **Audience mapping**: Implement host-to-audience mapping

## Connecting to the main project

After completing this project, you understand how AuthBridge works:

1. **ext-proc intercepts** requests before they reach the target service
2. **Token exchange** replaces the Authorization header with a service-specific token
3. **Envoy forwards** the modified request to the upstream

The AuthBridge implementation combines:

- This project's ext-proc pattern
- The sts-token-exchange logic for actual token exchange
- Configuration for host → audience mapping

## References

- [Envoy External Processing](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)
- [ext-proc protobuf definitions](https://github.com/envoyproxy/envoy/blob/main/api/envoy/service/ext_proc/v3/external_processor.proto)
- [go-control-plane](https://github.com/envoyproxy/go-control-plane)
- [AuthBridge ext-proc implementation](https://github.com/kagenti/kagenti-extensions/tree/main/AuthBridge/AuthProxy/go-processor)
