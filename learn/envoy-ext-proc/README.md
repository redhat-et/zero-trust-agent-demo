# Envoy ext-proc learning project

Learn how to write an Envoy External Processing filter in Go.

## Status: Planned

This project is scaffolded but tasks are not yet defined.

## Learning objectives

By completing this project, you will understand:

1. What Envoy External Processing (ext-proc) is
2. How ext-proc intercepts HTTP requests and responses
3. How to modify headers in transit
4. How to implement token exchange as an ext-proc filter
5. How AuthBridge's ext-proc component works

## Prerequisites

- Completed: jwt-validation project
- Completed: sts-token-exchange project
- Basic understanding of Envoy proxy
- gRPC basics (ext-proc uses gRPC)

## Key concepts to explore

- Envoy External Processing filter
- gRPC service implementation
- Header manipulation
- Request/response processing phases

## References

- [Envoy External Processing](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)
- [AuthBridge ext-proc implementation](https://github.com/kagenti/kagenti-extensions/tree/main/AuthBridge/AuthProxy/ext-proc)
