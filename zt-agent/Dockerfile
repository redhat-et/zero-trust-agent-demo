FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /zt-agent ./zt-agent

FROM alpine:3.23

RUN apk --no-cache add ca-certificates curl && \
    addgroup -S ztagent && adduser -S ztagent -G ztagent

WORKDIR /app
COPY --from=builder /zt-agent /app/zt-agent

USER ztagent

EXPOSE 8000

ENTRYPOINT ["/app/zt-agent"]
CMD ["serve"]
