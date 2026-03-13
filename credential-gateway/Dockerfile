FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /credential-gateway ./credential-gateway

FROM alpine:3.23

RUN apk --no-cache add ca-certificates curl

WORKDIR /app
COPY --from=builder /credential-gateway /app/credential-gateway

EXPOSE 8080

ENTRYPOINT ["/app/credential-gateway"]
CMD ["serve"]
