FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /opa-service ./opa-service

FROM alpine:3.23

RUN apk --no-cache add ca-certificates curl

WORKDIR /app
COPY --from=builder /opa-service /app/opa-service
COPY opa-service/policies /app/policies

EXPOSE 8085

ENTRYPOINT ["/app/opa-service"]
CMD ["serve", "--policy-dir=/app/policies"]
