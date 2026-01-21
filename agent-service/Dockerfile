FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /agent-service ./agent-service

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /agent-service /app/agent-service

EXPOSE 8083

ENTRYPOINT ["/app/agent-service"]
CMD ["serve"]
