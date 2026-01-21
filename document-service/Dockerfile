FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /document-service ./document-service

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /document-service /app/document-service

EXPOSE 8084

ENTRYPOINT ["/app/document-service"]
CMD ["serve"]
