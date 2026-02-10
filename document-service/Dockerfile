FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /document-service ./document-service

FROM alpine:3.23

RUN apk --no-cache add ca-certificates curl

WORKDIR /app
COPY --from=builder /document-service /app/document-service

EXPOSE 8084

ENTRYPOINT ["/app/document-service"]
CMD ["serve"]
