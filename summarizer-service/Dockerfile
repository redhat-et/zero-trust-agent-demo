FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /summarizer-service ./summarizer-service

FROM alpine:3.23

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /summarizer-service /app/summarizer-service

EXPOSE 8086

ENTRYPOINT ["/app/summarizer-service"]
CMD ["serve"]
