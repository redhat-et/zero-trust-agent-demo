FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /web-dashboard ./web-dashboard

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /web-dashboard /app/web-dashboard

EXPOSE 8080

ENTRYPOINT ["/app/web-dashboard"]
CMD ["serve"]
