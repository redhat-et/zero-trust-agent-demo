FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /reviewer-service ./reviewer-service

FROM alpine:3.23

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /reviewer-service /app/reviewer-service

EXPOSE 8087

ENTRYPOINT ["/app/reviewer-service"]
CMD ["serve"]
