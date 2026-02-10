FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /user-service ./user-service

FROM alpine:3.23

RUN apk --no-cache add ca-certificates curl

WORKDIR /app
COPY --from=builder /user-service /app/user-service

EXPOSE 8082

ENTRYPOINT ["/app/user-service"]
CMD ["serve"]
