FROM golang:1.23.2-alpine AS builder
LABEL maintainer="Viktor S. | t.me/fakelag"
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/main.go
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/configs/config.yml ./configs/
RUN adduser -D -g '' appuser
USER appuser
CMD ["./main"] 