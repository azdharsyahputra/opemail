# Stage 1: Build binary
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git
ENV GOTOOLCHAIN=auto
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/mailopen ./cmd/mailopen

# Stage 2: Minimal runtime
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata openssl curl

WORKDIR /app
COPY --from=builder /app/bin/mailopen /usr/local/bin/mailopen

EXPOSE 8085
CMD ["mailopen", "server", "--addr", ":8085"]
