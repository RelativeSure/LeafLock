FROM golang:1.25-alpine@sha256:26111811bc967321e7b6f852e914d14bede324cd1accb7f81811929a6a57fea9 AS builder

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

RUN apk --no-cache add build-base git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN go build \
      -ldflags='-w -s -extldflags "-static"' \
      -trimpath \
      -o main . && \
    chmod +x /app/main

RUN go build \
      -ldflags='-w -s -extldflags "-static"' \
      -trimpath \
      -o entrypoint ./cmd/entrypoint && \
    chmod +x /app/entrypoint

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder --chmod=0755 /app/main /app/main
COPY --from=builder --chmod=0755 /app/entrypoint /app/entrypoint

RUN addgroup -g 1001 -S app && \
    adduser -S -D -H -u 1001 -s /sbin/nologin -G app app && \
    chown -R app:app /app

USER app

EXPOSE 8080

ENV BACKEND_BINARY=/app/main

ENTRYPOINT ["/app/entrypoint"]
