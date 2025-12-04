FROM golang:1.25-alpine@sha256:3587db7cc96576822c606d119729370dbf581931c5f43ac6d3fa03ab4ed85a10 AS builder

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

FROM alpine:3.23@sha256:51183f2cfa6320055da30872f211093f9ff1d3cf06f39a0bdb212314c5dc7375

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
