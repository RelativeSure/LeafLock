FROM golang:1.25-alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd AS builder

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

FROM alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

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
