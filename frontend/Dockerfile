FROM node:22-alpine@sha256:dbcedd8aeab47fbc0f4dd4bffa55b7c3c729a707875968d467aaaea42d6225af AS builder

# CRITICAL: Railway cache buster - change this line to force rebuild
RUN set -eux \
  && echo "Force rebuild: 2025-10-24-11-00-VITE-MIGRATION" \
  && apk --no-cache add git

WORKDIR /app

ARG VITE_API_URL=http://localhost:8080
ENV VITE_API_URL=$VITE_API_URL

RUN npm install -g pnpm@10.18.3

COPY package.json pnpm-lock.yaml ./

# Clean install to avoid stale dependencies
RUN rm -rf node_modules .pnpm-store && pnpm install --frozen-lockfile

COPY . .

# Clean build to avoid stale artifacts
RUN rm -rf dist && pnpm run build

FROM caddy:2.10-alpine@sha256:953131cfea8e12bfe1c631a36308e9660e4389f0c3dfb3be957044d3ac92d446

RUN apk --no-cache add ca-certificates curl gettext bind-tools

COPY Caddyfile /etc/caddy/Caddyfile
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --from=builder /app/dist /usr/share/caddy

ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data

RUN addgroup -g 1001 -S caddy-user \
    && adduser -S -D -H -u 1001 -s /sbin/nologin -G caddy-user -g caddy-user caddy-user \
    && mkdir -p /config /data \
    && chown -R caddy-user:caddy-user /usr/share/caddy /etc/caddy /config /data \
    && chown caddy-user:caddy-user /usr/bin/caddy

USER caddy-user

ENV PORT=80

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS --max-time 2 http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
