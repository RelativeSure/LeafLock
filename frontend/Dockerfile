FROM node:22-alpine AS builder

RUN apk --no-cache add git

WORKDIR /app

ARG VITE_API_URL=http://localhost:8080
ENV VITE_API_URL=$VITE_API_URL

RUN npm install -g pnpm@10.17.1

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

RUN pnpm run build

FROM caddy:2.8-alpine

RUN apk --no-cache add ca-certificates curl gettext bind-tools

COPY Caddyfile /etc/caddy/Caddyfile
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --from=builder /app/dist /usr/share/caddy

RUN addgroup -g 1001 -S caddy-user \
    && adduser -S -D -H -u 1001 -s /sbin/nologin -G caddy-user -g caddy-user caddy-user \
    && chown -R caddy-user:caddy-user /usr/share/caddy /etc/caddy \
    && chown caddy-user:caddy-user /usr/bin/caddy

USER caddy-user

ENV PORT=80

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS --max-time 2 http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
