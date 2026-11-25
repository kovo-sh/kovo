# syntax=docker/dockerfile:1

FROM docker:27-cli AS docker-cli

FROM node:24-bookworm-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build

FROM node:24-bookworm-slim AS runtime

ARG KOVO_WORKER_IMAGE=ghcr.io/wwwillchen/kovo-worker:latest

LABEL org.opencontainers.image.source="https://github.com/wwwillchen/guardian" \
      org.opencontainers.image.title="kovo-hunter" \
      org.opencontainers.image.description="Kovo Hunter defensive web-application security verification platform"

ENV NODE_ENV=production \
    PORT=8000 \
    KOVO_DATA_DIR=/data \
    KOVO_WORKER_IMAGE=${KOVO_WORKER_IMAGE} \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    HOME=/home/kovo

WORKDIR /app

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git \
  && ./node_modules/.bin/playwright install --with-deps chromium \
  && rm -rf /var/lib/apt/lists/* \
  && docker --version

COPY --from=builder /app/build ./build
COPY --from=builder /app/public ./public
COPY --from=builder /app/scripts ./scripts
COPY --from=builder /app/src ./src
COPY --from=builder /app/drizzle ./drizzle
COPY --from=builder /app/worker/kovo_verify ./worker/kovo_verify
COPY --from=builder /app/LICENSE ./LICENSE

RUN groupadd --gid 10001 kovo \
  && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/kovo --shell /bin/sh kovo \
  && mkdir -p /data /scratch /home/kovo \
  && chown -R 10001:10001 /data /scratch /home/kovo \
  && chmod 0700 /data \
  && chmod 0755 /scratch \
  && chmod -R a+rX /app /opt/ms-playwright

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 8000) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

CMD ["node", "scripts/serve.ts"]
