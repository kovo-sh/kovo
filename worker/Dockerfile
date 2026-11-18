FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
WORKDIR /opt/guardian-worker
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY bridge.ts ./
USER 10001:10001
ENTRYPOINT ["/usr/bin/timeout", "--signal=KILL", "15s", "node", "--max-old-space-size=128", "/opt/guardian-worker/bridge.ts"]
