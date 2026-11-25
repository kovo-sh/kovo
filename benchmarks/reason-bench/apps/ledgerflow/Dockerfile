FROM node:24-slim

# Loopback-only lab runtime. Build from the repository root:
#   docker build -f benchmarks/reason-bench/apps/ledgerflow/Dockerfile -t ledgerflow .
WORKDIR /app
COPY benchmarks/reason-bench /app/benchmarks/reason-bench

ENV KOVO_ALLOW_LOCAL_LAB=1 \
    NODE_ENV=production \
    NODE_OPTIONS=--no-warnings

USER node
# No ports are published; the server binds 127.0.0.1:0 inside the container.
CMD ["node", "benchmarks/reason-bench/run.ts", "serve", "--app", "ledgerflow", "--seed", "1"]
