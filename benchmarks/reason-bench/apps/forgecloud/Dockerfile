# Loopback-only lab image. The app binds 127.0.0.1 inside the container; no ports are published.
FROM node:24-slim
WORKDIR /lab
COPY benchmarks/reason-bench /lab/benchmarks/reason-bench
ENV KOVO_ALLOW_LOCAL_LAB=1
WORKDIR /lab/benchmarks/reason-bench
CMD ["node", "run.ts", "serve", "--app", "forgecloud", "--seed", "1", "--out-dir", "/tmp/forgecloud-out"]
