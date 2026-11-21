# Guardian v3 Hardened Air-Gapped Worker Image (guardian-worker:local / guardian-worker:v3)
# Runs strictly with --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001

FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS tools-downloader

ARG TARGETARCH=amd64

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tar gzip \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /out/bin /tmp/dl

# Pinned SHA-256 offline SAST / secret / IaC binaries
RUN set -eux; \
  case "${TARGETARCH}" in \
    amd64) \
      GITLEAKS_ARCH="x64"; GITLEAKS_SHA="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"; \
      TRUFFLEHOG_ARCH="amd64"; TRUFFLEHOG_SHA="b2d85eba59865e98f45c9fc9f77d2c6d62df529fdd5755af121304ea5a7cecbb"; \
      TRIVY_ARCH="64bit"; TRIVY_SHA="bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"; \
      OPENGREP_ASSET="opengrep_linux_x86"; OPENGREP_SHA="37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0"; \
      ;; \
    arm64) \
      GITLEAKS_ARCH="arm64"; GITLEAKS_SHA="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"; \
      TRUFFLEHOG_ARCH="arm64"; TRUFFLEHOG_SHA="aa61657049229ae523e8455fcbba87dff57b0a2ba6bdb391a38cf75e6d4016dd"; \
      TRIVY_ARCH="ARM64"; TRIVY_SHA="ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3"; \
      OPENGREP_ASSET="opengrep_linux_aarch64"; OPENGREP_SHA="6257b65423a744b704af2ff9beeb8f222c2f6925236af386b56b031d4c06d6d8"; \
      ;; \
    *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  \
  # 1. gitleaks v8.30.1
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GITLEAKS_ARCH}.tar.gz" -o /tmp/dl/gitleaks.tgz; \
  echo "${GITLEAKS_SHA}  /tmp/dl/gitleaks.tgz" | sha256sum -c -; \
  tar -xzf /tmp/dl/gitleaks.tgz -C /out/bin gitleaks; \
  chmod 0755 /out/bin/gitleaks; \
  \
  # 2. trufflehog v3.100.0 (always invoked with --no-verification inside --network none)
  curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v3.100.0/trufflehog_3.100.0_linux_${TRUFFLEHOG_ARCH}.tar.gz" -o /tmp/dl/trufflehog.tgz; \
  echo "${TRUFFLEHOG_SHA}  /tmp/dl/trufflehog.tgz" | sha256sum -c -; \
  tar -xzf /tmp/dl/trufflehog.tgz -C /out/bin trufflehog; \
  chmod 0755 /out/bin/trufflehog; \
  \
  # 3. trivy v0.76.2 (offline-scan IaC/misconfig + custom SCA ruleset)
  curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/dl/trivy.tgz; \
  echo "${TRIVY_SHA}  /tmp/dl/trivy.tgz" | sha256sum -c -; \
  tar -xzf /tmp/dl/trivy.tgz -C /out/bin trivy; \
  chmod 0755 /out/bin/trivy; \
  \
  # 4. opengrep v2.0.0 (offline SAST & deterministic AST re-verification)
  curl -fsSL "https://github.com/opengrep/opengrep/releases/download/v2.0.0/${OPENGREP_ASSET}" -o /out/bin/opengrep; \
  echo "${OPENGREP_SHA}  /out/bin/opengrep" | sha256sum -c -; \
  chmod 0755 /out/bin/opengrep; \
  rm -rf /tmp/dl

FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 python3-venv git ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && python3 -m venv /opt/guardian-venv \
  && /opt/guardian-venv/bin/pip install --no-cache-dir --upgrade pip \
  && /opt/guardian-venv/bin/pip install --no-cache-dir bandit==1.8.3 PyJWT==2.10.1 cryptography==44.0.2 \
  && chmod -R a+rX /opt/guardian-venv \
  && ln -s /tmp/guardian-evidence /evidence

COPY --from=tools-downloader /out/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=tools-downloader /out/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=tools-downloader /out/bin/trivy /usr/local/bin/trivy
COPY --from=tools-downloader /out/bin/opengrep /usr/local/bin/opengrep

WORKDIR /opt/guardian-worker
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
  && chmod -R a+rX /opt/guardian-worker/node_modules \
  && AST_GREP_BIN="$(find /opt/guardian-worker/node_modules/@ast-grep -maxdepth 2 -type f -name ast-grep | head -n1)" \
  && test -n "${AST_GREP_BIN}" \
  && chmod 0755 "${AST_GREP_BIN}" \
  && ln -sf "${AST_GREP_BIN}" /usr/local/bin/ast-grep \
  && ln -sf "${AST_GREP_BIN}" /usr/local/bin/sg

COPY rules /opt/guardian-rules
RUN chmod -R a+rX /opt/guardian-rules \
  && mkdir -p /tmp/.config /tmp/.cache /tmp/rule-check \
  && printf 'const x = 1; el.innerHTML = x;\n' > /tmp/rule-check/a.js \
  && printf 'const x: number = 1; el.innerHTML = String(x);\n' > /tmp/rule-check/a.ts \
  && printf 'export const C = () => <div dangerouslySetInnerHTML={{ __html: x }} />;\n' > /tmp/rule-check/a.tsx \
  && printf 'import subprocess\nsubprocess.run(x, shell=True)\n' > /tmp/rule-check/a.py \
  && printf 'package main\nfunc f() { db.Query(fmt.Sprintf("%s", x)) }\n' > /tmp/rule-check/a.go \
  && printf 'hostNetwork: true\n' > /tmp/rule-check/a.yaml \
  && HOME=/tmp XDG_CONFIG_HOME=/tmp/.config XDG_CACHE_HOME=/tmp/.cache opengrep scan --config /opt/guardian-rules/opengrep --json --no-git-ignore /tmp/rule-check \
     | node -e 'const d = JSON.parse(require("fs").readFileSync(0,"utf8")); if ((d.errors||[]).length || (d.skipped_rules||[]).length) { console.error(JSON.stringify(d, null, 2)); process.exit(1); } if (!(d.results||[]).length) { console.error("No opengrep matches on fixture"); process.exit(1); }' \
  && ast-grep scan --config /opt/guardian-rules/ast-grep/sgconfig.yml --json=compact /tmp/rule-check \
     | node -e 'const d = JSON.parse(require("fs").readFileSync(0,"utf8")); if (!Array.isArray(d) || !d.some(m => m.ruleId === "guardian-ast-tsx-dangerous-html")) { console.error("Missing ast-grep tsx match", d); process.exit(1); }' \
  && rm -rf /tmp/rule-check /tmp/.config /tmp/.cache

COPY analyzers.ts bridge.ts ./
RUN chmod 0644 /opt/guardian-worker/analyzers.ts /opt/guardian-worker/bridge.ts

ENV PATH="/opt/guardian-venv/bin:/opt/guardian-worker/node_modules/.bin:/usr/local/bin:/usr/bin:/bin" \
    HOME="/tmp" \
    XDG_CACHE_HOME="/tmp/.cache" \
    XDG_CONFIG_HOME="/tmp/.config" \
    TRIVY_CACHE_DIR="/tmp/.trivy-cache" \
    TRIVY_DISABLE_TELEMETRY="true" \
    SEMGREP_SEND_METRICS="off" \
    OPENGREP_SEND_METRICS="off" \
    PYTHONDONTWRITEBYTECODE="1"

USER 10001:10001
ENTRYPOINT ["node", "--max-old-space-size=384", "/opt/guardian-worker/bridge.ts"]
