# Kovo

**Open-source AI pentester that won't break prod.**

Self-hosted · Apache 2.0 · [Latest Release](https://github.com/kovo-sh/kovo/releases/latest) · [Docker Guide](docs/DOCKER.md) · [Architecture](ARCHITECTURE.md)

Catch the real-world vulnerabilities attackers find with ARTEX—backed by **host-enforced guardrails**, not prompts.

> Only assess applications you own or have explicit written authorization to test.

---

## Why Kovo

ARTEX proved autonomous AI agents can run real pentests end to end—but red-team tools are easy to misuse on your own software. Kovo brings that same autonomous depth with host-enforced guardrails, so you never probe third-party hosts, wreck production data, or leak test credentials.

- **Air-gapped workers (`--network=none`)** — Workers run in hardened `--read-only --network=none --cap-drop=ALL` containers (UID `10001`). They cannot open a raw socket. Every outbound request passes through a **Host Request Broker** enforcing your scope allowlist, execution tiers (**Tiers 0–3**, starting read-only), and RPS rate limits.
- **Opaque persona vault (`0 creds to LLM`)** — Test multi-user and cross-tenant authorization without ever showing cookies, tokens, or JWTs to the model. Sessions stay sealed on the host; the broker injects them and agents only see opaque placeholders like `[redacted:user_b]`.
- **Code-aware + zero-LLM replay proof (`/repos:ro`, `Verify fix`)** — Mount your repositories read-only (`/repos`) so agents read your actual routes and handlers. Every confirmed finding stores the exact control vs. variant replay assertions—ship your patch and click **Verify fix** to retest against your live app with zero LLM tokens.

### Locked to your apps, by design

1. **Isolated** — Worker containers run with `--network=none` and no secrets; raw sockets die at the container wall.
2. **Brokered** — Approved requests pass through the Host Request Broker, which swaps persona placeholders for sealed credentials before contacting your app.
3. **Blocked** — Any request targeting an out-of-scope or third-party host hits the scope wall and never gets a packet.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full technical design.

---

## Getting started

First pentest in five minutes—run with Docker Compose (recommended) or build from source.

### 1. Start Kovo

#### Option A: Docker Compose (recommended)

Runs Kovo as two unprivileged containers (`kovo` + `docker-socket-proxy`, no `--privileged` and no Docker-in-Docker) using prebuilt multi-arch (`linux/amd64`, `linux/arm64`) images from GHCR:

```sh
curl -fsSLO https://raw.githubusercontent.com/kovo-sh/kovo/main/docker-compose.yml
docker compose pull
docker compose up
```

Then open the one-time bootstrap URL printed in the `kovo` logs (for example, `http://127.0.0.1:8000/?bootstrap=...`). Opening it once consumes the secret and sets a local `HttpOnly`, `SameSite=Strict` session cookie (all unauthenticated requests fail closed with `401`).

See [docs/DOCKER.md](docs/DOCKER.md) for `KOVO_PORT`, pinning `KOVO_VERSION`, `KOVO_HOST_SCRATCH_DIR`, and the `docker-socket-proxy` security model.

#### Option B: Run from source

Requires **Node.js 24.13.1+** and a local Docker daemon for isolated `--network=none` worker containers:

```sh
git clone https://github.com/kovo-sh/kovo.git
cd kovo
npm ci
npm run worker:build
npx playwright install chromium
npm run build
npm start
```

Open the one-time `http://127.0.0.1:8000/?bootstrap=...` URL printed on startup (also written to `${KOVO_DATA_DIR:-.kovo}/bootstrap`, mode `0600`). Set `PORT` or `KOVO_DATA_DIR` to customize the port or data directory.

### 2. Bring your own model

Open **Model settings** in the UI and plug in any **OpenAI-compatible** (Responses API) or **Anthropic** (Messages API) key:

| Setting | Recommended default |
| --- | --- |
| **Provider** | OpenRouter |
| **Model** | DeepSeek v4.1 Flash (`deepseek/deepseek-v4.1-flash-1017`) |
| **Also works** | Any OpenAI Responses or Anthropic Messages-compatible endpoint |

### 3. Launch your first pentest

1. Paste your target website URL.
2. Review and approve the discovered domains in scope.
3. Optionally connect read-only GitHub repos (`/repos`) and test accounts in the opaque persona vault.
4. Launch the run, inspect confirmed replay proofs, and click **Verify fix** after shipping patches.

---

## How it stacks up

| Dimension | **Kovo** | ARTEX | Strix | Classic DAST (ZAP / Nuclei) |
| --- | --- | --- | --- | --- |
| **Safety & guardrails** | Air-gapped worker, host broker, Tiers 0–3, opaque vault | Built for red-teaming; easy to misuse on your own apps | Containerized; operator-managed safety | Rule/template driven; manual auth and scope tuning |
| **Finding proof** | Zero-LLM replay proof + Verify Fix | Agent-generated PoCs and reports | Agent exploit scripts and PoCs | Signature match; manual false-positive triage |
| **Code context** | Full read-only `/repos` mounts | Primarily external / black-box | Source + dynamic hybrid | Black-box HTTP only |
| **Interface** | Self-hosted end-to-end management UI | Self-hosted web UI | CLI-first | Desktop GUI (ZAP) / CLI (Nuclei) |
| **License** | Apache 2.0 | Open-source / source-available | Apache 2.0 | Apache 2.0 / MIT |

---

## FAQ

- **Is Kovo free? What are the restrictions?**
  100% free and open source under **Apache 2.0**. Unlimited runs across all your apps—you only pay your own LLM provider.
- **Can it really not break production?**
  Workers run with `--network=none`, so every request passes through the host broker. You control the domain allowlist, RPS rate limits, and execution tier (Tiers 0–3, starting read-only), and test credentials stay sealed in the host vault—never shown to the LLM.
- **Enterprise Edition (in development):**
  SSO, configurable roles and RBAC, and scheduled routine pentest runs with automated email and Slack reports. Contact [will@kovo.sh](mailto:will@kovo.sh?subject=Kovo%20Enterprise).

---

## Built in the open

Built under the [Apache 2.0 License](LICENSE) by **Will Chen** (ex-Google Staff Software Engineer, creator of [Dyad](https://github.com/dyad-sh/dyad) and [Mesop](https://github.com/mesop-dev/mesop)).

---

## Developing Kovo

### Prerequisites & setup

- **Node.js `>= 24.13.1`** and a local **Docker** daemon (`docker` CLI reachable by your shell, e.g. via the `docker` group)
- Install dependencies, Playwright Chromium, and the local hardened worker image:

```sh
npm ci
npm run worker:install
npm run worker:build
npx playwright install chromium
```

### Common development & verification commands

```sh
npm run check                        # TypeScript typecheck (tsc --noEmit)
npm run build                        # Production Vite/TanStack Start build
bash scripts/worker-gate.sh          # Fast pre-handoff gate (static ratchets + tsc + fast unit suites)
bash scripts/docker-smoke.sh         # Verify worker UID 10001 + --network=none bridge handshake
npm run test:boundaries              # Security boundary & broker tests
npm run test:e2e                     # Live Chromium E2E UI tests (replays recorded fixtures)
```

To verify the full Docker Compose sibling-container stack locally:

```sh
docker build -t kovo:local --build-arg KOVO_WORKER_IMAGE=kovo-worker:v4 .
bash scripts/docker-compose-smoke.sh
```

After editing anything under `worker/`, rebuild the local image with `npm run worker:build`. See [docs/DOCKER.md](docs/DOCKER.md) for the human-approved container release process (`.github/workflows/release.yml`) and [docs/SMOKE-BATTERY.md](docs/SMOKE-BATTERY.md) for the agentic inner-loop smoke battery.
