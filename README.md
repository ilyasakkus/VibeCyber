# WebCyber

WebCyber is an open-source security scanning platform designed to inspect web targets, source code repositories, mobile application packages, and desktop binaries using a unified finding model.

> [!IMPORTANT]
> WebCyber must only be used on targets you own or have explicit authorization to test. The default `observe` and `safe` profiles do not perform state-mutating requests, store persistent payloads, or execute exploits.

## Current State

The repository contains a Phase 1a vertical slice operating with a local control plane:

- Cloudflare-compatible React web control dashboard with a `same-origin` API proxy layer.
- Loopback Go control API listening locally with mandatory Bearer token authentication.
- Bounded in-memory job queue with recent jobs, cancellation, and SSE event streaming.
- Go CLI core with safe defaults and a unified finding schema.
- Electron desktop bridge wrapping the Go CLI with local file picking and strict IPC boundaries.
- Standardized JSON and SARIF output contracts.
- Built-in bounds for SSRF prevention, redirects, file/symlink traversal, timeouts, and output limits.
- Security policy, threat model, and plugin manifest contracts.

Web scanning is currently passive and read-only. Source code, mobile package, and desktop application scanning in the control API require `WEBCYBER_ALLOW_LOCAL=true`. This setting does not affect direct CLI usage or the desktop application accessing user-selected local paths.

Integrations for Nuclei, Semgrep, Trivy, Gitleaks, MobSF, and deep binary analysis tools will be introduced in subsequent phases as signed and pinned worker adapters. User input is never converted into shell commands.

## Architecture

```text
Web browser → same-origin web proxy → loopback Go control API
                                           │
                                           ▼
                                  bounded in-memory queue
                                           │
                                           ▼
                                    Go scanner core

Electron desktop → bundled Go CLI ────→ Go scanner core
Go CLI ───────────────────────────────→ Go scanner core
```

The browser never accesses the control token directly; the web server proxy attaches authorization credentials to requests sent to the Go API. The web browser cannot read local file paths independently. In development mode, local targets are scanned via the local control API, while in desktop mode, targets are accessed via explicit user selection.

For details, refer to [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Requirements

- Node.js 22.13 or higher
- Go 1.24 or higher
- An operating system supported by Electron (for desktop shell development)

## Getting Started

To install dependencies and start both the web dashboard and the Go control plane together:

```bash
npm install
npm run dev:full
```

`dev:full` opens the Go API on `127.0.0.1:7071` by default; unless environment variables are pre-configured, it generates a random bearer token on each launch and shares it exclusively between the web proxy and Go daemon process. `WEBCYBER_ALLOW_LOCAL` defaults to `true` under this script for local development. If either process terminates, the runner gracefully shuts down the remaining child process.

To develop the web interface standalone:

```bash
npm run dev
```

This command does not start the Go backend daemon. If the control API is unreachable, the dashboard intentionally displays an offline status without generating fake or mock scan results.

To run the control service independently, set `WEBCYBER_CONTROL_TOKEN`.
`WEBCYBER_API_URL` configures the URL the web proxy connects to, `WEBCYBER_CONTROL_ADDR` configures the bind address for the Go service, and `WEBCYBER_ALLOW_LOCAL` controls whether local target types are exposed over the API. The API provides health/capability checks, job creation, listing and reading, cancellation, and per-job SSE event streams.

Go CLI:

```bash
go test ./cmd/... ./internal/...
go run ./cmd/webcyber scan --type source --target . --profile observe --format json
```

Observation checks against an authorized URL:

```bash
go run ./cmd/webcyber scan \
  --type web \
  --target https://example.com \
  --profile observe \
  --format sarif
```

Desktop shell:

```bash
npm --prefix desktop install
npm --prefix desktop run prepare:scanner
npm --prefix desktop start
```

## Security Profiles

| Profile | Purpose | Default Boundary |
| --- | --- | --- |
| `observe` | TLS, header, metadata, and local static analysis | Read-only / Non-mutating |
| `safe` | Read-only web observation; contract for expanded local static rules | Read-only; no active crawler yet |
| `active` | Deep verification testing in authorized staging environments | Disabled in Phase 1a |

> [!WARNING]
> The Phase 1a control API is designed for local development. Do not expose this Go API + web proxy setup directly to the public internet without adding robust authentication, tenant isolation, rate limiting, and target ownership verification. The in-memory queue is ephemeral; PostgreSQL, Redis, RBAC, auditing, and target ownership controls are planned for Phase 1b.

## Repository Structure

```text
app/                 Web operations dashboard and same-origin control proxy layer
cmd/webcyber/        CLI entrypoint
cmd/webcyberd/       Local Go control daemon
internal/            Scanner core, control queue, and built-in adapters
desktop/             Secure Electron desktop shell and CLI bridge
docs/                Architecture, threat model, and roadmap documentation
schemas/             Plugin manifest contracts
```

## Roadmap

Phase 1a unifies the web dashboard and Go scanner core within a secure local control boundary. Phase 1b will introduce a persistent, multi-tenant production control plane. Subsequent phases will bring worker adapters, deeper mobile/desktop analysis engines, and opt-in active DAST. The detailed plan is documented in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Contributing & License

For contribution guidelines, see [`CONTRIBUTING.md`](CONTRIBUTING.md). For security reporting, see [`SECURITY.md`](SECURITY.md). WebCyber is released under the Apache-2.0 License.
