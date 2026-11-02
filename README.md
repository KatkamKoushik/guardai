# GuardAI: Cybersecurity & Threat Intelligence Platform

[![Next.js](https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19-blue?style=flat-square&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-v4-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Tests](https://img.shields.io/badge/Tests-72%20Passed-brightgreen?style=flat-square)](./tests)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](./Dockerfile)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1-6BA539?style=flat-square&logo=openapi-initiative&logoColor=white)](./docs/openapi.yaml)
[![Security Policy](https://img.shields.io/badge/Security-Threat%20Model%20Enforced-green?style=flat-square)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

GuardAI is an automated threat intelligence, lexical heuristic evaluation, and active cryptographic scanning platform. Designed for security analysts, incident responders, and DevSecOps pipelines, it combines algorithmic URL triage, strict cryptographic network probing, multi-engine reputation intelligence, and 3D WebGL global threat visualization.

---

## Architecture & Defense-in-Depth

GuardAI enforces layered security at every layer of the scanning and alerting lifecycle:

```mermaid
flowchart TD
    User([Security Analyst / API Client]) -->|Scan Request| Gateway[Next.js API Gateway]
    Gateway -->|1. Sanitize & Refang| Heuristics[Lexical Heuristics Engine]
    Gateway -->|2. Pre-flight DNS Validation| SSRF[SSRF & Egress Controller]
    SSRF -->|Private/Reserved/Metadata IP| Blocked[400 Bad Request Blocked]
    SSRF -->|Validated Public IP| Pinned[Pinned IP Transport]
    Pinned -->|3. Strict Handshake| TLS[Cryptographic TLS Probe]
    Pinned -->|4. Bounded HTTP Probe| Target[(Target Server)]
    Gateway -->|5. Reputation Queries| Intel[VirusTotal / Safe Browsing / AbuseIPDB]
    Intel --> Aggregator[Threat Intelligence Matrix]
    TLS --> Aggregator
    Heuristics --> Aggregator
    Aggregator -->|6. Multi-Dimensional Verdict| Store[(PostgreSQL / Prisma)]
    Aggregator -->|7. Verified Webhook| Alerts[Discord / Telegram Alert Dispatcher]
```

---

## Core Security Guarantees & Features

### 1. SSRF & Egress Network Protection (`src/lib/ssrf.ts`)
- **Pre-flight DNS Inspection**: Resolves both `A` and `AAAA` records, rejecting any target that resolves to private (RFC 1918), link-local, carrier-grade NAT (RFC 6598), loopback (`127.0.0.0/8`), or cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`).
- **Alternate IP Format Normalization**: Validates and normalizes decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`), and IPv4-mapped IPv6 (`::ffff:127.0.0.1`) addresses.
- **DNS Rebinding Prevention**: Outbound sockets connect directly to the verified pinned IP address while preserving the canonical `Host` and TLS `servername` headers.
- **Hop-by-Hop Redirect Validation**: All HTTP redirects are inspected manually (`redirect: 'manual'`), re-resolving and re-validating the scheme, hostname, port, and IP range at every hop (max 5 hops).
- **Protocol & Port Constraints**: Outbound traffic is restricted strictly to `http:` and `https:` on standard web ports (`80`, `443`, `8080`, `8443`). Credentials in URLs (`user:pass@host`) are rejected.

### 2. Cryptographic TLS/SSL Verification (`src/lib/tls-probe.ts`)
- **Strict Root CA Validation**: TLS connections run with `rejectUnauthorized: true` against the trusted root certificate store. Unauthorized certificates are **never** reported as valid.
- **Hostname Identity Enforcement**: Uses SNI and SAN verification (`tls.checkServerIdentity`) to ensure certificate subject matches requested hostname.
- **Explicit Status Model**: Accurately categorizes `VALID`, `EXPIRED`, `SELF_SIGNED`, `HOSTNAME_MISMATCH`, `UNTRUSTED_ROOT`, `REVOKED`, `UNENCRYPTED_HTTP`, `TIMEOUT`, and `CONNECTION_REFUSED`.
- **Diagnostic Inspection**: When a certificate fails validation, a secondary inspection captures issuer and expiry metadata strictly for triage display, without marking the result valid.

### 3. Threat Intelligence Semantics & Abstention (`src/lib/threat-intel.ts`)
- **Explicit Provider Status**: Models provider states independently (`clean`, `malicious`, `suspicious`, `not_found`, `timeout`, `quota_exhausted`, `disabled`, `unknown`, `error`).
- **No False Clean Results**: Missing API keys, network timeouts, or "not found" responses are never converted into a "clean" or "safe" result.
- **Automated Abstention Policy**: If all external reputation engines are disabled, the scanner outputs an `INCONCLUSIVE` verdict with explicit disclosures rather than an unsupported clean claim.
- **Evidence Dimensions**: Separates heuristic score, provider detections, TLS status, and network reachability into distinct audit trails.

### 4. Webhook & Integration Destination Safety (`src/lib/webhooks.ts`)
- **Strict Destination Whitelisting**: Discord webhooks are validated against canonical patterns (`https://discord.com/api/webhooks/<id>/<token>`). Arbitrary external URLs are rejected.
- **Telegram Credential Schemas**: Bot tokens and chat IDs are enforced using strict structural schemas.
- **Secret Redaction**: Webhook URLs and bot tokens are masked in API responses and audit logs (`••••••••`).
- **Anti-Abuse Rate Limiting**: Setup and test endpoints enforce sliding-window rate limits (max 5 requests per minute per user).

### 5. Multi-User Tenant Isolation & Database Caching (`src/lib/db.ts`)
- **Hot-Reload Singleton**: Properly caches the PrismaClient and pg pool across development HMR cycles, preventing pool exhaustion.
- **Graceful Shutdown**: Hooks `SIGINT`, `SIGTERM`, and `beforeExit` to disconnect database pools cleanly.
- **User Scoping**: Scans, audit logs, and notification integrations are strictly scoped to verified user sessions with deny-by-default authorization.

---

## Repository Structure

```
guardai/
├── .github/workflows/
│   └── ci.yml                 # Clean-lockfile CI pipeline (lint, typecheck, test, build)
├── docs/
│   ├── THREAT_MODEL.md        # Comprehensive product threat model & attack trees
│   └── INCIDENT_RUNBOOK.md    # Incident playbooks (SSRF, credential leak, provider outage)
├── prisma/
│   ├── schema.prisma          # Database schema (User, Scan, Notification, ThreatTelemetry)
│   └── prisma.config.ts       # Prisma runtime configuration
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── alerts/        # Alert channel configuration & test endpoints
│   │   │   ├── audit/         # Authenticated audit log API
│   │   │   ├── cron/ingest/   # URLhaus threat feed ingestion
│   │   │   ├── notifications/ # Secure sample notification dispatcher
│   │   │   ├── scan/          # Synchronous & real-time SSE scan endpoints
│   │   │   └── telemetry/     # Real-time threat feed & SSE stream
│   │   ├── audit/             # Audit logs page
│   │   ├── notifications/     # Alert configuration UI
│   │   ├── scan/              # Deep scan interface
│   │   └── threats/           # 3D interactive WebGL threat map
│   ├── lib/
│   │   ├── audit.ts           # Structured audit logging
│   │   ├── auth.ts            # NextAuth configuration
│   │   ├── db.ts              # Prisma singleton & pool lifecycle
│   │   ├── env.ts             # Runtime environment validation
│   │   ├── heuristics.ts      # Shannon entropy & lexical analysis
│   │   ├── notifications.ts   # Notification dispatcher service
│   │   ├── ssrf.ts            # SSRF protection, DNS validation, pinned transport
│   │   ├── threat-intel.ts    # Threat intelligence matrix & abstention policy
│   │   ├── tls-probe.ts       # Cryptographic TLS handshake & cert verification
│   │   └── webhooks.ts        # Webhook validation, token masking, rate limits
├── tests/
│   ├── auth-isolation.test.ts # Negative authorization & user-scoping tests
│   ├── heuristics.test.ts     # Shannon entropy & lexical heuristic tests
│   ├── ssrf.test.ts           # Comprehensive 20-vector SSRF test suite
│   ├── threat-intel.test.ts   # Threat intelligence semantics & abstention tests
│   ├── tls.test.ts            # TLS certificate verification tests
│   └── webhooks.test.ts       # Webhook pattern matching & rate limit tests
├── package.json               # Package manifest with npm@11.19.0 lockfile
├── SECURITY.md                # Vulnerability disclosure policy & SLAs
└── README.md                  # Project documentation
```

---

## Getting Started

### Prerequisites
- Node.js 20.x or higher
- npm 11.x (`npm -v`)
- PostgreSQL database instance

### Local Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/KatkamKoushik/guardai.git
   cd guardai
   ```

2. **Install dependencies from the clean lockfile:**
   ```bash
   npm ci
   ```

3. **Configure Environment Variables:**
   Copy the example environment configuration into `.env.local`:
   ```bash
   cp .env.example .env.local
   ```
   Configure the following required variables:
   ```env
   DATABASE_URL="postgresql://user:password@localhost:5432/guardai"
   NEXTAUTH_URL="http://localhost:3000"
   NEXTAUTH_SECRET="a-secure-random-secret-string-at-least-32-characters"

   # External Threat Intelligence (Optional — scanner abstains gracefully if omitted)
   VIRUSTOTAL_API_KEY="your-virustotal-api-key"
   GOOGLE_SAFE_BROWSING_API_KEY="your-google-safe-browsing-key"
   ABUSEIPDB_KEY="your-abuseipdb-api-key"
   URLHAUS_KEY="your-urlhaus-api-key"
   ```

4. **Generate Prisma Client & Synchronize Database:**
   ```bash
   npx prisma generate
   npx prisma db push
   ```

5. **Run the Verification Test Suite:**
   ```bash
   npm test
   ```

6. **Start the Development Server:**
   ```bash
   npm run dev
   ```
   Open [http://localhost:3000](http://localhost:3000) to access GuardAI.

---

## 🐳 Docker Container Deployment

GuardAI includes a multi-stage, rootless, production-optimized container setup with automated PostgreSQL orchestration:

```bash
# Build and boot the entire stack (Next.js app + PostgreSQL 16)
docker compose up --build -d

# Check stack liveness and health status
docker compose ps
```

The container runs with non-root security privileges (`nextjs:nodejs` UID 1001) and includes automated healthcheck polling against `/api/ready`.

---

## 🩺 Observability & Health Probes

- **Liveness Probe** (`GET /api/health`): Returns HTTP 200 with runtime diagnostics, process uptime, Node.js version, and RSS/heap memory utilization.
- **Readiness Probe** (`GET /api/ready`): Performs a deep PostgreSQL round-trip ping (`SELECT 1`), returning HTTP 200 when ready and HTTP 503 when disconnected.
- **API Documentation**: Complete OpenAPI 3.1 schema available in [`docs/openapi.yaml`](docs/openapi.yaml).

---

## Available Scripts

| Script | Purpose |
|--------|---------|
| `npm run dev` | Starts Next.js development server with Turbopack. |
| `npm run build` | Builds the optimized production application. |
| `npm run start` | Boots the compiled production server. |
| `npm run typecheck` | Runs TypeScript compiler checks without emitting files (`tsc --noEmit`). |
| `npm test` | Runs the full Vitest security, regression, and unit test suite. |
| `npm run test:coverage` | Generates a test coverage report across all modules. |

---

## Known Limitations & Roadmap

- **External Provider Dependency**: When VirusTotal and Google Safe Browsing API keys are absent, GuardAI abstains with an `INCONCLUSIVE` verdict rather than guessing. Adding API keys activates full multi-engine correlation.
- **RDAP Rate Limits**: RDAP domain age lookups rely on open IANA bootstrap servers, which may rate-limit high-frequency bulk queries.
- **Distributed Rate Limiting**: The current sliding-window rate limiter runs in-process. A planned Redis/Vercel KV adapter is slated for multi-region serverless deployments.

---

## License & Security Contact

- **License**: MIT License (see [LICENSE](LICENSE)).
- **Security Inquiries**: Refer to [SECURITY.md](SECURITY.md) or contact `koushikkatkam@gmail.com`.
