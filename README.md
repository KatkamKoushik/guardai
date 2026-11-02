# GuardAI: Cybersecurity & Threat Intelligence Platform

[![CI Pipeline](https://github.com/KatkamKoushik/guardai/actions/workflows/ci.yml/badge.svg)](https://github.com/KatkamKoushik/guardai/actions/workflows/ci.yml)
[![Next.js](https://img.shields.io/badge/Next.js-16.4.3-black?style=flat-square&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19.2.4-blue?style=flat-square&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-v4-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Vitest & Stress](https://img.shields.io/badge/Vitest-80%20Passed-brightgreen?style=flat-square)](./tests)
[![Playwright E2E](https://img.shields.io/badge/Playwright-11%20Passed-45ba4b?style=flat-square&logo=playwright&logoColor=white)](./e2e)
[![Security Audit](https://img.shields.io/badge/Audit-0%20Vulnerabilities-brightgreen?style=flat-square)](https://github.com/KatkamKoushik/guardai)
[![Docker](https://img.shields.io/badge/Docker-Multi--Stage%20Rootless-2496ED?style=flat-square&logo=docker&logoColor=white)](./Dockerfile)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1.0-6BA539?style=flat-square&logo=openapi-initiative&logoColor=white)](./docs/openapi.yaml)
[![Wiki](https://img.shields.io/badge/Wiki-Documented-informational?style=flat-square&logo=gitbook&logoColor=white)](https://github.com/KatkamKoushik/guardai/wiki)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

GuardAI is an automated threat intelligence, lexical heuristic evaluation, and active cryptographic scanning platform. Designed for security analysts, incident responders, and DevSecOps pipelines, it combines algorithmic URL triage, strict cryptographic network probing, multi-engine reputation intelligence, and 3D WebGL global threat telemetry visualization.

---

## Technical Documentation & Wiki

Detailed technical documentation, architectural deep dives, threat trees, and operational runbooks are published on the [GuardAI GitHub Wiki](https://github.com/KatkamKoushik/guardai/wiki):

* **[Wiki Home](https://github.com/KatkamKoushik/guardai/wiki)**: High-level overview, capabilities map, and operational scorecard.
* **[Architecture & Pipelines](https://github.com/KatkamKoushik/guardai/wiki/Architecture-and-Pipelines)**: Complete sequence diagrams, domain services, and pinned IP transport.
* **[Threat Model & Security](https://github.com/KatkamKoushik/guardai/wiki/Threat-Model-and-Security)**: Trust boundaries, attack trees, SSRF mitigations, and secret redaction.
* **[API & Telemetry Reference](https://github.com/KatkamKoushik/guardai/wiki/API-and-Telemetry-Reference)**: REST schemas, Server-Sent Events (SSE) specs, and health endpoints.
* **[Threat Evaluation Matrix](https://github.com/KatkamKoushik/guardai/wiki/Threat-Evaluation-Matrix)**: 0-100 scoring calibration, confidence tiers, and automated abstention policies.
* **[Deployment & DevOps](https://github.com/KatkamKoushik/guardai/wiki/Deployment-and-DevOps)**: Docker multi-stage builds, rootless container security, and CI workflows.

---

## Architecture & System Map

```mermaid
flowchart TD
    subgraph ClientLayer["Client & Integration Layer"]
        Analyst["Security Analyst / Dashboard UI"]
        DevOps["CI/CD Pipeline / Automation Client"]
    end

    subgraph IngressSecurity["Ingress Sanitization & SSRF Defense"]
        Sanitize["1. Defanged Input Sanitization (hxxp -> http)"]
        LexicalGate["2. Lexical Sanity & Gibberish Filter"]
        DNSCheck["3. Pre-flight DNS Inspection (A & AAAA)"]
        EgressFilter{"Private / Metadata IP?"}
        BlockTarget["400 Bad Request: Egress Blocked"]
        PinTransport["4. Pinned IP Transport Socket"]
    end

    subgraph ParallelInspection["Multi-Dimensional Inspection Engines"]
        TLSProbe["TLS Verification Probe (rejectUnauthorized: true)"]
        GeoIPEngine["MaxMind GeoIP Engine (Offline Local DB)"]
        RDAPEngine["ICANN RDAP Domain Age Resolver"]
        HeadersEngine["HTTP Defensive Headers Analyzer (HSTS, CSP)"]
        ThreatFeeds["Threat Intelligence Feeds (VirusTotal, GSB, AbuseIPDB, URLhaus)"]
        ShannonEntropy["Shannon Entropy & Phishing Lexical Analyzer"]
    end

    subgraph CorrelationEngine["Decision & Persistence Engine"]
        Matrix["Threat Intelligence Aggregation Matrix"]
        AbstentionPolicy{"External Feeds Available?"}
        InconclusiveReport["INCONCLUSIVE Verdict (Abstention)"]
        CalibratedScore["Calibrated Risk Score (0 - 100)"]
        PostgresDB[(PostgreSQL 16 Database)]
        NotificationService["Notification Dispatcher (Discord & Telegram Webhooks)"]
    end

    Analyst --> Sanitize
    DevOps --> Sanitize
    Sanitize --> LexicalGate
    LexicalGate --> DNSCheck
    DNSCheck --> EgressFilter
    EgressFilter -->|Yes: RFC 1918/3927| BlockTarget
    EgressFilter -->|No: Public IP Validated| PinTransport

    PinTransport --> TLSProbe
    PinTransport --> GeoIPEngine
    PinTransport --> RDAPEngine
    PinTransport --> HeadersEngine
    PinTransport --> ThreatFeeds
    PinTransport --> ShannonEntropy

    TLSProbe --> Matrix
    GeoIPEngine --> Matrix
    RDAPEngine --> Matrix
    HeadersEngine --> Matrix
    ThreatFeeds --> Matrix
    ShannonEntropy --> Matrix

    Matrix --> AbstentionPolicy
    AbstentionPolicy -->|No: All Feeds Disabled| InconclusiveReport
    AbstentionPolicy -->|Yes: Correlated Detections| CalibratedScore

    CalibratedScore --> PostgresDB
    InconclusiveReport --> PostgresDB
    CalibratedScore --> NotificationService
```

---

## Scanning Pipeline Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client / Analyst
    participant API as Next.js API Route
    participant SSRF as SSRF & Egress Gate
    participant Recon as Network & TLS Recon
    participant Feeds as Threat Feeds
    participant Matrix as Threat Matrix
    participant DB as PostgreSQL
    participant SSE as Event Stream

    Client->>API: Initiate Scan (URL)
    API->>SSRF: validateTargetForSSRF(url)
    
    alt Target in Private Range / Loopback / Metadata
        SSRF-->>API: Rejected (RFC 1918 / Cloud Metadata Violation)
        API-->>Client: 400 Bad Request
    else Target Validated
        SSRF-->>API: Allowed with Pinned IP
        API->>SSE: Step: Initialization (Complete)
        
        par Parallel Reconnaissance
            API->>Recon: probeTLS(pinnedIp, hostname)
            API->>Recon: lookupGeoIp(pinnedIp)
            API->>Recon: lookupDomainRegistration(hostname)
            API->>Recon: safeFetch(HEAD) & analyzeSecurityHeaders()
            API->>Feeds: collectThreatIntel(url, pinnedIp)
        end

        Recon-->>API: TLS Status, GeoIP, Domain Age, Header Grade
        Feeds-->>API: Provider Detections (VT, GSB, AbuseIPDB, URLhaus)
        API->>SSE: Step: Network Recon & Threat Intel (Progress updates)

        API->>Matrix: evaluateThreatMatrix(evidence)
        Matrix-->>API: Calibrated Verdict & Score

        par Persistence & Dispatch
            API->>DB: Persist Scan Record
            API->>SSE: Step: Complete (Final Result Payload)
        end
        
        API-->>Client: Final Scan Response
    end
```

---

## Core Security Controls & Guarantees

### 1. SSRF and Egress Network Protection (`src/lib/ssrf.ts`)
* **Pre-flight DNS Inspection**: Resolves both `A` and `AAAA` records, rejecting any target that resolves to private (RFC 1918), link-local, carrier-grade NAT (RFC 6598), loopback (`127.0.0.0/8`), or cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`).
* **Alternate IP Format Normalization**: Validates and normalizes decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`), and IPv4-mapped IPv6 (`::ffff:127.0.0.1`) addresses.
* **DNS Rebinding Prevention**: Outbound sockets connect directly to the verified pinned IP address while preserving the canonical `Host` and TLS `servername` headers.
* **Hop-by-Hop Redirect Validation**: All HTTP redirects are inspected manually (`redirect: "manual"`), re-resolving and re-validating the scheme, hostname, port, and IP range at every hop (max 5 hops).
* **Protocol and Port Constraints**: Outbound traffic is restricted strictly to `http:` and `https:` on standard web ports (`80`, `443`, `8080`, `8443`). Credentials in URLs (`user:pass@host`) are rejected.

### 2. Cryptographic TLS/SSL Verification (`src/lib/tls-probe.ts`)
* **Strict Root CA Validation**: TLS connections run with `rejectUnauthorized: true` against the trusted root certificate store. Unauthorized certificates are never reported as valid.
* **Hostname Identity Enforcement**: Uses SNI and SAN verification (`tls.checkServerIdentity`) to ensure certificate subject matches requested hostname.
* **Explicit Status Model**: Accurately categorizes `VALID`, `EXPIRED`, `SELF_SIGNED`, `HOSTNAME_MISMATCH`, `UNTRUSTED_ROOT`, `REVOKED`, `UNENCRYPTED_HTTP`, `TIMEOUT`, and `CONNECTION_REFUSED`.
* **Diagnostic Inspection**: When a certificate fails validation, a secondary inspection captures issuer and expiry metadata strictly for triage display, without marking the result valid.

### 3. Modular Scanner Pipeline (`src/lib/scanner/`)
* **Offline-First GeoIP (`geoip.ts`)**: Embedded MaxMind database lookup executes in 0-2ms with zero external network requests or rate limits.
* **ICANN RDAP Domain Age (`rdap.ts`)**: Queries authoritative registries (Verisign, PIR, ICANN bootstrap) to extract registration dates and flag newly registered domains (<30 days old).
* **Security Headers Analyzer (`security-headers.ts`)**: Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options (`nosniff`), Referrer-Policy, and Permissions-Policy with letter grading (`A` through `F`).
* **Threat Collector (`threat-collector.ts`)**: Multi-provider queries across VirusTotal, Google Safe Browsing, AbuseIPDB, and URLhaus with status isolation.

### 4. Threat Intelligence Semantics & Abstention (`src/lib/threat-intel.ts`)
* **Explicit Provider Status**: Models provider states independently (`clean`, `malicious`, `suspicious`, `not_found`, `timeout`, `quota_exhausted`, `disabled`, `unknown`, `error`).
* **No False Clean Results**: Missing API keys, network timeouts, or "not found" responses are never converted into a "clean" or "safe" result.
* **Automated Abstention Policy**: If all external reputation engines are disabled, the scanner outputs an `INCONCLUSIVE` verdict with explicit disclosures rather than an unsupported clean claim.
* **Evidence Dimensions**: Separates heuristic score, provider detections, TLS status, and network reachability into distinct audit trails.

### 5. Webhook & Integration Destination Safety (`src/lib/webhooks.ts`)
* **Strict Destination Whitelisting**: Discord webhooks are validated against canonical patterns (`https://discord.com/api/webhooks/<id>/<token>`). Arbitrary external URLs are rejected.
* **Telegram Credential Schemas**: Bot tokens and chat IDs are enforced using strict structural schemas.
* **Secret Redaction**: Webhook URLs and bot tokens are masked in API responses and audit logs (`••••••••`).
* **Anti-Abuse Rate Limiting**: Setup and test endpoints enforce sliding-window rate limits (max 5 requests per minute per user).

### 6. Multi-User Tenant Isolation & Database Caching (`src/lib/db.ts`)
* **Hot-Reload Singleton**: Properly caches the PrismaClient and pg pool across development HMR cycles, preventing pool exhaustion.
* **Graceful Shutdown**: Hooks `SIGINT`, `SIGTERM`, and `beforeExit` to disconnect database pools cleanly.
* **User Scoping**: Scans, audit logs, and notification integrations are strictly scoped to verified user sessions with deny-by-default authorization.

---

## Repository Structure

```
guardai/
├── .github/workflows/
│   └── ci.yml                 # Clean-lockfile CI pipeline (lint, typecheck, test, build)
├── docs/
│   ├── openapi.yaml           # OpenAPI 3.1.0 API specification
│   ├── THREAT_MODEL.md        # Comprehensive product threat model & attack trees
│   ├── INCIDENT_RUNBOOK.md    # Incident playbooks (SSRF, credential leak, provider outage)
│   └── wiki/                  # Offline mirror of GitHub Wiki technical documentation
├── prisma/
│   ├── schema.prisma          # Database schema (User, Scan, Notification, ThreatTelemetry)
│   └── prisma.config.ts       # Prisma runtime configuration
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── alerts/        # Alert channel configuration & test endpoints
│   │   │   ├── audit/         # Authenticated audit log API
│   │   │   ├── cron/ingest/   # URLhaus threat feed ingestion
│   │   │   ├── health/        # Container liveness probe endpoint
│   │   │   ├── notifications/ # Secure sample notification dispatcher
│   │   │   ├── ready/         # Database readiness probe endpoint
│   │   │   ├── scan/          # Synchronous & real-time SSE scan endpoints
│   │   │   └── telemetry/     # Real-time threat feed & SSE stream
│   │   ├── audit/             # Audit logs page
│   │   ├── notifications/     # Alert configuration UI
│   │   ├── scan/              # Deep scan interface
│   │   └── threats/           # 3D interactive WebGL threat map
│   ├── lib/
│   │   ├── audit.ts           # Structured audit logging
│   │   ├── auth.ts            # NextAuth configuration
│   │   ├── db.ts              # Prisma singleton & pg connection pool lifecycle
│   │   ├── env.ts             # Runtime environment validation
│   │   ├── heuristics.ts      # Shannon entropy & lexical analysis
│   │   ├── notifications.ts   # Notification dispatcher service
│   │   ├── scanner/           # Modular scanning services (GeoIP, RDAP, Headers, Feeds)
│   │   ├── ssrf.ts            # SSRF protection, DNS validation, pinned transport
│   │   ├── threat-intel.ts    # Threat intelligence matrix & abstention policy
│   │   ├── tls-probe.ts       # Cryptographic TLS handshake & cert verification
│   │   └── webhooks.ts        # Webhook validation, token masking, rate limits
├── tests/
│   ├── auth-isolation.test.ts # Negative authorization & user-scoping tests
│   ├── health.test.ts         # Liveness and readiness probe tests
│   ├── heuristics.test.ts     # Shannon entropy & lexical heuristic tests
│   ├── scanner.test.ts        # Modular GeoIP, RDAP, and header analyzer tests
│   ├── ssrf.test.ts           # Comprehensive 20-vector SSRF test suite
│   ├── threat-intel.test.ts   # Threat intelligence semantics & abstention tests
│   ├── tls.test.ts            # TLS certificate verification tests
│   └── webhooks.test.ts       # Webhook pattern matching & rate limit tests
├── .dockerignore              # Docker build context exclusions
├── Dockerfile                 # Multi-stage rootless container build
├── docker-compose.yml         # Application and PostgreSQL orchestration
├── CONTRIBUTING.md            # Contribution guidelines & coding standards
├── CODE_OF_CONDUCT.md        # Contributor Covenant v2.1
├── SECURITY.md                # Vulnerability disclosure policy & SLAs
├── package.json               # Package manifest with npm@11.19.0 lockfile
└── README.md                  # Project documentation
```

---

## Getting Started

### Prerequisites
* Node.js 22.x LTS
* npm 11.x (`npm -v`)
* PostgreSQL 16 database instance

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

## Docker Container Deployment

GuardAI includes a 4-stage, rootless, production-optimized container setup with automated PostgreSQL orchestration:

```bash
# Build and boot the entire stack (Next.js app + PostgreSQL 16)
docker compose up --build -d

# Check stack liveness and health status
docker compose ps
```

The container runs with non-root security privileges (`nextjs:nodejs` UID 1001) and includes automated healthcheck polling against `/api/ready`.

---

## Observability & Health Probes

* **Liveness Probe** (`GET /api/health`): Returns HTTP 200 with runtime diagnostics, process uptime, Node.js version, and RSS/heap memory utilization.
* **Readiness Probe** (`GET /api/ready`): Performs a deep PostgreSQL round-trip ping (`SELECT 1`), returning HTTP 200 when ready and HTTP 503 when disconnected.
* **API Documentation**: Complete OpenAPI 3.1.0 schema available in [`docs/openapi.yaml`](docs/openapi.yaml).

---

## Available Scripts

| Script | Purpose |
| :--- | :--- |
| `npm run dev` | Starts Next.js development server with Turbopack. |
| `npm run build` | Builds the optimized production application. |
| `npm run start` | Boots the compiled production server. |
| `npm run typecheck` | Runs TypeScript compiler checks without emitting files (`tsc --noEmit`). |
| `npm test` | Runs the full Vitest security, regression, and unit test suite (80 tests). |
| `npm run test:stress` | Runs the concurrency, rate-limit burst, and SSRF stress benchmarks. |
| `npm run test:e2e` | Runs the 11-test Playwright end-to-end browser suite. |
| `npm run test:coverage` | Generates a test coverage report across all modules. |

---

## Known Limitations & Roadmap

* **External Provider Dependency**: When VirusTotal and Google Safe Browsing API keys are absent, GuardAI abstains with an `INCONCLUSIVE` verdict rather than guessing. Adding API keys activates full multi-engine correlation.
* **RDAP Rate Limits**: RDAP domain age lookups rely on open IANA bootstrap servers, which may rate-limit high-frequency bulk queries.
* **Distributed Rate Limiting**: The current sliding-window rate limiter runs in-process. A planned Redis/Vercel KV adapter is slated for multi-region serverless deployments.

---

## License & Security Contact

* **License**: MIT License (see [LICENSE](LICENSE)).
* **Security Inquiries**: Refer to [SECURITY.md](SECURITY.md) or contact `koushikkatkam@gmail.com`.
