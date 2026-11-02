# Deployment & DevOps

GuardAI is containerized using a 4-stage multi-stage Docker build, orchestrated with Docker Compose, and verified by an automated CI/CD pipeline on every commit.

---

## Container Build Pipeline

```mermaid
flowchart LR
    subgraph Stage1["Stage 1: Base"]
        BaseNode["node:22-alpine<br/>libc6-compat + openssl + curl"]
    end

    subgraph Stage2["Stage 2: Deps"]
        NpmCI["npm ci<br/>Clean lockfile install"]
    end

    subgraph Stage3["Stage 3: Builder"]
        PrismaGen["npx prisma generate"]
        NextBuild["npm run build<br/>Turbopack production build"]
    end

    subgraph Stage4["Stage 4: Runner"]
        NonRootUser["User: nextjs (UID 1001)"]
        DistCopy["Static Assets + .next"]
        Healthcheck["HEALTHCHECK: /api/health"]
    end

    Stage1 --> Stage2
    Stage2 --> Stage3
    Stage3 --> Stage4
```

---

## Docker Compose Quickstart

The entire platform, including database and background adapters, can be spun up with a single command:

```bash
# Clone the repository
git clone https://github.com/KatkamKoushik/guardai.git
cd guardai

# Build and start services in background
docker compose up --build -d

# Check running status and health probe
docker compose ps
```

### Container Services

| Service | Image | Internal Port | External Port | Healthcheck |
| :--- | :--- | :---: | :---: | :--- |
| **`guardai-app`** | Custom Multi-Stage | `3000` | `3000` | `curl -f http://localhost:3000/api/ready` |
| **`guardai-db`** | `postgres:16-alpine` | `5432` | `5432` | `pg_isready -U guardai_user -d guardai_db` |

---

## Continuous Integration (`.github/workflows/ci.yml`)

Every push to `master`, `main`, `feature/**`, and `docs/**` (as well as pull requests) triggers an automated multi-job pipeline:

```mermaid
flowchart LR
    subgraph Job1["Job 1: Security & Typecheck"]
        Audit["npm audit --audit-level=high"]
        Typecheck["npm run typecheck"]
    end

    subgraph Job2["Job 2: Unit & Stress Suite"]
        Vitest["Vitest Suite (80 Tests)<br/>SSRF, Heuristics, Stress"]
    end

    subgraph Job3["Job 3: Production Build"]
        Build["npm run build<br/>27 App Router Routes"]
    end

    subgraph Job4["Job 4: End-to-End Tests"]
        Playwright["Playwright Chromium (11 Tests)<br/>Health, Scan, Navigation"]
    end

    Job1 --> Job3
    Job3 --> Job4
```

### Pipeline Jobs Breakdown

1. **Security Audit & Typecheck:** Clean lockfile dependency check (`npm audit --audit-level=high`) and strict zero-error TypeScript validation (`tsc --noEmit`).
2. **Unit, Regression & Stress Suite:** Parallel execution of 80 tests covering SSRF loopback protections, Shannon entropy calculation, cryptographic TLS verification, constant-time compare, and concurrency bursts (500 security header checks, 100 concurrent SSRF queries).
3. **Optimized Production Build:** Full Turbopack compilation verifying zero build errors, asset compilation, and route generation across all 27 routes.
4. **Playwright End-to-End Suite:** Spin-up of production server on port 3000, Chromium browser execution, API health and readiness validation, SSRF boundary blocking, and client page navigation.
