# Architecture & Pipelines

GuardAI decomposes URL threat assessment into deterministic, modular pipeline stages. By decoupling network recon, cryptographic verification, reputation correlation, and client streaming, the system prevents single-point failures and maintains sub-second responsiveness.

---

## Scanning Pipeline Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Client as Security Analyst / Client
    participant GW as Next.js API Gateway
    participant SSRF as SSRF & Egress Controller
    participant DNS as DNS Resolver (getaddrinfo)
    participant TLS as Cryptographic TLS Probe
    participant Recon as Recon (GeoIP / RDAP / Headers)
    participant Feeds as Threat Intel Feeds (VT/GSB)
    participant Matrix as Threat Aggregation Matrix
    participant DB as PostgreSQL (Prisma)
    participant Alerts as Notification Dispatcher

    Client->>GW: POST /api/scan or GET /api/scan/stream?url=...
    GW->>GW: Refang (hxxp -> http) & Lexical Check
    GW->>SSRF: validateTargetForSSRF(url)
    SSRF->>DNS: Pre-flight DNS Lookup (A & AAAA)
    DNS-->>SSRF: Resolved Public IPs

    alt Private / Reserved / Metadata IP Detected
        SSRF-->>GW: Blocked (RFC 1918 / 3927 Egress Violation)
        GW-->>Client: 400 Bad Request (SSRF Rejection)
    else Public IP Validated
        SSRF-->>GW: Egress Allowed (Pinned IP Transport)
        
        par Parallel Reconnaissance
            GW->>TLS: probeTLS(hostname, pinnedIp)
            GW->>Recon: lookupGeoIp(pinnedIp) & lookupDomainRegistration(hostname)
            GW->>Recon: safeFetch(HEAD) & analyzeSecurityHeaders()
            GW->>Feeds: collectThreatIntel(url, pinnedIp)
        end

        TLS-->>GW: TLS Status (rejectUnauthorized: true, SAN/SNI)
        Recon-->>GW: GeoIP (City/ASN), RDAP (Age/Registrar), Headers (Grade)
        Feeds-->>GW: Provider Reports (VirusTotal, Safe Browsing, AbuseIPDB)

        GW->>Matrix: evaluateThreatMatrix(evidence)
        Matrix-->>GW: Verdict, Score (0-100), Confidence, Action

        par Asynchronous Persistence & Alerting
            GW->>DB: prisma.scan.create(details)
            opt Score >= 50 (High / Critical)
                GW->>Alerts: notifyUserForScan(Discord / Telegram)
            end
        end

        GW-->>Client: Complete Scan Report (SSE Stream / JSON Response)
    end
```

---

## Pipeline Modularization

All domain logic resides in dedicated services under `src/lib/`:

```mermaid
flowchart LR
    subgraph ScannerPackage["src/lib/scanner/"]
        GEO["geoip.ts<br/>(MaxMind Offline)"]
        RDAP["rdap.ts<br/>(ICANN Resolver)"]
        HDR["security-headers.ts<br/>(Defensive Grading)"]
        TC["threat-collector.ts<br/>(Multi-Engine Feeds)"]
    end

    subgraph SecurityCore["src/lib/"]
        SSRF["ssrf.ts<br/>(SSRF & Egress Gate)"]
        TLS["tls-probe.ts<br/>(Root CA Probe)"]
        HEX["heuristics.ts<br/>(Shannon Entropy)"]
        MAT["threat-intel.ts<br/>(Evidence Matrix)"]
    end

    GEO --> MAT
    RDAP --> MAT
    HDR --> MAT
    TC --> MAT
    SSRF --> ScannerPackage
    TLS --> MAT
    HEX --> MAT
```

### 1. SSRF & Egress Controller (`src/lib/ssrf.ts`)
* **DNS Pinning:** Resolves public IPs prior to socket initialization. Connects directly to the verified IP to defeat DNS rebinding attacks.
* **Hop-by-Hop Redirect Validation:** Enforces `redirect: "manual"` across all outgoing requests, inspecting each redirect destination against IP blocklists (up to 5 hops).

### 2. Cryptographic TLS Probe (`src/lib/tls-probe.ts`)
* **Root CA Validation:** Always sets `rejectUnauthorized: true`. Self-signed or untrusted certificates are reported as `valid: false`.
* **Identity Check:** Validates Subject Alternative Names (SAN) against the target hostname via `tls.checkServerIdentity`.

### 3. ICANN RDAP & Domain Age (`src/lib/scanner/rdap.ts`)
* **Registry Integration:** Queries authoritative RDAP registries (Verisign, PIR, ICANN bootstrap).
* **Domain Age Calculation:** Computes age in days and years. Flags newly registered domains (<30 days old) as high-risk phishing candidates.

### 4. Offline-First GeoIP (`src/lib/scanner/geoip.ts`)
* **Zero-Latency Lookup:** Uses local MaxMind database (`geoip-lite`) to resolve country, city, and coordinates in 0-2ms with zero external network dependency.
* **Enrichment Fallback:** Enriches Autonomous System Number (ASN) and ISP data via low-latency external API with fail-soft error handling.
