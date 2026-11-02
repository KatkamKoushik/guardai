# Security Policy

GuardAI takes the security of its infrastructure, scanners, and user integrations seriously. As a cybersecurity and threat intelligence platform, maintaining strict standards of integrity, confidentiality, and operational security across our probing pipeline and alert infrastructure is paramount.

---

## 1. Supported Versions

Active security updates and vulnerability patches are maintained for:

| Version | Supported | Notes |
| ------- | --------- | ----- |
| 1.0.x   | Yes       | Current active stable release |
| < 1.0   | No        | Deprecated |

---

## 2. Threat Model & Security Controls

GuardAI operates under an explicit threat model documented in detail at [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md):

- **SSRF Defense-in-Depth**:
  - Resolves both `A` and `AAAA` DNS records before outbound connection.
  - Rejects all private, loopback, link-local, multicast, reserved, and cloud metadata ranges (`169.254.169.254`, `100.100.100.200`).
  - Pins destination IP address during socket/HTTP connections to defeat DNS-rebinding attacks.
  - Re-validates every redirect hop (`Location` header) across scheme, port, hostname, and resolved IP ranges (max 5 hops).
  - Restricts schemes strictly to `http:` and `https:`, blocking user credentials in URLs.
- **Cryptographic TLS Verification**:
  - Validates full certificate chain against trusted root CAs with `rejectUnauthorized: true`.
  - Verifies hostname identity via SNI and SAN verification.
  - Enforces strict validity dates (`valid_from` <= now <= `valid_to`).
  - Never marks unauthorized, expired, self-signed, or mismatched certificates as valid.
- **Webhook & Alert Safety**:
  - Discord webhooks strictly constrained to `discord.com`/`discordapp.com` canonical endpoint patterns.
  - Telegram bot tokens and chat IDs validated against strict numeric/token schemas.
  - Arbitrary URL fetching is strictly prohibited.
  - Secret tokens are masked in client responses, logs, and error envelopes.
- **Threat Intelligence Integrity**:
  - Explicit status model: `clean`, `malicious`, `suspicious`, `not_found`, `timeout`, `quota_exhausted`, `disabled`, `unknown`, `error`.
  - Provider errors or absent API keys are never treated as "clean".
  - Enforces an automated abstention policy (`INCONCLUSIVE` verdict) when reputation evidence is unavailable.

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability in GuardAI, please report it via private disclosure. **Do not create public GitHub issues for security vulnerabilities.**

### Contact:
- **Security Lead:** `koushikkatkam@gmail.com`
- **Subject Line:** `[VULNERABILITY REPORT] GuardAI - <Brief Description>`

### Please include:
1. Attack vector classification (e.g., SSRF, TLS validation bypass, authentication bypass, BOLA, injection).
2. Step-by-step reproduction instructions or proof-of-concept.
3. Affected components, routes, or files.
4. Assessed impact and CVSS v3.1 vector if known.

---

## 4. Vulnerability Triage & SLA Commitments

| Severity | Definition | Initial Response SLA | Target Remediation SLA |
|----------|------------|----------------------|------------------------|
| **P0 (Critical)** | SSRF reaching internal networks, remote code execution, secret key exposure, auth bypass. | ≤ 24 hours | ≤ 48 hours |
| **P1 (High)** | False-safe threat verdicts, destination spoofing in webhooks, cross-user data access. | ≤ 48 hours | ≤ 5 business days |
| **P2 (Medium)** | Rate-limiting bypass, informative error leaks, denial of service on public endpoints. | ≤ 72 hours | ≤ 14 business days |
| **P3 (Low)** | Minor configuration discrepancies, documentation omissions. | ≤ 5 business days | Next release cycle |

---

## 5. Responsible Disclosure & Safe Harbor

We commit to:
- Acknowledging receipt of your report within the stated SLAs.
- Providing an estimated timeline for the fix and keeping you updated on remediation progress.
- Publicly crediting you in release notes upon patch deployment (unless anonymity is requested).
- Operating under safe harbor: We will not pursue legal action against researchers who discover and report vulnerabilities responsibly, avoid data destruction, and do not access or expose other users' data.
