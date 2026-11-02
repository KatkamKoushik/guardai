# GuardAI Incident Response Runbook

This document outlines the standard operational playbooks for addressing critical security and reliability incidents in GuardAI.

---

## Runbook 1: SSRF / Internal Network Probing Report

### Severity: P0 / Critical
**Symptoms / Triggers:**
- User or external security researcher reports an SSRF bypass reaching an internal IP, cloud metadata (`169.254.169.254`), or DNS rebinding exploit.
- Egress monitoring alerts indicating requests destined for RFC 1918 or link-local subnets.

### Immediate Containment Steps:
1. **Identify the Bypass Vector:**
   - Review incoming target URL in audit logs (`AuditLog` table).
   - Check if bypass used IPv6 encoding, octal/hex notation, DNS rebinding, CNAME chaining, or redirect hops.
2. **Immediate Egress Blocking:**
   - If running in cloud (AWS/GCP/Vercel/Railway), ensure cloud provider metadata protection is enabled (e.g. IMDSv2 with hop limit = 1).
   - Verify network firewall egress rules block outbound connections from application workers to RFC 1918 and `169.254.0.0/16`.
3. **Application Patching:**
   - Add the specific bypass pattern to `BLOCKED_HOST_PATTERNS` or `isDisallowedIP()` in `src/lib/ssrf.ts`.
   - Write a regression test in `tests/ssrf.test.ts`.
   - Run `npm test` and deploy immediately.
4. **Post-Incident Analysis:**
   - Inspect whether any internal services responded or leaked credentials.
   - Rotate database credentials and cloud tokens if metadata access was confirmed.

---

## Runbook 2: Compromised Integration Webhook / Bot Token

### Severity: P1 / High
**Symptoms / Triggers:**
- Discord webhook or Telegram bot token reported leaked or misused for spam.
- Abnormal outbound traffic rate from `/api/alerts/test`.

### Immediate Containment Steps:
1. **Disable Affected Channel:**
   - In database:
     ```sql
     UPDATE "Notification" SET "isActive" = false WHERE "id" = '<notification_id>';
     ```
2. **Revoke Upstream Token:**
   - If GuardAI's internal bot token leaked: Revoke immediately in Telegram BotFather (`/revoke`) or Discord Developer Portal.
   - If user's webhook leaked: Advise user to delete the webhook channel in their Discord server settings and regenerate.
3. **Audit Outbound History:**
   - Query `AuditLog` where `action = 'DEEP_SCAN'` or alert dispatches for abnormal destinations.
4. **Verify Masking Controls:**
   - Ensure logs, error messages, and API responses never output raw tokens (`validateDiscordWebhookUrl` and `validateTelegramConfig` must mask tokens).

---

## Runbook 3: External Threat Intelligence Provider Outage

### Severity: P2 / Medium
**Symptoms / Triggers:**
- VirusTotal or Google Safe Browsing API returns 5xx errors or persistent timeouts.
- Provider quota exhausted (HTTP 429).

### Operational Procedure:
1. **Verify Fallback & Abstention Behavior:**
   - Verify scanner automatically records status as `timeout`, `quota_exhausted`, or `error` in `ProviderReport`.
   - Ensure scanner **NEVER** marks target as `clean` when providers fail.
   - If both providers are offline, ensure verdict degrades gracefully to `INCONCLUSIVE` (abstention policy).
2. **Quota Management:**
   - If HTTP 429: Verify whether scan volume exceeded current API tier.
   - Temporarily increase provider timeouts or rely on GuardAI lexical heuristics until quota resets.
3. **Status Communication:**
   - Check provider status pages (status.virustotal.com, googlecloudstatus.com).

---

## Runbook 4: False-Safe Result Triage (Reported Phishing Site Flagged Safe)

### Severity: P1 / High
**Symptoms / Triggers:**
- A known active phishing or credential-harvesting site was scanned and assigned a "SAFE" verdict.

### Investigation & Remediation Steps:
1. **Retrieve Scan Details:**
   - Query `Scan` record by URL in Prisma:
     ```ts
     await prisma.scan.findFirst({ where: { url: targetUrl } });
     ```
   - Check individual dimension scores:
     - Were external providers enabled and clean?
     - What was the lexical probability score?
     - What was the TLS certificate status?
2. **Calibrate Lexical Features:**
   - If the phishing domain used a newly registered brand imitation or unseen keyword:
     - Add brand to `BRAND_NAMES` in `src/lib/heuristics.ts`.
     - Add keyword to `SUSPICIOUS_KEYWORDS`.
     - Check entropy and subdomain depth.
3. **Regression Test Addition:**
   - Add the false-safe URL to `tests/heuristics.test.ts`.
   - Verify the calibrated probability score is >= 60 (flagged).
4. **Deploy & Re-scan:**
   - Re-run scan to confirm verdict now indicates `SUSPICIOUS` or `CRITICAL`.

