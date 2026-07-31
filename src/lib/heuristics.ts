/**
 * GuardAI — Lexical Heuristics Engine v2
 *
 * A fully dynamic, algorithmic URL analysis engine that runs on every scan
 * regardless of whether external APIs are available. No CSV. No mock data.
 * Every signal is derived live from the input string.
 *
 * Exported surface:
 *   analyzeURL(urlStr)  → HeuristicResult
 *   isGibberish(input)  → boolean   (used by route validators)
 */

// ---------------------------------------------------------------------------
// 1. Shannon Entropy — measures randomness / obfuscation of character set
// ---------------------------------------------------------------------------
export function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const c = str[i];
    freq[c] = (freq[c] ?? 0) + 1;
  }
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ---------------------------------------------------------------------------
// 2. Gibberish / Invalid Input Detection
//    Returns true if the string is unlikely to be a real domain or URL.
//    A valid hostname must contain at least one dot and a recognisable TLD.
// ---------------------------------------------------------------------------
export function isGibberish(input: string): boolean {
  if (!input || typeof input !== "string") return true;

  // Strip protocol so we can inspect the raw hostname candidate
  const stripped = input
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/^\/\//, "")
    .split("/")[0]   // drop path
    .split("?")[0]   // drop query
    .split("#")[0];  // drop fragment

  // Check if it's a valid IPv4 or IPv6 (including brackets for IPv6)
  const ipv4Re = /^(?:\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
  const ipv6Re = /^\[?[0-9a-fA-F:]+\]?(:\d+)?$/;
  if (ipv4Re.test(stripped) || (stripped.includes(":") && ipv6Re.test(stripped))) {
    return false; // Valid IP address is not gibberish
  }

  // Must contain at least one dot (otherwise it's not a FQDN)
  if (!stripped.includes(".")) return true;

  // Labels must be non-empty and only contain valid hostname chars
  const labels = stripped.split(".");
  const validLabel = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$/i;
  for (const label of labels) {
    if (!label || !validLabel.test(label)) return true;
  }

  // TLD must be ≥ 2 chars and only letters (or xn-- for punycode)
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/i.test(tld) && !/^xn--/i.test(tld)) return true;

  // Minimum host length check — "a.io" is 4 chars and valid
  if (stripped.length < 4) return true;

  return false;
}

// ---------------------------------------------------------------------------
// 3. Lexical Feature Constants
// ---------------------------------------------------------------------------

/** Words overwhelmingly associated with phishing lure pages */
const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "sign-in", "logon", "log-on",
  "secure", "security", "account", "accounts",
  "verify", "verification", "validate", "validation",
  "update", "upgrade", "confirm", "confirmation",
  "bank", "banking", "wallet", "invoice", "billing",
  "paypal", "apple", "amazon", "microsoft", "google",
  "netflix", "instagram", "facebook", "support",
  "helpdesk", "admin", "webmail", "cpanel", "password",
  "credential", "auth", "oauth", "token", "free",
  "lucky", "winner", "prize", "urgent", "alert",
  "suspended", "limited", "unusual", "activity",
];

/** High-risk TLDs that are disproportionately used in abuse */
const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq",     // Freenom abuse magnets
  "xyz", "top", "club", "online",    // cheap/abused
  "ru", "cn", "pw", "cc",            // frequent phishing registries
  "icu", "monster", "cyou", "bond",  // frequently abused new gTLDs
]);

/** Known brand strings to detect typosquatting in the domain/path */
const BRAND_NAMES = [
  "paypal", "apple", "amazon", "microsoft", "google",
  "facebook", "instagram", "netflix", "chase", "wellsfargo",
  "citibank", "bankofamerica", "steam", "discord", "binance",
];

// Number→letter substitutions used in typosquatting (e.g. "g00gle")
const NUMBER_SUBSTITUTION_RE = /[0-9]/;
// Detect punycode/IDN encoding in the label
const PUNYCODE_RE = /xn--/i;
// Detect data: and javascript: URIs
const DANGEROUS_SCHEME_RE = /^(data|javascript|vbscript):/i;

// ---------------------------------------------------------------------------
// 4. Public Result Type
// ---------------------------------------------------------------------------
export interface HeuristicResult {
  /** Shannon entropy of the hostname */
  entropy: number;
  /** True if hostname is a raw IPv4/IPv6 address */
  hasIP: boolean;
  /** Total URL character length */
  length: number;
  /** Number of subdomain labels beyond the base domain */
  subdomainCount: number;
  /** Count of matched suspicious keywords */
  suspiciousWordsCount: number;
  /** Ratio of special chars to total URL length */
  specialCharRatio: number;
  /** Phishing probability 0–100 */
  probability: number;
  /** Human-readable signal descriptions */
  flags: string[];
}

// ---------------------------------------------------------------------------
// 5. Main Analysis Function
// ---------------------------------------------------------------------------
export function analyzeURL(urlStr: string): HeuristicResult {
  const flags: string[] = [];

  // --- Dangerous scheme fast-exit ---
  if (DANGEROUS_SCHEME_RE.test(urlStr.trim())) {
    return {
      entropy: 8,
      hasIP: false,
      length: urlStr.length,
      subdomainCount: 0,
      suspiciousWordsCount: 0,
      specialCharRatio: 0,
      probability: 100,
      flags: ["Dangerous URI scheme (data: / javascript:)"],
    };
  }

  let url: URL;
  try {
    const normalized =
      urlStr.startsWith("http://") || urlStr.startsWith("https://")
        ? urlStr
        : `https://${urlStr}`;
    url = new URL(normalized);
  } catch {
    return {
      entropy: 0,
      hasIP: false,
      length: urlStr.length,
      subdomainCount: 0,
      suspiciousWordsCount: 0,
      specialCharRatio: 0,
      probability: 100,
      flags: ["Invalid URL structure"],
    };
  }

  const hostname  = url.hostname.toLowerCase();
  const fullUrl   = urlStr.toLowerCase();
  const path      = url.pathname + url.search;
  const length    = urlStr.length;

  // ── Signal: Dangerous scheme in effective URL ──────────────────────────
  if (DANGEROUS_SCHEME_RE.test(url.protocol)) {
    flags.push("Dangerous URI scheme detected");
  }

  // ── Signal: URL Length ─────────────────────────────────────────────────
  if (length > 100) flags.push("Excessive URL length (>100 chars)");
  else if (length > 75) flags.push("Long URL (>75 chars)");

  // ── Signal: Shannon Entropy ────────────────────────────────────────────
  const entropy = calculateEntropy(hostname);
  if (entropy > 4.5) flags.push(`Very high domain entropy (${entropy.toFixed(2)}) — likely auto-generated`);
  else if (entropy > 4.0) flags.push(`Elevated domain entropy (${entropy.toFixed(2)}) — potential obfuscation`);

  // ── Signal: Raw IP Address as Hostname ────────────────────────────────
  const ipv4Re = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const hasIP  = ipv4Re.test(hostname) || hostname === "[::1]";
  if (hasIP) flags.push("IP address used as hostname (no domain name)");

  // ── Signal: Subdomains ────────────────────────────────────────────────
  const parts = hostname.split(".");
  const subdomainCount = Math.max(0, parts.length - 2);
  if (subdomainCount > 3) flags.push(`Excessive subdomain depth (${subdomainCount} levels)`);
  else if (subdomainCount > 2) flags.push(`Multiple subdomains detected (${subdomainCount} levels)`);

  // ── Signal: Hyphen Count ──────────────────────────────────────────────
  const hyphenCount = (hostname.match(/-/g) ?? []).length;
  if (hyphenCount > 4) flags.push(`Excessive hyphens in domain (${hyphenCount}) — common in phishing`);
  else if (hyphenCount > 2) flags.push(`Multiple hyphens in domain (${hyphenCount})`);

  // ── Signal: Punycode / IDN Homograph Attack ───────────────────────────
  if (PUNYCODE_RE.test(hostname)) {
    flags.push("Punycode/IDN encoding detected — possible homograph attack");
  }

  // ── Signal: Number Substitution (g00gle, paypa1) ──────────────────────
  const domainBody = parts.slice(0, -1).join(".");  // strip TLD
  if (NUMBER_SUBSTITUTION_RE.test(domainBody)) {
    flags.push("Digits in domain name — possible leet-speak brand impersonation");
  }

  // ── Signal: Suspicious TLD ────────────────────────────────────────────
  const tld = parts[parts.length - 1];
  if (SUSPICIOUS_TLDS.has(tld)) {
    flags.push(`Suspicious TLD ".${tld}" — high abuse frequency`);
  }

  // ── Signal: @ Symbol (credential masking) ─────────────────────────────
  if (fullUrl.includes("@")) {
    flags.push('Contains "@" — potential credential masking (user@host trick)');
  }

  // ── Signal: Suspicious Keywords in Domain ─────────────────────────────
  // Identify if the domain is legitimately owned by one of our tracked brands
  const matchedLegitBrand = BRAND_NAMES.find(brand => 
    hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`)
  );

  let suspiciousWordsCount = 0;
  const matchedKeywords: string[] = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (hostname.includes(kw)) {
      // Prevent brand keyword false positives on legitimate root domains
      if (matchedLegitBrand === kw) {
        continue;
      }
      suspiciousWordsCount++;
      matchedKeywords.push(kw);
    }
  }
  if (suspiciousWordsCount > 0) {
    flags.push(
      `Contains ${suspiciousWordsCount} phishing keyword${suspiciousWordsCount > 1 ? "s" : ""} in domain: ${matchedKeywords.slice(0, 5).join(", ")}`
    );
  }

  // ── Signal: Suspicious Path Tokens ────────────────────────────────────
  const PATH_SUSPICIOUS_KEYWORDS = ["phish", "malicious", "login", "verify", "account-update", "credential", "pay"];
  const pathTokens = path.split(/[\/\-_\.=&?]/).filter(Boolean);
  let pathSuspiciousCount = 0;
  const pathMatchedKeywords: string[] = [];
  
  for (const token of pathTokens) {
    const lowerToken = token.toLowerCase();
    for (const kw of PATH_SUSPICIOUS_KEYWORDS) {
      if (lowerToken.includes(kw) && !pathMatchedKeywords.includes(kw)) {
        pathSuspiciousCount++;
        pathMatchedKeywords.push(kw);
      }
    }
  }
  if (pathSuspiciousCount > 0) {
    flags.push(`Suspicious path keywords detected: ${pathMatchedKeywords.join(", ")}`);
  }

  // ── Signal: Brand Typosquatting ───────────────────────────────────────
  for (const brand of BRAND_NAMES) {
    // The brand string appears in the domain but is NOT the registered domain
    if (hostname.includes(brand) && !hostname.endsWith(`.${brand}.com`) && hostname !== `${brand}.com`) {
      flags.push(`Domain impersonates brand "${brand}" (typosquatting)`);
      break;
    }
  }

  // ── Signal: Special Character Ratio ──────────────────────────────────
  const specialMatches = fullUrl.match(/[-@?=_%&#!~]/g) ?? [];
  const specialCharRatio = specialMatches.length / length;
  if (specialCharRatio > 0.15) flags.push("Very high special-character ratio (>15%)");
  else if (specialCharRatio > 0.1) flags.push("High special-character ratio (>10%)");

  // ── Signal: Excessive Path Depth ─────────────────────────────────────
  const pathDepth = path.split("/").filter(Boolean).length;
  if (pathDepth > 5) flags.push(`Deep URL path (${pathDepth} segments) — common in obfuscated redirects`);

  // ── Signal: Hexadecimal / Percent-Encoded Hostname ────────────────────
  if (/%[0-9a-f]{2}/i.test(hostname)) {
    flags.push("Percent-encoded characters in hostname — potential obfuscation");
  }

  // ── Signal: Double Slash in Path (open redirect) ──────────────────────
  const pathOnly = url.pathname;
  if (pathOnly.includes("//")) {
    flags.push("Double slash in path — possible open redirect");
  }

  // ── Signal: Common File Extensions Known for Malware Delivery ─────────
  const malwareExts = /\.(exe|bat|cmd|ps1|vbs|js|jar|msi|dmg|sh|hta|scr|pif|cpl)(\?|#|$)/i;
  if (malwareExts.test(path)) {
    flags.push("URL points to a potentially executable file");
  }

  // ── Signal: Redirect Keywords ──────────────────────────────────────────
  if (/[?&](redirect|redir|url|next|goto|return|returnurl|r)=/i.test(path)) {
    flags.push("Open redirect parameter detected in query string");
  }

  // ---------------------------------------------------------------------------
  // 6. Weighted Score Calculation (0 → 100)
  // ---------------------------------------------------------------------------
  let score = 0;

  // Hard signals
  if (hasIP)                         score += 40;
  if (fullUrl.includes("@"))         score += 30;
  if (PUNYCODE_RE.test(hostname))    score += 25;
  if (SUSPICIOUS_TLDS.has(tld))      score += 20;
  if (malwareExts.test(path))        score += 35;

  // Entropy signals
  if (entropy > 4.5)                 score += 25;
  else if (entropy > 4.0)            score += 12;

  // Length signals
  if (length > 100)                  score += 15;
  else if (length > 75)              score += 8;

  // Structural signals
  if (subdomainCount > 3)            score += 20;
  else if (subdomainCount > 2)       score += 10;

  if (hyphenCount > 4)               score += 15;
  else if (hyphenCount > 2)          score += 7;

  if (NUMBER_SUBSTITUTION_RE.test(domainBody)) score += 10;
  if (pathDepth > 5)                 score += 8;
  if (path.includes("//"))           score += 10;
  if (/%[0-9a-f]{2}/i.test(hostname)) score += 15;

  // Keyword / brand signals
  score += Math.min(suspiciousWordsCount * 12, 40);
  if (pathSuspiciousCount > 0) score += Math.min(pathSuspiciousCount * 15, 30);

  // Brand typosquat — recheck inline (avoids double loop)
  for (const brand of BRAND_NAMES) {
    if (hostname.includes(brand) && !hostname.endsWith(`.${brand}.com`) && hostname !== `${brand}.com`) {
      score += 30;
      break;
    }
  }

  // Special char ratio
  if (specialCharRatio > 0.15)       score += 15;
  else if (specialCharRatio > 0.1)   score += 8;

  // Open redirect parameter
  if (/[?&](redirect|redir|url|next|goto|return|returnurl|r)=/i.test(path)) score += 10;

  const probability = Math.min(Math.round(score), 100);

  return {
    entropy,
    hasIP,
    length,
    subdomainCount,
    suspiciousWordsCount,
    specialCharRatio,
    probability,
    flags,
  };
}
