/**
 * Heuristics Engine for URL Lexical Analysis
 * Extracts features and calculates a heuristic risk probability.
 */

// 1. Shannon Entropy
function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const counts: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    counts[char] = (counts[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in counts) {
    const p = counts[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// 2. Lexical Features
const SUSPICIOUS_WORDS = [
  "login", "signin", "bank", "secure", "account", "update", "verify", 
  "wallet", "auth", "credential", "billing", "paypal", "admin", "free"
];

export interface HeuristicResult {
  entropy: number;
  hasIP: boolean;
  length: number;
  subdomainCount: number;
  suspiciousWordsCount: number;
  specialCharRatio: number;
  probability: number; // 0 to 100
  flags: string[];
}

export function analyzeURL(urlStr: string): HeuristicResult {
  const flags: string[] = [];
  let url: URL;
  
  try {
    // Prefix with http if missing to parse properly
    if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
      urlStr = 'http://' + urlStr;
    }
    url = new URL(urlStr);
  } catch (e) {
    return {
      entropy: 0, hasIP: false, length: urlStr.length, subdomainCount: 0,
      suspiciousWordsCount: 0, specialCharRatio: 0, probability: 100,
      flags: ["Invalid URL structure"]
    };
  }

  const hostname = url.hostname;
  const fullPath = url.pathname + url.search;

  // Feature: Length
  const length = urlStr.length;
  if (length > 75) flags.push("Excessive URL length");

  // Feature: Entropy
  const entropy = calculateEntropy(hostname);
  if (entropy > 4.0) flags.push("High domain entropy (randomized characters)");

  // Feature: IP Address in Hostname
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hasIP = ipv4Regex.test(hostname);
  if (hasIP) flags.push("IP address used instead of domain name");

  // Feature: Subdomains
  const parts = hostname.split('.');
  // Note: this is a naive count. co.uk adds to it, but it's fine for heuristics.
  const subdomainCount = parts.length > 2 ? parts.length - 2 : 0;
  if (subdomainCount > 2) flags.push("Multiple subdomains detected");

  // Feature: Suspicious words
  let suspiciousWordsCount = 0;
  const lowerUrl = urlStr.toLowerCase();
  for (const word of SUSPICIOUS_WORDS) {
    if (lowerUrl.includes(word)) {
      suspiciousWordsCount++;
    }
  }
  if (suspiciousWordsCount > 0) flags.push(`Contains ${suspiciousWordsCount} suspicious keywords`);

  // Feature: Special Character Ratio
  const specialChars = lowerUrl.match(/[\-\@\?\=\_\%\&\#]/g);
  const specialCharRatio = specialChars ? specialChars.length / length : 0;
  if (specialCharRatio > 0.1) flags.push("High ratio of special characters");
  
  if (lowerUrl.includes('@')) flags.push("Contains '@' symbol (credential masking)");

  // Calculate Probability (0-100)
  let score = 0;
  
  if (hasIP) score += 40;
  if (entropy > 4.0) score += 20;
  if (entropy > 4.5) score += 15;
  if (length > 75) score += 10;
  if (length > 100) score += 10;
  if (subdomainCount > 2) score += 15;
  if (subdomainCount > 3) score += 15;
  score += suspiciousWordsCount * 15;
  if (specialCharRatio > 0.1) score += 10;
  if (lowerUrl.includes('@')) score += 30;

  // Normalize to 0-100
  const probability = Math.min(Math.round(score), 100);

  return {
    entropy,
    hasIP,
    length,
    subdomainCount,
    suspiciousWordsCount,
    specialCharRatio,
    probability,
    flags
  };
}
