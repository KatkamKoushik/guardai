import type { DomainRegistrationInfo } from "./types";

/**
 * Extracts the effective registrar from RDAP vCard or handle structures.
 */
function extractRegistrar(entities: unknown): string {
  if (!Array.isArray(entities)) return "Unknown";
  const registrarEntity = entities.find(
    (e) => Array.isArray(e?.roles) && e.roles.includes("registrar")
  );
  if (!registrarEntity) return "Unknown";

  if (
    Array.isArray(registrarEntity.vcardArray) &&
    Array.isArray(registrarEntity.vcardArray[1])
  ) {
    const fnItem = registrarEntity.vcardArray[1].find(
      (item: unknown) => Array.isArray(item) && item[0] === "fn"
    );
    if (fnItem && fnItem[3]) {
      return String(fnItem[3]);
    }
  }

  return registrarEntity.handle || "Unknown";
}

/**
 * Extracts effective second-level domain name for RDAP querying.
 */
export function extractRootDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split(".");
  if (parts.length <= 2) return hostname;
  // Handle compound TLDs like co.uk, com.au, org.uk
  const lastTwo = parts.slice(-2).join(".");
  const compoundTlds = new Set([
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "co.jp",
    "com.br",
  ]);

  if (compoundTlds.has(lastTwo) && parts.length > 2) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

/**
 * Performs ICANN RDAP domain registration lookup with timeout and fail-soft handling.
 */
export async function lookupDomainRegistration(
  hostname: string,
  timeoutMs = 3500
): Promise<DomainRegistrationInfo> {
  const rootDomain = extractRootDomain(hostname);
  const tld = rootDomain.split(".").pop() || "";

  // Select authoritative RDAP endpoint
  let rdapUrl = `https://rdap.org/domain/${encodeURIComponent(rootDomain)}`;
  if (tld === "com" || tld === "net") {
    rdapUrl = `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(rootDomain)}`;
  } else if (tld === "org") {
    rdapUrl = `https://rdap.publicinterestregistry.org/rdap/domain/${encodeURIComponent(rootDomain)}`;
  }

  try {
    const res = await fetch(rdapUrl, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (res.ok) {
      const data = await res.json();
      const events = Array.isArray(data.events) ? data.events : [];

      const regEvent = events.find((e: any) => e.eventAction === "registration");
      const expEvent = events.find((e: any) => e.eventAction === "expiration");

      const creationDate = regEvent?.eventDate || null;
      const expirationDate = expEvent?.eventDate || null;
      const registrar = extractRegistrar(data.entities);

      let domainAgeDays: number | null = null;
      let domainAgeFormatted = "Unknown";
      let isNewlyRegistered = false;

      if (creationDate) {
        const createdMs = new Date(creationDate).getTime();
        if (!isNaN(createdMs)) {
          domainAgeDays = Math.max(0, Math.floor((Date.now() - createdMs) / (1000 * 60 * 60 * 24)));
          if (domainAgeDays < 30) {
            domainAgeFormatted = `${domainAgeDays} days`;
            isNewlyRegistered = true;
          } else if (domainAgeDays < 365) {
            const months = Math.floor(domainAgeDays / 30);
            domainAgeFormatted = `${months} months`;
          } else {
            const years = (domainAgeDays / 365.25).toFixed(1);
            domainAgeFormatted = `${years} years`;
          }
        }
      }

      const status = Array.isArray(data.status) ? data.status : [];

      return {
        registrar,
        creationDate,
        expirationDate,
        domainAgeDays,
        domainAgeFormatted,
        isNewlyRegistered,
        status,
      };
    }
  } catch {
    // Fail-soft on network or parsing error
  }

  return {
    registrar: "Data Unavailable",
    creationDate: null,
    expirationDate: null,
    domainAgeDays: null,
    domainAgeFormatted: "Unknown",
    isNewlyRegistered: false,
    status: [],
  };
}

