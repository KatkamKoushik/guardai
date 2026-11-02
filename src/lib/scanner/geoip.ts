import type { GeoIpData } from "./types";

/**
 * Resolves geolocation data for an IP address using local MaxMind-derived database
 * with fail-soft external fallback for ISP/ASN enrichment.
 */
export async function lookupGeoIp(ip: string): Promise<GeoIpData | null> {
  if (!ip) return null;

  let localResult: GeoIpData | null = null;

  // 1. Ultra-fast local lookup (0-2ms, offline, lazily evaluated)
  try {
    const geoipModule = await import("geoip-lite");
    const geoip = geoipModule.default || geoipModule;
    const local = geoip.lookup(ip);

    if (local) {
      localResult = {
        query: ip,
        city: local.city || undefined,
        region: local.region || undefined,
        country: local.country || undefined,
        countryCode: local.country || undefined,
        lat: local.ll ? local.ll[0] : undefined,
        lon: local.ll ? local.ll[1] : undefined,
        timezone: local.timezone || undefined,
      };
    }
  } catch {
    // Graceful fallback if geoip-lite binary dataset is inaccessible
  }

  // 2. ASN / ISP enrichment fallback via low-latency external API
  try {
    const res = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,city,regionName,isp,as,query`,
      { signal: AbortSignal.timeout(2500) }
    );

    if (res.ok) {
      const remote = await res.json();
      if (remote.status === "success") {
        return {
          query: ip,
          city: remote.city || localResult?.city,
          region: remote.regionName || localResult?.region,
          country: remote.country || localResult?.country,
          countryCode: localResult?.countryCode,
          isp: remote.isp,
          as: remote.as,
          asn: remote.as,
          lat: localResult?.lat,
          lon: localResult?.lon,
          timezone: localResult?.timezone,
        };
      }
    }
  } catch {
    // If external call fails or times out, return local result safely
  }

  return localResult;
}
