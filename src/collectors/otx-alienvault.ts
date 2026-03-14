/**
 * Collector: AlienVault OTX
 * Fetches threat pulses tagged with prompt injection / IDPI keywords.
 *
 * API: https://otx.alienvault.com/api/v1/
 */
import { normalizeDomain, upsertThreat, extractDomain } from "./common.js";
import type { Threat, AttackIntent, Technique } from "../types/index.js";

const OTX_API = "https://otx.alienvault.com/api/v1";
const SEARCH_TERMS = ["prompt injection", "IDPI", "indirect prompt injection"];

interface OtxIndicator {
  type: string;
  indicator: string;
  description: string;
}

interface OtxPulse {
  id: string;
  name: string;
  description: string;
  indicators: OtxIndicator[];
  created: string;
  modified: string;
  references: string[];
}

/** Search OTX for relevant pulses */
async function searchPulses(query: string): Promise<OtxPulse[]> {
  const url = `${OTX_API}/search/pulses?q=${encodeURIComponent(query)}&limit=20`;
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "htsbp-collector/1.0",
  };
  if (process.env.OTX_API_KEY) {
    headers["X-OTX-API-KEY"] = process.env.OTX_API_KEY;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`[otx] Search failed for "${query}": HTTP ${res.status}`);
  }

  const data = (await res.json()) as { results: OtxPulse[] };
  return data.results ?? [];
}

/** Fetch indicators for a specific pulse */
async function fetchPulseIndicators(pulseId: string): Promise<OtxIndicator[]> {
  const url = `${OTX_API}/pulses/${pulseId}/indicators?limit=500`;
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "htsbp-collector/1.0",
  };
  if (process.env.OTX_API_KEY) {
    headers["X-OTX-API-KEY"] = process.env.OTX_API_KEY;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`[otx] Failed to fetch pulse ${pulseId}: HTTP ${res.status}`);
  }

  const data = (await res.json()) as { results: OtxIndicator[] };
  return data.results ?? [];
}

/** Run the OTX AlienVault collector */
export async function collect(): Promise<{ added: number; updated: number }> {
  let added = 0;
  let updated = 0;
  const now = new Date().toISOString();
  const seenDomains = new Set<string>();

  for (const term of SEARCH_TERMS) {
    console.log(`[otx] Searching for "${term}"...`);
    const pulses = await searchPulses(term);
    console.log(`[otx] Found ${pulses.length} pulses for "${term}"`);

    for (const pulse of pulses) {
      const indicators = pulse.indicators?.length
        ? pulse.indicators
        : await fetchPulseIndicators(pulse.id);

      for (const indicator of indicators) {
        let domain: string | null = null;

        if (indicator.type === "domain") {
          domain = normalizeDomain(indicator.indicator);
        } else if (indicator.type === "URL" || indicator.type === "url") {
          domain = extractDomain(indicator.indicator);
        } else if (indicator.type === "hostname") {
          domain = normalizeDomain(indicator.indicator);
        }

        if (!domain || domain.length < 4 || seenDomains.has(domain)) continue;
        seenDomains.add(domain);

        const threat: Threat = {
          severity: "medium",
          intent: "other" as AttackIntent,
          techniques: [] as Technique[],
          description: `IDPI indicator from OTX pulse: ${pulse.name}`,
          source: "otx",
          source_url: `https://otx.alienvault.com/pulse/${pulse.id}`,
          first_seen: pulse.created || now,
          last_seen: pulse.modified || now,
          is_active: true,
        };

        const changed = upsertThreat(domain, threat);
        if (changed) {
          if (added === 0 || !changed) added++;
          else updated++;
        }
      }
    }
  }

  console.log(`[otx] Done: ${added} added, ${updated} updated`);
  return { added, updated };
}
