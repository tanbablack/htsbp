/**
 * Collector: AlienVault OTX
 * Fetches threat pulses tagged with prompt injection / IDPI keywords.
 *
 * Only registers domains/URLs that appear in pulses whose name or description
 * explicitly mentions IDPI-related terms, to avoid importing unrelated IoCs.
 *
 * API: https://otx.alienvault.com/api/v1/
 */
import { normalizeDomain, upsertThreat, extractDomain } from "./common.js";
import type { Threat, AttackIntent, Technique } from "../types/index.js";

const OTX_API = "https://otx.alienvault.com/api/v1";
const SEARCH_TERMS = ["prompt injection", "IDPI", "indirect prompt injection"];

/** Keywords that must appear in pulse name/description to be considered IDPI-relevant */
const RELEVANCE_KEYWORDS = [
  "prompt injection", "idpi", "indirect prompt",
  "llm attack", "ai poisoning", "ai injection",
  "hidden instruction", "hidden prompt",
];

/** Max indicators to process per pulse (avoid importing thousands of unrelated IoCs) */
const MAX_INDICATORS_PER_PULSE = 50;

/** Max total domains to add across all pulses */
const MAX_TOTAL_DOMAINS = 200;

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

/** Check if a pulse is actually IDPI-relevant based on its name and description */
function isPulseRelevant(pulse: OtxPulse): boolean {
  const text = `${pulse.name} ${pulse.description}`.toLowerCase();
  return RELEVANCE_KEYWORDS.some(kw => text.includes(kw));
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

/** Fetch indicators for a specific pulse (with error handling) */
async function fetchPulseIndicators(pulseId: string): Promise<OtxIndicator[]> {
  const url = `${OTX_API}/pulses/${pulseId}/indicators?limit=${MAX_INDICATORS_PER_PULSE}`;
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "htsbp-collector/1.0",
  };
  if (process.env.OTX_API_KEY) {
    headers["X-OTX-API-KEY"] = process.env.OTX_API_KEY;
  }

  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      console.warn(`[otx] Failed to fetch pulse ${pulseId}: HTTP ${res.status}, skipping`);
      return [];
    }

    const data = (await res.json()) as { results: OtxIndicator[] };
    return data.results ?? [];
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`[otx] Error fetching pulse ${pulseId}: ${message}, skipping`);
    return [];
  }
}

/** Run the OTX AlienVault collector */
export async function collect(): Promise<{ added: number; updated: number }> {
  let added = 0;
  let updated = 0;
  const now = new Date().toISOString();
  const seenDomains = new Set<string>();

  for (const term of SEARCH_TERMS) {
    if (seenDomains.size >= MAX_TOTAL_DOMAINS) {
      console.log(`[otx] Reached max domain limit (${MAX_TOTAL_DOMAINS}), stopping`);
      break;
    }

    console.log(`[otx] Searching for "${term}"...`);
    const pulses = await searchPulses(term);
    console.log(`[otx] Found ${pulses.length} pulses for "${term}"`);

    for (const pulse of pulses) {
      // Filter out pulses that aren't actually about IDPI
      if (!isPulseRelevant(pulse)) {
        console.log(`[otx] Skipping irrelevant pulse: ${pulse.name}`);
        continue;
      }

      const indicators = pulse.indicators?.length
        ? pulse.indicators.slice(0, MAX_INDICATORS_PER_PULSE)
        : await fetchPulseIndicators(pulse.id);

      for (const indicator of indicators) {
        if (seenDomains.size >= MAX_TOTAL_DOMAINS) break;

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
