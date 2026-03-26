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

/** Fetch with timeout helper */
async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs = 15000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Search OTX for relevant pulses.
 * Returns empty array on transient server errors (504/503/429/timeout)
 * instead of throwing, so other search terms can continue.
 * Retries up to MAX_RETRIES times with exponential backoff.
 */
const MAX_RETRIES = 2;
const RETRY_BASE_MS = 3000;

async function searchPulses(query: string): Promise<OtxPulse[]> {
  const url = `${OTX_API}/search/pulses?q=${encodeURIComponent(query)}&limit=20`;
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "htsbp-collector/1.0",
  };
  if (process.env.OTX_API_KEY) {
    headers["X-OTX-API-KEY"] = process.env.OTX_API_KEY;
  }

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const res = await fetchWithTimeout(url, { headers });

      // Transient server errors — skip gracefully (do not throw)
      if (res.status === 504 || res.status === 503 || res.status === 429) {
        const retryAfter = res.headers.get("Retry-After");
        const waitMs = retryAfter ? parseInt(retryAfter) * 1000 : RETRY_BASE_MS * Math.pow(2, attempt);
        if (attempt < MAX_RETRIES) {
          console.warn(`[otx] HTTP ${res.status} for "${query}", retrying in ${waitMs}ms (attempt ${attempt + 1}/${MAX_RETRIES})...`);
          await new Promise(r => setTimeout(r, waitMs));
          continue;
        }
        console.warn(`[otx] HTTP ${res.status} for "${query}" after ${MAX_RETRIES} retries, skipping term.`);
        return [];
      }

      if (!res.ok) {
        console.warn(`[otx] HTTP ${res.status} for "${query}", skipping term.`);
        return [];
      }

      const data = (await res.json()) as { results: OtxPulse[] };
      return data.results ?? [];

    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const isTimeout = message.includes("abort") || message.includes("timeout");
      if (attempt < MAX_RETRIES) {
        const waitMs = RETRY_BASE_MS * Math.pow(2, attempt);
        console.warn(`[otx] ${isTimeout ? "Timeout" : "Error"} for "${query}", retrying in ${waitMs}ms (attempt ${attempt + 1}/${MAX_RETRIES})...`);
        await new Promise(r => setTimeout(r, waitMs));
        continue;
      }
      console.warn(`[otx] Failed for "${query}" after ${MAX_RETRIES} retries: ${message}, skipping term.`);
      return [];
    }
  }

  return [];
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
          description: `IDPI threat independently verified by HTSBP. Discovered via OTX pulse: ${pulse.name}`,
          source: "htsbp",
          source_url: `https://otx.alienvault.com/pulse/${pulse.id}`,
          first_seen: pulse.created || now,
          last_seen: pulse.modified || now,
          is_active: true,
        };

        const result = upsertThreat(domain, threat);
        if (result === "added") added++;
        else if (result === "updated") updated++;
      }
    }
  }

  console.log(`[otx] Done: ${added} added, ${updated} updated`);
  return { added, updated };
}
