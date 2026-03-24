/**
 * Collector: tldrsec/prompt-injection-defenses
 * Parses the curated README for IDPI attack examples, URLs, and domains.
 *
 * Source: https://github.com/tldrsec/prompt-injection-defenses
 */
import { normalizeDomain, upsertThreat, extractDomain, EXCLUDED_DOMAINS } from "./common.js";
import type { Threat, AttackIntent, Technique } from "../types/index.js";

const README_URL =
  "https://raw.githubusercontent.com/tldrsec/prompt-injection-defenses/main/README.md";

/** Fetch the README content */
async function fetchReadme(): Promise<string> {
  const res = await fetch(README_URL, {
    headers: { "User-Agent": "htsbp-collector/1.0" },
  });
  if (!res.ok) {
    console.warn(`[tldrsec] Failed to fetch README: ${res.status}`);
    return "";
  }
  return res.text();
}

/** Extract URLs from markdown content */
function extractUrls(content: string): string[] {
  const urlRegex = /https?:\/\/[^\s)\]"'`>]+/gi;
  return [...new Set(content.match(urlRegex) ?? [])];
}

/**
 * Additional domains that are legitimate research/defense resources,
 * not attack sites. These appear in tldrsec README as references, not threats.
 */
const TLDRSEC_EXCLUDED_DOMAINS = new Set([
  ...EXCLUDED_DOMAINS,
  // Security research blogs / tools (cited as references, not attack sites)
  "simonwillison.net", "martinfowler.com", "splintered.co.uk",
  "kai-greshake.de", "learnprompting.org", "llm-guard.com",
  "research.kudelskisecurity.com", "developer.nvidia.com",
  "blog.langchain.dev", "llm7-landing.pages.dev",
  // Academic / publishing platforms
  "www.researchgate.net", "www.researchsquare.com", "www.scirp.org",
  "static1.squarespace.com",
  // AI company blogs
  "www.akaike.ai",
]);

/**
 * Check if a URL is likely an attack example (not a defense tool/paper).
 * Requires BOTH:
 * 1. Strong attack-specific keyword in context
 * 2. No defense/research framing nearby
 */
function isAttackExample(url: string, context: string): boolean {
  const lower = context.toLowerCase();

  // Hard exclusion: if context frames this as defense/research/tool
  const defenseIndicators = [
    "defense", "defend", "protect", "mitigat", "prevent",
    "research", "paper", "study", "analysis", "example of",
    "demonstrate", "proof of concept", "poc", "tool", "library",
    "framework", "plugin", "extension", "blog post", "write-up",
  ];
  if (defenseIndicators.some(kw => lower.includes(kw))) return false;

  // Must have strong attack-specific keywords (not generic "attack")
  const strongAttackIndicators = [
    "injection site",
    "in the wild",
    "real-world attack",
    "weaponized",
    "actively exploit",
    "malicious site",
    "poisoned site",
    "idpi payload",
    "confirmed threat",
  ];
  return strongAttackIndicators.some(kw => lower.includes(kw));
}

/** Run the tldrsec GitHub collector */
export async function collect(): Promise<{ added: number; updated: number }> {
  let added = 0;
  let updated = 0;
  const now = new Date().toISOString();

  console.log("[tldrsec] Fetching README...");
  const content = await fetchReadme();
  if (!content) return { added, updated };

  // Split into sections to get context around each URL
  const lines = content.split("\n");
  const urls = extractUrls(content);

  console.log(`[tldrsec] Found ${urls.length} URLs in README`);

  for (const url of urls) {
    const domain = extractDomain(url);
    if (!domain || domain.length < 4 || TLDRSEC_EXCLUDED_DOMAINS.has(domain)) continue;

    // Get surrounding context (lines near the URL mention)
    const contextLines: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(url)) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        contextLines.push(...lines.slice(start, end));
      }
    }
    const context = contextLines.join(" ");

    if (!isAttackExample(url, context)) continue;

    const threat: Threat = {
      url,
      severity: "medium",
      intent: "other" as AttackIntent,
      techniques: [] as Technique[],
      description: `IDPI reference found in tldrsec/prompt-injection-defenses curated list`,
      source: "tldrsec",
      source_url: "https://github.com/tldrsec/prompt-injection-defenses",
      first_seen: now,
      last_seen: now,
      is_active: true,
    };

    const result = upsertThreat(domain, threat);
    if (result === "added") added++;
    else if (result === "updated") updated++;
  }

  console.log(`[tldrsec] Done: ${added} added, ${updated} updated`);
  return { added, updated };
}
