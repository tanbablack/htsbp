/**
 * Collector: tldrsec/prompt-injection-defenses
 * Parses the curated README for IDPI attack examples, URLs, and domains.
 *
 * Source: https://github.com/tldrsec/prompt-injection-defenses
 */
import { normalizeDomain, upsertThreat, extractDomain } from "./common.js";
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

/** Check if a URL is likely an attack example (not a defense tool/paper) */
function isAttackExample(url: string, context: string): boolean {
  const lower = context.toLowerCase();
  const attackIndicators = [
    "attack",
    "malicious",
    "exploit",
    "injection site",
    "in the wild",
    "real-world",
    "payload",
    "weaponized",
  ];
  return attackIndicators.some(kw => lower.includes(kw));
}

/** Filter out known non-threat domains (GitHub, arxiv, etc.) */
const EXCLUDED_DOMAINS = new Set([
  "github.com",
  "arxiv.org",
  "twitter.com",
  "x.com",
  "youtube.com",
  "medium.com",
  "huggingface.co",
  "openai.com",
  "anthropic.com",
  "google.com",
  "docs.google.com",
  "linkedin.com",
  "reddit.com",
  "notion.so",
  "wikipedia.org",
  "npmjs.com",
  "pypi.org",
]);

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
    if (!domain || domain.length < 4 || EXCLUDED_DOMAINS.has(domain)) continue;

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
