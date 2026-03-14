/**
 * Collector: Web crawler for active IDPI detection
 * Crawls known domains to check if IDPI payloads are still active,
 * and detects new payloads using pattern matching.
 */
import { loadDomainFile, saveDomainFile, sanitizePayload } from "./common.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Technique } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

/** IDPI instruction patterns (regex + description) */
const INSTRUCTION_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i, name: "ignore_previous_instructions" },
  { pattern: /you\s+are\s+(now\s+)?a/i, name: "role_override" },
  { pattern: /system\s*:\s*/i, name: "system_prompt_mimicry" },
  { pattern: /do\s+not\s+(follow|obey|listen)/i, name: "ignore_previous_instructions" },
  { pattern: /override|bypass|disregard/i, name: "role_override" },
];

/** CSS concealment detection patterns */
const CONCEALMENT_PATTERNS: Array<{ pattern: RegExp; technique: Technique }> = [
  { pattern: /font-size\s*:\s*0/i, technique: "zero_font_size" },
  { pattern: /display\s*:\s*none/i, technique: "css_display_none" },
  { pattern: /visibility\s*:\s*hidden/i, technique: "css_visibility_hidden" },
  { pattern: /opacity\s*:\s*0(?:[;\s]|$)/i, technique: "css_opacity_zero" },
  { pattern: /position\s*:\s*(?:absolute|fixed)[^;]*(?:left|top)\s*:\s*-\d{4,}/i, technique: "offscreen_positioning" },
];

/** Fetch a URL and return the HTML body */
async function fetchPage(url: string, timeoutMs = 10000): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; htsbp-crawler/1.0; +https://hasthissitebeenpoisoned.ai)",
        Accept: "text/html",
      },
      signal: controller.signal,
      redirect: "follow",
    });

    clearTimeout(timer);
    if (!res.ok) return null;

    const contentType = res.headers.get("content-type") ?? "";
    if (!contentType.includes("text/html") && !contentType.includes("text/plain")) return null;

    return res.text();
  } catch {
    return null;
  }
}

/** Analyze HTML for IDPI payloads */
function analyzeHtml(html: string): {
  hasIdpi: boolean;
  techniques: Technique[];
  payloads: string[];
} {
  const techniques = new Set<Technique>();
  const payloads: string[] = [];

  // Check for concealment techniques with embedded instructions
  for (const { pattern: concealPattern, technique } of CONCEALMENT_PATTERNS) {
    if (concealPattern.test(html)) {
      // Check if there are instruction patterns nearby
      for (const { pattern: instrPattern } of INSTRUCTION_PATTERNS) {
        if (instrPattern.test(html)) {
          techniques.add(technique);
          const match = html.match(instrPattern);
          if (match) {
            payloads.push(sanitizePayload(match[0]));
          }
        }
      }
    }
  }

  // Check HTML comments for instructions
  const commentRegex = /<!--([\s\S]*?)-->/g;
  let commentMatch;
  while ((commentMatch = commentRegex.exec(html)) !== null) {
    const commentContent = commentMatch[1];
    for (const { pattern } of INSTRUCTION_PATTERNS) {
      if (pattern.test(commentContent)) {
        techniques.add("html_comment");
        payloads.push(sanitizePayload(commentContent.trim().slice(0, 200)));
      }
    }
  }

  // Check for visible plaintext instructions
  for (const { pattern } of INSTRUCTION_PATTERNS) {
    if (pattern.test(html)) {
      techniques.add("visible_plaintext");
    }
  }

  return {
    hasIdpi: techniques.size > 0,
    techniques: [...techniques],
    payloads: [...new Set(payloads)].slice(0, 10),
  };
}

/** Run the web crawler collector */
export async function collect(): Promise<{ added: number; updated: number }> {
  let added = 0;
  let updated = 0;
  const now = new Date().toISOString();

  if (!fs.existsSync(DOMAINS_DIR)) {
    console.log("[web-crawler] No domains directory found, skipping");
    return { added, updated };
  }

  const domainFiles = fs.readdirSync(DOMAINS_DIR).filter(f => f.endsWith(".json"));
  console.log(`[web-crawler] Crawling ${domainFiles.length} domains...`);

  for (const file of domainFiles) {
    const data = loadDomainFile(file.replace(".json", ""));
    const domain = data.domain;

    // Try to fetch the domain's main page
    const urls = new Set<string>();
    urls.add(`https://${domain}`);
    urls.add(`http://${domain}`);

    // Also check specific URLs from known threats
    for (const threat of data.threats) {
      if (threat.url) urls.add(threat.url);
    }

    let domainChanged = false;

    for (const url of urls) {
      const html = await fetchPage(url);
      if (!html) continue;

      const analysis = analyzeHtml(html);

      if (analysis.hasIdpi) {
        // Update existing threats with new last_seen
        for (const threat of data.threats) {
          if (threat.url === url || (!threat.url && url.includes(domain))) {
            threat.last_seen = now;
            threat.is_active = true;
            if (analysis.payloads.length > 0) {
              const existingPayloads = new Set(threat.raw_payloads ?? []);
              for (const p of analysis.payloads) existingPayloads.add(p);
              threat.raw_payloads = [...existingPayloads];
            }
            domainChanged = true;
            updated++;
          }
        }
      } else {
        // If previously active threats are no longer detected, keep is_active
        // (we don't set is_active=false based on a single check)
      }
    }

    if (domainChanged) {
      saveDomainFile(data);
    }
  }

  console.log(`[web-crawler] Done: ${added} added, ${updated} updated`);
  return { added, updated };
}
