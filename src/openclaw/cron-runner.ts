/**
 * OpenClaw cron runner: Uses Anthropic Messages API to discover and analyze IDPI threats.
 *
 * 1. Sends discovery-prompt.md to Claude for new threat discovery
 * 2. Parses JSON response and upserts threats via common.ts
 * 3. For new URLs, runs analysis-prompt.md for detailed analysis
 * 4. Triggers rebuild-stats.ts at the end
 *
 * Uses web_search tool to find real-time threat intelligence from the web.
 *
 * Environment: ANTHROPIC_API_KEY required
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { upsertThreat, extractDomain } from "../collectors/common.js";
import { PATTERNS_FILE } from "../lib/patterns.js";
import type { Threat, AttackIntent, Technique, Severity } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DISCOVERY_PROMPT_PATH = path.join(__dirname, "discovery-prompt.md");
const ANALYSIS_PROMPT_PATH = path.join(__dirname, "analysis-prompt.md");
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const MODEL = "claude-opus-4-6";

interface AnthropicMessage {
  role: "user" | "assistant";
  content: string | Array<{ type: "text"; text: string }>;
}

interface AnthropicContentBlock {
  type: string;
  text?: string;
  name?: string;
  id?: string;
  input?: Record<string, unknown>;
  tool_use_id?: string;
  content?: unknown[];
}

interface AnthropicResponse {
  content: AnthropicContentBlock[];
  stop_reason: string;
}

/** Call the Anthropic Messages API */
async function callClaude(prompt: string): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY environment variable is required");
  }

  const messages: AnthropicMessage[] = [{ role: "user", content: prompt }];

  const res = await fetch(ANTHROPIC_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 16384,
      tools: [
        {
          type: "web_search_20250305",
          name: "web_search",
          max_uses: 10,
        },
      ],
      messages,
    }),
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Anthropic API error ${res.status}: ${errorText}`);
  }

  const data = (await res.json()) as AnthropicResponse;
  // Web search responses contain mixed content blocks (server_tool_use,
  // web_search_tool_result, text). Extract and join all text blocks.
  const textParts = data.content
    .filter((c): c is AnthropicContentBlock & { text: string } => c.type === "text" && typeof c.text === "string")
    .map(c => c.text);
  return textParts.join("\n");
}

/** Discovery response shape (threats + optional pattern suggestions) */
interface DiscoveryResponse {
  threats: unknown[];
  suggested_patterns: unknown[];
}

/** Extract discovery response from Claude's output */
function extractDiscoveryResponse(text: string): DiscoveryResponse {
  const empty: DiscoveryResponse = { threats: [], suggested_patterns: [] };

  // Try parsing as the new object format { threats: [...], suggested_patterns: [...] }
  function tryParseObject(json: string): DiscoveryResponse | null {
    try {
      const parsed = JSON.parse(json);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return {
          threats: Array.isArray(parsed.threats) ? parsed.threats : [],
          suggested_patterns: Array.isArray(parsed.suggested_patterns) ? parsed.suggested_patterns : [],
        };
      }
      // Backwards compat: bare array = threats only
      if (Array.isArray(parsed)) {
        return { threats: parsed, suggested_patterns: [] };
      }
    } catch { /* fall through */ }
    return null;
  }

  // Try direct parse
  const direct = tryParseObject(text);
  if (direct) return direct;

  // Try extracting from code fences
  const fenceMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) {
    const fenced = tryParseObject(fenceMatch[1]);
    if (fenced) return fenced;
  }

  // Try finding object or array brackets
  const objMatch = text.match(/\{[\s\S]*\}/);
  if (objMatch) {
    const obj = tryParseObject(objMatch[0]);
    if (obj) return obj;
  }

  const arrayMatch = text.match(/\[[\s\S]*\]/);
  if (arrayMatch) {
    try {
      const arr = JSON.parse(arrayMatch[0]);
      if (Array.isArray(arr)) return { threats: arr, suggested_patterns: [] };
    } catch { /* fall through */ }
  }

  return empty;
}

/** Validate a severity value */
function isValidSeverity(s: unknown): s is Severity {
  return typeof s === "string" && ["critical", "high", "medium", "low"].includes(s);
}

/** Validate and append new patterns to data/patterns.json */
function appendSuggestedPatterns(suggestions: unknown[]): number {
  if (suggestions.length === 0) return 0;

  const raw = JSON.parse(fs.readFileSync(PATTERNS_FILE, "utf-8"));
  const existingNames = new Set<string>([
    ...raw.instructions.map((p: { name: string }) => p.name),
    ...raw.concealments.map((p: { name: string }) => p.name),
  ]);

  let added = 0;

  for (const item of suggestions) {
    const p = item as Record<string, unknown>;
    const name = p.name as string | undefined;
    const pattern = p.pattern as string | undefined;
    const flags = (p.flags as string) || "i";
    const category = p.category as string | undefined;
    const label = p.label as string | undefined;

    if (!name || !pattern || !category || !label) {
      console.warn(`[openclaw] Skipping invalid pattern suggestion: missing fields`);
      continue;
    }

    if (existingNames.has(name)) {
      console.log(`[openclaw] Pattern "${name}" already exists, skipping`);
      continue;
    }

    // Validate regex compiles
    try {
      new RegExp(pattern, flags);
    } catch (err) {
      console.warn(`[openclaw] Invalid regex "${pattern}": ${err}`);
      continue;
    }

    if (category === "instruction") {
      raw.instructions.push({ pattern, flags, name, label });
    } else if (category === "concealment") {
      const technique = (p.technique as string) || "other";
      raw.concealments.push({ pattern, flags, name, technique, label });
    } else {
      console.warn(`[openclaw] Unknown pattern category "${category}", skipping`);
      continue;
    }

    existingNames.add(name);
    added++;
    const reason = (p.reason as string) || "";
    console.log(`[openclaw] Added new pattern: "${name}" (${category})${reason ? ` — ${reason}` : ""}`);
  }

  if (added > 0) {
    raw._meta.version = (raw._meta.version || 0) + 1;
    raw._meta.updated_at = new Date().toISOString();
    fs.writeFileSync(PATTERNS_FILE, JSON.stringify(raw, null, 2) + "\n");
    console.log(`[openclaw] Patterns file updated: ${added} new pattern(s)`);
  }

  return added;
}

/**
 * Daily search query rotation for new IDPI site discovery.
 * Goal: find new malicious websites with IDPI payloads targeting AI agents.
 * Day-of-year mod 3 selects a distinct query set (3-day cycle).
 *
 * Design principles:
 * - Queries target actual attack sites, not research/defense articles
 * - Avoid CVE databases (they track software vulnerabilities, not IDPI sites)
 * - Security media coverage is already handled by discovery-prompt.md sources list
 */
const IDPI_DISCOVERY_QUERY_SETS: Record<number, { focus: string; queries: string[] }> = {
  0: {
    focus: "野生のIDPIペイロード検出（新規サイト）",
    queries: [
      '"ignore previous instructions" -site:github.com -site:arxiv.org -site:wikipedia.org',
      '"you are now a" -site:github.com -site:arxiv.org "hidden" OR "inject"',
      '"indirect prompt injection" "found" OR "discovered" OR "confirmed" -site:arxiv.org -site:wikipedia.org 2026',
      '"IDPI" "domain" OR "website" OR "url" "in the wild" 2026',
      '"prompt injection" "payload" "embedded" site:thehackernews.com OR site:bleepingcomputer.com OR site:cybersecuritynews.com',
    ],
  },
  1: {
    focus: "AIエージェント経由の悪意あるサイト報告",
    queries: [
      '"AI agent" "malicious" "website" "prompt" 2026 -site:arxiv.org',
      'site:unit42.paloaltonetworks.com "indirect prompt injection" 2025 OR 2026',
      '"LLM" "poisoned" "website" OR "page" -site:arxiv.org 2026',
      '"prompt injection" "weaponized" OR "in the wild" -poc -demo site:thehackernews.com OR site:wired.com OR site:arstechnica.com',
      '"hidden instructions" "AI" "website" -site:arxiv.org -site:github.com 2026',
    ],
  },
  2: {
    focus: "SEOポイズニング経由のAIエージェント汚染",
    queries: [
      '"SEO poisoning" "AI" OR "LLM" OR "agent" "search results" 2026',
      '"search result poisoning" "AI agent" OR "chatbot" OR "LLM" 2026',
      '"AI recommendation" "malicious" OR "poisoned" "website" 2026',
      'site:pillar.security OR site:lakera.ai OR site:llmsecurity.net "in the wild" 2026',
      '"prompt injection" "SEO" "confirmed" OR "observed" -poc -demo 2026',
    ],
  },
};

/** Build a prompt with dynamic context injected */
function buildPrompt(template: string): string {
  const now = new Date();
  const date = now.toISOString().split("T")[0];

  // Day-of-year mod 3 for daily rotation (3-day cycle)
  const startOfYear = new Date(now.getFullYear(), 0, 1);
  const dayOfYear = Math.floor(
    (now.getTime() - startOfYear.getTime()) / (24 * 60 * 60 * 1000)
  );
  const slot = dayOfYear % 3;
  const { focus, queries } = IDPI_DISCOVERY_QUERY_SETS[slot];

  // Load known domains for deduplication hint
  let knownDomains: string[] = [];
  if (fs.existsSync(DOMAINS_DIR)) {
    knownDomains = fs.readdirSync(DOMAINS_DIR)
      .filter(f => f.endsWith(".json"))
      .map(f => f.replace(".json", ""));
  }
  const sample = knownDomains.slice(0, 20).join(", ");
  const queriesText = queries.map((q, i) => `${i + 1}. \`${q}\``).join("\n");

  return template
    .replace("{{DATE}}", date)
    .replace("{{WEEKLY_FOCUS}}", focus)
    .replace("{{KNOWN_DOMAIN_COUNT}}", String(knownDomains.length))
    .replace("{{KNOWN_DOMAINS_SAMPLE}}", sample || "(なし)")
    .replace("{{SEARCH_QUERIES}}", queriesText);
}

/** Run the discovery phase */
async function runDiscovery(): Promise<number> {
  console.log("[openclaw] Running discovery phase...");
  const template = fs.readFileSync(DISCOVERY_PROMPT_PATH, "utf-8");
  const promptContent = buildPrompt(template);
  console.log(`[openclaw] Prompt built (${promptContent.length} chars)`);
  const response = await callClaude(promptContent);
  const { threats: discoveries, suggested_patterns } = extractDiscoveryResponse(response);

  console.log(`[openclaw] Discovered ${discoveries.length} potential threats`);

  let added = 0;
  const now = new Date().toISOString();

  for (const item of discoveries) {
    const entry = item as Record<string, unknown>;
    const domain = entry.domain as string | undefined;
    if (!domain) continue;

    const threat: Threat = {
      url: (entry.url as string) || undefined,
      severity: isValidSeverity(entry.severity) ? entry.severity : "medium",
      intent: (entry.intent as AttackIntent) || "other",
      techniques: (Array.isArray(entry.techniques) ? entry.techniques : []) as Technique[],
      description: (entry.description as string) || "Discovered by AI-driven analysis",
      source: "openclaw",
      source_url: (entry.source_url as string) || undefined,
      first_seen: now,
      last_seen: now,
      is_active: true,
    };

    const result = upsertThreat(domain, threat);
    if (result === "added") added++;
    else if (result === "updated") added++; // discovery phase counts all changes as progress
  }

  // Process pattern suggestions
  if (suggested_patterns.length > 0) {
    console.log(`[openclaw] ${suggested_patterns.length} pattern suggestion(s) received`);
    appendSuggestedPatterns(suggested_patterns);
  }

  console.log(`[openclaw] Discovery phase: ${added} threats added/updated`);
  return added;
}

/** Run analysis on a specific URL */
async function runAnalysis(targetUrl: string): Promise<void> {
  console.log(`[openclaw] Analyzing ${targetUrl}...`);

  const promptTemplate = fs.readFileSync(ANALYSIS_PROMPT_PATH, "utf-8");
  const prompt = promptTemplate.replace(/\{TARGET_URL\}/g, targetUrl);
  const response = await callClaude(prompt);

  // Try to parse the analysis result
  let analysis: Record<string, unknown>;
  try {
    const fenceMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
    analysis = JSON.parse(fenceMatch ? fenceMatch[1] : response);
  } catch {
    console.warn(`[openclaw] Failed to parse analysis for ${targetUrl}`);
    return;
  }

  if (!analysis.has_idpi) {
    console.log(`[openclaw] No IDPI found at ${targetUrl}`);
    return;
  }

  const domain = extractDomain(targetUrl);
  if (!domain) return;

  const now = new Date().toISOString();
  const threat: Threat = {
    url: targetUrl,
    severity: isValidSeverity(analysis.severity) ? analysis.severity : "medium",
    intent: (analysis.intent as AttackIntent) || "other",
    techniques: (Array.isArray(analysis.techniques) ? analysis.techniques : []) as Technique[],
    description: (analysis.notes as string) || "IDPI confirmed by AI analysis",
    source: "openclaw",
    first_seen: now,
    last_seen: now,
    is_active: true,
  };

  upsertThreat(domain, threat);
  console.log(`[openclaw] Analysis complete: IDPI confirmed at ${targetUrl}`);
}

/** Main entry point */
async function main(): Promise<void> {
  try {
    await runDiscovery();
    // Note: analysis phase would run on newly discovered URLs
    // but requires individual URL targets from the discovery results
    console.log("[openclaw] Cron run complete");
  } catch (error) {
    console.error("[openclaw] Error:", error);
    process.exit(1);
  }
}

// Export for testing
export { runDiscovery, runAnalysis };

main();
