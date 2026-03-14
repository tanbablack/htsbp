/**
 * OpenClaw cron runner: Uses Anthropic Messages API to discover and analyze IDPI threats.
 *
 * 1. Sends discovery-prompt.md to Claude for new threat discovery
 * 2. Parses JSON response and upserts threats via common.ts
 * 3. For new URLs, runs analysis-prompt.md for detailed analysis
 * 4. Triggers rebuild-stats.ts at the end
 *
 * Environment: ANTHROPIC_API_KEY required
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { upsertThreat, extractDomain } from "../collectors/common.js";
import type { Threat, AttackIntent, Technique, Severity } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DISCOVERY_PROMPT_PATH = path.join(__dirname, "discovery-prompt.md");
const ANALYSIS_PROMPT_PATH = path.join(__dirname, "analysis-prompt.md");

const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const MODEL = "claude-opus-4-6";

interface AnthropicMessage {
  role: "user" | "assistant";
  content: string | Array<{ type: "text"; text: string }>;
}

interface AnthropicResponse {
  content: Array<{ type: "text"; text: string }>;
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
      max_tokens: 4096,
      messages,
    }),
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Anthropic API error ${res.status}: ${errorText}`);
  }

  const data = (await res.json()) as AnthropicResponse;
  const textContent = data.content.find(c => c.type === "text");
  return textContent?.text ?? "";
}

/** Extract JSON array from a response that might contain markdown fences */
function extractJsonArray(text: string): unknown[] {
  // Try direct parse first
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
  } catch {
    // Try extracting from code fences
  }

  const fenceMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) {
    try {
      const parsed = JSON.parse(fenceMatch[1]);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      // Fall through
    }
  }

  // Try finding array brackets
  const arrayMatch = text.match(/\[[\s\S]*\]/);
  if (arrayMatch) {
    try {
      return JSON.parse(arrayMatch[0]);
    } catch {
      // Fall through
    }
  }

  return [];
}

/** Validate a severity value */
function isValidSeverity(s: unknown): s is Severity {
  return typeof s === "string" && ["critical", "high", "medium", "low"].includes(s);
}

/** Run the discovery phase */
async function runDiscovery(): Promise<number> {
  console.log("[openclaw] Running discovery phase...");
  const promptContent = fs.readFileSync(DISCOVERY_PROMPT_PATH, "utf-8");
  const response = await callClaude(promptContent);
  const discoveries = extractJsonArray(response);

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

    const changed = upsertThreat(domain, threat);
    if (changed) added++;
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
