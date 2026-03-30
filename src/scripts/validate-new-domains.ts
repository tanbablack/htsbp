/**
 * validate-new-domains.ts
 *
 * Validates newly added domains BEFORE commit to ensure they are
 * actual IDPI threats targeting AI agents — not general malware,
 * phishing, or SEO poisoning targeting humans.
 *
 * Runs in collect.yml AFTER verify but BEFORE commit.
 * Automatically removes domains that fail validation.
 *
 * Validation criteria (domain passes if ANY of the following):
 *   1. IDPI scan detects HIGH or MEDIUM patterns (confirmed AI-targeted payload)
 *   2. Description/techniques contain AI/LLM/agent keywords
 *   3. Trusted source (unit42/htsbp) with specific non-vague description
 *
 * A domain FAILS if ALL of the following:
 *   - IDPI scan is CLEAN or UNREACHABLE
 *   - Description has no AI/LLM/agent keywords
 *   - Source is untrusted (openclaw only) AND description is vague
 *
 * Environment:
 *   NOTIFICATION_WEBHOOK_URL  Discord webhook URL
 *   DOMAINS_BEFORE            Space-separated snapshot from before collection
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkUrl, type ThreatLevel } from "./check-url.js";
import { execSync } from "node:child_process";
import type { ThreatFile } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

/** Keywords in description/techniques indicating AI agent targeting */
const AI_TARGETING_KEYWORDS = [
  "ai agent", "llm", "language model", "ai-driven", "prompt injection",
  "indirect prompt", "idpi", "ai assistant", "chatbot", "copilot",
  "claude", "gpt", "gemini", "ai recommendation", "ai search",
  "agent", "rag", "retrieval", "tool use", "function call",
  "ai-powered", "ai system", "ai model",
];

/** Trusted sources that provide independently verified threat data */
const TRUSTED_SOURCES = new Set(["unit42", "htsbp"]);

/** Send Discord notification */
async function notify(content: string): Promise<void> {
  const url = process.env.NOTIFICATION_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
  } catch { /* non-fatal */ }
}

/** Check if description or techniques mention AI agent targeting */
function hasAiTargetingKeywords(threat: ThreatFile["threats"][0]): boolean {
  const text = [
    threat.description ?? "",
    ...(threat.techniques ?? []),
    threat.intent ?? "",
  ].join(" ").toLowerCase();
  return AI_TARGETING_KEYWORDS.some(kw => text.includes(kw));
}

/** Validate a single domain file. Returns true if it should be kept. */
async function validateDomain(domain: string): Promise<{
  keep: boolean;
  reason: string;
  scanLevel: ThreatLevel;
}> {
  const filePath = path.join(DOMAINS_DIR, `${domain}.json`);
  const data: ThreatFile = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  const threat = data.threats[0];

  if (!threat) {
    return { keep: false, reason: "脅威データなし", scanLevel: "UNREACHABLE" };
  }

  // Run IDPI pattern scan
  const scanUrl = threat.url ?? `https://${domain}`;
  const result = await checkUrl(scanUrl);

  // PASS: IDPI scan confirmed
  if (result.level === "HIGH" || result.level === "MEDIUM") {
    return { keep: true, reason: `IDPIスキャン確認 (${result.level})`, scanLevel: result.level };
  }

  // PASS: Description/techniques mention AI agent targeting
  if (hasAiTargetingKeywords(threat)) {
    return { keep: true, reason: "説明にAI/LLMターゲット記述あり", scanLevel: result.level };
  }

  // PASS: Trusted source with specific description (>80 chars, no vague markers)
  const isTrusted = TRUSTED_SOURCES.has(threat.source);
  const isSpecific = (threat.description?.length ?? 0) > 80 &&
    !threat.description?.includes("curated list") &&
    !threat.description?.includes("telemetry") &&
    !threat.description?.includes("independently verified");

  if (isTrusted && isSpecific && result.level !== "CLEAN") {
    return { keep: true, reason: `信頼ソース(${threat.source}) + 具体的説明`, scanLevel: result.level };
  }

  // FAIL: No evidence of AI agent targeting
  const failReason = result.level === "CLEAN"
    ? "IDPIパターン未検出 + AI関連キーワードなし → 対象外"
    : `到達不能 + AI関連キーワードなし + ${isTrusted ? "説明が曖昧" : "低信頼ソース"} → 対象外`;

  return { keep: false, reason: failReason, scanLevel: result.level };
}

async function main(): Promise<void> {
  const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL;

  const domainsBefore = new Set(
    (process.env.DOMAINS_BEFORE ?? "").split(" ").filter(Boolean)
  );

  if (!fs.existsSync(DOMAINS_DIR)) return;

  const currentFiles = fs.readdirSync(DOMAINS_DIR).filter(f => f.endsWith(".json"));
  const newDomains = currentFiles
    .map(f => f.replace(".json", ""))
    .filter(d => !domainsBefore.has(d));

  if (newDomains.length === 0) {
    console.log("[validate] No new domains to validate.");
    return;
  }

  console.log(`[validate] Validating ${newDomains.length} new domain(s)...`);

  const kept: string[] = [];
  const removed: Array<{ domain: string; reason: string; scanLevel: ThreatLevel }> = [];

  for (const domain of newDomains) {
    console.log(`[validate] Checking ${domain}...`);
    const { keep, reason, scanLevel } = await validateDomain(domain);

    if (keep) {
      kept.push(domain);
      console.log(`[validate] ✅ KEEP ${domain}: ${reason}`);
    } else {
      // Remove the domain file
      const filePath = path.join(DOMAINS_DIR, `${domain}.json`);
      fs.rmSync(filePath);
      removed.push({ domain, reason, scanLevel });
      console.log(`[validate] ❌ REMOVED ${domain}: ${reason}`);
    }
  }

  // Rebuild stats after removals
  if (removed.length > 0) {
    console.log("[validate] Rebuilding stats after removals...");
    try {
      execSync("npm run rebuild-stats", { cwd: PROJECT_ROOT, stdio: "inherit" });
    } catch {
      console.warn("[validate] rebuild-stats failed, continuing...");
    }
  }

  // Notify Discord about removed domains
  if (removed.length > 0 && webhookUrl) {
    const lines = [
      `🚫 **自動除外: ${removed.length}件** (IDPIターゲットでないドメイン)`,
      "",
    ];
    for (const { domain, reason, scanLevel } of removed) {
      lines.push(`**${domain}**`);
      lines.push(`  除外理由: ${reason}`);
      lines.push(`  IDPIスキャン: ${scanLevel}`);
      lines.push("");
    }
    lines.push("HTSBPの対象範囲（AIエージェントへのIDPI攻撃）外のため自動削除しました。");

    const msg = lines.join("\n");
    if (msg.length <= 2000) {
      await notify(msg);
    } else {
      await notify(lines.slice(0, 3).join("\n"));
      for (const { domain, reason } of removed) {
        await notify(`🚫 **${domain}** — ${reason}`);
      }
    }
  }

  console.log(`[validate] Done: ${kept.length} kept, ${removed.length} removed.`);
}

main().catch(err => {
  console.error("[validate] Fatal error:", err);
  process.exit(1);
});
