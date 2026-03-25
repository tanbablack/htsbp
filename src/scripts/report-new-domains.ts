/**
 * report-new-domains.ts
 *
 * Detects newly added domains since the last git commit, scans each with
 * check-url for IDPI patterns, and reports results to Discord.
 *
 * Usage:
 *   NOTIFICATION_WEBHOOK_URL=... npx tsx src/scripts/report-new-domains.ts
 *
 * Expected environment:
 *   NOTIFICATION_WEBHOOK_URL  Discord webhook URL
 *   DOMAINS_BEFORE            Space-separated list of domains before collection
 *                             (passed from collect.yml via env var)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkUrl, type ThreatLevel } from "./check-url.js";
import type { ThreatFile } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

const LEVEL_EMOJI: Record<ThreatLevel, string> = {
  HIGH: "🔴",
  MEDIUM: "🟡",
  LOW: "🟢",
  CLEAN: "✅",
  UNREACHABLE: "❌",
};

/** Send a message to Discord webhook */
async function sendDiscord(content: string): Promise<void> {
  const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn("[report-new] NOTIFICATION_WEBHOOK_URL not set, skipping notification");
    return;
  }
  await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });
}

async function main(): Promise<void> {
  const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn("[report-new] NOTIFICATION_WEBHOOK_URL not set, skipping");
    return;
  }

  // Domains before collection (passed as env var from collect.yml)
  const domainsBefore = new Set(
    (process.env.DOMAINS_BEFORE ?? "").split(" ").filter(Boolean)
  );

  // Current domains after collection
  const currentFiles = fs.existsSync(DOMAINS_DIR)
    ? fs.readdirSync(DOMAINS_DIR).filter(f => f.endsWith(".json"))
    : [];
  const currentDomains = currentFiles.map(f => f.replace(".json", ""));

  // Find new domains
  const newDomains = currentDomains.filter(d => !domainsBefore.has(d));

  if (newDomains.length === 0) {
    console.log("[report-new] No new domains added.");
    return;
  }

  console.log(`[report-new] ${newDomains.length} new domain(s) detected: ${newDomains.join(", ")}`);

  const lines: string[] = [
    `🆕 **新規ドメイン追加: ${newDomains.length}件**`,
    "",
  ];

  for (const domain of newDomains) {
    const filePath = path.join(DOMAINS_DIR, `${domain}.json`);
    const data: ThreatFile = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const threat = data.threats[0];
    if (!threat) continue;

    // Run IDPI pattern scan
    console.log(`[report-new] Scanning ${domain}...`);
    const scanUrl = threat.url ?? `https://${domain}`;
    const result = await checkUrl(scanUrl);
    const emoji = LEVEL_EMOJI[result.level];

    lines.push(`**${domain}**`);
    lines.push(`  IDPIスキャン: ${emoji} ${result.level}`);
    lines.push(`  重大度: ${threat.severity} | 意図: ${threat.intent}`);
    lines.push(`  ソース: ${threat.source}`);
    lines.push(`  説明: ${(threat.description ?? "").slice(0, 120)}`);
    if (threat.source_url) {
      lines.push(`  参照: <${threat.source_url}>`);
    }
    if (result.level === "CLEAN") {
      lines.push(`  ⚠️ IDPIパターン未検出 — 削除検討を推奨`);
    } else if (result.level === "UNREACHABLE") {
      lines.push(`  ⚠️ URLに到達不能 — 削除検討を推奨`);
    }
    lines.push("");
  }

  lines.push("削除が必要な場合は指示してください。");

  const message = lines.join("\n");

  // Discord has 2000 char limit per message — split if needed
  if (message.length <= 2000) {
    await sendDiscord(message);
  } else {
    // Send header first
    await sendDiscord(lines.slice(0, 3).join("\n"));
    // Send each domain as separate message
    let chunk: string[] = [];
    for (const line of lines.slice(3)) {
      chunk.push(line);
      if (chunk.join("\n").length > 1600 || line === "") {
        if (chunk.join("\n").trim()) {
          await sendDiscord(chunk.join("\n"));
        }
        chunk = [];
      }
    }
    if (chunk.join("\n").trim()) {
      await sendDiscord(chunk.join("\n"));
    }
  }

  console.log("[report-new] Notification sent.");
}

main().catch(err => {
  console.error("[report-new] Fatal error:", err);
  process.exit(1);
});
