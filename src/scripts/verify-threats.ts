/**
 * Auto-verify collected threat domains by actively scanning for IDPI patterns.
 * Updates severity based on scan results:
 *   HIGH findings    → severity: "high" (or keep "critical")
 *   MEDIUM findings  → severity: "medium"
 *   LOW findings     → severity: "low"
 *   CLEAN            → is_active: false (threat may have been remediated)
 *   UNREACHABLE      → no change (can't confirm or deny)
 *
 * Usage: npx tsx src/scripts/verify-threats.ts
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkUrl, type ThreatLevel } from "./check-url.js";
import type { ThreatFile, Severity } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

/** Map check-url ThreatLevel to domain severity */
function levelToSeverity(level: ThreatLevel, currentSeverity: Severity): Severity {
  switch (level) {
    case "HIGH": return currentSeverity === "critical" ? "critical" : "high";
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    default: return currentSeverity; // CLEAN/UNREACHABLE: no change here
  }
}

interface VerifyResult {
  domain: string;
  level: ThreatLevel;
  reason?: string;
  severityChanged: boolean;
  oldSeverity?: Severity;
  newSeverity?: Severity;
  deactivated: boolean;
}

async function main(): Promise<void> {
  if (!fs.existsSync(DOMAINS_DIR)) {
    console.log("No domains directory found.");
    return;
  }

  const domainFiles = fs.readdirSync(DOMAINS_DIR).filter(f => f.endsWith(".json"));
  console.log(`\n🔍 Verifying ${domainFiles.length} domains...\n`);

  const results: VerifyResult[] = [];
  let changed = 0;

  for (const file of domainFiles) {
    const filePath = path.join(DOMAINS_DIR, file);
    const data: ThreatFile = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const domain = data.domain;

    // Check the domain's main URL
    const result = await checkUrl(`https://${domain}`);
    const verifyResult: VerifyResult = {
      domain,
      level: result.level,
      reason: result.reason,
      severityChanged: false,
      deactivated: false,
    };

    let fileChanged = false;

    if (result.level === "CLEAN") {
      // No IDPI found — mark active threats as inactive
      for (const threat of data.threats) {
        if (threat.is_active) {
          threat.is_active = false;
          verifyResult.deactivated = true;
          fileChanged = true;
        }
      }
    } else if (result.level === "HIGH" || result.level === "MEDIUM" || result.level === "LOW") {
      // Update severity based on actual scan
      for (const threat of data.threats) {
        if (!threat.is_active) continue;
        const newSeverity = levelToSeverity(result.level, threat.severity);
        if (newSeverity !== threat.severity) {
          verifyResult.oldSeverity = threat.severity;
          verifyResult.newSeverity = newSeverity;
          verifyResult.severityChanged = true;
          threat.severity = newSeverity;
          fileChanged = true;
        }
        threat.last_seen = new Date().toISOString();
        fileChanged = true;
      }
    }
    // UNREACHABLE: no changes

    if (fileChanged) {
      data.updated_at = new Date().toISOString();
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n");
      changed++;
    }

    results.push(verifyResult);

    // Status output
    const icon = result.level === "HIGH" ? "🔴" :
                 result.level === "MEDIUM" ? "🟡" :
                 result.level === "LOW" ? "🟢" :
                 result.level === "CLEAN" ? "✅" : "❌";
    const extra = result.level === "UNREACHABLE" ? ` (${result.reason})` :
                  verifyResult.severityChanged ? ` severity: ${verifyResult.oldSeverity} → ${verifyResult.newSeverity}` :
                  verifyResult.deactivated ? " → deactivated" : "";
    console.log(`  ${icon} ${domain}: ${result.level}${extra}`);
  }

  // Summary
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, CLEAN: 0, UNREACHABLE: 0 };
  for (const r of results) counts[r.level]++;

  console.log(`\n${"─".repeat(50)}`);
  console.log(`Verification complete: ${domainFiles.length} domains`);
  console.log(`  🔴 HIGH: ${counts.HIGH}  🟡 MEDIUM: ${counts.MEDIUM}  🟢 LOW: ${counts.LOW}`);
  console.log(`  ✅ CLEAN: ${counts.CLEAN}  ❌ UNREACHABLE: ${counts.UNREACHABLE}`);
  console.log(`  Files updated: ${changed}\n`);
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
