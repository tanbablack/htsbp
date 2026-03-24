/**
 * Run all threat data collectors sequentially.
 * Each collector's failure does not block others.
 * After all collectors run, rebuilds stats and commits changes.
 */
import { execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");

interface CollectorResult {
  name: string;
  success: boolean;
  added: number;
  updated: number;
  error?: string;
}

/** Dynamically import and run a collector */
async function runCollector(name: string, modulePath: string): Promise<CollectorResult> {
  console.log(`\n${"=".repeat(50)}`);
  console.log(`Running collector: ${name}`);
  console.log("=".repeat(50));

  try {
    const mod = await import(modulePath);
    const result = await mod.collect();
    return {
      name,
      success: true,
      added: result.added ?? 0,
      updated: result.updated ?? 0,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[${name}] Error: ${message}`);
    return {
      name,
      success: false,
      added: 0,
      updated: 0,
      error: message,
    };
  }
}

/** Send error notification via webhook */
async function sendNotification(message: string): Promise<void> {
  const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn("NOTIFICATION_WEBHOOK_URL not set, skipping notification");
    return;
  }

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: message }),
    });
  } catch (err) {
    console.error("Failed to send notification:", err);
  }
}

/** Rebuild stats and index files */
function rebuildStats(): void {
  console.log("\nRebuilding stats and index...");
  execSync("npx tsx src/scripts/rebuild-stats.ts", {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
}

/** Git commit and push data changes */
function gitCommitAndPush(totalAdded: number, totalUpdated: number): void {
  try {
    // Check if there are changes
    const status = execSync("git status --porcelain data/", {
      cwd: PROJECT_ROOT,
      encoding: "utf-8",
    }).trim();

    if (!status) {
      console.log("\nNo data changes to commit.");
      return;
    }

    console.log("\nCommitting data changes...");
    execSync("git add data/", { cwd: PROJECT_ROOT, stdio: "inherit" });
    const message = `data: update threats [auto] - ${totalAdded} new, ${totalUpdated} updated`;
    execSync(`git commit -m "${message}"`, { cwd: PROJECT_ROOT, stdio: "inherit" });
    execSync("git push", { cwd: PROJECT_ROOT, stdio: "inherit" });
    console.log("Changes pushed successfully.");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Git operation failed:", message);
  }
}

/** Main entry point */
async function main(): Promise<void> {
  const collectors: Array<[string, string]> = [
    ["unit42-github", "../collectors/unit42-github.js"],
    ["otx-alienvault", "../collectors/otx-alienvault.js"],
    // tldrsec-github removed: tldrsec/prompt-injection-defenses is a defense
    // techniques reference, not an attack site list. All URLs it contained
    // were research/tool references, not actual IDPI threat domains.
    ["web-crawler", "../collectors/web-crawler.js"],
  ];

  const results: CollectorResult[] = [];

  for (const [name, modulePath] of collectors) {
    const result = await runCollector(name, modulePath);
    results.push(result);
  }

  // Summary
  console.log(`\n${"=".repeat(50)}`);
  console.log("Collection Summary");
  console.log("=".repeat(50));

  let totalAdded = 0;
  let totalUpdated = 0;
  const failures: CollectorResult[] = [];

  for (const r of results) {
    const status = r.success ? "OK" : "FAILED";
    console.log(`  ${r.name}: ${status} (${r.added} added, ${r.updated} updated)`);
    totalAdded += r.added;
    totalUpdated += r.updated;
    if (!r.success) failures.push(r);
  }

  console.log(`\nTotal: ${totalAdded} added, ${totalUpdated} updated`);

  // Rebuild stats
  rebuildStats();

  // Git commit and push (only in CI)
  if (process.env.CI || process.env.GITHUB_ACTIONS) {
    gitCommitAndPush(totalAdded, totalUpdated);
  }

  // Send error notifications
  if (failures.length > 0) {
    const errorMessages = failures
      .map(f => `Source: ${f.name}\nError: ${f.error}`)
      .join("\n\n");
    await sendNotification(
      `🚨 HTSBP Collector Error\n\n${errorMessages}`
    );
  }
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
