/**
 * Process threat reports from GitHub Issues (new-threat label).
 *
 * For each open issue with `new-threat` label:
 * 1. Extract URL from issue body
 * 2. Run checkUrl() to verify IDPI presence
 * 3. If threat detected → register in data/ via upsertThreat() and close issue
 * 4. If clean → comment and close issue
 * 5. If unreachable → leave open for retry (close after 3 retries)
 *
 * Runs as part of daily GitHub Actions collection.
 * Requires: GITHUB_TOKEN, GITHUB_REPOSITORY env vars.
 */
import { checkUrl, type ThreatLevel } from "./check-url.js";
import { upsertThreat, extractDomain } from "../collectors/common.js";
import { sendDiscordNotification } from "../lib/github.js";
import type { Threat, Severity, Technique } from "../types/index.js";

const GITHUB_API = "https://api.github.com";

interface GitHubIssue {
  number: number;
  title: string;
  body: string;
  html_url: string;
  labels: Array<{ name: string }>;
}

/** Extract URL from structured issue body */
function extractUrlFromBody(body: string): string | null {
  // Match: **URL:** `https://...`
  const match = body.match(/\*\*URL:\*\*\s*`([^`]+)`/);
  if (match) return match[1];

  // Fallback: match from issue template format (yaml-based)
  const urlMatch = body.match(/### URL\s*\n+\s*(https?:\/\/\S+)/);
  if (urlMatch) return urlMatch[1];

  // Last fallback: first URL in body
  const anyUrl = body.match(/https?:\/\/\S+/);
  return anyUrl ? anyUrl[0] : null;
}

/** Extract severity from issue body */
function extractSeverityFromBody(body: string): Severity {
  const match = body.match(/\*\*Severity:\*\*\s*(\w+)/);
  if (match) {
    const s = match[1].toLowerCase();
    if (["critical", "high", "medium", "low"].includes(s)) return s as Severity;
  }
  return "medium";
}

/** Count retry labels on an issue */
function getRetryCount(issue: GitHubIssue): number {
  return issue.labels.filter(l => l.name.startsWith("retry-")).length;
}

/** Map ThreatLevel to Severity */
function levelToSeverity(level: ThreatLevel): Severity {
  switch (level) {
    case "HIGH": return "high";
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    default: return "medium";
  }
}

/** Map finding types to techniques */
function findingsToTechniques(findings: Array<{ type: string }>): Technique[] {
  const techniques: Technique[] = [];
  for (const f of findings) {
    switch (f.type) {
      case "concealment": techniques.push("css_display_none"); break;
      case "comment_injection": techniques.push("html_comment"); break;
      case "meta_injection": techniques.push("html_attribute_cloaking"); break;
      case "aria_injection": techniques.push("html_attribute_cloaking"); break;
    }
  }
  return [...new Set(techniques)];
}

/** GitHub API helper */
async function githubApi(
  method: string,
  endpoint: string,
  body?: unknown,
): Promise<unknown> {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  if (!token || !repo) {
    throw new Error("GITHUB_TOKEN and GITHUB_REPOSITORY are required");
  }

  const res = await fetch(`${GITHUB_API}/repos/${repo}${endpoint}`, {
    method,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API ${method} ${endpoint}: ${res.status} ${text}`);
  }

  return res.json();
}

/** Comment on an issue */
async function commentOnIssue(issueNumber: number, comment: string): Promise<void> {
  await githubApi("POST", `/issues/${issueNumber}/comments`, { body: comment });
}

/** Close an issue */
async function closeIssue(issueNumber: number): Promise<void> {
  await githubApi("PATCH", `/issues/${issueNumber}`, { state: "closed" });
}

/** Add a label to an issue */
async function addLabel(issueNumber: number, label: string): Promise<void> {
  await githubApi("POST", `/issues/${issueNumber}/labels`, { labels: [label] });
}

/** Main entry point */
async function main(): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  if (!token || !repo) {
    console.log("[process-reports] GITHUB_TOKEN or GITHUB_REPOSITORY not set, skipping");
    return;
  }

  console.log("[process-reports] Fetching open issues with 'new-threat' label...");

  const issues = (await githubApi(
    "GET",
    "/issues?labels=new-threat&state=open&per_page=20",
  )) as GitHubIssue[];

  if (issues.length === 0) {
    console.log("[process-reports] No open threat reports to process");
    return;
  }

  console.log(`[process-reports] Found ${issues.length} report(s) to process`);

  let registered = 0;
  let clean = 0;
  let unreachable = 0;

  for (const issue of issues) {
    const url = extractUrlFromBody(issue.body ?? "");
    if (!url) {
      console.log(`[process-reports] #${issue.number}: Could not extract URL, skipping`);
      await commentOnIssue(issue.number, "⚠️ URLを抽出できませんでした。手動で確認してください。");
      continue;
    }

    console.log(`[process-reports] #${issue.number}: Checking ${url}...`);
    const result = await checkUrl(url);

    switch (result.level) {
      case "HIGH":
      case "MEDIUM": {
        const domain = extractDomain(url);
        if (!domain) {
          console.log(`[process-reports] #${issue.number}: Could not extract domain from ${url}`);
          break;
        }

        const reportedSeverity = extractSeverityFromBody(issue.body ?? "");
        const detectedSeverity = levelToSeverity(result.level);
        // Use the higher severity between reported and detected
        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        const finalSeverity = (severityOrder[reportedSeverity] ?? 3) < (severityOrder[detectedSeverity] ?? 3)
          ? reportedSeverity : detectedSeverity;

        const threat: Threat = {
          url,
          severity: finalSeverity,
          intent: "other",
          techniques: findingsToTechniques(result.findings),
          description: `Community report verified by automated scan. ${result.findings.length} finding(s) detected.`,
          source: "community",
          source_url: issue.html_url,
          first_seen: new Date().toISOString(),
          last_seen: new Date().toISOString(),
          is_active: true,
        };

        upsertThreat(domain, threat);
        registered++;

        const findingSummary = result.findings
          .map(f => `- ${f.label}`)
          .join("\n");

        await commentOnIssue(
          issue.number,
          `✅ **脅威を検出・登録しました**\n\n` +
          `- 脅威レベル: ${result.level}\n` +
          `- 重要度: ${finalSeverity}\n` +
          `- 検出件数: ${result.findings.length}\n\n` +
          `**検出内容:**\n${findingSummary}\n\n` +
          `データベースに自動登録しました。`,
        );
        await addLabel(issue.number, "verified");
        await closeIssue(issue.number);
        console.log(`[process-reports] #${issue.number}: REGISTERED (${result.level})`);
        break;
      }

      case "LOW": {
        await commentOnIssue(
          issue.number,
          `⚠️ **低信頼度の検出あり**\n\n` +
          `脅威レベル: LOW\n` +
          `手動での確認が必要です。自動登録は行いません。`,
        );
        await addLabel(issue.number, "needs-review");
        console.log(`[process-reports] #${issue.number}: LOW - needs manual review`);
        break;
      }

      case "CLEAN": {
        clean++;
        await commentOnIssue(
          issue.number,
          `✅ **IDPIパターン未検出**\n\n` +
          `自動スキャンの結果、このURLにIDPIパターンは検出されませんでした。`,
        );
        await addLabel(issue.number, "clean");
        await closeIssue(issue.number);
        console.log(`[process-reports] #${issue.number}: CLEAN`);
        break;
      }

      case "UNREACHABLE": {
        unreachable++;
        const retryCount = getRetryCount(issue);
        if (retryCount >= 3) {
          await commentOnIssue(
            issue.number,
            `❌ **URLに到達できません（${retryCount + 1}回目）**\n\n` +
            `理由: ${result.reason}\n` +
            `3回以上到達できないため、このIssueを閉じます。`,
          );
          await addLabel(issue.number, "unreachable");
          await closeIssue(issue.number);
          console.log(`[process-reports] #${issue.number}: UNREACHABLE (max retries, closing)`);
        } else {
          await commentOnIssue(
            issue.number,
            `⏳ **URLに到達できません（${retryCount + 1}回目）**\n\n` +
            `理由: ${result.reason}\n` +
            `次回の実行時にリトライします。`,
          );
          await addLabel(issue.number, `retry-${retryCount + 1}`);
          console.log(`[process-reports] #${issue.number}: UNREACHABLE (retry ${retryCount + 1})`);
        }
        break;
      }
    }
  }

  console.log(`\n[process-reports] Summary: ${registered} registered, ${clean} clean, ${unreachable} unreachable`);

  if (registered > 0) {
    await sendDiscordNotification(
      `📋 脅威レポート処理完了\n\n` +
      `登録: ${registered}件\n` +
      `CLEAN: ${clean}件\n` +
      `到達不能: ${unreachable}件`,
    );
  }
}

main().catch(err => {
  console.error("[process-reports] Fatal error:", err);
  process.exit(1);
});
