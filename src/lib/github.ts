/**
 * GitHub API utilities for creating threat report issues.
 */

export interface ThreatReportInput {
  url: string;
  severity?: string;
  description?: string;
}

export interface ThreatReportResult {
  issueUrl: string;
  issueNumber: number;
}

const GITHUB_API = "https://api.github.com";

/** Create a GitHub Issue for a threat report */
export async function createThreatReportIssue(
  input: ThreatReportInput,
): Promise<ThreatReportResult> {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;

  if (!token) {
    throw new Error("GITHUB_TOKEN environment variable is required");
  }
  if (!repo) {
    throw new Error("GITHUB_REPOSITORY environment variable is required (e.g. owner/repo)");
  }

  // Extract domain from URL for issue title
  let domain: string;
  try {
    domain = new URL(input.url).hostname;
  } catch {
    domain = input.url;
  }

  const severity = input.severity ?? "unsure";
  const description = input.description ?? "No description provided";

  // Structured body — machine-parseable by process-reports.ts
  const body = [
    `## Threat Report`,
    ``,
    `**URL:** \`${input.url}\``,
    `**Severity:** ${severity}`,
    `**Description:** ${description}`,
    ``,
    `---`,
    `_Reported via HTSBP MCP/API_`,
  ].join("\n");

  const res = await fetch(`${GITHUB_API}/repos/${repo}/issues`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      title: `[Threat Report] ${domain}`,
      body,
      labels: ["new-threat"],
    }),
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`GitHub API error ${res.status}: ${errorText}`);
  }

  const data = (await res.json()) as { html_url: string; number: number };
  return { issueUrl: data.html_url, issueNumber: data.number };
}

/** Send a Discord notification via webhook */
export async function sendDiscordNotification(message: string): Promise<void> {
  const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn("NOTIFICATION_WEBHOOK_URL is not set, skipping Discord notification");
    return;
  }

  try {
    console.log("Sending Discord notification to webhook...");
    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: message }),
    });

    if (!res.ok) {
      const errorBody = await res.text().catch(() => "(no body)");
      console.error(`Discord webhook error ${res.status}: ${errorBody}`);
    } else {
      console.log("Discord notification sent successfully");
    }
  } catch (err) {
    console.error("Failed to send Discord notification:", err);
  }
}
