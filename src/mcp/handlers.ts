/** MCP Tool handlers — execute tool calls using the shared data loader */
import {
  loadDomainThreats,
  loadThreatIndex,
} from "../lib/data-loader.js";
import {
  createThreatReportIssue,
  sendDiscordNotification,
} from "../lib/github.js";
import type { Threat } from "../types/index.js";

interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

/** Handle check_domain tool call */
function handleCheckDomain(args: Record<string, unknown>): ToolResult {
  const domain = (args.domain as string | undefined)?.toLowerCase().trim();
  if (!domain) {
    return { content: [{ type: "text", text: "Error: missing required argument 'domain'" }], isError: true };
  }

  const data = loadDomainThreats(domain);
  if (!data) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ domain, is_malicious: false, threats: [] }, null, 2),
      }],
    };
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        domain: data.domain,
        is_malicious: data.threats.some(t => t.is_active),
        threats: data.threats,
      }, null, 2),
    }],
  };
}

/** Handle check_url tool call */
function handleCheckUrl(args: Record<string, unknown>): ToolResult {
  const rawUrl = (args.url as string | undefined)?.trim();
  if (!rawUrl) {
    return { content: [{ type: "text", text: "Error: missing required argument 'url'" }], isError: true };
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return { content: [{ type: "text", text: "Error: invalid URL format" }], isError: true };
  }

  const domain = parsedUrl.hostname.toLowerCase();
  const data = loadDomainThreats(domain);

  if (!data) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ url: rawUrl, domain, is_malicious: false, threats: [] }, null, 2),
      }],
    };
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        url: rawUrl,
        domain: data.domain,
        is_malicious: data.threats.some(t => t.is_active),
        threats: data.threats,
      }, null, 2),
    }],
  };
}

/** Handle list_threats tool call */
function handleListThreats(args: Record<string, unknown>): ToolResult {
  const severity = args.severity as string | undefined;
  const intent = args.intent as string | undefined;
  const limit = Math.min(Math.max(Number(args.limit) || 20, 1), 50);

  const index = loadThreatIndex();

  interface ThreatWithDomain extends Threat {
    domain: string;
  }
  const results: ThreatWithDomain[] = [];

  for (const [domain, entry] of Object.entries(index.domains)) {
    if (intent && !entry.intents.includes(intent)) continue;

    const domainData = loadDomainThreats(domain);
    if (!domainData) continue;

    for (const threat of domainData.threats) {
      if (severity && threat.severity !== severity) continue;
      if (intent && threat.intent !== intent) continue;
      results.push({ ...threat, domain });
    }
  }

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  results.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  return {
    content: [{
      type: "text",
      text: JSON.stringify({ threats: results.slice(0, limit), total: results.length }, null, 2),
    }],
  };
}

/** Handle report_threat tool call */
async function handleReportThreat(args: Record<string, unknown>): Promise<ToolResult> {
  const rawUrl = (args.url as string | undefined)?.trim();
  if (!rawUrl) {
    return { content: [{ type: "text", text: "Error: missing required argument 'url'" }], isError: true };
  }

  try {
    new URL(rawUrl);
  } catch {
    return { content: [{ type: "text", text: "Error: invalid URL format. Provide a full URL (e.g. https://example.com/page)" }], isError: true };
  }

  try {
    const result = await createThreatReportIssue({
      url: rawUrl,
      severity: args.severity as string | undefined,
      description: args.description as string | undefined,
    });

    await sendDiscordNotification(
      `🆕 新しい脅威通報\n\nURL: ${rawUrl}\nIssue: ${result.issueUrl}`,
    );

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: true,
          message: "Threat report created. It will be automatically verified during the next daily collection.",
          issue_url: result.issueUrl,
          issue_number: result.issueNumber,
        }, null, 2),
      }],
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { content: [{ type: "text", text: `Error creating report: ${message}` }], isError: true };
  }
}

/** Dispatch a tool call by name */
export async function executeTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
  switch (name) {
    case "check_domain":
      return handleCheckDomain(args);
    case "check_url":
      return handleCheckUrl(args);
    case "list_threats":
      return handleListThreats(args);
    case "report_threat":
      return handleReportThreat(args);
    default:
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
  }
}
