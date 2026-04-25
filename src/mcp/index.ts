/**
 * MCP サーバー本体 (tools + handlers + JSON-RPC ルータ 同居)
 *
 * 公開ツール: check_domain / list_threats
 */
import { loadDomainThreats, loadThreatIndex } from "../lib/data-loader.js";
import type { Threat } from "../types.js";

/* ────────────────────────────────────────────────────────────────────────── */
/* Tool 定義                                                                   */
/* ────────────────────────────────────────────────────────────────────────── */

interface McpToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
  annotations?: McpToolAnnotations;
}

const MCP_TOOLS: McpToolDefinition[] = [
  {
    name: "check_domain",
    description:
      "Check if a domain hosts known IDPI (Indirect Prompt Injection) attacks targeting AI agents",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Domain to check (e.g. reviewerpress.com)" },
      },
      required: ["domain"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "list_threats",
    description: "List known IDPI threats with optional filters",
    inputSchema: {
      type: "object",
      properties: {
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level",
        },
        intent: { type: "string", description: "Filter by attack intent" },
        limit: {
          type: "number",
          description: "Maximum number of results (default: 20, max: 50)",
        },
      },
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

/* ────────────────────────────────────────────────────────────────────────── */
/* Handlers                                                                    */
/* ────────────────────────────────────────────────────────────────────────── */

interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

function handleCheckDomain(args: Record<string, unknown>): ToolResult {
  const domain = (args.domain as string | undefined)?.toLowerCase().trim();
  if (!domain) {
    return {
      content: [{ type: "text", text: "Error: missing required argument 'domain'" }],
      isError: true,
    };
  }
  const data = loadDomainThreats(domain);
  if (!data) {
    return {
      content: [
        { type: "text", text: JSON.stringify({ domain, is_malicious: false, threats: [] }, null, 2) },
      ],
    };
  }
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            domain: data.domain,
            is_malicious: data.threats.some((t) => t.is_active),
            threats: data.threats,
          },
          null,
          2,
        ),
      },
    ],
  };
}

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

  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  results.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          { threats: results.slice(0, limit), total: results.length },
          null,
          2,
        ),
      },
    ],
  };
}

async function executeTool(
  name: string,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  switch (name) {
    case "check_domain":
      return handleCheckDomain(args);
    case "list_threats":
      return handleListThreats(args);
    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}

/* ────────────────────────────────────────────────────────────────────────── */
/* JSON-RPC ルータ                                                              */
/* ────────────────────────────────────────────────────────────────────────── */

const SERVER_INFO = { name: "htsbp", version: "1.0.0" };
const SERVER_CAPABILITIES = { tools: {} };

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export async function handleJsonRpc(request: JsonRpcRequest): Promise<JsonRpcResponse> {
  const id = request.id ?? null;
  switch (request.method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: SERVER_INFO,
          capabilities: SERVER_CAPABILITIES,
        },
      };
    case "notifications/initialized":
      return { jsonrpc: "2.0", id, result: {} };
    case "tools/list":
      return { jsonrpc: "2.0", id, result: { tools: MCP_TOOLS } };
    case "tools/call": {
      const params = request.params ?? {};
      const toolName = params.name as string;
      const toolArgs = (params.arguments ?? {}) as Record<string, unknown>;
      if (!toolName) {
        return { jsonrpc: "2.0", id, error: { code: -32602, message: "Missing tool name" } };
      }
      const result = await executeTool(toolName, toolArgs);
      return { jsonrpc: "2.0", id, result };
    }
    case "ping":
      return { jsonrpc: "2.0", id, result: {} };
    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${request.method}` },
      };
  }
}

export async function processRequest(
  body: string,
): Promise<JsonRpcResponse | JsonRpcResponse[]> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } };
  }
  if (Array.isArray(parsed)) {
    return Promise.all(parsed.map((req) => handleJsonRpc(req as JsonRpcRequest)));
  }
  return handleJsonRpc(parsed as JsonRpcRequest);
}
