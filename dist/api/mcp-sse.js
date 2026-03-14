"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/api/mcp-sse.ts
var mcp_sse_exports = {};
__export(mcp_sse_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(mcp_sse_exports);

// src/mcp/tools.ts
var MCP_TOOLS = [
  {
    name: "check_domain",
    description: "Check if a domain hosts known IDPI (Indirect Prompt Injection) attacks targeting AI agents",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain to check (e.g. reviewerpress.com)"
        }
      },
      required: ["domain"]
    }
  },
  {
    name: "check_url",
    description: "Check if a specific URL contains known IDPI payloads",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Full URL to check"
        }
      },
      required: ["url"]
    }
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
          description: "Filter by severity level"
        },
        intent: {
          type: "string",
          description: "Filter by attack intent"
        },
        limit: {
          type: "number",
          description: "Maximum number of results (default: 20, max: 50)"
        }
      }
    }
  }
];

// src/lib/data-loader.ts
var import_node_fs = __toESM(require("node:fs"), 1);
var import_node_path = __toESM(require("node:path"), 1);
function getDataDir() {
  return import_node_path.default.join(process.cwd(), "data");
}
function loadThreatIndex() {
  const filePath = import_node_path.default.join(getDataDir(), "threats", "index.json");
  return JSON.parse(import_node_fs.default.readFileSync(filePath, "utf-8"));
}
function loadDomainThreats(domain) {
  const filePath = import_node_path.default.join(getDataDir(), "threats", "domains", `${domain}.json`);
  if (!import_node_fs.default.existsSync(filePath))
    return null;
  return JSON.parse(import_node_fs.default.readFileSync(filePath, "utf-8"));
}
var corsHeaders = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

// src/mcp/handlers.ts
function handleCheckDomain(args) {
  const domain = args.domain?.toLowerCase().trim();
  if (!domain) {
    return { content: [{ type: "text", text: "Error: missing required argument 'domain'" }], isError: true };
  }
  const data = loadDomainThreats(domain);
  if (!data) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ domain, is_malicious: false, threats: [] }, null, 2)
      }]
    };
  }
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        domain: data.domain,
        is_malicious: data.threats.some((t) => t.is_active),
        threats: data.threats
      }, null, 2)
    }]
  };
}
function handleCheckUrl(args) {
  const rawUrl = args.url?.trim();
  if (!rawUrl) {
    return { content: [{ type: "text", text: "Error: missing required argument 'url'" }], isError: true };
  }
  let parsedUrl;
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
        text: JSON.stringify({ url: rawUrl, domain, is_malicious: false, threats: [] }, null, 2)
      }]
    };
  }
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        url: rawUrl,
        domain: data.domain,
        is_malicious: data.threats.some((t) => t.is_active),
        threats: data.threats
      }, null, 2)
    }]
  };
}
function handleListThreats(args) {
  const severity = args.severity;
  const intent = args.intent;
  const limit = Math.min(Math.max(Number(args.limit) || 20, 1), 50);
  const index = loadThreatIndex();
  const results = [];
  for (const [domain, entry] of Object.entries(index.domains)) {
    if (intent && !entry.intents.includes(intent))
      continue;
    const domainData = loadDomainThreats(domain);
    if (!domainData)
      continue;
    for (const threat of domainData.threats) {
      if (severity && threat.severity !== severity)
        continue;
      if (intent && threat.intent !== intent)
        continue;
      results.push({ ...threat, domain });
    }
  }
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  results.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));
  return {
    content: [{
      type: "text",
      text: JSON.stringify({ threats: results.slice(0, limit), total: results.length }, null, 2)
    }]
  };
}
function executeTool(name, args) {
  switch (name) {
    case "check_domain":
      return handleCheckDomain(args);
    case "check_url":
      return handleCheckUrl(args);
    case "list_threats":
      return handleListThreats(args);
    default:
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
  }
}

// src/mcp/server.ts
var SERVER_INFO = {
  name: "htsbp",
  version: "1.0.0"
};
var SERVER_CAPABILITIES = {
  tools: {}
};
function handleJsonRpc(request) {
  const id = request.id ?? null;
  switch (request.method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: SERVER_INFO,
          capabilities: SERVER_CAPABILITIES
        }
      };
    case "notifications/initialized":
      return { jsonrpc: "2.0", id, result: {} };
    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: MCP_TOOLS }
      };
    case "tools/call": {
      const params = request.params ?? {};
      const toolName = params.name;
      const toolArgs = params.arguments ?? {};
      if (!toolName) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "Missing tool name" }
        };
      }
      const result = executeTool(toolName, toolArgs);
      return { jsonrpc: "2.0", id, result };
    }
    case "ping":
      return { jsonrpc: "2.0", id, result: {} };
    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${request.method}` }
      };
  }
}
function processRequest(body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" }
    };
  }
  if (Array.isArray(parsed)) {
    return parsed.map((req) => handleJsonRpc(req));
  }
  return handleJsonRpc(parsed);
}

// src/api/mcp-sse.ts
var MCP_HEADERS = {
  ...corsHeaders,
  "Cache-Control": "no-cache"
};
var handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        ...corsHeaders,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept"
      },
      body: ""
    };
  }
  if (event.httpMethod === "GET") {
    const host = event.headers.host ?? "localhost:8888";
    const proto = event.headers["x-forwarded-proto"] ?? "https";
    const endpointUrl = `${proto}://${host}/api/mcp-sse`;
    const sseBody = [
      `event: endpoint`,
      `data: ${endpointUrl}`,
      ``,
      ``
    ].join("\n");
    return {
      statusCode: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*"
      },
      body: sseBody
    };
  }
  if (event.httpMethod === "POST") {
    if (!event.body) {
      return {
        statusCode: 400,
        headers: MCP_HEADERS,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Empty request body" }
        })
      };
    }
    const response = processRequest(event.body);
    return {
      statusCode: 200,
      headers: {
        ...MCP_HEADERS,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(response)
    };
  }
  return {
    statusCode: 405,
    headers: MCP_HEADERS,
    body: JSON.stringify({ error: "Method not allowed" })
  };
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handler
});
