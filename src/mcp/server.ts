/** MCP JSON-RPC 2.0 protocol handling */
import { MCP_TOOLS } from "./tools.js";
import { executeTool } from "./handlers.js";

const SERVER_INFO = {
  name: "htsbp",
  version: "1.0.0",
};

const SERVER_CAPABILITIES = {
  tools: {},
};

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

/** Process a single JSON-RPC request and return a response */
export function handleJsonRpc(request: JsonRpcRequest): JsonRpcResponse {
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
      // Notification — no response needed, but return ack if id present
      return { jsonrpc: "2.0", id, result: {} };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: MCP_TOOLS },
      };

    case "tools/call": {
      const params = request.params ?? {};
      const toolName = params.name as string;
      const toolArgs = (params.arguments ?? {}) as Record<string, unknown>;

      if (!toolName) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "Missing tool name" },
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
        error: { code: -32601, message: `Method not found: ${request.method}` },
      };
  }
}

/** Parse and process a JSON-RPC request body string */
export function processRequest(body: string): JsonRpcResponse | JsonRpcResponse[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" },
    };
  }

  // Batch request
  if (Array.isArray(parsed)) {
    return parsed.map(req => handleJsonRpc(req as JsonRpcRequest));
  }

  return handleJsonRpc(parsed as JsonRpcRequest);
}
