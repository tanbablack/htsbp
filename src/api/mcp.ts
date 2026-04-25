/**
 * MCP Server endpoint: POST /api/mcp (Streamable HTTP transport)
 *
 * Implements the MCP Streamable HTTP transport as required by Anthropic's
 * Connectors Directory. Only POST is supported — no SSE connection dance.
 *
 * POST — Handles JSON-RPC 2.0 messages (initialize, tools/list, tools/call).
 */
import { processRequest } from "../mcp/index.js";
import {
  corsHeaders,
  type NetlifyEvent,
  type NetlifyResponse,
} from "../lib/data-loader.js";

const MCP_HEADERS: Record<string, string> = {
  ...corsHeaders,
  "Cache-Control": "no-cache",
};

export const handler = async (event: NetlifyEvent): Promise<NetlifyResponse> => {
  // CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        ...corsHeaders,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept",
      },
      body: "",
    };
  }

  // Only POST is accepted for Streamable HTTP transport
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: MCP_HEADERS,
      body: JSON.stringify({ error: "Method not allowed. Use POST." }),
    };
  }

  if (!event.body) {
    return {
      statusCode: 400,
      headers: MCP_HEADERS,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Empty request body" },
      }),
    };
  }

  const response = await processRequest(event.body);

  return {
    statusCode: 200,
    headers: {
      ...MCP_HEADERS,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(response),
  };
};
