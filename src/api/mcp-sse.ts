/**
 * MCP Server endpoint: GET /api/mcp-sse (SSE) and POST /api/mcp-sse (Streamable HTTP)
 *
 * GET  — Returns SSE stream with endpoint event for the POST URL.
 * POST — Handles JSON-RPC 2.0 messages (initialize, tools/list, tools/call).
 *
 * Due to Netlify Functions timeout constraints, the SSE connection is one-shot.
 * The Streamable HTTP transport (POST) is the primary interaction path.
 */
import { processRequest } from "../mcp/server.js";
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
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept",
      },
      body: "",
    };
  }

  // GET — SSE: send endpoint event pointing to this same URL for POST
  if (event.httpMethod === "GET") {
    // Determine the base URL for the POST endpoint
    const host = event.headers.host ?? "localhost:8888";
    const proto = event.headers["x-forwarded-proto"] ?? "https";
    const endpointUrl = `${proto}://${host}/api/mcp-sse`;

    // Return SSE response with the endpoint event
    const sseBody = [
      `event: endpoint`,
      `data: ${endpointUrl}`,
      ``,
      ``,
    ].join("\n");

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
      },
      body: sseBody,
    };
  }

  // POST — Streamable HTTP: handle JSON-RPC 2.0
  if (event.httpMethod === "POST") {
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

    const response = processRequest(event.body);

    return {
      statusCode: 200,
      headers: {
        ...MCP_HEADERS,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(response),
    };
  }

  return {
    statusCode: 405,
    headers: MCP_HEADERS,
    body: JSON.stringify({ error: "Method not allowed" }),
  };
};
