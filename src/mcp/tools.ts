/** MCP Tool definitions for HTSBP */

export interface McpToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
  annotations?: McpToolAnnotations;
}

export const MCP_TOOLS: McpToolDefinition[] = [
  {
    name: "check_domain",
    description:
      "Check if a domain hosts known IDPI (Indirect Prompt Injection) attacks targeting AI agents",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain to check (e.g. reviewerpress.com)",
        },
      },
      required: ["domain"],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
    },
  },
  {
    name: "check_url",
    description: "Check if a specific URL contains known IDPI payloads",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Full URL to check",
        },
      },
      required: ["url"],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
    },
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
        intent: {
          type: "string",
          description: "Filter by attack intent",
        },
        limit: {
          type: "number",
          description: "Maximum number of results (default: 20, max: 50)",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
    },
  },
  {
    name: "report_threat",
    description:
      "Report a suspected IDPI threat URL for investigation. Creates a tracked report that will be automatically verified and registered if confirmed.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "URL suspected of containing IDPI payloads (required)",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Estimated severity (optional, will be auto-assessed)",
        },
        description: {
          type: "string",
          description: "Description of the suspected threat (optional)",
        },
      },
      required: ["url"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
    },
  },
];
