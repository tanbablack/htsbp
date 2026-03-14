/**
 * POST /api/report-threat
 * Report a suspected IDPI threat URL. Creates a GitHub Issue for tracking.
 *
 * Body: { url: string, severity?: string, description?: string }
 */
import {
  createThreatReportIssue,
  sendDiscordNotification,
} from "../lib/github.js";
import {
  corsHeaders,
  jsonResponse,
  errorResponse,
  type NetlifyEvent,
  type NetlifyResponse,
} from "../lib/data-loader.js";

const POST_CORS_HEADERS: Record<string, string> = {
  ...corsHeaders,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

export const handler = async (event: NetlifyEvent): Promise<NetlifyResponse> => {
  // CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        ...POST_CORS_HEADERS,
        "Access-Control-Allow-Headers": "Content-Type",
      },
      body: "",
    };
  }

  if (event.httpMethod !== "POST") {
    return errorResponse("Method not allowed. Use POST.", 405);
  }

  if (!event.body) {
    return errorResponse("Request body is required");
  }

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(event.body);
  } catch {
    return errorResponse("Invalid JSON body");
  }

  const url = (body.url as string | undefined)?.trim();
  if (!url) {
    return errorResponse("Missing required field: url");
  }

  try {
    new URL(url);
  } catch {
    return errorResponse("Invalid URL format. Provide a full URL (e.g. https://example.com/page)");
  }

  try {
    const result = await createThreatReportIssue({
      url,
      severity: body.severity as string | undefined,
      description: body.description as string | undefined,
    });

    let notificationSent = false;
    try {
      await sendDiscordNotification(
        `🆕 新しい脅威通報\n\nURL: ${url}\nIssue: ${result.issueUrl}`,
      );
      notificationSent = true;
    } catch (notifyErr) {
      console.error("Discord notification failed:", notifyErr);
    }

    return {
      statusCode: 201,
      headers: POST_CORS_HEADERS,
      body: JSON.stringify({
        success: true,
        message: "Threat report created. It will be automatically verified during the next daily collection.",
        issue_url: result.issueUrl,
        issue_number: result.issueNumber,
        notification_sent: notificationSent,
      }),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("Failed to create threat report:", message);
    return errorResponse(`Failed to create report: ${message}`, 500);
  }
};
