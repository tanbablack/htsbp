/**
 * POST /api/report-threat
 *
 * URL + 出典 + 説明を受け取り、PR を起票する (検証は pr-validate.yml が PR で実行)。
 *
 * 入力 JSON:
 *   {
 *     url: string,          // 必須
 *     source_url: string,   // 必須
 *     description: string,  // 必須 (20文字以上)
 *     severity?: "critical" | "high" | "medium" | "low"
 *   }
 *
 * レスポンス:
 *   201 { pr_url, pr_number, branch, host }
 *   400 { error: <field>, message }
 *   500 { error: "internal", message }
 */
import {
  handleCors,
  jsonResponse,
  errorResponse,
  type NetlifyEvent,
  type NetlifyResponse,
} from "../lib/data-loader.js";
import {
  submitThreatReport,
  ReportValidationError,
  type SubmitInput,
} from "../lib/report.js";

export const handler = async (event: NetlifyEvent): Promise<NetlifyResponse> => {
  const cors = handleCors(event);
  if (cors) return cors;

  if (event.httpMethod !== "POST") {
    return errorResponse("Method not allowed. Use POST.", 405);
  }
  if (!event.body) {
    return errorResponse("Empty request body");
  }

  let input: SubmitInput;
  try {
    input = JSON.parse(event.body) as SubmitInput;
  } catch {
    return errorResponse("Invalid JSON body");
  }

  try {
    const result = await submitThreatReport(input);
    return jsonResponse(
      {
        success: true,
        message: "PR を起票しました。pr-validate ワークフローが自動検証を実行します。",
        ...result,
      },
      201,
    );
  } catch (err) {
    if (err instanceof ReportValidationError) {
      return jsonResponse({ error: err.field, message: err.message }, 400);
    }
    const message = err instanceof Error ? err.message : String(err);
    return jsonResponse({ error: "internal", message }, 500);
  }
};
