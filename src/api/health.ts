/**
 * GET /api/health
 * Health check endpoint returning system status.
 */
import {
  countDomainFiles,
  loadStats,
  handleCors,
  jsonResponse,
  type NetlifyEvent,
  type NetlifyResponse,
} from "../lib/data-loader.js";

export const handler = async (event: NetlifyEvent): Promise<NetlifyResponse> => {
  const cors = handleCors(event);
  if (cors) return cors;

  try {
    const stats = loadStats();
    return jsonResponse({
      status: "ok",
      data_file_count: countDomainFiles(),
      last_updated: stats.last_updated,
      version: "1.0.0",
    });
  } catch {
    return jsonResponse({ status: "error", message: "Failed to load data" }, 500);
  }
};
