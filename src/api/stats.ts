/**
 * GET /api/stats
 * Return threat statistics summary.
 */
import {
  loadStats,
  handleCors,
  jsonResponse,
  type NetlifyEvent,
  type NetlifyResponse,
} from "../lib/data-loader.js";

export const handler = async (event: NetlifyEvent): Promise<NetlifyResponse> => {
  const cors = handleCors(event);
  if (cors) return cors;

  const stats = loadStats();
  return jsonResponse(stats);
};
