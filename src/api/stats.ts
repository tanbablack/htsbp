/**
 * GET /api/stats
 *
 * 集計サマリ (LP の counter 表示用) を index.json + domain ファイルから都度算出する。
 * stats.json ファイルは持たない。
 */
import {
  loadDomainThreats,
  loadThreatIndex,
  handleCors,
  jsonResponse,
  type NetlifyEvent,
  type NetlifyResponse,
} from "../lib/data-loader.js";

export const handler = async (event: NetlifyEvent): Promise<NetlifyResponse> => {
  const cors = handleCors(event);
  if (cors) return cors;

  const index = loadThreatIndex();

  let totalThreats = 0;
  const bySeverity: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  const byIntent: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  let lastUpdated = index.generated_at;

  for (const [domain] of Object.entries(index.domains)) {
    const data = loadDomainThreats(domain);
    if (!data) continue;
    if (data.updated_at > lastUpdated) lastUpdated = data.updated_at;
    for (const t of data.threats) {
      totalThreats++;
      bySeverity[t.severity] = (bySeverity[t.severity] ?? 0) + 1;
      byIntent[t.intent] = (byIntent[t.intent] ?? 0) + 1;
      bySource[t.source] = (bySource[t.source] ?? 0) + 1;
    }
  }

  return jsonResponse({
    total_threats: totalThreats,
    total_domains: index.total_domains,
    by_severity: bySeverity,
    by_intent: byIntent,
    by_source: bySource,
    last_updated: lastUpdated,
    generated_at: new Date().toISOString(),
  });
};
