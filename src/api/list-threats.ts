/**
 * GET /api/list-threats?severity=critical&intent=data_destruction&limit=50&offset=0
 * List known IDPI threats with optional filters.
 */
import {
  loadThreatIndex,
  loadDomainThreats,
  handleCors,
  jsonResponse,
  errorResponse,
  type NetlifyEvent,
  type NetlifyResponse,
} from "../lib/data-loader.js";
import type { Severity, Threat } from "../types/index.js";

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const MAX_LIMIT = 50;

export const handler = async (event: NetlifyEvent): Promise<NetlifyResponse> => {
  const cors = handleCors(event);
  if (cors) return cors;

  const params = event.queryStringParameters ?? {};
  const severity = params.severity?.toLowerCase();
  const intent = params.intent?.toLowerCase();
  const limit = Math.min(Math.max(parseInt(params.limit ?? "20", 10) || 20, 1), MAX_LIMIT);
  const offset = Math.max(parseInt(params.offset ?? "0", 10) || 0, 0);

  if (severity && !VALID_SEVERITIES.has(severity)) {
    return errorResponse(`Invalid severity. Must be one of: ${[...VALID_SEVERITIES].join(", ")}`);
  }

  const index = loadThreatIndex();

  // Collect matching threats across all domains
  interface ThreatWithDomain extends Threat {
    domain: string;
  }
  const allThreats: ThreatWithDomain[] = [];

  for (const [domain, entry] of Object.entries(index.domains)) {
    // Quick filter using index metadata
    if (severity && entry.max_severity !== severity as Severity) {
      // max_severity might not match - we need to check individual threats
      // Only skip if the severity filter is stricter than max_severity
    }
    if (intent && !entry.intents.includes(intent)) {
      continue;
    }

    const domainData = loadDomainThreats(domain);
    if (!domainData) continue;

    for (const threat of domainData.threats) {
      if (severity && threat.severity !== severity) continue;
      if (intent && threat.intent !== intent) continue;
      allThreats.push({ ...threat, domain });
    }
  }

  // Sort by severity (critical first), then by last_seen (newest first)
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  allThreats.sort((a, b) => {
    const sev = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
    if (sev !== 0) return sev;
    return b.last_seen.localeCompare(a.last_seen);
  });

  const paginated = allThreats.slice(offset, offset + limit);

  return jsonResponse({
    threats: paginated,
    total: allThreats.length,
    limit,
    offset,
  });
};
