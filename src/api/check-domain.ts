/**
 * GET /api/check-domain?domain=reviewerpress.com
 * Check if a domain hosts known IDPI threats.
 */
import {
  loadDomainThreats,
  handleCors,
  jsonResponse,
  errorResponse,
  type NetlifyEvent,
  type NetlifyResponse,
} from "../lib/data-loader.js";

export const handler = async (event: NetlifyEvent): Promise<NetlifyResponse> => {
  const cors = handleCors(event);
  if (cors) return cors;

  const domain = event.queryStringParameters?.domain?.toLowerCase().trim();
  if (!domain) {
    return errorResponse("Missing required parameter: domain");
  }

  const data = loadDomainThreats(domain);

  if (!data) {
    return jsonResponse({
      domain,
      is_malicious: false,
      threats: [],
    });
  }

  return jsonResponse({
    domain: data.domain,
    is_malicious: data.threats.some(t => t.is_active),
    threats: data.threats,
  });
};
