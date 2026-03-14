/**
 * GET /api/check-url?url=https://...
 * Extract domain from URL and check for IDPI threats. Also matches specific URLs.
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

  const rawUrl = event.queryStringParameters?.url?.trim();
  if (!rawUrl) {
    return errorResponse("Missing required parameter: url");
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return errorResponse("Invalid URL format");
  }

  const domain = parsedUrl.hostname.toLowerCase();
  const data = loadDomainThreats(domain);

  if (!data) {
    return jsonResponse({
      url: rawUrl,
      domain,
      is_malicious: false,
      threats: [],
    });
  }

  // Filter threats that match the specific URL (if url field exists), plus threats without url
  const urlMatched = data.threats.filter(t => t.url === rawUrl);
  const allThreats = data.threats;

  return jsonResponse({
    url: rawUrl,
    domain: data.domain,
    is_malicious: allThreats.some(t => t.is_active),
    url_matched: urlMatched.length > 0,
    threats: allThreats,
  });
};
