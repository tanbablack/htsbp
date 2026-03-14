"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/api/list-threats.ts
var list_threats_exports = {};
__export(list_threats_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(list_threats_exports);

// src/lib/data-loader.ts
var import_node_fs = __toESM(require("node:fs"), 1);
var import_node_path = __toESM(require("node:path"), 1);
function getDataDir() {
  return import_node_path.default.join(process.cwd(), "data");
}
function loadThreatIndex() {
  const filePath = import_node_path.default.join(getDataDir(), "threats", "index.json");
  return JSON.parse(import_node_fs.default.readFileSync(filePath, "utf-8"));
}
function loadDomainThreats(domain) {
  const filePath = import_node_path.default.join(getDataDir(), "threats", "domains", `${domain}.json`);
  if (!import_node_fs.default.existsSync(filePath))
    return null;
  return JSON.parse(import_node_fs.default.readFileSync(filePath, "utf-8"));
}
var corsHeaders = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};
function jsonResponse(data, statusCode = 200) {
  return {
    statusCode,
    headers: corsHeaders,
    body: JSON.stringify(data)
  };
}
function errorResponse(message, statusCode = 400) {
  return {
    statusCode,
    headers: corsHeaders,
    body: JSON.stringify({ error: message })
  };
}
function handleCors(event) {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }
  return null;
}

// src/api/list-threats.ts
var VALID_SEVERITIES = /* @__PURE__ */ new Set(["critical", "high", "medium", "low"]);
var MAX_LIMIT = 50;
var handler = async (event) => {
  const cors = handleCors(event);
  if (cors)
    return cors;
  const params = event.queryStringParameters ?? {};
  const severity = params.severity?.toLowerCase();
  const intent = params.intent?.toLowerCase();
  const limit = Math.min(Math.max(parseInt(params.limit ?? "20", 10) || 20, 1), MAX_LIMIT);
  const offset = Math.max(parseInt(params.offset ?? "0", 10) || 0, 0);
  if (severity && !VALID_SEVERITIES.has(severity)) {
    return errorResponse(`Invalid severity. Must be one of: ${[...VALID_SEVERITIES].join(", ")}`);
  }
  const index = loadThreatIndex();
  const allThreats = [];
  for (const [domain, entry] of Object.entries(index.domains)) {
    if (severity && entry.max_severity !== severity) {
    }
    if (intent && !entry.intents.includes(intent)) {
      continue;
    }
    const domainData = loadDomainThreats(domain);
    if (!domainData)
      continue;
    for (const threat of domainData.threats) {
      if (severity && threat.severity !== severity)
        continue;
      if (intent && threat.intent !== intent)
        continue;
      allThreats.push({ ...threat, domain });
    }
  }
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allThreats.sort((a, b) => {
    const sev = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
    if (sev !== 0)
      return sev;
    return b.last_seen.localeCompare(a.last_seen);
  });
  const paginated = allThreats.slice(offset, offset + limit);
  return jsonResponse({
    threats: paginated,
    total: allThreats.length,
    limit,
    offset
  });
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handler
});
