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

// src/api/check-domain.ts
var check_domain_exports = {};
__export(check_domain_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(check_domain_exports);

// src/lib/data-loader.ts
var import_node_fs = __toESM(require("node:fs"), 1);
var import_node_path = __toESM(require("node:path"), 1);
function getDataDir() {
  return import_node_path.default.join(process.cwd(), "data");
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

// src/api/check-domain.ts
var handler = async (event) => {
  const cors = handleCors(event);
  if (cors)
    return cors;
  const domain = event.queryStringParameters?.domain?.toLowerCase().trim();
  if (!domain) {
    return errorResponse("Missing required parameter: domain");
  }
  const data = loadDomainThreats(domain);
  if (!data) {
    return jsonResponse({
      domain,
      is_malicious: false,
      threats: []
    });
  }
  return jsonResponse({
    domain: data.domain,
    is_malicious: data.threats.some((t) => t.is_active),
    threats: data.threats
  });
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handler
});
