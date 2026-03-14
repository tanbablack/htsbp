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

// src/api/health.ts
var health_exports = {};
__export(health_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(health_exports);

// src/lib/data-loader.ts
var import_node_fs = __toESM(require("node:fs"), 1);
var import_node_path = __toESM(require("node:path"), 1);
function getDataDir() {
  return import_node_path.default.join(process.cwd(), "data");
}
function loadStats() {
  const filePath = import_node_path.default.join(getDataDir(), "stats.json");
  return JSON.parse(import_node_fs.default.readFileSync(filePath, "utf-8"));
}
function countDomainFiles() {
  const dir = import_node_path.default.join(getDataDir(), "threats", "domains");
  if (!import_node_fs.default.existsSync(dir))
    return 0;
  return import_node_fs.default.readdirSync(dir).filter((f) => f.endsWith(".json")).length;
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
function handleCors(event) {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }
  return null;
}

// src/api/health.ts
var handler = async (event) => {
  const cors = handleCors(event);
  if (cors)
    return cors;
  try {
    const stats = loadStats();
    return jsonResponse({
      status: "ok",
      data_file_count: countDomainFiles(),
      last_updated: stats.last_updated,
      version: "1.0.0"
    });
  } catch {
    return jsonResponse({ status: "error", message: "Failed to load data" }, 500);
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handler
});
