/**
 * Shared data loading utilities for Netlify Functions.
 * Reads JSON files from the data/ directory at runtime.
 */
import fs from "node:fs";
import path from "node:path";
import type { ThreatFile, ThreatIndex } from "../types.js";

/** Resolve the data directory path (works in both local dev and deployed Lambda) */
function getDataDir(): string {
  return path.join(process.cwd(), "data");
}

/** Load the lightweight threat index */
export function loadThreatIndex(): ThreatIndex {
  const filePath = path.join(getDataDir(), "threats", "index.json");
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

/** Load threat data for a specific domain, or null if not found */
export function loadDomainThreats(domain: string): ThreatFile | null {
  const filePath = path.join(getDataDir(), "threats", "domains", `${domain}.json`);
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

/** Standard CORS + JSON response headers */
export const corsHeaders: Record<string, string> = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

/** Netlify Function event shape (minimal) */
export interface NetlifyEvent {
  queryStringParameters: Record<string, string | undefined> | null;
  httpMethod: string;
  path: string;
  headers: Record<string, string>;
  body: string | null;
}

/** Netlify Function response shape */
export interface NetlifyResponse {
  statusCode: number;
  headers?: Record<string, string>;
  body: string;
}

/** Create a JSON success response */
export function jsonResponse(data: unknown, statusCode = 200): NetlifyResponse {
  return {
    statusCode,
    headers: corsHeaders,
    body: JSON.stringify(data),
  };
}

/** Create a JSON error response */
export function errorResponse(message: string, statusCode = 400): NetlifyResponse {
  return {
    statusCode,
    headers: corsHeaders,
    body: JSON.stringify({ error: message }),
  };
}

/** Handle CORS preflight */
export function handleCors(event: NetlifyEvent): NetlifyResponse | null {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }
  return null;
}
