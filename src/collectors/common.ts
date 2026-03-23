/**
 * Common utilities for threat data collectors.
 * Handles domain normalization, deduplication, and JSON file I/O.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Threat, ThreatFile } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

/**
 * Domains that must never be added as threats (major platforms, CDNs, etc.)
 * Collectors should check this before calling upsertThreat.
 */
export const EXCLUDED_DOMAINS = new Set([
  // Package registries
  "npmjs.com", "pypi.org", "rubygems.org", "crates.io", "pkg.go.dev",
  // Major platforms
  "github.com", "gitlab.com", "bitbucket.org",
  "google.com", "docs.google.com", "youtube.com", "googleapis.com",
  "microsoft.com", "azure.com", "live.com", "office.com",
  "apple.com", "icloud.com",
  "amazon.com", "aws.amazon.com", "amazonaws.com",
  "facebook.com", "instagram.com", "meta.com", "ai.meta.com",
  "twitter.com", "x.com",
  "linkedin.com", "reddit.com",
  "wikipedia.org", "wikimedia.org",
  "cloudflare.com",
  "medium.com", "notion.so",
  "huggingface.co", "openai.com", "anthropic.com",
  "arxiv.org",
  // AI/ML known legitimate
  "langchain.com", "langchain.dev",
]);

/** Normalize a domain name: lowercase, strip trailing dot, reverse defanging */
export function normalizeDomain(raw: string): string {
  let domain = raw.trim().toLowerCase();
  // Remove trailing dot
  if (domain.endsWith(".")) {
    domain = domain.slice(0, -1);
  }
  // Reverse common defanging
  domain = domain
    .replace(/\[\.]/g, ".")
    .replace(/\[\.\]/g, ".")
    .replace(/\(dot\)/gi, ".")
    .replace(/hxxp/gi, "http");
  // Strip protocol if present
  try {
    const url = new URL(domain.startsWith("http") ? domain : `https://${domain}`);
    domain = url.hostname;
  } catch {
    // Keep as-is if not parsable
  }
  return domain;
}

/** Extract domain from a URL string */
export function extractDomain(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Load existing threat file for a domain, or create a new empty one */
export function loadDomainFile(domain: string): ThreatFile {
  const filePath = path.join(DOMAINS_DIR, `${domain}.json`);
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  }
  return {
    domain,
    threats: [],
    updated_at: new Date().toISOString(),
  };
}

/** Save a threat file to disk */
export function saveDomainFile(data: ThreatFile): void {
  fs.mkdirSync(DOMAINS_DIR, { recursive: true });
  const filePath = path.join(DOMAINS_DIR, `${data.domain}.json`);
  data.updated_at = new Date().toISOString();
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n");
}

/**
 * Upsert a threat into a domain's threat file.
 * Deduplication: same source + same intent = update existing entry.
 * Returns "added" if new, "updated" if existing was changed, false if no change.
 */
export function upsertThreat(domain: string, threat: Threat): "added" | "updated" | false {
  const normalized = normalizeDomain(domain);

  // Reject globally excluded domains
  if (EXCLUDED_DOMAINS.has(normalized)) {
    console.log(`[common] Skipping excluded domain: ${normalized}`);
    return false;
  }
  const data = loadDomainFile(normalized);

  // Find existing threat with same source + intent
  const existingIdx = data.threats.findIndex(
    t => t.source === threat.source && t.intent === threat.intent
  );

  if (existingIdx >= 0) {
    const existing = data.threats[existingIdx];
    // Update last_seen and is_active if newer
    if (threat.last_seen > existing.last_seen) {
      existing.last_seen = threat.last_seen;
      existing.is_active = threat.is_active;
      // Append new raw payloads if any
      if (threat.raw_payloads?.length) {
        const existingPayloads = new Set(existing.raw_payloads ?? []);
        for (const p of threat.raw_payloads) {
          existingPayloads.add(p);
        }
        existing.raw_payloads = [...existingPayloads];
      }
      saveDomainFile(data);
      return "updated";
    }
    return false;
  }

  // New threat — add it
  data.threats.push(threat);
  saveDomainFile(data);
  return "added";
}

/** Sanitize a payload string to prevent execution (HTML entity encoding) */
export function sanitizePayload(raw: string): string {
  return raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

/** Get the project root path */
export function getProjectRoot(): string {
  return PROJECT_ROOT;
}
