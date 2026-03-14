import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ThreatFile, ThreatIndex, ThreatIndexEntry, Stats, Severity } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");
const INDEX_PATH = path.join(PROJECT_ROOT, "data/threats/index.json");
const STATS_PATH = path.join(PROJECT_ROOT, "data/stats.json");

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
};

/** Compare two severity levels, returning the more severe one */
function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] <= SEVERITY_ORDER[b] ? a : b;
}

/** Rebuild index.json and stats.json from all domain threat files */
function rebuild(): void {
  if (!fs.existsSync(DOMAINS_DIR)) {
    console.error("No domains directory found. Run seed first.");
    process.exit(1);
  }

  const files = fs.readdirSync(DOMAINS_DIR).filter(f => f.endsWith(".json")).sort();

  const index: ThreatIndex = {
    domains: {},
    total_threats: 0,
    total_domains: 0,
    generated_at: new Date().toISOString()
  };

  const bySeverity: Stats["by_severity"] = { critical: 0, high: 0, medium: 0, low: 0 };
  const byIntent: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  let lastUpdated = "";

  for (const file of files) {
    const filePath = path.join(DOMAINS_DIR, file);
    const data: ThreatFile = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const domain = data.domain;

    if (data.updated_at > lastUpdated) {
      lastUpdated = data.updated_at;
    }

    let domainMaxSeverity: Severity = "low";
    const intents = new Set<string>();
    let domainLastSeen = "";
    let domainIsActive = false;

    for (const threat of data.threats) {
      index.total_threats++;
      domainMaxSeverity = maxSeverity(domainMaxSeverity, threat.severity);
      intents.add(threat.intent);

      if (threat.last_seen > domainLastSeen) {
        domainLastSeen = threat.last_seen;
      }
      if (threat.is_active) {
        domainIsActive = true;
      }

      bySeverity[threat.severity]++;
      byIntent[threat.intent] = (byIntent[threat.intent] || 0) + 1;
      bySource[threat.source] = (bySource[threat.source] || 0) + 1;
    }

    const entry: ThreatIndexEntry = {
      max_severity: domainMaxSeverity,
      intents: Array.from(intents).sort(),
      threat_count: data.threats.length,
      last_seen: domainLastSeen,
      is_active: domainIsActive
    };

    index.domains[domain] = entry;
    index.total_domains++;
  }

  // Sort domains alphabetically in the index
  const sortedDomains: ThreatIndex["domains"] = {};
  for (const key of Object.keys(index.domains).sort()) {
    sortedDomains[key] = index.domains[key];
  }
  index.domains = sortedDomains;

  // Write index.json
  fs.mkdirSync(path.dirname(INDEX_PATH), { recursive: true });
  fs.writeFileSync(INDEX_PATH, JSON.stringify(index, null, 2) + "\n");
  console.log(`Generated: ${INDEX_PATH} (${index.total_domains} domains, ${index.total_threats} threats)`);

  // Sort by_intent and by_source alphabetically
  const sortedByIntent: Record<string, number> = {};
  for (const key of Object.keys(byIntent).sort()) {
    sortedByIntent[key] = byIntent[key];
  }
  const sortedBySource: Record<string, number> = {};
  for (const key of Object.keys(bySource).sort()) {
    sortedBySource[key] = bySource[key];
  }

  const stats: Stats = {
    total_threats: index.total_threats,
    total_domains: index.total_domains,
    by_severity: bySeverity,
    by_intent: sortedByIntent,
    by_source: sortedBySource,
    last_updated: lastUpdated,
    generated_at: new Date().toISOString()
  };

  fs.writeFileSync(STATS_PATH, JSON.stringify(stats, null, 2) + "\n");
  console.log(`Generated: ${STATS_PATH}`);
}

rebuild();
