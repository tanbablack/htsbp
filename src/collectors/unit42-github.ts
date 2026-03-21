/**
 * Collector: Unit42 GitHub repositories
 * Fetches IoC data from Palo Alto Networks Unit42 threat intelligence repos.
 *
 * Target repositories:
 * - PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information
 * - PaloAltoNetworks/Unit42-timely-threat-intel
 */
import { normalizeDomain, upsertThreat } from "./common.js";
import type { Threat, AttackIntent, Technique } from "../types/index.js";

const REPOS = [
  "PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information",
  "PaloAltoNetworks/Unit42-timely-threat-intel",
];

const GITHUB_API = "https://api.github.com";

/** Keywords indicating IDPI/prompt-injection relevance */
const RELEVANT_KEYWORDS = [
  "prompt.injection",
  "prompt_injection",
  "idpi",
  "indirect.prompt",
  "llm.attack",
  "ai.agent",
];

interface GitHubTreeEntry {
  path: string;
  type: string;
  url: string;
}

/** Fetch repository tree from GitHub API */
async function fetchRepoTree(repo: string): Promise<GitHubTreeEntry[]> {
  const url = `${GITHUB_API}/repos/${repo}/git/trees/main?recursive=1`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "htsbp-collector/1.0",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    console.warn(`Failed to fetch tree for ${repo}: ${res.status}`);
    return [];
  }

  const data = (await res.json()) as { tree: GitHubTreeEntry[] };
  return data.tree ?? [];
}

/** Fetch raw file content from GitHub */
async function fetchFileContent(repo: string, filePath: string): Promise<string> {
  const url = `https://raw.githubusercontent.com/${repo}/main/${filePath}`;
  const res = await fetch(url, {
    headers: { "User-Agent": "htsbp-collector/1.0" },
  });
  if (!res.ok) return "";
  return res.text();
}

/** Check if a file path is relevant to IDPI */
function isRelevantFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return RELEVANT_KEYWORDS.some(kw => lower.includes(kw));
}

/** Extract domains and URLs from text content */
function extractIndicators(content: string): { domains: string[]; urls: string[] } {
  const urlRegex = /https?:\/\/[^\s"'<>\]]+/gi;
  const domainRegex = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|in|website|ai)\b/gi;

  const urls = [...new Set((content.match(urlRegex) ?? []))];
  const domains = [...new Set((content.match(domainRegex) ?? []))];

  return { domains, urls };
}

/** Run the Unit42 GitHub collector */
export async function collect(): Promise<{ added: number; updated: number }> {
  let added = 0;
  let updated = 0;
  const now = new Date().toISOString();

  for (const repo of REPOS) {
    console.log(`[unit42-github] Scanning ${repo}...`);

    const tree = await fetchRepoTree(repo);
    const relevantFiles = tree.filter(
      entry => entry.type === "blob" && isRelevantFile(entry.path)
    );

    console.log(`[unit42-github] Found ${relevantFiles.length} relevant files in ${repo}`);

    for (const file of relevantFiles) {
      const content = await fetchFileContent(repo, file.path);
      if (!content) continue;

      const { domains } = extractIndicators(content);

      for (const rawDomain of domains) {
        const domain = normalizeDomain(rawDomain);
        if (!domain || domain.length < 4) continue;

        const threat: Threat = {
          severity: "medium",
          intent: "other" as AttackIntent,
          techniques: [] as Technique[],
          description: `IDPI indicator found in Unit42 repository: ${repo}, file: ${file.path}`,
          source: "unit42",
          source_url: `https://github.com/${repo}/blob/main/${file.path}`,
          first_seen: now,
          last_seen: now,
          is_active: true,
        };

        const result = upsertThreat(domain, threat);
        if (result === "added") added++;
        else if (result === "updated") updated++;
      }
    }
  }

  console.log(`[unit42-github] Done: ${added} added, ${updated} updated`);
  return { added, updated };
}
