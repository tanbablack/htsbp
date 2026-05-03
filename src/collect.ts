/**
 * 日次収集パイプライン (新規ドメイン)
 *
 * 段階 1: 発見    sources.json 全エントリを毎日必ず巡回
 *                 method 別に otx_api / claude_web_search / internal を使い分け
 * 段階 2: 判定    候補ごとに lib/scan + lib/research を実行し総合判定
 * 段階 3: 反映    should_register: true のドメインごとに個別 PR 起票
 */
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanUrl } from "./lib/scan.js";
import { researchDomain } from "./lib/research.js";
import {
  isValidHttpUrl,
  type DataSource,
  type ScanResult,
  type ResearchResult,
  type Threat,
  type ThreatFile,
} from "./types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const DATA_DIR = path.join(PROJECT_ROOT, "data");
const DOMAINS_DIR = path.join(DATA_DIR, "threats/domains");
const SOURCES_PATH = path.join(DATA_DIR, "sources.json");

const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const MODEL = "claude-opus-4-6";

const OTX_API = "https://otx.alienvault.com/api/v1";
const OTX_TERMS = ["prompt injection", "IDPI", "indirect prompt injection"];
const OTX_RELEVANCE = [
  "prompt injection",
  "idpi",
  "indirect prompt",
  "llm attack",
  "ai poisoning",
  "ai injection",
  "hidden instruction",
  "hidden prompt",
];
const OTX_MAX_INDICATORS_PER_PULSE = 50;
const OTX_MAX_TOTAL_DOMAINS = 200;

const KNOWN_PLATFORMS = new Set([
  "npmjs.com", "pypi.org", "rubygems.org", "crates.io", "pkg.go.dev",
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
  "medium.com", "notion.so", "notion.com",
  "huggingface.co", "openai.com", "anthropic.com",
  "arxiv.org",
  "langchain.com", "langchain.dev",
  "chat.openai.com", "copilot.microsoft.com", "bing.com",
  "cursor.sh", "cursor.com", "claude.ai",
  "gemini.google.com", "perplexity.ai", "superhuman.com",
]);

interface Candidate {
  host: string;
  url: string;
  source: string;
  sourceUrl: string;
  description: string;
}

/* ────────────────────────────────────────────────────────────────────────── */
/* 段階 1: 発見                                                                */
/* ────────────────────────────────────────────────────────────────────────── */

function loadSources(): DataSource[] {
  return JSON.parse(fs.readFileSync(SOURCES_PATH, "utf-8"));
}

function loadKnownDomains(): Set<string> {
  if (!fs.existsSync(DOMAINS_DIR)) return new Set();
  return new Set(
    fs.readdirSync(DOMAINS_DIR).filter((f) => f.endsWith(".json")).map((f) => f.replace(".json", "")),
  );
}

function normalizeHost(raw: string): string | null {
  const cleaned = raw
    .trim()
    .toLowerCase()
    .replace(/\[\.\]/g, ".")
    .replace(/\(dot\)/gi, ".")
    .replace(/hxxp/gi, "http");
  try {
    const u = new URL(cleaned.startsWith("http") ? cleaned : `https://${cleaned}`);
    return u.hostname.replace(/\.$/, "");
  } catch {
    return null;
  }
}

interface OtxIndicator { type: string; indicator: string; }
interface OtxPulse {
  id: string;
  name: string;
  description: string;
  indicators: OtxIndicator[];
  created: string;
  modified: string;
}

async function otxFetch<T>(url: string): Promise<T | null> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "htsbp-collect/1.0",
  };
  if (process.env.OTX_API_KEY) headers["X-OTX-API-KEY"] = process.env.OTX_API_KEY;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 15_000);
      const res = await fetch(url, { headers, signal: ctrl.signal });
      clearTimeout(timer);
      if (res.status === 504 || res.status === 503 || res.status === 429) {
        await new Promise((r) => setTimeout(r, 3000 * 2 ** attempt));
        continue;
      }
      if (!res.ok) return null;
      return (await res.json()) as T;
    } catch {
      if (attempt === 2) return null;
      await new Promise((r) => setTimeout(r, 3000 * 2 ** attempt));
    }
  }
  return null;
}

async function discoverFromOtxApi(known: Set<string>): Promise<Candidate[]> {
  const out: Candidate[] = [];
  const seen = new Set<string>();
  for (const term of OTX_TERMS) {
    if (seen.size >= OTX_MAX_TOTAL_DOMAINS) break;
    const data = await otxFetch<{ results: OtxPulse[] }>(
      `${OTX_API}/search/pulses?q=${encodeURIComponent(term)}&limit=20`,
    );
    if (!data) continue;
    for (const pulse of data.results ?? []) {
      const text = `${pulse.name} ${pulse.description}`.toLowerCase();
      if (!OTX_RELEVANCE.some((kw) => text.includes(kw))) continue;
      const indicators: OtxIndicator[] = pulse.indicators?.length
        ? pulse.indicators.slice(0, OTX_MAX_INDICATORS_PER_PULSE)
        : ((await otxFetch<{ results: OtxIndicator[] }>(
            `${OTX_API}/pulses/${pulse.id}/indicators?limit=${OTX_MAX_INDICATORS_PER_PULSE}`,
          ))?.results ?? []);
      for (const ind of indicators) {
        if (seen.size >= OTX_MAX_TOTAL_DOMAINS) break;
        let host: string | null = null;
        if (ind.type === "domain" || ind.type === "hostname") host = normalizeHost(ind.indicator);
        else if (ind.type === "URL" || ind.type === "url") {
          try { host = new URL(ind.indicator).hostname.toLowerCase(); } catch { host = null; }
        }
        if (!host || host.length < 4) continue;
        if (seen.has(host) || known.has(host) || KNOWN_PLATFORMS.has(host)) continue;
        seen.add(host);
        out.push({
          host,
          url: ind.type.toLowerCase() === "url" ? ind.indicator : `https://${host}/`,
          source: "otx-api",
          sourceUrl: `https://otx.alienvault.com/pulse/${pulse.id}`,
          description: `OTX pulse "${pulse.name}" で IDPI 関連 indicator として列挙`,
        });
      }
    }
  }
  return out;
}

async function discoverViaClaudeWebSearch(
  src: DataSource,
  known: Set<string>,
): Promise<Candidate[]> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || !src.url) return [];

  const knownList = [...known, ...KNOWN_PLATFORMS].slice(0, 200).join(", ");
  const prompt = `あなたは IDPI 脅威情報リサーチャー。全て日本語で回答せよ。

## 調査対象ソース
${src.name} (${src.url})

## タスク
web_search ツールで上記ソース URL のみを過去 30 日範囲で調査し、
「AI エージェントを標的とした間接プロンプトインジェクション (IDPI) を仕込んだ
悪意ある Web サイト」として報告された新規ドメインを最大 30 件抽出せよ。

## 除外指示
以下に含まれるドメインは出力するな:
${knownList}

## 出力形式 (厳守)
JSON のみ。前置き・後書き不要。全フィールド日本語/英語混在可。

\`\`\`json
{
  "candidates": [
    {
      "domain": "example.com",
      "url": "https://example.com/path",
      "description": "発見状況を 1 文で説明 (日本語)",
      "source_url": "https://出典記事の URL"
    }
  ]
}
\`\`\``;

  const res = await fetch(ANTHROPIC_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 4000,
      tools: [{ type: "web_search_20250305", name: "web_search", max_uses: 6 }],
      messages: [{ role: "user", content: prompt }],
    }),
  });
  if (!res.ok) return [];

  const data = (await res.json()) as { content: Array<{ type: string; text?: string }> };
  const text = data.content
    .filter((c) => c.type === "text" && c.text)
    .map((c) => c.text!)
    .join("\n");
  const fence = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  const jsonStr = fence ? fence[1] : text.match(/\{[\s\S]*\}/)?.[0] ?? "";

  try {
    const parsed = JSON.parse(jsonStr) as {
      candidates: Array<{
        domain: string;
        url?: string;
        description?: string;
        source_url?: string;
      }>;
    };
    const out: Candidate[] = [];
    const seen = new Set<string>();
    for (const c of parsed.candidates ?? []) {
      const host = normalizeHost(c.domain);
      if (!host) continue;
      if (seen.has(host) || known.has(host) || KNOWN_PLATFORMS.has(host)) continue;
      if (!c.source_url || !isValidHttpUrl(c.source_url)) continue; // 出典なきものは捨てる
      seen.add(host);
      out.push({
        host,
        url: c.url && isValidHttpUrl(c.url) ? c.url : `https://${host}/`,
        source: src.id,
        sourceUrl: c.source_url,
        description: c.description ?? `${src.name} で IDPI 関連として報告`,
      });
    }
    return out;
  } catch {
    return [];
  }
}

async function discover(known: Set<string>): Promise<{
  candidates: Candidate[];
  sourceLog: Array<{ id: string; ok: boolean; count: number }>;
}> {
  const sources = loadSources();
  const candidates: Candidate[] = [];
  const sourceLog: Array<{ id: string; ok: boolean; count: number }> = [];
  const seen = new Set<string>();

  for (const src of sources) {
    if (src.method === "internal") continue;
    let found: Candidate[] = [];
    let ok = false;
    try {
      if (src.method === "otx_api") {
        found = await discoverFromOtxApi(known);
      } else if (src.method === "claude_web_search") {
        found = await discoverViaClaudeWebSearch(src, known);
      }
      ok = true;
    } catch (err) {
      console.warn(`[collect] ${src.id} 巡回失敗:`, err instanceof Error ? err.message : err);
    }
    let added = 0;
    for (const c of found) {
      if (seen.has(c.host)) continue;
      seen.add(c.host);
      candidates.push(c);
      added++;
    }
    sourceLog.push({ id: src.id, ok, count: added });
    console.log(`[collect] ${src.id}: ${ok ? "OK" : "FAILED"} (+${added})`);
  }
  return { candidates, sourceLog };
}

/* ────────────────────────────────────────────────────────────────────────── */
/* 段階 2: 判定                                                                */
/* ────────────────────────────────────────────────────────────────────────── */

interface ComprehensiveJudgment {
  shouldRegister: boolean;
  confidence: "high" | "medium" | "low";
  reasoningMd: string;
  scan: ScanResult;
  research: ResearchResult;
}

function deriveJudgment(scan: ScanResult, research: ResearchResult): ComprehensiveJudgment {
  // Combine: malicious code + (valid source OR malicious domain class) → register
  const codeMalicious = scan.aiVerdict === "malicious";
  const sourceValid = research.sourceVerdict === "valid";
  const domainMalicious = research.domainClass === "malicious";
  const domainLegitimate = research.domainClass === "legitimate";

  let shouldRegister = false;
  let confidence: "high" | "medium" | "low" = "low";

  if (codeMalicious && (sourceValid || domainMalicious)) {
    shouldRegister = true;
    confidence = sourceValid && domainMalicious ? "high" : "medium";
  } else if (codeMalicious && !domainLegitimate) {
    shouldRegister = true;
    confidence = "low";
  }

  if (domainLegitimate) {
    shouldRegister = false;
    confidence = "high";
  }

  return { shouldRegister, confidence, reasoningMd: "", scan, research };
}

function renderReasoningMd(host: string, sourceUrl: string, j: ComprehensiveJudgment): string {
  const lines: string[] = [];
  lines.push(`# 新規 IDPI 候補: \`${host}\``);
  lines.push("");
  lines.push("## 候補メタデータ");
  lines.push(`- ドメイン: \`${host}\``);
  lines.push(`- 出典: <${sourceUrl}>`);
  lines.push("");
  lines.push("## 観点 1: 到達性 + AI を騙す悪意コードの実在");
  lines.push(`- 到達: ${j.scan.reachable ? `可 (HTTP ${j.scan.httpStatus ?? "?"})` : "不可"}`);
  lines.push(`- AI 判定: ${j.scan.aiVerdict}`);
  lines.push(`- intent: ${j.scan.intent}`);
  lines.push(`- techniques: ${j.scan.techniques.join(", ") || "(なし)"}`);
  lines.push(`- severity: ${j.scan.severity}`);
  lines.push("");
  lines.push(j.scan.reasoningJa);
  lines.push("");
  lines.push("## 観点 2: ソース妥当性 + ドメイン Web 検索評判");
  lines.push(`- ソース妥当性: ${j.research.sourceVerdict}`);
  lines.push(`- ドメイン分類: ${j.research.domainClass}`);
  lines.push("");
  lines.push(j.research.reasoningJa);
  lines.push("");
  lines.push("## 総合判定");
  lines.push(`- 登録支持: ${j.shouldRegister ? "はい" : "いいえ"}`);
  lines.push(`- 確信度: ${j.confidence}`);
  return lines.join("\n");
}

async function judge(c: Candidate): Promise<ComprehensiveJudgment> {
  const scan = await scanUrl(c.url);
  const research = await researchDomain(c.host, c.sourceUrl);
  const j = deriveJudgment(scan, research);
  j.reasoningMd = renderReasoningMd(c.host, c.sourceUrl, j);
  return j;
}

/* ────────────────────────────────────────────────────────────────────────── */
/* 段階 3: 反映                                                                */
/* ────────────────────────────────────────────────────────────────────────── */

function buildThreat(c: Candidate, j: ComprehensiveJudgment): Threat {
  const now = new Date().toISOString();
  return {
    url: c.url,
    severity: j.scan.severity,
    intent: j.scan.intent,
    techniques: j.scan.techniques,
    description: c.description,
    source: c.source,
    source_url: c.sourceUrl,
    first_seen: now,
    last_seen: now,
    is_active: true,
  };
}

function writeThreat(c: Candidate, threat: Threat): void {
  if (!isValidHttpUrl(threat.source_url)) {
    throw new Error(`書込拒否: ${c.host} の source_url が不正 (${threat.source_url})`);
  }
  fs.mkdirSync(DOMAINS_DIR, { recursive: true });
  const filePath = path.join(DOMAINS_DIR, `${c.host}.json`);
  const data: ThreatFile = {
    domain: c.host,
    threats: [threat],
    updated_at: new Date().toISOString(),
  };
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n");
}

function execGit(cmd: string): string {
  return execSync(cmd, { cwd: PROJECT_ROOT, encoding: "utf-8" }).trim();
}

function gitConfigure(): void {
  try {
    execGit("git config user.name htsbp-bot");
    execGit("git config user.email bot@hasthissitebeenpoisoned.ai");
  } catch { /* ignore */ }
}

function rebuildIndex(): void {
  const indexPath = path.join(DATA_DIR, "threats/index.json");
  const files = fs.readdirSync(DOMAINS_DIR).filter((f) => f.endsWith(".json"));
  const domains: Record<string, unknown> = {};
  let totalThreats = 0;
  for (const f of files) {
    const data = JSON.parse(fs.readFileSync(path.join(DOMAINS_DIR, f), "utf-8")) as ThreatFile;
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 } as const;
    let maxSev: keyof typeof sevOrder = "low";
    const intents = new Set<string>();
    let lastSeen = data.updated_at;
    let isActive = false;
    for (const t of data.threats) {
      if (sevOrder[t.severity] < sevOrder[maxSev]) maxSev = t.severity;
      intents.add(t.intent);
      if (t.last_seen > lastSeen) lastSeen = t.last_seen;
      if (t.is_active) isActive = true;
    }
    domains[data.domain] = {
      max_severity: maxSev,
      intents: [...intents],
      threat_count: data.threats.length,
      last_seen: lastSeen,
      is_active: isActive,
    };
    totalThreats += data.threats.length;
  }
  fs.writeFileSync(
    indexPath,
    JSON.stringify(
      {
        domains,
        total_threats: totalThreats,
        total_domains: files.length,
        generated_at: new Date().toISOString(),
      },
      null,
      2,
    ) + "\n",
  );
}

async function openPrViaCli(branch: string, title: string, bodyPath: string): Promise<void> {
  try {
    execSync(
      `gh pr create --title ${JSON.stringify(title)} --body-file ${JSON.stringify(bodyPath)} --base main --head ${branch} --label auto-collect --label needs-review`,
      { cwd: PROJECT_ROOT, stdio: "inherit" },
    );
  } catch (err) {
    console.warn("[collect] gh pr create 失敗:", err instanceof Error ? err.message : err);
  }
}

async function reflectOne(c: Candidate, j: ComprehensiveJudgment): Promise<void> {
  if (!j.shouldRegister) {
    console.log(`[collect] skip ${c.host}: 登録見送り`);
    return;
  }

  const threat = buildThreat(c, j);
  writeThreat(c, threat);
  rebuildIndex();

  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const branch = `auto/${c.host}-${date}`;

  const fileRel = path.relative(PROJECT_ROOT, path.join(DOMAINS_DIR, `${c.host}.json`));
  const indexRel = path.relative(PROJECT_ROOT, path.join(DATA_DIR, "threats/index.json"));
  const bodyPath = path.join(PROJECT_ROOT, `.pr-body-${c.host}.md`);
  fs.writeFileSync(bodyPath, j.reasoningMd);

  try {
    gitConfigure();
    execGit(`git checkout -B ${branch}`);
    execGit(`git add ${JSON.stringify(fileRel)} ${JSON.stringify(indexRel)}`);
    execGit(
      `git commit -m ${JSON.stringify(`data: 新規IDPI候補 ${c.host} を追加 (要レビュー)`)}`,
    );
    execGit(`git push -u --force origin ${branch}`);
    await openPrViaCli(branch, `data: 新規IDPI候補 ${c.host} を追加 (要レビュー)`, bodyPath);
    execGit("git checkout main");
  } catch (err) {
    console.warn(`[collect] PR 起票失敗 ${c.host}:`, err instanceof Error ? err.message : err);
  } finally {
    fs.rmSync(bodyPath, { force: true });
  }
}

/* ────────────────────────────────────────────────────────────────────────── */
/* main                                                                        */
/* ────────────────────────────────────────────────────────────────────────── */

async function main(): Promise<void> {
  const known = loadKnownDomains();
  console.log(`[collect] 既知ドメイン: ${known.size} 件`);

  console.log("[collect] === 段階 1: 発見 ===");
  const { candidates, sourceLog } = await discover(known);
  const ok = sourceLog.filter((s) => s.ok).length;
  const fail = sourceLog.length - ok;
  console.log(`[collect] 巡回成功 ${ok} / 失敗 ${fail} / 候補 ${candidates.length} 件`);

  console.log("[collect] === 段階 2 + 3: 判定 + 反映 ===");
  for (const c of candidates) {
    console.log(`[collect] judging ${c.host}...`);
    try {
      const j = await judge(c);
      await reflectOne(c, j);
    } catch (err) {
      console.warn(`[collect] ${c.host} 失敗:`, err instanceof Error ? err.message : err);
    }
  }
  console.log("[collect] 完了");
}

main().catch((err) => {
  console.error("[collect] 致命的エラー:", err);
  process.exit(1);
});
