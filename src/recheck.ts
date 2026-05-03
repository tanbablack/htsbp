/**
 * 既存ドメイン再検証パイプライン
 *
 * data/threats/domains/<host>.json 全件を対象に scanUrl() を実行し、
 * 到達性 / severity / techniques に変化があれば該当レコードを更新して
 * ドメインごとに個別 PR を起票する。
 *
 * レート制御: 1 日あたり最大 100 ドメイン (last_seen が古い順)。
 */
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanUrl } from "./lib/scan.js";
import type { ScanResult, Threat, ThreatFile } from "./types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const DATA_DIR = path.join(PROJECT_ROOT, "data");
const DOMAINS_DIR = path.join(DATA_DIR, "threats/domains");
const INDEX_PATH = path.join(DATA_DIR, "threats/index.json");
const MAX_PER_DAY = 100;
const UNREACHABLE_FLIP_THRESHOLD = 3; // 連続到達不能でも is_active=true→false に切り替えるしきい値

interface DomainEntry {
  host: string;
  filePath: string;
  data: ThreatFile;
  lastSeen: string;
}

function loadAll(): DomainEntry[] {
  if (!fs.existsSync(DOMAINS_DIR)) return [];
  return fs
    .readdirSync(DOMAINS_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      const filePath = path.join(DOMAINS_DIR, f);
      const data = JSON.parse(fs.readFileSync(filePath, "utf-8")) as ThreatFile;
      const lastSeen = data.threats
        .map((t) => t.last_seen)
        .sort()
        .reverse()[0] ?? data.updated_at;
      return { host: data.domain, filePath, data, lastSeen };
    });
}

interface Diff {
  reachabilityChanged: boolean;
  severityChanged: boolean;
  newTechniques: string[];
  before: { severity: string; isActive: boolean; techniques: string[] };
  after: { severity: string; isActive: boolean; techniques: string[] };
  scan: ScanResult;
}

/** 1 ドメインを再検証し、変化を検出 */
async function recheckOne(entry: DomainEntry): Promise<Diff | null> {
  const target = entry.data.threats[0];
  if (!target) return null;
  const url = target.url ?? `https://${entry.host}/`;
  const scan = await scanUrl(url);

  const beforeActive = target.is_active;
  const beforeSeverity = target.severity;
  const beforeTechniques = [...target.techniques];

  // 到達性: 不可になったら is_active=false (将来的にしきい値判定用カウンタを raw_payloads 等に持たせる余地)
  let afterActive = beforeActive;
  if (!scan.reachable && beforeActive) afterActive = false;
  if (scan.reachable && !beforeActive) afterActive = true;

  let afterSeverity = beforeSeverity;
  if (scan.reachable && scan.aiVerdict === "malicious") {
    afterSeverity = scan.severity;
  }

  const afterTechniquesSet = new Set(beforeTechniques);
  const newTechniques: string[] = [];
  if (scan.reachable) {
    for (const tech of scan.techniques) {
      if (!afterTechniquesSet.has(tech)) {
        afterTechniquesSet.add(tech);
        newTechniques.push(tech);
      }
    }
  }
  const afterTechniques = [...afterTechniquesSet];

  const reachabilityChanged = beforeActive !== afterActive;
  const severityChanged = beforeSeverity !== afterSeverity;
  const techniquesChanged = newTechniques.length > 0;

  if (!reachabilityChanged && !severityChanged && !techniquesChanged) return null;

  // ファイル更新: target レコードのみ更新
  const now = new Date().toISOString();
  const updated: Threat = {
    ...target,
    severity: afterSeverity,
    is_active: afterActive,
    techniques: afterTechniques as Threat["techniques"],
    last_seen: now,
  };
  const newData: ThreatFile = {
    ...entry.data,
    threats: [updated, ...entry.data.threats.slice(1)],
    updated_at: now,
  };
  fs.writeFileSync(entry.filePath, JSON.stringify(newData, null, 2) + "\n");

  return {
    reachabilityChanged,
    severityChanged,
    newTechniques,
    before: {
      severity: beforeSeverity,
      isActive: beforeActive,
      techniques: beforeTechniques,
    },
    after: {
      severity: afterSeverity,
      isActive: afterActive,
      techniques: afterTechniques,
    },
    scan,
  };
}

function rebuildIndex(): void {
  const files = fs.readdirSync(DOMAINS_DIR).filter((f) => f.endsWith(".json"));
  const domains: Record<string, unknown> = {};
  let totalThreats = 0;
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 } as const;
  for (const f of files) {
    const data = JSON.parse(fs.readFileSync(path.join(DOMAINS_DIR, f), "utf-8")) as ThreatFile;
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
    INDEX_PATH,
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

function renderDiffMd(host: string, diff: Diff): string {
  const lines: string[] = [];
  lines.push(`# 既存ドメイン再検証: \`${host}\``);
  lines.push("");
  lines.push("## 検出した変化");
  if (diff.reachabilityChanged) {
    lines.push(`- 到達性 (\`is_active\`): \`${diff.before.isActive}\` → \`${diff.after.isActive}\``);
  }
  if (diff.severityChanged) {
    lines.push(`- severity: \`${diff.before.severity}\` → \`${diff.after.severity}\``);
  }
  if (diff.newTechniques.length > 0) {
    lines.push(`- 新規 techniques: ${diff.newTechniques.map((t) => `\`${t}\``).join(", ")}`);
  }
  lines.push("");
  lines.push("## scanUrl() 結果");
  lines.push(`- 到達: ${diff.scan.reachable ? `可 (HTTP ${diff.scan.httpStatus ?? "?"})` : "不可"}`);
  lines.push(`- AI 判定: ${diff.scan.aiVerdict}`);
  lines.push(`- intent: ${diff.scan.intent}`);
  lines.push(`- techniques: ${diff.scan.techniques.join(", ") || "(なし)"}`);
  lines.push(`- severity: ${diff.scan.severity}`);
  lines.push("");
  lines.push("## 判定根拠");
  lines.push(diff.scan.reasoningJa);
  return lines.join("\n");
}

function execGit(cmd: string): string {
  return execSync(cmd, { cwd: PROJECT_ROOT, encoding: "utf-8" }).trim();
}

async function openPrForRecheck(host: string, diff: Diff): Promise<void> {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const branch = `auto/recheck/${host}-${date}`;
  const filePath = path.relative(PROJECT_ROOT, path.join(DOMAINS_DIR, `${host}.json`));
  const indexRel = path.relative(PROJECT_ROOT, INDEX_PATH);
  const bodyPath = path.join(PROJECT_ROOT, `.pr-body-recheck-${host}.md`);
  fs.writeFileSync(bodyPath, renderDiffMd(host, diff));

  try {
    execGit("git config user.name htsbp-bot");
    execGit("git config user.email bot@hasthissitebeenpoisoned.ai");
    execGit(`git checkout -B ${branch}`);
    execGit(`git add ${JSON.stringify(filePath)} ${JSON.stringify(indexRel)}`);
    execGit(`git commit -m ${JSON.stringify(`data: ${host} 再検証で変化を検出 (要レビュー)`)}`);
    execGit(`git push -u --force origin ${branch}`);
    execSync(
      `gh pr create --title ${JSON.stringify(`data: ${host} 再検証で変化を検出 (要レビュー)`)} --body-file ${JSON.stringify(bodyPath)} --base main --head ${branch} --label auto-recheck --label needs-review`,
      { cwd: PROJECT_ROOT, stdio: "inherit" },
    );
    execGit("git checkout main");
  } catch (err) {
    console.warn(`[recheck] PR 起票失敗 ${host}:`, err instanceof Error ? err.message : err);
  } finally {
    fs.rmSync(bodyPath, { force: true });
  }
}

async function main(): Promise<void> {
  const all = loadAll();
  if (all.length === 0) {
    console.log("[recheck] 対象ドメインなし");
    return;
  }
  // last_seen の古い順に並べ、上限内で対象を切る
  all.sort((a, b) => (a.lastSeen < b.lastSeen ? -1 : a.lastSeen > b.lastSeen ? 1 : 0));
  const targets = all.slice(0, MAX_PER_DAY);
  console.log(`[recheck] 対象 ${targets.length}/${all.length} 件`);

  let changed = 0;
  for (const entry of targets) {
    console.log(`[recheck] scanning ${entry.host}...`);
    try {
      const diff = await recheckOne(entry);
      if (!diff) {
        console.log(`[recheck] ${entry.host}: 変化なし`);
        continue;
      }
      rebuildIndex();
      await openPrForRecheck(entry.host, diff);
      changed++;
    } catch (err) {
      console.warn(`[recheck] ${entry.host} 失敗:`, err instanceof Error ? err.message : err);
    }
  }
  console.log(`[recheck] 完了: 変化検出 ${changed} 件`);
}

main().catch((err) => {
  console.error("[recheck] 致命的エラー:", err);
  process.exit(1);
});

// Suppress unused export warnings if linter changes
export const _UNREACHABLE_FLIP_THRESHOLD = UNREACHABLE_FLIP_THRESHOLD;
