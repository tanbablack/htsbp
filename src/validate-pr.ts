/**
 * 人間 PR の事前検証
 *
 * data/threats/domains/** に変更を含む PR (auto/* ブランチ以外) で起動。
 * 変更ドメインを抽出し scanUrl() (観点1) + researchDomain() (観点2) を実行。
 * PR コメントとして検証結果を投稿し、必須欠落・到達不能 + 出典裏付けなしは
 * exit 1 で CI 失敗 → merge ブロック。
 *
 * 環境変数:
 *   GITHUB_TOKEN
 *   GITHUB_REPOSITORY (owner/repo)
 *   PR_NUMBER         PR 番号
 *   BASE_REF          base ブランチ ref (デフォルト main)
 */
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanUrl } from "./lib/scan.js";
import { researchDomain } from "./lib/research.js";
import { isValidHttpUrl, type ThreatFile } from "./types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const DOMAINS_DIR_REL = "data/threats/domains";

interface ChangedFile {
  host: string;
  filePath: string;
  status: "added" | "modified";
}

function listChangedDomainFiles(baseRef: string): ChangedFile[] {
  const out: ChangedFile[] = [];
  const diff = execSync(`git diff --name-status ${baseRef}...HEAD`, {
    cwd: PROJECT_ROOT,
    encoding: "utf-8",
  }).trim();
  for (const line of diff.split("\n")) {
    if (!line) continue;
    const [code, ...rest] = line.split(/\s+/);
    const filePath = rest.join(" ");
    if (!filePath.startsWith(`${DOMAINS_DIR_REL}/`) || !filePath.endsWith(".json")) continue;
    if (code === "D") continue; // 削除は対象外
    const host = path.basename(filePath, ".json");
    out.push({
      host,
      filePath: path.join(PROJECT_ROOT, filePath),
      status: code === "A" ? "added" : "modified",
    });
  }
  return out;
}

interface Verdict {
  host: string;
  status: ChangedFile["status"];
  blockers: string[];
  scanMd: string;
  researchMd: string;
}

async function validateOne(file: ChangedFile): Promise<Verdict> {
  const blockers: string[] = [];

  if (!fs.existsSync(file.filePath)) {
    return {
      host: file.host,
      status: file.status,
      blockers: ["ファイルが存在しない"],
      scanMd: "",
      researchMd: "",
    };
  }

  let data: ThreatFile;
  try {
    data = JSON.parse(fs.readFileSync(file.filePath, "utf-8")) as ThreatFile;
  } catch {
    return {
      host: file.host,
      status: file.status,
      blockers: ["JSON パース失敗"],
      scanMd: "",
      researchMd: "",
    };
  }

  // source_url 必須項目チェック
  for (const t of data.threats) {
    if (!t.source_url || !isValidHttpUrl(t.source_url)) {
      blockers.push(`source_url が不正/未指定 (intent=${t.intent})`);
    }
  }

  const target = data.threats[0];
  if (!target) {
    blockers.push("threats が空");
    return { host: file.host, status: file.status, blockers, scanMd: "", researchMd: "" };
  }

  const url = target.url ?? `https://${file.host}/`;
  const scan = await scanUrl(url);
  const research = await researchDomain(file.host, target.source_url);

  if (!scan.reachable && research.sourceVerdict !== "valid") {
    blockers.push("到達不能 + 出典裏付けなし");
  }

  const scanMd = [
    "### 観点 1: 到達性 + AI 悪意コード",
    `- 到達: ${scan.reachable ? `可 (HTTP ${scan.httpStatus ?? "?"})` : "不可"}`,
    `- AI 判定: ${scan.aiVerdict}`,
    `- intent: ${scan.intent}`,
    `- techniques: ${scan.techniques.join(", ") || "(なし)"}`,
    `- severity: ${scan.severity}`,
    "",
    scan.reasoningJa,
  ].join("\n");

  const researchMd = [
    "### 観点 2: ソース妥当性 + ドメイン Web 検索評判",
    `- ソース妥当性: ${research.sourceVerdict}`,
    `- ドメイン分類: ${research.domainClass}`,
    "",
    research.reasoningJa,
  ].join("\n");

  return { host: file.host, status: file.status, blockers, scanMd, researchMd };
}

function renderComment(verdicts: Verdict[]): string {
  const lines: string[] = ["# PR 事前検証結果", ""];
  for (const v of verdicts) {
    const emoji = v.blockers.length === 0 ? "✅" : "🚫";
    lines.push(`## ${emoji} \`${v.host}\` (${v.status})`);
    if (v.blockers.length > 0) {
      lines.push("");
      lines.push("**ブロッカー:**");
      for (const b of v.blockers) lines.push(`- ${b}`);
    }
    if (v.scanMd) {
      lines.push("");
      lines.push(v.scanMd);
    }
    if (v.researchMd) {
      lines.push("");
      lines.push(v.researchMd);
    }
    lines.push("");
  }
  return lines.join("\n");
}

async function postComment(comment: string): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const prNumber = process.env.PR_NUMBER;
  if (!token || !repo || !prNumber) {
    console.log("[validate-pr] GH 環境変数未設定。コメント投稿をスキップ:");
    console.log(comment);
    return;
  }
  const res = await fetch(
    `https://api.github.com/repos/${repo}/issues/${prNumber}/comments`,
    {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: comment }),
    },
  );
  if (!res.ok) {
    console.warn(`[validate-pr] コメント投稿失敗 HTTP ${res.status}`);
  }
}

async function main(): Promise<void> {
  const baseRef = process.env.BASE_REF ?? "origin/main";
  const changed = listChangedDomainFiles(baseRef);
  if (changed.length === 0) {
    console.log("[validate-pr] domains 配下の変更なし");
    return;
  }
  console.log(`[validate-pr] 対象 ${changed.length} 件`);

  const verdicts: Verdict[] = [];
  for (const f of changed) {
    console.log(`[validate-pr] validating ${f.host} (${f.status})`);
    verdicts.push(await validateOne(f));
  }

  const comment = renderComment(verdicts);
  await postComment(comment);

  const blocked = verdicts.some((v) => v.blockers.length > 0);
  if (blocked) {
    console.error("[validate-pr] ブロッカーあり、CI 失敗");
    process.exit(1);
  }
  console.log("[validate-pr] OK");
}

main().catch((err) => {
  console.error("[validate-pr] 致命的エラー:", err);
  process.exit(1);
});
