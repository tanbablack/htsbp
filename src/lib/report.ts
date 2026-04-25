/**
 * Threat Report 受付ヘルパー
 *
 * /api/report-threat と MCP report_threat ツールから共有される実装。
 * GitHub REST API を使って:
 *   1. main の HEAD SHA 取得
 *   2. ブランチ作成 (report/<host>-<unix_ts>)
 *   3. data/threats/domains/<host>.json をブランチに作成
 *   4. PR 起票
 * を行い、PR URL を返す。検証 (scan + research) は pr-validate.yml が
 * 当該 PR で自動実行する。
 *
 * 環境変数:
 *   GITHUB_TOKEN      ブランチ作成・ファイル作成・PR 起票に使用
 *   GITHUB_REPOSITORY owner/repo (例: tanbablack/htsbp)
 */
import { isValidHttpUrl, type Severity, type Threat, type ThreatFile } from "../types.js";

const GITHUB_API = "https://api.github.com";

export interface SubmitInput {
  url: string;
  source_url: string;
  description: string;
  severity?: Severity;
}

export interface SubmitResult {
  pr_url: string;
  pr_number: number;
  branch: string;
  host: string;
}

export class ReportValidationError extends Error {
  constructor(public readonly field: string, message: string) {
    super(message);
    this.name = "ReportValidationError";
  }
}

/** 入力を検証し、不備があれば ReportValidationError を throw */
function validateInput(input: SubmitInput): { host: string } {
  if (!isValidHttpUrl(input.url)) {
    throw new ReportValidationError("url", "url は http:// または https:// の正規 URL が必須");
  }
  if (!isValidHttpUrl(input.source_url)) {
    throw new ReportValidationError(
      "source_url",
      "source_url は http:// または https:// の正規 URL が必須 (出典明示は HTSBP の必須要件)",
    );
  }
  const description = (input.description ?? "").trim();
  if (description.length < 20) {
    throw new ReportValidationError(
      "description",
      "description は 20 文字以上の説明文が必須 (観測した隠し命令の場所・文言・挙動など)",
    );
  }
  if (input.severity && !["critical", "high", "medium", "low"].includes(input.severity)) {
    throw new ReportValidationError(
      "severity",
      "severity は critical / high / medium / low のいずれかのみ",
    );
  }
  let host: string;
  try {
    host = new URL(input.url).hostname.toLowerCase();
  } catch {
    throw new ReportValidationError("url", "url からホスト名を抽出できない");
  }
  if (host.length < 4 || !host.includes(".")) {
    throw new ReportValidationError("url", `url のホスト名 "${host}" が不正`);
  }
  return { host };
}

interface GhContext {
  token: string;
  owner: string;
  repo: string;
}

function getContext(): GhContext {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  if (!token) throw new Error("GITHUB_TOKEN が未設定");
  if (!repo || !repo.includes("/")) throw new Error("GITHUB_REPOSITORY (owner/repo) が未設定");
  const [owner, name] = repo.split("/");
  return { token, owner, repo: name };
}

async function ghFetch(
  ctx: GhContext,
  method: string,
  path: string,
  body?: unknown,
): Promise<unknown> {
  const res = await fetch(`${GITHUB_API}/repos/${ctx.owner}/${ctx.repo}${path}`, {
    method,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${ctx.token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API ${method} ${path}: ${res.status} ${text.slice(0, 200)}`);
  }
  return res.json();
}

function buildThreatFile(host: string, input: SubmitInput): ThreatFile {
  const now = new Date().toISOString();
  const threat: Threat = {
    url: input.url,
    severity: input.severity ?? "medium",
    intent: "other",
    techniques: [],
    description: input.description.trim(),
    source: "report-threat",
    source_url: input.source_url,
    first_seen: now,
    last_seen: now,
    is_active: true,
  };
  return { domain: host, threats: [threat], updated_at: now };
}

function buildPrBody(host: string, input: SubmitInput): string {
  return [
    `本 PR は \`/api/report-threat\` または MCP \`report_threat\` ツール経由で送信された脅威レポートを起票したものです。`,
    "",
    `## 送信内容`,
    `- **対象 URL**: ${input.url}`,
    `- **対象ホスト**: \`${host}\``,
    `- **出典 (source_url)**: ${input.source_url}`,
    `- **送信者の severity 見立て**: ${input.severity ?? "(未指定 → medium で初期化)"}`,
    "",
    `## 観測内容 (送信者記述)`,
    "",
    "> " + input.description.replace(/\n/g, "\n> "),
    "",
    `## 検証`,
    "本 PR は \`pr-validate.yml\` ワークフローによって観点 1 (scan: 到達性 + AI 悪意コード解析 + severity 判定) と観点 2 (research: source_url 妥当性 + ドメイン Web 検索評判) で自動検証され、結果が PR コメントとして投稿されます。検証で問題が検出された場合は CI が失敗し merge ブロックされます。",
    "",
    `## レビュアーの判断`,
    "PR コメントの検証結果を確認し、内容が妥当であれば merge してください。",
  ].join("\n");
}

/** メインエントリポイント */
export async function submitThreatReport(input: SubmitInput): Promise<SubmitResult> {
  const { host } = validateInput(input);
  const ctx = getContext();

  // 1. main HEAD SHA
  const mainRef = (await ghFetch(ctx, "GET", "/git/ref/heads/main")) as {
    object: { sha: string };
  };
  const mainSha = mainRef.object.sha;

  // 2. ブランチ作成
  const branch = `report/${host}-${Date.now()}`;
  await ghFetch(ctx, "POST", "/git/refs", {
    ref: `refs/heads/${branch}`,
    sha: mainSha,
  });

  // 3. ファイル作成
  const filePath = `data/threats/domains/${host}.json`;
  const content = JSON.stringify(buildThreatFile(host, input), null, 2) + "\n";
  const contentB64 = Buffer.from(content, "utf-8").toString("base64");
  await ghFetch(ctx, "PUT", `/contents/${encodeURIComponent(filePath).replace(/%2F/g, "/")}`, {
    message: `report: ${host} (via API/MCP)`,
    content: contentB64,
    branch,
  });

  // 4. PR 起票
  const pr = (await ghFetch(ctx, "POST", "/pulls", {
    title: `report: ${host} (via API/MCP)`,
    head: branch,
    base: "main",
    body: buildPrBody(host, input),
  })) as { html_url: string; number: number };

  return {
    pr_url: pr.html_url,
    pr_number: pr.number,
    branch,
    host,
  };
}
