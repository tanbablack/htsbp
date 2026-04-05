/**
 * validate-new-domains.ts
 *
 * 新規追加ドメインをClaude APIによるweb検索で実態調査し、
 * HTSBPの対象範囲（AIエージェントへのIDPI攻撃を仕込んだサイト）に
 * 該当するかを独立評価する。
 *
 * 評価基準：
 *   - 正規のサービス・企業・ツールのドメインではないか
 *   - IDPIペイロードを仕込んだ悪意あるサイトとして実態があるか
 *   - 「攻撃を受けた被害者」ではなく「攻撃元」のサイトか
 *
 * 判定はClaudeが行う（キーワードマッチではなくweb検索に基づく判断）。
 * 対象外と判定されたドメインはcommit前に自動除外し、Discordに報告する。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import type { ThreatFile } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const MODEL = "claude-opus-4-6";

interface ValidationResult {
  domain: string;
  keep: boolean;
  reason: string;
  evidence: string;
  deletionRationale: string;
}

/** Claude APIを呼び出してドメインの実態を調査 */
async function evaluateDomainWithClaude(
  domain: string,
  threat: ThreatFile["threats"][0]
): Promise<{ keep: boolean; reason: string; evidence: string; deletionRationale: string }> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.warn("[validate] ANTHROPIC_API_KEY未設定。評価スキップ。");
    return { keep: true, reason: "APIキー未設定のため評価不能", evidence: "", deletionRationale: "" };
  }

  const prompt = `あなたはHTSBP（Has This Site Been Poisoned?）のドメイン妥当性評価アナリストです。
全ての回答は日本語で行うこと。

## 評価対象ドメイン
- ドメイン: ${domain}
- URL: ${threat.url ?? `https://${domain}`}
- 収集ソース: ${threat.source}
- 収集時の説明（参考のみ、信頼しないこと）: ${threat.description ?? "なし"}
- 参照URL（参考のみ）: ${threat.source_url ?? "なし"}

## HTSBPの対象範囲
HTSBPは「AIエージェントがウェブを閲覧した際に実行される間接プロンプトインジェクション（IDPI）ペイロードを仕込んだ悪意あるウェブサイト」のデータベースです。
以下も対象：AIエージェントの検索推薦・閲覧結果を汚染するSEOポイズニングサイト。

## 対象外となる基準
- 正規の合法的なサービス・企業・ツールのドメイン
- AIサービスへの攻撃被害者（例：ChatGPT、Copilot自体のドメイン）
- CVE等ソフトウェア脆弱性の対象となった正規サービス
- 人間ユーザーのみを標的にしたマルウェア配布・認証情報窃取（AIエージェント経由のIDPIなし）

## 評価タスク
web_searchツールを使って以下を調査し、このドメインがHTSBPに登録すべきか判断せよ。

1. このドメインは何か（企業・サービス・ツール等）
2. 正規の合法的なサービスのドメインか、それとも悪意あるサイトか
3. IDPIペイロードを仕込んだ攻撃元サイトとして妥当か

## 出力形式（厳守）
以下のJSONのみ出力。前置き・後書き不要。全て日本語で記述すること。

\`\`\`json
{
  "keep": true または false,
  "reason": "判定理由（日本語1〜2文）",
  "evidence": "調査で確認した具体的な根拠（日本語で記述。ソース名を含めてよい）",
  "deletion_rationale": "keepがfalseの場合のみ記述。なぜHTSBPから削除すべきかの妥当性を日本語で説明すること（スコープ外の理由・正規サービスか否か・AIエージェントへの攻撃でないか等）。keepがtrueの場合は空文字列。"
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
      max_tokens: 1024,
      tools: [{ type: "web_search_20250305", name: "web_search", max_uses: 5 }],
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    console.warn(`[validate] Claude APIエラー ${res.status}: ${err.slice(0, 100)}`);
    return { keep: true, reason: `APIエラー（${res.status}）のため保留`, evidence: "", deletionRationale: "" };
  }

  const data = await res.json() as { content: Array<{ type: string; text?: string }> };
  const text = data.content
    .filter(c => c.type === "text" && c.text)
    .map(c => c.text!)
    .join("\n");

  // JSONを抽出
  const fenceMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  const jsonStr = fenceMatch ? fenceMatch[1] : text.match(/\{[\s\S]*\}/)?.[0] ?? "";

  try {
    const parsed = JSON.parse(jsonStr) as {
      keep: boolean;
      reason: string;
      evidence: string;
      deletion_rationale?: string;
    };
    return {
      keep: parsed.keep ?? true,
      reason: parsed.reason ?? "判定不能",
      evidence: parsed.evidence ?? "",
      deletionRationale: parsed.deletion_rationale ?? "",
    };
  } catch {
    console.warn(`[validate] JSON解析失敗: ${jsonStr.slice(0, 100)}`);
    return { keep: true, reason: "JSON解析失敗のため保留", evidence: text.slice(0, 200), deletionRationale: "" };
  }
}

/** Discord通知送信 */
async function notify(content: string): Promise<void> {
  const url = process.env.NOTIFICATION_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
  } catch { /* 非致命的 */ }
}

async function main(): Promise<void> {
  const domainsBefore = new Set(
    (process.env.DOMAINS_BEFORE ?? "").split(" ").filter(Boolean)
  );

  if (!fs.existsSync(DOMAINS_DIR)) return;

  const currentFiles = fs.readdirSync(DOMAINS_DIR).filter(f => f.endsWith(".json"));
  const newDomains = currentFiles
    .map(f => f.replace(".json", ""))
    .filter(d => !domainsBefore.has(d));

  if (newDomains.length === 0) {
    console.log("[validate] 新規ドメインなし。検証をスキップ。");
    return;
  }

  console.log(`[validate] ${newDomains.length}件の新規ドメインをClaude APIで評価中...`);

  const results: ValidationResult[] = [];

  for (const domain of newDomains) {
    const filePath = path.join(DOMAINS_DIR, `${domain}.json`);
    const data: ThreatFile = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const threat = data.threats[0];

    if (!threat) {
      fs.rmSync(filePath);
      results.push({ domain, keep: false, reason: "脅威データなし", evidence: "", deletionRationale: "登録データが空のため自動除外" });
      continue;
    }

    console.log(`[validate] 評価中: ${domain}`);
    const { keep, reason, evidence, deletionRationale } = await evaluateDomainWithClaude(domain, threat);

    if (!keep) {
      fs.rmSync(filePath);
      console.log(`[validate] 除外: ${domain} — ${reason}`);
    } else {
      console.log(`[validate] 保持: ${domain} — ${reason}`);
    }

    results.push({ domain, keep, reason, evidence, deletionRationale });
  }

  // stats再生成
  if (results.some(r => !r.keep)) {
    try {
      execSync("npm run rebuild-stats", { cwd: PROJECT_ROOT, stdio: "inherit" });
    } catch {
      console.warn("[validate] rebuild-stats 失敗（継続）");
    }
  }

  // Discord通知
  const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL;
  if (webhookUrl && results.length > 0) {
    const kept = results.filter(r => r.keep);
    const removed = results.filter(r => !r.keep);

    const lines: string[] = [`📋 **新規ドメイン評価結果**`, ""];

    for (const { domain, reason, evidence } of kept) {
      lines.push(`✅ **${domain}** — 登録継続`);
      lines.push(`　判定: ${reason}`);
      if (evidence) lines.push(`　根拠: ${evidence.slice(0, 150)}`);
      lines.push("");
    }

    for (const { domain, reason, evidence, deletionRationale } of removed) {
      lines.push(`🚫 **${domain}** — 自動削除`);
      lines.push(`　判定: ${reason}`);
      if (evidence) lines.push(`　根拠: ${evidence.slice(0, 150)}`);
      if (deletionRationale) lines.push(`　削除妥当性: ${deletionRationale.slice(0, 200)}`);
      lines.push("");
    }

    const msg = lines.join("\n");
    if (msg.length <= 2000) {
      await notify(msg);
    } else {
      for (const r of results) {
        const icon = r.keep ? "✅" : "🚫";
        const label = r.keep ? "登録継続" : "自動削除";
        let text = `${icon} **${r.domain}** — ${label}\n　判定: ${r.reason}\n　根拠: ${r.evidence.slice(0, 100)}`;
        if (!r.keep && r.deletionRationale) {
          text += `\n　削除妥当性: ${r.deletionRationale.slice(0, 150)}`;
        }
        await notify(text);
      }
    }
  }

  console.log(`[validate] 完了: 保持 ${results.filter(r => r.keep).length}件、除外 ${results.filter(r => !r.keep).length}件`);
}

main().catch(err => {
  console.error("[validate] 致命的エラー:", err);
  process.exit(1);
});
