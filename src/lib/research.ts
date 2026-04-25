/**
 * 観点 2: ソース妥当性 + ドメイン Web 検索評判
 *
 * Claude 1 コール + web_search で source_url の中身が対象ドメインに本当に
 * 言及しているかを確認 + 対象ドメイン自体を web_search で評判確認。
 */
import type { ResearchResult } from "../types.js";

const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const MODEL = "claude-opus-4-6";

export async function researchDomain(
  host: string,
  sourceUrl: string,
): Promise<ResearchResult> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return {
      sourceVerdict: "unknown",
      domainClass: "unknown",
      reasoningJa: "ANTHROPIC_API_KEY 未設定のため Web 検索ベース調査をスキップ",
    };
  }

  const prompt = `あなたは HTSBP (Has This Site Been Poisoned?) のドメイン妥当性審査アナリスト。
全て日本語で回答せよ。

## 評価対象
- ドメイン: ${host}
- 出典 URL: ${sourceUrl}

## 評価タスク
web_search ツールで以下 2 点を調査せよ。

### (a) ソース妥当性
出典 URL (${sourceUrl}) の中身を確認し、
そのページが対象ドメイン \`${host}\` を IDPI 関連で本当に言及しているか、
description との整合性を判定せよ。

### (b) ドメイン評判
対象ドメイン \`${host}\` を web_search で調査し、
正規企業/サービスか、悪意ある IDPI/SEO 汚染サイトか、未知かを分類せよ。

## 出力形式 (厳守)
JSON のみ。前置き・後書き不要。全フィールド日本語で記述。

\`\`\`json
{
  "source_verdict": "valid" | "weak" | "invalid" | "unknown",
  "domain_class": "malicious" | "legitimate" | "unknown",
  "reasoning_ja": "(a) ソース妥当性と (b) ドメイン分類それぞれの根拠を日本語で 3〜5 文。参照したサイト名/記事名/URL を含めてよい。"
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
      max_tokens: 1500,
      tools: [
        { type: "web_search_20250305", name: "web_search", max_uses: 5 },
      ],
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    return {
      sourceVerdict: "unknown",
      domainClass: "unknown",
      reasoningJa: `Claude API エラー (HTTP ${res.status}): ${err.slice(0, 100)}`,
    };
  }

  const data = (await res.json()) as {
    content: Array<{ type: string; text?: string }>;
  };
  const text = data.content
    .filter((c) => c.type === "text" && c.text)
    .map((c) => c.text!)
    .join("\n");

  const fence = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  const jsonStr = fence ? fence[1] : text.match(/\{[\s\S]*\}/)?.[0] ?? "";

  try {
    const parsed = JSON.parse(jsonStr) as {
      source_verdict: ResearchResult["sourceVerdict"];
      domain_class: ResearchResult["domainClass"];
      reasoning_ja: string;
    };
    return {
      sourceVerdict: parsed.source_verdict ?? "unknown",
      domainClass: parsed.domain_class ?? "unknown",
      reasoningJa: parsed.reasoning_ja ?? "調査根拠なし",
    };
  } catch {
    return {
      sourceVerdict: "unknown",
      domainClass: "unknown",
      reasoningJa: "Claude 応答の JSON 解析失敗",
    };
  }
}
