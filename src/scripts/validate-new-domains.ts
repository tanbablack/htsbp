/**
 * validate-new-domains.ts
 *
 * 新規追加ドメインがHTSBPの対象範囲（AIエージェントへのIDPI攻撃）に
 * 該当するかを独立検証し、対象外のドメインをcommit前に自動除外する。
 *
 * 実行タイミング：collect.yml の verify 完了後・commit 前
 *
 * 判定基準（優先順）：
 *   1. IDPIスキャン HIGH/MEDIUM → 保持（AIペイロード実検出）
 *   2. source_url の実取得 → 記事内にIDPIキーワードがあれば保持（独立検証）
 *   3. 信頼ソース（unit42/htsbp）かつ source_url が有効なメディアドメイン → 保持
 *   4. 上記すべて満たさない → 除外
 *
 * コレクターが生成した description の内容は判定に使用しない（自己参照を排除）。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkUrl, type ThreatLevel } from "./check-url.js";
import { execSync } from "node:child_process";
import type { ThreatFile } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

/** 信頼できる外部ソースドメイン（独立したセキュリティメディア・研究機関） */
const TRUSTED_SOURCE_DOMAINS = new Set([
  "unit42.paloaltonetworks.com",
  "otx.alienvault.com",
  "thehackernews.com",
  "bleepingcomputer.com",
  "threatpost.com",
  "cybersecuritynews.com",
  "securityweek.com",
  "kaspersky.com",
  "securelist.com",
  "crowdstrike.com",
  "mandiant.com",
  "trendmicro.com",
  "microsoft.com",
  "google.com",
  "cert.org",
  "nvd.nist.gov",
  "cve.mitre.org",
  "arxiv.org",
  "pillar.security",
  "lakera.ai",
  "simonwillison.net",
  "gbhackers.com",
  "darkreading.com",
]);

/** 外部記事内でIDPI対象であることを示すキーワード */
const IDPI_EVIDENCE_KEYWORDS = [
  "prompt injection",
  "indirect prompt injection",
  "idpi",
  "ai agent",
  "llm",
  "language model",
  "chatbot",
  "ai assistant",
  "copilot",
  "rag",
  "retrieval augmented",
  "tool use",
  "function call",
  "ai-powered",
  "ai system",
  "ai search",
  "ai recommendation",
  "poisoned.*ai",
  "ai.*poison",
];

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

/** URLのドメイン部分を取得 */
function getDomain(url: string): string | null {
  try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return null; }
}

/** 外部URLを取得してIDPIキーワードが含まれるか確認（独立検証） */
async function verifySourceUrl(sourceUrl: string): Promise<{
  trusted: boolean;
  hasIdpiKeyword: boolean;
  reason: string;
}> {
  const sourceDomain = getDomain(sourceUrl);
  if (!sourceDomain) {
    return { trusted: false, hasIdpiKeyword: false, reason: "source_url が無効" };
  }

  const isTrustedDomain = TRUSTED_SOURCE_DOMAINS.has(sourceDomain);

  // 記事本文を取得してIDPIキーワードを確認
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const res = await fetch(sourceUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; htsbp-validator/1.0)" },
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timer);

    if (!res.ok) {
      return {
        trusted: isTrustedDomain,
        hasIdpiKeyword: false,
        reason: `記事取得失敗 HTTP ${res.status}（${sourceDomain}）`,
      };
    }

    const text = (await res.text()).toLowerCase();
    const foundKeyword = IDPI_EVIDENCE_KEYWORDS.find(kw => {
      try { return new RegExp(kw).test(text); } catch { return text.includes(kw); }
    });

    return {
      trusted: isTrustedDomain,
      hasIdpiKeyword: !!foundKeyword,
      reason: foundKeyword
        ? `記事内にIDPIキーワード「${foundKeyword}」を確認（${sourceDomain}）`
        : `記事内にIDPIキーワードなし（${sourceDomain}）`,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      trusted: isTrustedDomain,
      hasIdpiKeyword: false,
      reason: `記事取得エラー: ${msg.slice(0, 60)}（${sourceDomain}）`,
    };
  }
}

/**
 * ドメインの妥当性を独立検証する。
 * コレクター生成の description は判定に使用しない。
 */
async function validateDomain(domain: string): Promise<{
  keep: boolean;
  reason: string;
  scanLevel: ThreatLevel;
  evidence: string;
}> {
  const filePath = path.join(DOMAINS_DIR, `${domain}.json`);
  const data: ThreatFile = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  const threat = data.threats[0];

  if (!threat) {
    return { keep: false, reason: "脅威データなし", scanLevel: "UNREACHABLE", evidence: "なし" };
  }

  // ステップ1：IDPIスキャン（実際のHTMLを解析）
  const scanUrl = threat.url ?? `https://${domain}`;
  const result = await checkUrl(scanUrl);

  if (result.level === "HIGH" || result.level === "MEDIUM") {
    return {
      keep: true,
      reason: "IDPIスキャンで対象ペイロードを実検出",
      scanLevel: result.level,
      evidence: `スキャンURL: ${scanUrl} → ${result.level}`,
    };
  }

  // ステップ2：source_url の独立検証
  const sourceUrl = threat.source_url;
  if (sourceUrl) {
    const verification = await verifySourceUrl(sourceUrl);

    if (verification.trusted && verification.hasIdpiKeyword) {
      return {
        keep: true,
        reason: "信頼ソースの記事内でIDPI関連キーワードを確認",
        scanLevel: result.level,
        evidence: `${verification.reason}`,
      };
    }

    if (verification.trusted && !verification.hasIdpiKeyword) {
      return {
        keep: false,
        reason: "信頼ソースだがIDPI関連キーワードなし（AIエージェント対象外の可能性）",
        scanLevel: result.level,
        evidence: `${verification.reason}`,
      };
    }

    if (!verification.trusted && verification.hasIdpiKeyword) {
      return {
        keep: false,
        reason: "非信頼ソース（独立検証不可）",
        scanLevel: result.level,
        evidence: `ソース ${getDomain(sourceUrl)} は信頼リスト外`,
      };
    }
  }

  // ステップ3：source_url なし または取得失敗
  return {
    keep: false,
    reason: "IDPIスキャン未検出かつ独立検証不可",
    scanLevel: result.level,
    evidence: sourceUrl ? `source_url の検証失敗` : "source_url なし",
  };
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

  console.log(`[validate] ${newDomains.length}件の新規ドメインを検証中...`);

  const kept: Array<{ domain: string; reason: string; scanLevel: ThreatLevel; evidence: string }> = [];
  const removed: Array<{ domain: string; reason: string; scanLevel: ThreatLevel; evidence: string }> = [];

  for (const domain of newDomains) {
    console.log(`[validate] 検証中: ${domain}`);
    const result = await validateDomain(domain);

    if (result.keep) {
      kept.push({ domain, ...result });
      console.log(`[validate] 保持: ${domain} — ${result.reason}`);
    } else {
      fs.rmSync(path.join(DOMAINS_DIR, `${domain}.json`));
      removed.push({ domain, ...result });
      console.log(`[validate] 除外: ${domain} — ${result.reason}`);
    }
  }

  // stats 再生成
  if (removed.length > 0) {
    try {
      execSync("npm run rebuild-stats", { cwd: PROJECT_ROOT, stdio: "inherit" });
    } catch {
      console.warn("[validate] rebuild-stats 失敗（継続）");
    }
  }

  // Discord通知
  const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL;
  if (webhookUrl && (kept.length > 0 || removed.length > 0)) {
    const lines: string[] = [`📋 **新規ドメイン検証結果**`, ""];

    for (const { domain, reason, scanLevel, evidence } of kept) {
      lines.push(`✅ **${domain}** — 保持`);
      lines.push(`　判定理由: ${reason}`);
      lines.push(`　証拠: ${evidence}`);
      lines.push(`　IDPIスキャン: ${scanLevel}`);
      lines.push("");
    }

    for (const { domain, reason, scanLevel, evidence } of removed) {
      lines.push(`🚫 **${domain}** — 除外`);
      lines.push(`　判定理由: ${reason}`);
      lines.push(`　証拠: ${evidence}`);
      lines.push(`　IDPIスキャン: ${scanLevel}`);
      lines.push("");
    }

    const msg = lines.join("\n");
    if (msg.length <= 2000) {
      await notify(msg);
    } else {
      await notify(lines.slice(0, 3).join("\n"));
      for (const item of [...kept, ...removed]) {
        await notify([
          item.keep === undefined
            ? `✅ **${item.domain}**`
            : `🚫 **${item.domain}**`,
          `　${item.reason}`,
          `　証拠: ${item.evidence}`,
        ].join("\n"));
      }
    }
  }

  console.log(`[validate] 完了: 保持 ${kept.length}件、除外 ${removed.length}件`);
}

main().catch(err => {
  console.error("[validate] 致命的エラー:", err);
  process.exit(1);
});
