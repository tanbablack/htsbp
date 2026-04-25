# Has This Site Been Poisoned? (HTSBP)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

AI エージェントを標的に間接プロンプトインジェクション (IDPI) を仕込んだ Web サイトの公開脅威情報フィード。完全自動の日次収集 + 人間レビュー (PR merge) で運用する。

## 提供経路

3 系統。すべて同一の `data/` を源泉とし、応答には常に `source_url` を含む。

| 経路 | 内容 |
|---|---|
| REST API | `/api/check-domain` `/api/list-threats` `/api/stats` `/api/mcp` |
| MCP | ツール `check_domain` / `list_threats` |
| 静的 DL | `data/` 配下を Netlify 静的配信 + GitHub raw URL |

### REST API

```bash
curl "https://hasthissitebeenpoisoned.ai/api/check-domain?domain=reviewerpress.com"
```

### MCP Server (Claude Desktop / Cursor / Windsurf)

```json
{
  "mcpServers": {
    "htsbp": {
      "url": "https://hasthissitebeenpoisoned.ai/api/mcp"
    }
  }
}
```

### Raw Data

`data/threats/` 配下の JSON ファイルとして配信。`https://hasthissitebeenpoisoned.ai/data/threats/index.json` または GitHub raw URL から取得可能。

## リポジトリレイアウト

```
htsbp/
├── README.md
├── LICENSE
├── package.json                scripts: build / collect / recheck / dev
├── tsconfig.json
├── netlify.toml
├── build.mjs
├── .gitignore
│
├── data/                       脅威データ本体と巡回設定
│   ├── threats/
│   │   ├── domains/
│   │   │   └── <host>.json     1ドメイン1ファイル詳細レコード (source_url 必須)
│   │   └── index.json          照会用軽量サマリ (自動生成)
│   └── sources.json            巡回義務リスト
│
├── public/                     公開静的サイト
│   ├── index.html              LP
│   ├── docs.html               利用者向け API ドキュメント
│   └── llms.txt                AI エージェント向け案内
│
├── src/
│   ├── types.ts                data/ 配下 JSON の形式定義。source_url 必須をコンパイル時に強制
│   ├── api/                    Netlify Functions (REST エンドポイント実装)
│   │   ├── check-domain.ts     ドメイン照会 (domain → 該当 Threat 群を返す)
│   │   ├── list-threats.ts     一覧取得 (severity / intent / 件数フィルタ)
│   │   └── mcp.ts              MCP HTTP ルーティング
│   ├── mcp/
│   │   └── index.ts            MCP サーバー本体 (tools + handlers 同居)
│   ├── lib/
│   │   ├── data-loader.ts      API 共通ヘルパー (data/ 読込)
│   │   ├── scan.ts             観点 1: HTTP fetch + Claude AI 解析 + severity 判定
│   │   └── research.ts         観点 2: web_search で source 妥当性 + ドメイン評判
│   ├── collect.ts              新規ドメイン発見+判定+反映 (scan + research を呼ぶ)
│   ├── recheck.ts              既存ドメイン再検証+反映 (scan のみを呼ぶ)
│   └── validate-pr.ts          人間 PR の事前検証 (scan + research を呼びコメント投稿)
│
└── .github/workflows/
    ├── collect.yml             日次 cron (collect → recheck の順に実行)
    └── pr-validate.yml         PR 起票/更新時に validate-pr を実行 (auto/* ブランチは skip)
```

## 共通検証ライブラリ

### `src/lib/scan.ts` — 観点 1

URL を入力に「到達性 + AI 悪意コード解析 + severity 判定」を実行する単一関数 `scanUrl(url)` を export する。

```ts
scanUrl(url): Promise<{
  reachable: boolean;
  httpStatus?: number;
  aiVerdict: "malicious" | "benign" | "unknown";
  intent: AttackIntent;
  techniques: Technique[];
  severity: Severity;
  reasoningJa: string;
}>
```

内部処理: HTTP fetch (15 秒 timeout) → HTML 先頭 30KB を Claude が解析 → severity 判定ロジックに従い severity を確定。

#### severity 判定ロジック

| severity | 条件 |
|---|---|
| `critical` | 破壊的・金銭的操作のペイロードが実在: `data_destruction` / `unauthorized_transaction` / `credential_theft` / `api_key_exfiltration` 等 |
| `high` | 誘導的・情報漏洩的操作のペイロードが実在: `sensitive_information_leakage` / `phishing_redirect` / `ad_review_bypass` / `system_prompt_leakage` 等 |
| `medium` | ペイロードは確認したが影響は限定的: `seo_poisoning` / `anti_scraping` / `irrelevant_output` / `recruitment_manipulation` 等 |
| `low` | ペイロード片のみ・実行性が不確か / `aiVerdict: benign` だが既存 record で悪意とされている等の不一致 |

### `src/lib/research.ts` — 観点 2

ドメインと出典 URL を入力に「ソース妥当性 + ドメイン Web 検索評判」を統合判定する `researchDomain(host, sourceUrl)` を export する。

```ts
researchDomain(host, sourceUrl): Promise<{
  sourceVerdict: "valid" | "weak" | "invalid" | "unknown";
  domainClass: "malicious" | "legitimate" | "unknown";
  reasoningJa: string;
}>
```

内部処理: Claude 1 コール + `web_search` で `source_url` の中身が対象ドメインに本当に言及しているか確認 + 対象ドメイン自体を `web_search` で評判確認。

## 日次パイプライン (`collect.yml`)

cron で 1 日 1 回起動し、以下を順次実行。

### 1. 新規ドメイン発見+判定+反映 (`src/collect.ts`)

#### 段階 1: 発見

`sources.json` 全エントリを毎日必ず巡回 (Claude 裁量による skip を許さない)。`method` 別の取得方式:

- **`otx_api`** — AlienVault OTX 公式 API。`prompt injection` / `IDPI` / `indirect prompt injection` の 3 タームで pulse 検索、IDPI 関連キーワード合致 pulse のみから indicators 抽出。1 pulse 50 indicator・全体 200 domain 上限。504/503/429 はリトライ後 skip
- **`claude_web_search`** — ソースごとに Claude を 1 回呼び `web_search` で対象 URL のみを過去 30 日範囲で調査

`sources.json` 初期エントリ: `unit42` (claude_web_search) / `otx-api` (otx_api)。既知ドメインと主要プラットフォームはプロンプトで除外指示。巡回成功/失敗は GitHub Actions ワークフローログに出力。

#### 段階 2: 判定

候補ごとに以下を実行。

- `lib/scan.ts` の `scanUrl()` を呼ぶ (観点 1)
- `lib/research.ts` の `researchDomain()` を呼ぶ (観点 2)
- 両結果を統合し総合判定: `should_register: bool` + `confidence` + 日本語根拠 Markdown を生成

フェイルセーフは「安全側に倒して登録見送り」。

#### 段階 3: 反映

`should_register: true` のドメインごとに **個別の PR** を起票。書込前に `source_url` の存在と URL 形式を再バリデート。

- ブランチ: `auto/<host>-<YYYYMMDD>`
- 内容: 当該ドメインのドメインファイル + `index.json` 再生成分
- PR 本文: 観点 1+2+総合判定の日本語根拠 Markdown

### 2. 既存ドメイン再検証+反映 (`src/recheck.ts`)

`data/threats/domains/<host>.json` 全件を対象に `scanUrl()` を実行 (観点 1 のみ。出典は既に検証済みなので観点 2 は走らせない)。

| 検出した変化 | アクション |
|---|---|
| 到達性が変化 (例: 200 → 404 を 3 回連続で観測) | `is_active` を更新 |
| severity が変化 | `severity` を更新 |
| 新しい技術 (`techniques`) を観察 | `techniques` 配列に追加 |
| 上記いずれかの変化あり | `last_seen` をスキャン日時に更新 |
| 全て変化なし | スキップ (PR を出さない) |

変化を観察したドメインごとに **個別の PR** を起票:
- ブランチ: `auto/recheck/<host>-<YYYYMMDD>`
- PR 本文: 変化の前後比較 + `scanUrl()` の `reasoningJa`

レート制御: 1 日あたり最大 100 ドメイン。超える場合は `last_seen` が古い順にローテーション。

## PR 事前検証 (`pr-validate.yml` → `src/validate-pr.ts`)

`data/threats/domains/**` に変更を含む PR が起票/更新されたタイミングで自動実行。auto ブランチ (`auto/*`) からの PR は日次パイプラインで既に検証済みなので skip し、人間 PR のみ実行する。

```yaml
if: !startsWith(github.head_ref, 'auto/')
```

`validate-pr.ts` は変更ドメインを抽出し、`scanUrl()` (観点 1) + `researchDomain()` (観点 2) を実行:

- `source_url` 必須項目の存在確認
- 観点 1+2 の結果を PR コメントとして投稿
- 既存値との差分があれば指摘
- 必須欠落・到達不能 + 出典裏付けなしは CI ステータスを失敗にして merge ブロック

これにより、auto PR (collect.ts/recheck.ts 由来) と人間 PR の両方が同じ検証ライブラリ (`lib/scan.ts` + `lib/research.ts`) を通る。重い `research` (`web_search`) は新規追加時のみ走り、再検証時は走らない。

## Self-Hosting

```bash
git clone https://github.com/tanbablack/htsbp.git
cd htsbp
npm install
npm run dev
```

## Contributing

新規 IDPI サイトの貢献は **PR 経由** で受け付ける。`data/threats/domains/<host>.json` を作成して PR を起票すれば `pr-validate.yml` が自動で観点 1+2 を実行し、結果をコメントする。`source_url` (出典) は必須。

PR を merge できるのはレビュアーのみ。完全自動 merge は許可しない。

## License

MIT
