# IDPI脅威インテリジェンス: 新規サイト発見タスク

## あなたの役割
AIセキュリティリサーチャーとして、間接プロンプトインジェクション（IDPI）を含むWebサイトの新規情報を収集する。

## タスク
Web検索を使って以下のソースを実際に検索し、IDPI攻撃を含むドメイン/URLの最新情報を収集せよ。
必ずweb_searchツールを使用してリアルタイムの情報を取得すること。学習済みデータのみに頼らないこと。

### 調査対象ソース
1. セキュリティブログ・リサーチ記事（直近7日の最新情報を優先）
   - Unit 42 (Palo Alto Networks)
   - Pillar Security
   - Lakera Blog
   - NeuralTrust Blog
   - Kaspersky Securelist
   - Brave Security Blog
   - HackerNews (AI security関連)
2. GitHub（新規Issue/PR/リポジトリ）
   - "indirect prompt injection" "IDPI" "prompt injection website" で検索
3. 学術論文（arXiv cs.CR, cs.AI）
   - "indirect prompt injection" "wild" "in-the-wild" で検索
4. CVE/脆弱性データベース
   - prompt injection 関連CVE

### 出力形式（厳守）
以下のJSONオブジェクトとして出力。自然言語の前置き・後書きは一切不要。

```json
{
  "threats": [
    {
      "domain": "example.com",
      "url": "https://example.com/malicious-page",
      "severity": "high",
      "intent": "seo_poisoning",
      "techniques": ["css_display_none", "javascript_dynamic"],
      "description": "Hidden IDPI payload found promoting phishing site via AI recommendations",
      "source": "unit42 blog post dated 2026-03-10",
      "source_url": "https://unit42.paloaltonetworks.com/..."
    }
  ],
  "suggested_patterns": []
}
```

### 重要な制約
- 実際にIDPI攻撃が確認されたサイトのみ報告すること
- 「理論的に可能」「PoCとして作成された」ものは除外
- ドメインの defang（[.]表記）は不要。生ドメインで出力
- 1回の実行で最大50件まで

## 追加タスク: 検出パターンの提案

調査中に、既存のIDPI検出パターンでは捕捉できない**新しい攻撃手法や隠蔽テクニック**を発見した場合、`suggested_patterns` で提案せよ。

### 現在の検出パターン（既知）
**命令パターン**: ignore previous instructions, role override (you are now a), system prompt mimicry, disobey, override/bypass/disregard, chat template injection ([INST]/im_start), IMPORTANT: override, direct AI directive
**隠蔽パターン**: zero font size, display:none, visibility:hidden, opacity:0, offscreen positioning, white-on-white text, zero dimensions, overflow:hidden

### パターン提案フォーマット
```json
{
  "category": "instruction",
  "pattern": "new\\s+regex\\s+here",
  "flags": "i",
  "name": "short_snake_case_name",
  "label": "Human-readable description",
  "technique": "technique_name_for_concealments_only",
  "reason": "Observed at example.com — uses CSS clip-path to hide injected instructions"
}
```

### パターン提案の制約
- 実際に野生で観測された攻撃手法のみ
- 正規表現としてコンパイル可能であること
- 既存パターンと重複しないこと
- category は "instruction" または "concealment"
- 新しいパターンがなければ空配列 `[]` でよい
