# IDPI脅威インテリジェンス: 新規サイト発見タスク

## あなたの役割
AIセキュリティリサーチャーとして、間接プロンプトインジェクション（IDPI）を含むWebサイトの新規情報を収集する。

## タスク
以下のソースを調査し、IDPI攻撃を含むドメイン/URLの新規情報を収集せよ。

### 調査対象ソース
1. セキュリティブログ・リサーチ記事（直近30日）
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
以下のJSON配列として出力。自然言語の前置き・後書きは一切不要。

```json
[
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
]
```

### 重要な制約
- 実際にIDPI攻撃が確認されたサイトのみ報告すること
- 「理論的に可能」「PoCとして作成された」ものは除外
- ドメインの defang（[.]表記）は不要。生ドメインで出力
- 1回の実行で最大50件まで
