/**
 * data/ 配下 JSON の形式定義。
 * source_url の必須化はここでコンパイル時に強制する。
 */

export type AttackIntent =
  | "ad_review_bypass"
  | "seo_poisoning"
  | "data_destruction"
  | "denial_of_service"
  | "unauthorized_transaction"
  | "sensitive_information_leakage"
  | "system_prompt_leakage"
  | "credential_theft"
  | "api_key_exfiltration"
  | "recruitment_manipulation"
  | "review_manipulation"
  | "anti_scraping"
  | "irrelevant_output"
  | "resource_exhaustion"
  | "phishing_redirect"
  | "ai_memory_poisoning"
  | "ai_output_manipulation"
  | "malware_distribution"
  | "other";

export type Technique =
  | "zero_font_size"
  | "css_display_none"
  | "css_visibility_hidden"
  | "css_opacity_zero"
  | "offscreen_positioning"
  | "html_comment"
  | "html_attribute_cloaking"
  | "textarea_hidden"
  | "color_camouflage"
  | "javascript_dynamic"
  | "url_fragment_injection"
  | "url_parameter_injection"
  | "visible_plaintext"
  | "ignore_previous_instructions"
  | "role_override"
  | "base64_encoding"
  | "payload_splitting"
  | "homoglyph_substitution"
  | "bidi_attack"
  | "multilingual_prompt"
  | "markdown_injection"
  | "system_prompt_mimicry"
  | "memory_persistence_injection"
  | "memory_manipulation"
  | "summarize_button_manipulation"
  | "url_prompt_parameter_injection"
  | "visible_plaintext_footer"
  | "other";

export type Severity = "critical" | "high" | "medium" | "low";

/** 1 件の脅威レコード。source_url は必須 (出典なきレコードは存在し得ない) */
export interface Threat {
  url?: string;
  severity: Severity;
  intent: AttackIntent;
  techniques: Technique[];
  description: string;
  source: string;
  source_url: string;
  first_seen: string;
  last_seen: string;
  is_active: boolean;
  raw_payloads?: string[];
}

/** data/threats/domains/<host>.json の構造 */
export interface ThreatFile {
  domain: string;
  threats: Threat[];
  updated_at: string;
}

/** 軽量インデックスエントリ */
export interface ThreatIndexEntry {
  max_severity: Severity;
  intents: string[];
  threat_count: number;
  last_seen: string;
  is_active: boolean;
}

/** data/threats/index.json の構造 */
export interface ThreatIndex {
  domains: Record<string, ThreatIndexEntry>;
  total_threats: number;
  total_domains: number;
  generated_at: string;
}

/** data/sources.json の各エントリ */
export interface DataSource {
  id: string;
  name: string;
  url: string | null;
  type: string;
  /** collect.ts での取得方式。"internal" は巡回 skip */
  method: "otx_api" | "claude_web_search" | "internal";
  update_frequency: string;
}

/** lib/scan.ts の出力 (観点 1) */
export interface ScanResult {
  reachable: boolean;
  httpStatus?: number;
  aiVerdict: "malicious" | "benign" | "unknown";
  intent: AttackIntent;
  techniques: Technique[];
  severity: Severity;
  reasoningJa: string;
}

/** lib/research.ts の出力 (観点 2) */
export interface ResearchResult {
  sourceVerdict: "valid" | "weak" | "invalid" | "unknown";
  domainClass: "malicious" | "legitimate" | "unknown";
  reasoningJa: string;
}

/** url の形式バリデート (書込層用) */
export function isValidHttpUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}
