/** Attack intent classification for IDPI threats */
export type AttackIntent =
  | "ad_review_bypass"
  | "seo_poisoning"
  | "data_destruction"
  | "denial_of_service"
  | "unauthorized_transaction"
  | "sensitive_info_leakage"
  | "system_prompt_leakage"
  | "recruitment_manipulation"
  | "review_manipulation"
  | "anti_scraping"
  | "irrelevant_output"
  | "resource_exhaustion"
  | "phishing_redirect"
  | "other";

/** Concealment technique used by IDPI payloads */
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
  | "other";

/** Severity level for threats */
export type Severity = "critical" | "high" | "medium" | "low";

/** Individual threat record */
export interface Threat {
  url?: string;
  severity: Severity;
  intent: AttackIntent;
  techniques: Technique[];
  description: string;
  source: string;
  source_url?: string;
  first_seen: string;
  last_seen: string;
  is_active: boolean;
  raw_payloads?: string[];
}

/** Per-domain threat file stored in data/threats/domains/{domain}.json */
export interface ThreatFile {
  domain: string;
  threats: Threat[];
  updated_at: string;
}

/** Lightweight index entry for a single domain */
export interface ThreatIndexEntry {
  max_severity: Severity;
  intents: string[];
  threat_count: number;
  last_seen: string;
  is_active: boolean;
}

/** Auto-generated index of all domains (data/threats/index.json) */
export interface ThreatIndex {
  domains: {
    [domain: string]: ThreatIndexEntry;
  };
  total_threats: number;
  total_domains: number;
  generated_at: string;
}

/** Auto-generated statistics summary (data/stats.json) */
export interface Stats {
  total_threats: number;
  total_domains: number;
  by_severity: { critical: number; high: number; medium: number; low: number };
  by_intent: { [key: string]: number };
  by_source: { [key: string]: number };
  last_updated: string;
  generated_at: string;
}

/** Data source definition (data/sources.json) */
export interface DataSource {
  id: string;
  name: string;
  url: string | null;
  type: string;
  update_frequency: string;
}
