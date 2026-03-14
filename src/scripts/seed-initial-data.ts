import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ThreatFile, Threat } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const DOMAINS_DIR = path.join(PROJECT_ROOT, "data/threats/domains");

interface SeedEntry {
  domain: string;
  threats: Threat[];
}

const initialData: SeedEntry[] = [
  {
    domain: "reviewerpress.com",
    threats: [{
      url: "https://reviewerpress.com/advertorial-maxvision-can/?lang=en",
      severity: "critical",
      intent: "ad_review_bypass",
      techniques: ["zero_font_size", "css_display_none", "css_visibility_hidden", "css_opacity_zero", "offscreen_positioning", "textarea_hidden", "color_camouflage", "javascript_dynamic"],
      description: "First known real-world AI ad review bypass. 24 injection attempts using 8+ concealment techniques. Promotes scam military glasses product.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2025-12-15T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "reviewerpressus.mycartpanda.com",
    threats: [{
      severity: "high",
      intent: "phishing_redirect",
      techniques: [],
      description: "Fraudulent payment redirect destination linked to reviewerpress.com scam.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2025-12-15T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "cblanke2.pages.dev",
    threats: [{
      severity: "critical",
      intent: "data_destruction",
      techniques: ["html_attribute_cloaking"],
      description: "Attempts to execute rm -rf --no-preserve-root and fork bomb via IDPI payload.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "llm7-landing.pages.dev",
    threats: [{
      url: "https://llm7-landing.pages.dev/_next/static/chunks/app/page-94a1a9b785a7305c.js",
      severity: "high",
      intent: "unauthorized_transaction",
      techniques: ["javascript_dynamic"],
      description: "IDPI payload embedded in JS chunk file attempting to redirect AI agents to unauthorized transactions.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "storage3d.com",
    threats: [{
      url: "https://storage3d.com/storage/2009.11",
      severity: "high",
      intent: "unauthorized_transaction",
      techniques: ["javascript_dynamic"],
      description: "Forces AI agent to visit Stripe payment link for unauthorized donation.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "1winofficialsite.in",
    threats: [{
      severity: "high",
      intent: "seo_poisoning",
      techniques: ["visible_plaintext"],
      description: "SEO poisoning to promote phishing site impersonating betting platform via LLM recommendations.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "dylansparks.com",
    threats: [{
      severity: "medium",
      intent: "other",
      techniques: [],
      description: "IDPI detected in Unit42 telemetry. Specific payload details not publicly disclosed.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "leroibear.com",
    threats: [{
      severity: "medium",
      intent: "other",
      techniques: [],
      description: "IDPI detected in Unit42 telemetry.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "myshantispa.com",
    threats: [{
      severity: "medium",
      intent: "other",
      techniques: [],
      description: "IDPI detected in Unit42 telemetry.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "perceptivepumpkin.com",
    threats: [{
      severity: "medium",
      intent: "other",
      techniques: [],
      description: "IDPI detected in Unit42 telemetry.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  },
  {
    domain: "ericwbailey.website",
    threats: [{
      url: "https://ericwbailey.website/published/accessibility-preference-settings-information-architecture-and-internalized-ableism",
      severity: "low",
      intent: "anti_scraping",
      techniques: ["visible_plaintext"],
      description: "Anti-scraping IDPI embedded in blog post content.",
      source: "unit42",
      source_url: "https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/",
      first_seen: "2026-03-03T00:00:00Z",
      last_seen: "2026-03-03T00:00:00Z",
      is_active: true
    }]
  }
];

/** Generate seed data files for all initial threat domains */
function seed(): void {
  fs.mkdirSync(DOMAINS_DIR, { recursive: true });

  const now = new Date().toISOString();

  for (const entry of initialData) {
    const threatFile: ThreatFile = {
      domain: entry.domain,
      threats: entry.threats,
      updated_at: now
    };

    const filePath = path.join(DOMAINS_DIR, `${entry.domain}.json`);
    fs.writeFileSync(filePath, JSON.stringify(threatFile, null, 2) + "\n");
    console.log(`Created: ${filePath}`);
  }

  console.log(`\nSeeded ${initialData.length} domain files.`);
}

seed();
