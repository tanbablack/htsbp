/**
 * CLI tool: Check a URL for IDPI (Indirect Prompt Injection) threats.
 *
 * Usage: npx tsx src/scripts/check-url.ts <url>
 *
 * Fetches the page, scans for hidden instructions, concealment techniques,
 * and reports findings with evidence.
 */
import { loadPatterns } from "../lib/patterns.js";

const { instructions: INSTRUCTION_PATTERNS, concealments: CONCEALMENT_PATTERNS } = loadPatterns();

interface Finding {
  type: "instruction" | "concealment" | "comment_injection" | "meta_injection" | "aria_injection";
  label: string;
  evidence: string;
  line?: number;
}

function extractContext(html: string, match: RegExpMatchArray, chars = 80): string {
  const idx = match.index ?? 0;
  const start = Math.max(0, idx - chars);
  const end = Math.min(html.length, idx + match[0].length + chars);
  const before = start > 0 ? "..." : "";
  const after = end < html.length ? "..." : "";
  return before + html.slice(start, end).replace(/\n/g, "\\n") + after;
}

function getLineNumber(html: string, index: number): number {
  return html.slice(0, index).split("\n").length;
}

function analyzeUrl(html: string): Finding[] {
  const findings: Finding[] = [];

  // 1. Instruction patterns in full HTML
  for (const { pattern, label } of INSTRUCTION_PATTERNS) {
    const match = html.match(pattern);
    if (match) {
      findings.push({
        type: "instruction",
        label,
        evidence: extractContext(html, match),
        line: getLineNumber(html, match.index ?? 0),
      });
    }
  }

  // 2. Concealment techniques
  for (const { pattern, label } of CONCEALMENT_PATTERNS) {
    const match = html.match(pattern);
    if (match) {
      findings.push({
        type: "concealment",
        label,
        evidence: extractContext(html, match),
        line: getLineNumber(html, match.index ?? 0),
      });
    }
  }

  // 3. HTML comments with instructions
  const commentRegex = /<!--([\s\S]*?)-->/g;
  let commentMatch;
  while ((commentMatch = commentRegex.exec(html)) !== null) {
    const content = commentMatch[1];
    for (const { pattern, label } of INSTRUCTION_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          type: "comment_injection",
          label: `HTML comment: ${label}`,
          evidence: `<!-- ${content.trim().slice(0, 200)} -->`,
          line: getLineNumber(html, commentMatch.index),
        });
      }
    }
  }

  // 4. Meta tags with suspicious content
  const metaRegex = /<meta\s[^>]*content\s*=\s*["']([^"']*)["'][^>]*>/gi;
  let metaMatch;
  while ((metaMatch = metaRegex.exec(html)) !== null) {
    const content = metaMatch[1];
    for (const { pattern, label } of INSTRUCTION_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          type: "meta_injection",
          label: `Meta tag: ${label}`,
          evidence: metaMatch[0].slice(0, 200),
          line: getLineNumber(html, metaMatch.index),
        });
      }
    }
  }

  // 5. ARIA / data attributes with instructions
  const ariaRegex = /(?:aria-label|aria-description|data-[\w-]+)\s*=\s*["']([^"']{20,})["']/gi;
  let ariaMatch;
  while ((ariaMatch = ariaRegex.exec(html)) !== null) {
    const content = ariaMatch[1];
    for (const { pattern, label } of INSTRUCTION_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          type: "aria_injection",
          label: `ARIA/data attr: ${label}`,
          evidence: ariaMatch[0].slice(0, 200),
          line: getLineNumber(html, ariaMatch.index),
        });
      }
    }
  }

  return findings;
}

/** Check result with threat level */
export type ThreatLevel = "HIGH" | "MEDIUM" | "LOW" | "CLEAN" | "UNREACHABLE";

export interface CheckResult {
  url: string;
  level: ThreatLevel;
  findings: Finding[];
  reason?: string;
  httpStatus?: number;
}

/** Determine threat level from findings */
function determineThreatLevel(findings: Finding[]): ThreatLevel {
  if (findings.length === 0) return "CLEAN";
  const instructions = findings.filter(f => f.type === "instruction");
  const concealments = findings.filter(f => f.type === "concealment");
  const injections = findings.filter(f => ["comment_injection", "meta_injection", "aria_injection"].includes(f.type));
  const hasCombined = instructions.length > 0 && concealments.length > 0;
  const hasInjection = injections.length > 0;
  if (hasCombined || hasInjection) return "HIGH";
  if (instructions.length > 0) return "MEDIUM";
  return "LOW";
}

/** Check a URL for IDPI threats (importable by other scripts) */
export async function checkUrl(targetUrl: string): Promise<CheckResult> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const res = await fetch(targetUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; htsbp-checker/1.0)",
        Accept: "text/html",
      },
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timer);

    if (!res.ok) {
      return { url: targetUrl, level: "UNREACHABLE", findings: [], reason: `HTTP ${res.status} ${res.statusText}`, httpStatus: res.status };
    }

    const contentType = res.headers.get("content-type") ?? "";
    if (!contentType.includes("text/html") && !contentType.includes("text/plain")) {
      return { url: targetUrl, level: "UNREACHABLE", findings: [], reason: `Non-HTML content: ${contentType}` };
    }

    const html = await res.text();
    const findings = analyzeUrl(html);
    return { url: targetUrl, level: determineThreatLevel(findings), findings };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const reason = message.includes("abort") ? "Timeout (15s)" : message;
    return { url: targetUrl, level: "UNREACHABLE", findings: [], reason };
  }
}

async function main() {
  const url = process.argv[2];
  if (!url) {
    console.error("Usage: npx tsx src/scripts/check-url.ts <url>");
    process.exit(1);
  }

  const targetUrl = url.startsWith("http") ? url : `https://${url}`;
  console.log(`\n🔍 Checking: ${targetUrl}\n`);

  const result = await checkUrl(targetUrl);

  if (result.level === "UNREACHABLE") {
    console.log(`❌ UNREACHABLE: ${result.reason}\n`);
    process.exit(2);
  }

  if (result.findings.length === 0) {
    console.log("✅ No IDPI patterns detected.\n");
    process.exit(0);
  }

  const { findings } = result;
  const instructions = findings.filter(f => f.type === "instruction");
  const concealments = findings.filter(f => f.type === "concealment");
  const injections = findings.filter(f => ["comment_injection", "meta_injection", "aria_injection"].includes(f.type));

  console.log(`⚠️  ${findings.length} finding(s) detected — Threat level: ${result.level}\n`);

  if (instructions.length > 0) {
    console.log("── Instruction Patterns ──");
    for (const f of instructions) {
      console.log(`  Line ${f.line}: ${f.label}`);
      console.log(`    ${f.evidence}\n`);
    }
  }

  if (concealments.length > 0) {
    console.log("── Concealment Techniques ──");
    for (const f of concealments) {
      console.log(`  Line ${f.line}: ${f.label}`);
      console.log(`    ${f.evidence}\n`);
    }
  }

  if (injections.length > 0) {
    console.log("── Hidden Injections ──");
    for (const f of injections) {
      console.log(`  Line ${f.line}: ${f.label}`);
      console.log(`    ${f.evidence}\n`);
    }
  }

  if (result.level === "HIGH") {
    console.log("⚠️  COMBINED THREAT: Instruction patterns + concealment detected.");
    console.log("   This is a strong indicator of intentional IDPI attack.\n");
  }
}

// Only run CLI when executed directly (not imported)
const isDirectRun = process.argv[1]?.includes("check-url");
if (isDirectRun) main();
