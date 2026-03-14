/**
 * Shared IDPI detection pattern loader.
 *
 * Loads patterns from data/patterns.json and compiles RegExp at runtime.
 * Used by check-url.ts, web-crawler.ts, and extended by OpenClaw.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Technique } from "../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const PATTERNS_PATH = path.join(PROJECT_ROOT, "data/patterns.json");

/* ── JSON schema types ── */

interface RawInstructionPattern {
  pattern: string;
  flags: string;
  name: string;
  label: string;
}

interface RawConcealmentPattern {
  pattern: string;
  flags: string;
  name: string;
  technique: string;
  label: string;
}

interface RawPatterns {
  instructions: RawInstructionPattern[];
  concealments: RawConcealmentPattern[];
  _meta?: Record<string, unknown>;
}

/* ── Compiled types (exported) ── */

export interface InstructionPattern {
  pattern: RegExp;
  name: string;
  label: string;
}

export interface ConcealmentPattern {
  pattern: RegExp;
  name: string;
  technique: Technique;
  label: string;
}

export interface LoadedPatterns {
  instructions: InstructionPattern[];
  concealments: ConcealmentPattern[];
}

/* ── Loader ── */

let cached: LoadedPatterns | null = null;

/** Load and compile patterns from data/patterns.json (cached after first call). */
export function loadPatterns(): LoadedPatterns {
  if (cached) return cached;

  const raw: RawPatterns = JSON.parse(fs.readFileSync(PATTERNS_PATH, "utf-8"));

  const instructions: InstructionPattern[] = raw.instructions.map(p => ({
    pattern: new RegExp(p.pattern, p.flags),
    name: p.name,
    label: p.label,
  }));

  const concealments: ConcealmentPattern[] = raw.concealments.map(p => ({
    pattern: new RegExp(p.pattern, p.flags),
    name: p.name,
    technique: p.technique as Technique,
    label: p.label,
  }));

  cached = { instructions, concealments };
  return cached;
}

/** Force reload (used after OpenClaw appends new patterns). */
export function reloadPatterns(): LoadedPatterns {
  cached = null;
  return loadPatterns();
}

/** Path to patterns.json (for OpenClaw to write to). */
export const PATTERNS_FILE = PATTERNS_PATH;
