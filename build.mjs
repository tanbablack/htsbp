import { build } from "esbuild";
import { readdirSync, writeFileSync, mkdirSync, rmSync } from "node:fs";

// Clean output directory to remove stale compiled files
rmSync("dist/api", { recursive: true, force: true });

const apiFiles = readdirSync("src/api")
  .filter(f => f.endsWith(".ts"))
  .map(f => `src/api/${f}`);

await build({
  entryPoints: apiFiles,
  bundle: true,
  platform: "node",
  target: "node20",
  outdir: "dist/api",
  format: "cjs",
  sourcemap: false,
});

// Ensure dist/api uses CommonJS resolution (overrides root "type": "module")
mkdirSync("dist/api", { recursive: true });
writeFileSync("dist/api/package.json", '{"type": "commonjs"}\n');

console.log(`Built ${apiFiles.length} functions to dist/api/`);
