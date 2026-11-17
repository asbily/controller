"use strict";

import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import "./lint.mjs";

const ROOT = process.cwd();
const OUT_DIR = join(ROOT, "public");

await rm(OUT_DIR, { recursive: true, force: true });
await mkdir(OUT_DIR, { recursive: true });

// Copy strictly public frontend assets (never backend source, tests, or worker code)
await cp(join(ROOT, "index.html"), join(OUT_DIR, "index.html"));
await cp(join(ROOT, "style.css"), join(OUT_DIR, "style.css"));
await cp(join(ROOT, "script.js"), join(OUT_DIR, "script.js"));
await cp(join(ROOT, "assets"), join(OUT_DIR, "assets"), { recursive: true });
await cp(join(ROOT, "dashboard"), join(OUT_DIR, "dashboard"), { recursive: true });

console.log("Built static public/ directory for Vercel deployment.");
