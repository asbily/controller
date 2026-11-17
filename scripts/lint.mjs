"use strict";

import { readdir } from "node:fs/promises";
import { join, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const ROOT = process.cwd();
const IGNORE_DIRS = new Set(["node_modules", ".git", ".wrangler", "data", "public"]);

async function collectJsFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    if (IGNORE_DIRS.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectJsFiles(fullPath)));
    } else if (entry.isFile() && [".js", ".mjs"].includes(extname(entry.name))) {
      files.push(fullPath);
    }
  }
  return files;
}

const files = await collectJsFiles(ROOT);
let failed = false;

for (const file of files) {
  try {
    await execFileAsync(process.execPath, ["--check", file]);
  } catch (err) {
    failed = true;
    console.error(`Syntax error in ${file}:\n${err.stderr || err.message}`);
  }
}

if (failed) {
  process.exit(1);
}

console.log(`Checked ${files.length} JavaScript files with zero syntax errors.`);
