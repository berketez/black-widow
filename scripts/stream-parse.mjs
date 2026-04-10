/**
 * stream-parse.mjs -- Streaming JS parser for 200MB+ files.
 *
 * Strategy:
 *   1. Read the file line-by-line with readline
 *   2. Track brace depth to find top-level statement boundaries
 *   3. Write each top-level block to a separate file
 *   4. Optionally parse each block with Babel independently
 *
 * Usage:
 *   node stream-parse.mjs <input> <output-dir> [--parse] [--max-block-kb N]
 *
 * Output:
 *   output-dir/block_0001.js, block_0002.js, ...
 *   Stdout: JSON { total_blocks, parse_errors, stats }
 */

import { createReadStream } from "fs";
import { createInterface } from "readline";
import { mkdir, writeFile, stat } from "fs/promises";
import { join, basename } from "path";

// Optional Babel -- only if --parse flag is given
let parser = null;
let generator = null;

const args = process.argv.slice(2);
const inputFile = args[0];
const outputDir = args[1];
const shouldParse = args.includes("--parse");

const maxBlockKbIdx = args.indexOf("--max-block-kb");
const maxBlockKb = maxBlockKbIdx >= 0 ? parseInt(args[maxBlockKbIdx + 1], 10) : 512;
const maxBlockBytes = maxBlockKb * 1024;

if (!inputFile || !outputDir) {
  console.error("Usage: node stream-parse.mjs <input> <output-dir> [--parse] [--max-block-kb N]");
  process.exit(1);
}

// Lazy-load Babel only when needed
async function loadBabel() {
  if (!shouldParse) return;
  try {
    const parserModule = await import("@babel/parser");
    const generatorModule = await import("@babel/generator");
    parser = parserModule.default?.parse || parserModule.parse;
    generator = generatorModule.default?.default || generatorModule.default;
  } catch (e) {
    console.error(`[stream-parse] Babel not available: ${e.message}`);
  }
}

/**
 * Classify a line to detect top-level statement starts.
 * Returns true if this line begins a new top-level declaration.
 */
function isTopLevelStart(line, depth) {
  if (depth !== 0) return false;
  const trimmed = line.trimStart();
  if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) return false;

  // Top-level declarations
  const topLevelPatterns = [
    /^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s/,
    /^(?:export\s+)?(?:const|let|var)\s/,
    /^(?:export\s+)?class\s/,
    /^(?:export\s+)?(?:default|enum|interface|type|namespace)\s/,
    /^module\.exports\s*=/,
    /^exports\./,
    /^Object\.defineProperty\s*\(/,
    /^__webpack_require__/,
    /^\/\*\*/, // JSDoc comment start
    /^\/\*[^*]/, // Block comment start
    /^"use strict"/,
    /^'use strict'/,
  ];

  return topLevelPatterns.some(p => p.test(trimmed));
}

/**
 * Count brace changes in a line, ignoring strings and comments.
 * Returns the net change in depth.
 */
function countBraceChanges(line) {
  let delta = 0;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inTemplate = false;
  let escaped = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const prev = i > 0 ? line[i - 1] : "";

    if (escaped) {
      escaped = false;
      continue;
    }

    if (ch === "\\") {
      escaped = true;
      continue;
    }

    if (inSingleQuote) {
      if (ch === "'") inSingleQuote = false;
      continue;
    }
    if (inDoubleQuote) {
      if (ch === '"') inDoubleQuote = false;
      continue;
    }
    if (inTemplate) {
      if (ch === "`") inTemplate = false;
      continue;
    }

    // Line comment -- ignore rest of line
    if (ch === "/" && i + 1 < line.length && line[i + 1] === "/") {
      break;
    }

    if (ch === "'") { inSingleQuote = true; continue; }
    if (ch === '"') { inDoubleQuote = true; continue; }
    if (ch === "`") { inTemplate = true; continue; }

    if (ch === "{") delta++;
    if (ch === "}") delta--;
  }

  return delta;
}

async function main() {
  await loadBabel();
  await mkdir(outputDir, { recursive: true });

  const fileStats = await stat(inputFile);
  const fileSizeMB = (fileStats.size / (1024 * 1024)).toFixed(1);

  const rl = createInterface({
    input: createReadStream(inputFile, { encoding: "utf-8" }),
    crlfDelay: Infinity,
  });

  let blockIndex = 0;
  let currentBlock = [];
  let currentBlockSize = 0;
  let depth = 0;
  let totalLines = 0;
  let parseErrors = 0;
  let parsedBlocks = 0;
  let lineNumber = 0;
  let inBlockComment = false;

  const blockFiles = [];

  async function flushBlock() {
    if (currentBlock.length === 0) return;

    blockIndex++;
    const blockNum = String(blockIndex).padStart(5, "0");
    const blockFile = join(outputDir, `block_${blockNum}.js`);
    const blockContent = currentBlock.join("\n");

    await writeFile(blockFile, blockContent, "utf-8");
    blockFiles.push(blockFile);

    // Optional Babel parse for validation
    if (shouldParse && parser) {
      try {
        parser(blockContent, {
          sourceType: "module",
          plugins: ["jsx", "typescript", "decorators-legacy", "classProperties"],
          errorRecovery: true,
        });
        parsedBlocks++;
      } catch (e) {
        parseErrors++;
      }
    }

    currentBlock = [];
    currentBlockSize = 0;
  }

  for await (const line of rl) {
    lineNumber++;
    totalLines++;

    // Track block comments
    if (!inBlockComment && line.trimStart().startsWith("/*")) {
      inBlockComment = true;
    }
    if (inBlockComment && line.includes("*/")) {
      inBlockComment = false;
    }

    const braceChange = countBraceChanges(line);
    const prevDepth = depth;
    depth += braceChange;

    // Clamp depth (malformed files)
    if (depth < 0) depth = 0;

    // Detect block boundary: we're at depth 0 and this starts a new statement
    const atTopLevel = prevDepth === 0 && depth === 0 && !inBlockComment;
    const isNewStatement = isTopLevelStart(line, 0);

    if (atTopLevel && isNewStatement && currentBlock.length > 0) {
      await flushBlock();
    }

    // Force flush if block is too large (prevents memory issues)
    if (currentBlockSize > maxBlockBytes && depth === 0) {
      await flushBlock();
    }

    currentBlock.push(line);
    currentBlockSize += line.length + 1; // +1 for newline
  }

  // Flush remaining
  await flushBlock();

  const result = {
    success: true,
    input_file: basename(inputFile),
    input_size_mb: parseFloat(fileSizeMB),
    total_lines: totalLines,
    total_blocks: blockIndex,
    parse_errors: parseErrors,
    parsed_blocks: parsedBlocks,
    stats: {
      avg_block_lines: blockIndex > 0 ? Math.round(totalLines / blockIndex) : 0,
      max_block_kb: maxBlockKb,
      babel_parse: shouldParse,
    },
  };

  console.log(JSON.stringify(result));
}

main().catch(err => {
  console.log(JSON.stringify({
    success: false,
    error: err.message,
    total_blocks: 0,
    parse_errors: 0,
  }));
  process.exit(1);
});
