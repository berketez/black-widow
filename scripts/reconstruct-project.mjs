/**
 * reconstruct-project.mjs -- Transform deobfuscated modules into a real project structure.
 *
 * Input:  Directory of module files (module_0001.js, module_0002.js, ...)
 * Output: Directory with organized src/ structure
 *
 * Usage:
 *   node reconstruct-project.mjs <modules-dir> <output-dir> [--target-name NAME]
 *
 * Strategy:
 *   1. Analyze each module: exports, imports, content patterns
 *   2. Categorize into folders (src/tools/, src/api/, src/mcp/, etc.)
 *   3. Generate meaningful filenames from export names
 *   4. Rewrite import/require paths to match new structure
 *   5. Create index.js files for each folder
 *   6. Split large files (>500 lines), merge tiny files (<10 lines)
 *
 * Stdout: JSON with stats
 */

import { readdir, readFile, writeFile, mkdir, stat } from "fs/promises";
import { join, basename, dirname, relative, extname } from "path";
import { existsSync } from "fs";

const args = process.argv.slice(2);
const modulesDir = args[0];
const outputDir = args[1];
const targetNameIdx = args.indexOf("--target-name");
const targetName = targetNameIdx >= 0 ? args[targetNameIdx + 1] : "reconstructed";

if (!modulesDir || !outputDir) {
  console.error("Usage: node reconstruct-project.mjs <modules-dir> <output-dir> [--target-name NAME]");
  process.exit(1);
}

// -----------------------------------------------------------------------
// Category detection patterns
// -----------------------------------------------------------------------

const CATEGORY_PATTERNS = [
  // UI/Rendering
  { folder: "src/components", patterns: [
    /React\.createElement/i, /jsx|JSX/, /render\s*\(/, /Component\s*\{/,
    /\.tsx?$/, /createPortal/, /forwardRef/,
  ]},
  { folder: "src/hooks", patterns: [
    /^(?:export\s+)?(?:function\s+)?use[A-Z]/m,
    /return\s*\[.*useState/,
    /useEffect|useCallback|useMemo|useRef|useReducer|useContext/,
  ]},
  { folder: "src/ui", patterns: [
    /Render|Display|Terminal|Prompt|Spinner|Progress|Ink/i,
    /chalk\.|ansi|color|style/i,
    /blessed|inquirer|ora|listr/i,
  ]},

  // Architecture
  { folder: "src/tools", patterns: [
    /Tool|BashTool|ReadTool|WriteTool|EditTool|GlobTool|GrepTool/,
    /toolExecution|executeToolUse|runTool/i,
    /ToolResult|ToolInput|toolName/,
  ]},
  { folder: "src/mcp", patterns: [
    /MCP|McpServer|McpClient|McpSession|Protocol/,
    /ModelContextProtocol|mcp_/i,
    /createMcpSession|mcpTransport/i,
  ]},
  { folder: "src/cli", patterns: [
    /CLI|Command|argv|commander|yargs|meow/i,
    /process\.argv/,
    /parseArgs|getopt|flags/i,
    /subcommand|--\w+/,
  ]},
  { folder: "src/api", patterns: [
    /fetch\s*\(/, /axios\.\w+\s*\(/, /XMLHttpRequest/,
    /\.get\s*\(\s*['"/]/, /\.post\s*\(\s*['"/]/,
    /baseURL|endpoint|api[_-]?url/i,
    /http\.request|https\.request/,
  ]},
  { folder: "src/server", patterns: [
    /createServer|express\(\)|app\.listen/,
    /router\.|middleware|req\s*,\s*res/,
    /koa|fastify|hapi/i,
  ]},

  // Data
  { folder: "src/database", patterns: [
    /SQL|query|database|mongo|postgres|mysql|sqlite/i,
    /knex|sequelize|typeorm|prisma|mongoose/i,
    /\.query\s*\(|\.execute\s*\(/,
  ]},
  { folder: "src/streams", patterns: [
    /Stream|Buffer|Pipe|Transform|Readable|Writable/,
    /\.pipe\s*\(/, /createReadStream|createWriteStream/,
    /highWaterMark|objectMode/,
  ]},

  // Security
  { folder: "src/crypto", patterns: [
    /encrypt|decrypt|hash|sign|verify|cipher/i,
    /crypto\.|createHash|createHmac|randomBytes/,
    /bcrypt|argon|scrypt|pbkdf/i,
    /AES|RSA|SHA|HMAC/,
  ]},
  { folder: "src/auth", patterns: [
    /Auth|Token|Session|Permission|OAuth|JWT/i,
    /login|logout|signin|signup|authenticate/i,
    /bearer|cookie|csrf|cors/i,
  ]},

  // Infrastructure
  { folder: "src/events", patterns: [
    /\.on\s*\(\s*['"]/, /EventEmitter|addEventListener/,
    /\.emit\s*\(/, /removeListener|off\s*\(/,
    /observer|subscribe|publish|dispatch/i,
  ]},
  { folder: "src/config", patterns: [
    /Config|Settings|Options|Preferences/,
    /process\.env/, /\.env\b/,
    /defaults?\s*=\s*\{/, /loadConfig|readConfig/i,
  ]},
  { folder: "src/logging", patterns: [
    /Logger|log\.|debug\.|warn\.|error\./,
    /winston|pino|bunyan|morgan/i,
    /logLevel|LOG_LEVEL|verbose/i,
  ]},
  { folder: "src/errors", patterns: [
    /Error\s*\{|extends\s+Error/,
    /throw\s+new\s+\w*Error/,
    /ErrorHandler|errorBoundary|onError/i,
  ]},

  // Utilities
  { folder: "src/utils", patterns: [
    /parse|serialize|validate|sanitize/i,
    /format|transform|convert/i,
    /helper|utility|misc/i,
  ]},
  { folder: "tests", patterns: [
    /describe\s*\(|it\s*\(|test\s*\(/,
    /expect\s*\(|assert\.|should\./,
    /jest|mocha|chai|vitest/i,
    /beforeEach|afterEach|beforeAll/,
  ]},
];

// -----------------------------------------------------------------------
// Module analysis
// -----------------------------------------------------------------------

/**
 * Extract the primary export name from module content.
 */
function extractExportName(content) {
  // export default class X
  let match = content.match(/export\s+default\s+class\s+(\w+)/);
  if (match) return match[1];

  // export default function X
  match = content.match(/export\s+default\s+function\s+(\w+)/);
  if (match) return match[1];

  // module.exports = X (where X is capitalized identifier)
  match = content.match(/module\.exports\s*=\s*([A-Z]\w+)/);
  if (match) return match[1];

  // exports.X = (not __esModule, not default)
  match = content.match(/exports\.([A-Z]\w+)\s*=/);
  if (match && match[1] !== "__esModule") return match[1];

  // class X { or class X extends Y {
  match = content.match(/class\s+([A-Z]\w+)/);
  if (match) return match[1];

  // function X( (capitalized)
  match = content.match(/function\s+([A-Z]\w+)\s*\(/);
  if (match) return match[1];

  // const X = ... (capitalized)
  match = content.match(/(?:const|var|let)\s+([A-Z]\w+)\s*=/);
  if (match) return match[1];

  // function x( (lowercase, but meaningful)
  match = content.match(/function\s+(\w{3,})\s*\(/);
  if (match) return match[1];

  // const x = function or const x = (
  match = content.match(/(?:const|var|let)\s+(\w{3,})\s*=\s*(?:async\s+)?(?:function|\()/);
  if (match) return match[1];

  return null;
}

/**
 * Extract module ID from filename.
 */
function extractModuleId(filename) {
  const match = filename.match(/module[_-]?(\w+)/);
  return match ? match[1] : basename(filename, extname(filename));
}

/**
 * Extract require/import references from content.
 * Returns array of { raw, moduleId } objects.
 */
function extractImports(content) {
  const imports = [];
  const patterns = [
    /require\s*\(\s*["']([^"']+)["']\s*\)/g,
    /(?:import|from)\s+["']([^"']+)["']/g,
    /import\s*\(\s*["']([^"']+)["']\s*\)/g,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const raw = match[1];
      // Extract module ID from relative paths like ./module_42 or ./42
      const idMatch = raw.match(/\.\/(?:module[_-]?)?(\d+)(?:\.js)?$/);
      if (idMatch) {
        imports.push({ raw, moduleId: idMatch[1] });
      } else {
        imports.push({ raw, moduleId: null });
      }
    }
  }

  return imports;
}

/**
 * Categorize a module based on content patterns.
 */
function categorizeModule(content) {
  const scores = {};

  for (const category of CATEGORY_PATTERNS) {
    let score = 0;
    for (const pattern of category.patterns) {
      if (pattern.test(content)) {
        score++;
      }
    }
    if (score > 0) {
      scores[category.folder] = score;
    }
  }

  if (Object.keys(scores).length === 0) {
    return "src/lib";
  }

  // Return the category with the highest score
  return Object.entries(scores).sort((a, b) => b[1] - a[1])[0][0];
}

/**
 * Convert a name to kebab-case filename.
 * UserManager -> user-manager
 * handleToolExecution -> handle-tool-execution
 */
function toKebabCase(name) {
  if (!name) return null;
  return name
    .replace(/([a-z])([A-Z])/g, "$1-$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1-$2")
    .replace(/[_\s]+/g, "-")
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "");
}

/**
 * Generate a meaningful filename for a module.
 */
function generateFilename(exportName, moduleId, content) {
  if (exportName) {
    const kebab = toKebabCase(exportName);
    if (kebab && kebab.length >= 2) return kebab;
  }

  // Try to extract a meaningful name from content
  const funcMatch = content.match(/function\s+(\w{4,})\s*\(/);
  if (funcMatch) {
    const kebab = toKebabCase(funcMatch[1]);
    if (kebab && kebab.length >= 2) return kebab;
  }

  // Fallback to module ID
  return `module-${moduleId}`;
}

// -----------------------------------------------------------------------
// File operations
// -----------------------------------------------------------------------

/**
 * Split a file that's over maxLines into multiple files.
 * Splits at function boundaries.
 */
function splitLargeContent(content, maxLines = 500) {
  const lines = content.split("\n");
  if (lines.length <= maxLines) return [content];

  const chunks = [];
  let currentChunk = [];
  let depth = 0;

  for (const line of lines) {
    const braceOpen = (line.match(/{/g) || []).length;
    const braceClose = (line.match(/}/g) || []).length;
    depth += braceOpen - braceClose;

    currentChunk.push(line);

    // Split at top-level boundaries when chunk is big enough
    if (depth <= 0 && currentChunk.length >= maxLines * 0.7) {
      chunks.push(currentChunk.join("\n"));
      currentChunk = [];
      depth = 0;
    }
  }

  if (currentChunk.length > 0) {
    chunks.push(currentChunk.join("\n"));
  }

  return chunks;
}

/**
 * Merge tiny modules (< minLines) in the same category.
 */
function mergeTinyModules(modules, minLines = 10) {
  const merged = [];
  const tinyByCategory = {};

  for (const mod of modules) {
    const lineCount = mod.content.split("\n").length;
    if (lineCount < minLines) {
      if (!tinyByCategory[mod.category]) {
        tinyByCategory[mod.category] = [];
      }
      tinyByCategory[mod.category].push(mod);
    } else {
      merged.push(mod);
    }
  }

  // Merge tiny modules per category
  for (const [category, tinyMods] of Object.entries(tinyByCategory)) {
    if (tinyMods.length <= 1) {
      merged.push(...tinyMods);
      continue;
    }

    // Group into chunks of ~20 tiny modules
    for (let i = 0; i < tinyMods.length; i += 20) {
      const group = tinyMods.slice(i, i + 20);
      const combinedContent = group.map(m => {
        return `// --- Originally: ${m.originalFile} (${m.exportName || m.moduleId}) ---\n${m.content}`;
      }).join("\n\n");

      merged.push({
        ...group[0],
        content: combinedContent,
        filename: `${basename(category)}-utils-${Math.floor(i / 20) + 1}`,
        mergedFrom: group.map(m => m.moduleId),
      });
    }
  }

  return merged;
}

// -----------------------------------------------------------------------
// Import rewriting
// -----------------------------------------------------------------------

/**
 * Rewrite module ID references to real file paths.
 */
function rewriteImports(content, moduleMap, currentFilePath) {
  let result = content;

  // Replace require('./module_42') or require('./42') with real paths
  result = result.replace(
    /require\s*\(\s*["'](\.\/(?:module[_-]?)?\d+(?:\.js)?)["']\s*\)/g,
    (match, raw) => {
      const idMatch = raw.match(/(\d+)/);
      if (idMatch && moduleMap[idMatch[1]]) {
        const targetPath = moduleMap[idMatch[1]];
        let relativePath = relative(dirname(currentFilePath), targetPath);
        if (!relativePath.startsWith(".")) relativePath = "./" + relativePath;
        // Remove .js extension for cleaner imports
        relativePath = relativePath.replace(/\.js$/, "");
        return `require("${relativePath}")`;
      }
      return match;
    }
  );

  return result;
}

// -----------------------------------------------------------------------
// Index file generation
// -----------------------------------------------------------------------

/**
 * Generate index.js for a directory (re-exports).
 */
function generateIndexContent(files, dirPath) {
  const lines = [
    "/**",
    ` * Auto-generated index - Karadul v1.0 Reconstruction`,
    ` */`,
    "",
  ];

  for (const file of files.sort()) {
    const name = basename(file, ".js");
    // Convert kebab-case to valid JS identifier (camelCase)
    let varName = name
      .replace(/^[^a-zA-Z_$]/, "_") // Ensure starts with valid char
      .replace(/-([a-zA-Z])/g, (_, c) => c.toUpperCase()) // kebab -> camel
      .replace(/[^a-zA-Z0-9_$]/g, "_"); // Replace invalid chars
    // Ensure not empty
    if (!varName) varName = "_module";
    lines.push(`exports["${name}"] = require("./${name}");`);
  }

  lines.push("");
  return lines.join("\n");
}

// -----------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------

async function main() {
  // Ensure output directory
  await mkdir(outputDir, { recursive: true });
  await mkdir(join(outputDir, "src"), { recursive: true });

  // Read all module files
  let files;
  try {
    files = await readdir(modulesDir);
  } catch (e) {
    console.log(JSON.stringify({
      success: false,
      error: `Cannot read modules directory: ${e.message}`,
    }));
    process.exit(1);
  }

  const moduleFiles = files
    .filter(f => f.endsWith(".js"))
    .sort();

  if (moduleFiles.length === 0) {
    // Try modules/ subdirectory
    const subDir = join(modulesDir, "modules");
    if (existsSync(subDir)) {
      const subFiles = await readdir(subDir);
      moduleFiles.push(...subFiles.filter(f => f.endsWith(".js")).sort());
      // Update source dir
      // We'll handle this in the loop
    }
  }

  if (moduleFiles.length === 0) {
    console.log(JSON.stringify({
      success: false,
      error: "No .js module files found",
      total_modules: 0,
    }));
    process.exit(0);
  }

  // Phase 1: Analyze all modules
  const modules = [];
  const errors = [];
  const categoryStats = {};

  for (const filename of moduleFiles) {
    let filePath = join(modulesDir, filename);
    if (!existsSync(filePath)) {
      filePath = join(modulesDir, "modules", filename);
    }

    try {
      const content = await readFile(filePath, "utf-8");
      const moduleId = extractModuleId(filename);
      const exportName = extractExportName(content);
      const category = categorizeModule(content);
      const imports = extractImports(content);
      const lineCount = content.split("\n").length;

      const generatedName = generateFilename(exportName, moduleId, content);

      modules.push({
        originalFile: filename,
        moduleId,
        exportName,
        category,
        filename: generatedName,
        imports,
        content,
        lineCount,
        filePath: null, // Set after writing
      });

      categoryStats[category] = (categoryStats[category] || 0) + 1;
    } catch (e) {
      errors.push(`Failed to read ${filename}: ${e.message}`);
    }
  }

  // Phase 2: Merge tiny modules, split large ones
  let processedModules = mergeTinyModules(modules);
  const splitModules = [];

  for (const mod of processedModules) {
    const chunks = splitLargeContent(mod.content, 500);
    if (chunks.length === 1) {
      splitModules.push(mod);
    } else {
      for (let i = 0; i < chunks.length; i++) {
        splitModules.push({
          ...mod,
          content: chunks[i],
          filename: `${mod.filename}-part${i + 1}`,
          splitFrom: mod.filename,
          lineCount: chunks[i].split("\n").length,
        });
      }
    }
  }

  processedModules = splitModules;

  // Phase 3: Write files and build module map
  const moduleMap = {}; // moduleId -> output file path
  const dirFiles = {}; // directory -> [filenames]
  const usedFilenames = new Set();

  for (const mod of processedModules) {
    // Create category directory
    const catDir = join(outputDir, mod.category);
    await mkdir(catDir, { recursive: true });

    // Handle filename conflicts
    let finalName = mod.filename;
    let counter = 2;
    while (usedFilenames.has(join(mod.category, finalName))) {
      finalName = `${mod.filename}-${counter}`;
      counter++;
    }
    usedFilenames.add(join(mod.category, finalName));

    const outPath = join(catDir, `${finalName}.js`);
    mod.filePath = outPath;

    // Map module ID to output path
    if (mod.moduleId) {
      moduleMap[mod.moduleId] = outPath;
    }
    if (mod.mergedFrom) {
      for (const id of mod.mergedFrom) {
        moduleMap[id] = outPath;
      }
    }

    // Track files per directory
    if (!dirFiles[mod.category]) dirFiles[mod.category] = [];
    dirFiles[mod.category].push(`${finalName}.js`);
  }

  // Phase 4: Rewrite imports and write files
  let filesWritten = 0;
  for (const mod of processedModules) {
    // Add header comment
    const header = [
      "/**",
      ` * ${mod.exportName || mod.filename}`,
      ` * Category: ${mod.category}`,
      ` * Reconstructed by Karadul v1.0`,
      mod.splitFrom ? ` * Split from: ${mod.splitFrom}` : null,
      mod.mergedFrom ? ` * Merged from: ${mod.mergedFrom.length} modules` : null,
      ` * Original: ${mod.originalFile}`,
      " */",
      "",
    ].filter(Boolean).join("\n");

    // Rewrite imports
    const rewritten = rewriteImports(mod.content, moduleMap, mod.filePath);

    try {
      await writeFile(mod.filePath, header + rewritten, "utf-8");
      filesWritten++;
    } catch (e) {
      errors.push(`Failed to write ${mod.filePath}: ${e.message}`);
    }
  }

  // Phase 5: Generate index files
  for (const [dir, files] of Object.entries(dirFiles)) {
    const dirPath = join(outputDir, dir);
    const indexContent = generateIndexContent(files, dirPath);
    try {
      await writeFile(join(dirPath, "index.js"), indexContent, "utf-8");
    } catch (e) {
      errors.push(`Failed to write index for ${dir}: ${e.message}`);
    }
  }

  // Phase 6: Generate main entry point
  const mainEntryLines = [
    "/**",
    ` * ${targetName} - Main Entry Point`,
    " * Reconstructed by Karadul v1.0",
    " */",
    "",
    '"use strict";',
    "",
  ];

  for (const dir of Object.keys(dirFiles).sort()) {
    const varName = basename(dir).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    mainEntryLines.push(`// ${dir}`);
    mainEntryLines.push(`// const ${varName} = require("./${dir}");`);
    mainEntryLines.push("");
  }

  mainEntryLines.push('console.log("Reconstructed project ready.");');
  mainEntryLines.push("");

  const srcIndex = join(outputDir, "src", "index.js");
  await writeFile(srcIndex, mainEntryLines.join("\n"), "utf-8");

  // Result
  const result = {
    success: true,
    total_modules: moduleFiles.length,
    files_written: filesWritten,
    categories: categoryStats,
    module_map_size: Object.keys(moduleMap).length,
    merged_count: processedModules.filter(m => m.mergedFrom).length,
    split_count: processedModules.filter(m => m.splitFrom).length,
    errors,
    stats: {
      avg_lines: Math.round(
        processedModules.reduce((sum, m) => sum + m.lineCount, 0) / Math.max(processedModules.length, 1)
      ),
      directories: Object.keys(dirFiles).length,
    },
  };

  console.log(JSON.stringify(result));
}

main().catch(err => {
  console.log(JSON.stringify({
    success: false,
    error: err.message,
    total_modules: 0,
    files_written: 0,
  }));
  process.exit(1);
});
