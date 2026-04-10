#!/usr/bin/env node
/**
 * smart-webpack-unpack.mjs -- Gercek Webpack/esbuild Module Extraction
 *
 * Claude Code CLI gibi esbuild bundle'larini tanimlayabilen akilli module splitter.
 *
 * Desteklenen bundle formatlari:
 *   1. esbuild CJS wrapper: var X = U((exports, module) => { ... })
 *   2. esbuild ESM interop:  var Y = Q1(X)
 *   3. esbuild re-export:    lb(target, { name: () => ref })
 *   4. Webpack IIFE object:  (function(modules) { ... })({ 0: function(e,t,n){}, ... })
 *   5. Webpack IIFE array:   [function(e,t,n){}, ...]
 *   6. Webpack 5 named:      __webpack_modules__ = { "./src/file.js": ... }
 *   7. Top-level IIFE:       (function() { ... })() -- kapsayici IIFE'leri ayir
 *
 * Kullanim:
 *   node --max-old-space-size=8192 smart-webpack-unpack.mjs <input> <output-dir>
 *
 * Cikti:
 *   output-dir/modules/       -- Her modul ayri dosya
 *   output-dir/dependency_graph.json
 *   stdout: JSON stats
 */

import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";
import { createRequire } from "node:module";

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

// js-beautify lazy-load -- pre-beautify fallback icin
const _require = createRequire(import.meta.url);
let jsBeautify = null;
function loadBeautify() {
  try { jsBeautify = _require("js-beautify"); return true; } catch { return false; }
}

// ---------- CLI ----------
const args = process.argv.slice(2);

if (args.length < 2) {
  emit({ success: false, errors: ["Kullanim: node smart-webpack-unpack.mjs <input> <output-dir>"] });
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputDir = resolve(args[1]);
const modulesDir = join(outputDir, "modules");

// ---------- Read ----------
let source, fileSize;
try {
  fileSize = statSync(inputPath).size;
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  emit({ success: false, errors: [`Dosya okunamadi: ${err.message}`] });
  process.exit(1);
}

try {
  mkdirSync(modulesDir, { recursive: true });
} catch (err) {
  emit({ success: false, errors: [`Cikti dizini olusturulamadi: ${err.message}`] });
  process.exit(1);
}

// ---------- Parse ----------
const errors = [];
let ast;
try {
  ast = parse(source, {
    sourceType: "unambiguous",
    allowImportExportEverywhere: true,
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowUndeclaredExports: true,
    errorRecovery: true,
    plugins: [
      "jsx", "typescript", "decorators-legacy", "classProperties",
      "classPrivateProperties", "classPrivateMethods", "dynamicImport",
      "optionalChaining", "nullishCoalescingOperator", "exportDefaultFrom",
      "exportNamespaceFrom", "topLevelAwait", "importMeta",
    ],
  });
  if (ast.errors?.length > 0) {
    for (const e of ast.errors.slice(0, 20)) {
      errors.push(`Parse recovered: ${e.message}`);
    }
  }
} catch (babelErr) {
  // Babel parse basarisiz -- pre-beautify ile tekrar dene
  errors.push(`Babel parse basarisiz: ${babelErr.message}`);

  let retrySuccess = false;
  if (loadBeautify()) {
    try {
      const beautified = jsBeautify.js_beautify(source, {
        indent_size: 2, indent_char: " ", max_preserve_newlines: 2,
        preserve_newlines: true, brace_style: "collapse,preserve-inline",
        wrap_line_length: 120,
      });
      ast = parse(beautified, {
        sourceType: "unambiguous",
        allowImportExportEverywhere: true,
        allowReturnOutsideFunction: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true,
        errorRecovery: true,
        plugins: [
          "jsx", "typescript", "decorators-legacy", "classProperties",
          "classPrivateProperties", "classPrivateMethods", "dynamicImport",
          "optionalChaining", "nullishCoalescingOperator", "exportDefaultFrom",
          "exportNamespaceFrom", "topLevelAwait", "importMeta",
        ],
      });
      // parse basarili oldu ama beautified kaynak uzerinde calisiyor,
      // bu yuzden generate edilen kod beautified olacak (sorun degil)
      source = beautified;
      errors.push("Pre-beautify + Babel retry basarili");
      retrySuccess = true;
    } catch (retryErr) {
      errors.push(`Pre-beautify retry de basarisiz: ${retryErr.message}`);
    }
  }

  if (!retrySuccess) {
    // Son care: regex-based webpack module ID extraction
    const regexModuleIds = [];
    // __webpack_require__(12345) pattern
    const wpReqRe = /__webpack_require__\(\s*(\d+|"[^"]+"|'[^']+')\s*\)/g;
    let m;
    while ((m = wpReqRe.exec(source)) !== null) {
      let id = m[1];
      if (id.startsWith('"') || id.startsWith("'")) id = id.slice(1, -1);
      else id = parseInt(id, 10);
      if (!regexModuleIds.includes(id)) regexModuleIds.push(id);
    }
    emit({
      success: false,
      bundle_format: "unknown",
      total_modules: 0,
      helpers_detected: {},
      modules: [],
      file_size: fileSize,
      regex_module_ids: regexModuleIds.length,
      errors,
    });
    process.exit(0);
  }
}

// ---------- Module Detection ----------
// moduleId -> { node, type, name, deps, exports, requireAlias }
const detectedModules = new Map();
let bundleFormat = "unknown";

// esbuild pattern detection
// Once U(), Q1(), lb(), X1() gibi helper fonksiyonlari tespit et
let cjsWrapperName = null;     // U
let esmInteropName = null;     // Q1
let reExportName = null;       // lb
let requireAliasName = null;   // X1
let requireAliasInit = null;   // FJ1 gibi lazy init wrapper

try {
  traverse(ast, {
    noScope: true,

    // esbuild helper tespiti: var U = (A, B) => () => (B || A((B={exports:{}}).exports, B), B.exports)
    VariableDeclarator(path) {
      const id = path.node.id;
      const init = path.node.init;
      if (!t.isIdentifier(id) || !init) return;

      // createRequire pattern: var X1 = createRequire(import.meta.url) veya wnB(import.meta.url)
      if (t.isCallExpression(init)) {
        const callee = init.callee;
        // require alias: createRequire veya kisa isim ile cagirilmis
        if (init.arguments.length === 1) {
          const arg = init.arguments[0];
          // import.meta.url pattern
          if (t.isMemberExpression(arg) && t.isMetaProperty(arg.object)) {
            requireAliasName = id.name;
          }
        }
      }

      // CJS wrapper: var U = (A, B) => () => (B || A(...), B.exports)
      if (
        t.isArrowFunctionExpression(init) &&
        init.params.length === 2 &&
        init.body
      ) {
        const bodyCode = safeGenerate(init.body);
        if (bodyCode.includes(".exports") && bodyCode.includes("exports:{}")) {
          cjsWrapperName = id.name;
        }
      }

      // ESM interop: var Q1 = (A, B, Q) => { ... defineProperty ... default ... }
      if (
        t.isArrowFunctionExpression(init) &&
        init.params.length >= 2
      ) {
        const bodyCode = safeGenerate(init.body);
        if (bodyCode.includes("__esModule") || (bodyCode.includes("default") && bodyCode.includes("enumerable"))) {
          esmInteropName = id.name;
        }
      }

      // Re-export helper: var lb = (A, B) => { for (var Q in B) defineProperty(A, Q, ...) }
      if (
        t.isArrowFunctionExpression(init) &&
        init.params.length === 2
      ) {
        const bodyCode = safeGenerate(init.body);
        if (bodyCode.includes("enumerable") && bodyCode.includes("configurable") && bodyCode.includes("get:")) {
          reExportName = id.name;
        }
      }

      // Lazy init wrapper: var FJ1 = (A, B) => () => (A && (B = A(A = 0)), B)
      if (
        t.isArrowFunctionExpression(init) &&
        init.params.length === 2
      ) {
        const bodyCode = safeGenerate(init.body);
        if (bodyCode.includes("A=0") || bodyCode.includes("A = 0")) {
          requireAliasInit = id.name;
        }
      }
    },
  });
} catch (err) {
  errors.push(`Helper detection hata: ${err.message}`);
}

// Ana module extraction
try {
  traverse(ast, {
    noScope: true,

    VariableDeclarator(path) {
      const id = path.node.id;
      const init = path.node.init;
      if (!t.isIdentifier(id) || !init) return;

      // Pattern 1: esbuild CJS wrapper -- var ModuleName = U((exports, module) => { ... })
      if (
        cjsWrapperName &&
        t.isCallExpression(init) &&
        t.isIdentifier(init.callee) &&
        init.callee.name === cjsWrapperName &&
        init.arguments.length === 1 &&
        (t.isArrowFunctionExpression(init.arguments[0]) ||
         t.isFunctionExpression(init.arguments[0]))
      ) {
        const factory = init.arguments[0];
        const moduleId = id.name;
        const moduleName = inferModuleName(factory, moduleId);

        detectedModules.set(moduleId, {
          node: factory,
          type: "esbuild_cjs",
          name: moduleName,
          deps: new Set(),
          exports: [],
          varName: moduleId,
        });

        if (bundleFormat === "unknown") bundleFormat = "esbuild";
      }

      // Pattern 2: esbuild ESM interop -- var Y = Q1(X)
      if (
        esmInteropName &&
        t.isCallExpression(init) &&
        t.isIdentifier(init.callee) &&
        init.callee.name === esmInteropName &&
        init.arguments.length >= 1
      ) {
        const firstArg = init.arguments[0];
        if (t.isIdentifier(firstArg)) {
          // X -> Y mapping (CJS -> ESM wrapper)
          const sourceModule = firstArg.name;
          if (detectedModules.has(sourceModule)) {
            const mod = detectedModules.get(sourceModule);
            mod.esmAlias = id.name;
          }
        }
      }
    },

    // Pattern 3: Webpack IIFE object/array
    CallExpression(path) {
      const node = path.node;
      const callee = node.callee;

      // IIFE pattern
      const isIIFE =
        t.isFunctionExpression(callee) ||
        t.isArrowFunctionExpression(callee);

      if (!isIIFE) return;

      for (const arg of node.arguments) {
        if (t.isObjectExpression(arg)) {
          extractWebpackObjectModules(arg);
        } else if (t.isArrayExpression(arg)) {
          extractWebpackArrayModules(arg);
        }
      }
    },

    // Pattern 4: __webpack_modules__ assignment
    AssignmentExpression(path) {
      const node = path.node;
      if (
        t.isIdentifier(node.left) &&
        node.left.name === "__webpack_modules__" &&
        t.isObjectExpression(node.right)
      ) {
        extractWebpackObjectModules(node.right);
      }
    },
  });
} catch (err) {
  errors.push(`Module detection hata: ${err.message}`);
}

// Re-export bilgilerini topla
if (reExportName) {
  try {
    traverse(ast, {
      noScope: true,
      CallExpression(path) {
        const node = path.node;
        if (
          t.isIdentifier(node.callee) &&
          node.callee.name === reExportName &&
          node.arguments.length >= 2
        ) {
          const target = node.arguments[0];
          const exports = node.arguments[1];

          if (t.isIdentifier(target) && t.isObjectExpression(exports)) {
            const modId = target.name;
            for (const prop of exports.properties) {
              if (t.isObjectProperty(prop) && t.isIdentifier(prop.key)) {
                if (detectedModules.has(modId)) {
                  detectedModules.get(modId).exports.push(prop.key.name);
                }
              }
            }
          }
        }
      },
    });
  } catch (err) {
    errors.push(`Re-export detection hata: ${err.message}`);
  }
}

// ---------- Node.js Built-in Modules ----------
const NODE_BUILTINS = new Set([
  "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
  "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
  "events", "fs", "http", "http2", "https", "inspector", "module", "net",
  "os", "path", "perf_hooks", "process", "punycode", "querystring",
  "readline", "repl", "stream", "string_decoder", "sys", "timers",
  "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
  "worker_threads", "zlib",
]);

// npm paket adi temizleme: "node:fs" -> "fs", "@scope/pkg/sub" -> "@scope/pkg"
function normalizePackageName(raw) {
  let name = raw;
  // "node:" prefix'ini kaldir
  if (name.startsWith("node:")) name = name.slice(5);
  // Scoped paket: @scope/pkg/sub -> @scope/pkg
  if (name.startsWith("@")) {
    const parts = name.split("/");
    if (parts.length >= 2) name = parts[0] + "/" + parts[1];
  } else {
    // Normal paket: pkg/sub -> pkg
    name = name.split("/")[0];
  }
  return name;
}

// Bilinen npm paketleri icin kisa isim haritasi
const NPM_DISPLAY_NAMES = {
  "@aws-sdk": "aws_sdk",
  "@smithy": "smithy",
  "@aws-crypto": "aws_crypto",
  "@grpc/grpc-js": "grpc_js",
  "@grpc/proto-loader": "grpc_proto_loader",
  "@sentry/node": "sentry_node",
  "@sentry/core": "sentry_core",
  "@anthropic-ai/sdk": "anthropic_sdk",
  "tree-sitter": "tree_sitter",
  "node-fetch": "node_fetch",
  "form-data": "form_data",
  "graceful-fs": "graceful_fs",
  "delayed-stream": "delayed_stream",
  "proxy-agent": "proxy_agent",
  "highlight.js": "hljs",
};

// moduleId -> npm package name
const moduleIdPackageMap = new Map();

// Dependency analizi + npm paket ismi cikarma
for (const [moduleId, modInfo] of detectedModules.entries()) {
  try {
    const bodyCode = safeGenerate(modInfo.node);

    // require() cagilarini bul ve npm paket ismi cikar
    if (requireAliasName) {
      const reqPattern = new RegExp(`${escapeRegex(requireAliasName)}\\("([^"]+)"\\)`, "g");
      let match;
      while ((match = reqPattern.exec(bodyCode)) !== null) {
        modInfo.deps.add(match[1]);
      }
    }

    // Normal require("paket") cagilarini tara
    const requireRegex = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
    let reqMatch;
    while ((reqMatch = requireRegex.exec(bodyCode)) !== null) {
      const rawPkg = reqMatch[1];
      const pkgName = normalizePackageName(rawPkg);

      // Node.js built-in modulu mu?
      if (NODE_BUILTINS.has(pkgName)) {
        if (!modInfo.npmPackage) {
          // Modul kendi basina bir node built-in wrapper ise
          // (sadece require + re-export yapiyorsa)
          if (bodyCode.length < 500) {
            modInfo.npmPackage = pkgName;
            modInfo.name = cleanName(moduleId, `node_${pkgName}`);
          }
        }
        modInfo.requireDeps = modInfo.requireDeps || [];
        modInfo.requireDeps.push(rawPkg);
      }
      // npm paketinden mi geliyor (relative path degilse)?
      else if (!rawPkg.startsWith(".") && !rawPkg.startsWith("/")) {
        modInfo.npmPackage = modInfo.npmPackage || pkgName;
        modInfo.requireDeps = modInfo.requireDeps || [];
        modInfo.requireDeps.push(rawPkg);
      }
    }

    // Icerik pattern'lerinden npm paket tespiti (string literal analizi)
    if (!modInfo.npmPackage) {
      // Bilinen paket string'leri
      if (bodyCode.includes("@aws-sdk/") || bodyCode.includes("@aws-crypto/")) {
        modInfo.npmPackage = "@aws-sdk";
      } else if (bodyCode.includes("@grpc/grpc-js") || (bodyCode.includes("grpc") && bodyCode.includes("ServiceClient"))) {
        modInfo.npmPackage = "@grpc/grpc-js";
      } else if (bodyCode.includes("@sentry/")) {
        modInfo.npmPackage = "@sentry/node";
      } else if (bodyCode.includes("@anthropic-ai/sdk") || bodyCode.includes("anthropic")) {
        // Sadece anthropic SDK referansi olanlar, "anthropic" string'i cok generic
        if (bodyCode.includes("@anthropic-ai/sdk") || bodyCode.includes("AnthropicError")) {
          modInfo.npmPackage = "@anthropic-ai/sdk";
        }
      } else if (bodyCode.includes("semver") && bodyCode.includes("SemVer")) {
        modInfo.npmPackage = "semver";
      } else if (bodyCode.includes("highlight") && (bodyCode.includes("case_insensitive") || bodyCode.includes("HLJS"))) {
        modInfo.npmPackage = "highlight.js";
      } else if (bodyCode.includes("protobuf") && bodyCode.includes("Type")) {
        modInfo.npmPackage = "protobufjs";
      } else if (bodyCode.includes("tree-sitter") || bodyCode.includes("TreeSitter")) {
        modInfo.npmPackage = "tree-sitter";
      }
    }

    // npm paket ismi bulunduysa kaydet
    if (modInfo.npmPackage) {
      moduleIdPackageMap.set(moduleId, modInfo.npmPackage);
      // Daha anlamli isim ver
      const displayName = NPM_DISPLAY_NAMES[modInfo.npmPackage] || sanitizeFileName(modInfo.npmPackage);
      if (modInfo.name === `module_${moduleId}` || modInfo.name === moduleId) {
        modInfo.name = cleanName(moduleId, `${displayName}_${moduleId}`);
      }
    }

    // Diger module referanslari
    for (const [otherId, otherInfo] of detectedModules.entries()) {
      if (otherId === moduleId) continue;
      if (bodyCode.includes(otherId + "(") || bodyCode.includes(otherId + ".")) {
        modInfo.deps.add(otherId);
      }
    }
  } catch (err) {
    errors.push(`Module ${moduleId} dependency hata: ${err.message}`);
  }
}

// ---------- Module Naming ----------
// Fonksiyon iceriginden anlamli isim cikar
function inferModuleName(factoryNode, varName) {
  const bodyCode = safeGenerate(factoryNode, 3000);

  // React pattern
  if (bodyCode.includes("createElement") && bodyCode.includes("Component")) return cleanName(varName, "react_module");
  if (bodyCode.includes("React.Fragment") || bodyCode.includes("jsx")) return cleanName(varName, "jsx_module");

  // HTTP/API pattern
  if (bodyCode.includes("createServer") && bodyCode.includes("listen")) return cleanName(varName, "server");
  if (bodyCode.includes("fetch(") || bodyCode.includes("XMLHttpRequest")) return cleanName(varName, "http_client");

  // Auth pattern
  if (bodyCode.includes("token") && bodyCode.includes("auth")) return cleanName(varName, "auth");
  if (bodyCode.includes("jwt") || bodyCode.includes("Bearer")) return cleanName(varName, "jwt_auth");

  // Crypto pattern
  if (bodyCode.includes("createHash") || bodyCode.includes("createHmac")) return cleanName(varName, "crypto_utils");

  // CLI pattern
  if (bodyCode.includes("process.argv") || bodyCode.includes("commander")) return cleanName(varName, "cli");
  if (bodyCode.includes("stdin") && bodyCode.includes("stdout")) return cleanName(varName, "terminal");

  // File system pattern
  if (bodyCode.includes("readFile") || bodyCode.includes("writeFile")) return cleanName(varName, "file_ops");
  if (bodyCode.includes("readdir") || bodyCode.includes("mkdir")) return cleanName(varName, "dir_ops");

  // Logging
  if (bodyCode.includes("console.log") && bodyCode.includes("console.error")) return cleanName(varName, "logger");

  // Config
  if (bodyCode.includes("process.env") && bodyCode.includes("config")) return cleanName(varName, "config");

  // gRPC -- proto sadece grpc baglami icerisindeyse
  if (bodyCode.includes("grpc") && bodyCode.includes("ServiceClient")) return cleanName(varName, "grpc");
  if (bodyCode.includes("@grpc/") || bodyCode.includes("grpc-js")) return cleanName(varName, "grpc");

  // WebSocket
  if (bodyCode.includes("WebSocket") || bodyCode.includes("ws://")) return cleanName(varName, "websocket");

  // JSON/serialization
  if (bodyCode.includes("JSON.parse") && bodyCode.includes("JSON.stringify")) return cleanName(varName, "serialization");

  // Event emitter
  if (bodyCode.includes("EventEmitter") || bodyCode.includes(".emit(")) return cleanName(varName, "events");

  // Stream
  if (bodyCode.includes("Readable") || bodyCode.includes("Writable") || bodyCode.includes("Transform")) return cleanName(varName, "streams");

  // Sentry
  if (bodyCode.includes("@sentry/") || bodyCode.includes("sentry-javascript")) return cleanName(varName, "sentry");

  // Buffer/binary
  if (bodyCode.includes("Buffer.from") && bodyCode.includes("Buffer.alloc")) return cleanName(varName, "buffer_utils");

  // Regex/pattern
  if (bodyCode.includes("RegExp(") && bodyCode.includes(".exec(")) return cleanName(varName, "regex_utils");

  // Error handling
  if (bodyCode.includes("Error(") && bodyCode.includes("captureStackTrace")) return cleanName(varName, "error_handler");

  // Process/spawn
  if (bodyCode.includes("child_process") || bodyCode.includes("execSync")) return cleanName(varName, "process_utils");

  // Anthropic/Claude specific
  if (bodyCode.includes("anthropic") || bodyCode.includes("claude")) return cleanName(varName, "anthropic_api");
  if (bodyCode.includes("conversation") && bodyCode.includes("message")) return cleanName(varName, "conversation");
  if (bodyCode.includes("prompt") && bodyCode.includes("completion")) return cleanName(varName, "prompt_handler");
  if (bodyCode.includes("tool") && bodyCode.includes("function_call")) return cleanName(varName, "tool_handler");

  // MIME types
  if (bodyCode.includes("application/") && bodyCode.includes("text/")) return cleanName(varName, "mime_types");

  // Color/ANSI
  if (bodyCode.includes("\\x1b[") || bodyCode.includes("\\u001b[")) return cleanName(varName, "ansi_colors");

  // Orjinal isim varsa onu kullan
  return cleanName(varName, null);
}

function cleanName(varName, fallback) {
  // Eger varName zaten anlamli ise (3+ karakter, camelCase)
  if (varName.length > 4 && /^[a-z]/.test(varName)) return varName;
  return fallback || varName;
}

// ---------- Webpack Module Extractors ----------
function extractWebpackObjectModules(objNode) {
  for (const prop of objNode.properties) {
    if (!t.isObjectProperty(prop) && !t.isObjectMethod(prop)) continue;

    let moduleId;
    if (t.isNumericLiteral(prop.key)) moduleId = String(prop.key.value);
    else if (t.isStringLiteral(prop.key)) moduleId = prop.key.value;
    else if (t.isIdentifier(prop.key)) moduleId = prop.key.name;
    else continue;

    const funcNode = t.isObjectMethod(prop) ? prop : prop.value;
    if (!t.isFunctionExpression(funcNode) && !t.isArrowFunctionExpression(funcNode) && !t.isObjectMethod(funcNode)) continue;

    if (!detectedModules.has(moduleId)) {
      detectedModules.set(moduleId, {
        node: funcNode,
        type: "webpack_object",
        name: `module_${moduleId}`,
        deps: new Set(),
        exports: [],
        varName: moduleId,
      });
      bundleFormat = bundleFormat === "unknown" ? "webpack_object" : bundleFormat;
    }
  }
}

function extractWebpackArrayModules(arrNode) {
  for (let i = 0; i < arrNode.elements.length; i++) {
    const el = arrNode.elements[i];
    if (!el) continue;
    if (!t.isFunctionExpression(el) && !t.isArrowFunctionExpression(el)) continue;

    const moduleId = String(i);
    if (!detectedModules.has(moduleId)) {
      detectedModules.set(moduleId, {
        node: el,
        type: "webpack_array",
        name: `module_${i}`,
        deps: new Set(),
        exports: [],
        varName: moduleId,
      });
      bundleFormat = bundleFormat === "unknown" ? "webpack_array" : bundleFormat;
    }
  }
}

// ---------- Ayrica top-level yapilari (import/export, IIFE) da ayir ----------
// esbuild bundle'in tamamini parcalamak icin top-level statement'lari gruplara ayir
if (detectedModules.size === 0 || bundleFormat === "unknown") {
  // Hicbir webpack/esbuild module bulunamadiysa, dosyayi top-level statement gruplarina ayir
  try {
    const body = ast.program.body;
    let currentChunk = [];
    let chunkIndex = 0;
    const CHUNK_SIZE = 500; // satir

    for (const stmt of body) {
      currentChunk.push(stmt);

      const stmtCode = safeGenerate(stmt, 100);
      const lineCount = stmtCode.split("\n").length;

      if (currentChunk.length >= 10 || lineCount > CHUNK_SIZE) {
        const chunkId = `chunk_${chunkIndex}`;
        // Sadece anlamli buyuklukte chunk'lar
        const fullCode = currentChunk.map((s) => safeGenerate(s)).join("\n");
        if (fullCode.length > 200) {
          detectedModules.set(chunkId, {
            node: null,
            rawCode: fullCode,
            type: "top_level_chunk",
            name: chunkId,
            deps: new Set(),
            exports: [],
            varName: chunkId,
          });
        }
        currentChunk = [];
        chunkIndex++;
      }
    }

    // Son chunk
    if (currentChunk.length > 0) {
      const chunkId = `chunk_${chunkIndex}`;
      const fullCode = currentChunk.map((s) => safeGenerate(s)).join("\n");
      if (fullCode.length > 200) {
        detectedModules.set(chunkId, {
          node: null,
          rawCode: fullCode,
          type: "top_level_chunk",
          name: chunkId,
          deps: new Set(),
          exports: [],
          varName: chunkId,
        });
      }
    }

    if (chunkIndex > 0) bundleFormat = "flat_chunked";
  } catch (err) {
    errors.push(`Top-level chunking hata: ${err.message}`);
  }
}

// ---------- Write Modules ----------
const moduleOutputs = [];
const usedFileNames = new Set();

for (const [moduleId, modInfo] of detectedModules.entries()) {
  try {
    let code;
    if (modInfo.rawCode) {
      code = modInfo.rawCode;
    } else if (modInfo.node) {
      const result = generate(modInfo.node, {
        comments: true,
        compact: false,
        concise: false,
      });
      code = result.code;
    } else {
      continue;
    }

    // Dosya adi
    let fileName = sanitizeFileName(modInfo.name || moduleId);
    if (usedFileNames.has(fileName)) {
      let suffix = 2;
      while (usedFileNames.has(`${fileName}_${suffix}`)) suffix++;
      fileName = `${fileName}_${suffix}`;
    }
    usedFileNames.add(fileName);

    // Header
    const deps = [...modInfo.deps];
    const exportsStr = modInfo.exports?.length > 0 ? modInfo.exports.join(", ") : "none";
    const npmStr = modInfo.npmPackage || "none";
    const reqDepsStr = modInfo.requireDeps?.length > 0 ? modInfo.requireDeps.join(", ") : "none";
    const header = [
      `/**`,
      ` * Module: ${moduleId}`,
      ` * Type: ${modInfo.type}`,
      ` * Name: ${modInfo.name || "unknown"}`,
      ` * npm package: ${npmStr}`,
      ` * Exports: ${exportsStr}`,
      ` * Dependencies: [${deps.join(", ")}]`,
      ` * Node.js requires: [${reqDepsStr}]`,
      ` * Original var: ${modInfo.varName}`,
      ` * Unpacked by Karadul v1.0`,
      ` */`,
      ``,
    ].join("\n");

    const moduleCode = header + code + "\n";
    const filePath = join(modulesDir, `${fileName}.js`);
    writeFileSync(filePath, moduleCode, "utf-8");

    moduleOutputs.push({
      id: moduleId,
      name: modInfo.name || moduleId,
      type: modInfo.type,
      file: `${fileName}.js`,
      size: Buffer.byteLength(moduleCode, "utf-8"),
      lines: moduleCode.split("\n").length,
      dependencies: deps,
      exports: modInfo.exports || [],
      esm_alias: modInfo.esmAlias || null,
      npm_package: modInfo.npmPackage || null,
      require_deps: modInfo.requireDeps || [],
    });
  } catch (err) {
    errors.push(`Module ${moduleId} yazma hata: ${err.message}`);
  }
}

// ---------- Dependency Graph ----------
const depGraph = {};
for (const [moduleId, modInfo] of detectedModules.entries()) {
  depGraph[moduleId] = [...(modInfo.deps || [])];
}

try {
  const graphPath = join(outputDir, "dependency_graph.json");
  writeFileSync(graphPath, JSON.stringify({
    bundle_format: bundleFormat,
    total_modules: moduleOutputs.length,
    helpers: {
      cjs_wrapper: cjsWrapperName,
      esm_interop: esmInteropName,
      re_export: reExportName,
      require_alias: requireAliasName,
    },
    modules: moduleOutputs.map((m) => ({
      id: m.id, name: m.name, file: m.file, type: m.type,
      exports: m.exports, esm_alias: m.esm_alias,
      npm_package: m.npm_package, require_deps: m.require_deps,
    })),
    graph: depGraph,
  }, null, 2), "utf-8");

  // Module ID -> Package Name mapping dosyasi (rename pipeline icin)
  if (moduleIdPackageMap.size > 0) {
    const mapPath = join(outputDir, "module_id_map.json");
    const idMap = {};
    for (const [id, pkg] of moduleIdPackageMap.entries()) {
      const mod = detectedModules.get(id);
      idMap[id] = {
        npm_package: pkg,
        display_name: NPM_DISPLAY_NAMES[pkg] || sanitizeFileName(pkg),
        module_name: mod?.name || id,
        exports: mod?.exports || [],
        require_deps: mod?.requireDeps || [],
      };
    }
    writeFileSync(mapPath, JSON.stringify({
      total_mapped: moduleIdPackageMap.size,
      total_modules: detectedModules.size,
      coverage: (moduleIdPackageMap.size / Math.max(1, detectedModules.size) * 100).toFixed(1) + "%",
      node_builtins: [...moduleIdPackageMap.entries()]
        .filter(([_, pkg]) => NODE_BUILTINS.has(pkg))
        .map(([id, pkg]) => ({ id, package: pkg })),
      npm_packages: [...moduleIdPackageMap.entries()]
        .filter(([_, pkg]) => !NODE_BUILTINS.has(pkg))
        .map(([id, pkg]) => ({ id, package: pkg })),
      id_to_name: idMap,
    }, null, 2), "utf-8");
  }
} catch (err) {
  errors.push(`Dependency graph yazma hata: ${err.message}`);
}

// ---------- Result ----------
emit({
  success: moduleOutputs.length > 0,
  bundle_format: bundleFormat,
  total_modules: moduleOutputs.length,
  npm_mapped_modules: moduleIdPackageMap.size,
  npm_packages_found: [...new Set(moduleIdPackageMap.values())].sort(),
  helpers_detected: {
    cjs_wrapper: cjsWrapperName,
    esm_interop: esmInteropName,
    re_export: reExportName,
    require_alias: requireAliasName,
  },
  modules: moduleOutputs,
  file_size: fileSize,
  errors,
});

// ===== Helpers =====

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function safeGenerate(node, maxLen) {
  try {
    const { code } = generate(node, { compact: true });
    if (maxLen && code.length > maxLen) return code.slice(0, maxLen);
    return code;
  } catch (_) {
    return "";
  }
}

function sanitizeFileName(name) {
  // Dosya adi icin guvenli karakter seti
  return name
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .slice(0, 60) || "unnamed";
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
