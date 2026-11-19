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
 *   8. Webpack 5 JSONP oebegi: (self.webpackChunkX = ... || []).push([[id], { ... }])
 *   9. Webpack 5 Node oebegi:  exports.ids = [...]; exports.modules = { ... }
 *
 * P20b: 4-6 ve 8-9'da nesne/dizi ancak webpack calisma zamanina bagliysa modul
 * haritasi sayilir (require islevi, R.m = M, __webpack_* adi, oebek kaydi);
 * birden cok aday varsa secim ve gerekcesi `module_map_selection`'da.
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
// P20b: girdi önce düz JS eklentileriyle ayrıştırılır. `typescript` eklentisi
// geçerli JS'i de bozabiliyor (Electron Fiddle `renderer/main_window/index.js`,
// webpack 5, 904 modül: "Unexpected token, expected ':'" → 0 modül). TS
// eklentisi yalnız düz JS ayrıştırması düşerse denenir; kullanılan küme
// çıktıda (`parser_plugins`) yazılır ve modül sınamasında da o kullanılır.
const PLUGINS_JS = [
  "jsx", "decorators-legacy", "classProperties",
  "classPrivateProperties", "classPrivateMethods", "dynamicImport",
  "optionalChaining", "nullishCoalescingOperator", "exportDefaultFrom",
  "exportNamespaceFrom", "topLevelAwait", "importMeta",
];
const PLUGINS_TS = ["typescript", ...PLUGINS_JS];
let parserMode = "js";

function parseWith(code, plugins) {
  return parse(code, {
    sourceType: "unambiguous",
    allowImportExportEverywhere: true,
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowUndeclaredExports: true,
    errorRecovery: true,
    plugins,
  });
}

// Düz JS, düşerse TS eklentisi. İkisi de düşerse son hata fırlatılır.
function parseJsThenTs(code) {
  try {
    const parsed = parseWith(code, PLUGINS_JS);
    parserMode = "js";
    return parsed;
  } catch (jsErr) {
    const parsed = parseWith(code, PLUGINS_TS);
    parserMode = "typescript";
    errors.push(`Duz JS ayristirmasi basarisiz (${jsErr.message}); typescript eklentisiyle ayristirildi`);
    return parsed;
  }
}

const errors = [];
let ast;
try {
  ast = parseJsThenTs(source);
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
      ast = parseJsThenTs(beautified);
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

// P20b: webpack modül haritası adayları (kapsayıcı düğüm -> aday) ve
// traverse sonrası çözülecek kanıtlar.
const mapCandidates = new Map();
const pendingRequireM = [];
const pendingNodeChunks = [];
let sawExportsChunkIds = false;
// Kanıt türleri ve ağırlıkları. Aday ancak en az bir kanıtla harita sayılır.
const MAP_EVIDENCE_WEIGHT = {
  // R(id) içinde M[id].call(x, y, z, R) / M[id](y, z, R): __webpack_require__'ın
  // kendini modül fabrikasına geçirmesi (webpack çalışma zamanının tanımı).
  runtime_require_call: 3,
  // __webpack_require__.m = __webpack_modules__ (aynı R ile).
  require_m_assignment: 2,
  // (self.webpackChunk<ad> = … || []).push([[öbek], MODÜLLER]) / webpackJsonp.
  jsonp_chunk_push: 3,
  // Node öbeği: exports.ids = […]; exports.modules = {…}.
  node_chunk_exports: 3,
  "name:__webpack_modules__": 2,
  "name:__webpack_require__": 1,
};

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

      // P20b: var __webpack_modules__ = ({...}) (küçültülmemiş webpack 5)
      if (id.name === "__webpack_modules__" && isMapContainer(init)) {
        mapCandidate(init, "declaration").evidence.add("name:__webpack_modules__");
      }

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

    // Pattern 3/4 (P20b): webpack modül haritası ADAYLARI. Eskiden her IIFE'nin
    // nesne / dizi argümanı doğrudan "modül haritası" sayılıyordu; webpack 5
    // paketinde (Fiddle main/index.js) haritayı değil bir Prisma nesnesinin
    // özelliklerini (`then`, `catch`, `VERSION` …) modül diye çıkarıyordu.
    // Artık aday yalnız webpack ÇALIŞMA ZAMANINA bağlıysa harita sayılır;
    // seçim traverse'ten sonra (selectModuleMap).
    CallExpression(path) {
      const node = path.node;
      const callee = node.callee;
      if (t.isFunctionExpression(callee) || t.isArrowFunctionExpression(callee)) {
        for (const arg of node.arguments) {
          if (isMapContainer(arg)) mapCandidate(arg, "iife_argument");
        }
      }
      noteRuntimeModuleCall(path);
      noteJsonpChunk(path);
    },

    AssignmentExpression(path) {
      const { left, right } = path.node;
      if (t.isIdentifier(left, { name: "__webpack_modules__" }) && isMapContainer(right)) {
        mapCandidate(right, "assignment").evidence.add("name:__webpack_modules__");
      }
      // __webpack_require__.m = __webpack_modules__ (küçültülmüş: o.m = s)
      if (
        t.isMemberExpression(left) && !left.computed &&
        t.isIdentifier(left.property, { name: "m" }) &&
        t.isIdentifier(left.object) && t.isIdentifier(right)
      ) {
        pendingRequireM.push({ path, req: left.object.name, map: right.name });
      }
      // Node öbeği: exports.modules = {...}; exports.ids = [...]
      if (t.isMemberExpression(left) && !left.computed && t.isIdentifier(left.object, { name: "exports" })) {
        if (t.isIdentifier(left.property, { name: "modules" }) && isMapContainer(right)) {
          pendingNodeChunks.push(right);
        } else if (t.isIdentifier(left.property, { name: "ids" }) || t.isIdentifier(left.property, { name: "id" })) {
          sawExportsChunkIds = true;
        }
      }
    },
  });
} catch (err) {
  errors.push(`Module detection hata: ${err.message}`);
}

const moduleMapSelection = selectModuleMap();

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

// ---------- Webpack modül haritası: aday, kanıt, seçim (P20b) ----------
// (Kanıt ağırlıkları MAP_EVIDENCE_WEIGHT: "Module Detection" başında; seçim
// traverse'ten hemen sonra koştuğu için burada tanımlansa TDZ hatası verirdi.)

function isMapContainer(node) {
  return t.isObjectExpression(node) || t.isArrayExpression(node);
}

function mapCandidate(container, source) {
  let c = mapCandidates.get(container);
  if (!c) {
    c = { node: container, sources: new Set(), evidence: new Set(), requireNames: new Set() };
    mapCandidates.set(container, c);
  }
  c.sources.add(source);
  return c;
}

// İşlevin adı: bildirim adı, ya da `var R = function…` / `R = function…`.
function functionName(fnPath) {
  const n = fnPath.node;
  if (n.id && t.isIdentifier(n.id)) return n.id.name;
  const parent = fnPath.parentPath && fnPath.parentPath.node;
  if (t.isVariableDeclarator(parent) && t.isIdentifier(parent.id)) return parent.id.name;
  if (t.isAssignmentExpression(parent) && t.isIdentifier(parent.left)) return parent.left.name;
  return null;
}

// Bir gövdenin DOĞRUDAN deyimlerinde `name` bildirimi: kapsayıcı başlangıç
// değeri, kapsayıcı olmayan bildirim için null, bildirim yoksa undefined.
function findDeclaredContainer(body, name) {
  const stmts = t.isBlockStatement(body) || t.isProgram(body) ? body.body : null;
  if (!stmts) return undefined;
  for (const st of stmts) {
    if (!t.isVariableDeclaration(st)) continue;
    for (const d of st.declarations) {
      if (t.isIdentifier(d.id) && d.id.name === name) {
        return isMapContainer(d.init) ? d.init : null;
      }
    }
  }
  return undefined;
}

// `name`'in bağını sözcüksel olarak yukarı doğru çöz (kapsam nesnesi yok:
// traverse noScope). İşlev parametresiyse ve işlev hemen çağrılıyorsa (IIFE)
// karşılık gelen argüman; değişkense başlangıç değeri. Kapsayıcı değilse null.
function resolveMapContainer(fromPath, name) {
  let p = fromPath;
  while (p) {
    const n = p.node;
    if (t.isFunction(n)) {
      const idx = n.params.findIndex((q) => t.isIdentifier(q) && q.name === name);
      if (idx >= 0) {
        const call = p.parentPath && p.parentPath.node;
        if (t.isCallExpression(call) && call.callee === n) {
          const arg = call.arguments[idx];
          return isMapContainer(arg) ? arg : null;
        }
        return null;
      }
      const found = findDeclaredContainer(n.body, name);
      if (found !== undefined) return found;
    } else if (t.isProgram(n)) {
      const found = findDeclaredContainer(n, name);
      return found === undefined ? null : found;
    }
    p = p.parentPath;
  }
  return null;
}

// R(id) { … M[id].call(a, b, c, R) … }  |  R(id) { … M[id](b, c, R) … }
function noteRuntimeModuleCall(path) {
  const node = path.node;
  const callee = node.callee;
  let member = null;
  let args = null;
  if (
    t.isMemberExpression(callee) && !callee.computed &&
    t.isIdentifier(callee.property, { name: "call" }) &&
    t.isMemberExpression(callee.object) && callee.object.computed
  ) {
    member = callee.object;
    args = node.arguments.slice(1);
  } else if (t.isMemberExpression(callee) && callee.computed) {
    member = callee;
    args = node.arguments;
  }
  if (!member || !t.isIdentifier(member.object) || !t.isIdentifier(member.property)) return;
  if (args.length < 2) return;
  const last = args[args.length - 1];
  if (!t.isIdentifier(last)) return;
  const fnPath = path.getFunctionParent();
  if (!fnPath) return;
  const reqName = functionName(fnPath);
  const firstParam = fnPath.node.params[0];
  if (
    !reqName || reqName !== last.name ||
    !t.isIdentifier(firstParam) || firstParam.name !== member.property.name
  ) return;
  const container = resolveMapContainer(fnPath, member.object.name);
  if (!container) return;
  const c = mapCandidate(container, "runtime_require");
  c.evidence.add("runtime_require_call");
  c.requireNames.add(reqName);
  if (reqName === "__webpack_require__") c.evidence.add("name:__webpack_require__");
}

// Öbek kaydının hedefi webpack'in öbek dizisi mi (webpackChunk<ad> / webpackJsonp)?
function isWebpackChunkGlobal(node, depth = 0) {
  if (!node || depth > 4) return false;
  const re = /^webpack(Chunk|Jsonp)/;
  if (t.isIdentifier(node)) return re.test(node.name);
  if (t.isMemberExpression(node)) {
    if (!node.computed && t.isIdentifier(node.property)) return re.test(node.property.name);
    if (node.computed && t.isStringLiteral(node.property)) return re.test(node.property.value);
    return false;
  }
  if (t.isAssignmentExpression(node)) return isWebpackChunkGlobal(node.left, depth + 1);
  if (t.isLogicalExpression(node)) {
    return isWebpackChunkGlobal(node.left, depth + 1) || isWebpackChunkGlobal(node.right, depth + 1);
  }
  return false;
}

// (self.webpackChunk<ad> = self.webpackChunk<ad> || []).push([[öbek kimlikleri], MODÜLLER, …])
function noteJsonpChunk(path) {
  const { callee } = path.node;
  const args = path.node.arguments;
  if (!t.isMemberExpression(callee) || callee.computed) return;
  if (!t.isIdentifier(callee.property, { name: "push" })) return;
  if (!isWebpackChunkGlobal(callee.object)) return;
  const a = args[0];
  if (!t.isArrayExpression(a) || a.elements.length < 2 || !t.isArrayExpression(a.elements[0])) return;
  const mods = a.elements[1];
  if (!isMapContainer(mods)) return;
  mapCandidate(mods, "jsonp_chunk").evidence.add("jsonp_chunk_push");
}

function candidateModuleCount(c) {
  if (t.isArrayExpression(c.node)) return c.node.elements.filter(Boolean).length;
  return c.node.properties.filter((p) => t.isObjectProperty(p) || t.isObjectMethod(p)).length;
}

function candidateScore(c) {
  let s = 0;
  for (const e of c.evidence) s += MAP_EVIDENCE_WEIGHT[e] || 0;
  return s;
}

function describeCandidate(c) {
  return {
    sources: [...c.sources].sort(),
    shape: t.isArrayExpression(c.node) ? "array" : "object",
    module_count: candidateModuleCount(c),
    evidence: [...c.evidence].sort(),
    score: candidateScore(c),
    line: c.node.loc ? c.node.loc.start.line : null,
    column: c.node.loc ? c.node.loc.start.column : null,
  };
}

// Kanıtları tamamla, iç içe adayları ayıkla, en güçlü kanıtlı dış adayı seç
// ve modüllerini detectedModules'e aktar. Gerekçe çıktı JSON'una yazılır.
function selectModuleMap() {
  // R.m = M yalnız aynı R çalışma zamanı kanıtı taşıyorsa sayılır.
  for (const { path, req, map } of pendingRequireM) {
    const container = resolveMapContainer(path, map);
    const c = container && mapCandidates.get(container);
    if (c && c.requireNames.has(req)) c.evidence.add("require_m_assignment");
  }
  if (sawExportsChunkIds) {
    for (const container of pendingNodeChunks) {
      mapCandidate(container, "node_chunk").evidence.add("node_chunk_exports");
    }
  }

  const all = [...mapCandidates.values()];
  const linked = all.filter((c) => c.evidence.size > 0);
  const rejected = [];
  for (const c of all) {
    if (c.evidence.size === 0) {
      rejected.push({ ...describeCandidate(c), reason: "webpack çalışma zamanına bağı yok" });
    }
  }
  // İç içe: başka bir bağlı adayın kapsayıcısı içinde duran harita, paketlenmiş
  // bir kütüphanenin kendi çalışma zamanıdır; o kod dış haritanın bir modülünün
  // içindedir ve kimlikleri dış haritanınkilerle çakışır.
  const outer = [];
  for (const c of linked) {
    const host = linked.find((o) => o !== c && o.node.start <= c.node.start && c.node.end <= o.node.end);
    if (host) {
      rejected.push({
        ...describeCandidate(c),
        reason: `iç içe: ${host.node.loc ? host.node.loc.start.line + ":" + host.node.loc.start.column : "?"} haritasının bir modülü içinde`,
      });
    } else {
      outer.push(c);
    }
  }
  outer.sort((a, b) =>
    candidateScore(b) - candidateScore(a) ||
    candidateModuleCount(b) - candidateModuleCount(a) ||
    a.node.start - b.node.start);
  const chosen = outer[0] || null;
  for (const c of outer.slice(1)) {
    rejected.push({ ...describeCandidate(c), reason: "daha zayıf kanıtlı dış aday" });
  }

  let esbuildNestedDropped = 0;
  if (chosen) {
    // Seçilen haritanın içinde kalan esbuild sarmalayıcıları o haritanın bir
    // modülünün parçasıdır; ayrı modül sayılmaz.
    for (const [id, mod] of [...detectedModules.entries()]) {
      if (
        mod.type === "esbuild_cjs" && mod.node &&
        chosen.node.start <= mod.node.start && mod.node.end <= chosen.node.end
      ) {
        detectedModules.delete(id);
        esbuildNestedDropped += 1;
      }
    }
    if (bundleFormat === "esbuild" && ![...detectedModules.values()].some((m) => m.type === "esbuild_cjs")) {
      bundleFormat = "unknown";
    }
    if (t.isObjectExpression(chosen.node)) extractWebpackObjectModules(chosen.node);
    else extractWebpackArrayModules(chosen.node);
    if (chosen.evidence.has("jsonp_chunk_push")) bundleFormat = bundleFormat === "esbuild" ? bundleFormat : "webpack_jsonp_chunk";
    else if (chosen.evidence.has("node_chunk_exports")) bundleFormat = bundleFormat === "esbuild" ? bundleFormat : "webpack_node_chunk";
  }

  return {
    rule:
      "Aday (nesne/dizi) yalnız webpack çalışma zamanına bağlıysa harita sayılır: " +
      "R(id) içinde M[id](…, R) çağrısı, aynı R ile R.m = M, __webpack_modules__ / " +
      "__webpack_require__ adı, webpackChunk/webpackJsonp öbek kaydı ya da " +
      "exports.ids + exports.modules. Başka bir haritanın içindeki harita iç içe " +
      "sayılır; dış adaylardan kanıt puanı (eşitlikte modül sayısı) en yüksek olan seçilir.",
    candidates_total: all.length,
    candidates_linked: linked.length,
    chosen: chosen ? describeCandidate(chosen) : null,
    rejected_total: rejected.length,
    rejected: rejected.slice(0, 30),
    esbuild_nested_dropped: esbuildNestedDropped,
  };
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
let parseOkCount = 0;
const parseFailed = [];

for (const [moduleId, modInfo] of detectedModules.entries()) {
  try {
    let code;
    let wrapped = false;
    if (modInfo.rawCode) {
      code = modInfo.rawCode;
    } else if (modInfo.node) {
      // BICIM-01: modül düğümü bir İFADEDİR (paket nesnesindeki
      // `function (e, t, n) {...}`, ok işlevi ya da nesne yöntemi). Tek başına
      // generate edilip dosyaya yazılınca adsız `function (` deyimi olur ve
      // dosya ayrıştırılamaz. İfade deyimi olarak yazılır:
      // `(function (e, t, n) {...});` — anlam eklemez, yalnız geçerli JS yapar.
      const program = moduleNodeToProgram(modInfo.node);
      wrapped = program !== null;
      const result = generate(program || modInfo.node, {
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
      ...(wrapped
        ? [` * Form: module factory written as an expression statement`]
        : []),
      ` * Unpacked by Karadul`,
      ` */`,
      ``,
    ].join("\n");

    const moduleCode = header + code + "\n";
    const filePath = join(modulesDir, `${fileName}.js`);
    writeFileSync(filePath, moduleCode, "utf-8");

    // Yazılan her modül ayrıştırıcıyla sınanır; ayrıştırılamayan sayılır ve
    // çıktıda adıyla bildirilir (sessiz bozuk dosya yok).
    const parseError = checkModuleParses(moduleCode);
    if (parseError === null) {
      parseOkCount += 1;
    } else {
      parseFailed.push({ file: `${fileName}.js`, error: parseError });
    }

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
      parse_ok: parseError === null,
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
    module_map_selection: moduleMapSelection,
    parser_plugins: parserMode,
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
  // BICIM-01 / MEK-12: yazılan modüllerden kaçı ayrıştırılabildi (Babel,
  // hata kurtarmasız). total_modules = modules_parse_ok + modules_parse_failed.
  modules_parse_ok: parseOkCount,
  modules_parse_failed: parseFailed.length,
  parse_failed_modules: parseFailed.slice(0, 50),
  // P20b: modül haritası seçiminin gerekçesi (seçilen aday, kanıtları,
  // reddedilen adaylar ve nedenleri) ve girdinin ayrıştırıldığı eklenti kümesi.
  module_map_selection: moduleMapSelection,
  parser_plugins: parserMode,
  file_size: fileSize,
  errors,
});

// ===== Helpers =====

// Modül ayrıştırma sınaması: girdi ayrıştırmasıyla aynı eklenti kümesi, ama
// hata kurtarma KAPALI (kurtarılan hata = eksik AST = ayrıştırılamaz sayılır).
// (Eklenti kümeleri dosyanın başında, ayrıştırmadan önce tanımlı; P20b: girdi
// hangi kümeyle ayrıştıysa modül de onunla sınanır.)
function checkModuleParses(code) {
  const MODULE_CHECK_PLUGINS = parserMode === "typescript" ? PLUGINS_TS : PLUGINS_JS;
  try {
    parse(code, {
      sourceType: "unambiguous",
      allowImportExportEverywhere: true,
      allowReturnOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowUndeclaredExports: true,
      errorRecovery: false,
      plugins: MODULE_CHECK_PLUGINS,
    });
    return null;
  } catch (err) {
    return String(err && err.message ? err.message : err).slice(0, 200);
  }
}

// Modül düğümünü tek başına geçerli bir programa çevir (BICIM-01).
// FunctionExpression / ArrowFunctionExpression -> ifade deyimi; ObjectMethod
// (`0(e, t, n) {...}`) -> adsız FunctionExpression -> ifade deyimi. Generator
// ifade deyiminin başındaki `function`'ı kendisi paranteze alır.
function moduleNodeToProgram(node) {
  let expr = node;
  if (t.isObjectMethod(node)) {
    expr = t.functionExpression(
      null, node.params, node.body, node.generator, node.async,
    );
  }
  if (t.isExpression(expr)) {
    return t.program([t.expressionStatement(expr)]);
  }
  return null;
}

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
