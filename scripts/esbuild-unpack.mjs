#!/usr/bin/env node
/**
 * esbuild-unpack.mjs -- esbuild Bundle Module Extraction
 *
 * Claude Code CLI gibi esbuild ile bundle edilmis JS dosyalarini
 * ayri modullere parcalar ve npm paket tespiti yapar.
 *
 * Desteklenen esbuild pattern'leri:
 *   1. CJS wrapper:    var X = U((exports, module) => { ... })
 *   2. ESM interop:    var Y = Q1(X(), 1)          (__toESM)
 *   3. Re-export:      lb(target, { name: () => ref })
 *   4. Lazy init:      var Z = FJ1(() => { ... })
 *   5. createRequire:  var X1 = wnB(import.meta.url)
 *
 * Kullanim:
 *   node --max-old-space-size=8192 esbuild-unpack.mjs <input> <output-dir>
 *
 * Cikti:
 *   output-dir/modules/          -- Her modul ayri dosya
 *   output-dir/module_map.json   -- Modul ID -> npm paket eslestirmesi
 *   output-dir/dependency_graph.json
 *   stdout: JSON stats
 *
 * Karadul v1.0 -- esbuild ozel modul cikarici
 */

import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

// ========== CLI ==========
const args = process.argv.slice(2);

if (args.length < 2) {
  emit({ success: false, errors: ["Kullanim: node esbuild-unpack.mjs <input> <output-dir>"] });
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputDir = resolve(args[1]);
const modulesDir = join(outputDir, "modules");

// ========== Read Source ==========
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

// ========== Parse ==========
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
} catch (err) {
  emit({ success: false, errors: [`Fatal parse: ${err.message}`] });
  process.exit(0);
}

// ========== Phase 1: Helper Detection ==========
// esbuild helper fonksiyonlarini tespit et (U, Q1, lb, FJ1, X1)
let cjsWrapperName = null;     // U -- (exports, buf) => () => (...)
let esmInteropName = null;     // Q1 -- __toESM
let reExportName = null;       // lb -- re-export helper
let lazyInitName = null;       // FJ1 -- lazy init wrapper
let requireAliasName = null;   // X1 -- createRequire(import.meta.url) (ilk bulunan)
const allRequireAliases = [];  // Tum createRequire alias'lari
let definePropertyName = null; // yu1 -- Object.defineProperty alias

try {
  // Helper fonksiyon tespiti icin yardimci -- hem var hem function declaration icin calisir
  function checkHelperFunction(name, params, bodyNode) {
    const paramCount = params.length;

    // ESM interop: function Q1(A, B, Q) { ... __esModule ... default ... }
    if (!esmInteropName && paramCount >= 2 && paramCount <= 3) {
      const bodyCode = safeGenerate(bodyNode, 1000);
      if (
        (bodyCode.includes("__esModule") || bodyCode.includes('"default"')) &&
        bodyCode.includes("enumerable")
      ) {
        esmInteropName = name;
        return true;
      }
    }

    // Re-export helper: function lb(A, B) { for (var Q in B) defineProperty(...) }
    if (!reExportName && paramCount === 2) {
      const bodyCode = safeGenerate(bodyNode, 500);
      if (
        bodyCode.includes("enumerable") &&
        bodyCode.includes("configurable") &&
        bodyCode.includes("get:")
      ) {
        reExportName = name;
        return true;
      }
    }

    return false;
  }

  traverse(ast, {
    noScope: true,

    // function declaration'lar: function Q1(...) { ... }, function lb(...) { ... }
    FunctionDeclaration(path) {
      const node = path.node;
      if (!t.isIdentifier(node.id)) return;
      checkHelperFunction(node.id.name, node.params, node.body);
    },

    VariableDeclarator(path) {
      const id = path.node.id;
      const init = path.node.init;
      if (!t.isIdentifier(id) || !init) return;

      // createRequire pattern: var X1 = wnB(import.meta.url)
      if (t.isCallExpression(init) && init.arguments.length === 1) {
        const arg = init.arguments[0];
        if (t.isMemberExpression(arg) && t.isMetaProperty(arg.object)) {
          allRequireAliases.push(id.name);
          if (!requireAliasName) requireAliasName = id.name;  // ilkini kullan
        }
      }

      // Object.defineProperty alias: var yu1 = Object.defineProperty (diger tespitlerde kullanilir)
      if (
        t.isMemberExpression(init) &&
        t.isIdentifier(init.object, { name: "Object" }) &&
        t.isIdentifier(init.property, { name: "defineProperty" })
      ) {
        definePropertyName = id.name;
      }

      if (!t.isArrowFunctionExpression(init) && !t.isFunctionExpression(init)) return;
      const paramCount = init.params.length;

      // CJS wrapper: var U = (A, B) => () => (B || A((B={exports:{}}).exports, B), B.exports)
      if (paramCount === 2) {
        const bodyCode = safeGenerate(init.body, 500);
        if (bodyCode.includes(".exports") && bodyCode.includes("exports:{}")) {
          cjsWrapperName = id.name;
          return;
        }
      }

      // var ile tanimlanan ESM interop ve re-export (arrow function)
      checkHelperFunction(id.name, init.params, init.body);

      // Lazy init: var FJ1 = (A, B) => () => (A && (B = A(A = 0)), B)
      if (!lazyInitName && paramCount === 2) {
        const bodyCode = safeGenerate(init.body, 300);
        if (
          (bodyCode.includes("A=0") || bodyCode.includes("A = 0") ||
           bodyCode.includes("arg=0") || bodyCode.includes("arg = 0")) &&
          !bodyCode.includes("exports")
        ) {
          lazyInitName = id.name;
          return;
        }
      }
    },
  });
} catch (err) {
  errors.push(`Helper detection hata: ${err.message}`);
}

console.error(`[esbuild-unpack] Helpers: CJS=${cjsWrapperName}, ESM=${esmInteropName}, reExport=${reExportName}, lazyInit=${lazyInitName}, require=${requireAliasName} (all: ${allRequireAliases.join(", ")})`);

if (!cjsWrapperName) {
  emit({
    success: false,
    errors: ["esbuild CJS wrapper pattern (U) bulunamadi. Bu dosya esbuild bundle degil olabilir."],
  });
  process.exit(0);
}

// ========== Phase 2: Module Extraction ==========
// moduleId -> { node, type, name, deps, exports, esmAlias, lazyDeps, requireDeps }
const detectedModules = new Map();
// ESM alias map: esmAliasVar -> sourceModuleId
const esmAliasMap = new Map();
// Lazy init modules: lazyVarName -> { node, deps }
const lazyModules = new Map();
// Re-export info: targetVar -> [{name, getterBody}]
const reExports = new Map();

try {
  traverse(ast, {
    noScope: true,

    VariableDeclarator(path) {
      const id = path.node.id;
      const init = path.node.init;
      if (!t.isIdentifier(id) || !init) return;

      // Pattern 1: CJS wrapper -- var ModuleName = U((exports, module) => { ... })
      if (
        t.isCallExpression(init) &&
        t.isIdentifier(init.callee, { name: cjsWrapperName }) &&
        init.arguments.length === 1 &&
        (t.isArrowFunctionExpression(init.arguments[0]) ||
         t.isFunctionExpression(init.arguments[0]))
      ) {
        const factory = init.arguments[0];
        detectedModules.set(id.name, {
          node: factory,
          type: "esbuild_cjs",
          name: id.name,
          deps: new Set(),
          exports: [],
          requireDeps: [],   // X1("stream") gibi node require'lar
          lazyDeps: [],      // Diger U() modullerini cagiriyorsa
          startLine: factory.loc?.start?.line ?? null,
          endLine: factory.loc?.end?.line ?? null,
        });
        return;
      }

      // Pattern 2: ESM interop -- var Y = Q1(X(), 1) veya var Y = Q1(X())
      if (
        esmInteropName &&
        t.isCallExpression(init) &&
        t.isIdentifier(init.callee, { name: esmInteropName }) &&
        init.arguments.length >= 1
      ) {
        const firstArg = init.arguments[0];
        // Q1(X()) -- X'i cagirip ESM uyumlulugu ekliyor
        if (t.isCallExpression(firstArg) && t.isIdentifier(firstArg.callee)) {
          esmAliasMap.set(id.name, firstArg.callee.name);
        }
        // Q1(X) -- dogrudan referans
        else if (t.isIdentifier(firstArg)) {
          esmAliasMap.set(id.name, firstArg.name);
        }
        return;
      }

      // Pattern 4: Lazy init -- var Z = FJ1(() => { ... })
      if (
        lazyInitName &&
        t.isCallExpression(init) &&
        t.isIdentifier(init.callee, { name: lazyInitName }) &&
        init.arguments.length === 1 &&
        (t.isArrowFunctionExpression(init.arguments[0]) ||
         t.isFunctionExpression(init.arguments[0]))
      ) {
        const factory = init.arguments[0];
        lazyModules.set(id.name, {
          node: factory,
          type: "esbuild_lazy_init",
          name: id.name,
          deps: new Set(),
        });
        return;
      }
    },

    // Pattern 3: Re-export -- lb(target, { name: () => ref, ... })
    CallExpression(path) {
      if (!reExportName) return;
      const node = path.node;
      if (
        t.isIdentifier(node.callee, { name: reExportName }) &&
        node.arguments.length >= 2 &&
        t.isIdentifier(node.arguments[0]) &&
        t.isObjectExpression(node.arguments[1])
      ) {
        const targetVar = node.arguments[0].name;
        const exportEntries = [];

        for (const prop of node.arguments[1].properties) {
          if (t.isObjectProperty(prop) || t.isObjectMethod(prop)) {
            const keyName = t.isIdentifier(prop.key) ? prop.key.name :
                            t.isStringLiteral(prop.key) ? prop.key.value : null;
            if (keyName) {
              // Arrow getter: name: () => ref
              let refName = null;
              if (t.isObjectProperty(prop) && t.isArrowFunctionExpression(prop.value)) {
                const body = prop.value.body;
                if (t.isIdentifier(body)) {
                  refName = body.name;
                }
              }
              exportEntries.push({ name: keyName, ref: refName });
            }
          }
        }

        if (!reExports.has(targetVar)) {
          reExports.set(targetVar, []);
        }
        reExports.get(targetVar).push(...exportEntries);
      }
    },
  });
} catch (err) {
  errors.push(`Module extraction hata: ${err.message}`);
}

console.error(`[esbuild-unpack] Found: ${detectedModules.size} CJS modules, ${esmAliasMap.size} ESM aliases, ${lazyModules.size} lazy inits, ${reExports.size} re-export targets`);

// ========== Phase 3: Dependency Analysis ==========
// Her moduldeki fonksiyon cagilarini tariyoruz.
// Strateji: Modülun generate edilmis kodunu regexle tarayarak
// ModulName() cagrilarini buluyoruz. Bu O(N) cunku sadece bilinen isimleri ariyoruz.

const allModuleNames = new Set(detectedModules.keys());

for (const [moduleId, modInfo] of detectedModules.entries()) {
  try {
    const bodyCode = safeGenerate(modInfo.node, 100000);

    // Node.js require cagirlari: X1("stream"), X1("util"), Q99("url"), lM5("path") vb.
    for (const alias of allRequireAliases) {
      const reqRe = new RegExp(`${escapeRegex(alias)}\\(["']([^"']+)["']\\)`, "g");
      let match;
      while ((match = reqRe.exec(bodyCode)) !== null) {
        if (!modInfo.requireDeps.includes(match[1])) {
          modInfo.requireDeps.push(match[1]);
        }
      }
    }

    // Diger U() modullerini cagiranlar: SomeModule()
    // Not: Sadece bilinen module adlariyla eslestiriyoruz
    // Performance icin tek bir regex olusturup tarama yapiyoruz
    for (const otherName of allModuleNames) {
      if (otherName === moduleId) continue;
      // "OtherModule()" pattern'ini ara -- ancak property erisimleri (OtherModule.xxx) atlama
      // Kisa isimleri sadece tam eslesme ile kabul et (false positive onleme)
      if (otherName.length <= 2) continue;  // cok kisa isimler cok fazla false positive verir
      if (bodyCode.includes(otherName + "(")) {
        modInfo.deps.add(otherName);
      }
    }
  } catch (err) {
    errors.push(`Dependency analizi ${moduleId}: ${err.message}`);
  }
}

// Lazy init dependency'leri
for (const [lazyName, lazyInfo] of lazyModules.entries()) {
  try {
    const bodyCode = safeGenerate(lazyInfo.node, 50000);
    for (const modName of allModuleNames) {
      if (bodyCode.includes(modName + "(")) {
        lazyInfo.deps.add(modName);
      }
    }
    // Q1() ESM interop cagirilari
    if (esmInteropName && bodyCode.includes(esmInteropName + "(")) {
      // Bu lazy init icinde ESM interop var -- daha fazla analiz gerekiyorsa eklenebilir
    }
  } catch (err) {
    errors.push(`Lazy init dependency ${lazyName}: ${err.message}`);
  }
}

// ESM alias -> source module baglantisi
for (const [aliasName, sourceName] of esmAliasMap.entries()) {
  if (detectedModules.has(sourceName)) {
    const mod = detectedModules.get(sourceName);
    if (!mod.esmAliases) mod.esmAliases = [];
    mod.esmAliases.push(aliasName);
  }
}

// Re-export bilgilerini modullere ekle
for (const [targetVar, exportList] of reExports.entries()) {
  // targetVar bir lb() export hedefi -- genellikle module scope'taki bir obje
  // Export isimlerini ilgili modul ile iliskilendirmeye calis
  // Eger targetVar bir modul ise dogrudan ekle
  if (detectedModules.has(targetVar)) {
    detectedModules.get(targetVar).exports.push(...exportList.map(e => e.name));
  }
}

// ========== Phase 4: npm Package Detection ==========
// Bilinen npm paketlerini modullerin icerikleri ve string imzalarindan tespit et

const NPM_SIGNATURES = [
  // React ecosystem
  { match: (code) => code.includes("react.element") && code.includes("isReactComponent"), pkg: "react", category: "react" },
  { match: (code) => code.includes("react-dom") || (code.includes("hydrateRoot") && code.includes("createRoot")), pkg: "react-dom", category: "react" },
  { match: (code) => code.includes("jsx-runtime") || code.includes("react/jsx"), pkg: "react/jsx-runtime", category: "react" },

  // AWS SDK v3
  { match: (code) => code.includes("@aws-sdk/") || code.includes("smithy"), pkg: "@aws-sdk", category: "aws" },
  { match: (code) => code.includes("@aws-crypto/"), pkg: "@aws-crypto", category: "aws" },

  // Anthropic
  { match: (code) => code.includes("anthropic") && code.includes("api_key"), pkg: "@anthropic-ai/sdk", category: "anthropic" },
  { match: (code) => code.includes("x-api-key") && code.includes("anthropic-version"), pkg: "@anthropic-ai/sdk", category: "anthropic" },

  // Sentry
  { match: (code) => code.includes("@sentry/") || code.includes("sentry-javascript"), pkg: "@sentry/node", category: "monitoring" },
  { match: (code) => code.includes("dsn") && code.includes("sentry") && code.includes("breadcrumb"), pkg: "@sentry/core", category: "monitoring" },

  // Streams / Node.js wrappers
  { match: (code) => code.includes("DelayedStream") && code.includes("maxDataSize"), pkg: "delayed-stream", category: "streams" },
  { match: (code) => code.includes("CombinedStream") || (code.includes("_streams") && code.includes("pauseStreams") && code.includes("_getNext")), pkg: "combined-stream", category: "streams" },
  { match: (code) => code.includes("FormData") && code.includes("_multiPartHeader") && code.includes("boundary"), pkg: "form-data", category: "http" },

  // HTTP / networking
  { match: (code) => code.includes("node-fetch") || (code.includes("FetchError") && code.includes("AbortError")), pkg: "node-fetch", category: "http" },
  { match: (code) => code.includes("undici") && code.includes("MockPool"), pkg: "undici", category: "http" },
  { match: (code) => code.includes("proxy-agent") || code.includes("ProxyAgent"), pkg: "proxy-agent", category: "http" },
  { match: (code) => code.includes("pac-proxy-agent") || code.includes("PacProxyAgent"), pkg: "pac-proxy-agent", category: "http" },
  { match: (code) => code.includes("https-proxy-agent") && code.includes("HttpsProxyAgent"), pkg: "https-proxy-agent", category: "http" },
  { match: (code) => code.includes("http-proxy-agent") && code.includes("HttpProxyAgent"), pkg: "http-proxy-agent", category: "http" },
  { match: (code) => code.includes("socks-proxy-agent"), pkg: "socks-proxy-agent", category: "http" },

  // MIME / content type
  { match: (code) => code.includes("application/1d-interleaved-parityfec") && code.includes("source") && code.includes("iana"), pkg: "mime-db", category: "mime" },
  { match: (code) => code.includes("mime.getType") || code.includes("mime.getExtension"), pkg: "mime", category: "mime" },

  // Lodash
  { match: (code) => code.includes("[object Arguments]") && code.includes("[object Array]") && code.includes("[object Boolean]") && code.includes("[object Map]"), pkg: "lodash", category: "utility" },

  // Highlight.js
  { match: (code) => code.includes("getLanguage") && code.includes("highlight") && code.includes("registerLanguage"), pkg: "highlight.js", category: "ui" },

  // Ink (React terminal UI)
  { match: (code) => code.includes("ink") && code.includes("render") && code.includes("Newline"), pkg: "ink", category: "terminal" },

  // Yoga layout
  { match: (code) => code.includes("yoga") && code.includes("YGNode"), pkg: "yoga-layout", category: "terminal" },

  // Zod
  { match: (code) => code.includes("ZodType") || code.includes("ZodString") || code.includes("ZodObject"), pkg: "zod", category: "validation" },

  // Commander / CLI
  { match: (code) => code.includes("commander") && code.includes("Command") && code.includes("parse"), pkg: "commander", category: "cli" },

  // Chalk / colors
  { match: (code) => code.includes("chalk") && code.includes("ansi256"), pkg: "chalk", category: "terminal" },
  { match: (code) => code.includes("\\x1b[") && code.includes("\\x1b[0m") && code.length < 5000, pkg: "ansi-styles", category: "terminal" },

  // WebSocket
  { match: (code) => code.includes("WebSocket") && code.includes("CONNECTING") && code.includes("CLOSING"), pkg: "ws", category: "networking" },

  // gRPC
  { match: (code) => code.includes("@grpc/grpc-js") || code.includes("grpc-js"), pkg: "@grpc/grpc-js", category: "rpc" },
  { match: (code) => code.includes("grpc") && code.includes("ServiceClient") && code.includes("Channel"), pkg: "@grpc/grpc-js", category: "rpc" },

  // Protobuf
  { match: (code) => code.includes("protobuf") && code.includes("Field") && code.includes("Message"), pkg: "protobufjs", category: "serialization" },

  // UUID
  { match: (code) => code.includes("uuid") && code.includes("v4") && /[0-9a-f]{8}-/.test(code), pkg: "uuid", category: "utility" },

  // YAML
  { match: (code) => code.includes("YAML") && code.includes("parseDocument"), pkg: "yaml", category: "serialization" },

  // Diff
  { match: (code) => code.includes("diffLines") || code.includes("structuredPatch") || code.includes("applyPatch"), pkg: "diff", category: "utility" },

  // Semver
  { match: (code) => code.includes("semver") && code.includes("SemVer") && code.includes("prerelease"), pkg: "semver", category: "utility" },

  // tree-sitter
  { match: (code) => code.includes("tree-sitter") || code.includes("TreeSitter"), pkg: "tree-sitter", category: "parsing" },

  // Marked (markdown)
  { match: (code) => code.includes("marked") && code.includes("Lexer") && code.includes("Parser") && code.includes("Tokenizer"), pkg: "marked", category: "parsing" },

  // Glob / minimatch
  { match: (code) => code.includes("minimatch") && code.includes("Minimatch"), pkg: "minimatch", category: "filesystem" },
  { match: (code) => code.includes("glob") && code.includes("Glob") && code.includes("hasMagic"), pkg: "glob", category: "filesystem" },

  // strip-ansi / ansi-regex
  { match: (code) => code.includes("ansi-regex") || (code.includes("stripAnsi") && code.includes("\\u001B")), pkg: "strip-ansi", category: "terminal" },

  // Graceful-fs
  { match: (code) => code.includes("graceful-fs") || (code.includes("lutimes") && code.includes("graceful")), pkg: "graceful-fs", category: "filesystem" },

  // debug
  { match: (code) => code.includes("createDebug") && code.includes("namespace") && code.includes("enabled"), pkg: "debug", category: "utility" },

  // ms (time conversion)
  { match: (code) => /\bms\b/.test(code) && code.includes("msToString") || (code.includes("parse") && code.includes("100d") && code.includes("365.25d")), pkg: "ms", category: "utility" },

  // Readable-stream
  { match: (code) => code.includes("Readable") && code.includes("Writable") && code.includes("Duplex") && code.includes("Transform") && code.includes("PassThrough"), pkg: "readable-stream", category: "streams" },

  // String decoder
  { match: (code) => code.includes("StringDecoder") && code.includes("utf8CheckByte"), pkg: "string_decoder", category: "streams" },

  // open (open browser/app)
  { match: (code) => code.includes("xdg-open") && code.includes("darwin") && code.includes("open"), pkg: "open", category: "utility" },
];

// Ek: version string'lerinden paket tespiti
const VERSION_PATTERNS = [
  { re: /version.*["']18\.\d+\.\d+["']/, pkg: "react", condition: (code) => code.includes("react") || code.includes("Component") },
  { re: /version.*["']3\.8[0-9]{2}\.\d+["']/, pkg: "@aws-sdk/client-*", condition: () => true },
  { re: /version.*["']3\.79[0-9]\.\d+["']/, pkg: "@aws-sdk/client-*", condition: () => true },
  { re: /version.*["']9\.\d+\.\d+["']/, pkg: "@sentry/node", condition: (code) => code.includes("sentry") || code.includes("dsn") },
  { re: /version.*["']7\.\d+\.\d+["']/, pkg: "semver", condition: (code) => code.includes("SemVer") },
];

// Her module npm paket eslestirmesi yap
const moduleMap = {};
const packageModules = {};  // pkg -> [moduleId, ...]

for (const [moduleId, modInfo] of detectedModules.entries()) {
  try {
    const bodyCode = safeGenerate(modInfo.node, 50000);

    // String imza eslestirmesi
    for (const sig of NPM_SIGNATURES) {
      try {
        if (sig.match(bodyCode)) {
          moduleMap[moduleId] = sig.pkg;
          if (!packageModules[sig.pkg]) packageModules[sig.pkg] = [];
          packageModules[sig.pkg].push(moduleId);
          break;  // Ilk eslesen kazanir
        }
      } catch (_) {
        // matcher hatasi - atla
      }
    }

    // Eger string imzasindan bulunamadiysa, version string'i dene
    if (!moduleMap[moduleId]) {
      for (const vp of VERSION_PATTERNS) {
        if (vp.re.test(bodyCode) && vp.condition(bodyCode)) {
          moduleMap[moduleId] = vp.pkg;
          if (!packageModules[vp.pkg]) packageModules[vp.pkg] = [];
          packageModules[vp.pkg].push(moduleId);
          break;
        }
      }
    }

    // Node.js built-in require'larindan isim cikar
    if (!moduleMap[moduleId] && modInfo.requireDeps.length > 0) {
      // Eger tek bir require varsa ve node built-in ise, onu etiket olarak kullan
      const nonNodeDeps = modInfo.requireDeps.filter(d => !isNodeBuiltin(d));
      if (nonNodeDeps.length === 1) {
        moduleMap[moduleId] = nonNodeDeps[0];
        if (!packageModules[nonNodeDeps[0]]) packageModules[nonNodeDeps[0]] = [];
        packageModules[nonNodeDeps[0]].push(moduleId);
      }
    }
  } catch (err) {
    errors.push(`npm tespit ${moduleId}: ${err.message}`);
  }
}

console.error(`[esbuild-unpack] npm package matches (Phase 4): ${Object.keys(moduleMap).length} modules mapped to ${Object.keys(packageModules).length} packages`);

// ========== Phase 4b: Path-based npm Package Detection ==========
// esbuild bundle'lar bazen kaynak dosya path'lerini embed eder:
//   - file:///home/runner/.../node_modules/PACKAGE/...
//   - var __dirname = "/.../node_modules/PACKAGE/..."
//   - fileURLToPath("file:///.../node_modules/PACKAGE/...")
// Bu path'lerden paket adi cikartiyoruz (Phase 4'te bulunamayanlar icin)

const PATH_RE = /(?:node_modules\/)((?:@[a-zA-Z0-9_-]+\/)?[a-zA-Z0-9_.-]+)/g;
const SRC_PATH_RE = /(?:claude-cli-internal\/)(src\/[a-zA-Z0-9_./]+\.(?:ts|js))/g;

// Modul -> kaynak dosya path'i mapping'i (source recovery icin)
const moduleSourcePaths = {};

let pathDetectionCount = 0;
for (const [moduleId, modInfo] of detectedModules.entries()) {
  if (moduleMap[moduleId]) continue; // Zaten npm eslesmesi var

  try {
    const bodyCode = safeGenerate(modInfo.node, 50000);

    // node_modules/ path'lerinden paket adi cikar
    const pkgMatches = new Set();
    let pathMatch;
    PATH_RE.lastIndex = 0;
    while ((pathMatch = PATH_RE.exec(bodyCode)) !== null) {
      const pkgName = pathMatch[1];
      // .bin, .cache gibi meta dizinleri atla
      if (pkgName.startsWith(".")) continue;
      pkgMatches.add(pkgName);
    }

    if (pkgMatches.size === 1) {
      // Tek paket referansi -> yuksek guvenilirlik
      const pkg = [...pkgMatches][0];
      moduleMap[moduleId] = pkg;
      if (!packageModules[pkg]) packageModules[pkg] = [];
      packageModules[pkg].push(moduleId);
      pathDetectionCount++;
    } else if (pkgMatches.size > 1) {
      // Birden fazla paket referansi -> en cok tekrar edeni sec
      const pkgArr = [];
      PATH_RE.lastIndex = 0;
      while ((pathMatch = PATH_RE.exec(bodyCode)) !== null) {
        const p = pathMatch[1];
        if (!p.startsWith(".")) pkgArr.push(p);
      }
      const freq = {};
      for (const p of pkgArr) freq[p] = (freq[p] || 0) + 1;
      const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
      if (sorted[0] && sorted[0][1] >= 2) {
        const pkg = sorted[0][0];
        moduleMap[moduleId] = pkg;
        if (!packageModules[pkg]) packageModules[pkg] = [];
        packageModules[pkg].push(moduleId);
        pathDetectionCount++;
      }
    }

    // Kaynak dosya path'lerini topla (src/ altindaki .ts/.js dosyalari)
    SRC_PATH_RE.lastIndex = 0;
    let srcMatch;
    while ((srcMatch = SRC_PATH_RE.exec(bodyCode)) !== null) {
      if (!moduleSourcePaths[moduleId]) moduleSourcePaths[moduleId] = [];
      moduleSourcePaths[moduleId].push(srcMatch[1]);
    }
  } catch (err) {
    errors.push(`Path detection ${moduleId}: ${err.message}`);
  }
}

console.error(`[esbuild-unpack] Phase 4b: ${pathDetectionCount} modules matched via embedded paths, ${Object.keys(moduleSourcePaths).length} modules with source paths`);

// ========== Phase 4c: __dirname-based Detection ==========
// var __dirname = "/path/to/node_modules/PACKAGE/..."
const DIRNAME_RE = /__dirname\s*=\s*["']([^"']+)["']/g;
let dirnameDetectionCount = 0;

for (const [moduleId, modInfo] of detectedModules.entries()) {
  if (moduleMap[moduleId]) continue;

  try {
    // __dirname genellikle modülün basinda tanimlanir, ama buyuk modullerde
    // safeGenerate limiti yetmeyebilir. 50K'ya cikariyoruz.
    const bodyCode = safeGenerate(modInfo.node, 50000);
    DIRNAME_RE.lastIndex = 0;
    let dm;
    while ((dm = DIRNAME_RE.exec(bodyCode)) !== null) {
      const dirPath = dm[1];
      const nmIdx = dirPath.indexOf("node_modules/");
      if (nmIdx >= 0) {
        const afterNm = dirPath.slice(nmIdx + "node_modules/".length);
        // Scoped package: @scope/name veya regular: name
        let pkgName;
        if (afterNm.startsWith("@")) {
          const parts = afterNm.split("/");
          pkgName = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : parts[0];
        } else {
          pkgName = afterNm.split("/")[0];
        }
        if (pkgName && !pkgName.startsWith(".")) {
          moduleMap[moduleId] = pkgName;
          if (!packageModules[pkgName]) packageModules[pkgName] = [];
          packageModules[pkgName].push(moduleId);
          dirnameDetectionCount++;
          break;
        }
      }
    }
  } catch (err) {
    errors.push(`__dirname detection ${moduleId}: ${err.message}`);
  }
}

console.error(`[esbuild-unpack] Phase 4c: ${dirnameDetectionCount} modules matched via __dirname`);
console.error(`[esbuild-unpack] Total npm matches: ${Object.keys(moduleMap).length} modules -> ${Object.keys(packageModules).length} packages`);

// ========== Phase 5: Category-based Naming ==========
// moduleId -> anlamli dosya adi
function inferModuleName(moduleId, modInfo) {
  // npm paket eslesmesi varsa onu kullan
  if (moduleMap[moduleId]) {
    const pkgClean = moduleMap[moduleId].replace(/[@/]/g, "_").replace(/_+/g, "_").replace(/^_/, "");
    return `${pkgClean}__${moduleId}`;
  }

  // Icerik tabanli genel siniflandirma
  try {
    const bodyCode = safeGenerate(modInfo.node, 3000);

    if (bodyCode.includes("createElement") && bodyCode.includes("Component")) return `react_component__${moduleId}`;
    if (bodyCode.includes("jsx") || bodyCode.includes("Fragment")) return `jsx__${moduleId}`;
    if (bodyCode.includes("createServer") || bodyCode.includes("listen(")) return `server__${moduleId}`;
    if (bodyCode.includes("fetch(") || bodyCode.includes("XMLHttpRequest")) return `http_client__${moduleId}`;
    if (bodyCode.includes("createHash") || bodyCode.includes("createHmac")) return `crypto__${moduleId}`;
    if (bodyCode.includes("process.argv") || bodyCode.includes("commander")) return `cli__${moduleId}`;
    if (bodyCode.includes("readFile") || bodyCode.includes("writeFile")) return `file_ops__${moduleId}`;
    if (bodyCode.includes("readdir") || bodyCode.includes("mkdir")) return `dir_ops__${moduleId}`;
    if (bodyCode.includes("EventEmitter") || bodyCode.includes(".emit(")) return `events__${moduleId}`;
    if (bodyCode.includes("Readable") || bodyCode.includes("Transform")) return `stream__${moduleId}`;
    if (bodyCode.includes("Buffer.from") || bodyCode.includes("Buffer.alloc")) return `buffer__${moduleId}`;
    if (bodyCode.includes("child_process") || bodyCode.includes("execSync")) return `process__${moduleId}`;
    if (bodyCode.includes("process.env") && bodyCode.includes("config")) return `config__${moduleId}`;
    if (bodyCode.includes("console.log") && bodyCode.includes("console.error")) return `logger__${moduleId}`;
  } catch (_) {
    // generator hatasi - fallback
  }

  // Varsayilan: orijinal degisken ismi
  return `module__${moduleId}`;
}

// ========== Phase 6: Write Modules ==========
const moduleOutputs = [];
// macOS APFS case-insensitive FS icin dosya adi cakismasi onleme:
// usedFileNames lowercase olarak tutulur, boylece Module_A ve module_a cakismasi yakalanir
const usedFileNames = new Set();
function hasFileName(name) { return usedFileNames.has(name.toLowerCase()); }
function addFileName(name) { usedFileNames.add(name.toLowerCase()); }

for (const [moduleId, modInfo] of detectedModules.entries()) {
  try {
    const result = generate(modInfo.node, {
      comments: true,
      compact: false,
      concise: false,
    });
    const code = result.code;

    // Dosya adi
    let fileName = sanitizeFileName(inferModuleName(moduleId, modInfo));
    if (hasFileName(fileName)) {
      let suffix = 2;
      while (hasFileName(`${fileName}_${suffix}`)) suffix++;
      fileName = `${fileName}_${suffix}`;
    }
    addFileName(fileName);

    // Header
    const deps = [...modInfo.deps];
    const reqDeps = modInfo.requireDeps || [];
    const exportsStr = modInfo.exports.length > 0 ? modInfo.exports.join(", ") : "none";
    const esmAliases = modInfo.esmAliases || [];
    const npmPkg = moduleMap[moduleId] || "unknown";

    const srcPaths = moduleSourcePaths[moduleId] || [];
    const header = [
      `/**`,
      ` * Module: ${moduleId}`,
      ` * Type: ${modInfo.type}`,
      ` * npm package: ${npmPkg}`,
      ` * Exports: [${exportsStr}]`,
      ` * ESM aliases: [${esmAliases.join(", ")}]`,
      ` * Module dependencies: [${deps.join(", ")}]`,
      ` * Node.js requires: [${reqDeps.join(", ")}]`,
      ...(srcPaths.length > 0 ? [` * Source paths: [${srcPaths.join(", ")}]`] : []),
      ` * Lines: ${modInfo.startLine || "?"}-${modInfo.endLine || "?"}`,
      ` * Unpacked by Karadul esbuild-unpack v1.1`,
      ` */`,
      ``,
    ].join("\n");

    const moduleCode = header + code + "\n";
    const filePath = join(modulesDir, `${fileName}.js`);
    writeFileSync(filePath, moduleCode, "utf-8");

    moduleOutputs.push({
      id: moduleId,
      name: fileName,
      type: modInfo.type,
      file: `${fileName}.js`,
      size: Buffer.byteLength(moduleCode, "utf-8"),
      lines: code.split("\n").length,
      dependencies: deps,
      require_deps: reqDeps,
      exports: modInfo.exports,
      esm_aliases: esmAliases,
      npm_package: npmPkg,
    });
  } catch (err) {
    errors.push(`Module ${moduleId} yazma hata: ${err.message}`);
  }
}

// Lazy init modullerini de ayri yaz
for (const [lazyName, lazyInfo] of lazyModules.entries()) {
  try {
    const result = generate(lazyInfo.node, { comments: true, compact: false, concise: false });
    const code = result.code;
    const deps = [...lazyInfo.deps];

    const fileName = sanitizeFileName(`lazy__${lazyName}`);
    addFileName(fileName);

    const header = [
      `/**`,
      ` * Lazy Init Module: ${lazyName}`,
      ` * Type: ${lazyInfo.type}`,
      ` * Dependencies: [${deps.join(", ")}]`,
      ` * Unpacked by Karadul esbuild-unpack v1.0`,
      ` */`,
      ``,
    ].join("\n");

    const moduleCode = header + code + "\n";
    const filePath = join(modulesDir, `${fileName}.js`);
    writeFileSync(filePath, moduleCode, "utf-8");

    moduleOutputs.push({
      id: lazyName,
      name: fileName,
      type: lazyInfo.type,
      file: `${fileName}.js`,
      size: Buffer.byteLength(moduleCode, "utf-8"),
      lines: code.split("\n").length,
      dependencies: deps,
      npm_package: "lazy_init",
    });
  } catch (err) {
    errors.push(`Lazy module ${lazyName} yazma hata: ${err.message}`);
  }
}

// ========== Phase 6b: Write ESM alias modules ==========
// esmAliasMap: aliasName -> sourceModuleName (string)
// Bu alias'lar var Y = Q1(X(), 1) seklinde tanimlanir -- ESM interop wrapper'lari
// Dosya olarak yazilmazsa modul sayisi eksik kalir
for (const [aliasName, sourceName] of esmAliasMap.entries()) {
  try {
    // Dosya adi -- cakisma varsa suffix ekle (CJS loop'undaki gibi)
    let fileName = sanitizeFileName(`esm__${aliasName}`);
    if (hasFileName(fileName)) {
      let suffix = 2;
      while (hasFileName(`${fileName}_${suffix}`)) suffix++;
      fileName = `${fileName}_${suffix}`;
    }
    addFileName(fileName);

    // Kaynak modulun bilgilerini al (varsa)
    const sourceInfo = detectedModules.get(sourceName);
    const npmPkg = moduleMap[sourceName] || "esm_alias";

    const header = [
      `/**`,
      ` * ESM Alias: ${aliasName}`,
      ` * Source module: ${sourceName}`,
      ` * Type: esm_reexport`,
      ` * npm package: ${npmPkg}`,
      ` * Unpacked by Karadul esbuild-unpack v1.0`,
      ` */`,
      ``,
    ].join("\n");

    // Eger kaynak modulun AST node'u varsa, onu generate et
    // Yoksa sembolik re-export wrapper yaz
    let code;
    if (sourceInfo && sourceInfo.node) {
      try {
        const result = generate(sourceInfo.node, { comments: true, compact: false });
        code = result.code;
      } catch (_genErr) {
        code = `// ESM re-export from ${sourceName}\n// Generator error, symbolic reference\nexport default ${sourceName};\n`;
      }
    } else {
      // Kaynak modul CJS olarak tespit edilmemis olabilir (baska bir ESM alias, lazy, vb.)
      // Sembolik wrapper yaz
      code = `// ESM re-export wrapper\n// Source: ${sourceName}\nexport * from "./${sourceName}";\nexport { default } from "./${sourceName}";\n`;
    }

    const moduleCode = header + code + "\n";
    const filePath = join(modulesDir, `${fileName}.js`);
    writeFileSync(filePath, moduleCode, "utf-8");

    moduleOutputs.push({
      id: aliasName,
      name: fileName,
      type: "esm_alias",
      file: `${fileName}.js`,
      size: Buffer.byteLength(moduleCode, "utf-8"),
      lines: code.split("\n").length,
      dependencies: [sourceName],
      npm_package: npmPkg,
    });
  } catch (err) {
    errors.push(`ESM alias ${aliasName} yazma hata: ${err.message}`);
  }
}

console.error(`[esbuild-unpack] Phase 6b: ${esmAliasMap.size} ESM alias modules written`);

// ========== Phase 6c: Write orphan re-export modules ==========
// reExports: targetVar -> [{name, ref}, ...]
// Eger targetVar bir CJS modul degilse (detectedModules'da yoksa),
// bu re-export bilgisi hicbir dosyaya yazilmamis demektir.
// Bunlari ayri dosya olarak yaz.
for (const [targetVar, exportList] of reExports.entries()) {
  try {
    // Eger targetVar zaten bir CJS modul ise, exports bilgisi o modulun dosyasinda zaten var
    if (detectedModules.has(targetVar)) continue;

    // Dosya adi -- cakisma varsa suffix ekle (CJS loop'undaki gibi)
    let fileName = sanitizeFileName(`reexport__${targetVar}`);
    if (hasFileName(fileName)) {
      let suffix = 2;
      while (hasFileName(`${fileName}_${suffix}`)) suffix++;
      fileName = `${fileName}_${suffix}`;
    }
    addFileName(fileName);

    const header = [
      `/**`,
      ` * Re-export Module: ${targetVar}`,
      ` * Type: esm_reexport_target`,
      ` * Exports: [${exportList.map(e => e.name).join(", ")}]`,
      ` * Unpacked by Karadul esbuild-unpack v1.0`,
      ` */`,
      ``,
    ].join("\n");

    // Export listesinden kod uret -- lb() helper'in yaptigi defineProperty'leri acik yaz
    const propDefs = exportList.map(e => {
      const getter = e.ref ? `() => ${e.ref}` : `() => undefined /* ref not resolved */`;
      return `  ${e.name}: { get: ${getter}, enumerable: true }`;
    });

    const code = [
      `// Re-export definitions (lb() pattern)`,
      `// Original: ${reExportName || "lb"}(${targetVar}, { ... })`,
      `const ${targetVar} = {};`,
      `Object.defineProperties(${targetVar}, {`,
      propDefs.join(",\n"),
      `});`,
      `export default ${targetVar};`,
      ``,
    ].join("\n");

    const moduleCode = header + code + "\n";
    const filePath = join(modulesDir, `${fileName}.js`);
    writeFileSync(filePath, moduleCode, "utf-8");

    // Export referanslarindan dependency listesi cikar
    const deps = exportList
      .filter(e => e.ref)
      .map(e => e.ref)
      .filter((v, i, a) => a.indexOf(v) === i);  // unique

    moduleOutputs.push({
      id: targetVar,
      name: fileName,
      type: "esm_reexport_target",
      file: `${fileName}.js`,
      size: Buffer.byteLength(moduleCode, "utf-8"),
      lines: code.split("\n").length,
      dependencies: deps,
      exports: exportList.map(e => e.name),
      npm_package: moduleMap[targetVar] || "reexport",
    });
  } catch (err) {
    errors.push(`Re-export module ${targetVar} yazma hata: ${err.message}`);
  }
}

console.error(`[esbuild-unpack] Phase 6c: orphan re-export modules written`);

// ========== Phase 7: Write module_map.json ==========
try {
  const mapPath = join(outputDir, "module_map.json");
  const mapData = {
    total_modules: detectedModules.size,
    total_esm_aliases: esmAliasMap.size,
    total_re_export_targets: reExports.size,
    total_files_written: moduleOutputs.length,
    mapped_modules: Object.keys(moduleMap).length,
    packages: {},
    module_to_package: moduleMap,
    esm_aliases: Object.fromEntries(esmAliasMap),
    esm_alias_files: moduleOutputs.filter(m => m.type === "esm_alias").map(m => ({ id: m.id, file: m.file, source: m.dependencies[0] })),
    reexport_files: moduleOutputs.filter(m => m.type === "esm_reexport_target").map(m => ({ id: m.id, file: m.file, exports: m.exports })),
    source_paths: moduleSourcePaths,
    re_exports: {},
  };

  // Package -> modules grubu
  for (const [pkg, mods] of Object.entries(packageModules)) {
    mapData.packages[pkg] = {
      module_count: mods.length,
      modules: mods,
    };
  }

  // Re-export bilgileri
  for (const [targetVar, exports] of reExports.entries()) {
    mapData.re_exports[targetVar] = exports;
  }

  writeFileSync(mapPath, JSON.stringify(mapData, null, 2), "utf-8");
} catch (err) {
  errors.push(`module_map.json yazma hata: ${err.message}`);
}

// ========== Phase 8: Write dependency_graph.json ==========
const depGraph = {};
for (const [moduleId, modInfo] of detectedModules.entries()) {
  depGraph[moduleId] = {
    deps: [...modInfo.deps],
    require_deps: modInfo.requireDeps || [],
    esm_aliases: modInfo.esmAliases || [],
    npm_package: moduleMap[moduleId] || null,
  };
}

// Lazy init'leri de ekle
for (const [lazyName, lazyInfo] of lazyModules.entries()) {
  depGraph[lazyName] = {
    deps: [...lazyInfo.deps],
    type: "lazy_init",
  };
}

// ESM alias'lari da ekle
for (const [aliasName, sourceName] of esmAliasMap.entries()) {
  depGraph[aliasName] = {
    deps: [sourceName],
    type: "esm_alias",
    source: sourceName,
    npm_package: moduleMap[sourceName] || null,
  };
}

// Orphan re-export'lari da ekle (CJS modulle eslesmeyenler)
for (const [targetVar, exportList] of reExports.entries()) {
  if (detectedModules.has(targetVar)) continue;  // zaten CJS olarak eklendi
  if (depGraph[targetVar]) continue;  // zaten eklendiyse atla
  const deps = exportList.filter(e => e.ref).map(e => e.ref).filter((v, i, a) => a.indexOf(v) === i);
  depGraph[targetVar] = {
    deps: deps,
    type: "esm_reexport_target",
    exports: exportList.map(e => e.name),
  };
}

try {
  const graphPath = join(outputDir, "dependency_graph.json");
  writeFileSync(graphPath, JSON.stringify({
    bundle_format: "esbuild",
    total_modules: detectedModules.size,
    total_lazy: lazyModules.size,
    total_esm_aliases: esmAliasMap.size,
    total_re_exports: reExports.size,
    helpers: {
      cjs_wrapper: cjsWrapperName,
      esm_interop: esmInteropName,
      re_export: reExportName,
      lazy_init: lazyInitName,
      require_alias: requireAliasName,
    },
    graph: depGraph,
  }, null, 2), "utf-8");
} catch (err) {
  errors.push(`dependency_graph.json yazma hata: ${err.message}`);
}

// ========== Result ==========
// Yazilan dosya tiplerine gore sayi
const writtenByType = {};
for (const m of moduleOutputs) {
  const t = m.type || "unknown";
  writtenByType[t] = (writtenByType[t] || 0) + 1;
}

const result = {
  success: moduleOutputs.length > 0,
  bundle_format: "esbuild",
  total_detected: detectedModules.size + lazyModules.size + esmAliasMap.size,
  total_cjs_modules: detectedModules.size,
  total_lazy_inits: lazyModules.size,
  total_esm_aliases: esmAliasMap.size,
  total_re_exports: reExports.size,
  npm_packages_detected: Object.keys(packageModules).length,
  npm_packages: Object.keys(packageModules),
  path_detected_modules: pathDetectionCount,
  dirname_detected_modules: dirnameDetectionCount,
  source_path_modules: Object.keys(moduleSourcePaths).length,
  module_map_summary: Object.entries(packageModules).map(([pkg, mods]) => `${pkg} (${mods.length})`),
  helpers: {
    cjs_wrapper: cjsWrapperName,
    esm_interop: esmInteropName,
    re_export: reExportName,
    lazy_init: lazyInitName,
    require_alias: requireAliasName,
  },
  modules_written: moduleOutputs.length,
  written_by_type: writtenByType,
  file_size: fileSize,
  errors: errors.slice(0, 50),  // ilk 50 hata
};

emit(result);

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
  return name
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .slice(0, 80) || "unnamed";
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isNodeBuiltin(moduleName) {
  const builtins = new Set([
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers",
    "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
    "worker_threads", "zlib",
    // node: prefix
    "node:assert", "node:buffer", "node:child_process", "node:cluster",
    "node:console", "node:constants", "node:crypto", "node:dgram",
    "node:diagnostics_channel", "node:dns", "node:domain", "node:events",
    "node:fs", "node:http", "node:http2", "node:https", "node:inspector",
    "node:module", "node:net", "node:os", "node:path", "node:perf_hooks",
    "node:process", "node:punycode", "node:querystring", "node:readline",
    "node:repl", "node:stream", "node:string_decoder", "node:sys",
    "node:timers", "node:tls", "node:trace_events", "node:tty", "node:url",
    "node:util", "node:v8", "node:vm", "node:wasi", "node:worker_threads",
    "node:zlib",
  ]);
  return builtins.has(moduleName) || moduleName.startsWith("node:");
}
