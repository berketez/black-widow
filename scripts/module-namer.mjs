#!/usr/bin/env node
/**
 * module-namer.mjs -- Webpack/esbuild Module Naming from Content Analysis
 *
 * Her modul dosyasini okur, iceriginden anlamli isim cikarir:
 *   1. Ilk export edilen class/function ismi
 *   2. require() ile import edilen npm paketi
 *   3. En uzun / en anlamli string literal
 *   4. Ozel pattern tespiti (highlight.js lang, semver, aws-sdk, vb.)
 *
 * Cikti: JSON manifest + rename edilmis dosyalar
 *
 * Kullanim:
 *   node module-namer.mjs <modules-dir> [--apply] [--manifest-only]
 */

import { readFileSync, writeFileSync, readdirSync, renameSync, existsSync, mkdirSync } from "node:fs";
import { resolve, join, basename, dirname } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;

const args = process.argv.slice(2);
const modulesDir = resolve(args[0] || ".");
const applyRename = args.includes("--apply");
const manifestOnly = args.includes("--manifest-only");

// ---------- Known Package Patterns ----------
const KNOWN_PACKAGES = {
  // AWS SDK
  "aws-sdk": "aws_sdk",
  "@aws-sdk": "aws_sdk",
  "@aws-crypto": "aws_crypto",
  "@smithy": "smithy",
  // Semver
  "semver": "semver",
  // Highlight.js - language detection
  "highlight": "hljs",
  // Node built-ins
  "fs": "fs_module",
  "path": "path_module",
  "os": "os_module",
  "http": "http_module",
  "https": "https_module",
  "crypto": "crypto_module",
  "stream": "stream_module",
  "events": "events_module",
  "util": "util_module",
  "net": "net_module",
  "dns": "dns_module",
  "tls": "tls_module",
  "zlib": "zlib_module",
  "child_process": "child_process_module",
  "buffer": "buffer_module",
  "url": "url_module",
  "querystring": "querystring_module",
  "assert": "assert_module",
};

// Highlight.js language name -> module name
const HLJS_LANGUAGES = new Set([
  "1c","abnf","accesslog","actionscript","ada","angelscript","apache","applescript",
  "arcade","arduino","armasm","asciidoc","aspectj","autohotkey","autoit","avrasm",
  "awk","axapta","bash","basic","bnf","brainfuck","c","cal","capnproto","ceylon",
  "clean","clojure","cmake","coffeescript","coq","cos","cpp","crmsh","crystal",
  "csharp","csp","css","d","dart","delphi","diff","django","dns","dockerfile",
  "dos","dsconfig","dts","dust","ebnf","elixir","elm","erb","erlang","excel",
  "fix","flix","fortran","fsharp","gams","gauss","gcode","gherkin","glsl","gml",
  "go","golo","gradle","graphql","groovy","haml","handlebars","haskell","haxe",
  "hsp","http","hy","inform7","ini","irpf90","isbl","java","javascript","json",
  "julia","kotlin","lasso","latex","ldif","leaf","less","lisp","livecodeserver",
  "livescript","llvm","lsl","lua","makefile","markdown","mathematica","matlab",
  "maxima","mel","mercury","mipsasm","mizar","mojolicious","monkey","moonscript",
  "n1ql","nestedtext","nginx","nim","nix","objectivec","ocaml","openscad",
  "oxygene","parser3","perl","pf","pgsql","php","plaintext","pony","powershell",
  "processing","profile","prolog","properties","protobuf","puppet","purebasic",
  "python","q","qml","r","reasonml","rib","roboconf","routeros","rsl","ruby",
  "ruleslanguage","rust","sas","scala","scheme","scilab","scss","shell","smali",
  "smalltalk","sml","sqf","sql","stan","stata","step21","stylus","subunit",
  "swift","taggerscript","tap","tcl","thrift","tp","twig","typescript","vala",
  "vbnet","vbscript","verilog","vhdl","vim","wasm","wren","x86asm","xl","xml",
  "xquery","yaml","zephir",
]);

function analyzeModule(filePath) {
  const source = readFileSync(filePath, "utf-8");
  const fileName = basename(filePath, ".js");

  const result = {
    originalName: fileName,
    newName: null,
    category: "unknown",
    confidence: 0,
    signals: [],
  };

  // 1. Check header comment for clues
  const headerMatch = source.match(/\/\*\*[\s\S]*?\*\//);
  const depMatch = source.match(/Dependencies:\s*\[([^\]]*)\]/);
  const deps = depMatch ? depMatch[1].split(",").map(s => s.trim()).filter(Boolean) : [];

  // 2. Parse AST (with error recovery for partial files)
  let ast;
  try {
    ast = parse(source, {
      sourceType: "unambiguous",
      allowImportExportEverywhere: true,
      allowReturnOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowUndeclaredExports: true,
      errorRecovery: true,
      plugins: ["jsx","typescript","decorators-legacy","classProperties","classPrivateProperties",
        "classPrivateMethods","dynamicImport","optionalChaining","nullishCoalescingOperator",
        "exportDefaultFrom","exportNamespaceFrom","topLevelAwait","importMeta"],
    });
  } catch (e) {
    // Fallback: string-based analysis only
    return analyzeStringsOnly(source, fileName, result);
  }

  // Collect signals from AST
  const signals = {
    exportedClasses: [],
    exportedFunctions: [],
    exportedNames: [],
    requireCalls: [],
    classDeclarations: [],
    functionDeclarations: [],
    stringLiterals: [],
    nameProperty: null,       // { name: "..." } pattern
    languageName: null,        // highlight.js language
    definedProperties: [],     // Object.defineProperty or exports.X
    protoAssignments: [],      // X.prototype.method
  };

  try {
    traverse(ast, {
      // Class declarations
      ClassDeclaration(path) {
        if (path.node.id?.name) {
          signals.classDeclarations.push(path.node.id.name);
        }
      },

      // Function declarations
      FunctionDeclaration(path) {
        if (path.node.id?.name && path.node.id.name.length > 3) {
          signals.functionDeclarations.push(path.node.id.name);
        }
      },

      // Assignment to exports
      AssignmentExpression(path) {
        const left = path.node.left;
        const right = path.node.right;

        // module.exports = X or exports.X = Y
        if (t.isMemberExpression(left)) {
          if (t.isIdentifier(left.property)) {
            const prop = left.property.name;
            // module.exports = ClassName
            if (prop === "exports") {
              if (t.isIdentifier(right) && right.name.length > 3) {
                signals.exportedNames.push(right.name);
              }
              if (t.isClassExpression(right) && right.id?.name) {
                signals.exportedClasses.push(right.id.name);
              }
              if (t.isFunctionExpression(right) && right.id?.name) {
                signals.exportedFunctions.push(right.id.name);
              }
            }
            // exports.ClassName = ...
            if (t.isMemberExpression(left.object) &&
                t.isIdentifier(left.object.property) &&
                left.object.property.name === "exports") {
              if (prop.length > 3 && prop[0] === prop[0].toUpperCase()) {
                signals.exportedClasses.push(prop);
              } else if (prop.length > 3) {
                signals.definedProperties.push(prop);
              }
            }
            // X.exports.Y = ...
            if (t.isIdentifier(left.object) && /exports?/.test(left.object.name)) {
              if (prop.length > 3) {
                signals.definedProperties.push(prop);
              }
            }
          }

          // X.prototype.method = ...
          if (t.isMemberExpression(left.object) &&
              t.isIdentifier(left.object.property) &&
              left.object.property.name === "prototype") {
            if (t.isIdentifier(left.object.object)) {
              signals.protoAssignments.push(left.object.object.name);
            }
          }
        }
      },

      // Object.defineProperty(exports, "X", ...)
      CallExpression(path) {
        const callee = path.node.callee;
        const args = path.node.arguments;

        // require("package-name")
        if (t.isIdentifier(callee) && callee.name === "require" &&
            args[0] && t.isStringLiteral(args[0])) {
          signals.requireCalls.push(args[0].value);
        }

        // X() calls where X looks like require alias
        if (t.isIdentifier(callee) && args.length === 0) {
          // function call with no args, might be a require wrapper
        }

        // Object.defineProperty(exports, "name", { value: ... })
        if (t.isMemberExpression(callee) &&
            t.isIdentifier(callee.object, { name: "Object" }) &&
            t.isIdentifier(callee.property, { name: "defineProperty" }) &&
            args[1] && t.isStringLiteral(args[1])) {
          const propName = args[1].value;
          if (propName !== "__esModule" && propName.length > 3) {
            signals.definedProperties.push(propName);
          }
        }
      },

      // String literals (collect interesting ones)
      StringLiteral(path) {
        const val = path.node.value;
        if (val.length < 3 || val.length > 200) return;
        // Skip common junk
        if (/^[.\/\\@#]/.test(val)) return;
        if (/^\d+\.\d+/.test(val)) return; // version numbers
        signals.stringLiterals.push(val);
      },

      // Object property { name: "..." }
      ObjectProperty(path) {
        if (t.isIdentifier(path.node.key, { name: "name" }) &&
            t.isStringLiteral(path.node.value)) {
          const val = path.node.value.value;
          if (val.length > 1 && val.length < 60) {
            if (!signals.nameProperty) signals.nameProperty = val;
          }
        }
        // { aliases: [...] } - highlight.js pattern
        if (t.isIdentifier(path.node.key, { name: "aliases" }) &&
            t.isArrayExpression(path.node.value)) {
          const aliases = path.node.value.elements
            .filter(e => t.isStringLiteral(e))
            .map(e => e.value);
          if (aliases.length > 0 && signals.nameProperty) {
            const lang = signals.nameProperty.toLowerCase();
            if (HLJS_LANGUAGES.has(lang)) {
              signals.languageName = lang;
            }
          }
        }
      },
    });
  } catch (e) {
    // Traverse error - fall back to what we have
  }

  // ---------- Decision Logic ----------

  // Priority 1: Highlight.js language module
  if (signals.languageName) {
    result.newName = `hljs_lang_${signals.languageName}`;
    result.category = "hljs_language";
    result.confidence = 0.95;
    result.signals.push(`hljs language: ${signals.languageName}`);
    return result;
  }

  // Check name property for hljs pattern even without aliases
  if (signals.nameProperty && source.includes("case_insensitive") &&
      (source.includes("keywords") || source.includes("contains"))) {
    const lang = signals.nameProperty.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (lang.length > 0 && lang.length < 30) {
      result.newName = `hljs_lang_${lang}`;
      result.category = "hljs_language";
      result.confidence = 0.90;
      result.signals.push(`hljs language (name prop): ${signals.nameProperty}`);
      return result;
    }
  }

  // Priority 2: Exported class name
  if (signals.exportedClasses.length > 0) {
    const cls = signals.exportedClasses[0];
    const name = toSnakeCase(cls);
    if (name.length > 2) {
      result.newName = name;
      result.category = "class_export";
      result.confidence = 0.90;
      result.signals.push(`exported class: ${cls}`);
      return result;
    }
  }

  // Priority 3: Exported function name
  if (signals.exportedFunctions.length > 0) {
    const fn = signals.exportedFunctions[0];
    const name = toSnakeCase(fn);
    if (name.length > 2) {
      result.newName = name;
      result.category = "function_export";
      result.confidence = 0.85;
      result.signals.push(`exported function: ${fn}`);
      return result;
    }
  }

  // Priority 4: Exported name (identifier)
  if (signals.exportedNames.length > 0) {
    const n = signals.exportedNames[0];
    if (n.length > 3) {
      result.newName = toSnakeCase(n);
      result.category = "name_export";
      result.confidence = 0.80;
      result.signals.push(`exported name: ${n}`);
      return result;
    }
  }

  // Priority 5: Prototype assignments (class pattern)
  if (signals.protoAssignments.length > 0) {
    const counts = {};
    signals.protoAssignments.forEach(n => counts[n] = (counts[n]||0)+1);
    const top = Object.entries(counts).sort((a,b) => b[1]-a[1])[0];
    if (top && top[0].length > 3) {
      result.newName = toSnakeCase(top[0]);
      result.category = "class_prototype";
      result.confidence = 0.75;
      result.signals.push(`prototype class: ${top[0]} (${top[1]} methods)`);
      return result;
    }
  }

  // Priority 6: Class declarations
  if (signals.classDeclarations.length > 0) {
    const cls = signals.classDeclarations[0];
    if (cls.length > 3) {
      result.newName = toSnakeCase(cls);
      result.category = "class_declaration";
      result.confidence = 0.75;
      result.signals.push(`class declaration: ${cls}`);
      return result;
    }
  }

  // Priority 7: Function declarations (non-trivial)
  if (signals.functionDeclarations.length > 0) {
    // Pick the longest, most descriptive name
    const sorted = [...signals.functionDeclarations].sort((a,b) => b.length - a.length);
    const fn = sorted[0];
    if (fn.length > 4) {
      result.newName = toSnakeCase(fn);
      result.category = "function_declaration";
      result.confidence = 0.65;
      result.signals.push(`function declaration: ${fn}`);
      return result;
    }
  }

  // Priority 8: defineProperty exports
  if (signals.definedProperties.length > 0) {
    // Multiple exports -> pick the most descriptive
    const meaningful = signals.definedProperties.filter(p => p.length > 4);
    if (meaningful.length > 0) {
      // If all start with same prefix, use that
      const prefix = commonPrefix(meaningful);
      if (prefix.length > 4) {
        result.newName = toSnakeCase(prefix);
      } else {
        result.newName = toSnakeCase(meaningful[0]);
      }
      result.category = "property_exports";
      result.confidence = 0.60;
      result.signals.push(`defined properties: ${meaningful.slice(0,5).join(", ")}`);
      return result;
    }
  }

  // Priority 9: require() calls -> infer category
  if (signals.requireCalls.length > 0) {
    // External package detection
    for (const req of signals.requireCalls) {
      for (const [pkg, name] of Object.entries(KNOWN_PACKAGES)) {
        if (req === pkg || req.startsWith(pkg + "/")) {
          result.newName = `${name}_util`;
          result.category = "package_related";
          result.confidence = 0.55;
          result.signals.push(`requires: ${req}`);
          return result;
        }
      }
    }
  }

  // Priority 10: Semver-related patterns
  if (source.includes("NUMERICIDENTIFIER") || source.includes("MAINVERSION") ||
      source.includes("PRERELEASE") || source.includes("semver")) {
    result.newName = "semver_" + fileName;
    result.category = "semver";
    result.confidence = 0.80;
    result.signals.push("semver pattern detected");
    return result;
  }

  // Priority 11: Name property (generic)
  if (signals.nameProperty && signals.nameProperty.length > 2) {
    const cleaned = signals.nameProperty.toLowerCase().replace(/[^a-z0-9_]/g, "_").replace(/_+/g, "_").replace(/^_|_$/g, "");
    if (cleaned.length > 2 && cleaned.length < 40) {
      result.newName = cleaned;
      result.category = "name_property";
      result.confidence = 0.50;
      result.signals.push(`name property: ${signals.nameProperty}`);
      return result;
    }
  }

  // Priority 12: String-based heuristics
  return analyzeStringsOnly(source, fileName, result);
}

function analyzeStringsOnly(source, fileName, result) {
  // Highlight.js language (missed by AST - e.g. pycon/python-repl style)
  if (source.includes("subLanguage") || (source.includes("aliases") && source.includes("className"))) {
    const nameMatch = source.match(/name:\s*"([^"]+)"/);
    if (nameMatch) {
      const lang = nameMatch[1].toLowerCase().replace(/[^a-z0-9]/g, "");
      if (lang.length > 0 && lang.length < 30) {
        result.newName = `hljs_lang_${lang}`;
        result.category = "hljs_language";
        result.confidence = 0.80;
        result.signals.push(`hljs language (string match): ${nameMatch[1]}`);
        return result;
      }
    }
  }

  // Ajv / JSON Schema validator patterns
  if (source.includes("keyword") && (source.includes("schemaType") || source.includes("$data"))) {
    const kwMatch = source.match(/keyword:\s*"([^"]+)"/);
    if (kwMatch) {
      result.newName = `ajv_keyword_${kwMatch[1]}`;
      result.category = "ajv_keyword";
      result.confidence = 0.80;
      result.signals.push(`Ajv keyword: ${kwMatch[1]}`);
      return result;
    }
  }
  if (source.includes("discriminator") && source.includes("DiscrError")) {
    result.newName = `ajv_discriminator`;
    result.category = "ajv_keyword";
    result.confidence = 0.75;
    result.signals.push("Ajv discriminator keyword");
    return result;
  }
  if (source.includes("Ajv") || (source.includes("addSchema") && source.includes("compile"))) {
    result.newName = `ajv_core_${fileName}`;
    result.category = "ajv";
    result.confidence = 0.65;
    result.signals.push("Ajv core pattern");
    return result;
  }

  // AWS SDK patterns
  if (source.includes("aws-sdk") || source.includes("@aws-sdk") || source.includes("AWS.")) {
    result.newName = `aws_${fileName}`;
    result.category = "aws_sdk";
    result.confidence = 0.50;
    result.signals.push("AWS SDK pattern");
    return result;
  }
  // Smithy / AWS service model
  if (source.includes("Smithy") || source.includes("smithy") || source.includes("ServiceException")) {
    result.newName = `smithy_${fileName}`;
    result.category = "smithy";
    result.confidence = 0.55;
    result.signals.push("Smithy pattern");
    return result;
  }

  // Crypto patterns
  if (source.includes("SHA-256") || source.includes("sha256") || source.includes("SHA256") || source.includes("Sha256")) {
    result.newName = `crypto_sha256_${fileName}`;
    result.category = "crypto";
    result.confidence = 0.60;
    result.signals.push("SHA-256 pattern");
    return result;
  }
  if (source.includes("HMAC") || source.includes("createHmac")) {
    result.newName = `crypto_hmac_${fileName}`;
    result.category = "crypto";
    result.confidence = 0.55;
    result.signals.push("HMAC pattern");
    return result;
  }
  if (source.includes("RawSha256") || source.includes("convertToBuffer") || source.includes("isEmptyData")) {
    result.newName = `crypto_util_${fileName}`;
    result.category = "crypto";
    result.confidence = 0.55;
    result.signals.push("Crypto utility pattern");
    return result;
  }

  // Microsoft tslib / TypeScript helpers
  if (source.includes("__extends") || source.includes("__assign") || source.includes("__decorate") ||
      source.includes("__awaiter") || source.includes("__generator")) {
    result.newName = `tslib_helpers_${fileName}`;
    result.category = "tslib";
    result.confidence = 0.70;
    result.signals.push("TypeScript helpers (tslib)");
    return result;
  }
  // Microsoft copyright = tslib
  if (source.includes("Microsoft Corporation") && source.includes("Permission to use")) {
    result.newName = `tslib_${fileName}`;
    result.category = "tslib";
    result.confidence = 0.65;
    result.signals.push("Microsoft tslib license");
    return result;
  }

  // STS / Credential Provider
  if (source.includes("AssumeRole") || source.includes("GetSessionToken") || source.includes("credentialProvider")) {
    result.newName = `aws_sts_${fileName}`;
    result.category = "aws_sts";
    result.confidence = 0.60;
    result.signals.push("AWS STS/credential pattern");
    return result;
  }

  // Endpoint / Region resolver
  if (source.includes("endpointUrl") || source.includes("regionConfig") || source.includes("getRegionInfo")) {
    result.newName = `aws_endpoint_${fileName}`;
    result.category = "aws_endpoint";
    result.confidence = 0.55;
    result.signals.push("AWS endpoint resolver");
    return result;
  }

  // HTTP/URL patterns
  if (source.includes("HTTP/1.1") || source.includes("Content-Type") || source.includes("application/json")) {
    if (source.includes("request") || source.includes("Request")) {
      result.newName = `http_request_${fileName}`;
    } else if (source.includes("response") || source.includes("Response")) {
      result.newName = `http_response_${fileName}`;
    } else {
      result.newName = `http_${fileName}`;
    }
    result.category = "http";
    result.confidence = 0.45;
    result.signals.push("HTTP pattern");
    return result;
  }

  // XML/HTML patterns
  if (source.includes("createElement") || source.includes("innerHTML") || source.includes("<!DOCTYPE")) {
    result.newName = `dom_${fileName}`;
    result.category = "dom";
    result.confidence = 0.40;
    result.signals.push("DOM pattern");
    return result;
  }

  // JSON/YAML patterns
  if (source.includes("JSON.parse") && source.includes("JSON.stringify")) {
    result.newName = `json_util_${fileName}`;
    result.category = "json";
    result.confidence = 0.40;
    result.signals.push("JSON util pattern");
    return result;
  }

  // Event emitter / EventTarget
  if (source.includes("EventEmitter") || source.includes("addListener") || source.includes("removeAllListeners")) {
    result.newName = `event_emitter_${fileName}`;
    result.category = "events";
    result.confidence = 0.45;
    result.signals.push("EventEmitter pattern");
    return result;
  }

  // Buffer / Stream patterns
  if (source.includes("createReadStream") || source.includes("createWriteStream") || source.includes("pipe(")) {
    result.newName = `stream_${fileName}`;
    result.category = "stream";
    result.confidence = 0.45;
    result.signals.push("Stream pattern");
    return result;
  }

  // Retry / backoff
  if (source.includes("retryCount") || source.includes("maxRetries") || source.includes("exponentialBackoff") ||
      (source.includes("retry") && source.includes("delay"))) {
    result.newName = `retry_${fileName}`;
    result.category = "retry";
    result.confidence = 0.50;
    result.signals.push("Retry/backoff pattern");
    return result;
  }

  // Middleware / plugin pattern
  if (source.includes("middleware") && source.includes("stack")) {
    result.newName = `middleware_${fileName}`;
    result.category = "middleware";
    result.confidence = 0.45;
    result.signals.push("Middleware stack pattern");
    return result;
  }

  // Serialization / deserialization
  if (source.includes("serialize") || source.includes("deserialize") ||
      source.includes("Serialize") || source.includes("Deserialize")) {
    result.newName = `serde_${fileName}`;
    result.category = "serialization";
    result.confidence = 0.50;
    result.signals.push("Serialization pattern");
    return result;
  }

  // Protocol/command pattern (AWS SDK v3 style)
  if (source.includes("Command") && source.includes("input") && source.includes("output")) {
    result.newName = `command_${fileName}`;
    result.category = "command";
    result.confidence = 0.50;
    result.signals.push("Command pattern");
    return result;
  }

  // Error class pattern
  if (source.includes("Error.call") || source.includes("Error.captureStackTrace") ||
      (source.includes("this.name") && source.includes("this.message"))) {
    result.newName = `error_${fileName}`;
    result.category = "error";
    result.confidence = 0.50;
    result.signals.push("Custom error class");
    return result;
  }

  // Regex heavy module
  const regexCount = (source.match(/new RegExp\(/g) || []).length;
  if (regexCount > 5) {
    result.newName = `regex_${fileName}`;
    result.category = "regex";
    result.confidence = 0.35;
    result.signals.push(`${regexCount} RegExp instances`);
    return result;
  }

  // Validation patterns (generic)
  if (source.includes("validate") && source.includes("errors")) {
    result.newName = `validator_${fileName}`;
    result.category = "validation";
    result.confidence = 0.40;
    result.signals.push("Validation pattern");
    return result;
  }

  // Config / options pattern
  if ((source.match(/config/gi) || []).length > 5 && source.includes("defaults")) {
    result.newName = `config_${fileName}`;
    result.category = "config";
    result.confidence = 0.35;
    result.signals.push("Configuration pattern");
    return result;
  }

  // Logger / logging
  if (source.includes("logger") && (source.includes("debug") || source.includes("warn") || source.includes("info"))) {
    result.newName = `logger_${fileName}`;
    result.category = "logging";
    result.confidence = 0.40;
    result.signals.push("Logger pattern");
    return result;
  }

  // Utility detection: short module with simple operations
  const lines = source.split("\n").length;
  if (lines < 50) {
    // Check for simple utility exports
    const exportMatch = source.match(/exports\.(\w+)\s*=/g);
    if (exportMatch && exportMatch.length === 1) {
      const name = exportMatch[0].match(/exports\.(\w+)/)[1];
      if (name.length > 3) {
        result.newName = `util_${toSnakeCase(name)}`;
        result.category = "small_util";
        result.confidence = 0.40;
        result.signals.push(`small utility exporting: ${name}`);
        return result;
      }
    }
  }

  // No match
  result.newName = null;
  result.category = "unknown";
  result.confidence = 0;
  return result;
}

// ---------- Helpers ----------

function toSnakeCase(str) {
  // CamelCase -> snake_case, but keep short acronyms
  return str
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "");
}

function commonPrefix(strings) {
  if (strings.length === 0) return "";
  let prefix = strings[0];
  for (let i = 1; i < strings.length; i++) {
    while (!strings[i].startsWith(prefix)) {
      prefix = prefix.slice(0, -1);
      if (prefix.length === 0) return "";
    }
  }
  return prefix;
}

// ---------- Main ----------
const files = readdirSync(modulesDir).filter(f => f.endsWith(".js")).sort();
console.error(`[module-namer] Analyzing ${files.length} modules in ${modulesDir}...`);

const manifest = [];
const nameCounts = {};
let namedCount = 0;
let totalCount = 0;

for (const file of files) {
  const filePath = join(modulesDir, file);
  totalCount++;

  try {
    const result = analyzeModule(filePath);

    if (result.newName) {
      // Deduplicate names
      const base = result.newName;
      if (nameCounts[base] === undefined) {
        nameCounts[base] = 0;
      } else {
        nameCounts[base]++;
        result.newName = `${base}_${nameCounts[base]}`;
      }
      namedCount++;
    }

    manifest.push(result);
  } catch (e) {
    manifest.push({
      originalName: basename(file, ".js"),
      newName: null,
      category: "error",
      confidence: 0,
      signals: [`Error: ${e.message}`],
    });
  }

  if (totalCount % 100 === 0) {
    console.error(`  [${totalCount}/${files.length}] ${namedCount} named so far...`);
  }
}

// ---------- Summary ----------
const categories = {};
manifest.forEach(m => {
  categories[m.category] = (categories[m.category] || 0) + 1;
});

const summary = {
  total_modules: totalCount,
  named_modules: namedCount,
  unnamed_modules: totalCount - namedCount,
  naming_rate: ((namedCount / totalCount) * 100).toFixed(1) + "%",
  categories,
};

console.error(`\n[module-namer] Summary:`);
console.error(`  Total: ${totalCount}`);
console.error(`  Named: ${namedCount} (${summary.naming_rate})`);
console.error(`  Categories: ${JSON.stringify(categories, null, 2)}`);

// ---------- Output ----------
const output = {
  summary,
  modules: manifest,
};

if (manifestOnly || !applyRename) {
  writeFileSync(join(dirname(modulesDir), "module_names.json"), JSON.stringify(output, null, 2));
  console.error(`\n[module-namer] Manifest written to module_names.json`);
}

if (applyRename) {
  const renamedDir = join(dirname(modulesDir), "modules_named");
  if (!existsSync(renamedDir)) mkdirSync(renamedDir, { recursive: true });

  let applied = 0;
  for (const m of manifest) {
    const src = join(modulesDir, m.originalName + ".js");
    const newName = m.newName || m.originalName;
    const dst = join(renamedDir, newName + ".js");

    try {
      // Read source, update header comment, write to new location
      let content = readFileSync(src, "utf-8");
      if (m.newName) {
        // Update the Name field in header
        content = content.replace(
          /(\* Name:)\s*\S+/,
          `$1 ${m.newName}`
        );
        // Add naming info to header
        content = content.replace(
          /(\* Unpacked by Karadul v3\.0)/,
          `* Named: ${m.newName} (${m.category}, confidence: ${m.confidence})\n * Signals: ${m.signals.join("; ")}\n * $1`
        );
      }
      writeFileSync(dst, content);
      applied++;
    } catch (e) {
      console.error(`  Error renaming ${m.originalName}: ${e.message}`);
    }
  }

  console.error(`\n[module-namer] ${applied} modules written to ${renamedDir}/`);
}

// Also output JSON to stdout
process.stdout.write(JSON.stringify(summary) + "\n");
