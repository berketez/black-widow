#!/usr/bin/env node
/**
 * deobfuscate.mjs — Babel AST analiz pipeline (Acorn fallback destekli)
 *
 * STDIN'den veya dosya path'inden JS kaynak okur, AST uzerinde analiz yapar
 * ve sonucu JSON olarak stdout'a yazar.
 *
 * Babel parse basarisiz olursa (orn. 30MB+ minified VS Code/Monaco bundle'lari)
 * otomatik olarak Acorn parser'a duser. Acorn daha tolerant ve hizlidir.
 *
 * Kullanim:
 *   node deobfuscate.mjs <input-file> [--stats-only] [--extract-strings] [--extract-functions]
 *
 * Cikti: JSON { success, stats, functions, strings, imports, exports, webpack_modules, errors }
 *
 * 9MB+ dosyalar icin: node --max-old-space-size=4096 deobfuscate.mjs <file>
 */

import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import { createRequire } from "node:module";

// Babel ESM uyumluluk -- traverse default export CJS wrapper'dan gelir
const traverse = _traverse.default || _traverse;

// Acorn lazy-load -- sadece Babel basarisiz olursa yuklenir
const _require = createRequire(import.meta.url);
let acorn = null;
let acornWalk = null;

function loadAcorn() {
  try {
    acorn = _require("acorn");
    acornWalk = _require("acorn-walk");
    return true;
  } catch {
    return false;
  }
}

// --- CLI arguman parse ---
const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const positional = args.filter((a) => !a.startsWith("--"));

const statsOnly = flags.has("--stats-only");
const extractStrings = flags.has("--extract-strings") || !statsOnly;
const extractFunctions = flags.has("--extract-functions") || !statsOnly;

if (positional.length === 0) {
  const result = {
    success: false,
    errors: ["Kullanim: node deobfuscate.mjs <input-file> [--stats-only] [--extract-strings] [--extract-functions]"],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const inputPath = resolve(positional[0]);

// --- Kaynak oku ---
let source;
let fileSize;
try {
  const stat = statSync(inputPath);
  fileSize = stat.size;
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  const result = {
    success: false,
    errors: [`Dosya okunamadi: ${inputPath} — ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const totalLines = source.split("\n").length;

// --- Babel parse (tolerant mode) ---
const errors = [];
let ast;
try {
  ast = parse(source, {
    sourceType: "unambiguous",
    allowImportExportEverywhere: true,
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowUndeclaredExports: true,
    errorRecovery: true, // Parse hatalarinda devam et
    plugins: [
      "jsx",
      "typescript",
      "decorators-legacy",
      "classProperties",
      "classPrivateProperties",
      "classPrivateMethods",
      "dynamicImport",
      "optionalChaining",
      "nullishCoalescingOperator",
      "exportDefaultFrom",
      "exportNamespaceFrom",
      "topLevelAwait",
    ],
  });

  // errorRecovery ile yakalanan hatalar
  if (ast.errors && ast.errors.length > 0) {
    for (const e of ast.errors) {
      errors.push(`Parse hatasi (recovered): ${e.message} @ L${e.loc?.line || "?"}`);
    }
  }
} catch (babelErr) {
  // Babel parse basarisiz -- Acorn fallback dene
  errors.push(`Babel parse basarisiz (Acorn fallback deneniyor): ${babelErr.message}`);

  if (loadAcorn()) {
    try {
      ast = acorn.parse(source, {
        ecmaVersion: 2024,
        sourceType: "module",
        allowReturnOutsideFunction: true,
        allowImportExportEverywhere: true,
        locations: true,
      });
      errors.push("Acorn fallback basarili");
    } catch (acornErr) {
      // Acorn da basarisiz -- son cikis
      const result = {
        success: false,
        stats: { total_lines: totalLines, file_size_bytes: fileSize },
        errors: [
          `Babel parse hatasi: ${babelErr.message}`,
          `Acorn parse hatasi: ${acornErr.message}`,
        ],
        functions: [],
        strings: [],
        imports: [],
        exports: [],
        webpack_modules: [],
      };
      process.stdout.write(JSON.stringify(result) + "\n");
      process.exit(0);
    }
  } else {
    // Acorn yuklenemedi
    const result = {
      success: false,
      stats: { total_lines: totalLines, file_size_bytes: fileSize },
      errors: [`Fatal parse hatasi: ${babelErr.message}`, "Acorn modulu yuklenemedi (npm install acorn acorn-walk)"],
      functions: [],
      strings: [],
      imports: [],
      exports: [],
      webpack_modules: [],
    };
    process.stdout.write(JSON.stringify(result) + "\n");
    process.exit(0);
  }
}

// --- Hangi parser kullanildi? ---
// Babel AST node tipleri: StringLiteral, NumericLiteral, ObjectProperty, ...
// Acorn AST node tipleri (ESTree): Literal, Property, ...
const isAcornAST = !ast.type || ast.type === "Program" &&
  ast.body?.[0]?.type !== undefined &&
  !ast.program; // Babel AST'de ast.program var, Acorn'da yok

const usedAcorn = ast.body !== undefined && !ast.program;

// --- AST Traversal ---
const functions = [];
const strings = [];
const imports = [];
const exports_ = [];
const webpackModules = [];

// String minimum uzunluk (config'den gelen deger CLI'da kullanilabilir)
const STRING_MIN_LENGTH = 4;

// Webpack module ID set (hiz icin array yerine Set kullan)
const _webpackIdSet = new Set();

if (usedAcorn && acornWalk) {
  // ---- Acorn AST traversal (ESTree format) ----
  try {
    acornWalk.full(ast, (node) => {
      // Fonksiyon tespiti
      if (extractFunctions && (
        node.type === "FunctionDeclaration" ||
        node.type === "FunctionExpression" ||
        node.type === "ArrowFunctionExpression"
      )) {
        let name = node.id?.name || "";
        if (!name && node.type === "ArrowFunctionExpression") name = "<arrow>";
        if (!name) name = "<anonymous>";
        functions.push({
          name,
          params: (node.params || []).map((p) => acornParamName(p)),
          startLine: node.loc?.start.line || 0,
          endLine: node.loc?.end.line || 0,
          isAsync: node.async || false,
          isGenerator: node.generator || false,
        });
      }

      // String literal tespiti (Acorn: Literal node)
      if (extractStrings && node.type === "Literal" && typeof node.value === "string") {
        if (node.value.length >= STRING_MIN_LENGTH) {
          strings.push(node.value);
        }
      }

      // Template literal tespiti
      if (extractStrings && node.type === "TemplateLiteral") {
        for (const quasi of (node.quasis || [])) {
          const val = quasi.value?.cooked || quasi.value?.raw;
          if (val && val.length >= STRING_MIN_LENGTH) {
            strings.push(val);
          }
        }
      }

      // Import tespiti
      if (node.type === "ImportDeclaration") {
        const specifiers = (node.specifiers || []).map((s) => {
          if (s.type === "ImportDefaultSpecifier") return { type: "default", local: s.local.name };
          if (s.type === "ImportNamespaceSpecifier") return { type: "namespace", local: s.local.name };
          return {
            type: "named",
            imported: s.imported?.name || "",
            local: s.local.name,
          };
        });
        imports.push({
          source: node.source.value,
          specifiers,
          line: node.loc?.start.line || 0,
        });
      }

      // Require / __webpack_require__ tespiti
      if (node.type === "CallExpression") {
        const callee = node.callee;
        // require("module")
        if (
          callee?.type === "Identifier" &&
          callee.name === "require" &&
          node.arguments?.length === 1 &&
          node.arguments[0].type === "Literal" &&
          typeof node.arguments[0].value === "string"
        ) {
          imports.push({
            source: node.arguments[0].value,
            specifiers: [{ type: "cjs_require" }],
            line: node.loc?.start.line || 0,
          });
        }

        // __webpack_require__(id)
        if (
          callee?.type === "Identifier" &&
          callee.name === "__webpack_require__" &&
          node.arguments?.length >= 1
        ) {
          const arg = node.arguments[0];
          let moduleId = null;
          if (arg.type === "Literal" && (typeof arg.value === "number" || typeof arg.value === "string")) {
            moduleId = arg.value;
          }
          if (moduleId !== null && !_webpackIdSet.has(moduleId)) {
            _webpackIdSet.add(moduleId);
            webpackModules.push(moduleId);
          }
        }
      }

      // Export tespiti
      if (node.type === "ExportNamedDeclaration") {
        if (node.declaration) {
          if (node.declaration.type === "VariableDeclaration") {
            for (const decl of node.declaration.declarations) {
              exports_.push({
                type: "named",
                name: decl.id?.name || "<unknown>",
                line: node.loc?.start.line || 0,
              });
            }
          } else if (node.declaration.id) {
            exports_.push({
              type: "named",
              name: node.declaration.id.name,
              line: node.loc?.start.line || 0,
            });
          }
        }
        if (node.specifiers) {
          for (const spec of node.specifiers) {
            exports_.push({
              type: "named",
              name: spec.exported?.name || "",
              line: node.loc?.start.line || 0,
            });
          }
        }
      }

      if (node.type === "ExportDefaultDeclaration") {
        exports_.push({
          type: "default",
          name: node.declaration?.id?.name || "<default>",
          line: node.loc?.start.line || 0,
        });
      }

      if (node.type === "ExportAllDeclaration") {
        exports_.push({
          type: "all",
          source: node.source?.value || "",
          line: node.loc?.start.line || 0,
        });
      }

      // Webpack module obje tespiti (Acorn: Property node)
      if (node.type === "ObjectExpression" && node.properties?.length >= 2) {
        let numericKeyCount = 0;
        let funcValueCount = 0;
        for (const prop of node.properties) {
          if (prop.type !== "Property") continue;
          const key = prop.key;
          if (key?.type === "Literal" && (typeof key.value === "number" || typeof key.value === "string")) {
            numericKeyCount++;
          }
          const val = prop.value;
          if (val?.type === "FunctionExpression" || val?.type === "ArrowFunctionExpression") {
            funcValueCount++;
          }
        }
        if (numericKeyCount >= 2 && funcValueCount >= 2) {
          for (const prop of node.properties) {
            if (prop.type !== "Property") continue;
            const key = prop.key;
            let moduleId;
            if (key?.type === "Literal") moduleId = key.value;
            else continue;
            if (moduleId !== undefined && !_webpackIdSet.has(moduleId)) {
              _webpackIdSet.add(moduleId);
              webpackModules.push(moduleId);
            }
          }
        }
      }
    });
  } catch (err) {
    errors.push(`Acorn traversal hatasi: ${err.message}`);
  }
} else {
  // ---- Babel AST traversal ----
  try {
    traverse(ast, {
      // Fonksiyon tespiti
      FunctionDeclaration(path) {
        if (!extractFunctions) return;
        const node = path.node;
        functions.push({
          name: node.id?.name || "<anonymous>",
          params: node.params.map((p) => paramName(p)),
          startLine: node.loc?.start.line || 0,
          endLine: node.loc?.end.line || 0,
          isAsync: node.async || false,
          isGenerator: node.generator || false,
        });
      },

      FunctionExpression(path) {
        if (!extractFunctions) return;
        const node = path.node;
        let name = node.id?.name || "";
        if (!name && path.parent.type === "VariableDeclarator" && path.parent.id) {
          name = path.parent.id.name || "";
        }
        if (!name && path.parent.type === "Property" && path.parent.key) {
          name = path.parent.key.name || path.parent.key.value || "";
        }
        if (!name && path.parent.type === "ObjectProperty" && path.parent.key) {
          name = path.parent.key.name || path.parent.key.value || "";
        }
        functions.push({
          name: name || "<anonymous>",
          params: node.params.map((p) => paramName(p)),
          startLine: node.loc?.start.line || 0,
          endLine: node.loc?.end.line || 0,
          isAsync: node.async || false,
          isGenerator: node.generator || false,
        });
      },

      ArrowFunctionExpression(path) {
        if (!extractFunctions) return;
        const node = path.node;
        let name = "";
        if (path.parent.type === "VariableDeclarator" && path.parent.id) {
          name = path.parent.id.name || "";
        }
        if (path.parent.type === "Property" && path.parent.key) {
          name = path.parent.key.name || path.parent.key.value || "";
        }
        if (path.parent.type === "ObjectProperty" && path.parent.key) {
          name = path.parent.key.name || path.parent.key.value || "";
        }
        functions.push({
          name: name || "<arrow>",
          params: node.params.map((p) => paramName(p)),
          startLine: node.loc?.start.line || 0,
          endLine: node.loc?.end.line || 0,
          isAsync: node.async || false,
          isGenerator: false,
        });
      },

      // String literal tespiti
      StringLiteral(path) {
        if (!extractStrings) return;
        const val = path.node.value;
        if (val.length >= STRING_MIN_LENGTH) {
          strings.push(val);
        }
      },

      TemplateLiteral(path) {
        if (!extractStrings) return;
        for (const quasi of path.node.quasis) {
          const val = quasi.value.cooked || quasi.value.raw;
          if (val && val.length >= STRING_MIN_LENGTH) {
            strings.push(val);
          }
        }
      },

      // Import tespiti
      ImportDeclaration(path) {
        const node = path.node;
        const specifiers = node.specifiers.map((s) => {
          if (s.type === "ImportDefaultSpecifier") return { type: "default", local: s.local.name };
          if (s.type === "ImportNamespaceSpecifier") return { type: "namespace", local: s.local.name };
          return {
            type: "named",
            imported: s.imported?.name || s.imported?.value || "",
            local: s.local.name,
          };
        });
        imports.push({
          source: node.source.value,
          specifiers,
          line: node.loc?.start.line || 0,
        });
      },

      // Require tespiti (CJS)
      CallExpression(path) {
        const node = path.node;

        // require("module") tespiti
        if (
          node.callee.type === "Identifier" &&
          node.callee.name === "require" &&
          node.arguments.length === 1 &&
          node.arguments[0].type === "StringLiteral"
        ) {
          imports.push({
            source: node.arguments[0].value,
            specifiers: [{ type: "cjs_require" }],
            line: node.loc?.start.line || 0,
          });
        }

        // __webpack_require__(id) tespiti
        if (
          node.callee.type === "Identifier" &&
          node.callee.name === "__webpack_require__" &&
          node.arguments.length >= 1
        ) {
          const arg = node.arguments[0];
          let moduleId = null;
          if (arg.type === "NumericLiteral") moduleId = arg.value;
          else if (arg.type === "StringLiteral") moduleId = arg.value;
          if (moduleId !== null && !_webpackIdSet.has(moduleId)) {
            _webpackIdSet.add(moduleId);
            webpackModules.push(moduleId);
          }
        }
      },

      // Export tespiti
      ExportNamedDeclaration(path) {
        const node = path.node;
        if (node.declaration) {
          if (node.declaration.type === "VariableDeclaration") {
            for (const decl of node.declaration.declarations) {
              exports_.push({
                type: "named",
                name: decl.id?.name || "<unknown>",
                line: node.loc?.start.line || 0,
              });
            }
          } else if (node.declaration.id) {
            exports_.push({
              type: "named",
              name: node.declaration.id.name,
              line: node.loc?.start.line || 0,
            });
          }
        }
        if (node.specifiers) {
          for (const spec of node.specifiers) {
            exports_.push({
              type: "named",
              name: spec.exported?.name || spec.exported?.value || "",
              line: node.loc?.start.line || 0,
            });
          }
        }
      },

      ExportDefaultDeclaration(path) {
        exports_.push({
          type: "default",
          name: path.node.declaration?.id?.name || "<default>",
          line: path.node.loc?.start.line || 0,
        });
      },

      ExportAllDeclaration(path) {
        exports_.push({
          type: "all",
          source: path.node.source?.value || "",
          line: path.node.loc?.start.line || 0,
        });
      },

      // Webpack module obje tespiti -- IIFE({0: function(e,t,n){...}, 1: ...}) pattern
      ObjectExpression(path) {
        const parent = path.parent;
        if (parent.type !== "CallExpression") return;

        const props = path.node.properties;
        if (props.length < 2) return;

        let numericKeyCount = 0;
        let funcValueCount = 0;
        for (const prop of props) {
          if (prop.type !== "ObjectProperty") continue;
          const key = prop.key;
          if (key.type === "NumericLiteral" || key.type === "StringLiteral") {
            numericKeyCount++;
          }
          if (
            prop.value.type === "FunctionExpression" ||
            prop.value.type === "ArrowFunctionExpression"
          ) {
            funcValueCount++;
          }
        }

        if (numericKeyCount >= 2 && funcValueCount >= 2) {
          for (const prop of props) {
            if (prop.type !== "ObjectProperty") continue;
            const key = prop.key;
            let moduleId;
            if (key.type === "NumericLiteral") moduleId = key.value;
            else if (key.type === "StringLiteral") moduleId = key.value;
            else continue;

            if (!_webpackIdSet.has(moduleId)) {
              _webpackIdSet.add(moduleId);
              webpackModules.push(moduleId);
            }
          }
        }
      },
    });
  } catch (err) {
    errors.push(`Traversal hatasi: ${err.message}`);
  }
}

// --- Sonuc ---
const result = {
  success: errors.length === 0 || functions.length > 0 || strings.length > 0,
  stats: {
    functions: functions.length,
    strings: strings.length,
    imports: imports.length,
    exports: exports_.length,
    webpack_modules: webpackModules.length,
    total_lines: totalLines,
    file_size_bytes: fileSize,
    parser: usedAcorn ? "acorn" : "babel",
  },
  functions: statsOnly ? [] : functions,
  strings: statsOnly ? [] : strings,
  imports: statsOnly ? [] : imports,
  exports: statsOnly ? [] : exports_,
  webpack_modules: webpackModules,
  errors,
};

process.stdout.write(JSON.stringify(result) + "\n");

// --- Helpers ---

/** Babel AST parametre isim cikarma */
function paramName(param) {
  switch (param.type) {
    case "Identifier":
      return param.name;
    case "AssignmentPattern":
      return paramName(param.left) + "=...";
    case "RestElement":
      return "..." + paramName(param.argument);
    case "ObjectPattern":
      return "{...}";
    case "ArrayPattern":
      return "[...]";
    default:
      return "?";
  }
}

/** Acorn (ESTree) AST parametre isim cikarma */
function acornParamName(param) {
  if (!param) return "?";
  switch (param.type) {
    case "Identifier":
      return param.name;
    case "AssignmentPattern":
      return acornParamName(param.left) + "=...";
    case "RestElement":
      return "..." + acornParamName(param.argument);
    case "ObjectPattern":
      return "{...}";
    case "ArrayPattern":
      return "[...]";
    default:
      return "?";
  }
}
