#!/usr/bin/env node
/**
 * extract-modules.mjs — Webpack module extraction with dependency graph
 *
 * Webpack bundle'dan tum modulleri cikarir ve her modulu ayri dosyaya yazar.
 * Dependency graph'i JSON olarak uretir.
 *
 * Kullanim:
 *   node extract-modules.mjs <input-file> <output-dir>
 *
 * Cikti (stdout JSON):
 *   {
 *     "success": true,
 *     "total_modules": 342,
 *     "modules": [
 *       {"id": "0", "size": 1234, "dependencies": ["1", "2"], "file": "module_000.js"},
 *       ...
 *     ],
 *     "dependency_graph": {"0": ["1", "2"], "1": ["3"], ...},
 *     "entry_point": "0"
 *   }
 *
 * 9MB+ dosyalar icin: node --max-old-space-size=4096 extract-modules.mjs <file> <dir>
 */

import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

// --- CLI argumanlari ---
const args = process.argv.slice(2);

if (args.length < 2) {
  const result = {
    success: false,
    total_modules: 0,
    modules: [],
    dependency_graph: {},
    entry_point: null,
    errors: ["Kullanim: node extract-modules.mjs <input-file> <output-dir>"],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputDir = resolve(args[1]);

// --- Girdiyi oku ---
let source;
let fileSize;
try {
  fileSize = statSync(inputPath).size;
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  const result = {
    success: false,
    total_modules: 0,
    modules: [],
    dependency_graph: {},
    entry_point: null,
    errors: [`Dosya okunamadi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

// --- Cikti dizini olustur ---
try {
  mkdirSync(outputDir, { recursive: true });
} catch (err) {
  const result = {
    success: false,
    total_modules: 0,
    modules: [],
    dependency_graph: {},
    entry_point: null,
    errors: [`Cikti dizini olusturulamadi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

// --- Babel parse ---
let ast;
const errors = [];

try {
  ast = parse(source, {
    sourceType: "unambiguous",
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
    errorRecovery: true,
    plugins: [
      "jsx",
      "typescript",
      "decorators-legacy",
      "classProperties",
      "dynamicImport",
      "optionalChaining",
      "nullishCoalescingOperator",
      "topLevelAwait",
    ],
  });
  if (ast.errors && ast.errors.length > 0) {
    for (const e of ast.errors) {
      errors.push(`Parse (recovered): ${e.message}`);
    }
  }
} catch (err) {
  const result = {
    success: false,
    total_modules: 0,
    modules: [],
    dependency_graph: {},
    entry_point: null,
    errors: [`Fatal parse hatasi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
}

// --- Webpack module'leri bul ---
// Map: moduleId (string) -> { node: AST node, deps: Set<string> }
const modules = new Map();
let detectedEntryPoint = null;
let bundleFormat = "unknown"; // "iife_object", "iife_array", "arrow_object", "assignment"

try {
  traverse(ast, {
    // Pattern 1: IIFE wrapper — (function(modules) { ... })({ 0: function(e,t,n){}, ... })
    // Pattern 2: Arrow function wrapper — ((modules) => { ... })({ 0: (e,t,n) => {}, ... })
    CallExpression(path) {
      const node = path.node;
      const callee = node.callee;

      // IIFE veya arrow wrapper tespit
      const isIIFE =
        callee.type === "FunctionExpression" ||
        callee.type === "ArrowFunctionExpression";
      // Parantezli IIFE: (function(){})()
      const isWrappedIIFE =
        callee.type === "SequenceExpression" &&
        callee.expressions.length > 0 &&
        (callee.expressions[callee.expressions.length - 1].type === "FunctionExpression" ||
         callee.expressions[callee.expressions.length - 1].type === "ArrowFunctionExpression");

      if (!isIIFE && !isWrappedIIFE) return;

      // Arguman obje veya array mi?
      for (const arg of node.arguments) {
        if (arg.type === "ObjectExpression") {
          extractModulesFromObject(arg, path);
          if (callee.type === "ArrowFunctionExpression") {
            bundleFormat = "arrow_object";
          } else {
            bundleFormat = "iife_object";
          }
        } else if (arg.type === "ArrayExpression") {
          extractModulesFromArray(arg);
          bundleFormat = "iife_array";
        }
      }

      // Entry point tespiti: IIFE icindeki __webpack_require__(s) veya n(n.s = 0) pattern'i
      if (isIIFE && callee.body) {
        findEntryPoint(callee.body);
      }
    },

    // Pattern 3: var __webpack_modules__ = { ... }
    VariableDeclarator(path) {
      const node = path.node;
      if (
        node.id.type === "Identifier" &&
        (node.id.name === "__webpack_modules__" || node.id.name === "modules") &&
        node.init &&
        node.init.type === "ObjectExpression"
      ) {
        extractModulesFromObject(node.init, path);
        bundleFormat = "assignment";
      }
    },

    // Pattern 4: Assignment — __webpack_modules__ = { ... }
    AssignmentExpression(path) {
      const node = path.node;
      if (
        node.left.type === "Identifier" &&
        node.left.name === "__webpack_modules__" &&
        node.right.type === "ObjectExpression"
      ) {
        extractModulesFromObject(node.right, path);
        bundleFormat = "assignment";
      }
    },
  });
} catch (err) {
  errors.push(`Traversal hatasi: ${err.message}`);
}

// --- Dependency analizi ---
// Her module icinde __webpack_require__(id) cagrilarini bul
const dependencyGraph = {};

for (const [moduleId, moduleInfo] of modules.entries()) {
  const deps = new Set();

  try {
    // Module AST'sini generate edip tekrar parse etmek yerine
    // dogrudan module node'undaki CallExpression'lari tara
    const moduleAst = moduleInfo.node;
    findDependencies(moduleAst, deps);
  } catch (err) {
    // Dependency analizi basarisiz olursa bos birak
    errors.push(`Module ${moduleId} dependency analizi hatasi: ${err.message}`);
  }

  moduleInfo.deps = deps;
  dependencyGraph[moduleId] = [...deps];
}

// --- Entry point ---
// Eger traversal'dan bulunamadiysa, en cok bagimliligi olan module
if (!detectedEntryPoint && modules.size > 0) {
  let maxDeps = -1;
  for (const [id, info] of modules.entries()) {
    if (info.deps.size > maxDeps) {
      maxDeps = info.deps.size;
      detectedEntryPoint = id;
    }
  }
}

// --- Modulleri dosyalara yaz ---
const moduleOutputs = [];

for (const [moduleId, moduleInfo] of modules.entries()) {
  try {
    const { code } = generate(moduleInfo.node, {
      comments: true,
      compact: false,
      concise: false,
    });

    const deps = [...moduleInfo.deps];
    const paddedId = String(moduleId).padStart(3, "0");
    const fileName = `module_${paddedId}.js`;
    const filePath = join(outputDir, fileName);

    // Header yorum
    const depStr = deps.length > 0 ? deps.join(", ") : "none";
    const header = `/* Module ID: ${moduleId}, Dependencies: [${depStr}] */\n\n`;
    const moduleCode = header + code + "\n";

    writeFileSync(filePath, moduleCode, "utf-8");

    const codeSize = Buffer.byteLength(moduleCode, "utf-8");
    moduleOutputs.push({
      id: String(moduleId),
      size: codeSize,
      dependencies: deps,
      file: fileName,
    });
  } catch (err) {
    errors.push(`Module ${moduleId} yazilamadi: ${err.message}`);
  }
}

// --- Dependency graph JSON dosyasini da yaz ---
try {
  const graphPath = join(outputDir, "dependency_graph.json");
  writeFileSync(
    graphPath,
    JSON.stringify(
      {
        entry_point: detectedEntryPoint,
        bundle_format: bundleFormat,
        modules: moduleOutputs.length,
        graph: dependencyGraph,
      },
      null,
      2
    ),
    "utf-8"
  );
} catch (err) {
  errors.push(`Dependency graph yazilamadi: ${err.message}`);
}

// --- Sonuc ---
const result = {
  success: moduleOutputs.length > 0,
  total_modules: moduleOutputs.length,
  modules: moduleOutputs,
  dependency_graph: dependencyGraph,
  entry_point: detectedEntryPoint,
  bundle_format: bundleFormat,
  file_size: fileSize,
  errors,
};

process.stdout.write(JSON.stringify(result) + "\n");

// ===== Helper fonksiyonlar =====

/**
 * ObjectExpression'dan webpack modullerini cikar.
 * Numeric/string key + function value pattern'ini arar.
 */
function extractModulesFromObject(objNode, parentPath) {
  const props = objNode.properties;
  if (props.length < 1) return;

  let moduleCount = 0;

  for (const prop of props) {
    if (prop.type !== "ObjectProperty" && prop.type !== "ObjectMethod") continue;

    const key = prop.key;
    let moduleId;

    if (key.type === "NumericLiteral") {
      moduleId = String(key.value);
    } else if (key.type === "StringLiteral") {
      moduleId = key.value;
    } else if (key.type === "Identifier") {
      // Webpack 5 named chunks: e.g., "./src/utils.js"
      moduleId = key.name;
    } else {
      continue;
    }

    // Value: FunctionExpression, ArrowFunctionExpression, veya ObjectMethod
    let funcNode;
    if (prop.type === "ObjectMethod") {
      // Object method syntax: { 0(e, t, n) { ... } }
      funcNode = prop;
    } else if (
      prop.value.type === "FunctionExpression" ||
      prop.value.type === "ArrowFunctionExpression"
    ) {
      funcNode = prop.value;
    } else {
      continue;
    }

    if (!modules.has(moduleId)) {
      modules.set(moduleId, { node: funcNode, deps: new Set() });
      moduleCount++;
    }
  }
}

/**
 * ArrayExpression'dan webpack modullerini cikar.
 * [function(e,t,n){}, function(e,t,n){}, ...] pattern'i.
 */
function extractModulesFromArray(arrNode) {
  const elements = arrNode.elements;
  if (elements.length < 1) return;

  for (let i = 0; i < elements.length; i++) {
    const el = elements[i];
    if (!el) continue; // sparse array (null element)

    if (
      el.type === "FunctionExpression" ||
      el.type === "ArrowFunctionExpression"
    ) {
      const moduleId = String(i);
      if (!modules.has(moduleId)) {
        modules.set(moduleId, { node: el, deps: new Set() });
      }
    }
  }
}

/**
 * Module AST node'u icindeki __webpack_require__(id) cagrilarini bul.
 * Recursive AST traversal yapar.
 */
function findDependencies(node, deps) {
  if (!node || typeof node !== "object") return;

  // CallExpression: __webpack_require__(id) veya n(id) veya e(id)
  if (node.type === "CallExpression") {
    const callee = node.callee;
    const args = node.arguments;

    if (callee && args && args.length >= 1) {
      // __webpack_require__(123) veya tek harfli alias (n, e, r gibi)
      const isWebpackRequire =
        (callee.type === "Identifier" && callee.name === "__webpack_require__") ||
        (callee.type === "MemberExpression" &&
         callee.object.type === "Identifier" &&
         callee.object.name === "__webpack_require__");

      // Module factory parametresi olarak alinan require fonksiyonu
      // Pattern: function(e, t, n) { n(1); n(2); }
      // n 3. parametre ise webpack require olabilir
      // Bunu sadece __webpack_require__ icin kesin yapabiliriz
      if (isWebpackRequire) {
        const arg = args[0];
        if (arg.type === "NumericLiteral") {
          deps.add(String(arg.value));
        } else if (arg.type === "StringLiteral") {
          deps.add(arg.value);
        }
      }
    }
  }

  // Recursive traversal
  for (const key of Object.keys(node)) {
    if (key === "type" || key === "loc" || key === "start" || key === "end") continue;
    if (key === "leadingComments" || key === "trailingComments" || key === "innerComments") continue;

    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === "object" && item.type) {
          findDependencies(item, deps);
        }
      }
    } else if (child && typeof child === "object" && child.type) {
      findDependencies(child, deps);
    }
  }
}

/**
 * IIFE body icinden entry point'i bul.
 * Pattern: n(n.s = 0) veya __webpack_require__(__webpack_require__.s = 0)
 */
function findEntryPoint(bodyNode) {
  if (!bodyNode || typeof bodyNode !== "object") return;

  if (bodyNode.type === "CallExpression") {
    const callee = bodyNode.callee;
    const args = bodyNode.arguments;

    // n(n.s = 0) pattern
    if (
      callee &&
      callee.type === "Identifier" &&
      args &&
      args.length >= 1
    ) {
      const arg = args[0];
      // n.s = 0 (AssignmentExpression)
      if (arg.type === "AssignmentExpression") {
        const right = arg.right;
        if (right.type === "NumericLiteral") {
          detectedEntryPoint = String(right.value);
          return;
        } else if (right.type === "StringLiteral") {
          detectedEntryPoint = right.value;
          return;
        }
      }
      // Dogrudan n(0) pattern
      if (arg.type === "NumericLiteral") {
        detectedEntryPoint = String(arg.value);
        return;
      }
      if (arg.type === "StringLiteral") {
        detectedEntryPoint = arg.value;
        return;
      }
    }
  }

  // Recursive
  for (const key of Object.keys(bodyNode)) {
    if (key === "type" || key === "loc" || key === "start" || key === "end") continue;
    if (key === "leadingComments" || key === "trailingComments" || key === "innerComments") continue;

    const child = bodyNode[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === "object" && item.type) {
          findEntryPoint(item);
          if (detectedEntryPoint !== null) return;
        }
      }
    } else if (child && typeof child === "object" && child.type) {
      findEntryPoint(child);
      if (detectedEntryPoint !== null) return;
    }
  }
}
