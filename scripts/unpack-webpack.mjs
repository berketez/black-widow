#!/usr/bin/env node
/**
 * unpack-webpack.mjs — Webpack bundle unpacker
 *
 * __webpack_require__ veya IIFE pattern'ini tespit edip modulleri
 * ayri dosyalara yazar.
 *
 * Kullanim:
 *   node unpack-webpack.mjs <input-file> <output-dir>
 *
 * Her modulu ayri dosyaya yazar: module_0.js, module_1.js, ...
 * Istatistikleri JSON olarak stdout'a yazar.
 *
 * 9MB+ dosyalar icin: node --max-old-space-size=4096 unpack-webpack.mjs <file> <dir>
 */

import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

const args = process.argv.slice(2);

if (args.length < 2) {
  const result = {
    success: false,
    errors: ["Kullanim: node unpack-webpack.mjs <input-file> <output-dir>"],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputDir = resolve(args[1]);

// Girdiyi oku
let source;
let fileSize;
try {
  fileSize = statSync(inputPath).size;
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  const result = {
    success: false,
    errors: [`Dosya okunamadi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

// Cikti dizinini olustur
try {
  mkdirSync(outputDir, { recursive: true });
} catch (err) {
  const result = {
    success: false,
    errors: [`Cikti dizini olusturulamadi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

// Parse
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
    errors: [`Fatal parse hatasi: ${err.message}`],
    stats: { file_size_bytes: fileSize, modules_found: 0, modules_written: 0 },
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
}

// --- Webpack module objesi bul ---
// Pattern 1: IIFE({0: function(e,t,n){...}, 1: ...})
// Pattern 2: IIFE([function(e,t,n){...}, function(e,t,n){...}])
// Pattern 3: __webpack_modules__ = {...}

const modules = new Map(); // moduleId -> AST node

try {
  traverse(ast, {
    // Obje bazli module map -- {0: function(e,t,n){}, ...}
    ObjectExpression(path) {
      const parent = path.parent;
      // IIFE argumani veya atama
      const isIIFEArg = parent.type === "CallExpression";
      const isAssignment =
        parent.type === "AssignmentExpression" &&
        parent.left.type === "MemberExpression";

      if (!isIIFEArg && !isAssignment) return;

      const props = path.node.properties;
      if (props.length < 2) return;

      let numericCount = 0;
      let funcCount = 0;

      for (const prop of props) {
        if (prop.type !== "ObjectProperty") continue;
        const key = prop.key;
        if (key.type === "NumericLiteral" || key.type === "StringLiteral") {
          numericCount++;
        }
        if (
          prop.value.type === "FunctionExpression" ||
          prop.value.type === "ArrowFunctionExpression"
        ) {
          funcCount++;
        }
      }

      // En az 2 module -> webpack module objesi
      if (numericCount >= 2 && funcCount >= 2) {
        for (const prop of props) {
          if (prop.type !== "ObjectProperty") continue;
          const key = prop.key;
          let moduleId;
          if (key.type === "NumericLiteral") moduleId = String(key.value);
          else if (key.type === "StringLiteral") moduleId = key.value;
          else continue;

          if (!modules.has(moduleId)) {
            modules.set(moduleId, prop.value);
          }
        }
      }
    },

    // Array bazli module map -- [function(e,t,n){}, ...]
    ArrayExpression(path) {
      const parent = path.parent;
      if (parent.type !== "CallExpression") return;

      const elements = path.node.elements;
      if (elements.length < 2) return;

      let funcCount = 0;
      for (const el of elements) {
        if (
          el &&
          (el.type === "FunctionExpression" || el.type === "ArrowFunctionExpression")
        ) {
          funcCount++;
        }
      }

      // Cogu eleman fonksiyon ise webpack array format
      if (funcCount >= elements.length * 0.5 && funcCount >= 2) {
        for (let i = 0; i < elements.length; i++) {
          const el = elements[i];
          if (
            el &&
            (el.type === "FunctionExpression" || el.type === "ArrowFunctionExpression")
          ) {
            const moduleId = String(i);
            if (!modules.has(moduleId)) {
              modules.set(moduleId, el);
            }
          }
        }
      }
    },
  });
} catch (err) {
  errors.push(`Traversal hatasi: ${err.message}`);
}

// --- Modulleri dosyalara yaz ---
let modulesWritten = 0;
const moduleStats = [];

for (const [moduleId, node] of modules.entries()) {
  try {
    const { code } = generate(node, {
      comments: true,
      compact: false,
      concise: false,
    });

    // Header yorum ekle
    const header = `/**\n * Webpack Module ${moduleId}\n * Unpacked by Karadul v1.0\n */\n\n`;
    const moduleCode = header + code + "\n";

    const fileName = `module_${moduleId}.js`;
    const filePath = join(outputDir, fileName);
    writeFileSync(filePath, moduleCode, "utf-8");

    const lineCount = moduleCode.split("\n").length;
    moduleStats.push({
      id: moduleId,
      file: fileName,
      lines: lineCount,
      size: Buffer.byteLength(moduleCode, "utf-8"),
    });
    modulesWritten++;
  } catch (err) {
    errors.push(`Module ${moduleId} yazilamadi: ${err.message}`);
  }
}

// --- Sonuc ---
const result = {
  success: modulesWritten > 0,
  stats: {
    file_size_bytes: fileSize,
    modules_found: modules.size,
    modules_written: modulesWritten,
    total_lines: source.split("\n").length,
  },
  modules: moduleStats,
  output_dir: outputDir,
  errors,
};

process.stdout.write(JSON.stringify(result) + "\n");
