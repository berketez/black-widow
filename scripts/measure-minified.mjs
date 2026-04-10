#!/usr/bin/env node
/**
 * Minified identifier oranini olc.
 * Identifier: 1-2 karakter veya 3 karakter olup _/$ ile baslayanlar.
 * Sabit/built-in/keyword olanlar haric.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;

const inputPath = resolve(process.argv[2]);
const source = readFileSync(inputPath, "utf-8");

const ast = parse(source, {
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

const RESERVED = new Set([
  "break","case","catch","continue","debugger","default","delete",
  "do","else","finally","for","function","if","in","instanceof",
  "new","return","switch","this","throw","try","typeof","var",
  "void","while","with","class","const","enum","export","extends",
  "import","super","implements","interface","let","package","private",
  "protected","public","static","yield","null","true","false",
  "undefined","NaN","Infinity","arguments","eval",
]);

const BUILTINS = new Set([
  "Object","Array","String","Number","Boolean","Function","Symbol","BigInt",
  "Math","Date","RegExp","Error","TypeError","RangeError","SyntaxError","ReferenceError",
  "Map","Set","WeakMap","WeakSet","Promise","Proxy","Reflect",
  "JSON","console","process","Buffer","global","globalThis","window","document",
  "setTimeout","setInterval","clearTimeout","clearInterval","setImmediate","clearImmediate",
  "require","module","exports","__filename","__dirname","__webpack_require__",
  "parseInt","parseFloat","isNaN","isFinite","decodeURIComponent","encodeURIComponent",
  "decodeURI","encodeURI","eval","atob","btoa",
  "TextDecoder","TextEncoder","URL","URLSearchParams","AbortController","AbortSignal",
  "EventTarget","Event","CustomEvent","MessageChannel","MessagePort",
  "ReadableStream","WritableStream","TransformStream",
  "ArrayBuffer","SharedArrayBuffer","DataView","Uint8Array","Int8Array",
  "Uint16Array","Int16Array","Uint32Array","Int32Array","Float32Array","Float64Array",
  "BigInt64Array","BigUint64Array",
  "Intl","WebAssembly","performance","queueMicrotask",
]);

function isMinified(name) {
  if (RESERVED.has(name) || BUILTINS.has(name)) return false;
  if (name.startsWith("__")) return false; // __webpack_require__ etc
  if (name.length <= 2) return true;
  if (name.length === 3 && (name[0] === '_' || name[0] === '$')) return true;
  return false;
}

const uniqueNames = new Set();
const minifiedNames = new Set();
let totalRefs = 0;
let minifiedRefs = 0;

traverse(ast, {
  Identifier(path) {
    const name = path.node.name;
    if (!name) return;
    // Skip property access (member expression property that is not computed)
    if (t.isMemberExpression(path.parent) && path.parent.property === path.node && !path.parent.computed) return;
    // Skip object property keys
    if (t.isObjectProperty(path.parent) && path.parent.key === path.node && !path.parent.computed) return;
    // Skip labels
    if (t.isLabeledStatement(path.parent) && path.parent.label === path.node) return;
    if (t.isBreakStatement(path.parent) && path.parent.label === path.node) return;
    if (t.isContinueStatement(path.parent) && path.parent.label === path.node) return;

    totalRefs++;
    uniqueNames.add(name);
    if (isMinified(name)) {
      minifiedRefs++;
      minifiedNames.add(name);
    }
  }
});

const uniqueTotal = uniqueNames.size;
const uniqueMinified = minifiedNames.size;
const pctUnique = ((uniqueMinified / uniqueTotal) * 100).toFixed(1);
const pctRefs = ((minifiedRefs / totalRefs) * 100).toFixed(1);

console.log(JSON.stringify({
  total_unique_identifiers: uniqueTotal,
  minified_unique: uniqueMinified,
  readable_unique: uniqueTotal - uniqueMinified,
  minified_pct_unique: pctUnique + "%",
  total_refs: totalRefs,
  minified_refs: minifiedRefs,
  readable_refs: totalRefs - minifiedRefs,
  minified_pct_refs: pctRefs + "%",
  readable_pct_refs: (100 - parseFloat(pctRefs)).toFixed(1) + "%",
  top_minified: [...minifiedNames].slice(0, 30),
}, null, 2));
