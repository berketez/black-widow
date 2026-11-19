#!/usr/bin/env node
/**
 * p20b_webpack_say.mjs — webpack modül haritasının BAĞIMSIZ sayımı (P20b kalem 1).
 *
 * smart-webpack-unpack.mjs'in algılayıcısından ayrı yazılmıştır: modül haritasını
 * biçiminden (nesne / dizi) değil, webpack ÇALIŞMA ZAMANININ onu nasıl
 * kullandığından bulur. Hiçbir kod çalıştırılmaz (yalnız Babel AST + kapsam).
 *
 * Tanınan kalıplar:
 *   A) require işlevi: R(id) gövdesinde `M[id].call(x.exports, x, x.exports, R)`
 *      ya da `M[id](x, x.exports, R)`. M'nin bağı kapsamdan çözülür: değişken
 *      başlangıç değeri (nesne / dizi) ya da IIFE parametresi → karşılık gelen argüman.
 *   B) JSONP öbek kaydı: `(...webpackChunk<ad>... || []).push([[öbek kimlikleri], MODÜLLER, ...])`
 *      ya da webpack 4 `webpackJsonp` (kimlik dizisi + modül nesnesi / dizisi).
 *   C) Node öbeği: `exports.modules = {…}` (aynı programda `exports.ids` ya da `exports.id`).
 *
 * Kullanım: node p20b_webpack_say.mjs <girdi.js>
 * Çıktı (stdout, tek satır JSON): {file, maps: [{kind, shape, count, line, start, nested, ids}],
 *   module_ids (yalnız dış haritalar), total, nested_module_ids}
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;

const inputPath = resolve(process.argv[2] || "");
const source = readFileSync(inputPath, "utf-8");
const ast = parse(source, {
  sourceType: "unambiguous",
  allowReturnOutsideFunction: true,
  errorRecovery: true,
  plugins: ["jsx", "classProperties", "classPrivateProperties", "classPrivateMethods",
    "dynamicImport", "optionalChaining", "nullishCoalescingOperator", "topLevelAwait"],
});

function keyOf(prop) {
  if (t.isNumericLiteral(prop.key)) return String(prop.key.value);
  if (t.isStringLiteral(prop.key)) return prop.key.value;
  if (t.isIdentifier(prop.key) && !prop.computed) return prop.key.name;
  return null;
}

function idsOfContainer(node) {
  if (t.isObjectExpression(node)) {
    const ids = [];
    for (const p of node.properties) {
      if (!t.isObjectProperty(p) && !t.isObjectMethod(p)) continue;
      const k = keyOf(p);
      if (k !== null) ids.push(k);
    }
    return ids;
  }
  if (t.isArrayExpression(node)) {
    const ids = [];
    node.elements.forEach((el, i) => { if (el) ids.push(String(i)); });
    return ids;
  }
  return null;
}

// Bağı çözülen ifadenin kapsayıcı düğümü (nesne / dizi) ya da null.
function resolveContainer(path, name) {
  const binding = path.scope.getBinding(name);
  if (!binding) return null;
  const bp = binding.path;
  if (bp.isVariableDeclarator()) {
    const init = bp.node.init;
    if (t.isObjectExpression(init) || t.isArrayExpression(init)) return init;
    return null;
  }
  if (binding.kind === "param") {
    const fn = bp.parentPath && bp.parentPath.isFunction() ? bp.parentPath : bp.findParent((p) => p.isFunction());
    if (!fn) return null;
    const idx = fn.node.params.indexOf(bp.node);
    const call = fn.parentPath;
    if (idx >= 0 && call && call.isCallExpression() && call.node.callee === fn.node) {
      const arg = call.node.arguments[idx];
      if (t.isObjectExpression(arg) || t.isArrayExpression(arg)) return arg;
    }
  }
  return null;
}

const maps = [];
const seen = new Set();
function addMap(kind, container, line) {
  if (!container || seen.has(container)) return;
  seen.add(container);
  const ids = idsOfContainer(container) || [];
  maps.push({ kind, count: ids.length, ids, line, start: container.start, end: container.end,
    shape: t.isArrayExpression(container) ? "array" : "object" });
}

function isMemberNamed(node, re) {
  return t.isMemberExpression(node) && !node.computed && t.isIdentifier(node.property) && re.test(node.property.name);
}

function mentionsChunkGlobal(node) {
  let found = false;
  const visit = (n) => {
    if (!n || found || typeof n !== "object") return;
    if (isMemberNamed(n, /^webpack(Chunk|Jsonp)/)) { found = true; return; }
    if (t.isIdentifier(n) && /^webpack(Chunk|Jsonp)/.test(n.name)) { found = true; return; }
    for (const key of t.VISITOR_KEYS[n.type] || []) {
      const v = n[key];
      if (Array.isArray(v)) v.forEach(visit); else visit(v);
    }
  };
  visit(node);
  return found;
}

traverse(ast, {
  CallExpression(path) {
    const node = path.node;
    const callee = node.callee;

    // A) M[id].call(x.exports, x, x.exports, R)  |  M[id](x, x.exports, R)
    let target = null;
    let args = null;
    if (isMemberNamed(callee, /^call$/) && t.isMemberExpression(callee.object) && callee.object.computed) {
      target = callee.object; args = node.arguments.slice(1);
    } else if (t.isMemberExpression(callee) && callee.computed) {
      target = callee; args = node.arguments;
    }
    if (target && t.isIdentifier(target.object) && t.isIdentifier(target.property) && args.length === 3) {
      const [a0, a1, a2] = args;
      const fn = path.getFunctionParent();
      const fnName = fn && (fn.node.id ? fn.node.id.name
        : (fn.parentPath.isVariableDeclarator() && t.isIdentifier(fn.parentPath.node.id) ? fn.parentPath.node.id.name : null));
      const firstParam = fn && fn.node.params[0];
      const shape = t.isIdentifier(a0) && isMemberNamed(a1, /^exports$/) && t.isIdentifier(a1.object)
        && a1.object.name === a0.name && t.isIdentifier(a2) && fnName && a2.name === fnName
        && t.isIdentifier(firstParam) && firstParam.name === target.property.name;
      if (shape) {
        addMap("runtime_require", resolveContainer(path, target.object.name), node.loc?.start.line);
      }
    }

    // B) (...webpackChunk...).push([[ids], MODULES, ...])
    if (isMemberNamed(callee, /^push$/) && mentionsChunkGlobal(callee.object) && node.arguments.length >= 1) {
      const a = node.arguments[0];
      if (t.isArrayExpression(a) && a.elements.length >= 2 && t.isArrayExpression(a.elements[0])) {
        const mods = a.elements[1];
        if (t.isObjectExpression(mods) || t.isArrayExpression(mods)) {
          addMap("jsonp_chunk", mods, node.loc?.start.line);
        }
      }
    }
  },
  AssignmentExpression(path) {
    // C) exports.modules = {...}
    const { left, right } = path.node;
    if (isMemberNamed(left, /^modules$/) && t.isIdentifier(left.object) && left.object.name === "exports"
      && (t.isObjectExpression(right) || t.isArrayExpression(right))) {
      if (/\bexports\.ids?\s*=/.test(source)) addMap("node_chunk", right, path.node.loc?.start.line);
    }
  },
});

// İç içe harita: başka bir haritanın kapsayıcısı içinde duran harita (paketlenmiş bir
// kütüphanenin kendi webpack çalışma zamanı). Dış haritanın modülü onu zaten içerir;
// beklenen modül kümesi yalnız DIŞ haritalardan kurulur.
for (const m of maps) {
  m.nested = maps.some((o) => o !== m && o.start <= m.start && m.end <= o.end);
}
const all = new Set();
for (const m of maps) if (!m.nested) for (const id of m.ids) all.add(id);
const nestedIds = new Set();
for (const m of maps) if (m.nested) for (const id of m.ids) nestedIds.add(id);
process.stdout.write(JSON.stringify({
  file: inputPath,
  parse_errors: (ast.errors || []).length,
  maps: maps.map((m) => ({ kind: m.kind, shape: m.shape, count: m.count, line: m.line,
    start: m.start, nested: m.nested, ids: m.ids })),
  module_ids: [...all],
  total: all.size,
  nested_module_ids: [...nestedIds],
}) + "\n");
