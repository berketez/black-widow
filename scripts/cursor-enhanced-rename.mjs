#!/usr/bin/env node
/**
 * cursor-enhanced-rename.mjs -- Cursor-Specific Enhanced Semantic Renamer
 *
 * Phase 10'dan sonra kalan minified identifier'lari Cursor'a ozel
 * context kurallariyla rename eder. Phase 10'un genel kurallarinin
 * kapsamadigi ozel pattern'leri yakalar.
 *
 * Ek Kurallar (Phase 10'un ustune):
 *   11. Prototype access pattern  -> constructor/cls
 *   12. High binary ops + no methods -> counter/offset/index
 *   13. Purely called (no props, no methods) -> handler/fn
 *   14. Event listener callback pos -> eventArg/eventData
 *   15. Assignment from member expression -> derived/ref
 *   16. Single property dominant -> contextual name
 *   17. Conditional return pattern -> result/value
 *   18. Switch/if-else comparison chain -> kind/type/mode
 *   19. Namespace property access (X.C, X.Q) -> ns/mod
 *   20. Loop counter (for init) -> idx/counter
 *   21. Await expression -> awaited/asyncResult
 *   22. Parameter with default value context -> optParam
 *   23. Argument name clash dedup (Phase 9's variable_N) - re-score
 *   24. Length/size dominant -> collection/list
 *   25. Bitwise ops dominant -> flags/bits/mask
 *
 * Kullanim:
 *   node --max-old-space-size=8192 cursor-enhanced-rename.mjs <input> <output>
 *
 * Cikti: JSON { success, renamed, stats }
 */

import { readFileSync, writeFileSync, statSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

// ---------- CLI ----------
const args = process.argv.slice(2);
const inputPath = resolve(args[0]);
const outputPath = resolve(args[1]);

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

if (!args[0] || !args[1]) {
  emit({ success: false, errors: ["Kullanim: node cursor-enhanced-rename.mjs <input> <output>"] });
  process.exit(1);
}

// ---------- Reserved ----------
const RESERVED = new Set([
  "break","case","catch","continue","debugger","default","delete",
  "do","else","finally","for","function","if","in","instanceof",
  "new","return","switch","this","throw","try","typeof","var",
  "void","while","with","class","const","enum","export","extends",
  "import","super","implements","interface","let","package","private",
  "protected","public","static","yield","null","true","false",
  "undefined","NaN","Infinity","arguments","eval",
]);

// ---------- Helpers ----------
function isMinified(name) {
  if (name.length <= 2) return true;
  if (name.length === 3 && (name[0] === '_' || name[0] === '$')) return true;
  return false;
}

function makeUnique(scope, baseName) {
  if (RESERVED.has(baseName)) baseName = baseName + "Val";
  if (!scope.hasBinding(baseName)) {
    let p = scope.parent, conflict = false;
    while (p) { if (p.hasOwnBinding(baseName)) { conflict = true; break; } p = p.parent; }
    if (!conflict) return baseName;
  }
  for (let i = 2; i < 200; i++) {
    const c = `${baseName}${i}`;
    if (!scope.hasBinding(c)) {
      let p = scope.parent, conflict = false;
      while (p) { if (p.hasOwnBinding(c)) { conflict = true; break; } p = p.parent; }
      if (!conflict) return c;
    }
  }
  return null;
}

/** Detailed usage collection -- extends Phase 10 with more signals */
function collectUsage(binding) {
  const info = {
    methodCalls: new Set(),
    propertyReads: new Set(),
    propertyWrites: new Set(),
    calledAs: false,
    comparedWith: [],
    typeofChecks: [],
    usedInForOf: false,
    usedAsForOfIterator: false,
    destructured: false,
    indexAccessed: false,
    arithmeticOperand: false,
    stringConcatenated: false,
    thrownAsError: false,
    usedInNew: false,
    usedAsKey: false,
    // Extended signals
    prototypeAccess: false,
    bitwiseOps: 0,
    binaryOpsCount: 0,
    awaitedResult: false,
    returnedFromFunc: false,
    usedWithSpread: false,
    passedToFunctions: [],
    assignedFromMember: false,
    assignedFromAwait: false,
    assignedFromCall: false,
    forLoopInit: false,
    forLoopUpdate: false,
    switchDiscriminant: false,
    refCount: 0,
    // Length/size pattern
    lengthAccess: false,
    // Conditional pattern
    conditionalTest: false,
    // Property dominant
    dominantPropCount: 0,
    dominantProp: null,
  };
  if (!binding?.referencePaths) return info;

  info.refCount = binding.referencePaths.length;
  const propCounts = {};

  for (const ref of binding.referencePaths) {
    const p = ref.parent;
    const pp = ref.parentPath;
    if (!p) continue;

    // Member expression (non-computed)
    if (t.isMemberExpression(p) && p.object === ref.node && !p.computed) {
      const prop = p.property?.name;
      if (prop) {
        propCounts[prop] = (propCounts[prop] || 0) + 1;
        const gp = pp?.parent;
        if (t.isCallExpression(gp) && gp.callee === p) {
          info.methodCalls.add(prop);
        } else {
          info.propertyReads.add(prop);
        }
        if (prop === "prototype") info.prototypeAccess = true;
        if (prop === "length" || prop === "size") info.lengthAccess = true;
      }
    }

    // Computed property access
    if (t.isMemberExpression(p) && p.object === ref.node && p.computed) {
      info.indexAccessed = true;
      if (t.isStringLiteral(p.property)) {
        const sv = p.property.value;
        info.propertyReads.add(sv);
        propCounts[sv] = (propCounts[sv] || 0) + 1;
      }
    }

    // Called as function
    if (t.isCallExpression(p) && p.callee === ref.node) info.calledAs = true;

    // Passed to function
    if (t.isCallExpression(p) && p.arguments?.includes(ref.node)) {
      const callee = p.callee;
      const fn = t.isIdentifier(callee) ? callee.name :
        (t.isMemberExpression(callee) && !callee.computed ? callee.property?.name : null);
      if (fn) info.passedToFunctions.push(fn);
    }

    // Comparison
    if (t.isBinaryExpression(p) && (p.operator === "===" || p.operator === "==")) {
      const other = p.left === ref.node ? p.right : p.left;
      if (t.isStringLiteral(other)) info.comparedWith.push(other.value);
      if (t.isNumericLiteral(other)) info.arithmeticOperand = true;
    }

    // typeof
    if (t.isUnaryExpression(p) && p.operator === "typeof") {
      const gp = pp?.parent;
      if (t.isBinaryExpression(gp)) {
        const other = gp.left === p ? gp.right : gp.left;
        if (t.isStringLiteral(other)) info.typeofChecks.push(other.value);
      }
    }

    // For-of
    if (t.isForOfStatement(p) && p.right === ref.node) info.usedInForOf = true;

    // Destructured
    if (t.isVariableDeclarator(p) && p.init === ref.node && t.isObjectPattern(p.id)) info.destructured = true;

    // Throw
    if (t.isThrowStatement(p) && p.argument === ref.node) info.thrownAsError = true;

    // New
    if (t.isNewExpression(p) && p.callee === ref.node) info.usedInNew = true;

    // Binary ops
    if (t.isBinaryExpression(p)) {
      if (["+","-","*","/","%","**"].includes(p.operator)) {
        info.binaryOpsCount++;
        const other = p.left === ref.node ? p.right : p.left;
        if (t.isNumericLiteral(other)) info.arithmeticOperand = true;
        if (t.isStringLiteral(other) && p.operator === "+") info.stringConcatenated = true;
      }
      if (["&","|","^","<<",">>",">>>"].includes(p.operator)) {
        info.bitwiseOps++;
        info.binaryOpsCount++;
      }
    }

    // Assignment: what is assigned to this variable
    if (t.isAssignmentExpression(p) && t.isMemberExpression(p.left) && p.left.object === ref.node && !p.left.computed) {
      if (p.left.property?.name) info.propertyWrites.add(p.left.property.name);
    }

    // Await
    if (t.isAwaitExpression(p) && p.argument === ref.node) info.awaitedResult = true;

    // Return
    if (t.isReturnStatement(p) && p.argument === ref.node) info.returnedFromFunc = true;

    // Spread
    if (t.isSpreadElement(p) && p.argument === ref.node) info.usedWithSpread = true;

    // Switch discriminant
    if (t.isSwitchStatement(p) && p.discriminant === ref.node) info.switchDiscriminant = true;

    // Conditional test
    if (t.isConditionalExpression(p) && p.test === ref.node) info.conditionalTest = true;
    if (t.isIfStatement(p) && p.test === ref.node) info.conditionalTest = true;

    // For loop init/update
    if (t.isForStatement(p)) {
      if (p.init && t.isAssignmentExpression(p.init) && p.init.left === ref.node) info.forLoopInit = true;
      if (p.init && t.isVariableDeclaration(p.init)) {
        for (const d of p.init.declarations) {
          if (d.id === ref.node) info.forLoopInit = true;
        }
      }
      if (p.update) {
        if (t.isUpdateExpression(p.update) && p.update.argument === ref.node) info.forLoopUpdate = true;
        if (t.isAssignmentExpression(p.update) && p.update.left === ref.node) info.forLoopUpdate = true;
      }
    }
    // For-in key
    if (t.isForInStatement(p) && p.right !== ref.node) {
      // Check if this is the variable declaration
    }
  }

  // Binding definition context
  if (binding.path) {
    try {
      const bp = binding.path;
      const init = bp.node?.init;
      if (init) {
        if (t.isMemberExpression(init)) info.assignedFromMember = true;
        if (t.isAwaitExpression(init)) info.assignedFromAwait = true;
        if (t.isCallExpression(init)) info.assignedFromCall = true;
      }
      const bpp = bp.parentPath;
      const bgp = bpp?.parentPath;
      if (bgp) {
        if (t.isForOfStatement(bgp.node)) info.usedAsForOfIterator = true;
        if (t.isForInStatement(bgp.node)) info.usedAsKey = true;
        if (t.isForStatement(bgp.node)) info.forLoopInit = true;
      }
    } catch (_) {}
  }

  // Dominant property
  const sorted = Object.entries(propCounts).sort((a,b) => b[1] - a[1]);
  if (sorted.length > 0) {
    info.dominantProp = sorted[0][0];
    info.dominantPropCount = sorted[0][1];
  }

  return info;
}

/** Enhanced name inference -- all rules */
function inferName(info, binding) {
  const mc = info.methodCalls;
  const pr = info.propertyReads;
  const pw = info.propertyWrites;
  const allProps = new Set([...pr, ...pw]);

  // --- Assignment source (require, new, literal) ---
  const initNode = binding?.path?.node?.init;
  if (initNode) {
    if (t.isCallExpression(initNode) && t.isIdentifier(initNode.callee) &&
        initNode.callee.name === "require" && initNode.arguments?.[0] &&
        t.isStringLiteral(initNode.arguments[0])) {
      const mod = initNode.arguments[0].value.replace(/^node:/, "");
      const knownMods = { fs:"fs",path:"pathMod",os:"os",http:"http",https:"https",
        url:"urlModule",crypto:"crypto",events:"events",stream:"streamMod",
        util:"util",child_process:"childProcess",net:"net",dns:"dns",
        tls:"tls",zlib:"zlib",buffer:"bufferModule",http2:"http2",
        assert:"assert",querystring:"querystring" };
      if (knownMods[mod]) return { name: knownMods[mod], confidence: 0.95, rule: "require_module" };
      const parts = mod.split("/");
      const last = parts[parts.length-1].replace(/[^a-zA-Z0-9_$]/g, "");
      if (last && last.length > 1) return { name: last, confidence: 0.80, rule: "require_module" };
    }
    if (t.isNewExpression(initNode) && t.isIdentifier(initNode.callee)) {
      const cn = initNode.callee.name;
      if (cn.includes("Error")) return { name: "error", confidence: 0.90, rule: "new_error" };
      if (cn === "Map") return { name: "map", confidence: 0.85, rule: "new_collection" };
      if (cn === "Set") return { name: "set", confidence: 0.85, rule: "new_collection" };
      if (cn === "WeakMap") return { name: "weakMap", confidence: 0.85, rule: "new_collection" };
      if (cn === "WeakSet") return { name: "weakSet", confidence: 0.85, rule: "new_collection" };
      if (cn === "RegExp") return { name: "regex", confidence: 0.80, rule: "new_regex" };
      if (cn === "Date") return { name: "date", confidence: 0.80, rule: "new_date" };
      if (cn === "URL") return { name: "url", confidence: 0.85, rule: "new_url" };
      if (cn === "Promise") return { name: "promise", confidence: 0.80, rule: "new_promise" };
      if (cn === "AbortController") return { name: "abortCtrl", confidence: 0.85, rule: "new_abort" };
      if (cn === "TextDecoder") return { name: "decoder", confidence: 0.85, rule: "new_decoder" };
      if (cn === "TextEncoder") return { name: "encoder", confidence: 0.85, rule: "new_encoder" };
      if (cn === "EventEmitter") return { name: "emitter", confidence: 0.85, rule: "new_emitter" };
      if (cn === "Buffer") return { name: "buf", confidence: 0.85, rule: "new_buffer" };
      // Generic new: lowercase first letter
      const lc = cn[0].toLowerCase() + cn.slice(1);
      if (lc.length > 2 && !RESERVED.has(lc)) return { name: lc, confidence: 0.65, rule: "new_generic" };
    }
    if (t.isArrayExpression(initNode)) return { name: "items", confidence: 0.60, rule: "array_literal" };
    if (t.isRegExpLiteral(initNode)) return { name: "pattern", confidence: 0.75, rule: "regex_literal" };
    if (t.isObjectExpression(initNode)) {
      // Check if it has known property names
      const propNames = initNode.properties
        .filter(p => t.isObjectProperty(p) && t.isIdentifier(p.key))
        .map(p => p.key.name);
      if (propNames.includes("headers") || propNames.includes("method")) return { name: "requestOpts", confidence: 0.70, rule: "obj_request" };
      if (propNames.includes("host") || propNames.includes("port") || propNames.includes("hostname")) return { name: "connOpts", confidence: 0.70, rule: "obj_connection" };
      if (propNames.length >= 3) return { name: "config", confidence: 0.45, rule: "obj_config" };
    }
    // Assigned from await
    if (t.isAwaitExpression(initNode)) return { name: "result", confidence: 0.50, rule: "await_result" };
    // Assigned from boolean literal
    if (t.isBooleanLiteral(initNode)) return { name: "flag", confidence: 0.55, rule: "bool_literal" };
    // Assigned from numeric literal (0 or 1 -> counter, else -> value)
    if (t.isNumericLiteral(initNode)) {
      if (initNode.value === 0 || initNode.value === 1) {
        if (info.binaryOpsCount >= 2) return { name: "count", confidence: 0.55, rule: "numeric_counter" };
      }
      return { name: "num", confidence: 0.45, rule: "numeric_literal" };
    }
    // Assigned from string literal
    if (t.isStringLiteral(initNode)) {
      if (initNode.value.length === 0) return { name: "str", confidence: 0.40, rule: "empty_string" };
      return { name: "str", confidence: 0.45, rule: "string_literal" };
    }
    // Assigned from template literal
    if (t.isTemplateLiteral(initNode)) return { name: "str", confidence: 0.45, rule: "template_literal" };
    // Assigned from null/undefined
    if (t.isNullLiteral(initNode)) return { name: "ref", confidence: 0.40, rule: "null_init" };
  }

  // --- Rule 11: Prototype access pattern ---
  if (info.prototypeAccess) return { name: "ctor", confidence: 0.75, rule: "prototype_access" };

  // --- Error pattern ---
  if (pr.has("message") && (pr.has("stack") || pr.has("code"))) return { name: "error", confidence: 0.90, rule: "error_props" };
  if (info.thrownAsError) return { name: "error", confidence: 0.85, rule: "throw_target" };

  // --- String methods ---
  const strMethods = ["split","trim","replace","replaceAll","match","indexOf","startsWith","endsWith","toLowerCase","toUpperCase","substring","charAt","padStart","padEnd","repeat","normalize","trimStart","trimEnd","search","slice","localeCompare","charCodeAt","codePointAt"];
  const strScore = strMethods.filter(m => mc.has(m)).length;
  if (strScore >= 2) return { name: "str", confidence: 0.85, rule: "string_api" };
  if (mc.has("split") && !mc.has("push")) return { name: "input", confidence: 0.75, rule: "string_api" };

  // --- Array methods ---
  const arrMethods = ["push","pop","shift","unshift","map","filter","reduce","forEach","find","some","every","sort","slice","splice","concat","join","includes","indexOf","findIndex","flat","flatMap","reverse","fill","entries","values","keys"];
  const arrScore = arrMethods.filter(m => mc.has(m)).length;
  if (arrScore >= 2) return { name: "items", confidence: 0.85, rule: "array_api" };
  if (mc.has("push") || mc.has("pop") || mc.has("shift") || mc.has("unshift")) return { name: "items", confidence: 0.80, rule: "array_api" };
  if ((mc.has("map") || mc.has("filter") || mc.has("forEach")) && info.lengthAccess) return { name: "items", confidence: 0.80, rule: "array_api" };
  if (mc.has("map") || mc.has("filter") || mc.has("forEach")) return { name: "items", confidence: 0.70, rule: "array_api" };

  // --- Map/Set ---
  if (mc.has("get") && mc.has("set") && mc.has("has")) return { name: "cache", confidence: 0.80, rule: "map_api" };
  if (mc.has("get") && mc.has("set")) return { name: "store", confidence: 0.70, rule: "map_api" };
  if (mc.has("add") && mc.has("has")) return { name: "seen", confidence: 0.70, rule: "set_api" };
  if (mc.has("delete") && mc.has("has") && mc.has("get")) return { name: "cache", confidence: 0.70, rule: "map_api" };

  // --- Promise ---
  if (mc.has("then") && mc.has("catch")) return { name: "promise", confidence: 0.85, rule: "promise_api" };
  if (mc.has("then")) return { name: "promise", confidence: 0.70, rule: "promise_api" };

  // --- Stream/EventEmitter ---
  if (mc.has("pipe") && (mc.has("on") || mc.has("write"))) return { name: "stream", confidence: 0.80, rule: "stream_api" };
  if (mc.has("pipe")) return { name: "stream", confidence: 0.70, rule: "stream_api" };
  if (mc.has("on") && mc.has("emit")) return { name: "emitter", confidence: 0.80, rule: "emitter_api" };
  if (mc.has("on") && mc.has("removeListener")) return { name: "emitter", confidence: 0.75, rule: "emitter_api" };
  if (mc.has("addListener") && mc.has("removeListener")) return { name: "emitter", confidence: 0.75, rule: "emitter_api" };

  // --- fs/path/crypto ---
  const fsMethods = ["readFileSync","writeFileSync","readFile","writeFile","existsSync","mkdirSync","readdirSync","statSync","unlinkSync","rename","createReadStream","createWriteStream","access","mkdir","rmdir","readdir","stat","lstat"];
  if (fsMethods.some(m => mc.has(m))) return { name: "fs", confidence: 0.90, rule: "fs_api" };
  if (mc.has("resolve") && mc.has("join") && !mc.has("then")) return { name: "pathMod", confidence: 0.85, rule: "path_api" };
  if (mc.has("createHash") || mc.has("randomBytes") || mc.has("createHmac")) return { name: "crypto", confidence: 0.90, rule: "crypto_api" };

  // --- HTTP request/response ---
  const reqProps = ["body","params","query","headers","method","url","hostname","path","protocol"];
  if (reqProps.filter(p => allProps.has(p)).length >= 2) return { name: "request", confidence: 0.80, rule: "http_req" };
  if (reqProps.filter(p => allProps.has(p)).length >= 1 && mc.has("on")) return { name: "request", confidence: 0.70, rule: "http_req" };
  const resMethods = ["send","json","status","render","redirect","end","write","writeHead","setHeader"];
  if (resMethods.filter(m => mc.has(m)).length >= 2) return { name: "response", confidence: 0.85, rule: "http_res" };

  // --- DOM ---
  const domProps = ["innerHTML","textContent","className","style","children","parentNode","tagName","nodeType","firstChild","lastChild","nextSibling","attributes"];
  if (domProps.filter(p => allProps.has(p)).length >= 2) return { name: "element", confidence: 0.85, rule: "dom_api" };
  if (mc.has("createElement") || mc.has("querySelector") || mc.has("querySelectorAll")) return { name: "doc", confidence: 0.85, rule: "dom_api" };
  if (mc.has("getAttribute") || mc.has("setAttribute") || mc.has("addEventListener")) return { name: "element", confidence: 0.80, rule: "dom_api" };

  // --- Rule 12: High binary ops, no methods -> counter/offset ---
  if (info.binaryOpsCount >= 3 && mc.size === 0 && pr.size <= 1) {
    if (info.bitwiseOps >= 2) return { name: "flags", confidence: 0.60, rule: "bitwise_pattern" };
    if (info.forLoopInit || info.forLoopUpdate) return { name: "idx", confidence: 0.70, rule: "loop_counter" };
    return { name: "offset", confidence: 0.55, rule: "high_binary_ops" };
  }

  // --- Rule 20: For loop counter ---
  if (info.forLoopInit) {
    if (info.arithmeticOperand || info.binaryOpsCount >= 1) return { name: "idx", confidence: 0.75, rule: "for_loop_idx" };
  }

  // --- typeof check ---
  if (info.typeofChecks.length > 0) {
    const types = new Set(info.typeofChecks);
    if (types.has("function")) return { name: "fn", confidence: 0.75, rule: "typeof_fn" };
    if (types.has("string")) return { name: "str", confidence: 0.70, rule: "typeof_str" };
    if (types.has("number")) return { name: "num", confidence: 0.70, rule: "typeof_num" };
    if (types.has("boolean")) return { name: "flag", confidence: 0.65, rule: "typeof_bool" };
    if (types.has("object")) return { name: "obj", confidence: 0.55, rule: "typeof_obj" };
  }

  // --- Rule 13: Purely called, no props ---
  if (info.calledAs && !info.usedInNew && mc.size === 0 && pr.size === 0 && info.binaryOpsCount === 0) {
    return { name: "handler", confidence: 0.55, rule: "pure_callback" };
  }

  // --- Rule 18: Switch discriminant ---
  if (info.switchDiscriminant) return { name: "kind", confidence: 0.70, rule: "switch_disc" };

  // --- Callback pattern ---
  if (info.calledAs && info.typeofChecks.includes("function")) return { name: "callback", confidence: 0.80, rule: "callback" };

  // --- Iterator ---
  if (info.usedAsForOfIterator) return { name: "item", confidence: 0.80, rule: "for_of_item" };
  if (info.usedAsKey) return { name: "key", confidence: 0.80, rule: "for_in_key" };
  if (info.usedInForOf) return { name: "items", confidence: 0.75, rule: "iterable" };

  // --- Comparison (many string comparisons -> kind/type) ---
  if (info.comparedWith.length >= 3) {
    const httpMethods = ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"];
    if (info.comparedWith.some(v => httpMethods.includes(v))) return { name: "method", confidence: 0.80, rule: "http_method" };
    return { name: "kind", confidence: 0.70, rule: "multi_compare" };
  }

  // --- Rule 21: Await result ---
  if (info.assignedFromAwait) return { name: "result", confidence: 0.55, rule: "await_result" };

  // --- Destructuring ---
  if (info.destructured) return { name: "options", confidence: 0.60, rule: "destructured" };

  // --- Rule 24: Length/size dominant -> collection ---
  if (info.lengthAccess && info.indexAccessed && mc.size === 0) return { name: "data", confidence: 0.55, rule: "length_index" };
  if (info.lengthAccess && !info.calledAs) return { name: "collection", confidence: 0.45, rule: "length_access" };

  // --- Index access ---
  if (info.indexAccessed && allProps.size === 0 && mc.size === 0) return { name: "source", confidence: 0.50, rule: "index_access" };

  // --- Rule 25: Bitwise dominant ---
  if (info.bitwiseOps >= 2) return { name: "flags", confidence: 0.60, rule: "bitwise_pattern" };

  // --- Arithmetic ---
  if (info.arithmeticOperand && !info.stringConcatenated) return { name: "num", confidence: 0.55, rule: "arithmetic" };
  if (info.stringConcatenated && !info.arithmeticOperand) return { name: "str", confidence: 0.50, rule: "string_concat" };

  // --- Constructor ---
  if (info.usedInNew) return { name: "Ctor", confidence: 0.70, rule: "new_call" };

  // --- Config/options (many properties, few methods) ---
  if (allProps.size >= 4 && mc.size <= 1 && !info.calledAs) return { name: "options", confidence: 0.50, rule: "config_obj" };
  if (allProps.size >= 2 && mc.size === 0 && !info.calledAs && !info.indexAccessed) return { name: "ctx", confidence: 0.40, rule: "context_obj" };

  // --- Rule 19: Namespace property access dominant ---
  if (info.dominantPropCount >= 3 && info.dominantProp) {
    // e.C accessed 100 times -> e is likely a module/namespace
    if (info.dominantPropCount >= 5) return { name: "mod", confidence: 0.45, rule: "ns_dominant" };
  }

  // --- Rule 17: Returned from func ---
  if (info.returnedFromFunc && mc.size === 0 && pr.size === 0 && !info.calledAs) {
    return { name: "result", confidence: 0.40, rule: "return_value" };
  }

  // --- Rule 15: Assigned from member expression ---
  if (info.assignedFromMember && mc.size === 0 && pr.size <= 1) {
    return { name: "ref", confidence: 0.35, rule: "member_assign" };
  }

  // --- Rule 16: Assigned from call ---
  if (info.assignedFromCall && mc.size === 0 && pr.size <= 1 && !info.calledAs) {
    return { name: "val", confidence: 0.35, rule: "call_result" };
  }

  // --- Spread usage ---
  if (info.usedWithSpread) return { name: "rest", confidence: 0.45, rule: "spread" };

  // --- Ultra-low confidence fallbacks based on reference count ---
  // Single-use variables that are just passed to a function
  if (info.refCount <= 2 && info.passedToFunctions.length >= 1 && mc.size === 0 && pr.size === 0) {
    return { name: "arg", confidence: 0.30, rule: "pass_through" };
  }

  return null;
}

/** Parameter position inference (enhanced for Cursor patterns) */
function inferParam(funcPath, idx, count, bodyStr) {
  // Express middleware: (req, res, next)
  const reqInd = [".body",".params",".query",".headers",".method"];
  const resInd = [".send(",".json(",".status(",".render(",".redirect("];
  const reqS = reqInd.filter(i => bodyStr.includes(i)).length;
  const resS = resInd.filter(i => bodyStr.includes(i)).length;
  if (reqS >= 1 && resS >= 1) {
    if (count === 4) return ["error","request","response","next"][idx];
    if (count >= 2 && count <= 3) return ["request","response","next"][idx];
  }

  // CommonJS module: (exports, module, require)
  if (count >= 2 && count <= 3) {
    if (bodyStr.includes("module.exports") || bodyStr.includes(".exports")) {
      if (idx === 0) return "exports";
      if (idx === 1) return "module";
      if (idx === 2) return "require";
    }
  }

  // Webpack module function: (module, exports, __webpack_require__)
  if (count === 3 && bodyStr.includes("__webpack_require__")) {
    if (idx === 0) return "module";
    if (idx === 1) return "exports";
    if (idx === 2) return "require";
  }

  // Array iterator callbacks
  if (t.isCallExpression(funcPath.parent) && t.isMemberExpression(funcPath.parent.callee)) {
    const mn = funcPath.parent.callee.property?.name;
    const iterM = ["map","filter","forEach","find","findIndex","some","every","flatMap"];
    if (iterM.includes(mn)) {
      if (idx === 0) return "item";
      if (idx === 1) return "index";
      if (idx === 2) return "array";
    }
    if (mn === "reduce" || mn === "reduceRight") {
      if (idx === 0) return "acc";
      if (idx === 1) return "item";
      if (idx === 2) return "index";
    }
    if (mn === "sort" && count === 2) return idx === 0 ? "left" : "right";
    if (mn === "replace" && idx === 0) return "match";

    // Event handlers: .on("event", handler)
    if ((mn === "on" || mn === "once" || mn === "addEventListener") &&
        funcPath.parent.arguments?.[0] && t.isStringLiteral(funcPath.parent.arguments[0])) {
      const ev = funcPath.parent.arguments[0].value;
      if (ev === "error" && idx === 0) return "error";
      if (ev === "data" && idx === 0) return "chunk";
      if (ev === "message" && idx === 0) return "message";
      if (ev === "connection" && idx === 0) return "socket";
      if (ev === "request" && idx === 0) return "request";
      if (ev === "response" && idx === 0) return "response";
      if (ev === "end" && idx === 0) return "eventData";
      if (ev === "close" && idx === 0) return "eventData";
      if (ev === "open" && idx === 0) return "eventData";
      if (ev === "click" && idx === 0) return "event";
      if (ev === "change" && idx === 0) return "event";
      if (idx === 0) return "eventData";
    }

    // Promise: .then(result => ...), .catch(err => ...)
    if (mn === "then") {
      if (idx === 0) return "result";
    }
    if (mn === "catch") {
      if (idx === 0) return "error";
    }
  }

  // Single-parameter function that looks like a callback
  if (count === 1 && funcPath.parent) {
    // Passed to a function call as argument
    if (t.isCallExpression(funcPath.parent)) {
      const callee = funcPath.parent.callee;
      if (t.isIdentifier(callee)) {
        const fn = callee.name;
        if (fn === "setTimeout" || fn === "setInterval") return null; // no param
        if (fn.includes("Error") || fn === "reject") return "error";
      }
      // .subscribe(callback)
      if (t.isMemberExpression(callee) && !callee.computed) {
        const mn = callee.property?.name;
        if (mn === "subscribe" && idx === 0) return "value";
        if (mn === "use" && idx === 0) return "arg"; // middleware
      }
    }
  }

  // Two-parameter function: (err, result) pattern
  if (count === 2) {
    // Check if body uses first param in error-like way
    if (idx === 0 && (bodyStr.includes(".message") || bodyStr.includes(".stack") || bodyStr.includes("throw "))) {
      return "error";
    }
    if (idx === 1 && bodyStr.includes("return ")) {
      return "result";
    }
  }

  return null;
}

// ---------- Parse ----------
let source, fileSize;
try {
  fileSize = statSync(inputPath).size;
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  emit({ success: false, errors: [`Dosya okunamadi: ${err.message}`] });
  process.exit(1);
}

const startTime = Date.now();

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
} catch (err) {
  emit({ success: false, errors: [`Parse hatasi: ${err.message}`] });
  process.exit(1);
}

// ---------- Rename ----------
let renameCount = 0;
const ruleHits = Object.create(null);
const minConfidence = 0.30;

try {
  traverse(ast, {
    CatchClause(path) {
      const param = path.node.param;
      if (!param || !t.isIdentifier(param) || !isMinified(param.name)) return;
      const nn = makeUnique(path.scope, "error");
      if (nn && nn !== param.name) {
        try { path.scope.rename(param.name, nn); renameCount++; ruleHits["catch_clause"] = (ruleHits["catch_clause"]||0)+1; } catch(_){}
      }
    },
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression"(path) {
      const params = path.node.params;
      if (params.length === 0) return;
      let bodyStr = "";
      try {
        const { code } = generate(path.node.body, { compact: true });
        bodyStr = code.length > 4000 ? code.slice(0, 4000) : code;
      } catch (_) {}

      for (let i = 0; i < params.length; i++) {
        const p = params[i];
        if (!t.isIdentifier(p) || !isMinified(p.name)) continue;
        const binding = path.scope.getBinding(p.name);
        if (!binding) continue;

        let best = null;
        const posName = inferParam(path, i, params.length, bodyStr);
        if (posName) best = { name: posName, confidence: 0.80, rule: "param_position" };

        const info = collectUsage(binding);
        const usageResult = inferName(info, binding);
        if (usageResult && (!best || usageResult.confidence > best.confidence)) best = usageResult;

        if (!best || best.confidence < minConfidence) continue;
        const nn = makeUnique(path.scope, best.name);
        if (!nn || nn === p.name) continue;
        try {
          path.scope.rename(p.name, nn);
          renameCount++;
          ruleHits[best.rule] = (ruleHits[best.rule]||0)+1;
        } catch(_){}
      }
    },
    VariableDeclarator(path) {
      const id = path.node.id;
      if (!t.isIdentifier(id) || !isMinified(id.name)) return;
      const binding = path.scope.getBinding(id.name);
      if (!binding) return;

      const info = collectUsage(binding);
      const best = inferName(info, binding);

      if (!best || best.confidence < minConfidence) return;
      const nn = makeUnique(path.scope, best.name);
      if (!nn || nn === id.name) return;
      try {
        path.scope.rename(id.name, nn);
        renameCount++;
        ruleHits[best.rule] = (ruleHits[best.rule]||0)+1;
      } catch(_){}
    },
  });
} catch (err) {
  emit({ success: false, errors: [`Traverse hatasi: ${err.message}`] });
  process.exit(1);
}

// ---------- Generate Output ----------
try {
  const { code } = generate(ast, {
    comments: true,
    compact: false,
    concise: false,
    jsescOption: { minimal: true },
  });

  const outDir = dirname(outputPath);
  try { mkdirSync(outDir, { recursive: true }); } catch (_) {}

  writeFileSync(outputPath, code, "utf-8");
  const outputSize = statSync(outputPath).size;

  emit({
    success: true,
    renamed: renameCount,
    stats: {
      input_size: fileSize,
      output_size: outputSize,
      duration_ms: Date.now() - startTime,
      rule_hits: ruleHits,
    },
    errors: [],
  });
} catch (err) {
  emit({
    success: false,
    renamed: renameCount,
    errors: [`Generate hatasi: ${err.message}`],
  });
}
