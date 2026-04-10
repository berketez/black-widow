#!/usr/bin/env node
/**
 * aggressive-rename.mjs -- Phase 2 Agresif Rename
 *
 * Enhanced rename sonrasi kalan minified identifier'lari rename eder.
 * Daha dusuk confidence threshold + daha fazla fallback kural.
 *
 * Ozellikle hedefler:
 *   - Tek-harfli function parametreleri (_, T, K, R, O, q, ...)
 *   - Kisa scope degiskenleri
 *   - Webpack module wrapper parametreleri
 *   - Arrow function parametreleri
 *
 * Kullanim:
 *   node --max-old-space-size=8192 aggressive-rename.mjs <input> <output>
 */

import { readFileSync, writeFileSync, statSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

const args = process.argv.slice(2);
const inputPath = resolve(args[0]);
const outputPath = resolve(args[1]);

function emit(obj) { process.stdout.write(JSON.stringify(obj) + "\n"); }

if (!args[0] || !args[1]) {
  emit({ success: false, errors: ["Usage: node aggressive-rename.mjs <input> <output>"] });
  process.exit(1);
}

const RESERVED = new Set([
  "break","case","catch","continue","debugger","default","delete",
  "do","else","finally","for","function","if","in","instanceof",
  "new","return","switch","this","throw","try","typeof","var",
  "void","while","with","class","const","enum","export","extends",
  "import","super","implements","interface","let","package","private",
  "protected","public","static","yield","null","true","false",
  "undefined","NaN","Infinity","arguments","eval",
]);

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
  for (let i = 2; i < 500; i++) {
    const c = `${baseName}${i}`;
    if (!scope.hasBinding(c)) {
      let p = scope.parent, conflict = false;
      while (p) { if (p.hasOwnBinding(c)) { conflict = true; break; } p = p.parent; }
      if (!conflict) return c;
    }
  }
  return null;
}

/**
 * Scope-based context inference: what is the enclosing context?
 * Returns a hint string based on the parent/grandparent.
 */
function getContextHint(path) {
  let current = path;
  for (let i = 0; i < 10; i++) {
    current = current.parentPath;
    if (!current) break;

    // Property assignment on a known object
    if (t.isObjectProperty(current.node)) {
      const key = current.node.key;
      if (t.isIdentifier(key)) return key.name;
      if (t.isStringLiteral(key)) return key.value;
    }

    // Variable declarator with a meaningful name
    if (t.isVariableDeclarator(current.node) && t.isIdentifier(current.node.id)) {
      const name = current.node.id.name;
      if (name.length > 3) return name;
    }

    // Function/method with a name
    if (t.isFunctionDeclaration(current.node) && current.node.id?.name) {
      return current.node.id.name;
    }
    if (t.isClassMethod(current.node) && t.isIdentifier(current.node.key)) {
      return current.node.key.name;
    }
  }
  return null;
}

/**
 * Analyze how a binding is used to pick a generic but meaningful name.
 * This is more aggressive than enhanced-rename -- lower confidence threshold.
 */
function analyzeBinding(binding, scope) {
  if (!binding?.referencePaths) return null;

  const refs = binding.referencePaths;
  const refCount = refs.length;

  // Collect all info
  let memberAccesses = new Set();
  let methodCalls = new Set();
  let calledAsFunction = false;
  let usedInNew = false;
  let comparedWithStrings = [];
  let arithmeticUse = false;
  let bitwiseUse = false;
  let indexAccessed = false;
  let stringOps = false;
  let forInit = false;
  let forUpdate = false;
  let thrownAsError = false;
  let returnedFromFunc = false;
  let usedInForOf = false;
  let assignedFromAwait = false;
  let assignedFromNew = false;
  let assignedFromCall = false;
  let assignedFromMember = false;
  let passedToFunctions = [];
  let typeofChecks = [];
  let conditionalTest = false;
  let switchDisc = false;
  let lengthAccess = false;
  let spreadUsed = false;
  let binaryOps = 0;

  for (const ref of refs) {
    const p = ref.parent;
    const pp = ref.parentPath;
    if (!p) continue;

    // Member expression
    if (t.isMemberExpression(p) && p.object === ref.node) {
      if (!p.computed && t.isIdentifier(p.property)) {
        const prop = p.property.name;
        memberAccesses.add(prop);
        const gp = pp?.parent;
        if (t.isCallExpression(gp) && gp.callee === p) {
          methodCalls.add(prop);
        }
        if (prop === "length" || prop === "size") lengthAccess = true;
      }
      if (p.computed) indexAccessed = true;
    }

    // Called as function
    if (t.isCallExpression(p) && p.callee === ref.node) calledAsFunction = true;
    if (t.isNewExpression(p) && p.callee === ref.node) usedInNew = true;

    // Binary ops
    if (t.isBinaryExpression(p)) {
      binaryOps++;
      if (["+","-","*","/","%","**"].includes(p.operator)) {
        const other = p.left === ref.node ? p.right : p.left;
        if (t.isNumericLiteral(other)) arithmeticUse = true;
        if (t.isStringLiteral(other) && p.operator === "+") stringOps = true;
      }
      if (["&","|","^","<<",">>",">>>"].includes(p.operator)) bitwiseUse = true;
      if (["===","==","!==","!="].includes(p.operator)) {
        const other = p.left === ref.node ? p.right : p.left;
        if (t.isStringLiteral(other)) comparedWithStrings.push(other.value);
      }
    }

    // Typeof
    if (t.isUnaryExpression(p) && p.operator === "typeof") {
      const gp = pp?.parent;
      if (t.isBinaryExpression(gp)) {
        const other = gp.left === p ? gp.right : gp.left;
        if (t.isStringLiteral(other)) typeofChecks.push(other.value);
      }
    }

    // Control flow
    if (t.isIfStatement(p) && p.test === ref.node) conditionalTest = true;
    if (t.isConditionalExpression(p) && p.test === ref.node) conditionalTest = true;
    if (t.isSwitchStatement(p) && p.discriminant === ref.node) switchDisc = true;

    // For loop
    if (t.isForStatement(p)) {
      if (p.init && (
        (t.isAssignmentExpression(p.init) && p.init.left === ref.node) ||
        (t.isVariableDeclaration(p.init) && p.init.declarations.some(d => d.id === ref.node))
      )) forInit = true;
      if (p.update && (
        (t.isUpdateExpression(p.update) && p.update.argument === ref.node) ||
        (t.isAssignmentExpression(p.update) && p.update.left === ref.node)
      )) forUpdate = true;
    }

    // For-of
    if (t.isForOfStatement(p) && p.right === ref.node) usedInForOf = true;

    // Throw
    if (t.isThrowStatement(p)) thrownAsError = true;

    // Return
    if (t.isReturnStatement(p) && p.argument === ref.node) returnedFromFunc = true;

    // Spread
    if (t.isSpreadElement(p) && p.argument === ref.node) spreadUsed = true;

    // Passed to functions
    if (t.isCallExpression(p) && p.arguments?.includes(ref.node)) {
      const callee = p.callee;
      if (t.isIdentifier(callee)) passedToFunctions.push(callee.name);
      if (t.isMemberExpression(callee) && !callee.computed && t.isIdentifier(callee.property)) {
        passedToFunctions.push(callee.property.name);
      }
    }
  }

  // Check init expression
  const initNode = binding.path?.node?.init;
  if (initNode) {
    if (t.isAwaitExpression(initNode)) assignedFromAwait = true;
    if (t.isNewExpression(initNode)) assignedFromNew = true;
    if (t.isCallExpression(initNode)) assignedFromCall = true;
    if (t.isMemberExpression(initNode)) assignedFromMember = true;
  }

  // ---------- Decision Rules ----------

  // Rule: Error handling
  if (thrownAsError) return "err";
  if (memberAccesses.has("message") && (memberAccesses.has("stack") || memberAccesses.has("code"))) return "err";

  // Rule: For loop counter
  if (forInit && (forUpdate || arithmeticUse)) return "i";
  if (forInit) return "idx";

  // Rule: For-of item
  if (usedInForOf) return "items";

  // Rule: Switch discriminant
  if (switchDisc) return "kind";

  // Rule: String comparison chain
  if (comparedWithStrings.length >= 2) return "type";

  // Rule: Typeof check
  if (typeofChecks.length > 0) {
    if (typeofChecks.includes("function")) return "fn";
    if (typeofChecks.includes("string")) return "str";
    if (typeofChecks.includes("number")) return "num";
    if (typeofChecks.includes("object")) return "obj";
    if (typeofChecks.includes("boolean")) return "flag";
  }

  // Rule: Constructor
  if (usedInNew) return "Ctor";

  // Rule: Array methods
  const arrM = ["push","pop","shift","unshift","map","filter","reduce","forEach","find","some","every","sort","splice","concat","join","includes","indexOf","findIndex","flat","flatMap"];
  if (arrM.filter(m => methodCalls.has(m)).length >= 1) return "arr";

  // Rule: Map/Set
  if (methodCalls.has("get") && methodCalls.has("set")) return "map";
  if (methodCalls.has("add") && methodCalls.has("has")) return "set";

  // Rule: Promise
  if (methodCalls.has("then")) return "promise";

  // Rule: Stream
  if (methodCalls.has("pipe")) return "stream";
  if (methodCalls.has("on") && methodCalls.has("emit")) return "emitter";

  // Rule: String methods
  const strM = ["split","trim","replace","match","indexOf","startsWith","endsWith","toLowerCase","toUpperCase","substring","charAt","padStart","padEnd","search","slice"];
  if (strM.filter(m => methodCalls.has(m)).length >= 1) return "str";

  // Rule: Pure function call (no props, no methods)
  if (calledAsFunction && !usedInNew && methodCalls.size === 0 && memberAccesses.size === 0) return "fn";

  // Rule: Bitwise heavy
  if (bitwiseUse) return "bits";

  // Rule: Arithmetic heavy
  if (arithmeticUse && binaryOps >= 2) return "num";

  // Rule: Length/index access
  if (lengthAccess && indexAccessed) return "arr";
  if (lengthAccess) return "list";
  if (indexAccessed && methodCalls.size === 0) return "data";

  // Rule: Conditional test
  if (conditionalTest && memberAccesses.size === 0) return "flag";

  // Rule: Await result
  if (assignedFromAwait) return "result";

  // Rule: New expression result
  if (assignedFromNew) return "inst";

  // Rule: Spread
  if (spreadUsed) return "rest";

  // Rule: Many properties, few methods -> object/config
  if (memberAccesses.size >= 3 && methodCalls.size <= 1 && !calledAsFunction) return "opts";
  if (memberAccesses.size >= 1 && methodCalls.size === 0 && !calledAsFunction && !indexAccessed) return "ctx";

  // Rule: Returned from function
  if (returnedFromFunc && methodCalls.size === 0 && memberAccesses.size === 0) return "val";

  // Rule: String concatenation
  if (stringOps) return "str";

  // Rule: Assigned from call (generic)
  if (assignedFromCall) return "val";

  // Rule: Assigned from member
  if (assignedFromMember) return "ref";

  // Rule: Single use passed to function
  if (refCount <= 2 && passedToFunctions.length >= 1) return "arg";

  // Rule: Parameter with very few refs
  if (refCount === 0) return "unused";
  if (refCount === 1) return "tmp";

  return "v";
}

// ---------- Parse ----------
let source, fileSize;
try {
  fileSize = statSync(inputPath).size;
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  emit({ success: false, errors: [`Read error: ${err.message}`] });
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
  emit({ success: false, errors: [`Parse error: ${err.message}`] });
  process.exit(1);
}

// ---------- Rename ----------
let renameCount = 0;
const ruleHits = Object.create(null);

function doRename(scope, oldName, newBase, rule) {
  const nn = makeUnique(scope, newBase);
  if (!nn || nn === oldName) return false;
  try {
    scope.rename(oldName, nn);
    renameCount++;
    ruleHits[rule] = (ruleHits[rule]||0)+1;
    return true;
  } catch(_) { return false; }
}

try {
  traverse(ast, {
    // Catch clause params
    CatchClause(path) {
      const param = path.node.param;
      if (!param || !t.isIdentifier(param) || !isMinified(param.name)) return;
      doRename(path.scope, param.name, "err", "catch_param");
    },

    // Function params
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression"(path) {
      const params = path.node.params;
      if (params.length === 0) return;

      // First, try positional inference
      let bodyStr = "";
      try {
        const { code } = generate(path.node.body, { compact: true });
        bodyStr = code.length > 2000 ? code.slice(0, 2000) : code;
      } catch (_) {}

      // Iterator callback detection
      const isIterCb = t.isCallExpression(path.parent) && t.isMemberExpression(path.parent.callee);
      let iterMethod = null;
      if (isIterCb && t.isIdentifier(path.parent.callee.property)) {
        iterMethod = path.parent.callee.property.name;
      }

      for (let i = 0; i < params.length; i++) {
        const p = params[i];
        if (!t.isIdentifier(p) || !isMinified(p.name)) continue;
        const binding = path.scope.getBinding(p.name);
        if (!binding) continue;

        // Positional: iterator callbacks
        if (iterMethod) {
          const iterM = ["map","filter","forEach","find","findIndex","some","every","flatMap"];
          if (iterM.includes(iterMethod)) {
            if (i === 0) { doRename(path.scope, p.name, "item", "iter_item"); continue; }
            if (i === 1) { doRename(path.scope, p.name, "idx", "iter_idx"); continue; }
            if (i === 2) { doRename(path.scope, p.name, "arr", "iter_arr"); continue; }
          }
          if (iterMethod === "reduce" || iterMethod === "reduceRight") {
            if (i === 0) { doRename(path.scope, p.name, "acc", "reduce_acc"); continue; }
            if (i === 1) { doRename(path.scope, p.name, "item", "reduce_item"); continue; }
            if (i === 2) { doRename(path.scope, p.name, "idx", "reduce_idx"); continue; }
          }
          if (iterMethod === "sort" && params.length === 2) {
            if (i === 0) { doRename(path.scope, p.name, "a", "sort_a"); continue; }
            if (i === 1) { doRename(path.scope, p.name, "b", "sort_b"); continue; }
          }
          if (iterMethod === "replace" && i === 0) { doRename(path.scope, p.name, "match", "replace_match"); continue; }
          // Event handlers
          if (["on","once","addEventListener"].includes(iterMethod)) {
            if (i === 0) { doRename(path.scope, p.name, "event", "event_param"); continue; }
          }
          if (iterMethod === "then" && i === 0) { doRename(path.scope, p.name, "result", "then_result"); continue; }
          if (iterMethod === "catch" && i === 0) { doRename(path.scope, p.name, "err", "catch_err"); continue; }
        }

        // Webpack CJS wrapper: (module, exports, require) / (exports, module)
        if (params.length >= 2 && params.length <= 3 && i === 0) {
          if (bodyStr.includes("__esModule") || bodyStr.includes("module.exports") || bodyStr.includes(".exports")) {
            if (params.length === 3) {
              if (i === 0) { doRename(path.scope, p.name, "module", "webpack_module"); continue; }
            } else {
              if (i === 0) { doRename(path.scope, p.name, "exports", "webpack_exports"); continue; }
            }
          }
        }
        if (params.length >= 2 && params.length <= 3 && i === 1) {
          if (bodyStr.includes("__esModule") || bodyStr.includes(".exports")) {
            if (params.length === 3) {
              if (i === 1) { doRename(path.scope, p.name, "exports", "webpack_exports"); continue; }
            } else {
              if (i === 1) { doRename(path.scope, p.name, "module", "webpack_module"); continue; }
            }
          }
        }
        if (params.length === 3 && i === 2 && bodyStr.includes("require")) {
          doRename(path.scope, p.name, "require", "webpack_require");
          continue;
        }

        // Error-first callback: (err, data)
        if (params.length === 2 && i === 0) {
          if (bodyStr.includes(".message") || bodyStr.includes(".stack") || bodyStr.includes("throw ")) {
            doRename(path.scope, p.name, "err", "errfirst_err");
            continue;
          }
        }

        // Generic: analyze usage
        const inferredName = analyzeBinding(binding, path.scope);
        if (inferredName) {
          doRename(path.scope, p.name, inferredName, "binding_analysis");
        }
      }
    },

    // Variable declarations
    VariableDeclarator(path) {
      const id = path.node.id;
      if (!t.isIdentifier(id) || !isMinified(id.name)) return;
      const binding = path.scope.getBinding(id.name);
      if (!binding) return;

      const inferredName = analyzeBinding(binding, path.scope);
      if (inferredName) {
        doRename(path.scope, id.name, inferredName, "var_binding");
      }
    },
  });
} catch (err) {
  emit({ success: false, errors: [`Traverse error: ${err.message}`] });
  process.exit(1);
}

// ---------- Output ----------
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
    errors: [`Generate error: ${err.message}`],
  });
}
