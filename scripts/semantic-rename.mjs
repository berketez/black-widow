#!/usr/bin/env node
/**
 * semantic-rename.mjs -- Scope-Aware Semantic Variable Renamer
 *
 * Black Widow v1.0 -- Karadul
 *
 * Minified tek/iki harfli identifier'lari kullanim baglamlarindan
 * anlamli isimlere donusturur. Babel scope.rename() ile guvenli rename.
 *
 * 10 Kural Seti:
 *   1. API call context:    e.split(".") -> e = input/str
 *   2. Method chain:        t.map(...)   -> t = items/list
 *   3. Property access:     n[i]         -> n = source/data
 *   4. Comparison:          e === "str"  -> e = value/key
 *   5. typeof check:        typeof e === "function" -> e = callback/fn
 *   6. Error handling:      catch(e)     -> e = error
 *   7. Callback pattern:    fn(e, t) where t is called -> t = callback
 *   8. DOM/Node.js pattern: e.createElement -> e = document
 *   9. Iterator:            for(let e of t) -> e = item, t = items
 *  10. Destructuring hint:  const {a, b} = e -> e = options/config
 *
 * Standalone kullanim:
 *   node --max-old-space-size=8192 semantic-rename.mjs <input> <output> [--dry-run] [--min-confidence 0.5]
 *
 * Cikti (stdout JSON):
 *   { success, renamed, mappings: [{scope, old, new, rule, confidence}], stats }
 *
 * Entegrasyon:
 *   deep-deobfuscate.mjs Phase 10 olarak dahil edilebilir.
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
const positional = args.filter((a) => !a.startsWith("--"));
const flags = new Map();
for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith("--") && args[i + 1] && !args[i + 1].startsWith("--")) {
    flags.set(args[i], args[i + 1]);
    i++;
  } else if (args[i].startsWith("--")) {
    flags.set(args[i], "true");
  }
}

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

if (positional.length < 2) {
  emit({
    success: false,
    errors: ["Kullanim: node semantic-rename.mjs <input> <output> [--dry-run] [--min-confidence 0.5]"],
  });
  process.exit(1);
}

const inputPath = resolve(positional[0]);
const outputPath = resolve(positional[1]);
const dryRun = flags.has("--dry-run");
const minConfidence = parseFloat(flags.get("--min-confidence") || "0.3");

// ---------- Reserved words ----------
const RESERVED = new Set([
  "break", "case", "catch", "continue", "debugger", "default", "delete",
  "do", "else", "finally", "for", "function", "if", "in", "instanceof",
  "new", "return", "switch", "this", "throw", "try", "typeof", "var",
  "void", "while", "with", "class", "const", "enum", "export", "extends",
  "import", "super", "implements", "interface", "let", "package", "private",
  "protected", "public", "static", "yield", "null", "true", "false",
  "undefined", "NaN", "Infinity", "arguments", "eval",
]);

// ---------- Helpers ----------

/** Bir ismin minified olup olmadigini kontrol et */
function isMinified(name) {
  // 1-2 harf: her zaman minified
  if (name.length <= 2) return true;
  // _ ile baslayanlar hariç (convention)
  if (name.startsWith("_")) return false;
  // $ ile baslayanlar hariç (jQuery, etc.)
  if (name.startsWith("$")) return false;
  return false;
}

/** Scope icinde isim kullanilabilir mi kontrol et */
function isNameAvailable(scope, name) {
  if (RESERVED.has(name)) return false;
  if (scope.hasBinding(name)) return false;
  // Parent scope'lara da bak
  let current = scope.parent;
  while (current) {
    if (current.hasOwnBinding(name)) return false;
    current = current.parent;
  }
  return true;
}

/** Cakisma varsa suffix ekle */
function makeUnique(scope, baseName) {
  if (isNameAvailable(scope, baseName)) return baseName;
  for (let i = 2; i < 100; i++) {
    const candidate = `${baseName}${i}`;
    if (isNameAvailable(scope, candidate)) return candidate;
  }
  return null; // Bulunamadi
}

/** Fonksiyon body'sini compact string olarak al (max 3000 char) */
function getBodyString(node) {
  try {
    if (!node.body) return "";
    const { code } = generate(node.body, { compact: true });
    return code.length > 3000 ? code.slice(0, 3000) : code;
  } catch (_) {
    return "";
  }
}

/** Bir binding'in tum reference'larini tarayarak kullanim bilgisi topla */
function collectUsageInfo(binding) {
  const info = {
    methodCalls: new Set(),      // e.split(), e.map() -> split, map
    propertyReads: new Set(),    // e.length, e.name -> length, name
    propertyWrites: new Set(),   // e.x = ... -> x
    calledAs: false,             // e(...) seklinde cagriliyor mu
    passedToFunctions: [],       // foo(e) -> foo
    comparedWith: [],            // e === "x" -> "x"
    typeofChecks: [],            // typeof e === "function" -> "function"
    assignedFrom: null,          // e = X -> X'in tipini anlamak icin
    usedInForOf: false,          // for(let x of e) -> e iterable
    usedAsForOfIterator: false,  // for(let e of x) -> e is item
    destructured: false,         // const {a} = e -> e is object
    indexAccessed: false,        // e[i] veya e[0] -> e is array/object
    usedWithSpread: false,       // ...e -> e is iterable
    arithmeticOperand: false,    // e + 1, e * 2 -> e is number
    returnedFromFunc: false,     // return e
    thrownAsError: false,        // throw e
    usedInNew: false,            // new e() -> e is constructor
    usedAsKey: false,            // obj[e] -> e is key
    stringConcatenated: false,   // "x" + e + "y" -> e is string
  };

  if (!binding || !binding.referencePaths) return info;

  for (const refPath of binding.referencePaths) {
    const parent = refPath.parent;
    const parentPath = refPath.parentPath;
    if (!parent) continue;

    // Method call: e.method()
    if (
      t.isMemberExpression(parent) &&
      parent.object === refPath.node &&
      !parent.computed
    ) {
      const propName = parent.property?.name;
      if (propName) {
        // Ustu CallExpression mi?
        const grandParent = parentPath?.parent;
        if (
          t.isCallExpression(grandParent) &&
          grandParent.callee === parent
        ) {
          info.methodCalls.add(propName);
        } else {
          info.propertyReads.add(propName);
        }
      }
    }

    // Computed property access: e[i] veya e["key"]
    if (
      t.isMemberExpression(parent) &&
      parent.object === refPath.node &&
      parent.computed
    ) {
      info.indexAccessed = true;
      // e["literal"] -> property read
      if (t.isStringLiteral(parent.property)) {
        info.propertyReads.add(parent.property.value);
      }
    }

    // e(...) - called as function
    if (t.isCallExpression(parent) && parent.callee === refPath.node) {
      info.calledAs = true;
    }

    // foo(e) - passed as argument
    if (t.isCallExpression(parent) && parent.arguments?.includes(refPath.node)) {
      const calleeName = parent.callee?.name ||
        (t.isMemberExpression(parent.callee) ? parent.callee.property?.name : null);
      if (calleeName) info.passedToFunctions.push(calleeName);
    }

    // e === "literal" veya "literal" === e
    if (t.isBinaryExpression(parent) && (parent.operator === "===" || parent.operator === "==")) {
      const other = parent.left === refPath.node ? parent.right : parent.left;
      if (t.isStringLiteral(other)) info.comparedWith.push(other.value);
      if (t.isNumericLiteral(other)) info.arithmeticOperand = true;
    }

    // typeof e === "X"
    if (t.isUnaryExpression(parent) && parent.operator === "typeof") {
      // Ustundeki binary expression'a bak
      const grandParent = parentPath?.parent;
      if (t.isBinaryExpression(grandParent)) {
        const other = grandParent.left === parent ? grandParent.right : grandParent.left;
        if (t.isStringLiteral(other)) info.typeofChecks.push(other.value);
      }
    }

    // for(... of e) -> e is iterable
    if (t.isForOfStatement(parent) && parent.right === refPath.node) {
      info.usedInForOf = true;
    }

    // for(let e of ...) -> e is item
    if (t.isForOfStatement(parent) && parent.left === refPath.node) {
      info.usedAsForOfIterator = true;
    }
    // VariableDeclaration icinde: for (let e of ...)
    if (
      t.isVariableDeclarator(parent) &&
      parent.id === refPath.node &&
      t.isVariableDeclaration(parentPath?.parent)
    ) {
      const grandParent = parentPath?.parentPath?.parent;
      if (t.isForOfStatement(grandParent)) {
        info.usedAsForOfIterator = true;
      }
      if (t.isForInStatement(grandParent)) {
        info.usedAsKey = true;
      }
    }

    // const {a, b} = e -> destructuring
    if (
      t.isVariableDeclarator(parent) &&
      parent.init === refPath.node &&
      t.isObjectPattern(parent.id)
    ) {
      info.destructured = true;
    }

    // Array destructuring: const [a, b] = e
    if (
      t.isVariableDeclarator(parent) &&
      parent.init === refPath.node &&
      t.isArrayPattern(parent.id)
    ) {
      info.usedInForOf = true; // Array gibi davranir
    }

    // ...e (spread)
    if (t.isSpreadElement(parent) && parent.argument === refPath.node) {
      info.usedWithSpread = true;
    }

    // Arithmetic: e + 1, e * 2
    if (
      t.isBinaryExpression(parent) &&
      ["+", "-", "*", "/", "%", "**", "<<", ">>", ">>>", "&", "|", "^"].includes(parent.operator)
    ) {
      const other = parent.left === refPath.node ? parent.right : parent.left;
      if (t.isNumericLiteral(other)) info.arithmeticOperand = true;
      // String concat: "x" + e
      if (t.isStringLiteral(other) && parent.operator === "+") info.stringConcatenated = true;
    }

    // return e
    if (t.isReturnStatement(parent) && parent.argument === refPath.node) {
      info.returnedFromFunc = true;
    }

    // throw e
    if (t.isThrowStatement(parent) && parent.argument === refPath.node) {
      info.thrownAsError = true;
    }

    // new e()
    if (t.isNewExpression(parent) && parent.callee === refPath.node) {
      info.usedInNew = true;
    }

    // Property write: e.x = ...
    if (
      t.isAssignmentExpression(parent) &&
      t.isMemberExpression(parent.left) &&
      parent.left.object === refPath.node &&
      !parent.left.computed &&
      parent.left.property?.name
    ) {
      info.propertyWrites.add(parent.left.property.name);
    }

    // obj[e] = ... -> e is key
    if (
      t.isMemberExpression(parent) &&
      parent.property === refPath.node &&
      parent.computed
    ) {
      info.usedAsKey = true;
    }
  }

  // Assignment source (ilk referans degil, binding'in init'i)
  if (binding.path?.node?.init) {
    info.assignedFrom = binding.path.node.init;
  }

  // Binding definition context: for(let e of ...) veya for(let e in ...)
  // Bu bilgi reference path'lerde olmaz, binding path'in parent chain'inde
  if (binding.path) {
    try {
      const bindParent = binding.path.parentPath;
      const bindGrandParent = bindParent?.parentPath;
      if (bindGrandParent && t.isForOfStatement(bindGrandParent.node)) {
        info.usedAsForOfIterator = true;
      }
      if (bindGrandParent && t.isForInStatement(bindGrandParent.node)) {
        info.usedAsKey = true;
      }
    } catch (_) {}
  }

  return info;
}

// =====================================================================
// KURAL MOTORLARI (Rule Engines)
// Her kural bir { name, confidence } dondurur veya null
// =====================================================================

/** Kural 1: API Call Context - hangi method'lar cagriliyor? */
function ruleApiCallContext(info) {
  const mc = info.methodCalls;

  // String methods
  const stringMethods = ["split", "trim", "replace", "replaceAll", "match", "search",
    "slice", "substring", "substr", "indexOf", "lastIndexOf", "includes", "startsWith",
    "endsWith", "toLowerCase", "toUpperCase", "padStart", "padEnd", "repeat",
    "normalize", "localeCompare", "charCodeAt", "charAt", "codePointAt", "at"];
  const stringScore = stringMethods.filter(m => mc.has(m)).length;
  if (stringScore >= 2) return { name: "str", confidence: 0.85 };
  if (stringScore === 1) {
    // split ozel: cok yaygin, tek basina yeterli
    if (mc.has("split")) return { name: "input", confidence: 0.75 };
    if (mc.has("trim")) return { name: "text", confidence: 0.70 };
    if (mc.has("replace") || mc.has("replaceAll")) return { name: "pattern", confidence: 0.65 };
    return { name: "str", confidence: 0.60 };
  }

  // Array methods
  const arrayMethods = ["push", "pop", "shift", "unshift", "splice", "slice",
    "map", "filter", "reduce", "forEach", "find", "findIndex", "some", "every",
    "includes", "indexOf", "lastIndexOf", "flat", "flatMap", "sort", "reverse",
    "concat", "join", "fill", "copyWithin", "entries", "keys", "values", "at"];
  const arrayScore = arrayMethods.filter(m => mc.has(m)).length;
  if (arrayScore >= 2) return { name: "items", confidence: 0.85 };
  if (mc.has("push") || mc.has("pop") || mc.has("shift") || mc.has("unshift")) {
    return { name: "items", confidence: 0.80 };
  }
  if (mc.has("map")) return { name: "items", confidence: 0.75 };
  if (mc.has("filter")) return { name: "items", confidence: 0.75 };
  if (mc.has("forEach")) return { name: "items", confidence: 0.70 };
  if (mc.has("reduce")) return { name: "items", confidence: 0.70 };
  if (mc.has("join")) return { name: "parts", confidence: 0.70 };
  if (mc.has("sort")) return { name: "items", confidence: 0.65 };

  // Map/Set methods
  if (mc.has("get") && mc.has("set") && mc.has("has")) return { name: "cache", confidence: 0.80 };
  if (mc.has("get") && mc.has("set")) return { name: "store", confidence: 0.70 };
  if (mc.has("get") && mc.has("has")) return { name: "registry", confidence: 0.70 };
  if (mc.has("add") && mc.has("has") && mc.has("delete")) return { name: "itemSet", confidence: 0.75 };
  if (mc.has("add") && mc.has("has")) return { name: "seen", confidence: 0.70 };

  // Promise methods
  if (mc.has("then") && mc.has("catch")) return { name: "promise", confidence: 0.85 };
  if (mc.has("then")) return { name: "promise", confidence: 0.70 };

  // EventEmitter methods
  if (mc.has("on") && mc.has("emit")) return { name: "emitter", confidence: 0.80 };
  if (mc.has("on") && mc.has("off")) return { name: "emitter", confidence: 0.80 };
  if (mc.has("addEventListener")) return { name: "target", confidence: 0.75 };
  if (mc.has("removeEventListener")) return { name: "target", confidence: 0.75 };

  // Stream methods
  if (mc.has("pipe") && (mc.has("on") || mc.has("read") || mc.has("write"))) {
    return { name: "stream", confidence: 0.80 };
  }
  if (mc.has("pipe")) return { name: "readable", confidence: 0.70 };
  if (mc.has("write") && mc.has("end")) return { name: "writable", confidence: 0.75 };

  // Buffer methods
  if (mc.has("readUInt8") || mc.has("readUInt16LE") || mc.has("writeUInt8") ||
      mc.has("readInt32LE") || mc.has("readInt32BE") || mc.has("copy") && mc.has("fill")) {
    return { name: "buffer", confidence: 0.80 };
  }

  // RegExp
  if (mc.has("test") && mc.has("exec")) return { name: "regex", confidence: 0.80 };
  if (mc.has("test") && !mc.has("split")) return { name: "pattern", confidence: 0.65 };

  // Date
  if (mc.has("getTime") || mc.has("toISOString") || mc.has("getFullYear")) {
    return { name: "date", confidence: 0.80 };
  }

  // JSON-like
  if (mc.has("stringify") || mc.has("parse")) return { name: "serializer", confidence: 0.60 };

  // Error
  if (mc.has("captureStackTrace")) return { name: "error", confidence: 0.85 };

  return null;
}

/** Kural 2: Method chain / iterable kullanim */
function ruleMethodChain(info) {
  if (info.usedInForOf) return { name: "items", confidence: 0.75 };
  if (info.usedWithSpread && !info.calledAs) return { name: "items", confidence: 0.65 };
  return null;
}

/** Kural 3: Property access patterns */
function rulePropertyAccess(info) {
  const pr = info.propertyReads;
  const pw = info.propertyWrites;
  const allProps = new Set([...pr, ...pw]);

  // Error object
  if (pr.has("message") && (pr.has("stack") || pr.has("code") || pr.has("name"))) {
    return { name: "error", confidence: 0.90 };
  }
  if (pr.has("message") && pr.has("stack")) return { name: "error", confidence: 0.90 };

  // HTTP Request
  const reqProps = ["body", "params", "query", "headers", "method", "url", "path",
    "hostname", "protocol", "ip", "cookies", "session"];
  const reqScore = reqProps.filter(p => allProps.has(p)).length;
  if (reqScore >= 3) return { name: "request", confidence: 0.90 };
  if (reqScore >= 2) return { name: "request", confidence: 0.75 };

  // HTTP Response
  const resProps = ["statusCode", "statusMessage", "headersSent"];
  const resMethods = info.methodCalls;
  const resMethodNames = ["send", "json", "status", "end", "write", "setHeader",
    "writeHead", "render", "redirect"];
  const resScore = resProps.filter(p => allProps.has(p)).length +
    resMethodNames.filter(m => resMethods.has(m)).length;
  if (resScore >= 2) return { name: "response", confidence: 0.85 };

  // DOM Element
  const domProps = ["innerHTML", "outerHTML", "textContent", "className", "classList",
    "style", "children", "parentNode", "parentElement", "nextSibling", "previousSibling",
    "firstChild", "lastChild", "childNodes", "tagName", "nodeName", "nodeType",
    "attributes", "dataset", "id"];
  const domScore = domProps.filter(p => allProps.has(p)).length;
  if (domScore >= 2) return { name: "element", confidence: 0.85 };
  if (domScore === 1) return { name: "node", confidence: 0.60 };

  // DOM Document
  const docMethods = ["createElement", "createTextNode", "getElementById",
    "getElementsByClassName", "querySelector", "querySelectorAll",
    "createDocumentFragment", "createComment"];
  const docScore = docMethods.filter(m => resMethods.has(m)).length;
  if (docScore >= 1) return { name: "document", confidence: 0.85 };

  // fs module
  const fsMethods = ["readFileSync", "writeFileSync", "readFile", "writeFile",
    "existsSync", "mkdirSync", "readdirSync", "statSync", "unlinkSync",
    "renameSync", "createReadStream", "createWriteStream"];
  const fsScore = fsMethods.filter(m => resMethods.has(m)).length;
  if (fsScore >= 1) return { name: "fs", confidence: 0.90 };

  // path module
  const pathMethods = ["resolve", "join", "dirname", "basename", "extname",
    "relative", "normalize", "isAbsolute", "parse", "format", "sep"];
  // "parse" ve "join" cok generic, en az 2 gerekli
  const pathScore = pathMethods.filter(m => resMethods.has(m) || allProps.has(m)).length;
  if (pathScore >= 2) return { name: "path", confidence: 0.85 };
  if (resMethods.has("resolve") && resMethods.has("join")) return { name: "path", confidence: 0.80 };

  // os module
  if (resMethods.has("platform") && resMethods.has("arch")) return { name: "os", confidence: 0.85 };
  if (resMethods.has("homedir") || resMethods.has("tmpdir")) return { name: "os", confidence: 0.75 };

  // process-like
  if (allProps.has("env") && (allProps.has("argv") || allProps.has("cwd") || allProps.has("pid"))) {
    return { name: "proc", confidence: 0.80 };
  }
  if (allProps.has("env") && allProps.has("platform")) return { name: "proc", confidence: 0.75 };
  if (allProps.has("stdout") && allProps.has("stderr")) return { name: "proc", confidence: 0.80 };

  // child_process
  if (allProps.has("stdout") && allProps.has("stdin") && allProps.has("pid")) {
    return { name: "childProc", confidence: 0.80 };
  }

  // Config/Options object
  if (allProps.size >= 3 && !info.calledAs && !info.usedInNew) {
    // Cogu property read, method call az -> muhtemelen config/options
    if (info.methodCalls.size <= 1 && allProps.size >= 4) {
      return { name: "options", confidence: 0.50 };
    }
  }

  // .length property (could be array or string)
  if (pr.has("length") && allProps.size <= 2) {
    // Ek ipucu yoksa dusuk confidence
    return { name: "collection", confidence: 0.40 };
  }

  // .prototype -> constructor/class
  if (pr.has("prototype")) return { name: "ctor", confidence: 0.70 };

  // Index access (e[i]) with no other clues -> source/data
  if (info.indexAccessed && allProps.size === 0 && info.methodCalls.size === 0) {
    return { name: "source", confidence: 0.50 };
  }

  return null;
}

/** Kural 4: Comparison context */
function ruleComparison(info) {
  if (info.comparedWith.length === 0) return null;

  // Cok sayida string ile karsilastiriliyorsa -> muhtemelen type/kind/status
  if (info.comparedWith.length >= 3) return { name: "kind", confidence: 0.70 };

  // Spesifik string'ler
  const vals = info.comparedWith;
  const httpMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
  if (vals.some(v => httpMethods.includes(v))) return { name: "method", confidence: 0.80 };

  const events = ["click", "change", "submit", "load", "error", "close", "open",
    "message", "data", "end", "finish", "drain", "connect", "disconnect"];
  if (vals.some(v => events.includes(v))) return { name: "eventName", confidence: 0.75 };

  const boolLike = ["true", "false", "yes", "no", "on", "off", "enabled", "disabled"];
  if (vals.some(v => boolLike.includes(v.toLowerCase()))) return { name: "flag", confidence: 0.65 };

  // VS Code / Cursor ozel string pattern'leri
  // LSP method isimleri
  const lspMethods = ["textDocument/completion", "textDocument/hover", "textDocument/definition",
    "textDocument/references", "textDocument/rename", "textDocument/signatureHelp",
    "textDocument/codeAction", "textDocument/codeLens", "textDocument/formatting",
    "textDocument/rangeFormatting", "textDocument/onTypeFormatting",
    "textDocument/documentSymbol", "textDocument/documentHighlight",
    "textDocument/documentLink", "textDocument/foldingRange", "textDocument/selectionRange",
    "textDocument/semanticTokens", "textDocument/inlayHint", "textDocument/diagnostic",
    "textDocument/didOpen", "textDocument/didClose", "textDocument/didChange",
    "textDocument/didSave", "textDocument/publishDiagnostics",
    "workspace/didChangeConfiguration", "workspace/didChangeWatchedFiles",
    "window/showMessage", "window/logMessage", "initialize", "shutdown", "exit"];
  if (vals.some(v => lspMethods.includes(v) || v.startsWith("textDocument/") || v.startsWith("workspace/"))) {
    return { name: "lspMethod", confidence: 0.85 };
  }

  // VS Code editor ayarlari
  const vsCodeSettings = ["editor.fontSize", "editor.fontFamily", "editor.tabSize",
    "editor.insertSpaces", "editor.wordWrap", "editor.minimap.enabled",
    "editor.formatOnSave", "editor.formatOnPaste", "editor.suggestSelection",
    "editor.quickSuggestions", "workbench.colorTheme", "files.autoSave",
    "terminal.integrated.fontSize", "terminal.integrated.fontFamily"];
  if (vals.some(v => vsCodeSettings.includes(v) || v.startsWith("editor.") || v.startsWith("workbench."))) {
    return { name: "settingKey", confidence: 0.80 };
  }

  // VS Code view container isimleri
  const vsCodeViews = ["explorer", "scm", "debug", "extensions", "search", "output",
    "terminal", "problems", "panel", "statusBar", "activityBar"];
  if (vals.some(v => vsCodeViews.includes(v))) return { name: "viewId", confidence: 0.75 };

  return { name: "value", confidence: 0.45 };
}

/** Kural 5: typeof check */
function ruleTypeofCheck(info) {
  if (info.typeofChecks.length === 0) return null;

  const types = new Set(info.typeofChecks);
  if (types.has("function")) return { name: "fn", confidence: 0.75 };
  if (types.has("string")) return { name: "str", confidence: 0.70 };
  if (types.has("number")) return { name: "num", confidence: 0.70 };
  if (types.has("object")) return { name: "obj", confidence: 0.55 };
  if (types.has("boolean")) return { name: "flag", confidence: 0.65 };
  if (types.has("undefined")) return { name: "value", confidence: 0.45 };

  return null;
}

/** Kural 6: Error handling */
function ruleErrorHandling(info) {
  if (info.thrownAsError) return { name: "error", confidence: 0.85 };
  // catch clause'da yakalanan hata icin (catch handler binding'in kendisi)
  return null;
}

/** Kural 7: Callback pattern - e(args) seklinde cagriliyor + typeof "function" */
function ruleCallbackPattern(info) {
  if (info.calledAs && info.typeofChecks.includes("function")) {
    return { name: "callback", confidence: 0.80 };
  }
  if (info.calledAs && !info.usedInNew && info.methodCalls.size === 0 && info.propertyReads.size === 0) {
    // Sadece cagriliyor, property'lerine erisim yok -> muhtemelen callback
    return { name: "fn", confidence: 0.55 };
  }
  return null;
}

/** Kural 8: DOM/Node.js well-known patterns */
function ruleWellKnownAPIs(info) {
  const mc = info.methodCalls;

  // crypto
  if (mc.has("createHash") || mc.has("createHmac") || mc.has("randomBytes")) {
    return { name: "crypto", confidence: 0.90 };
  }

  // url
  if (mc.has("parse") && (info.propertyReads.has("hostname") || info.propertyReads.has("pathname"))) {
    return { name: "urlParser", confidence: 0.80 };
  }

  // http(s) module
  if (mc.has("createServer") && (mc.has("listen") || info.propertyReads.has("listen"))) {
    return { name: "server", confidence: 0.85 };
  }
  if (mc.has("request") && mc.has("get")) return { name: "httpClient", confidence: 0.75 };

  // child_process
  if (mc.has("exec") || mc.has("spawn") || mc.has("execSync") || mc.has("fork")) {
    return { name: "childProcess", confidence: 0.85 };
  }

  // console
  if (mc.has("log") && mc.has("error") && mc.has("warn")) {
    return { name: "logger", confidence: 0.70 };
  }

  // JSON
  if (mc.has("stringify") && mc.has("parse")) return { name: "JSON", confidence: 0.50 };

  // util
  if (mc.has("promisify") || mc.has("inspect") || mc.has("format")) {
    return { name: "util", confidence: 0.75 };
  }

  return null;
}

/** Kural 9: Iterator pattern */
function ruleIterator(info) {
  if (info.usedAsForOfIterator) return { name: "item", confidence: 0.80 };
  if (info.usedAsKey) return { name: "key", confidence: 0.80 };
  return null;
}

/** Kural 10: Destructuring hint */
function ruleDestructuring(info) {
  if (info.destructured) return { name: "options", confidence: 0.60 };
  return null;
}

/** Kural 11 (Bonus): Arithmetic/numeric context */
function ruleArithmetic(info) {
  if (info.arithmeticOperand && !info.stringConcatenated) {
    return { name: "num", confidence: 0.55 };
  }
  if (info.stringConcatenated && !info.arithmeticOperand) {
    return { name: "str", confidence: 0.50 };
  }
  return null;
}

/** Kural 12 (Bonus): Constructor pattern */
function ruleConstructor(info) {
  if (info.usedInNew) return { name: "Ctor", confidence: 0.70 };
  return null;
}

/** Kural 13: VS Code / Cursor String Literal Context
 *
 * Degiskenin cevreleyen baglaminda VS Code API string'leri varsa
 * bunlardan anlamli isim cikarir. Cursor bir VS Code fork'u oldugu icin
 * VS Code API string'leri cok zengindir ve minifier bunlari korur.
 *
 * Pattern'ler:
 *   - "vscode.workspace.getConfiguration" -> configManager/configProvider
 *   - "editor.fontSize" -> fontSizeConfig
 *   - "textDocument/completion" -> completionHandler/completionProvider
 *   - IPC channel isimleri: "vscode:..." -> channelHandler
 *   - Extension API: "onDid..." event handler isimleri
 */
function ruleVSCodeStringContext(info) {
  // passedToFunctions ve comparedWith'den VS Code API ipuclari cikar
  const allStrings = [...info.comparedWith, ...info.passedToFunctions];
  const propsAndMethods = [...info.propertyReads, ...info.methodCalls];

  // LSP handler pattern: textDocument/* method'lari
  for (const s of allStrings) {
    if (typeof s !== "string") continue;

    // textDocument/completion gibi LSP method'lari
    if (s.startsWith("textDocument/")) {
      const method = s.split("/")[1];
      if (method) {
        const name = method + "Handler";
        return { name, confidence: 0.80 };
      }
    }

    // workspace/* method'lari
    if (s.startsWith("workspace/")) {
      const method = s.split("/")[1];
      if (method) {
        const name = "workspace" + method.charAt(0).toUpperCase() + method.slice(1) + "Handler";
        return { name, confidence: 0.78 };
      }
    }
  }

  // VS Code configuration API pattern'leri
  // getConfiguration cagriliyorsa -> configManager
  if (propsAndMethods.includes("getConfiguration") || info.passedToFunctions.includes("getConfiguration")) {
    return { name: "configManager", confidence: 0.82 };
  }

  // createOutputChannel -> outputChannel
  if (propsAndMethods.includes("createOutputChannel")) {
    return { name: "outputChannel", confidence: 0.85 };
  }

  // registerCommand -> commandHandler
  if (propsAndMethods.includes("registerCommand") || info.passedToFunctions.includes("registerCommand")) {
    return { name: "commandHandler", confidence: 0.82 };
  }

  // createTreeView -> treeView
  if (propsAndMethods.includes("createTreeView")) {
    return { name: "treeView", confidence: 0.85 };
  }

  // createWebviewPanel -> webviewPanel
  if (propsAndMethods.includes("createWebviewPanel")) {
    return { name: "webviewPanel", confidence: 0.85 };
  }

  // registerTreeDataProvider -> treeDataProvider
  if (propsAndMethods.includes("registerTreeDataProvider") || info.passedToFunctions.includes("registerTreeDataProvider")) {
    return { name: "treeDataProvider", confidence: 0.82 };
  }

  // VS Code event handler pattern'leri
  // onDidChangeConfiguration, onDidChangeTextDocument, vb.
  for (const m of propsAndMethods) {
    if (typeof m !== "string") continue;
    if (m.startsWith("onDid")) {
      // onDidChangeConfiguration -> configChangeHandler
      // onDidChangeTextDocument -> textDocumentChangeHandler
      const event = m.slice(5); // "ChangeConfiguration"
      if (event.length > 2 && event.length < 40) {
        const handlerName = event.charAt(0).toLowerCase() + event.slice(1) + "Handler";
        return { name: handlerName, confidence: 0.78 };
      }
    }
    if (m.startsWith("onWill")) {
      const event = m.slice(6);
      if (event.length > 2 && event.length < 40) {
        const handlerName = event.charAt(0).toLowerCase() + event.slice(1) + "Handler";
        return { name: handlerName, confidence: 0.75 };
      }
    }
  }

  // IPC channel pattern: "vscode:openWindow" gibi
  for (const s of allStrings) {
    if (typeof s !== "string") continue;
    if (s.startsWith("vscode:")) {
      const action = s.slice(7); // "openWindow"
      if (action.length > 2 && action.length < 40) {
        return { name: action + "Handler", confidence: 0.75 };
      }
    }
  }

  // Diagnostic/problem ilgili pattern
  if (propsAndMethods.includes("createDiagnosticCollection") || info.passedToFunctions.includes("createDiagnosticCollection")) {
    return { name: "diagnosticCollection", confidence: 0.85 };
  }

  // StatusBar
  if (propsAndMethods.includes("createStatusBarItem")) {
    return { name: "statusBarItem", confidence: 0.85 };
  }

  // TextEditor
  if (propsAndMethods.includes("showTextDocument")) {
    return { name: "textEditor", confidence: 0.80 };
  }

  // QuickPick
  if (propsAndMethods.includes("showQuickPick") || propsAndMethods.includes("createQuickPick")) {
    return { name: "quickPick", confidence: 0.82 };
  }

  // InputBox
  if (propsAndMethods.includes("showInputBox") || propsAndMethods.includes("createInputBox")) {
    return { name: "inputBox", confidence: 0.82 };
  }

  return null;
}

// =====================================================================
// FONKSIYON PARAMETRE BAĞLAMI
// Fonksiyon parametreleri icin ek baglamsal kurallar
// =====================================================================

/** Parametre pozisyonundan isim cikart */
function inferParamFromPosition(funcPath, paramIndex, paramCount, bodyStr) {
  // Express/Koa middleware pattern: (req, res, next) veya (err, req, res, next)
  const reqIndicators = [".body", ".params", ".query", ".headers", ".method", ".url",
    ".cookies", ".session", ".ip", ".hostname"];
  const resIndicators = [".send(", ".json(", ".status(", ".render(", ".redirect(",
    ".setHeader(", ".writeHead(", ".end("];
  let reqScore = reqIndicators.filter(i => bodyStr.includes(i)).length;
  let resScore = resIndicators.filter(i => bodyStr.includes(i)).length;

  if (reqScore >= 1 && resScore >= 1) {
    if (paramCount === 4) {
      return ["error", "request", "response", "next"][paramIndex] || null;
    }
    if (paramCount >= 2 && paramCount <= 3) {
      return ["request", "response", "next"][paramIndex] || null;
    }
  }

  // Node.js callback pattern: (err, result) veya (err, data)
  if (paramCount === 2 && paramIndex === 0) {
    // Ilk param error mi? Body'de error handling var mi?
    if (bodyStr.includes(".message") || bodyStr.includes(".stack") ||
        bodyStr.includes("throw ") || bodyStr.includes("Error(")) {
      return "error";
    }
  }

  // esbuild CJS factory: (exports, module, require)
  if (paramCount >= 2 && paramCount <= 3) {
    if (bodyStr.includes(".exports") && bodyStr.includes("module.exports")) {
      if (paramIndex === 0) return "exports";
      if (paramIndex === 1) return "module";
      if (paramIndex === 2) return "require";
    }
    // Daha gevsek: sadece .exports varsa
    if (paramIndex === 0 && bodyStr.includes(".exports")) return "exports";
  }

  // Event handler: e.on('event', (data) => {})
  if (paramCount === 1) {
    const parent = funcPath.parent;
    if (t.isCallExpression(parent)) {
      const callee = parent.callee;
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
        const methodName = callee.property.name;
        if (methodName === "on" || methodName === "once" || methodName === "addEventListener") {
          // Event ismi ilk argumandan al
          if (parent.arguments.length >= 2 && t.isStringLiteral(parent.arguments[0])) {
            const eventName = parent.arguments[0].value;
            if (eventName === "error") return "error";
            if (eventName === "data") return "chunk";
            if (eventName === "message") return "message";
            if (eventName === "connection" || eventName === "connect") return "socket";
            if (eventName === "request") return "request";
            if (eventName === "close" || eventName === "end") return "reason";
            return "eventData";
          }
        }
        // Array callback: .map(item => ...), .filter(item => ...), .forEach(item => ...)
        const iterMethods = ["map", "filter", "forEach", "find", "findIndex", "some", "every",
          "flatMap", "reduce"];
        if (iterMethods.includes(methodName)) {
          if (paramIndex === 0) return methodName === "reduce" ? "accumulator" : "item";
          if (paramIndex === 1) return methodName === "reduce" ? "item" : "index";
          if (paramIndex === 2) return "array";
        }
        // .sort((a, b) => ...)
        if (methodName === "sort" && paramCount === 2) {
          return paramIndex === 0 ? "left" : "right";
        }
        // .replace(regex, (match, ...) => ...)
        if (methodName === "replace" && paramIndex === 0) return "match";
      }
    }
  }

  // Tek parametreli fonksiyonlar icin: parametre isim cikarimlari
  if (paramCount >= 2) {
    const parent = funcPath.parent;
    if (t.isCallExpression(parent) && t.isMemberExpression(parent.callee)) {
      const methodName = parent.callee.property?.name;
      const iterMethods = ["map", "filter", "forEach", "find", "findIndex", "some", "every", "flatMap"];
      if (iterMethods.includes(methodName)) {
        if (paramIndex === 0) return "item";
        if (paramIndex === 1) return "index";
        if (paramIndex === 2) return "array";
      }
      if (methodName === "reduce") {
        if (paramIndex === 0) return "acc";
        if (paramIndex === 1) return "item";
        if (paramIndex === 2) return "index";
      }
      if (methodName === "sort") {
        if (paramIndex === 0) return "a";  // sort icin a, b convention
        if (paramIndex === 1) return "b";
      }
    }
  }

  return null;
}

// =====================================================================
// VARIABLE DECLARATION BAĞLAMI
// var/let/const icin atama kaynagindan isim cikart
// =====================================================================

function inferFromAssignment(binding) {
  const initNode = binding.path?.node?.init;
  if (!initNode) return null;

  // const e = require("fs") -> fs
  if (
    t.isCallExpression(initNode) &&
    t.isIdentifier(initNode.callee) &&
    initNode.callee.name === "require" &&
    initNode.arguments.length === 1 &&
    t.isStringLiteral(initNode.arguments[0])
  ) {
    const modName = initNode.arguments[0].value.replace(/^node:/, "");
    const MOD_NAMES = {
      fs: "fs", path: "path", os: "os", http: "http", https: "https",
      url: "urlModule", crypto: "crypto", events: "events", stream: "stream",
      util: "util", child_process: "childProcess", net: "net", dns: "dns",
      tls: "tls", zlib: "zlib", readline: "readline", buffer: "bufferModule",
      querystring: "querystring", assert: "assert", vm: "vm", v8: "v8",
      cluster: "cluster", inspector: "inspector",
      "worker_threads": "workerThreads", "perf_hooks": "perfHooks",
      express: "express", react: "React", "react-dom": "ReactDOM",
      axios: "axios", lodash: "lodash", chalk: "chalk",
      commander: "commander", yargs: "yargs",
    };
    if (MOD_NAMES[modName]) return { name: MOD_NAMES[modName], confidence: 0.95 };
    // Bilinmeyen: son segment
    const parts = modName.split("/");
    const last = parts[parts.length - 1].replace(/[^a-zA-Z0-9_$]/g, "");
    if (last && last.length > 1) return { name: last, confidence: 0.80 };
  }

  // const e = new Error(...) -> error
  if (t.isNewExpression(initNode) && t.isIdentifier(initNode.callee)) {
    const ctorName = initNode.callee.name;
    if (ctorName.includes("Error")) return { name: "error", confidence: 0.90 };
    if (ctorName === "Map") return { name: "map", confidence: 0.85 };
    if (ctorName === "Set") return { name: "set", confidence: 0.85 };
    if (ctorName === "WeakMap") return { name: "weakMap", confidence: 0.85 };
    if (ctorName === "WeakSet") return { name: "weakSet", confidence: 0.85 };
    if (ctorName === "Promise") return { name: "promise", confidence: 0.80 };
    if (ctorName === "RegExp") return { name: "regex", confidence: 0.80 };
    if (ctorName === "Date") return { name: "date", confidence: 0.80 };
    if (ctorName === "URL") return { name: "url", confidence: 0.85 };
    if (ctorName === "Buffer") return { name: "buf", confidence: 0.80 };
    // Generic constructor: lowercase first letter
    const shortName = ctorName.charAt(0).toLowerCase() + ctorName.slice(1);
    if (shortName.length > 2 && shortName.length < 30) return { name: shortName, confidence: 0.70 };
  }

  // const e = [] -> items/list
  if (t.isArrayExpression(initNode)) return { name: "items", confidence: 0.60 };

  // const e = {} -> obj/options
  if (t.isObjectExpression(initNode)) {
    // Property sayisina bak
    if (initNode.properties.length >= 3) return { name: "config", confidence: 0.55 };
    return { name: "obj", confidence: 0.45 };
  }

  // const e = "" veya "some string" -> str
  if (t.isStringLiteral(initNode)) return { name: "str", confidence: 0.50 };

  // const e = 0 veya 42 -> num/count
  if (t.isNumericLiteral(initNode)) return { name: "num", confidence: 0.45 };

  // const e = true/false -> flag
  if (t.isBooleanLiteral(initNode)) return { name: "flag", confidence: 0.50 };

  // const e = null -> sonuc daha sonra atanacak, dusuk confidence
  if (t.isNullLiteral(initNode)) return { name: "result", confidence: 0.30 };

  // const e = /regex/ -> pattern
  if (t.isRegExpLiteral(initNode)) return { name: "pattern", confidence: 0.75 };

  // const e = someFunc() -> result
  if (t.isCallExpression(initNode) && !t.isIdentifier(initNode.callee, { name: "require" })) {
    // Fonksiyon adi ipucu verebilir
    const calleeName = initNode.callee?.name ||
      (t.isMemberExpression(initNode.callee) ? initNode.callee.property?.name : null);
    if (calleeName) {
      // get* -> result
      if (calleeName.startsWith("get") || calleeName.startsWith("fetch")) {
        return { name: "result", confidence: 0.50 };
      }
      if (calleeName.startsWith("create") || calleeName.startsWith("make") || calleeName.startsWith("build")) {
        const suffix = calleeName.replace(/^(create|make|build)/, "");
        if (suffix.length > 1) {
          const cleanName = suffix.charAt(0).toLowerCase() + suffix.slice(1);
          return { name: cleanName, confidence: 0.65 };
        }
      }
      if (calleeName === "toString") return { name: "str", confidence: 0.70 };
      if (calleeName === "parseInt" || calleeName === "parseFloat") return { name: "num", confidence: 0.75 };
      if (calleeName === "JSON.parse") return { name: "parsed", confidence: 0.65 };
    }
  }

  // const e = await ... -> result
  if (t.isAwaitExpression(initNode)) return { name: "result", confidence: 0.40 };

  return null;
}

// =====================================================================
// ANA MOTOR
// =====================================================================

// ---------- Read ----------
let source;
let fileSize;
try {
  fileSize = statSync(inputPath).size;
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  emit({ success: false, errors: [`Dosya okunamadi: ${err.message}`] });
  process.exit(1);
}

// ---------- Parse ----------
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
} catch (err) {
  emit({ success: false, errors: [`Parse hatasi: ${err.message}`] });
  process.exit(0);
}

// ---------- Analiz + Rename ----------
const startTime = Date.now();
const allMappings = [];  // {scope: string, old: string, new: string, rule: string, confidence: number}
let totalRenamed = 0;
let totalSkipped = 0;
let totalLowConfidence = 0;

const ruleHits = Object.create(null);  // rule -> count (no prototype chain)

function recordRule(ruleName) {
  ruleHits[ruleName] = (ruleHits[ruleName] || 0) + 1;
}

// Catch clause parametrelerini ayri isle (binding olmayabiliyor)
const catchParamsProcessed = new Set();

try {
  traverse(ast, {
    // Catch clause: catch(e) -> catch(error)
    CatchClause(path) {
      const param = path.node.param;
      if (!param || !t.isIdentifier(param)) return;
      if (!isMinified(param.name)) return;

      const newName = makeUnique(path.scope, "error");
      if (newName && newName !== param.name) {
        const confidence = 0.95;
        if (confidence >= minConfidence) {
          allMappings.push({
            scope: scopeLabel(path),
            old: param.name,
            new: newName,
            rule: "catch_clause",
            confidence,
          });
          recordRule("catch_clause");
          if (!dryRun) {
            try {
              path.scope.rename(param.name, newName);
              totalRenamed++;
            } catch (_) { totalSkipped++; }
          }
          catchParamsProcessed.add(param.name + "@" + (param.start || 0));
        }
      }
    },

    // Fonksiyon parametreleri
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression"(path) {
      const params = path.node.params;
      if (params.length === 0) return;

      const bodyStr = getBodyString(path.node);

      for (let i = 0; i < params.length; i++) {
        const param = params[i];
        if (!t.isIdentifier(param)) continue;
        if (!isMinified(param.name)) continue;

        // Binding al
        const binding = path.scope.getBinding(param.name);
        if (!binding) continue;

        // Oncelik sirali kural calistir
        let bestResult = null;
        let bestRule = null;

        // 1. Parametre pozisyon bazli cikarim (en yuksek oncelik)
        const posResult = inferParamFromPosition(path, i, params.length, bodyStr);
        if (posResult) {
          bestResult = { name: posResult, confidence: 0.80 };
          bestRule = "param_position";
        }

        // 2. Kullanim bazli kurallar (eger pozisyon daha dusuk confidence verdiyse override edebilir)
        const info = collectUsageInfo(binding);

        const rules = [
          ["api_call_context", ruleApiCallContext],
          ["method_chain", ruleMethodChain],
          ["property_access", rulePropertyAccess],
          ["comparison", ruleComparison],
          ["typeof_check", ruleTypeofCheck],
          ["error_handling", ruleErrorHandling],
          ["callback_pattern", ruleCallbackPattern],
          ["well_known_apis", ruleWellKnownAPIs],
          ["vscode_string_context", ruleVSCodeStringContext],
          ["iterator", ruleIterator],
          ["destructuring", ruleDestructuring],
          ["arithmetic", ruleArithmetic],
          ["constructor_pattern", ruleConstructor],
        ];

        for (const [ruleName, ruleFn] of rules) {
          const result = ruleFn(info);
          if (result && (!bestResult || result.confidence > bestResult.confidence)) {
            bestResult = result;
            bestRule = ruleName;
          }
        }

        // Confidence threshold check
        if (!bestResult || bestResult.confidence < minConfidence) {
          totalLowConfidence++;
          continue;
        }

        // Cakisma kontrolu ve rename
        const newName = makeUnique(path.scope, bestResult.name);
        if (!newName || newName === param.name) {
          totalSkipped++;
          continue;
        }

        allMappings.push({
          scope: scopeLabel(path),
          old: param.name,
          new: newName,
          rule: bestRule,
          confidence: bestResult.confidence,
        });
        recordRule(bestRule);

        if (!dryRun) {
          try {
            path.scope.rename(param.name, newName);
            totalRenamed++;
          } catch (_) { totalSkipped++; }
        }
      }
    },

    // Variable declarations: var/let/const ile tanimlanan minified isimler
    VariableDeclarator(path) {
      const id = path.node.id;
      if (!t.isIdentifier(id)) return;
      if (!isMinified(id.name)) return;

      const binding = path.scope.getBinding(id.name);
      if (!binding) return;

      // 1. Atama kaynagindan cikarim
      let bestResult = inferFromAssignment(binding);
      let bestRule = bestResult ? "assignment_source" : null;

      // 2. Kullanim bazli kurallar
      const info = collectUsageInfo(binding);

      const rules = [
        ["api_call_context", ruleApiCallContext],
        ["method_chain", ruleMethodChain],
        ["property_access", rulePropertyAccess],
        ["comparison", ruleComparison],
        ["typeof_check", ruleTypeofCheck],
        ["error_handling", ruleErrorHandling],
        ["callback_pattern", ruleCallbackPattern],
        ["well_known_apis", ruleWellKnownAPIs],
        ["iterator", ruleIterator],
        ["destructuring", ruleDestructuring],
        ["arithmetic", ruleArithmetic],
        ["constructor_pattern", ruleConstructor],
      ];

      for (const [ruleName, ruleFn] of rules) {
        const result = ruleFn(info);
        if (result && (!bestResult || result.confidence > bestResult.confidence)) {
          bestResult = result;
          bestRule = ruleName;
        }
      }

      // Confidence threshold
      if (!bestResult || bestResult.confidence < minConfidence) {
        totalLowConfidence++;
        return;
      }

      const newName = makeUnique(path.scope, bestResult.name);
      if (!newName || newName === id.name) {
        totalSkipped++;
        return;
      }

      allMappings.push({
        scope: scopeLabel(path),
        old: id.name,
        new: newName,
        rule: bestRule,
        confidence: bestResult.confidence,
      });
      recordRule(bestRule);

      if (!dryRun) {
        try {
          path.scope.rename(id.name, newName);
          totalRenamed++;
        } catch (_) { totalSkipped++; }
      }
    },
  });
} catch (err) {
  emit({
    success: false,
    errors: [`Traversal hatasi: ${err.message}`],
    stats: { duration_ms: Date.now() - startTime },
  });
  process.exit(0);
}

// ---------- Helper: scope label ----------
function scopeLabel(path) {
  // En yakin fonksiyon adini bul
  let current = path;
  while (current) {
    if (t.isFunctionDeclaration(current.node) && current.node.id) {
      return current.node.id.name;
    }
    if (t.isVariableDeclarator(current.parent) && t.isIdentifier(current.parent.id)) {
      return current.parent.id.name;
    }
    if (t.isObjectProperty(current.parent) && t.isIdentifier(current.parent.key)) {
      return current.parent.key.name;
    }
    current = current.parentPath;
  }
  return "<module>";
}

// ---------- Generate Output ----------
const duration = Date.now() - startTime;

if (!dryRun) {
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
      renamed: totalRenamed,
      skipped: totalSkipped,
      low_confidence: totalLowConfidence,
      mappings_count: allMappings.length,
      mappings_sample: allMappings.slice(0, 50),
      rule_hits: ruleHits,
      stats: {
        input_size: fileSize,
        output_size: outputSize,
        input_lines: source.split("\n").length,
        duration_ms: duration,
        avg_confidence: allMappings.length > 0
          ? +(allMappings.reduce((s, m) => s + m.confidence, 0) / allMappings.length).toFixed(3)
          : 0,
        confidence_distribution: {
          high: allMappings.filter(m => m.confidence >= 0.8).length,
          medium: allMappings.filter(m => m.confidence >= 0.5 && m.confidence < 0.8).length,
          low: allMappings.filter(m => m.confidence < 0.5).length,
        },
      },
    });
  } catch (err) {
    emit({
      success: false,
      errors: [`Generate hatasi: ${err.message}`],
      stats: { duration_ms: duration },
    });
  }
} else {
  // Dry run: sadece analiz sonuclarini raporla
  emit({
    success: true,
    mode: "dry-run",
    would_rename: allMappings.length,
    skipped: totalSkipped,
    low_confidence: totalLowConfidence,
    mappings: allMappings,
    rule_hits: ruleHits,
    stats: {
      input_size: fileSize,
      duration_ms: duration,
      avg_confidence: allMappings.length > 0
        ? +(allMappings.reduce((s, m) => s + m.confidence, 0) / allMappings.length).toFixed(3)
        : 0,
      confidence_distribution: {
        high: allMappings.filter(m => m.confidence >= 0.8).length,
        medium: allMappings.filter(m => m.confidence >= 0.5 && m.confidence < 0.8).length,
        low: allMappings.filter(m => m.confidence < 0.5).length,
      },
    },
  });
}
