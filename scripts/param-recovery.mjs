#!/usr/bin/env node
/**
 * param-recovery.mjs -- Call-site analizi ile parametre ismi recovery (LLM'siz)
 *
 * Black Widow v1.0 -- Karadul
 *
 * 3 strateji ile obfuscated parametre isimlerini geri kazanir:
 *
 *   Strateji 1: this.X = param
 *     constructor(e, t, n) { this.factory = e } → e = factory
 *
 *   Strateji 2: Destructuring
 *     function foo(e) { const { name, age } = e } → e = options({name, age})
 *
 *   Strateji 3: param.X erisimi (property access)
 *     function foo(e) { e.push(...) } → e = array (ipucu)
 *
 *   Strateji 4: Call-site object literal
 *     new Foo({ name: x, age: y }) → constructor param = options
 *
 * IMPORTANT: noScope mod -- traverse(..., { noScope: true })
 *   6MB dosyalarda duplicate declaration sorunu var, scope API devre disi.
 *
 * Kullanim:
 *   node --max-old-space-size=8192 param-recovery.mjs <input.js> [output.json]
 *
 * Cikti: JSON stdout veya dosyaya
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;

// ---------- CLI ----------
const args = process.argv.slice(2);
if (args.length < 1) {
  process.stdout.write(
    JSON.stringify({
      success: false,
      errors: ["Kullanim: node --max-old-space-size=8192 param-recovery.mjs <input.js> [output.json]"],
    }) + "\n"
  );
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputPath = args[1] ? resolve(args[1]) : null;

// ---------- Kaynak oku ----------
let source;
try {
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  process.stdout.write(
    JSON.stringify({ success: false, errors: [`Dosya okunamadi: ${err.message}`] }) + "\n"
  );
  process.exit(1);
}

// ---------- Parse ----------
console.error(`[param-recovery] Parsing ${inputPath} (${(source.length / 1e6).toFixed(1)}MB)...`);
let ast;
try {
  ast = parse(source, {
    sourceType: "unambiguous",
    allowReturnOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowSuperOutsideMethod: true,
    plugins: ["jsx", "typescript", "decorators-legacy", "classProperties", "classPrivateProperties",
      "classPrivateMethods", "optionalChaining", "nullishCoalescingOperator", "dynamicImport"],
    errorRecovery: true,
  });
} catch (err) {
  process.stdout.write(
    JSON.stringify({ success: false, errors: [`Parse hatasi: ${err.message}`] }) + "\n"
  );
  process.exit(1);
}

console.error(`[param-recovery] AST parsed. Starting analysis...`);

// =====================================================================
// VERI YAPILARI
// =====================================================================

// Her fonksiyon/method tanimlamasini topla
// Key: "className::methodName" veya "functionName" veya "anonymous@line"
const funcDefs = new Map();

// Her parametre icin recovery sonuclari
// Key: "funcKey::paramIndex" -> { name, strategy, confidence }
const recoveredParams = new Map();

// Call-site arguman bilgileri
// Key: callee ismi -> [{ args: [...], line }]
const callSites = new Map();

// =====================================================================
// YARDIMCI FONKSIYONLAR
// =====================================================================

/** Bir parametre node'unun gercek ismini al (pattern, rest, default destegi) */
function getParamName(paramNode) {
  if (t.isIdentifier(paramNode)) return paramNode.name;
  if (t.isAssignmentPattern(paramNode)) return getParamName(paramNode.left);
  if (t.isRestElement(paramNode)) return getParamName(paramNode.argument);
  if (t.isObjectPattern(paramNode)) return "{destructured}";
  if (t.isArrayPattern(paramNode)) return "[array]";
  return null;
}

/** Tek harfli veya obfuscated parametre mi? */
function isObfuscated(name) {
  if (!name) return false;
  // tek harf, tek harf + rakam (e, t, n, r, s, i, a, o, c, l, e2, t3...)
  return /^[a-z][0-9]?$/.test(name);
}

/** Fonksiyon key'i olustur */
function makeFuncKey(className, methodName, line) {
  if (className && methodName) return `${className}::${methodName}`;
  if (methodName) return methodName;
  return `anon@${line}`;
}

/** Body icindeki statement'lari duz liste olarak al (BlockStatement vs) */
function getBodyStatements(node) {
  if (!node) return [];
  if (t.isBlockStatement(node)) return node.body || [];
  // Arrow function: () => expr  -- tek expression
  return [node];
}

/** Bir AST node'unun icinden tum statement'lari recursive topla (ilk seviye yeterli) */
function* walkStatements(body) {
  if (!body) return;
  // body bir AST node olabilir, array olabilir, veya body.body ile nested olabilir
  let stmts;
  if (Array.isArray(body)) {
    stmts = body;
  } else if (body && typeof body === "object" && Array.isArray(body.body)) {
    stmts = body.body;
  } else if (body && typeof body === "object") {
    stmts = [body];
  } else {
    return;
  }
  for (const stmt of stmts) {
    if (!stmt) continue;
    yield stmt;
    // ExpressionStatement icindeki expression
    if (t.isExpressionStatement(stmt)) {
      yield stmt.expression;
      // SequenceExpression: (a, b, c) -> her biri
      if (t.isSequenceExpression(stmt.expression)) {
        for (const expr of stmt.expression.expressions) yield expr;
      }
    }
    // IfStatement: consequent/alternate
    if (t.isIfStatement(stmt)) {
      yield* walkStatements(stmt.consequent);
      if (stmt.alternate) yield* walkStatements(stmt.alternate);
    }
    // Try: block, handler, finalizer
    if (t.isTryStatement(stmt)) {
      yield* walkStatements(stmt.block);
      if (stmt.handler) yield* walkStatements(stmt.handler.body);
      if (stmt.finalizer) yield* walkStatements(stmt.finalizer);
    }
  }
}

// =====================================================================
// STRATEJI 1: this.X = param  (deep recursive tarama)
// =====================================================================

/** Body AST node'unu recursive dolasarak this.X = param pattern'lerini topla */
function analyzeThisAssignment(funcKey, params, bodyNode) {
  const paramNames = new Set(params.map(p => getParamName(p)).filter(Boolean));
  let found = 0;
  const maxDepth = 15; // Stack overflow koruması

  function checkAssignment(node, strategy) {
    if (!t.isAssignmentExpression(node) || node.operator !== "=") return;
    const left = node.left;
    let right = node.right;
    let suffix = "";
    let confidence = strategy === "this_assignment" ? 0.95 : 0.93;

    // this.X = param || default  veya  this.X = param ?? default
    if (t.isLogicalExpression(right) && (right.operator === "||" || right.operator === "??")) {
      suffix = ` ${right.operator} ...`;
      right = right.left;
      confidence = 0.90;
      strategy = "this_assignment_default";
    }

    if (
      t.isMemberExpression(left) &&
      t.isThisExpression(left.object) &&
      t.isIdentifier(left.property) &&
      t.isIdentifier(right) &&
      paramNames.has(right.name) &&
      isObfuscated(right.name)
    ) {
      const paramIdx = params.findIndex(p => getParamName(p) === right.name);
      if (paramIdx >= 0) {
        const propName = left.property.name;
        const cleanName = propName.replace(/^_+/, "") || propName;
        const key = `${funcKey}::${paramIdx}`;
        if (!recoveredParams.has(key) || recoveredParams.get(key).confidence < confidence) {
          recoveredParams.set(key, {
            originalName: right.name,
            recoveredName: cleanName,
            strategy,
            confidence,
            detail: `this.${propName} = ${right.name}${suffix}`,
          });
          found++;
        }
      }
    }
  }

  function deepWalk(node, depth) {
    if (!node || typeof node !== "object" || depth > maxDepth) return;
    if (Array.isArray(node)) {
      for (const child of node) deepWalk(child, depth);
      return;
    }

    // AssignmentExpression: this.X = param
    if (t.isAssignmentExpression(node)) {
      checkAssignment(node, "this_assignment");
    }

    // SequenceExpression: (this.X = e, this.Y = t, ...)
    if (t.isSequenceExpression(node)) {
      for (const expr of node.expressions) {
        if (t.isAssignmentExpression(expr)) {
          checkAssignment(expr, "this_assignment_seq");
        }
      }
    }

    // Cocuk node'lari recursive dolas
    // Ama ic fonksiyonlara GIRME (param scope degisir)
    for (const key of Object.keys(node)) {
      if (key === "start" || key === "end" || key === "loc" || key === "type" ||
          key === "leadingComments" || key === "trailingComments" || key === "extra") continue;
      const child = node[key];
      if (!child || typeof child !== "object") continue;

      // Ic fonksiyon tanimina girme - param scope degisir
      if (child.type === "FunctionExpression" || child.type === "ArrowFunctionExpression" ||
          child.type === "FunctionDeclaration" || child.type === "ClassMethod" ||
          child.type === "ObjectMethod") continue;

      deepWalk(child, depth + 1);
    }
  }

  deepWalk(bodyNode, 0);
  return found;
}

// =====================================================================
// STRATEJI 2: Destructuring -- const { X, Y } = param  (deep walk)
// =====================================================================
function analyzeDestructuring(funcKey, params, bodyNode) {
  const paramNames = new Set(params.map(p => getParamName(p)).filter(Boolean));
  let found = 0;
  const maxDepth = 15;

  function checkDeclarator(decl) {
    if (
      t.isObjectPattern(decl.id) &&
      t.isIdentifier(decl.init) &&
      paramNames.has(decl.init.name) &&
      isObfuscated(decl.init.name)
    ) {
      const paramIdx = params.findIndex(p => getParamName(p) === decl.init.name);
      if (paramIdx >= 0) {
        const props = decl.id.properties
          .filter(p => (t.isObjectProperty(p) || t.isProperty(p)) && t.isIdentifier(p.key))
          .map(p => p.key.name);
        // RestElement'teki identifier'i de al
        const rest = decl.id.properties.find(p => t.isRestElement(p));
        if (rest && t.isIdentifier(rest.argument)) {
          props.push(`...${rest.argument.name}`);
        }

        if (props.length > 0) {
          const key = `${funcKey}::${paramIdx}`;
          let recoveredName;
          if (props.length <= 2) {
            recoveredName = props.map(p => p.replace("...", "")).join("And");
          } else {
            recoveredName = "options";
          }

          if (!recoveredParams.has(key) || recoveredParams.get(key).confidence < 0.85) {
            recoveredParams.set(key, {
              originalName: decl.init.name,
              recoveredName,
              strategy: "destructuring",
              confidence: 0.88,
              detail: `const { ${props.join(", ")} } = ${decl.init.name}`,
              properties: props,
            });
            found++;
          }
        }
      }
    }
  }

  function deepWalk(node, depth) {
    if (!node || typeof node !== "object" || depth > maxDepth) return;
    if (Array.isArray(node)) {
      for (const child of node) deepWalk(child, depth);
      return;
    }

    if (t.isVariableDeclaration(node)) {
      for (const decl of node.declarations) checkDeclarator(decl);
    }
    if (t.isVariableDeclarator(node)) {
      checkDeclarator(node);
    }

    for (const key of Object.keys(node)) {
      if (key === "start" || key === "end" || key === "loc" || key === "type" ||
          key === "leadingComments" || key === "trailingComments" || key === "extra") continue;
      const child = node[key];
      if (!child || typeof child !== "object") continue;
      if (child.type === "FunctionExpression" || child.type === "ArrowFunctionExpression" ||
          child.type === "FunctionDeclaration") continue;
      deepWalk(child, depth + 1);
    }
  }

  deepWalk(bodyNode, 0);
  return found;
}

// =====================================================================
// STRATEJI 3: param.X erisimi (property access pattern)
// =====================================================================
function analyzePropertyAccess(funcKey, params, bodyNode) {
  const paramNames = new Set(params.map(p => getParamName(p)).filter(Boolean));
  // Her parametre icin erisilige property'leri topla
  const accessMap = new Map(); // paramName -> Set<propertyName>

  // Body icindeki tum node'lari recursive dolas
  function collectAccess(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const child of node) collectAccess(child);
      return;
    }

    // MemberExpression: param.X
    if (
      t.isMemberExpression(node) &&
      t.isIdentifier(node.object) &&
      paramNames.has(node.object.name) &&
      isObfuscated(node.object.name) &&
      t.isIdentifier(node.property) &&
      !node.computed
    ) {
      const pName = node.object.name;
      if (!accessMap.has(pName)) accessMap.set(pName, new Set());
      accessMap.get(pName).add(node.property.name);
    }

    // Cocuk node'lari dolas (performans icin sadece AST key'leri)
    for (const key of Object.keys(node)) {
      if (key === "start" || key === "end" || key === "loc" || key === "type" || key === "leadingComments" || key === "trailingComments") continue;
      const child = node[key];
      if (child && typeof child === "object") collectAccess(child);
    }
  }

  collectAccess(bodyNode);

  let found = 0;
  for (const [paramName, props] of accessMap) {
    const paramIdx = params.findIndex(p => getParamName(p) === paramName);
    if (paramIdx < 0) continue;

    const key = `${funcKey}::${paramIdx}`;
    // Zaten daha iyi bir recovery varsa atla
    if (recoveredParams.has(key) && recoveredParams.get(key).confidence >= 0.85) continue;

    const propList = [...props];

    // Bilinen pattern'lere gore isim ver
    let recoveredName = null;
    let confidence = 0.6;

    // Webpack exports pattern: t.X = ... (cok yaygin)
    if (props.has("__esModule") || (props.has("exports") && propList.length === 1)) {
      recoveredName = "exports";
      confidence = 0.78;
    }
    // Array pattern
    else if (props.has("push") || props.has("pop") || props.has("shift") || props.has("splice") || props.has("forEach") || props.has("map") || props.has("filter")) {
      recoveredName = "array";
      confidence = 0.60;
    }
    // Event emitter
    else if (props.has("on") && props.has("emit")) {
      recoveredName = "emitter";
      confidence = 0.68;
    }
    // Promise
    else if (props.has("then") && (props.has("catch") || props.has("finally"))) {
      recoveredName = "promise";
      confidence = 0.70;
    }
    // Stream
    else if ((props.has("pipe") && props.has("on")) || (props.has("write") && props.has("end"))) {
      recoveredName = "stream";
      confidence = 0.60;
    }
    // Request
    else if (props.has("method") && props.has("url")) {
      recoveredName = "request";
      confidence = 0.72;
    }
    // Response
    else if (props.has("statusCode") || props.has("setHeader")) {
      recoveredName = "response";
      confidence = 0.72;
    }
    // Error
    else if (props.has("message") && (props.has("stack") || props.has("code") || props.has("name"))) {
      recoveredName = "error";
      confidence = 0.72;
    }
    // Context (Babel/OpenTelemetry vs)
    else if (props.has("parsedType") || props.has("contextualErrorMap") || props.has("common")) {
      recoveredName = "context";
      confidence = 0.65;
    }
    // Path
    else if (props.has("fsPath") || props.has("dirname") || props.has("basename")) {
      recoveredName = "filePath";
      confidence = 0.65;
    }
    // Node.js child_process
    else if (props.has("stdin") && props.has("stdout")) {
      recoveredName = "childProcess";
      confidence = 0.68;
    }
    // Config/Options: cok sayida property erisimi
    else if (propList.length >= 4) {
      recoveredName = "options";
      confidence = 0.55;
    }
    // 2-3 property: tek property'den isim uretme, ama bilgi olarak kaydet
    else if (propList.length >= 2) {
      // Iki property'nin ortak temasi?
      recoveredName = propList.length === 2 ? propList.join("And") : "config";
      confidence = 0.45;
    }
    // 1 property: dusuk deger, ama yine de kaydet
    else if (propList.length === 1) {
      // Tek property erisilmis -- parametre bu property'nin sahibi
      const prop = propList[0];
      // Bazi ozel durumlar
      if (prop === "length") { recoveredName = "collection"; confidence = 0.35; }
      else if (prop === "prototype") { recoveredName = "constructor"; confidence = 0.45; }
      else if (prop === "call" || prop === "apply" || prop === "bind") { recoveredName = "fn"; confidence = 0.50; }
      else if (prop === "dispose" || prop === "destroy") { recoveredName = "disposable"; confidence = 0.45; }
      else { recoveredName = prop + "Owner"; confidence = 0.35; }
    }

    if (recoveredName) {
      recoveredParams.set(key, {
        originalName: paramName,
        recoveredName,
        strategy: "property_access",
        confidence,
        detail: `${paramName}.{${propList.join(", ")}}`,
        properties: propList,
      });
      found++;
    }
  }
  return found;
}

// =====================================================================
// STRATEJI 4: Call-site object literal → constructor param recovery
// =====================================================================
// Bu strateji iki asamali:
//   Asama 1: Traverse sirasinda call-site'lari topla
//   Asama 2: funcDefs ile eslestir

function collectCallSiteInfo(node) {
  // new Foo({ prop1: x, prop2: y })
  if (t.isNewExpression(node) && node.arguments?.length > 0) {
    const calleeName = getCalleeName(node.callee);
    if (calleeName) {
      const argsInfo = node.arguments.map(analyzeArgument);
      if (!callSites.has(calleeName)) callSites.set(calleeName, []);
      callSites.get(calleeName).push({
        args: argsInfo,
        line: node.loc?.start?.line || 0,
        type: "new",
      });
    }
  }

  // foo(arg1, arg2)  veya  obj.method(arg1, arg2)
  if (t.isCallExpression(node)) {
    const calleeName = getCalleeName(node.callee);
    if (calleeName && node.arguments?.length > 0) {
      const argsInfo = node.arguments.map(analyzeArgument);
      if (!callSites.has(calleeName)) callSites.set(calleeName, []);
      callSites.get(calleeName).push({
        args: argsInfo,
        line: node.loc?.start?.line || 0,
        type: "call",
      });
    }
  }
}

function getCalleeName(node) {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node) && t.isIdentifier(node.property)) {
    // obj.method -> "method"
    // Foo.Bar -> "Bar"
    return node.property.name;
  }
  return null;
}

function analyzeArgument(argNode) {
  // Object literal: { prop1: x, prop2: y }
  if (t.isObjectExpression(argNode)) {
    const props = argNode.properties
      .filter(p => t.isObjectProperty(p) && t.isIdentifier(p.key))
      .map(p => p.key.name);
    return { type: "object_literal", properties: props };
  }
  // Identifier: acik isimli degisken
  if (t.isIdentifier(argNode)) {
    return { type: "identifier", name: argNode.name, isObfuscated: isObfuscated(argNode.name) };
  }
  // String literal
  if (t.isStringLiteral(argNode)) {
    return { type: "string", value: argNode.value };
  }
  // Function/arrow
  if (t.isArrowFunctionExpression(argNode) || t.isFunctionExpression(argNode)) {
    return { type: "function" };
  }
  // Diger
  return { type: "other" };
}

// =====================================================================
// STRATEJI 5: Webpack module pattern
// Webpack callback: (e, t, n) => { } burada e=module, t=exports, n=require
// =====================================================================
const WEBPACK_PARAM_NAMES = ["module", "exports", "__webpack_require__"];

function isWebpackModuleCallback(path) {
  // Parent: ObjectProperty icinde, key numeric literal veya identifier
  // GrandParent: ObjectExpression (__webpack_modules__)
  const parent = path.parent;
  if (!parent) return false;

  // (e, t, n) => {} veya (e) => {} seklinde property value
  if (t.isObjectProperty(parent)) {
    const key = parent.key;
    // Key sayi (643: e => {}) veya string
    if (t.isNumericLiteral(key) || t.isStringLiteral(key)) {
      return true;
    }
  }
  return false;
}

function applyWebpackPattern(funcKey, params) {
  let found = 0;
  const max = Math.min(params.length, 3);
  for (let i = 0; i < max; i++) {
    const paramName = getParamName(params[i]);
    if (!isObfuscated(paramName)) continue;
    const key = `${funcKey}::${i}`;
    if (!recoveredParams.has(key) || recoveredParams.get(key).confidence < 0.80) {
      recoveredParams.set(key, {
        originalName: paramName,
        recoveredName: WEBPACK_PARAM_NAMES[i],
        strategy: "webpack_module",
        confidence: 0.80,
        detail: `webpack module callback param[${i}] = ${WEBPACK_PARAM_NAMES[i]}`,
      });
      found++;
    }
  }
  return found;
}

// =====================================================================
// ANA TRAVERSE
// =====================================================================

let totalFunctions = 0;
let totalParams = 0;
let obfuscatedParams = 0;

// Single-pass traverse: noScope = true
traverse(ast, {
  noScope: true,

  // Fonksiyon tanimlari
  "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ObjectMethod|ClassMethod"(path) {
    const node = path.node;
    const params = node.params || [];
    if (params.length === 0) return;

    totalFunctions++;
    totalParams += params.length;

    // Fonksiyon key'i belirle
    let className = null;
    let methodName = null;

    if (t.isClassMethod(node) || t.isObjectMethod(node)) {
      methodName = t.isIdentifier(node.key) ? node.key.name : (t.isStringLiteral(node.key) ? node.key.value : "computed");
      // Ust class'i bul
      const parentNode = path.parent;
      if (t.isClassBody(parentNode)) {
        const classNode = path.parentPath?.parent;
        if (classNode && t.isIdentifier(classNode.id)) {
          className = classNode.id.name;
        }
      }
    } else if (t.isFunctionDeclaration(node) && node.id) {
      methodName = node.id.name;
    } else if (t.isFunctionExpression(node) && node.id) {
      methodName = node.id.name;
    } else {
      // Arrow veya anonim: parent'a bak
      const parent = path.parent;
      if (t.isVariableDeclarator(parent) && t.isIdentifier(parent.id)) {
        methodName = parent.id.name;
      } else if (t.isAssignmentExpression(parent) && t.isIdentifier(parent.left)) {
        methodName = parent.left.name;
      } else if (t.isProperty(parent) && t.isIdentifier(parent.key)) {
        methodName = parent.key.name;
      } else if (t.isObjectProperty(parent) && t.isIdentifier(parent.key)) {
        methodName = parent.key.name;
      }
    }

    const line = node.loc?.start?.line || 0;
    const funcKey = makeFuncKey(className, methodName, line);

    // Kac tane obfuscated param var?
    const obfParams = params.filter(p => isObfuscated(getParamName(p)));
    obfuscatedParams += obfParams.length;

    if (obfParams.length === 0) return; // Zaten temiz isimler

    // Fonksiyon bilgisini kaydet
    funcDefs.set(funcKey, {
      className,
      methodName,
      line,
      params,
      paramCount: params.length,
    });

    const body = node.body;

    // Strateji 5: Webpack module pattern (en dusuk oncelik, diger stratejiler override eder)
    if (isWebpackModuleCallback(path)) {
      applyWebpackPattern(funcKey, params);
    }

    // Strateji 1: this.X = param (en yuksek oncelik)
    analyzeThisAssignment(funcKey, params, body);

    // Strateji 2: Destructuring
    analyzeDestructuring(funcKey, params, body);

    // Strateji 3: Property access
    analyzePropertyAccess(funcKey, params, body);
  },

  // Call-site bilgileri topla (Strateji 4 icin)
  "NewExpression|CallExpression"(path) {
    collectCallSiteInfo(path.node);
  },
});

console.error(`[param-recovery] Traverse complete. Applying call-site analysis...`);

// =====================================================================
// STRATEJI 4: Call-site eslestirme (post-process)
// =====================================================================
let callSiteRecoveries = 0;

for (const [funcKey, funcInfo] of funcDefs) {
  const { methodName, params } = funcInfo;
  if (!methodName) continue;

  // Bu fonksiyonu/constructor'i cagiran call-site'lar var mi?
  const sites = callSites.get(methodName);
  if (!sites || sites.length === 0) continue;

  for (const site of sites) {
    for (let i = 0; i < Math.min(site.args.length, params.length); i++) {
      const arg = site.args[i];
      const paramName = getParamName(params[i]);
      if (!isObfuscated(paramName)) continue;

      const key = `${funcKey}::${i}`;

      // Zaten yuksek confidence'li recovery varsa atla
      if (recoveredParams.has(key) && recoveredParams.get(key).confidence >= 0.85) continue;

      // Call-site'da object literal gecilmis
      if (arg.type === "object_literal" && arg.properties.length > 0) {
        const recoveredName = arg.properties.length <= 2
          ? arg.properties.join("And")
          : "options";

        recoveredParams.set(key, {
          originalName: paramName,
          recoveredName,
          strategy: "callsite_object",
          confidence: 0.82,
          detail: `call-site: ${methodName}({ ${arg.properties.join(", ")} })`,
          properties: arg.properties,
        });
        callSiteRecoveries++;
      }

      // Call-site'da acik isimli identifier gecilmis
      if (arg.type === "identifier" && !arg.isObfuscated && arg.name.length > 2) {
        const existing = recoveredParams.get(key);
        if (!existing || existing.confidence < 0.70) {
          recoveredParams.set(key, {
            originalName: paramName,
            recoveredName: arg.name,
            strategy: "callsite_identifier",
            confidence: 0.72,
            detail: `call-site: ${methodName}(..., ${arg.name}, ...)`,
          });
          callSiteRecoveries++;
        }
      }
    }
  }
}

console.error(`[param-recovery] Call-site analysis: ${callSiteRecoveries} additional recoveries`);

// =====================================================================
// SONUCLARI DERLE
// =====================================================================

// Strategy bazli istatistikler
const strategyStats = {};
for (const [, info] of recoveredParams) {
  const s = info.strategy;
  strategyStats[s] = (strategyStats[s] || 0) + 1;
}

// Sonuclari JSON'a cevir
const results = {};
for (const [key, info] of recoveredParams) {
  results[key] = {
    original: info.originalName,
    recovered: info.recoveredName,
    strategy: info.strategy,
    confidence: info.confidence,
    detail: info.detail,
  };
  if (info.properties) {
    results[key].properties = info.properties;
  }
}

const output = {
  success: true,
  stats: {
    totalFunctions,
    totalParams,
    obfuscatedParams,
    recoveredParams: recoveredParams.size,
    recoveryRate: obfuscatedParams > 0
      ? `${((recoveredParams.size / obfuscatedParams) * 100).toFixed(1)}%`
      : "0%",
    byStrategy: strategyStats,
  },
  recoveries: results,
};

// Cikti
const jsonStr = JSON.stringify(output, null, 2);

if (outputPath) {
  writeFileSync(outputPath, jsonStr, "utf-8");
  // Stdout'a ozet
  process.stdout.write(JSON.stringify({
    success: true,
    stats: output.stats,
    output: outputPath,
  }) + "\n");
} else {
  process.stdout.write(jsonStr + "\n");
}

console.error(`\n[param-recovery] === SONUC ===`);
console.error(`  Toplam fonksiyon: ${totalFunctions}`);
console.error(`  Toplam parametre: ${totalParams}`);
console.error(`  Obfuscated param: ${obfuscatedParams}`);
console.error(`  Geri kazanilan:   ${recoveredParams.size}`);
console.error(`  Kurtarma orani:   ${output.stats.recoveryRate}`);
console.error(`  Strateji dagilimi:`);
for (const [s, count] of Object.entries(strategyStats)) {
  console.error(`    ${s}: ${count}`);
}
