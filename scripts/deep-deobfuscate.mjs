#!/usr/bin/env node
/**
 * deep-deobfuscate.mjs -- Guclu Babel Transform Pipeline (Visitor-Merge Optimized)
 *
 * 10 asamali deobfuscation:
 *   Phase 1: Parse (tolerant mode, ESM + CJS)
 *   Phase 2: Constant Folding ("a"+"b" -> "ab", !0 -> true, void 0 -> undefined)
 *   Phase 3: Dead Code Elimination (if(false){} -> kaldir)
 *   Phase 4: Computed Property -> Static (obj["method"] -> obj.method)
 *   Phase 5: Comma Expression Splitting ((a=1,b=2,c) -> a=1; b=2; c;)
 *   Phase 6: Variable Declaration Splitting (var a=1,b=2 -> var a=1; var b=2;)
 *   Phase 7: Ternary -> If/Else (uzun ternary'ler icin)
 *   Phase 8: Arrow -> Named Function (const foo = () => {} -> function foo() {})
 *   Phase 9: Smart Variable Renaming (scope-aware, context-aware)
 *   Phase 10: Semantic Renaming (usage-based deep rename, 12 kural motoru)
 *
 * Optimizasyon: Phase 2-8 tek bir AST traverse'da birlestirildi (visitor-merge).
 * webcrack yaklasimi: Birden fazla transform'u tek traverse'da calistirmak
 * 7 ayri traverse yerine 1 tek traverse = ~3-5x hiz kazanci.
 *
 * Kullanim:
 *   node --max-old-space-size=8192 deep-deobfuscate.mjs <input> <output> [--phases all|1,2,3...]
 *
 * Stdout: JSON { success, phases_completed, stats, errors }
 */

import { readFileSync, writeFileSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";
import { createRequire } from "node:module";

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

// js-beautify lazy-load -- pre-beautify fallback icin
const _require = createRequire(import.meta.url);
let jsBeautify = null;

function loadBeautify() {
  try {
    jsBeautify = _require("js-beautify");
    return true;
  } catch {
    return false;
  }
}

/**
 * Pre-beautify: minified kaynak kodu once format et, sonra Babel ile tekrar dene.
 * 30MB+ minified dosyalarda Babel ternary+arrow+object pattern'lerinde takilabiliyor.
 * Beautify satirlara boldukten sonra cogu zaman parse basarili oluyor.
 */
function tryBeautifyThenParse(src) {
  if (!loadBeautify()) return null;

  const beautified = jsBeautify.js_beautify(src, {
    indent_size: 2,
    indent_char: " ",
    max_preserve_newlines: 2,
    preserve_newlines: true,
    brace_style: "collapse,preserve-inline",
    wrap_line_length: 120,
  });

  return parse(beautified, {
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
}

// ---------- Helpers (en uste tasindilar, visitor'lar kullanabilsin) ----------

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

const _RESERVED = new Set([
  "break", "case", "catch", "continue", "debugger", "default", "delete",
  "do", "else", "finally", "for", "function", "if", "in", "instanceof",
  "new", "return", "switch", "this", "throw", "try", "typeof", "var",
  "void", "while", "with", "class", "const", "enum", "export", "extends",
  "import", "super", "implements", "interface", "let", "package", "private",
  "protected", "public", "static", "yield", "null", "true", "false",
  "undefined", "NaN", "Infinity", "arguments",
]);

function isReservedWord(word) {
  return _RESERVED.has(word);
}

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

if (positional.length < 2) {
  emit({
    success: false,
    errors: ["Kullanim: node deep-deobfuscate.mjs <input> <output> [--phases all|1,2,3...]"],
  });
  process.exit(1);
}

const inputPath = resolve(positional[0]);
const outputPath = resolve(positional[1]);
const phasesArg = flags.get("--phases") || "all";
const requestedPhases = phasesArg === "all"
  ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  : phasesArg.split(",").map(Number).filter(Boolean);

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

const errors = [];
const phaseStats = {};
const phasesCompleted = [];

// ---------- Phase 1: Parse ----------
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
      "importMeta",
    ],
  });
  if (ast.errors?.length > 0) {
    for (const e of ast.errors) {
      errors.push(`Parse recovered: ${e.message} @ L${e.loc?.line || "?"}`);
    }
  }
  phaseStats["phase1_parse"] = { recovered_errors: ast.errors?.length || 0 };
  phasesCompleted.push(1);
} catch (babelErr) {
  // Babel parse basarisiz -- pre-beautify + tekrar dene
  errors.push(`Babel parse basarisiz: ${babelErr.message}`);

  try {
    ast = tryBeautifyThenParse(source);
    if (ast) {
      errors.push("Pre-beautify + Babel retry basarili");
      if (ast.errors?.length > 0) {
        for (const e of ast.errors) {
          errors.push(`Parse recovered (beautified): ${e.message} @ L${e.loc?.line || "?"}`);
        }
      }
      phaseStats["phase1_parse"] = {
        recovered_errors: ast.errors?.length || 0,
        method: "pre-beautify",
      };
      phasesCompleted.push(1);
    } else {
      throw new Error("Beautify yuklenemedi veya null AST");
    }
  } catch (retryErr) {
    // Pre-beautify de basarisiz -- dosyayi oldugu gibi kopyala, partial success
    errors.push(`Pre-beautify retry de basarisiz: ${retryErr.message}`);

    // Output dosyasina kaynak kodu oldugu gibi yaz (en azindan webpack unpack adimlari devam edebilsin)
    try {
      writeFileSync(outputPath, source, "utf-8");
    } catch { /* ignore */ }

    emit({
      success: false,
      phases_completed: [],
      stats: { file_size: fileSize },
      errors,
      output_file: outputPath,
      fallback_copy: true,
    });
    process.exit(0);
  }
}

// ---------- Phase 2-8: Combined Single-Pass Visitor (Visitor-Merge) ----------
//
// webcrack yaklasimi: Birden fazla Babel transform'unu tek bir AST traverse'da
// birlestiriyoruz. Her phase icin ayri sayac tutulur, stats uyumlu kalir.
//
// Sira bagimliligi:
//   Phase 2 (Constant Folding) -> Phase 3 (Dead Code): !0 -> true, sonra if(true) temizlenir
//   Babel exit visitor'lari bottom-up calisir: ic node once, parent sonra.
//   Yani if(!0){...} icin: once !0->true (UnaryExpression.exit), sonra if(true)->consequent (IfStatement.exit)
//   Bu tek pass'ta dogru calisir.
//
// Node tipi cakismasi:
//   Phase 6 (VarDeclaration split) + Phase 8 (Arrow to func) ikisi de VariableDeclaration kullanir.
//   Cozum: VariableDeclaration visitor'inda once arrow kontrolu, sonra split kontrolu.
//
//   Phase 5 (Comma split) + Phase 7 (Ternary to if) ikisi de ExpressionStatement kullanir.
//   Cozum: ExpressionStatement visitor'inda once comma kontrolu, sonra ternary kontrolu.

// Hangi phase'lar aktif?
const p2 = requestedPhases.includes(2);
const p3 = requestedPhases.includes(3);
const p4 = requestedPhases.includes(4);
const p5 = requestedPhases.includes(5);
const p6 = requestedPhases.includes(6);
const p7 = requestedPhases.includes(7);
const p8 = requestedPhases.includes(8);

// En az bir phase (2-8) aktif mi?
const anyCombinedPhase = p2 || p3 || p4 || p5 || p6 || p7 || p8;

if (anyCombinedPhase) {
  // Phase sayaclari
  let cnt2 = 0; // constant_folding
  let cnt3 = 0; // dead_code_elimination
  let cnt4 = 0; // computed_to_static
  let cnt5 = 0; // comma_splitting
  let cnt6 = 0; // var_declaration_split
  let cnt7 = 0; // ternary_to_if
  let cnt8 = 0; // arrow_to_function

  const combinedStart = Date.now();

  try {
    // Birlesik visitor: tum phase'lar tek traverse'da
    const combinedVisitor = {};

    // --- BinaryExpression (Phase 2: Constant Folding) ---
    if (p2) {
      combinedVisitor.BinaryExpression = {
        exit(path) {
          const { left, right, operator } = path.node;

          // String concatenation
          if (operator === "+" && t.isStringLiteral(left) && t.isStringLiteral(right)) {
            path.replaceWith(t.stringLiteral(left.value + right.value));
            cnt2++;
            return;
          }

          // Numeric operations
          if (t.isNumericLiteral(left) && t.isNumericLiteral(right)) {
            let result;
            switch (operator) {
              case "+": result = left.value + right.value; break;
              case "-": result = left.value - right.value; break;
              case "*": result = left.value * right.value; break;
              case "/": if (right.value !== 0) result = left.value / right.value; break;
              case "%": if (right.value !== 0) result = left.value % right.value; break;
              case "**": result = left.value ** right.value; break;
              case "|": result = left.value | right.value; break;
              case "&": result = left.value & right.value; break;
              case "^": result = left.value ^ right.value; break;
              case "<<": result = left.value << right.value; break;
              case ">>": result = left.value >> right.value; break;
              case ">>>": result = left.value >>> right.value; break;
              default: return;
            }
            if (result !== undefined && Number.isFinite(result)) {
              path.replaceWith(t.numericLiteral(result));
              cnt2++;
            }
          }
        },
      };
    }

    // --- UnaryExpression (Phase 2: Constant Folding -- !0->true, void 0->undefined) ---
    if (p2) {
      combinedVisitor.UnaryExpression = {
        exit(path) {
          const { operator, argument } = path.node;

          if (operator === "!" && t.isNumericLiteral(argument)) {
            path.replaceWith(t.booleanLiteral(!argument.value));
            cnt2++;
            return;
          }

          // void 0 -> undefined
          if (operator === "void" && t.isNumericLiteral(argument) && argument.value === 0) {
            path.replaceWith(t.identifier("undefined"));
            cnt2++;
            return;
          }
        },
      };
    }

    // --- IfStatement (Phase 3: Dead Code Elimination) ---
    if (p3) {
      combinedVisitor.IfStatement = {
        // exit kullaniyoruz: constant folding once calissin (!0->true), sonra if(true) temizlensin
        exit(path) {
          if (!path.node) return;
          const test = path.node.test;

          // if (false) { ... } -> kaldir
          if (t.isBooleanLiteral(test) && test.value === false) {
            if (path.node.alternate) {
              path.replaceWith(path.node.alternate);
            } else {
              path.remove();
            }
            cnt3++;
            return;
          }

          // if (true) { X } else { Y } -> X
          if (t.isBooleanLiteral(test) && test.value === true) {
            path.replaceWith(path.node.consequent);
            cnt3++;
            return;
          }

          // if (0) -> remove, if (1) -> consequent
          if (t.isNumericLiteral(test)) {
            if (test.value === 0) {
              if (path.node.alternate) {
                path.replaceWith(path.node.alternate);
              } else {
                path.remove();
              }
              cnt3++;
            } else {
              path.replaceWith(path.node.consequent);
              cnt3++;
            }
          }
        },
      };
    }

    // --- ConditionalExpression (Phase 3: Dead Code Elimination) ---
    if (p3) {
      combinedVisitor.ConditionalExpression = {
        exit(path) {
          if (!path.node) return;
          const test = path.node.test;

          if (t.isBooleanLiteral(test)) {
            path.replaceWith(test.value ? path.node.consequent : path.node.alternate);
            cnt3++;
          }
        },
      };
    }

    // --- MemberExpression (Phase 4: Computed to Static) ---
    if (p4) {
      combinedVisitor.MemberExpression = function (path) {
        if (!path.node.computed) return;
        const prop = path.node.property;
        if (!t.isStringLiteral(prop)) return;

        if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(prop.value) && !isReservedWord(prop.value)) {
          path.node.computed = false;
          path.node.property = t.identifier(prop.value);
          cnt4++;
        }
      };
    }

    // --- ObjectProperty (Phase 4: Computed to Static) ---
    if (p4) {
      combinedVisitor.ObjectProperty = function (path) {
        if (!path.node.computed) return;
        const key = path.node.key;
        if (!t.isStringLiteral(key)) return;

        if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(key.value) && !isReservedWord(key.value)) {
          path.node.computed = false;
          path.node.key = t.identifier(key.value);
          cnt4++;
        }
      };
    }

    // --- ExpressionStatement (Phase 5: Comma Splitting + Phase 7: Ternary to If) ---
    // Iki phase ayni node tipini kullaniyor. Tek visitor'da ikisini de handle ediyoruz.
    if (p5 || p7) {
      combinedVisitor.ExpressionStatement = function (path) {
        if (!path.node || !path.node.expression) return;
        const expr = path.node.expression;

        // Phase 5: Comma splitting (sequence expression)
        if (p5 && t.isSequenceExpression(expr)) {
          const stmts = expr.expressions.map((e) => t.expressionStatement(e));
          path.replaceWithMultiple(stmts);
          cnt5++;
          return; // replaceWithMultiple sonrasi path invalidate olur
        }

        // Phase 7: Ternary to if (conditional expression)
        if (p7 && t.isConditionalExpression(expr)) {
          const { code: testCode } = generate(expr.test, { compact: true });
          const { code: consCode } = generate(expr.consequent, { compact: true });
          const { code: altCode } = generate(expr.alternate, { compact: true });

          if (testCode.length + consCode.length + altCode.length < 80) return;

          const ifStmt = t.ifStatement(
            expr.test,
            t.expressionStatement(expr.consequent),
            t.expressionStatement(expr.alternate)
          );

          path.replaceWith(ifStmt);
          cnt7++;
        }
      };
    }

    // --- ReturnStatement (Phase 5: Comma Splitting) ---
    if (p5) {
      combinedVisitor.ReturnStatement = function (path) {
        if (!path.node) return;
        const arg = path.node.argument;
        if (!arg || !t.isSequenceExpression(arg)) return;

        const exprs = arg.expressions;
        if (exprs.length < 2) return;

        const stmts = [];
        for (let i = 0; i < exprs.length - 1; i++) {
          stmts.push(t.expressionStatement(exprs[i]));
        }
        stmts.push(t.returnStatement(exprs[exprs.length - 1]));

        path.replaceWithMultiple(stmts);
        cnt5++;
      };
    }

    // --- ThrowStatement (Phase 5: Comma Splitting) ---
    if (p5) {
      combinedVisitor.ThrowStatement = function (path) {
        if (!path.node) return;
        const arg = path.node.argument;
        if (!arg || !t.isSequenceExpression(arg)) return;

        const exprs = arg.expressions;
        if (exprs.length < 2) return;

        const stmts = [];
        for (let i = 0; i < exprs.length - 1; i++) {
          stmts.push(t.expressionStatement(exprs[i]));
        }
        stmts.push(t.throwStatement(exprs[exprs.length - 1]));

        path.replaceWithMultiple(stmts);
        cnt5++;
      };
    }

    // --- VariableDeclaration (Phase 6: Split + Phase 8: Arrow to Function) ---
    // Iki phase ayni node tipini kullaniyor.
    // Oncelik: Phase 8 (arrow to func) ONCE kontrol edilir -- cunku:
    //   const foo = () => {} tek decl'dir, Phase 6 zaten skip eder (length <= 1).
    //   Ama garanti icin once Phase 8 kontrolu.
    if (p6 || p8) {
      combinedVisitor.VariableDeclaration = function (path) {
        // Guard: replaceWithMultiple/replaceWith sonrasi path invalidate olabilir
        if (!path.node || !path.node.declarations) return;

        // --- Phase 8: Arrow to Named Function ---
        if (p8 && path.node.declarations.length === 1) {
          const decl = path.node.declarations[0];
          if (decl.init && t.isArrowFunctionExpression(decl.init) && t.isIdentifier(decl.id)) {
            const arrow = decl.init;
            // Sadece block body arrow'lar
            if (t.isBlockStatement(arrow.body)) {
              // this kullanan arrow'lari donusturme (semantik degisir)
              const { code: bodyCode } = generate(arrow.body, { compact: true });
              if (!bodyCode.includes("this.") && !bodyCode.includes("this[")) {
                const funcDecl = t.functionDeclaration(
                  t.identifier(decl.id.name),
                  arrow.params,
                  arrow.body,
                  arrow.generator || false,
                  arrow.async || false,
                );

                try {
                  path.replaceWith(funcDecl);
                  cnt8++;
                  return; // replaceWith sonrasi devam etme
                } catch (_) {
                  // Export icerisinde vb. calismayabilir
                }
              }
            }
          }
        }

        // --- Phase 6: Variable Declaration Splitting ---
        if (p6) {
          // Re-check guard: Phase 8 replaceWith sonrasi path invalidate olabilir
          if (!path.node || !path.node.declarations) return;
          if (path.node.declarations.length <= 1) return;
          // for-loop init'te split yapma
          if (path.parent.type === "ForStatement" && path.key === "init") return;
          if (path.parent.type === "ForInStatement") return;
          if (path.parent.type === "ForOfStatement") return;

          const kind = path.node.kind;
          const stmts = path.node.declarations.map((decl) =>
            t.variableDeclaration(kind, [decl])
          );

          try {
            path.replaceWithMultiple(stmts);
            cnt6++;
          } catch (_) {
            // Bazi pozisyonlarda (export, if test vb.) replaceWithMultiple calismaz
          }
        }
      };
    }

    // Birlesik traverse: TEK PASS
    traverse(ast, combinedVisitor);

    // Harcanan toplam sure
    const combinedDuration = Date.now() - combinedStart;

    // Her phase icin stats kaydet (uyumluluk icin ayri ayri)
    if (p2) {
      phaseStats["constant_folding"] = { transforms: cnt2, duration_ms: combinedDuration, merged: true };
      phasesCompleted.push(2);
    }
    if (p3) {
      phaseStats["dead_code_elimination"] = { transforms: cnt3, duration_ms: combinedDuration, merged: true };
      phasesCompleted.push(3);
    }
    if (p4) {
      phaseStats["computed_to_static"] = { transforms: cnt4, duration_ms: combinedDuration, merged: true };
      phasesCompleted.push(4);
    }
    if (p5) {
      phaseStats["comma_splitting"] = { transforms: cnt5, duration_ms: combinedDuration, merged: true };
      phasesCompleted.push(5);
    }
    if (p6) {
      phaseStats["var_declaration_split"] = { transforms: cnt6, duration_ms: combinedDuration, merged: true };
      phasesCompleted.push(6);
    }
    if (p7) {
      phaseStats["ternary_to_if"] = { transforms: cnt7, duration_ms: combinedDuration, merged: true };
      phasesCompleted.push(7);
    }
    if (p8) {
      phaseStats["arrow_to_function"] = { transforms: cnt8, duration_ms: combinedDuration, merged: true };
      phasesCompleted.push(8);
    }

  } catch (err) {
    const combinedDuration = Date.now() - combinedStart;
    errors.push(`Combined pass (phases 2-8) hata: ${err.message}`);
    // Hata durumunda hangi phase'lar istenmisse onlarin stats'ini kaydet
    const phaseNames = {
      2: "constant_folding", 3: "dead_code_elimination", 4: "computed_to_static",
      5: "comma_splitting", 6: "var_declaration_split", 7: "ternary_to_if", 8: "arrow_to_function",
    };
    for (const [num, name] of Object.entries(phaseNames)) {
      if (requestedPhases.includes(Number(num))) {
        phaseStats[name] = { error: err.message, duration_ms: combinedDuration };
      }
    }
  }
}

// ---------- Phase 9: Smart Variable Renaming ----------
// Bu phase scope.rename kullaniyor, birlesik pass'a dahil EDILEMEZ.
// Kendi traverse'inda kalir.
if (requestedPhases.includes(9)) {
  const phase9Start = Date.now();
  let renameCount = 0;

  const _MODULE_SUGGESTIONS = {
    fs: "fs", path: "path", os: "os",
    http: "http", https: "https", http2: "http2",
    url: "urlModule", crypto: "crypto",
    events: "events", stream: "stream",
    util: "util", child_process: "childProcess",
    net: "net", dns: "dns", tls: "tls",
    zlib: "zlib", readline: "readline",
    querystring: "querystring", buffer: "buffer",
    cluster: "cluster", vm: "vm", v8: "v8",
    assert: "assert", inspector: "inspector",
    perf_hooks: "perfHooks", worker_threads: "workerThreads",
    async_hooks: "asyncHooks", diagnostics_channel: "diagChannel",
    timers: "timers", console: "consoleModule",
    express: "express", react: "React", "react-dom": "ReactDOM",
    axios: "axios", lodash: "lodash", chalk: "chalk",
    commander: "commander", yargs: "yargs",
  };

  function _modSuggestion(moduleName) {
    const clean = moduleName.replace(/^node:/, "");
    if (_MODULE_SUGGESTIONS[clean]) return _MODULE_SUGGESTIONS[clean];
    if (clean.includes("/")) {
      const parts = clean.split("/");
      return parts.map((p, i) =>
        i === 0 ? p : p.charAt(0).toUpperCase() + p.slice(1)
      ).join("");
    }
    return null;
  }

  try {
    traverse(ast, {
      // require('X') pattern
      VariableDeclarator(path) {
        const init = path.node.init;
        if (!init || !t.isIdentifier(path.node.id)) return;
        const name = path.node.id.name;
        if (name.length > 3) return;

        if (
          t.isCallExpression(init) &&
          t.isIdentifier(init.callee) &&
          init.callee.name === "require" &&
          init.arguments.length === 1 &&
          t.isStringLiteral(init.arguments[0])
        ) {
          const suggested = _modSuggestion(init.arguments[0].value);
          if (suggested && suggested !== name) {
            try {
              path.scope.rename(name, suggested);
              renameCount++;
            } catch (_) {}
          }
        }
      },

      // catch(e) -> catch(error)
      CatchClause(path) {
        const param = path.node.param;
        if (param && t.isIdentifier(param) && param.name.length <= 2) {
          try {
            const uniqueName = path.scope.hasBinding("error") ? `error_${param.name}` : "error";
            path.scope.rename(param.name, uniqueName);
            renameCount++;
          } catch (_) {}
        }
      },

      // Fonksiyon parametreleri
      "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression"(path) {
        const params = path.node.params;
        if (params.length === 0) return;

        let bodyStr = "";
        try {
          const body = path.node.body;
          if (body) {
            const { code } = generate(body, { compact: true });
            bodyStr = code.length > 2000 ? code.slice(0, 2000) : code;
          }
        } catch (_) {}

        for (let i = 0; i < params.length; i++) {
          const param = params[i];
          if (!t.isIdentifier(param)) continue;
          if (param.name.length > 2) continue;

          let suggestion = null;

          // Express handler tespiti
          if (params.length >= 2 && params.length <= 4) {
            const reqMethods = [".body", ".params", ".query", ".headers", ".method"];
            const resMethods = [".send(", ".json(", ".status(", ".render(", ".redirect("];
            let reqScore = 0, resScore = 0;
            for (const m of reqMethods) if (bodyStr.includes(m)) reqScore++;
            for (const m of resMethods) if (bodyStr.includes(m)) resScore++;

            if (reqScore >= 1 && resScore >= 1) {
              if (params.length >= 4) {
                suggestion = ["error", "request", "response", "next"][i];
              } else {
                suggestion = ["request", "response", "next"][i];
              }
            }
          }

          // esbuild CJS factory: (exports, module) pattern
          if (!suggestion && params.length >= 2 && params.length <= 3) {
            if (i === 0 && bodyStr.includes(".exports")) suggestion = "exports";
            if (i === 1 && bodyStr.includes("module.exports")) suggestion = "module";
          }

          // Usage-based inference
          if (!suggestion) {
            const prefix = param.name + ".";
            if (bodyStr.includes(prefix + "push(") || bodyStr.includes(prefix + "map(") ||
                bodyStr.includes(prefix + "forEach(") || bodyStr.includes(prefix + "length")) {
              suggestion = "items";
            } else if (bodyStr.includes(prefix + "trim(") || bodyStr.includes(prefix + "split(") ||
                       bodyStr.includes(prefix + "replace(")) {
              suggestion = "text";
            } else if (bodyStr.includes(prefix + "message") || bodyStr.includes(prefix + "stack")) {
              suggestion = "err";
            } else if (bodyStr.includes(prefix + "then(") || bodyStr.includes(prefix + "catch(")) {
              suggestion = "promise";
            }
          }

          // Tek harf fallback
          if (!suggestion && param.name.length === 1) {
            const defaults = {
              a: "arg", b: "buf", c: "ctx", d: "data",
              e: "elem", f: "fn", g: "gen", h: "handler",
              i: "idx", j: "jdx", k: "key", l: "len",
              m: "mod", n: "count", o: "opts", p: "param",
              q: "query", r: "res", s: "str", t: "tmp",
              u: "usr", v: "val", w: "writer",
            };
            suggestion = defaults[param.name.toLowerCase()];
          }

          if (suggestion && suggestion !== param.name) {
            try {
              path.scope.rename(param.name, suggestion);
              renameCount++;
            } catch (_) {
              // Cakisma varsa devam et
            }
          }
        }
      },
    });

    phaseStats["smart_rename"] = { transforms: renameCount, duration_ms: Date.now() - phase9Start };
    phasesCompleted.push(9);
  } catch (err) {
    errors.push(`Phase 9 (smart_rename) hata: ${err.message}`);
    phaseStats["smart_rename"] = { error: err.message, duration_ms: Date.now() - phase9Start };
  }
}

// ---------- Phase 10: Semantic Renaming (Deep Usage-Based) ----------
// Phase 9'un basit pattern matching'ini asarak, Babel scope + binding analizi ile
// her minified identifier'in kullanim baglamini analiz eder.
// 12 kural motoru: api_call, method_chain, property_access, comparison, typeof,
// error_handling, callback, well_known_apis, iterator, destructuring, arithmetic, constructor
if (requestedPhases.includes(10)) {
  const phase10Start = Date.now();
  let semanticRenameCount = 0;
  const semanticRuleHits = Object.create(null);

  function _isMinified10(name) {
    if (name.length <= 2) return true;
    return false;
  }

  function _makeUnique10(scope, baseName) {
    if (_RESERVED.has(baseName)) baseName = baseName + "Val";
    if (!scope.hasBinding(baseName)) {
      let parent = scope.parent;
      let conflict = false;
      while (parent) {
        if (parent.hasOwnBinding(baseName)) { conflict = true; break; }
        parent = parent.parent;
      }
      if (!conflict) return baseName;
    }
    for (let i = 2; i < 100; i++) {
      const candidate = `${baseName}${i}`;
      if (!scope.hasBinding(candidate)) {
        let parent = scope.parent;
        let conflict = false;
        while (parent) {
          if (parent.hasOwnBinding(candidate)) { conflict = true; break; }
          parent = parent.parent;
        }
        if (!conflict) return candidate;
      }
    }
    return null;
  }

  function _collectUsage10(binding) {
    const info = {
      methodCalls: new Set(), propertyReads: new Set(), propertyWrites: new Set(),
      calledAs: false, comparedWith: [], typeofChecks: [],
      usedInForOf: false, usedAsForOfIterator: false, destructured: false,
      indexAccessed: false, arithmeticOperand: false, stringConcatenated: false,
      thrownAsError: false, usedInNew: false, usedAsKey: false,
    };
    if (!binding?.referencePaths) return info;

    for (const ref of binding.referencePaths) {
      const p = ref.parent;
      const pp = ref.parentPath;
      if (!p) continue;

      if (t.isMemberExpression(p) && p.object === ref.node && !p.computed) {
        const prop = p.property?.name;
        if (prop) {
          const gp = pp?.parent;
          if (t.isCallExpression(gp) && gp.callee === p) info.methodCalls.add(prop);
          else info.propertyReads.add(prop);
        }
      }
      if (t.isMemberExpression(p) && p.object === ref.node && p.computed) {
        info.indexAccessed = true;
        if (t.isStringLiteral(p.property)) info.propertyReads.add(p.property.value);
      }
      if (t.isCallExpression(p) && p.callee === ref.node) info.calledAs = true;
      if (t.isBinaryExpression(p) && (p.operator === "===" || p.operator === "==")) {
        const other = p.left === ref.node ? p.right : p.left;
        if (t.isStringLiteral(other)) info.comparedWith.push(other.value);
        if (t.isNumericLiteral(other)) info.arithmeticOperand = true;
      }
      if (t.isUnaryExpression(p) && p.operator === "typeof") {
        const gp = pp?.parent;
        if (t.isBinaryExpression(gp)) {
          const other = gp.left === p ? gp.right : gp.left;
          if (t.isStringLiteral(other)) info.typeofChecks.push(other.value);
        }
      }
      if (t.isForOfStatement(p) && p.right === ref.node) info.usedInForOf = true;
      if (t.isVariableDeclarator(p) && p.init === ref.node && t.isObjectPattern(p.id)) info.destructured = true;
      if (t.isThrowStatement(p) && p.argument === ref.node) info.thrownAsError = true;
      if (t.isNewExpression(p) && p.callee === ref.node) info.usedInNew = true;
      if (t.isBinaryExpression(p) && ["+","-","*","/","%"].includes(p.operator)) {
        const other = p.left === ref.node ? p.right : p.left;
        if (t.isNumericLiteral(other)) info.arithmeticOperand = true;
        if (t.isStringLiteral(other) && p.operator === "+") info.stringConcatenated = true;
      }
      if (t.isAssignmentExpression(p) && t.isMemberExpression(p.left) && p.left.object === ref.node && !p.left.computed) {
        if (p.left.property?.name) info.propertyWrites.add(p.left.property.name);
      }
    }
    // Binding definition context
    if (binding.path) {
      try {
        const bp = binding.path.parentPath;
        const bgp = bp?.parentPath;
        if (bgp && t.isForOfStatement(bgp.node)) info.usedAsForOfIterator = true;
        if (bgp && t.isForInStatement(bgp.node)) info.usedAsKey = true;
      } catch (_) {}
    }
    return info;
  }

  // Minimal kural motoru (Phase 10 icin kompakt)
  function _inferName10(info, binding) {
    const mc = info.methodCalls;
    const pr = info.propertyReads;
    const pw = info.propertyWrites;
    const allProps = new Set([...pr, ...pw]);

    // Assignment source (require, new, literal)
    const initNode = binding?.path?.node?.init;
    if (initNode) {
      if (t.isCallExpression(initNode) && t.isIdentifier(initNode.callee) &&
          initNode.callee.name === "require" && initNode.arguments?.[0] &&
          t.isStringLiteral(initNode.arguments[0])) {
        const mod = initNode.arguments[0].value.replace(/^node:/, "");
        const knownMods = { fs:"fs", path:"path", os:"os", http:"http", https:"https",
          url:"urlModule", crypto:"crypto", events:"events", stream:"stream",
          util:"util", child_process:"childProcess", net:"net", dns:"dns",
          tls:"tls", zlib:"zlib", buffer:"bufferModule", http2:"http2" };
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
        if (cn === "RegExp") return { name: "regex", confidence: 0.80, rule: "new_regex" };
        if (cn === "Date") return { name: "date", confidence: 0.80, rule: "new_date" };
        if (cn === "URL") return { name: "url", confidence: 0.85, rule: "new_url" };
      }
      if (t.isArrayExpression(initNode)) return { name: "items", confidence: 0.60, rule: "array_literal" };
      if (t.isRegExpLiteral(initNode)) return { name: "pattern", confidence: 0.75, rule: "regex_literal" };
    }

    // Error pattern
    if (pr.has("message") && (pr.has("stack") || pr.has("code"))) return { name: "error", confidence: 0.90, rule: "error_props" };
    if (info.thrownAsError) return { name: "error", confidence: 0.85, rule: "throw_target" };

    // String methods
    const strMethods = ["split","trim","replace","replaceAll","match","indexOf","startsWith","endsWith","toLowerCase","toUpperCase","substring","charAt"];
    const strScore = strMethods.filter(m => mc.has(m)).length;
    if (strScore >= 2) return { name: "str", confidence: 0.85, rule: "string_api" };
    if (mc.has("split")) return { name: "input", confidence: 0.75, rule: "string_api" };

    // Array methods
    const arrMethods = ["push","pop","shift","unshift","map","filter","reduce","forEach","find","some","every","sort","slice","splice","concat","join","includes","indexOf"];
    const arrScore = arrMethods.filter(m => mc.has(m)).length;
    if (arrScore >= 2) return { name: "items", confidence: 0.85, rule: "array_api" };
    if (mc.has("push") || mc.has("pop")) return { name: "items", confidence: 0.80, rule: "array_api" };
    if (mc.has("map") || mc.has("filter") || mc.has("forEach")) return { name: "items", confidence: 0.75, rule: "array_api" };

    // Map/Set
    if (mc.has("get") && mc.has("set") && mc.has("has")) return { name: "cache", confidence: 0.80, rule: "map_api" };
    if (mc.has("add") && mc.has("has")) return { name: "seen", confidence: 0.70, rule: "set_api" };

    // Promise
    if (mc.has("then") && mc.has("catch")) return { name: "promise", confidence: 0.85, rule: "promise_api" };
    if (mc.has("then")) return { name: "promise", confidence: 0.70, rule: "promise_api" };

    // Stream/EventEmitter
    if (mc.has("pipe")) return { name: "stream", confidence: 0.75, rule: "stream_api" };
    if (mc.has("on") && mc.has("emit")) return { name: "emitter", confidence: 0.80, rule: "emitter_api" };

    // fs/path/crypto
    const fsMethods = ["readFileSync","writeFileSync","readFile","writeFile","existsSync","mkdirSync","readdirSync","statSync"];
    if (fsMethods.some(m => mc.has(m))) return { name: "fs", confidence: 0.90, rule: "fs_api" };
    if (mc.has("resolve") && mc.has("join")) return { name: "path", confidence: 0.85, rule: "path_api" };
    if (mc.has("createHash") || mc.has("randomBytes")) return { name: "crypto", confidence: 0.90, rule: "crypto_api" };

    // HTTP request/response
    const reqProps = ["body","params","query","headers","method","url"];
    if (reqProps.filter(p => allProps.has(p)).length >= 2) return { name: "request", confidence: 0.80, rule: "http_req" };
    const resMethods = ["send","json","status","render","redirect"];
    if (resMethods.filter(m => mc.has(m)).length >= 2) return { name: "response", confidence: 0.85, rule: "http_res" };

    // DOM
    const domProps = ["innerHTML","textContent","className","style","children","parentNode","tagName"];
    if (domProps.filter(p => allProps.has(p)).length >= 2) return { name: "element", confidence: 0.85, rule: "dom_api" };
    if (mc.has("createElement") || mc.has("querySelector")) return { name: "document", confidence: 0.85, rule: "dom_api" };

    // typeof check
    if (info.typeofChecks.length > 0) {
      const types = new Set(info.typeofChecks);
      if (types.has("function")) return { name: "fn", confidence: 0.75, rule: "typeof_fn" };
      if (types.has("string")) return { name: "str", confidence: 0.70, rule: "typeof_str" };
      if (types.has("number")) return { name: "num", confidence: 0.70, rule: "typeof_num" };
      if (types.has("object")) return { name: "obj", confidence: 0.55, rule: "typeof_obj" };
    }

    // Callback pattern
    if (info.calledAs && info.typeofChecks.includes("function")) return { name: "callback", confidence: 0.80, rule: "callback" };
    if (info.calledAs && !info.usedInNew && mc.size === 0 && pr.size === 0) return { name: "fn", confidence: 0.55, rule: "callback" };

    // Iterator
    if (info.usedAsForOfIterator) return { name: "item", confidence: 0.80, rule: "for_of_item" };
    if (info.usedAsKey) return { name: "key", confidence: 0.80, rule: "for_in_key" };
    if (info.usedInForOf) return { name: "items", confidence: 0.75, rule: "iterable" };

    // Comparison (>= 3 string karsilastirmasi = type/kind)
    if (info.comparedWith.length >= 3) return { name: "kind", confidence: 0.70, rule: "multi_compare" };
    const httpMethods = ["GET","POST","PUT","DELETE","PATCH"];
    if (info.comparedWith.some(v => httpMethods.includes(v))) return { name: "method", confidence: 0.80, rule: "http_method" };

    // Destructuring
    if (info.destructured) return { name: "options", confidence: 0.60, rule: "destructured" };

    // Index access
    if (info.indexAccessed && allProps.size === 0 && mc.size === 0) return { name: "source", confidence: 0.50, rule: "index_access" };

    // Arithmetic
    if (info.arithmeticOperand && !info.stringConcatenated) return { name: "num", confidence: 0.55, rule: "arithmetic" };
    if (info.stringConcatenated && !info.arithmeticOperand) return { name: "str", confidence: 0.50, rule: "string_concat" };

    // Constructor
    if (info.usedInNew) return { name: "Ctor", confidence: 0.70, rule: "new_call" };

    // Config/options (cok property, az method)
    if (allProps.size >= 4 && mc.size <= 1 && !info.calledAs) return { name: "options", confidence: 0.50, rule: "config_obj" };

    // Prototype
    if (pr.has("prototype")) return { name: "ctor", confidence: 0.70, rule: "prototype" };

    return null;
  }

  // Parametre pozisyon bazli cikarim
  function _inferParam10(funcPath, idx, count, bodyStr) {
    const reqInd = [".body",".params",".query",".headers",".method"];
    const resInd = [".send(",".json(",".status(",".render(",".redirect("];
    const reqS = reqInd.filter(i => bodyStr.includes(i)).length;
    const resS = resInd.filter(i => bodyStr.includes(i)).length;
    if (reqS >= 1 && resS >= 1) {
      if (count === 4) return ["error","request","response","next"][idx];
      if (count >= 2 && count <= 3) return ["request","response","next"][idx];
    }
    if (count >= 2 && count <= 3) {
      if (bodyStr.includes(".exports") && bodyStr.includes("module.exports")) {
        if (idx === 0) return "exports";
        if (idx === 1) return "module";
        if (idx === 2) return "require";
      }
      if (idx === 0 && bodyStr.includes(".exports")) return "exports";
    }
    // Array callback pozisyonu
    if (t.isCallExpression(funcPath.parent) && t.isMemberExpression(funcPath.parent.callee)) {
      const mn = funcPath.parent.callee.property?.name;
      const iterM = ["map","filter","forEach","find","findIndex","some","every","flatMap"];
      if (iterM.includes(mn)) {
        if (idx === 0) return "item";
        if (idx === 1) return "index";
        if (idx === 2) return "array";
      }
      if (mn === "reduce") {
        if (idx === 0) return "acc";
        if (idx === 1) return "item";
      }
      if (mn === "sort" && count === 2) return idx === 0 ? "left" : "right";
      if ((mn === "on" || mn === "once") && funcPath.parent.arguments?.[0] && t.isStringLiteral(funcPath.parent.arguments[0])) {
        const ev = funcPath.parent.arguments[0].value;
        if (ev === "error" && idx === 0) return "error";
        if (ev === "data" && idx === 0) return "chunk";
        if (ev === "message" && idx === 0) return "message";
        if (ev === "connection" && idx === 0) return "socket";
        if (idx === 0) return "eventData";
      }
    }
    return null;
  }

  try {
    const minConfidence10 = 0.3;

    traverse(ast, {
      CatchClause(path) {
        const param = path.node.param;
        if (!param || !t.isIdentifier(param) || !_isMinified10(param.name)) return;
        const nn = _makeUnique10(path.scope, "error");
        if (nn && nn !== param.name) {
          try { path.scope.rename(param.name, nn); semanticRenameCount++; semanticRuleHits["catch_clause"] = (semanticRuleHits["catch_clause"]||0)+1; } catch(_){}
        }
      },
      "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression"(path) {
        const params = path.node.params;
        if (params.length === 0) return;
        let bodyStr = "";
        try { const {code} = generate(path.node.body, {compact:true}); bodyStr = code.length > 3000 ? code.slice(0,3000) : code; } catch(_){}

        for (let i = 0; i < params.length; i++) {
          const p = params[i];
          if (!t.isIdentifier(p) || !_isMinified10(p.name)) continue;
          const binding = path.scope.getBinding(p.name);
          if (!binding) continue;

          let best = null;
          const posName = _inferParam10(path, i, params.length, bodyStr);
          if (posName) best = { name: posName, confidence: 0.80, rule: "param_position" };

          const info = _collectUsage10(binding);
          const usageResult = _inferName10(info, binding);
          if (usageResult && (!best || usageResult.confidence > best.confidence)) best = usageResult;

          if (!best || best.confidence < minConfidence10) continue;
          const nn = _makeUnique10(path.scope, best.name);
          if (!nn || nn === p.name) continue;
          try { path.scope.rename(p.name, nn); semanticRenameCount++; semanticRuleHits[best.rule] = (semanticRuleHits[best.rule]||0)+1; } catch(_){}
        }
      },
      VariableDeclarator(path) {
        const id = path.node.id;
        if (!t.isIdentifier(id) || !_isMinified10(id.name)) return;
        const binding = path.scope.getBinding(id.name);
        if (!binding) return;

        let best = null;
        const info = _collectUsage10(binding);
        const initResult = (() => {
          const init = binding.path?.node?.init;
          if (!init) return null;
          if (t.isCallExpression(init) && t.isIdentifier(init.callee) && init.callee.name === "require" && init.arguments?.[0] && t.isStringLiteral(init.arguments[0])) {
            const mod = init.arguments[0].value.replace(/^node:/, "");
            const km = { fs:"fs",path:"path",os:"os",http:"http",https:"https",crypto:"crypto",http2:"http2",util:"util",events:"events",stream:"stream",child_process:"childProcess" };
            if (km[mod]) return { name: km[mod], confidence: 0.95, rule: "require_module" };
          }
          if (t.isNewExpression(init) && t.isIdentifier(init.callee)) {
            const cn = init.callee.name;
            if (cn.includes("Error")) return { name: "error", confidence: 0.90, rule: "new_error" };
            if (cn === "Map") return { name: "map", confidence: 0.85, rule: "new_collection" };
            if (cn === "Set") return { name: "set", confidence: 0.85, rule: "new_collection" };
          }
          if (t.isArrayExpression(init)) return { name: "items", confidence: 0.60, rule: "array_literal" };
          if (t.isRegExpLiteral(init)) return { name: "pattern", confidence: 0.75, rule: "regex_literal" };
          return null;
        })();
        if (initResult) best = initResult;

        const usageResult = _inferName10(info, binding);
        if (usageResult && (!best || usageResult.confidence > best.confidence)) best = usageResult;

        if (!best || best.confidence < minConfidence10) return;
        const nn = _makeUnique10(path.scope, best.name);
        if (!nn || nn === id.name) return;
        try { path.scope.rename(id.name, nn); semanticRenameCount++; semanticRuleHits[best.rule] = (semanticRuleHits[best.rule]||0)+1; } catch(_){}
      },
    });

    phaseStats["semantic_rename"] = {
      transforms: semanticRenameCount,
      rule_hits: semanticRuleHits,
      duration_ms: Date.now() - phase10Start,
    };
    phasesCompleted.push(10);
  } catch (err) {
    errors.push(`Phase 10 (semantic_rename) hata: ${err.message}`);
    phaseStats["semantic_rename"] = { error: err.message, duration_ms: Date.now() - phase10Start };
  }
}

// ---------- Generate Output ----------
try {
  const { code } = generate(ast, {
    comments: true,
    compact: false,
    concise: false,
    jsescOption: { minimal: true },
  });

  // Output dizini kontrol
  const outDir = dirname(outputPath);
  try {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(outDir, { recursive: true });
  } catch (_) {}

  writeFileSync(outputPath, code, "utf-8");

  const outputSize = statSync(outputPath).size;

  emit({
    success: true,
    phases_completed: phasesCompleted,
    stats: {
      input_size: fileSize,
      output_size: outputSize,
      input_lines: source.split("\n").length,
      output_lines: code.split("\n").length,
      phases: phaseStats,
    },
    errors,
  });
} catch (err) {
  emit({
    success: false,
    phases_completed: phasesCompleted,
    stats: { phases: phaseStats },
    errors: [...errors, `Generate hatasi: ${err.message}`],
  });
}
