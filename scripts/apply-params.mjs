#!/usr/bin/env node
/**
 * apply-params.mjs -- param-recovery.mjs ciktisindaki isimleri kodda uygula
 *
 * Black Widow v1.0 -- Karadul
 *
 * param-recovery.mjs'in uretiigi JSON'daki recovery mapping'lerini
 * kaynak koda uygular. Sadece fonksiyon PARAMETRELERINI rename eder
 * (degiskenleri degil -- o is apply-names.mjs'in isi).
 *
 * FARKLAR (apply-names.mjs ile):
 *   - apply-names.mjs: degisken isimlendirmesi (scope_renames veya flat)
 *   - apply-params.mjs: PARAMETRE isimlendirmesi (funcKey::paramIdx mapping)
 *
 * Calisma prensibi:
 *   1. Recovery JSON'dan funcKey->paramIdx mapping'lerini oku
 *   2. AST'yi traverse ederek her fonksiyonu bul
 *   3. FuncKey eslestir: className::methodName veya functionName veya anon@line
 *   4. Eslesn fonksiyonun parametrelerini rename et
 *   5. Parametre body icinde kullanildigi yerleri de rename et (deep walk)
 *
 * noScope mod: 6MB+ dosyalarda Babel scope API patlar, noScope kullaniyoruz.
 * Bu yuzden body icindeki identifier referanslarini elle izliyoruz.
 *
 * Kullanim:
 *   node --max-old-space-size=8192 apply-params.mjs <input.js> <params.json> <output.js>
 *     [--min-confidence 0.6]
 *     [--dry-run]
 *
 * Cikti (stdout JSON):
 *   {
 *     "success": true,
 *     "renamed": 3521,
 *     "skipped": 120,
 *     "functions_touched": 812,
 *     "mappings": {"constructor::0": {"from": "e", "to": "factory"}, ...},
 *     "output": "/path/to/output.js"
 *   }
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
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

const MIN_CONFIDENCE = parseFloat(flags.get("--min-confidence") || "0.6");
const DRY_RUN = flags.has("--dry-run");

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

if (positional.length < 3) {
  emit({
    success: false,
    renamed: 0,
    skipped: 0,
    functions_touched: 0,
    mappings: {},
    errors: [
      "Kullanim: node apply-params.mjs <input.js> <params.json> <output.js> [--min-confidence 0.6] [--dry-run]",
    ],
  });
  process.exit(1);
}

const inputPath = resolve(positional[0]);
const paramsPath = resolve(positional[1]);
const outputPath = resolve(positional[2]);

// ---------- Dosyalari oku ----------
let source, paramsData;

try {
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  emit({ success: false, renamed: 0, skipped: 0, functions_touched: 0, mappings: {}, errors: [`JS dosyasi okunamadi: ${err.message}`] });
  process.exit(1);
}

try {
  paramsData = JSON.parse(readFileSync(paramsPath, "utf-8"));
} catch (err) {
  emit({ success: false, renamed: 0, skipped: 0, functions_touched: 0, mappings: {}, errors: [`Params JSON okunamadi: ${err.message}`] });
  process.exit(1);
}

console.error(`[apply-params] Input: ${inputPath} (${(source.length / 1e6).toFixed(1)}MB)`);

const errors = [];

// ---------- Recovery mapping'lerini hazirla ----------
// paramsData.recoveries: { "funcKey::paramIdx": { original, recovered, strategy, confidence } }
const recoveries = paramsData.recoveries || {};

// funcKey -> [{ paramIdx, original, recovered, confidence }] seklinde grupla
const funcRecoveries = new Map();
let skipped = 0;

for (const [compositeKey, info] of Object.entries(recoveries)) {
  // composite key: "funcKey::paramIdx" -- SON :: ayirici paramIdx'dir
  const lastSep = compositeKey.lastIndexOf("::");
  if (lastSep < 0) {
    skipped++;
    continue;
  }
  const funcKey = compositeKey.substring(0, lastSep);
  const paramIdx = parseInt(compositeKey.substring(lastSep + 2), 10);
  if (isNaN(paramIdx)) {
    skipped++;
    continue;
  }

  // Confidence filtresi
  if ((info.confidence || 0) < MIN_CONFIDENCE) {
    skipped++;
    continue;
  }

  // Tek harfli orijinal kontrol
  const original = info.original || info.originalName;
  const recovered = info.recovered || info.recoveredName;
  if (!original || !recovered || original === recovered) {
    skipped++;
    continue;
  }

  // Sadece tek-harfli (veya tek harf + rakam) parametreleri rename et
  if (!/^[a-z][0-9]?$/i.test(original)) {
    skipped++;
    continue;
  }

  if (!funcRecoveries.has(funcKey)) {
    funcRecoveries.set(funcKey, []);
  }
  funcRecoveries.get(funcKey).push({ paramIdx, original, recovered, confidence: info.confidence || 0 });
}

console.error(`[apply-params] ${funcRecoveries.size} fonksiyon, ${skipped} skipped (confidence < ${MIN_CONFIDENCE} veya invalid)`);

if (funcRecoveries.size === 0) {
  // Hicbir recovery yok -- girdiyi oldugi gibi kopyala
  if (!DRY_RUN) {
    writeFileSync(outputPath, source, "utf-8");
  }
  emit({
    success: true,
    renamed: 0,
    skipped,
    functions_touched: 0,
    mappings: {},
    output: DRY_RUN ? null : outputPath,
    dry_run: DRY_RUN,
  });
  process.exit(0);
}

// ---------- Parse ----------
let ast;
try {
  ast = parse(source, {
    sourceType: "unambiguous",
    allowReturnOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowSuperOutsideMethod: true,
    plugins: [
      "jsx", "typescript", "decorators-legacy", "classProperties",
      "classPrivateProperties", "classPrivateMethods", "optionalChaining",
      "nullishCoalescingOperator", "dynamicImport", "logicalAssignment",
      "numericSeparator", "optionalCatchBinding", "throwExpressions",
      "topLevelAwait", "exportDefaultFrom", "exportNamespaceFrom",
      "asyncGenerators", "objectRestSpread", "importMeta", "importAssertions",
    ],
    errorRecovery: true,
  });
} catch (err) {
  emit({
    success: false, renamed: 0, skipped, functions_touched: 0, mappings: {},
    errors: [`Parse hatasi: ${err.message}`],
  });
  process.exit(0);
}

console.error(`[apply-params] AST parsed. Applying param renames...`);

// =====================================================================
// YARDIMCI FONKSIYONLAR
// =====================================================================

/** Parametre node'undan gercek ismi al */
function getParamName(paramNode) {
  if (t.isIdentifier(paramNode)) return paramNode.name;
  if (t.isAssignmentPattern(paramNode)) return getParamName(paramNode.left);
  if (t.isRestElement(paramNode)) return getParamName(paramNode.argument);
  return null;
}

/** Parametre node'unu set et (identifier, default, rest destegi) */
function setParamName(paramNode, newName) {
  if (t.isIdentifier(paramNode)) {
    paramNode.name = newName;
    return true;
  }
  if (t.isAssignmentPattern(paramNode)) {
    return setParamName(paramNode.left, newName);
  }
  if (t.isRestElement(paramNode)) {
    return setParamName(paramNode.argument, newName);
  }
  return false;
}

/** Fonksiyon key'i olustur (param-recovery.mjs ile ayni format) */
function makeFuncKey(node, parentNode, grandparentNode) {
  let className = null;
  let methodName = null;
  const line = node.loc?.start?.line || 0;

  if (t.isClassMethod(node) || t.isObjectMethod(node)) {
    methodName = t.isIdentifier(node.key) ? node.key.name :
      (t.isStringLiteral(node.key) ? node.key.value : "computed");
    // Ust class
    if (t.isClassBody(parentNode) && grandparentNode && t.isIdentifier(grandparentNode.id)) {
      className = grandparentNode.id.name;
    }
  } else if (t.isFunctionDeclaration(node) && node.id) {
    methodName = node.id.name;
  } else if (t.isFunctionExpression(node) && node.id) {
    methodName = node.id.name;
  } else {
    // Arrow veya anonim: parent'a bak
    if (t.isVariableDeclarator(parentNode) && t.isIdentifier(parentNode.id)) {
      methodName = parentNode.id.name;
    } else if (t.isAssignmentExpression(parentNode) && t.isIdentifier(parentNode.left)) {
      methodName = parentNode.left.name;
    } else if ((t.isProperty(parentNode) || t.isObjectProperty(parentNode)) && t.isIdentifier(parentNode.key)) {
      methodName = parentNode.key.name;
    }
  }

  if (className && methodName) return `${className}::${methodName}`;
  if (methodName) return methodName;
  return `anon@${line}`;
}

/**
 * Body icindeki identifier referanslarini rename et (deep walk).
 * noScope modda Babel scope API kullanamiyoruz, bu yuzden
 * body AST'sini recursive dolasip oldName identifier'larini buluyoruz.
 *
 * ONEMLI: Ic fonksiyonlara GIRMIYORUZ cunku parametre isimleri
 * shadow olabilir. Ayrica object property key'lerini ve member
 * expression property'lerini rename ETMIYORUZ.
 */
function renameInBody(bodyNode, oldName, newName, maxDepth = 20) {
  let count = 0;

  function walk(node, depth) {
    if (!node || typeof node !== "object" || depth > maxDepth) return;

    if (Array.isArray(node)) {
      for (const child of node) walk(child, depth);
      return;
    }

    // Identifier bulundu
    if (node.type === "Identifier" && node.name === oldName) {
      // Bu identifier'in rename edilip edilmemesi gerektigini kontrol et
      // Parent bilgisi yok (noScope), bu yuzden basit kontrol:
      // -- Sadece isim eslesmesi yeterli, apply-names.mjs ayni seyi yapiyor
      node.name = newName;
      count++;
    }

    // Cocuk node'lari dolas
    for (const key of Object.keys(node)) {
      // Performans: loc, comments gibi metadata key'lerini atla
      if (key === "start" || key === "end" || key === "loc" || key === "type" ||
          key === "leadingComments" || key === "trailingComments" || key === "extra") continue;

      const child = node[key];
      if (!child || typeof child !== "object") continue;

      // Ic fonksiyon tanimina GIRME -- parametre scope degisir
      if (child.type === "FunctionExpression" ||
          child.type === "ArrowFunctionExpression" ||
          child.type === "FunctionDeclaration" ||
          child.type === "ClassMethod" ||
          child.type === "ObjectMethod") {
        // Ic fonksiyonun PARAMETRELERINDE ayni isim var mi kontrol et
        // Varsa shadow -- bu dalda rename etmemeliyiz
        const innerParams = child.params || [];
        const innerParamNames = innerParams.map(p => getParamName(p)).filter(Boolean);
        if (innerParamNames.includes(oldName)) {
          // Shadow: bu ic fonksiyona girme
          continue;
        }
        // Shadow yok ama body'ye girmeliyiz (ic fonksiyonun body'si parametreyi kullanabilir)
        // ANCAK: ic fonksiyonun body'sine girmek tehlikeli -- ayni isimli
        // lokal degisken olabilir. Guvenli tarafta kaliyoruz ve GIRMIYORUZ.
        continue;
      }

      walk(child, depth + 1);
    }
  }

  walk(bodyNode, 0);
  return count;
}

/**
 * Body icindeki bir identifier'in member expression property veya
 * object property key olarak kullanilip kullanilmadigini kontrol eder.
 *
 * Bu fonksiyon renameInBody'de KULLANILMIYOR cunku noScope modda
 * parent bilgisi yok. Bunun yerine renameInBody tum identifier'leri
 * rename eder -- bu obfuscated tek-harfli parametreler icin guvenli.
 *
 * Mantik: Eger parametre ismi "e" ise, "e" identifier'i kodda sadece
 * parametre referansi olarak kullanilir. Bir property'nin ismi "e" olmaz
 * (obfuscator property isimlerini degistirmez). Tek sorun computed
 * member expression'lar (obj[e]) ama onlar da parametre referansidir.
 */

// =====================================================================
// ANA TRAVERSE: Fonksiyon parametre rename
// =====================================================================

const appliedMappings = {};
let renameCount = 0;
let functionsTouched = 0;

try {
  traverse(ast, {
    noScope: true,

    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ObjectMethod|ClassMethod"(path) {
      const node = path.node;
      const params = node.params || [];
      if (params.length === 0) return;

      // funcKey olustur
      const parentNode = path.parent;
      const grandparentNode = path.parentPath?.parent;
      const funcKey = makeFuncKey(node, parentNode, grandparentNode);

      // Bu fonksiyon icin recovery var mi?
      const recoveryList = funcRecoveries.get(funcKey);
      if (!recoveryList || recoveryList.length === 0) return;

      // Shadow kontrolu: ayni fonksiyonda birden fazla parametre
      // ayni isme rename edilmemeli
      const usedNewNames = new Set();
      // Mevcut parametre isimlerini topla
      const existingNames = new Set(params.map(p => getParamName(p)).filter(Boolean));

      let touched = false;

      for (const rec of recoveryList) {
        if (rec.paramIdx >= params.length) continue;

        const paramNode = params[rec.paramIdx];
        const currentName = getParamName(paramNode);

        // Orijinal isim eslesmiyor -- atla
        if (currentName !== rec.original) continue;

        let newName = rec.recovered;

        // Shadow kontrolu
        if (usedNewNames.has(newName) || (existingNames.has(newName) && newName !== currentName)) {
          // Suffix ekle
          let resolved = false;
          for (let suffix = 1; suffix <= 5; suffix++) {
            const suffixed = `${newName}_${suffix}`;
            if (!usedNewNames.has(suffixed) && !existingNames.has(suffixed)) {
              newName = suffixed;
              resolved = true;
              break;
            }
          }
          if (!resolved) {
            skipped++;
            continue;
          }
        }

        // Parametre node'unu rename et
        if (setParamName(paramNode, newName)) {
          usedNewNames.add(newName);
          existingNames.add(newName);
          existingNames.delete(currentName);

          // Body icindeki referanslari rename et
          const bodyRenames = renameInBody(node.body, currentName, newName);

          renameCount += 1 + bodyRenames; // parametre + body referanslari
          touched = true;

          appliedMappings[`${funcKey}::${rec.paramIdx}`] = {
            from: currentName,
            to: newName,
            confidence: rec.confidence,
            body_refs: bodyRenames,
          };
        }
      }

      if (touched) functionsTouched++;
    },
  });
} catch (err) {
  errors.push(`Traverse hatasi: ${err.message}`);
  console.error(`[apply-params] Traverse hatasi: ${err.message}`);
}

console.error(`[apply-params] Sonuc: ${renameCount} rename, ${functionsTouched} fonksiyon, ${skipped} skipped`);

// ---------- Cikti ----------
if (!DRY_RUN) {
  try {
    const { code } = generate(ast, {
      comments: true,
      compact: false,
      concise: false,
      retainLines: true,
    });
    writeFileSync(outputPath, code, "utf-8");
  } catch (err) {
    emit({
      success: false,
      renamed: renameCount,
      skipped,
      functions_touched: functionsTouched,
      mappings: appliedMappings,
      errors: [...errors, `Code generation hatasi: ${err.message}`],
    });
    process.exit(0);
  }
}

emit({
  success: true,
  renamed: renameCount,
  skipped,
  functions_touched: functionsTouched,
  mappings: appliedMappings,
  output: DRY_RUN ? null : outputPath,
  dry_run: DRY_RUN,
  min_confidence: MIN_CONFIDENCE,
  errors,
});
