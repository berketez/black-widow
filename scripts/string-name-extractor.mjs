#!/usr/bin/env node
/**
 * string-name-extractor.mjs -- Validation String'lerinden Parametre Ismi Cikarma
 *
 * Black Widow v1.0 -- Karadul
 *
 * Electron IPC handler'larindaki validation/error string'lerinden
 * GERCEK parametre isimlerini cikarir. Bu isimler orijinal TypeScript
 * kaynak kodundaki isimlerdir -- minifier bunlari string icinde biraktigi
 * icin %100 dogru.
 *
 * Desteklenen Pattern'ler:
 *   P1: 'Argument "NAME" at position N to method "METHOD" in interface "IFACE"'
 *   P2: 'Argument "NAME" at position N to event "EVENT" in interface "IFACE"'
 *   P3: 'Result from method "METHOD" in interface "IFACE"'
 *   P4: 'Incoming "METHOD" call on interface "IFACE"' (method ismi)
 *   P5: '"NAME" must be a TYPE' (type assertion)
 *   P6: '"NAME" must be a string/number' (alphabet/maxline etc.)
 *   P7: method("METHOD_NAME") cagrilari (impl.METHOD_NAME pattern'i)
 *   P8: console.warn/error icindeki 'expected TYPE for NAME' ipuclari
 *   P9: assert/throw icindeki 'Missing required: NAME'
 *   P10: Stack trace fonksiyon isimleri (at ClassName.methodName)
 *
 * Ayrica her validation satirindaki throw ifadesinin ONUNDE hangi degiskenin
 * kontrol edildigini tespit eder (typeof X, !validator(X) gibi).
 *
 * Kullanim:
 *   node string-name-extractor.mjs <input.js> <output.json>
 *
 * Cikti JSON:
 * {
 *   "extractions": [
 *     {
 *       "line": 4620,
 *       "pattern": "P1",
 *       "param_name": "promptText",
 *       "position": 0,
 *       "method": "requestDismiss",
 *       "interface": "QuickWindow",
 *       "obfuscated_var": "idx",
 *       "type_hint": "string|null",
 *       "confidence": 0.95
 *     }
 *   ],
 *   "param_map": { "idx": ["promptText", "payload", ...], "str": ["contentHeight", ...] },
 *   "method_registry": { "QuickWindow": { "requestDismiss": [...], ... } },
 *   "stats": { ... }
 * }
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

// ---------- CLI ----------
const args = process.argv.slice(2);
if (args.length < 2) {
  console.error(
    "Kullanim: node string-name-extractor.mjs <input.js> <output.json>"
  );
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputPath = resolve(args[1]);

let source;
try {
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  console.error(`Dosya okunamadi: ${err.message}`);
  process.exit(1);
}

const lines = source.split("\n");

// =====================================================================
// PATTERN TANIMLARI
// =====================================================================

// P1: Argument "NAME" at position N to method "METHOD" in interface "IFACE"
const P1_REGEX =
  /Argument "([^"]+)" at position (\d+) to method "([^"]+)" in interface "([^"]+)"/g;

// P2: Argument "NAME" at position N to event "EVENT" in interface "IFACE"
const P2_REGEX =
  /Argument "([^"]+)" at position (\d+) to event "([^"]+)" in interface "([^"]+)"/g;

// P3: Result from method "METHOD" in interface "IFACE"
const P3_REGEX =
  /Result from method "([^"]+)" in interface "([^"]+)"/g;

// P4: Incoming "METHOD" call on interface "IFACE"
const P4_REGEX =
  /Incoming "([^"]+)" call on interface "([^"]+)"/g;

// P5: "NAME" must be a TYPE (type assertion in throws)
const P5_REGEX =
  /"([a-zA-Z_]\w*)" must be a ([a-z]+)/g;

// P6: Generic 'Expected TYPE for argument "NAME"'
const P6_REGEX =
  /Expected\s+(\w+)\s+for\s+argument\s+"([^"]+)"/g;

// P7: elem.METHOD_NAME(...) veya impl.METHOD_NAME(...) pattern'i
// Validation satirindaki gercek method cagrisi
const P7_REGEX =
  /await\s+\w+\.([a-zA-Z_]\w+)\s*\(/g;

// P8: 'Invalid value for "NAME"'
const P8_REGEX =
  /Invalid value for "([^"]+)"/g;

// P9: 'Missing required argument: NAME' veya 'Missing required: NAME'
const P9_REGEX =
  /Missing required(?:\s+argument)?:\s*"?([a-zA-Z_]\w*)"?/g;

// P10: method "METHOD_NAME" icindeki fonksiyon isimleri (interface'siz)
const P10_REGEX =
  /method "([a-zA-Z_]\w+)"/g;

// =====================================================================
// OBFUSCATED DEGISKEN TESPITI
// =====================================================================

/**
 * Bir validation satirinda throw'dan ONCE hangi degiskenin kontrol
 * edildigini bulur.
 *
 * Ornekler:
 *   if (typeof idx != "string") throw new Error(...)   => idx, type_hint=string
 *   if (!M9e(idx)) throw new Error(...)                => idx, validator=M9e
 *   if (!(idx === null || typeof idx == "string"))      => idx, type_hint=string|null
 *   if (!(Array.isArray(idx) && ...))                   => idx, type_hint=array
 */
function extractObfuscatedVar(lineText, paramPosition) {
  // Strategy 1: typeof VAR != "TYPE" pattern'i
  const typeofMatch = lineText.match(
    /typeof\s+(\w+)\s*(!==?|===?)\s*"(\w+)"/
  );
  if (typeofMatch) {
    return {
      obfuscated_var: typeofMatch[1],
      type_hint: typeofMatch[3],
    };
  }

  // Strategy 2: !(VAR === null || typeof VAR == "TYPE") pattern'i
  const nullableTypeMatch = lineText.match(
    /!\((\w+)\s*===?\s*null\s*\|\|\s*typeof\s+\1\s*===?\s*"(\w+)"\)/
  );
  if (nullableTypeMatch) {
    return {
      obfuscated_var: nullableTypeMatch[1],
      type_hint: `${nullableTypeMatch[2]}|null`,
    };
  }

  // Strategy 3: !(VAR === undefined || ...) pattern'i
  const optionalMatch = lineText.match(
    /!\((\w+)\s*===?\s*undefined\s*\|\|/
  );
  if (optionalMatch) {
    return {
      obfuscated_var: optionalMatch[1],
      type_hint: "optional",
    };
  }

  // Strategy 4: !validator(VAR) pattern'i
  const validatorMatch = lineText.match(
    /!(\w+)\((\w+)\)/
  );
  if (validatorMatch) {
    return {
      obfuscated_var: validatorMatch[2],
      type_hint: `validated_by_${validatorMatch[1]}`,
    };
  }

  // Strategy 5: typeof VAR != "TYPE" (without quotes, already matched)
  const typeofMatch2 = lineText.match(
    /typeof\s+(\w+)\s*!=\s*"(\w+)"/
  );
  if (typeofMatch2) {
    return {
      obfuscated_var: typeofMatch2[1],
      type_hint: typeofMatch2[2],
    };
  }

  // Strategy 6: Array.isArray(VAR) pattern'i
  const arrayMatch = lineText.match(
    /Array\.isArray\((\w+)\)/
  );
  if (arrayMatch) {
    return {
      obfuscated_var: arrayMatch[1],
      type_hint: "array",
    };
  }

  return { obfuscated_var: null, type_hint: null };
}

/**
 * Bir IPC handler fonksiyonunun parametre listesini parsing yapar.
 * Satirin ONCESINE bakarak async (count, idx, str, arg, opts) => seklindeki
 * parametre listesini bulur.
 */
function findFunctionParams(lineIndex) {
  // Bu satirin bulundugu fonksiyonu bulmak icin onceki satirlara bak
  // Genellikle async (count, idx, str) => { seklinde bir satir var
  const searchRange = Math.max(0, lineIndex - 15);
  const contextLines = lines.slice(searchRange, lineIndex + 1).join("\n");

  // Pattern: async (PARAMS) => {
  const asyncMatch = contextLines.match(
    /async\s*\(([^)]+)\)\s*=>/
  );
  if (asyncMatch) {
    const params = asyncMatch[1]
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    return params;
  }

  // Pattern: function(PARAMS) {
  const funcMatch = contextLines.match(
    /function\s*\w*\s*\(([^)]+)\)\s*\{/
  );
  if (funcMatch) {
    const params = funcMatch[1]
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    return params;
  }

  return null;
}

// =====================================================================
// ANA TARAMA
// =====================================================================

const extractions = [];
const paramMap = new Map(); // obfuscated_var -> Set<real_name>
const methodRegistry = {}; // interface -> { method -> [params] }
const methodNames = new Set();
const interfaceNames = new Set();
const eventNames = new Set();

for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
  const line = lines[lineIdx];
  const lineNum = lineIdx + 1;

  // ---------- P1: Argument to method ----------
  let match;
  P1_REGEX.lastIndex = 0;
  while ((match = P1_REGEX.exec(line)) !== null) {
    const [, paramName, posStr, methodName, ifaceName] = match;
    const position = parseInt(posStr, 10);

    const { obfuscated_var, type_hint } = extractObfuscatedVar(line, position);

    // Parametre isimlerini fonksiyon parametreleriyle eslestir
    let resolvedObfVar = obfuscated_var;
    if (!resolvedObfVar) {
      // Fonksiyon parametrelerinden pozisyona gore bul
      const funcParams = findFunctionParams(lineIdx);
      if (funcParams && funcParams.length > position + 1) {
        // +1 cunku ilk parametre genellikle IPC event (count)
        resolvedObfVar = funcParams[position + 1];
      }
    }

    extractions.push({
      line: lineNum,
      pattern: "P1",
      param_name: paramName,
      position,
      method: methodName,
      interface: ifaceName,
      obfuscated_var: resolvedObfVar,
      type_hint: type_hint,
      confidence: 0.95,
    });

    // Map'e ekle
    if (resolvedObfVar) {
      if (!paramMap.has(resolvedObfVar)) paramMap.set(resolvedObfVar, new Set());
      paramMap.get(resolvedObfVar).add(paramName);
    }

    // Registry
    if (!methodRegistry[ifaceName]) methodRegistry[ifaceName] = {};
    if (!methodRegistry[ifaceName][methodName])
      methodRegistry[ifaceName][methodName] = [];
    methodRegistry[ifaceName][methodName].push({
      param_name: paramName,
      position,
      type_hint,
      obfuscated_var: resolvedObfVar,
    });

    methodNames.add(methodName);
    interfaceNames.add(ifaceName);
  }

  // ---------- P2: Argument to event ----------
  P2_REGEX.lastIndex = 0;
  while ((match = P2_REGEX.exec(line)) !== null) {
    const [, paramName, posStr, eventName, ifaceName] = match;
    const position = parseInt(posStr, 10);

    const { obfuscated_var, type_hint } = extractObfuscatedVar(line, position);

    extractions.push({
      line: lineNum,
      pattern: "P2",
      param_name: paramName,
      position,
      method: eventName,
      method_type: "event",
      interface: ifaceName,
      obfuscated_var: obfuscated_var,
      type_hint: type_hint,
      confidence: 0.95,
    });

    if (obfuscated_var) {
      if (!paramMap.has(obfuscated_var)) paramMap.set(obfuscated_var, new Set());
      paramMap.get(obfuscated_var).add(paramName);
    }

    if (!methodRegistry[ifaceName]) methodRegistry[ifaceName] = {};
    if (!methodRegistry[ifaceName][eventName])
      methodRegistry[ifaceName][eventName] = [];
    methodRegistry[ifaceName][eventName].push({
      param_name: paramName,
      position,
      type_hint,
      obfuscated_var,
      is_event: true,
    });

    eventNames.add(eventName);
    interfaceNames.add(ifaceName);
  }

  // ---------- P3: Result from method ----------
  P3_REGEX.lastIndex = 0;
  while ((match = P3_REGEX.exec(line)) !== null) {
    const [, methodName, ifaceName] = match;

    extractions.push({
      line: lineNum,
      pattern: "P3",
      param_name: null,
      method: methodName,
      interface: ifaceName,
      result_validation: true,
      confidence: 0.85,
    });

    methodNames.add(methodName);
    interfaceNames.add(ifaceName);
  }

  // ---------- P4: Incoming call ----------
  P4_REGEX.lastIndex = 0;
  while ((match = P4_REGEX.exec(line)) !== null) {
    const [, methodName, ifaceName] = match;

    extractions.push({
      line: lineNum,
      pattern: "P4",
      param_name: null,
      method: methodName,
      interface: ifaceName,
      origin_validation: true,
      confidence: 0.80,
    });

    methodNames.add(methodName);
    interfaceNames.add(ifaceName);
  }

  // ---------- P5: "NAME" must be a TYPE ----------
  P5_REGEX.lastIndex = 0;
  while ((match = P5_REGEX.exec(line)) !== null) {
    const [, name, typeName] = match;

    // Filtrele: "Argument", "Schema", gibi genel kelimeleri atla
    const skipWords = new Set([
      "argument", "schema", "path", "input", "output",
    ]);
    if (skipWords.has(name.toLowerCase())) continue;

    extractions.push({
      line: lineNum,
      pattern: "P5",
      param_name: name,
      type_hint: typeName,
      confidence: 0.70,
    });
  }

  // ---------- P8: Invalid value for "NAME" ----------
  P8_REGEX.lastIndex = 0;
  while ((match = P8_REGEX.exec(line)) !== null) {
    const [, name] = match;

    extractions.push({
      line: lineNum,
      pattern: "P8",
      param_name: name,
      confidence: 0.75,
    });
  }

  // ---------- P9: Missing required argument ----------
  P9_REGEX.lastIndex = 0;
  while ((match = P9_REGEX.exec(line)) !== null) {
    const [, name] = match;

    extractions.push({
      line: lineNum,
      pattern: "P9",
      param_name: name,
      confidence: 0.80,
    });
  }
}

// =====================================================================
// POST-PROCESSING: Cakisma analizi ve istatistikler
// =====================================================================

// obfuscated_var -> en sik gelen parametre ismi (most common mapping)
const varToMostCommonName = {};
for (const [obfVar, names] of paramMap) {
  // Position-based mapping: her pozisyon icin ayri isim
  // Bu nedenle burada sadece bilgiyi rapor ediyoruz
  varToMostCommonName[obfVar] = [...names];
}

// Interface bazli istatistik
const interfaceStats = {};
for (const [iface, methods] of Object.entries(methodRegistry)) {
  const methodCount = Object.keys(methods).length;
  let paramCount = 0;
  for (const params of Object.values(methods)) {
    paramCount += params.length;
  }
  interfaceStats[iface] = { methods: methodCount, params: paramCount };
}

// P1/P2 extraction'lardan unique param_name -> obfuscated_var mapping olustur
// Pozisyon bazli: position 0 -> genelde idx, position 1 -> str, position 2 -> arg
const positionMapping = {};
for (const ext of extractions) {
  if ((ext.pattern === "P1" || ext.pattern === "P2") && ext.obfuscated_var) {
    const pos = ext.position;
    if (!positionMapping[pos]) positionMapping[pos] = new Map();
    const posMap = positionMapping[pos];
    if (!posMap.has(ext.obfuscated_var)) posMap.set(ext.obfuscated_var, 0);
    posMap.set(ext.obfuscated_var, posMap.get(ext.obfuscated_var) + 1);
  }
}

// Pozisyon bazli en sik obfuscated var
const positionSummary = {};
for (const [pos, mapping] of Object.entries(positionMapping)) {
  const entries = [...mapping.entries()].sort((a, b) => b[1] - a[1]);
  positionSummary[pos] = entries.map(([name, count]) => ({ var: name, count }));
}

// Unique parametre isimleri
const uniqueParamNames = new Set(
  extractions
    .filter((e) => e.param_name)
    .map((e) => e.param_name)
);

// Confidence dagilimi
const confDistribution = { high: 0, medium: 0, low: 0 };
for (const ext of extractions) {
  if (ext.confidence >= 0.9) confDistribution.high++;
  else if (ext.confidence >= 0.7) confDistribution.medium++;
  else confDistribution.low++;
}

// =====================================================================
// CIKTI OLUSTUR
// =====================================================================

// paramMap'i JSON-serializable hale getir
const paramMapObj = {};
for (const [key, val] of paramMap) {
  paramMapObj[key] = [...val];
}

const result = {
  success: true,
  extractions,
  param_map: paramMapObj,
  method_registry: methodRegistry,
  stats: {
    total_extractions: extractions.length,
    unique_param_names: uniqueParamNames.size,
    unique_methods: methodNames.size,
    unique_events: eventNames.size,
    unique_interfaces: interfaceNames.size,
    confidence_distribution: confDistribution,
    interface_stats: interfaceStats,
    position_mapping: positionSummary,
    patterns_used: {
      P1_argument_method: extractions.filter((e) => e.pattern === "P1").length,
      P2_argument_event: extractions.filter((e) => e.pattern === "P2").length,
      P3_result_method: extractions.filter((e) => e.pattern === "P3").length,
      P4_incoming_call: extractions.filter((e) => e.pattern === "P4").length,
      P5_type_assertion: extractions.filter((e) => e.pattern === "P5").length,
      P8_invalid_value: extractions.filter((e) => e.pattern === "P8").length,
      P9_missing_required: extractions.filter((e) => e.pattern === "P9").length,
    },
  },
  // Kolay entegrasyon icin: context-analyzer'a verilecek format
  // { obfuscated_var: { line: N, suggested_name: "realName", position: P, method: "M" } }
  context_analyzer_hints: generateContextAnalyzerHints(extractions),
};

// JSON yaz
try {
  writeFileSync(outputPath, JSON.stringify(result, null, 2), "utf-8");
  console.log(`[OK] ${outputPath} yazildi`);
} catch (err) {
  console.error(`Dosya yazilamadi: ${err.message}`);
}

// Ozet rapor stdout'a
console.log("\n=== STRING NAME EXTRACTOR RAPOR ===");
console.log(`Toplam extraction: ${extractions.length}`);
console.log(`Unique parametre isimleri: ${uniqueParamNames.size}`);
console.log(`Unique method isimleri: ${methodNames.size}`);
console.log(`Unique event isimleri: ${eventNames.size}`);
console.log(`Unique interface isimleri: ${interfaceNames.size}`);
console.log(`\nConfidence dagilimi:`);
console.log(`  HIGH (>=0.9): ${confDistribution.high}`);
console.log(`  MEDIUM (0.7-0.9): ${confDistribution.medium}`);
console.log(`  LOW (<0.7): ${confDistribution.low}`);
console.log(`\nPattern dagilimi:`);
for (const [pattern, count] of Object.entries(result.stats.patterns_used)) {
  if (count > 0) console.log(`  ${pattern}: ${count}`);
}
console.log(`\nInterface bazli parametre sayilari:`);
for (const [iface, stats] of Object.entries(interfaceStats)) {
  console.log(`  ${iface}: ${stats.methods} method, ${stats.params} param`);
}
console.log(`\nObfuscated var -> Gercek isim eslesmesi:`);
for (const [obfVar, names] of Object.entries(paramMapObj).slice(0, 20)) {
  console.log(`  ${obfVar} -> [${names.slice(0, 5).join(", ")}${names.length > 5 ? `, ... (+${names.length - 5})` : ""}]`);
}

// =====================================================================
// CONTEXT ANALYZER HINT URETICI
// =====================================================================

/**
 * Extraction'lardan context-analyzer'in kullanabilecegi
 * hint map'i uretir.
 *
 * Format: { line: N, var_name: "idx", suggested_name: "sessionId",
 *           method: "getSession", interface: "LocalSessions",
 *           confidence: 0.95 }
 */
function generateContextAnalyzerHints(extractions) {
  const hints = [];

  for (const ext of extractions) {
    if (!ext.param_name || !ext.obfuscated_var) continue;

    hints.push({
      line: ext.line,
      var_name: ext.obfuscated_var,
      suggested_name: ext.param_name,
      position: ext.position,
      method: ext.method,
      interface: ext.interface || null,
      type_hint: ext.type_hint || null,
      confidence: ext.confidence,
    });
  }

  return hints;
}
