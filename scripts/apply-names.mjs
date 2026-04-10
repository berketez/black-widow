#!/usr/bin/env node
/**
 * apply-names.mjs -- Context-analyzer ciktisindaki isimleri kodda uygula
 *
 * Black Widow v1.0 -- Karadul
 *
 * SCOPE-AWARE VERSION:
 *   context-analyzer.mjs'nin scope_renames listesini kullanarak
 *   her scope'taki degiskeni dogru ismiyle rename eder.
 *
 *   Eger scope_renames yoksa (eski format), flat variables map'i kullanir.
 *
 * Kullanim:
 *   node --max-old-space-size=8192 apply-names.mjs <input.js> <names.json> <output.js>
 *     [--min-confidence 0.4]
 *     [--dry-run]
 *
 * Cikti (stdout JSON):
 *   {
 *     "success": true,
 *     "renamed": 142,
 *     "skipped": 23,
 *     "scope_aware": true,
 *     "mappings": {"scope1::e": "request", "scope2::e": "error"},
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

const MIN_CONFIDENCE = parseFloat(flags.get("--min-confidence") || "0.4");
const DRY_RUN = flags.has("--dry-run");

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

if (positional.length < 3) {
  emit({
    success: false,
    renamed: 0,
    skipped: 0,
    mappings: {},
    errors: [
      "Kullanim: node apply-names.mjs <input.js> <names.json> <output.js> [--min-confidence 0.4] [--dry-run]",
    ],
  });
  process.exit(1);
}

const inputPath = resolve(positional[0]);
const namesPath = resolve(positional[1]);
const outputPath = resolve(positional[2]);

// ---------- Dosyalari oku ----------
let source, namesData;

try {
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  emit({ success: false, renamed: 0, skipped: 0, mappings: {}, errors: [`JS dosyasi okunamadi: ${err.message}`] });
  process.exit(1);
}

try {
  namesData = JSON.parse(readFileSync(namesPath, "utf-8"));
} catch (err) {
  emit({ success: false, renamed: 0, skipped: 0, mappings: {}, errors: [`Names JSON okunamadi: ${err.message}`] });
  process.exit(1);
}

const errors = [];

// ---------- Scope-aware mi kontrol et ----------
const isScopeAware = !!(namesData.scope_renames && namesData.scope_renames.length > 0);

// =====================================================================
// PHASE 0: DUPLICATE DECLARATION FIX (ayni pre-process)
// =====================================================================
// apply-names.mjs de ayni duplicate fix'i yapmali cunku scope-aware
// traverse kullanacak

let ast;
let duplicatesFixed = 0;

try {
  ast = parse(source, {
    sourceType: "unambiguous",
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowImportExportEverywhere: true,
    errorRecovery: true,
    plugins: [
      "jsx", "typescript", "decorators-legacy", "classProperties",
      "classPrivateProperties", "classPrivateMethods", "dynamicImport",
      "optionalChaining", "nullishCoalescingOperator", "logicalAssignment",
      "numericSeparator", "optionalCatchBinding", "throwExpressions",
      "topLevelAwait", "exportDefaultFrom", "exportNamespaceFrom",
      "asyncGenerators", "objectRestSpread", "importMeta", "importAssertions",
    ],
  });
} catch (err) {
  emit({
    success: false, renamed: 0, skipped: 0, mappings: {},
    errors: [`Parse hatasi: ${err.message}`],
  });
  process.exit(0);
}

// Duplicate fix pre-process
function findFunctionScope(path) {
  let current = path.parentPath;
  while (current) {
    const type = current.node?.type;
    if (type === "FunctionDeclaration" || type === "FunctionExpression" ||
        type === "ArrowFunctionExpression" || type === "Program") {
      return current.node;
    }
    current = current.parentPath;
  }
  return null;
}

function findBlockScope(path) {
  let current = path.parentPath;
  while (current) {
    const type = current.node?.type;
    if (type === "FunctionDeclaration" || type === "FunctionExpression" ||
        type === "ArrowFunctionExpression" || type === "Program" ||
        type === "BlockStatement" || type === "ForStatement" ||
        type === "ForInStatement" || type === "ForOfStatement" ||
        type === "SwitchStatement") {
      return current.node;
    }
    current = current.parentPath;
  }
  return null;
}

try {
  traverse(ast, {
    noScope: true,
    VariableDeclaration(path) {
      const declarations = path.node.declarations;
      const kind = path.node.kind;

      let scopeBlock = kind === "var" ? findFunctionScope(path) : findBlockScope(path);
      if (!scopeBlock) scopeBlock = ast;
      if (!scopeBlock._seenVarNames) scopeBlock._seenVarNames = new Map();
      const seen = scopeBlock._seenVarNames;

      const toConvert = [];
      for (let i = 0; i < declarations.length; i++) {
        const decl = declarations[i];
        if (!decl.id || decl.id.type !== "Identifier") continue;
        const name = decl.id.name;
        if (seen.has(name)) {
          toConvert.push({ index: i, decl });
          duplicatesFixed++;
        } else {
          seen.set(name, kind);
        }
      }

      if (toConvert.length === 0) return;

      if (toConvert.length === declarations.length) {
        const assignments = toConvert.map(({ decl }) => {
          if (decl.init) return t.assignmentExpression("=", t.identifier(decl.id.name), decl.init);
          return null;
        }).filter(Boolean);

        if (assignments.length === 0) {
          // BUG FIX: init'siz declaration'lari silmemeli!
          // `var s;` gibi declaration'lar ileride kullaniliyor olabilir.
          // Silmek ReferenceError'a yol acar (strict mode'da).
          // Declaration'i oldugu gibi birakmak zararsiz ama silmek tehlikeli.
          return;
        }

        const isForInit = path.parent?.type === "ForStatement" && path.parent.init === path.node;
        const isForInLeft = (path.parent?.type === "ForInStatement" || path.parent?.type === "ForOfStatement") && path.parent.left === path.node;

        if (isForInit || isForInLeft) {
          if (assignments.length === 1) {
            try { path.replaceWith(assignments[0]); } catch(_) { path.node.kind = "var"; }
          } else {
            try { path.replaceWith(t.sequenceExpression(assignments)); } catch(_) { path.node.kind = "var"; }
          }
        } else {
          if (assignments.length === 1) {
            try { path.replaceWith(t.expressionStatement(assignments[0])); } catch(_) { path.node.kind = "var"; }
          } else {
            try { path.replaceWith(t.expressionStatement(t.sequenceExpression(assignments))); } catch(_) { path.node.kind = "var"; }
          }
        }
        return;
      }

      const assignmentExprs = [];
      for (const { index, decl } of toConvert.reverse()) {
        declarations.splice(index, 1);
        if (decl.init) {
          assignmentExprs.push(t.assignmentExpression("=", t.identifier(decl.id.name), decl.init));
        }
      }
      if (assignmentExprs.length > 0) {
        const isForInit = path.parent?.type === "ForStatement" && path.parent.init === path.node;
        if (isForInit) return;
        try {
          const stmts = assignmentExprs.map(a => t.expressionStatement(a));
          for (const stmt of stmts.reverse()) path.insertBefore(stmt);
        } catch (_) {
          path.node.kind = "var";
          for (const { decl } of toConvert) declarations.push(decl);
        }
      }
    },
  });
} catch (err) {
  errors.push(`Duplicate fix hatasi: ${err.message}`);
}

// Temizle
traverse(ast, {
  noScope: true,
  enter(path) {
    if (path.node._seenVarNames) delete path.node._seenVarNames;
  },
});

// ------------------------------------------------------------------
// PHASE 0.1: DUPLICATE FUNCTION PARAMETER FIX
// ------------------------------------------------------------------
// function az(items, items) gibi duplicate parametreleri duzelter.
// Ikinci (ve sonraki) ayni isimli parametrelere _2, _3 suffix ekler.
// Bu strict mode'da SyntaxError olur, bu yuzden fix gerekli.

let duplicateParamsFixed = 0;

try {
  traverse(ast, {
    noScope: true,
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ClassMethod|ObjectMethod"(path) {
      const params = path.node.params;
      if (!params || params.length < 2) return;

      const seenNames = new Set();
      for (let i = 0; i < params.length; i++) {
        const param = params[i];
        if (!param) continue;

        // Sadece Identifier parametreleri (destructuring vs. atlaniyor)
        if (param.type === "Identifier") {
          if (seenNames.has(param.name)) {
            // Duplicate parametre -- suffix ekle
            let suffix = 2;
            let newName = `${param.name}_${suffix}`;
            while (seenNames.has(newName)) {
              suffix++;
              newName = `${param.name}_${suffix}`;
            }
            param.name = newName;
            seenNames.add(newName);
            duplicateParamsFixed++;
          } else {
            seenNames.add(param.name);
          }
        } else if (param.type === "AssignmentPattern" && param.left?.type === "Identifier") {
          // Varsayilan degerli parametre: function(a, a = 5)
          const name = param.left.name;
          if (seenNames.has(name)) {
            let suffix = 2;
            let newName = `${name}_${suffix}`;
            while (seenNames.has(newName)) {
              suffix++;
              newName = `${name}_${suffix}`;
            }
            param.left.name = newName;
            seenNames.add(newName);
            duplicateParamsFixed++;
          } else {
            seenNames.add(name);
          }
        }
      }
    },
  });
} catch (err) {
  errors.push(`Duplicate param fix hatasi: ${err.message}`);
}

console.error(`[apply-names] ${duplicatesFixed} duplicate var duzeltildi, ${duplicateParamsFixed} duplicate param duzeltildi, scope_aware=${isScopeAware}`);

// Babel Scope monkey-patch (duplicate declaration toleransi)
try {
  const scopeModule = await import("@babel/traverse");
  const Scope = (scopeModule.default || scopeModule).Scope ||
    Object.values(scopeModule).find(v => v?.prototype?.registerBinding);

  if (Scope?.prototype?.registerBinding) {
    const originalRegisterBinding = Scope.prototype.registerBinding;
    Scope.prototype.registerBinding = function(kind, path, bindingPath) {
      try {
        return originalRegisterBinding.call(this, kind, path, bindingPath);
      } catch (err) {
        if (err.message?.includes("Duplicate declaration")) return;
        throw err;
      }
    };
    console.error("[apply-names] Scope.registerBinding patched");
  } else {
    try {
      const { Scope: S2 } = await import("/Users/apple/Desktop/black-widow/scripts/node_modules/@babel/traverse/lib/scope/index.js");
      if (S2?.prototype?.registerBinding) {
        const orig = S2.prototype.registerBinding;
        S2.prototype.registerBinding = function(kind, path, bindingPath) {
          try { return orig.call(this, kind, path, bindingPath); }
          catch (err) { if (err.message?.includes("Duplicate declaration")) return; throw err; }
        };
        console.error("[apply-names] Scope.registerBinding patched (direct)");
      }
    } catch(_) {}
  }
} catch (patchErr) {
  console.error("[apply-names] Scope patch basarisiz:", patchErr.message);
}

// =====================================================================
// SCOPE-AWARE RENAME (v1.0 -- Shadow Detection + Binding-Level Rename)
// =====================================================================
//
// BUG FIX'LER:
//   1. SHADOW DETECTION: Rename yapmadan once yeni ismin ayni scope'ta
//      baska bir binding'i shadow'layip shadow'lamayacagi kontrol edilir.
//      Shadow olacaksa suffix eklenir veya rename atlanir.
//
//   2. BINDING-LEVEL RENAME: Babel'in scope.rename() API'si kullanilir.
//      Bu API bir binding'in declaration'ini VE tum referanslarini
//      atomik olarak degistirir. Kismi rename (cross-scope leakage) olmaz.
//
//   3. VAR DECLARATION KORUMA: init'siz duplicate declaration'lar
//      artik silinmiyor (yukaridaki Phase 0'da duzeltildi).
//

if (isScopeAware) {
  // scope_renames listesinden bir lookup map olustur
  // scopeId::originalName -> { newName, confidence }
  const scopeRenameMap = new Map();
  let skipped = 0;

  for (const rename of namesData.scope_renames) {
    if (!rename.newName || rename.newName === rename.originalName) {
      skipped++;
      continue;
    }
    if (rename.confidence < MIN_CONFIDENCE) {
      skipped++;
      continue;
    }

    const key = `${rename.scopeId}::${rename.originalName}`;
    const existing = scopeRenameMap.get(key);
    if (!existing || rename.confidence > existing.confidence) {
      scopeRenameMap.set(key, {
        newName: rename.newName,
        confidence: rename.confidence,
      });
    }
  }

  console.error(`[apply-names] ${scopeRenameMap.size} scope-aware rename mapping, ${skipped} skipped`);

  // ------------------------------------------------------------------
  // SHADOW DETECTION HELPER
  // ------------------------------------------------------------------
  // Bir scope'ta newName kullanilirsa mevcut bir binding'i shadow'lar mi?
  function wouldShadow(scope, newName, originalName) {
    try {
      // 1. Ayni scope'ta bu isimde FARKLI bir binding var mi?
      const ownBinding = scope.getOwnBinding(newName);
      if (ownBinding) return true;

      // 2. Child scope'larda bu isimde binding var mi?
      //    (eger parent scope'tan rename yaparsak child'daki
      //     ayni isimli degisken yanlis referans alir)
      //    Babel scope API ile child scope'lari kontrol et
      //    NOT: scope.bindings sadece kendi scope'undakileri gosterir

      // 3. Parent scope'ta bu isimde binding var mi?
      //    (shadow olusturur)
      let parentScope = scope.parent;
      while (parentScope) {
        const parentBinding = parentScope.getOwnBinding(newName);
        if (parentBinding) {
          // Parent'ta newName var -- ama eger o da rename edilecekse sorun yok
          // Guvenli yol: her durumda shadow say
          return true;
        }
        parentScope = parentScope.parent;
      }

      // 4. Ayni scope'ta newName ile ayni isimli parametre var mi?
      //    (fonksiyon parametresi items, for-loop da items tanimlayinca shadow)
      const block = scope.block;
      if (block && (block.params || block.type === "CatchClause")) {
        const params = block.params || (block.param ? [block.param] : []);
        for (const param of params) {
          if (param.type === "Identifier" && param.name === newName) return true;
          // Destructuring pattern'lerini de kontrol et
          if (param.type === "ObjectPattern" || param.type === "ArrayPattern") {
            const names = [];
            collectPatternNames(param, names);
            if (names.includes(newName)) return true;
          }
        }
      }
    } catch (_) {
      // Scope API hatasi -- guvenli tarafta kal
      return false;
    }

    return false;
  }

  function collectPatternNames(pattern, names) {
    if (!pattern) return;
    if (pattern.type === "Identifier") {
      names.push(pattern.name);
    } else if (pattern.type === "ObjectPattern") {
      for (const prop of (pattern.properties || [])) {
        collectPatternNames(prop.value || prop.argument, names);
      }
    } else if (pattern.type === "ArrayPattern") {
      for (const elem of (pattern.elements || [])) {
        collectPatternNames(elem, names);
      }
    } else if (pattern.type === "AssignmentPattern") {
      collectPatternNames(pattern.left, names);
    } else if (pattern.type === "RestElement") {
      collectPatternNames(pattern.argument, names);
    }
  }

  // ------------------------------------------------------------------
  // SCOPE ID HELPER (context-analyzer ile ayni format)
  // ------------------------------------------------------------------
  function getScopeId(scope) {
    try {
      if (scope && scope.block) {
        const block = scope.block;
        if (block.loc && block.loc.start) {
          const funcName =
            block.id?.name ||
            (block.type === "Program" ? "program" : block.type);
          return `${funcName}@${block.loc.start.line}:${block.loc.start.column}`;
        }
        if (scope.uid !== undefined) return `scope_${scope.uid}`;
      }
    } catch (_) {}
    return "global";
  }

  // ------------------------------------------------------------------
  // BINDING-LEVEL RENAME
  // ------------------------------------------------------------------
  // Babel'in scope.rename(oldName, newName) kullanarak
  // tum referanslari atomik olarak degistirir.
  //
  // scope.rename() su isleri yapar:
  //   - binding.identifier.name = newName
  //   - Tum referencePaths'deki node.name = newName
  //   - Tum constantViolations'deki node.name = newName
  //   - Shorthand property'leri duzeltir
  //   - Scope binding registry'sini gunceller
  //
  // Eger scope.rename() basarisiz olursa fallback olarak
  // manuel binding-level rename yapariz.

  const appliedMappings = {};
  let renameCount = 0;
  let shadowSkipped = 0;
  let shadowSuffixed = 0;

  // Rename'leri topla: once tum binding'leri bul, sonra rename et
  // (traverse sirasinda rename yapmak iterator'u bozabilir)
  const pendingRenames = [];

  try {
    // PASS 1: Tum binding declaration'lari bul ve rename planla
    traverse(ast, {
      // Binding declaration'larini yakala
      "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|Program|ClassMethod|ObjectMethod"(path) {
        const scope = path.scope;
        if (!scope) return;

        const scopeId = getScopeId(scope);

        // Bu scope'taki tum binding'leri kontrol et
        for (const [bindingName, binding] of Object.entries(scope.bindings || {})) {
          if (bindingName.length > 3) continue;

          const key = `${scopeId}::${bindingName}`;
          const mapping = scopeRenameMap.get(key);
          if (!mapping) continue;

          pendingRenames.push({
            scope,
            scopeId,
            oldName: bindingName,
            newName: mapping.newName,
            confidence: mapping.confidence,
            binding,
          });
        }
      },
    });

    console.error(`[apply-names] ${pendingRenames.length} binding-level rename planlandi`);

    // PASS 2: Rename'leri uygula (en yuksek confidence'tan baslayarak)
    // Ayni scope'ta birden fazla rename olabilir -- oncelik sirasi onemli
    pendingRenames.sort((a, b) => b.confidence - a.confidence);

    // Zaten rename edilmis binding'leri izle
    const renamedBindings = new Set();
    // Bir scope'ta kullanilan yeni isimleri izle (shadow onleme icin)
    const usedNamesInScope = new Map(); // scopeId -> Set<newName>

    for (const rename of pendingRenames) {
      const { scope, scopeId, oldName, binding } = rename;
      let { newName } = rename;

      // Zaten rename edilmis mi?
      const bindingKey = `${scopeId}::${oldName}`;
      if (renamedBindings.has(bindingKey)) continue;

      // Shadow kontrolu
      if (wouldShadow(scope, newName, oldName)) {
        // Suffix ekleyerek shadow'u onlemeye calis
        let resolved = false;
        for (let suffix = 1; suffix <= 5; suffix++) {
          const suffixedName = `${newName}_${suffix}`;
          if (!wouldShadow(scope, suffixedName, oldName)) {
            newName = suffixedName;
            resolved = true;
            shadowSuffixed++;
            break;
          }
        }
        if (!resolved) {
          shadowSkipped++;
          console.error(`[apply-names] SHADOW SKIP: ${oldName} -> ${rename.newName} in ${scopeId}`);
          continue;
        }
      }

      // Ayni scope'ta bu yeni isim zaten kullanildi mi?
      if (!usedNamesInScope.has(scopeId)) {
        usedNamesInScope.set(scopeId, new Set());
      }
      const usedNames = usedNamesInScope.get(scopeId);
      if (usedNames.has(newName)) {
        // Baska bir binding zaten bu ismi aldi
        let resolved = false;
        for (let suffix = 1; suffix <= 5; suffix++) {
          const suffixedName = `${newName}_${suffix}`;
          if (!usedNames.has(suffixedName) && !wouldShadow(scope, suffixedName, oldName)) {
            newName = suffixedName;
            resolved = true;
            shadowSuffixed++;
            break;
          }
        }
        if (!resolved) {
          shadowSkipped++;
          continue;
        }
      }
      usedNames.add(newName);

      // ----- RENAME UYGULA -----
      // NOT: scope.rename() KULLANMIYORUZ!
      // scope.rename() duplicate declaration durumunda ayni isimli
      // FARKLI binding'leri de degistirebilir (cross-contamination).
      // Bunun yerine manualBindingRename kullaniyoruz -- sadece
      // bu binding'in identifier'ini ve referencePaths'ini degistirir.
      try {
        manualBindingRename(binding, oldName, newName);
        renamedBindings.add(bindingKey);
        renameCount++;
        appliedMappings[bindingKey] = { from: oldName, to: newName };
      } catch (manualErr) {
        errors.push(`Rename basarisiz ${oldName}->${newName} in ${scopeId}: ${manualErr.message}`);
      }
    }

    console.error(`[apply-names] Rename sonuc: ${renameCount} basarili, ${shadowSkipped} shadow-skip, ${shadowSuffixed} shadow-suffix`);

  } catch (err) {
    errors.push(`Scope-aware rename hatasi: ${err.message}`);

    // Fallback: flat rename
    console.error(`[apply-names] Scope-aware rename basarisiz, flat fallback'a donuluyor: ${err.message}`);
    flatRename(namesData.variables || {});
  }

  // ------------------------------------------------------------------
  // MANUAL BINDING RENAME FALLBACK
  // ------------------------------------------------------------------
  // scope.rename() calismazsa binding'in tum referanslarini elle degistirir
  function manualBindingRename(binding, oldName, newName) {
    // Declaration
    if (binding.identifier) {
      binding.identifier.name = newName;
    }

    // Tum referanslar
    if (binding.referencePaths) {
      for (const refPath of binding.referencePaths) {
        if (refPath.node && refPath.node.name === oldName) {
          // Shorthand object property kontrolu
          if (refPath.parent?.type === "ObjectProperty" &&
              refPath.parent.shorthand &&
              refPath.parent.value === refPath.node) {
            refPath.parent.shorthand = false;
          }
          refPath.node.name = newName;
        }
      }
    }

    // Constant violations (reassignment)
    if (binding.constantViolations) {
      for (const violationPath of binding.constantViolations) {
        // AssignmentExpression: violationPath.node.left
        if (violationPath.node?.left?.type === "Identifier" &&
            violationPath.node.left.name === oldName) {
          violationPath.node.left.name = newName;
        }
        // UpdateExpression: violationPath.node.argument
        if (violationPath.node?.argument?.type === "Identifier" &&
            violationPath.node.argument.name === oldName) {
          violationPath.node.argument.name = newName;
        }
      }
    }
  }

  // Cikti
  if (!DRY_RUN) {
    try {
      const { code } = generate(ast, { comments: true, compact: false, concise: false, retainLines: true });
      writeFileSync(outputPath, code, "utf-8");
    } catch (err) {
      emit({
        success: false, renamed: renameCount, skipped,
        scope_aware: true, mappings: appliedMappings,
        errors: [...errors, `Code generation hatasi: ${err.message}`],
      });
      process.exit(0);
    }
  }

  emit({
    success: true,
    renamed: renameCount,
    skipped,
    scope_aware: true,
    duplicates_fixed: duplicatesFixed,
    shadow_skipped: shadowSkipped,
    shadow_suffixed: shadowSuffixed,
    mappings: appliedMappings,
    output: DRY_RUN ? null : outputPath,
    dry_run: DRY_RUN,
    min_confidence: MIN_CONFIDENCE,
    errors,
  });

} else {
  // =====================================================================
  // FLAT RENAME (eski noScope davranisi -- geriye uyumluluk)
  // =====================================================================
  flatRename(namesData.variables || {});
}

function flatRename(variableNames) {
  const globalRenames = new Map();
  let skipped = 0;

  for (const [originalName, info] of Object.entries(variableNames)) {
    if (!info.suggested_name || info.suggested_name === originalName) {
      skipped++;
      continue;
    }
    if (info.confidence < MIN_CONFIDENCE) {
      skipped++;
      continue;
    }

    const existing = globalRenames.get(originalName);
    if (!existing || info.confidence > existing.confidence) {
      globalRenames.set(originalName, {
        newName: info.suggested_name,
        confidence: info.confidence,
      });
    }
  }

  const renameMap = new Map();
  for (const [originalName, { newName }] of globalRenames) {
    renameMap.set(originalName, newName);
  }

  const appliedMappings = {};
  let renameCount = 0;
  const renamedNodes = new Set();

  try {
    traverse(ast, {
      noScope: true,
      Identifier(path) {
        const name = path.node.name;
        if (!renameMap.has(name)) return;
        if (renamedNodes.has(path.node)) return;

        if (path.parent.type === "MemberExpression" && path.parent.property === path.node && !path.parent.computed) return;
        if (path.parent.type === "ObjectProperty" && path.parent.key === path.node && !path.parent.computed && !path.parent.shorthand) return;
        if (path.parent.type === "ObjectMethod" && path.parent.key === path.node && !path.parent.computed) return;
        if (path.parent.type === "ClassMethod" && path.parent.key === path.node && !path.parent.computed) return;
        if (path.parent.type === "ClassProperty" && path.parent.key === path.node && !path.parent.computed) return;
        if (path.parent.type === "LabeledStatement" || path.parent.type === "BreakStatement" || path.parent.type === "ContinueStatement") return;
        if (path.parent.type === "ImportSpecifier" && path.parent.imported === path.node) return;
        if (path.parent.type === "ExportSpecifier" && path.parent.exported === path.node) return;

        if (path.parent.type === "ObjectProperty" && path.parent.shorthand && path.parent.value === path.node) {
          path.parent.shorthand = false;
        }

        const newName = renameMap.get(name);
        path.node.name = newName;
        renamedNodes.add(path.node);
        renameCount++;

        if (!appliedMappings[name]) {
          appliedMappings[name] = newName;
        }
      },
    });
  } catch (err) {
    errors.push(`Flat rename hatasi: ${err.message}`);
  }

  if (!DRY_RUN) {
    try {
      const { code } = generate(ast, { comments: true, compact: false, concise: false, retainLines: true });
      writeFileSync(outputPath, code, "utf-8");
    } catch (err) {
      emit({
        success: false, renamed: renameCount, skipped,
        scope_aware: false, mappings: appliedMappings,
        errors: [...errors, `Code generation hatasi: ${err.message}`],
      });
      process.exit(0);
    }
  }

  emit({
    success: true,
    renamed: renameCount,
    skipped,
    scope_aware: false,
    duplicates_fixed: duplicatesFixed,
    mappings: appliedMappings,
    output: DRY_RUN ? null : outputPath,
    dry_run: DRY_RUN,
    min_confidence: MIN_CONFIDENCE,
    errors,
  });
}
