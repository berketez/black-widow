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
 * Çıktı (stdout, TEK JSON satırı):
 *   {
 *     "success": true,
 *     "renamed": 142,
 *     "skipped": 23,
 *     "scope_aware": true,
 *     "mappings": {"f@3:0::e": {"from": "e", "to": "request"}},
 *     "output": "/path/to/output.js"
 *   }
 *   Flat kipte (scope_renames yok ya da scope-aware yol çökerse)
 *   "scope_aware": false ve "mappings": {"e": "request"}.
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
function findBlockScope(path) {
  let current = path.parentPath;
  while (current) {
    const type = current.node?.type;
    if (type === "FunctionDeclaration" || type === "FunctionExpression" ||
        type === "ArrowFunctionExpression" || type === "Program" ||
        type === "BlockStatement" || type === "ForStatement" ||
        type === "ForInStatement" || type === "ForOfStatement" ||
        type === "SwitchStatement" || type === "StaticBlock") {
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

      // `var` tekrarı geçerli JS'tir; Babel onu aynı binding'in yeniden
      // bildirimi (constant violation) olarak kaydeder ve rename bildirimi de
      // değiştirir. Dönüştürmek çıktının anlamını bozuyordu: for-init'teki
      // tekrarın başlangıç ataması siliniyordu (`for (var t = X, n = 0; ...)`
      // -> `for (var t = X; ...)`) ve sınıf/nesne metodları fonksiyon scope'u
      // sayılmadığı için iki metoddaki `var a` birleştirilip ikincisi
      // bildirimsiz atamaya dönüyordu. Yalnız let/const ele alınır.
      if (kind === "var") return;

      let scopeBlock = findBlockScope(path);
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

      // Sadece bazı declarator'lar duplicate. For-init'te atamayı öne alacak
      // yer yok; declarator'u silmek başlangıç değerini kaybettirir. Olduğu gibi
      // bırakılır (Scope yaması tekrarı tolere eder).
      if (path.parent?.type === "ForStatement" && path.parent.init === path.node) return;

      const assignmentExprs = [];
      for (const { index, decl } of toConvert.reverse()) {
        declarations.splice(index, 1);
        if (decl.init) {
          assignmentExprs.push(t.assignmentExpression("=", t.identifier(decl.id.name), decl.init));
        }
      }
      if (assignmentExprs.length > 0) {
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
      // lib/scope/index.js CommonJS (`exports.default = Scope`): ESM import'ta sınıf `default.default` altında
      const scopeMod = await import(new URL("./node_modules/@babel/traverse/lib/scope/index.js", import.meta.url).href);
      const S2 = scopeMod.Scope ?? scopeMod.default?.default;
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
// SCOPE-AWARE RENAME (binding düzeyinde, ad yakalama kontrollü)
// =====================================================================
//
// PASS 1 bütün scope'ları gezer (fonksiyon, program, blok, for, catch,
// switch, sınıf, static blok, metod) ve her binding'i "<scopeId>::<ad>"
// anahtarıyla scope_renames'e eşler. AST'ye dokunmaz; çökerse flat yedeğe
// düşülür ve TEK JSON satırı (scope_aware: false) basılır.
//
// PASS 2 önerileri güven sırasıyla uygular. Yeni ad N yalnız şu koşullarda
// verilir; yoksa N_1..N_5 denenir (shadow_suffixed), hiçbiri uymazsa rename
// atlanır (shadow_skipped):
//   1. N geçerli bir binding adı (ayrılmış sözcük, eval, arguments değil) ve
//      programda global (hiçbir binding'e çözülmeyen) ad olarak geçmiyor.
//   2. Binding'in kendi scope'unda N adlı başka binding yok.
//   3. İç yakalama yok: binding'in her kullanım yeri (bildirim, referans,
//      yeniden atama/bildirim) ile binding'in scope'u arasındaki scope'ların
//      hiçbirinde N adlı başka binding yok. Varsa o kullanım ona bağlanırdı.
//   4. Dış yakalama yok: binding'in scope'undan görünen N adlı dış binding'in
//      bu scope'un alt ağacında kullanımı yok. Varsa o kullanım bu binding'e
//      bağlanırdı.
// Kontroller Babel'in scope kaydına değil, her rename'den sonra güncellenen
// kendi ad tablomuza bakar; önceki rename'lerin verdiği adlar da görülür.
//
// scope.rename() KULLANILMAZ: Duplicate declaration yaması altında aynı adlı
// FARKLI binding'leri de değiştirebilir. Yalnız bu binding'in bildirim,
// referans ve yeniden atama/bildirim kimlikleri değiştirilir (destructuring
// atama hedefleri ve `var` yeniden bildirimleri dahil).
// `export var/let/const/function/class` ile dışa verilen binding'ler
// yeniden adlandırılmaz: modülün dışa verdiği ad değişirdi (export_skipped).

function isValidBindingName(name) {
  return typeof name === "string" && t.isValidIdentifier(name) &&
    name !== "eval" && name !== "arguments";
}

// context-analyzer ile aynı biçim
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

function buildScopeModel(root) {
  const scopes = [];
  const seen = new Set();
  traverse(root, {
    enter(path) {
      const s = path.scope;
      if (s && !seen.has(s)) {
        seen.add(s);
        scopes.push(s);
      }
    },
  });
  if (scopes.length === 0) throw new Error("scope bulunamadı");

  const parentOf = new Map();
  const children = new Map();
  const names = new Map(); // scope -> Map(güncel ad -> binding)
  const homes = new Map(); // binding -> kayıtlı olduğu scope'lar (sınıf adı iki scope'ta)
  for (const s of scopes) {
    const parent = s.parent;
    if (parent && !seen.has(parent)) throw new Error(`üst scope modelde yok: ${getScopeId(s)}`);
    parentOf.set(s, parent || null);
    if (parent) {
      if (!children.has(parent)) children.set(parent, []);
      children.get(parent).push(s);
    }
    const table = new Map();
    for (const name of Object.keys(s.bindings)) {
      const binding = s.bindings[name];
      table.set(name, binding);
      if (!homes.has(binding)) homes.set(binding, []);
      homes.get(binding).push(s);
    }
    names.set(s, table);
  }

  // Alt ağaç testi: s, r'nin alt ağacında <=> tin[r] <= tin[s] <= tout[r]
  const program = scopes[0].getProgramParent();
  const tin = new Map();
  const tout = new Map();
  let clock = 0;
  const stack = [[program, false]];
  while (stack.length > 0) {
    const [s, exiting] = stack.pop();
    if (exiting) {
      tout.set(s, clock - 1);
      continue;
    }
    tin.set(s, clock++);
    stack.push([s, true]);
    for (const c of children.get(s) || []) stack.push([c, false]);
  }

  return {
    scopes, parentOf, names, homes, tin, tout,
    globals: new Set(Object.keys(program.globals || {})),
  };
}

function isExportedDeclaration(binding) {
  const p = binding.path;
  if (p.isFunctionDeclaration() || p.isClassDeclaration()) {
    return !!p.parentPath?.isExportNamedDeclaration();
  }
  if (p.isVariableDeclarator()) {
    return !!p.parentPath?.parentPath?.isExportNamedDeclaration();
  }
  return false;
}

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
  // PASS 1: scope modeli + rename planı (AST değişmez)
  // ------------------------------------------------------------------
  let model = null;
  const pendingRenames = [];
  try {
    model = buildScopeModel(ast);
    for (const scope of model.scopes) {
      let scopeId = null;
      for (const oldName of Object.keys(scope.bindings)) {
        const binding = scope.bindings[oldName];
        // Sınıf bildiriminin adı sınıf scope'unda da kayıtlı (aynı binding):
        // yalnız asıl scope'unda planlanır.
        if (binding.scope !== scope || oldName.length > 3) continue;
        scopeId ??= getScopeId(scope);
        const key = `${scopeId}::${oldName}`;
        const mapping = scopeRenameMap.get(key);
        if (!mapping) continue;
        pendingRenames.push({
          binding, scopeId, key, oldName,
          newName: mapping.newName,
          confidence: mapping.confidence,
        });
      }
    }
  } catch (err) {
    model = null;
    errors.push(`Scope-aware rename hatasi: ${err.message}`);
    console.error(`[apply-names] Scope-aware rename basarisiz, flat fallback'a donuluyor: ${err.message}`);
  }

  if (!model) {
    // AST'ye henüz dokunulmadı; raporu (tek JSON satırı) flatRename basar.
    flatRename(namesData.variables || {});
  } else {
    const { parentOf, names, homes, tin, tout, globals } = model;
    console.error(`[apply-names] ${pendingRenames.length} binding-level rename planlandi`);

    // Kullanım yerleri: {scope, nodes (yeniden adlandırılacak kimlikler), ref}
    const siteCache = new Map();
    const declaresInParent = (p) => p.isFunctionDeclaration() || p.isClassDeclaration();

    function siteInfo(binding) {
      let info = siteCache.get(binding);
      if (info) return info;
      const name = binding.identifier.name;
      const sites = [];
      // function/class bildiriminin adı kendi scope'unda değil, binding'in scope'unda
      sites.push({
        scope: declaresInParent(binding.path) ? binding.scope : binding.path.scope,
        nodes: [binding.identifier],
      });
      for (const ref of binding.referencePaths) {
        sites.push({ scope: ref.scope, nodes: [ref.node], ref });
      }
      for (const violation of binding.constantViolations) {
        // a = .., a++, [a] = .., ({a} = ..), for (a in ..), var a (yeniden), function a() {}
        const ids = t.getBindingIdentifiers(violation.node, true, true)[name];
        if (!ids) continue;
        sites.push({
          scope: declaresInParent(violation) ? parentOf.get(violation.scope) : violation.scope,
          nodes: [].concat(ids),
        });
      }
      const inner = new Set(); // kullanım yeri ile binding.scope arasındaki scope'lar
      let outside = false;
      for (const site of sites) {
        let s = site.scope;
        while (s && s !== binding.scope && !inner.has(s)) {
          inner.add(s);
          s = parentOf.get(s);
        }
        if (!s) outside = true; // binding'in scope'u dışında kullanım: güvenli tarafta kal
      }
      const tins = [];
      for (const site of sites) {
        const at = tin.get(site.scope);
        if (at !== undefined) tins.push(at);
      }
      tins.sort((x, y) => x - y);
      info = { sites, inner, outside, tins };
      siteCache.set(binding, info);
      return info;
    }

    function resolveFrom(scope, name) {
      for (let s = scope; s; s = parentOf.get(s)) {
        const binding = names.get(s)?.get(name);
        if (binding) return binding;
      }
      return null;
    }

    function anyInRange(sorted, lo, hi) {
      let l = 0;
      let h = sorted.length;
      while (l < h) {
        const m = (l + h) >> 1;
        if (sorted[m] < lo) l = m + 1;
        else h = m;
      }
      return l < sorted.length && sorted[l] <= hi;
    }

    function isSafeRename(binding, newName) {
      if (!isValidBindingName(newName) || globals.has(newName)) return false;
      const info = siteInfo(binding);
      if (info.outside) return false;
      for (const home of homes.get(binding) || [binding.scope]) {
        const other = names.get(home)?.get(newName);
        if (other && other !== binding) return false;
      }
      for (const s of info.inner) {
        const other = names.get(s)?.get(newName);
        if (other && other !== binding) return false;
      }
      const outer = resolveFrom(parentOf.get(binding.scope), newName);
      if (outer && outer !== binding) {
        const lo = tin.get(binding.scope);
        const hi = tout.get(binding.scope);
        if (lo === undefined || anyInRange(siteInfo(outer).tins, lo, hi)) return false;
      }
      return true;
    }

    function applyRename(binding, oldName, newName) {
      const info = siteInfo(binding);
      for (const site of info.sites) {
        for (const node of site.nodes) {
          if (node && node.name === oldName) node.name = newName;
        }
        const ref = site.ref;
        if (ref && ref.parent?.type === "ObjectProperty" && ref.parent.shorthand &&
            ref.parent.value === ref.node) {
          ref.parent.shorthand = false;
        }
      }
      for (const home of homes.get(binding) || [binding.scope]) {
        const table = names.get(home);
        if (!table) continue;
        if (table.get(oldName) === binding) table.delete(oldName);
        table.set(newName, binding);
      }
    }

    // ------------------------------------------------------------------
    // PASS 2: en yüksek güvenden başlayarak uygula (eşit güvende PASS 1 sırası)
    // ------------------------------------------------------------------
    pendingRenames.sort((a, b) => b.confidence - a.confidence);

    const appliedMappings = {};
    const renamedKeys = new Set();
    let renameCount = 0;
    let shadowSkipped = 0;
    let shadowSuffixed = 0;
    let exportSkipped = 0;

    for (const rename of pendingRenames) {
      if (renamedKeys.has(rename.key)) continue;
      try {
        if (isExportedDeclaration(rename.binding)) {
          exportSkipped++;
          continue;
        }
        let chosen = null;
        for (let suffix = 0; suffix <= 5 && chosen === null; suffix++) {
          const candidate = suffix === 0 ? rename.newName : `${rename.newName}_${suffix}`;
          if (isSafeRename(rename.binding, candidate)) chosen = candidate;
        }
        if (chosen === null) {
          shadowSkipped++;
          console.error(`[apply-names] SHADOW SKIP: ${rename.oldName} -> ${rename.newName} in ${rename.scopeId}`);
          continue;
        }
        if (chosen !== rename.newName) shadowSuffixed++;
        applyRename(rename.binding, rename.oldName, chosen);
        renamedKeys.add(rename.key);
        renameCount++;
        appliedMappings[rename.key] = { from: rename.oldName, to: chosen };
      } catch (err) {
        errors.push(`Rename basarisiz ${rename.oldName}->${rename.newName} in ${rename.scopeId}: ${err.message}`);
      }
    }

    console.error(`[apply-names] Rename sonuc: ${renameCount} basarili, ${shadowSkipped} shadow-skip, ${shadowSuffixed} shadow-suffix, ${exportSkipped} export-skip`);

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
      export_skipped: exportSkipped,
      mappings: appliedMappings,
      output: DRY_RUN ? null : outputPath,
      dry_run: DRY_RUN,
      min_confidence: MIN_CONFIDENCE,
      errors,
    });
  }
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
