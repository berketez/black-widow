# Feature Adoption Plan: Acik Kaynak RE Araclari -> Karadul v1.0

**Tarih:** 2026-03-23
**Hazirlayan:** Architect Agent
**Referanslar:** `OPEN_SOURCE_RE_TOOLS_ANALYSIS.md`, `IMPOSSIBLE-RE-MATH-ANALYSIS.md`, `PLAN_80_PERCENT.md`, `RE-ANTI-TECHNIQUES-RESEARCH.md`
**Kapsam:** 10 arac analizi + LLM strateji

---

## YONETICI OZETI

10 acik kaynak RE araci incelendi. Her birinin en guclu ozelligi, Karadul'daki mevcut karsiliği ve entegrasyon plani asagida. Sonucta 3 katmanli bir strateji cikariyorum:

1. **Hizli Kazanim (1-2 hafta):** webcrack visitor-merge, synchrony API gecisi, de4js eval decoder, r2pipe binary string xref
2. **Orta Vadeli (3-6 hafta):** angr CFGFast entegrasyonu, Ghidra script zenginlestirme, JStillery partial evaluation, Binary Ninja IL konseptinden ogrenerek multi-pass simplification
3. **LLM Katmani (paralel):** Local LLM ile batch function naming -- Cloud'a alternatif

**En yuksek ROI siralama:**

| # | Kaynak Arac | Ozellik | Karadul'a Etkisi | ROI (1-5) | Efor |
|---|-------------|---------|------------------|-----------|------|
| 1 | webcrack | Visitor-merge batch transform | JS deobf 3-5x hizlanma | 5 | 1-2 gun |
| 2 | radare2 | r2pipe string xref + CFG | Ghidra string xref bug'una alternatif | 5 | 1 gun |
| 3 | synchrony | Node.js API gecisi | Daha esnek obfuscator.io deobf | 4 | 0.5 gun |
| 4 | angr | CFGFast indirect jump resolution | Binary analiz dogrulugu %10-15 artisi | 4 | 3-4 gun |
| 5 | Ghidra | HighFunction SSA + bidirectional type propagation | C type recovery kalitesi 2x | 4 | 3-5 gun |
| 6 | de4js | Eval unpacker + auto-detect | Ek JS packer destegi | 3 | 1 gun |
| 7 | JStillery | Partial evaluation deobf | Dinamik JS deobfuscation | 3 | 2-3 gun |
| 8 | Binary Ninja | MLIL/HLIL konsepti | Multi-pass simplification framework | 3 | 5-8 gun |
| 9 | RetDec | Katmanli ceviri stratejisi | "Unresolved marker" sistemi | 2 | 3-4 gun |
| 10 | Cutter | Ghidra decompiler entegrasyonu | Karadul'da zaten Ghidra var | 1 | N/A |

---

## 1. RetDec (Avast) -- LLVM-Based C/C++ Decompiler

### En Guclu Ozelligi
**Katmanli Ceviri Stratejisi (Capstone2LlvmIr):** Her assembly instruction'i 4 seviyede cevirir:
1. Tam semantik LLVM IR
2. LLVM intrinsic fonksiyon
3. Pseudo-assembly (`__asm_xxx()`)
4. Kasitli atlama

Bu "ceviremedigini isaretle, gerisini temiz tut" yaklasimidir. RetDec, baskalarinin "her seyi cevirmeye calisip batirma" hatasina dusmez.

### Karadul'da Bu Var mi?
Kismen. `c_type_recoverer.py` confidence skorlari ile katmanli analiz yapiyor. Ancak Karadul'un reconstruction modulleri basarisiz olunca sessizce atliyor -- explicit "unresolved" marker birakilmiyor.

### Nasil Ekleriz?
```
Degisiklik: karadul/reconstruction/c_namer.py, binary_name_extractor.py
Konsept: "Unresolved Marker" sistemi

1. Her naming stratejisi basarisiz olunca `UNRESOLVED_<reason>` tag biraksin
   - UNRESOLVED_NO_STRING_CONTEXT
   - UNRESOLVED_NO_CALLEE_MATCH
   - UNRESOLVED_AMBIGUOUS_TYPE (birden fazla aday esit confidence)
2. Sonraki pass'ler bu tag'leri gorup hedefe alsin
3. Final raporda unresolved dagilimi goster -- hangi strateji nerede basarisiz?
```

### ROI: 2/5
RetDec "limited maintenance" modunda. Kodunu almak yerine FIKIRLERINI almak mantikli. Unresolved marker sistemi 3-4 gun efor, orta etki.

**Lisans:** MIT -- uyumlu.

---

## 2. Ghidra (NSA) -- Zaten Kullaniyoruz, Ek Script'ler

### En Guclu Ozelligi
**Rule-Based Iteratif Simplification + Bidirectional Type Propagation.**

Ghidra'nin decompiler engine'i iki yonlu tip yayilimi yapar (ileri + geri) ve her Rule bir `applyOp()` implement edip fixed-point'e kadar tekrar eder. Bu, Karadul'un tek yonlu tek gecisli pipeline'indan onemli olcude guclu.

### Karadul'da Bu Var mi?
- **Ghidra kullanimi:** VAR. `analyzeHeadless` ile decompile, string extraction, function listing yapiyoruz.
- **HighFunction API kullanimi:** YOK. Ghidra'nin SSA form, P-code sorgulama, tip yayilim API'sini kullanmiyoruz.
- **Bidirectional type propagation:** YOK. `c_type_recoverer.py` tek yonlu calisiyor.

### Hangi Ek Script'ler Ekleriz?

| # | Script | Amac | Dosya | Oncelik |
|---|--------|------|-------|---------|
| G1 | `extract_ssa_info.py` | Her fonksiyon icin SSA form: variable definitions, phi nodes, def-use chains | `karadul/ghidra/scripts/` | YUKSEK |
| G2 | `extract_pcode_ops.py` | P-code operation listesi: CPUI_CALL, CPUI_LOAD, CPUI_STORE dagilimi | `karadul/ghidra/scripts/` | ORTA |
| G3 | `extract_type_info.py` | Ghidra'nin kendi type inference sonuclarini dump et (HighVariable.getDataType()) | `karadul/ghidra/scripts/` | YUKSEK |
| G4 | `extract_call_graph_deep.py` | Fonksiyonlar arasi cagri grafigi + parametre tipleri + return tipleri | `karadul/ghidra/scripts/` | YUKSEK |
| G5 | `xref_string_to_function.py` | String -> fonksiyon xref haritasi (S1 bug fix icin) | `karadul/ghidra/scripts/` | KRITIK |

**G5 EN ONCELIKLI:** `PLAN_80_PERCENT.md`'deki Steam S1 adimi (Ghidra String XREF fix) buna bagimli. Mevcut `string_extractor.py` string'leri topluyor ama fonksiyona baglamiyor. `getReferencesTo()` API'si kullanilmali.

### Bidirectional Type Propagation Entegrasyonu
```
Dosya: karadul/reconstruction/c_type_recoverer.py

Mevcut (tek yonlu):
  kullanim -> tip cikarim
  ornek: param1 ile printf cagiriliyorsa -> param1 char* olabilir

Eklenecek (geri yayilim):
  fonksiyon return tip -> caller'daki degiskene tip propagasyonu
  ornek: fonksiyon int donduruyorsa, caller'da `x = call_func()` -> x int

Uygulama:
  1. Ghidra'nin HighFunction.getLocalSymbolMap() + getReturnType() ciktisini topla
  2. Call graph uzerinde BFS: her callee'nin return tipini caller'a yay
  3. Conflict varsa (iki farkli callee farkli tip) -> daha yuksek confidence kazanir
  4. Fixed-point: yeni tip bilgisi baska propagasyonu tetiklerse tekrar et
```

### ROI: 4/5
G5 (xref fix) 1 gun efor, buyuk etki (Steam %8 artis). Bidirectional type prop 3-5 gun, orta-yuksek etki.

**Lisans:** Apache 2.0 -- uyumlu.

---

## 3. radare2/rizin -- Scriptable RE Framework

### En Guclu Ozelligi
**r2pipe: 22 dilde scriptable, sub-saniye analizler.** radare2'nin en buyuk gucu Ghidra'nin zayif kaldigi yerde: HIZLI, HAFIF, TAM SCRIPTABLE. Ghidra headless 2-5 dakika baslatma suresi + JVM overhead. r2 saniyeler icinde acilir.

Ozellikle:
- `axt` (cross-reference to) komutu: String -> fonksiyon xref'i 100ms'de
- `afl` (function list): Hizli fonksiyon listesi
- `izzz` (string search): Multi-encoding string tarama
- `ahi` (hint info): Instruction-level annotation
- `agf` (function graph): ASCII CFG

### Karadul'da Bu Var mi?
`ToolPaths.radare2` config'de tanimli ama HICBIR YERDE KULLANILMIYOR. r2 installed but unused.

### Nasil Ekleriz?

**Birincil kullanim: Ghidra string xref bug'una hizli alternatif**

```python
# Yeni dosya: karadul/analyzers/r2_bridge.py

import r2pipe
import json

class R2Bridge:
    """radare2 ile hizli binary analiz -- Ghidra'yi tamamlayici."""

    def __init__(self, binary_path: str):
        self.r2 = r2pipe.open(binary_path, flags=["-2"])  # stderr suppress
        self.r2.cmd("aaa")  # Tam analiz (30s-2dk, Ghidra'dan 5-10x hizli)

    def get_string_xrefs(self) -> dict[str, list[str]]:
        """String -> referans veren fonksiyon(lar) haritasi.
        Ghidra string_extractor.py'nin bulamadigi xref'leri bununla yakala.
        """
        strings = json.loads(self.r2.cmd("izzj"))  # Tum string'ler JSON
        xref_map = {}
        for s in strings:
            addr = s.get("vaddr", 0)
            refs = json.loads(self.r2.cmd(f"axtj {addr}"))
            if refs:
                func_names = [r.get("fcn_name", f"fcn.{r['from']:08x}") for r in refs]
                xref_map[s.get("string", "")] = func_names
        return xref_map

    def get_function_cfg(self, func_addr: int) -> dict:
        """Fonksiyonun CFG'sini don -- CFF deflattening icin girdi."""
        return json.loads(self.r2.cmd(f"agfj @ {func_addr}"))

    def close(self):
        self.r2.quit()
```

**Ikincil kullanim: Binary diff icin hizli hash**

```python
def get_function_hashes(self) -> dict[str, str]:
    """Her fonksiyonun byte hash'i -- bindiff icin hizli prefilter."""
    funcs = json.loads(self.r2.cmd("aflj"))
    return {f["name"]: f.get("sha256", "") for f in funcs}
```

### ROI: 5/5
r2pipe kurulu (`pip install r2pipe`), r2 zaten kurulu. 1 gun efor, string xref + hizli CFG. Ghidra'nin 2-5 dk baslatma surecine alternatif.

**Lisans:** LGPL-3.0 -- runtime dependency olarak uyumlu.

---

## 4. Binary Ninja -- MLIL/HLIL Multi-Level IL

### En Guclu Ozelligi
**4 katmanli IL hierarchy:** LLIL -> MLIL -> HLIL -> Decompiler output. Her katman progressif soyutlama saglar:

| IL | Soyutlama | Ornek |
|----|-----------|-------|
| LLIL | Register-level | `eax = [esp + 0x4]` |
| MLIL | Variable-level, stack soyutlanmis | `var_4 = arg1` |
| HLIL | C-benzeri, dead code temizlenmis | `int result = input;` |
| Decompiler | Okunabilir C | `int result = input;` |

Karadul icin en degerli ogretim: **her transform'un hangi IL seviyesinde yapilacagini bilmek.**

### Karadul'da Bu Var mi?
Dogrudan yok (Binary Ninja ticari, entegrasyon anlamsiz). Ama KONSEPT olarak benzer bir yaklasim Karadul'un binary pipeline'inda eksik. Simdiki akis:

```
Binary -> Ghidra decompile -> tek seviye C output -> isim/tip recovery
```

Olmasi gereken:
```
Binary -> Ghidra P-code (LLIL benzeri)
       -> SSA form (MLIL benzeri)
       -> simplified C (HLIL benzeri)
       -> isim/tip recovery
```

### Nasil Ekleriz?
Binary Ninja'nin kendisini degil, IL katmanlama FIKRINI uyguluyoruz:

```
Dosya: karadul/reconstruction/multi_pass_simplifier.py

class MultiPassSimplifier:
    """Binary decompilation ciktisini katmanli basitlestir.
    Binary Ninja'nin LLIL->MLIL->HLIL felsefesinden esinlenmis.
    """

    def simplify(self, ghidra_output: str) -> str:
        # Pass 1 (LLIL-level): Register/stack ref temizleme
        result = self._clean_register_refs(ghidra_output)

        # Pass 2 (MLIL-level): Variable recovery, stack -> local var
        result = self._recover_variables(result)

        # Pass 3 (HLIL-level): Dead code elimination, constant folding
        result = self._eliminate_dead_code(result)
        result = self._fold_constants(result)

        # Pass 4 (Decompiler-level): Readable C formatting
        result = self._format_readable(result)

        return result
```

Bu yapiya mevcut `c_namer.py` ve `c_type_recoverer.py`'nin ciktilari entegre edilir.

### ROI: 3/5
Konseptualleri onemli ama uygulama eforu yuksek (5-8 gun). Binary Ninja'nin kendisi entegre edilmiyor, sadece felsefesi.

**Lisans:** Ticari -- entegrasyon yok, sadece konsept ilhami.

---

## 5. angr -- Symbolic Execution + CFG Recovery

### En Guclu Ozelligi
**CFGFast algoritmasinin indirect jump resolution'i.** 4 asamali CFG recovery:
1. Symbol table + prologue scanning
2. Queue-based VEX/P-code lifting
3. **JumpTableResolver:** Pattern tanima -> constant propagation -> index range -> bellekten target okuma
4. Pasif tarama: entropy/pattern ile kacirilmis bolgeleri bul

Ikinci guclu ozellik: **Claripy (Z3 frontend) ile opaque predicate cozumleme.**

### Karadul'da Bu Var mi?
- CFG recovery: Tamamen Ghidra'ya bagimli. Ghidra bulamazsa bulunamaz.
- Symbolic execution: YOK. `opaque_predicate.py` heuristic-based (pattern matching).
- Z3 solver: YOK.

### Nasil Ekleriz?

**Faz 1: CFGFast "second opinion" (3-4 gun)**

```python
# Degisiklik: karadul/analyzers/binary_intelligence.py
# Yeni dosya: karadul/analyzers/angr_bridge.py

import angr

class AngrBridge:
    """angr ile Ghidra'yi tamamlayici binary analiz."""

    def __init__(self, binary_path: str):
        # DIKKAT: angr agir dependency. Lazy import.
        self.project = angr.Project(binary_path, auto_discover=False)

    def recover_cfg(self) -> dict:
        """CFGFast ile CFG kurtarma -- Ghidra'nin bulamadigi fonksiyonlari bul."""
        cfg = self.project.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            force_smart_scan=True,
        )
        return {
            "functions": {addr: f.name for addr, f in cfg.kb.functions.items()},
            "total_nodes": len(cfg.graph.nodes()),
            "indirect_jumps_resolved": cfg.indirect_jumps_resolved,
        }

    def merge_with_ghidra(self, ghidra_functions: dict) -> dict:
        """angr ve Ghidra fonksiyon listelerini birlestir.
        Sadece Ghidra'da olmayanlari ekle -- angr'in false positive orani yuksek.
        """
        angr_funcs = self.recover_cfg()["functions"]
        new_functions = {}
        for addr, name in angr_funcs.items():
            if addr not in ghidra_functions:
                new_functions[addr] = name
        return new_functions
```

**Faz 2: Opaque Predicate Cozumleme (4-6 hafta -- Faz 3+)**

```python
from angr import Project
import claripy

def solve_opaque_predicate(project, predicate_addr: int) -> str | None:
    """Symbolic execution ile predicate'in her zaman True/False mi oldugunu test et."""
    state = project.factory.blank_state(addr=predicate_addr)
    simgr = project.factory.simgr(state)
    simgr.explore(find=predicate_addr + 0x20, avoid=predicate_addr + 0x40)

    if len(simgr.found) > 0 and len(simgr.avoid) == 0:
        return "ALWAYS_TRUE"
    elif len(simgr.found) == 0 and len(simgr.avoid) > 0:
        return "ALWAYS_FALSE"
    return None  # Gercek predicate, opaque degil
```

### Dependency Uyarisi
angr ~500MB pip install. Iki yaklasim:
- **A (Onerilen):** Lazy import + optional dependency. angr kurulu degilse bu ozellik devre disi.
- **B:** angr'in sadece `cle` + `claripy` modullerini kullan (~100MB). CFGFast olmaz ama Z3 solver olur.

### ROI: 4/5
CFGFast 3-4 gun efor, binary analiz dogrulugu %10-15 artis. Opaque predicate cozumleme daha uzun vadeli.

**Lisans:** BSD -- uyumlu.

---

## 6. Cutter -- Rizin Backend + Ghidra Decompiler GUI

### En Guclu Ozelligi
**Ghidra decompiler'ini native C++ olarak gommus (JVM'siz).** Reverse debug ozelligi (geri adim atma).

### Karadul'da Bu Var mi?
Karadul CLI-tabanli bir arac, GUI yok. Cutter'in Ghidra decompiler entegrasyonu zaten Karadul'un `analyzeHeadless` ile yaptigi ise benzer. Reverse debug ozelligi Karadul'un scope'u disinda (Frida zaten runtime analysis yapiyor).

### Nasil Ekleriz?
**Entegrasyon onerisi: YOK.** Cutter, Karadul'a ek deger saglamiyor cunku:
1. Ghidra decompiler zaten kullaniliyor
2. rizin backend = radare2 fork'u -- dogrudan r2pipe daha pratik
3. GUI gereksiz (Karadul CLI/web)

### ROI: 1/5
Karadul'a katkisi yok. radare2/rizin entegrasyonu r2pipe uzerinden yapilmali (yukaridaki Bolum 3).

---

## 7. webcrack -- JS Deobfuscation (npm)

### En Guclu Ozelligi
**Visitor-Merge Batch Transform.** N Babel transform'unu tek AST traversal'da birlestirerek 3-5x hizlanma.

Teknik detay:
```javascript
// MEVCUT (Karadul deep-deobfuscate.mjs):
applyTransform(ast, transform1);  // AST traversal #1
applyTransform(ast, transform2);  // AST traversal #2
...
applyTransform(ast, transformN);  // AST traversal #N
// N traversal!

// webcrack YAKLASIMIYLA:
applyTransforms(ast, [transform1, transform2, ..., transformN]);
// Visitor'lar merge edilir -> 1 traversal!
```

Ikinci guclu ozellik: **Safety tagging.** Her transform `safe` veya `unsafe` etiketli. Safe olanlar oncelikle calisir, hata durumunda safe noktaya geri donulur.

Ucuncusu: **isolated-vm sandbox.** String decoder fonksiyonlarini gercekten calistirarak statik analizin bulamadigi string'leri cozer.

### Karadul'da Bu Var mi?
- Visitor-merge: YOK. `deep-deobfuscate.mjs`'deki 9 faz sirali traversal yapiyor.
- Safety tagging: YOK. Tum transform'lar ayni guvenlik seviyesinde.
- Sandbox execution: YOK. `string_decryptor.py` tamamen statik analiz.

### Nasil Ekleriz?

**7a. Visitor-Merge (EN YUKSEK ONCELIK -- 1-2 gun)**

```javascript
// Dosya: scripts/deep-deobfuscate.mjs -- refactor

import { merge } from '@babel/traverse';  // veya manual merge

// Phase 1-3'u birlestir (hepsi safe):
const safeVisitors = merge([
    booleanSimplify.visitor(),
    deadCodeRemove.visitor(),
    stringConcat.visitor(),
    numericSimplify.visitor(),
]);

// Tek traversal:
traverse(ast, safeVisitors);

// Phase 4-6 (unsafe, ayri):
for (const unsafeTransform of unsafePhases) {
    traverse(ast, unsafeTransform.visitor());
}
```

Babel'in `@babel/traverse` dogrudan visitor merge desteklemiyor ama webcrack'in `mergeVisitors()` utility'sini port edebiliriz. Alternatif: `babel-plugin-macros` veya manual visitor key merge.

**7b. Safety Tagging (1 gun)**

```javascript
// Her transform'a tag ekle:
const transforms = [
    { name: "booleanSimplify", tag: "safe", visitor: ... },
    { name: "evalUnpack",      tag: "unsafe", visitor: ... },
    { name: "cfgDeflatten",    tag: "unsafe", visitor: ... },
];

// Calistirma stratejisi:
function applyWithSafety(ast, transforms) {
    const checkpoint = cloneDeep(ast);  // Safe noktasi

    // Oncellikle safe transform'lari calistir
    const safeOnes = transforms.filter(t => t.tag === "safe");
    applyTransforms(ast, safeOnes);

    // Sonra unsafe'leri tek tek calistir
    for (const t of transforms.filter(t => t.tag === "unsafe")) {
        try {
            applyTransform(ast, t);
        } catch (e) {
            console.warn(`Transform ${t.name} failed, continuing...`);
        }
    }
}
```

**7c. Sandbox Decoder Execution (2-3 gun -- Faz 2)**

```javascript
// Dosya: scripts/sandbox-decoder.mjs
import ivm from 'isolated-vm';

async function executeSandboxed(decoderCode, callExpression) {
    const isolate = new ivm.Isolate({ memoryLimit: 128 });
    const context = await isolate.createContext();

    // Decoder fonksiyonu sandbox'a yukle
    await context.eval(decoderCode);

    // Decoder'i cagir
    const result = await context.eval(callExpression);
    isolate.dispose();
    return result;
}
```

### ROI: 5/5
Visitor-merge 1-2 gun efor, 3-5x hizlanma. Safety tagging 1 gun, operasyonel guvenlik.

**Lisans:** MIT -- tam uyumlu.

---

## 8. de4js -- JS Deobfuscator (Eval/Packer/JJencode)

### En Guclu Ozelligi
**Eval unpacker + otomatik obfuscation tipi tespiti.** de4js su obfuscation turlerini cozer:
- `eval()` bazli packer'lar (Dean Edwards Packer, WiseLoop)
- Array-bazli obfuscation (Free JS Obfuscator)
- URL encode (bookmarklet)
- JSFuck, JJencode, AAencode
- Auto-detect: obfuscation turunu otomatik tespit

### Karadul'da Bu Var mi?
- eval() unpacking: `deep_pipeline.py`'de KISMEN mevcut. `deobfuscate.mjs`'de `eval` icerigi cikariyor ama tum packer tipleri desteklenmiyor.
- JSFuck/JJencode/AAencode: YOK. Bu egzotik obfuscation turleri Karadul'da tanimlanmiyor.
- Auto-detect: KISMEN. `detect_obfuscation_type()` mevcut ama sinirli.

### Nasil Ekleriz?

```javascript
// Dosya: scripts/exotic-deobfuscators.mjs
// de4js'in eval/packer/encode unpacker'larini port et

// 1. JSFuck decoder
function decodeJSFuck(code) {
    // JSFuck: sadece []()!+ karakterleri kullanir
    // eval() ile calistirarak gercek kodu elde et (sandbox icinde!)
    if (/^[\[\]()!+]+$/.test(code.trim())) {
        return sandboxEval(code);
    }
    return null;
}

// 2. Dean Edwards Packer decoder
function decodePacker(code) {
    const packerPattern = /eval\(function\(p,a,c,k,e,[dr]\)/;
    if (packerPattern.test(code)) {
        // p: packed string, a: base, c: count, k: dictionary, e/d: decode func
        return unpackPacker(code);
    }
    return null;
}

// 3. Auto-detect obfuscation type
function detectObfuscationType(code) {
    if (/^[\[\]()!+]+$/.test(code.trim())) return "jsfuck";
    if (/\$=~\[\]/.test(code)) return "jjencode";
    if (/ﾟωﾟﾉ/.test(code)) return "aaencode";
    if (/eval\(function\(p,a,c,k,e/.test(code)) return "packer";
    if (/__webpack_require__/.test(code)) return "webpack";
    if (/obfuscator\.io|_0x[a-f0-9]{4,6}/.test(code)) return "obfuscator_io";
    return "unknown";
}
```

### ROI: 3/5
JSFuck/JJencode karsilasma olasiligi dusuk ama eval packer cok yaygin. 1 gun efor.

**Lisans:** MIT -- tam uyumlu.

---

## 9. synchrony -- AST-Based JS Deobfuscator (obfuscator.io)

### En Guclu Ozelligi
**obfuscator.io'ya ozel, derinlemesine hedefli deobfuscation.** synchrony genel amacli degil -- tek bir obfuscator'a odaklanmis ve onu cok iyi cozer:
- String array detection + rotation/shuffle handling
- Control flow deobfuscation (obfuscator.io'nun CFF implementasyonuna ozel)
- Calculator deobfuscation (aritmetik ifade basitlestirme)
- Dead code removal

### Karadul'da Bu Var mi?
EVET -- `synchrony_wrapper.py` CLI olarak cagiriyor. Ama:
1. CLI overhead: subprocess baslatma, dosya I/O, sonuc okuma
2. Hangi transformer'larin calistigini bilemiyoruz
3. Hata durumunda detay yok

### Nasil Ekleriz?

**CLI -> Node.js API gecisi (0.5 gun)**

```javascript
// Dosya: scripts/synchrony-api.mjs
// synchrony'yi CLI yerine API olarak kullan

const { deobfuscate } = require('deobfuscator');  // synchrony'nin npm paketi

export async function deobfuscateWithSynchrony(code, options = {}) {
    const result = await deobfuscate(code, {
        ecmaVersion: 2022,
        transformers: options.transformers || [
            'Simplify',
            'jsc-controlflow',
            'jsc-calculator',
            'DeadCode'
        ],
    });

    return {
        code: result.code,
        transformersApplied: result.transformersApplied,  // Hangileri calisti?
        stats: result.stats,  // Kac node degisti?
    };
}
```

**Mevcut wrapper'i guncelle:**

```python
# Dosya: karadul/deobfuscators/synchrony_wrapper.py
# CLI cagrisi yerine Node.js script cagir

async def deobfuscate(self, code: str) -> DeobfuscationResult:
    # Eski: subprocess.run(["synchrony", "deobfuscate", tmpfile])
    # Yeni: subprocess.run(["node", "scripts/synchrony-api.mjs", tmpfile])
    # Avantaj: transformer detaylari, stats, hata mesajlari JSON olarak donuyor
```

### ROI: 4/5
0.5 gun efor, daha iyi kontrol ve debug yetenegi.

**Lisans:** GPL-3.0 -- DIKKAT. Runtime dependency OK, kod kopyalama YAPILAMAZ.

---

## 10. JStillery -- JS Dynamic Analysis via Partial Evaluation

### En Guclu Ozelligi
**Partial Evaluation ile dinamik deobfuscation.** JStillery programi ikiye boler:
1. **Statik kisim:** Derleme zamaninda bilinen degerleri hesaplar (reduce)
2. **Dinamik kisim:** Runtime'a bagli kismi oldugu gibi birakir

Bu, webcrack/synchrony'nin tamamen statik AST transform'larindan farkli bir yaklasim. Ozellikle:
- Self-modifying JS kodunu cozer (eval chain'leri)
- Runtime-dependent string concatenation'lari basitlestirir
- DOM-bagimsiz kisimdan DOM-bagimli kismi ayirir

### Karadul'da Bu Var mi?
YOK. Karadul'un JS pipeline'i tamamen statik (AST transform). Dinamik analiz sadece Frida ile (binary tarafinda).

### Nasil Ekleriz?

```javascript
// Dosya: scripts/partial-eval.mjs
// JStillery'nin partial evaluation mantigi -- basitlestirilmis port

import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';

function partialEvaluate(ast) {
    traverse(ast, {
        // Sabit ifadeleri hesapla
        BinaryExpression(path) {
            if (t.isNumericLiteral(path.node.left) && t.isNumericLiteral(path.node.right)) {
                const result = eval(`${path.node.left.value} ${path.node.operator} ${path.node.right.value}`);
                path.replaceWith(t.numericLiteral(result));
            }
        },

        // eval() icindeki sabit string'i ac
        CallExpression(path) {
            if (t.isIdentifier(path.node.callee, { name: 'eval' }) &&
                t.isStringLiteral(path.node.arguments[0])) {
                const innerAST = parse(path.node.arguments[0].value);
                path.replaceWith(innerAST.program.body[0]);
            }
        },

        // Sabit fonksiyon cagrilarini inline et
        // (fonksiyon govdesi side-effect free ise)
    });
}
```

### ROI: 3/5
Partial evaluation kavrami guclu ama uygulama karmasik. 2-3 gun efor, orta etki.

**Lisans:** GPL-3.0 -- DIKKAT. Konsepti al, kodu KOPYALAMA. Sifirdan yaz.

---

## ARACLARIN KARSILASTIRMALI OZET TABLOSU

| Arac | En Guclu Ozellik | Karadul'da Var mi? | Entegrasyon | Efor | Etki | ROI |
|------|-------------------|---------------------|-------------|------|------|-----|
| RetDec | Katmanli ceviri + unresolved marker | Kismen | Konsept adapte | 3-4 gun | Orta | 2/5 |
| Ghidra | Bidirectional type prop + Rule framework | Ghidra var, bu ozellikler yok | G1-G5 script'ler + c_type_recoverer refactor | 4-6 gun | Yuksek | 4/5 |
| radare2 | r2pipe hizli scriptable analiz | Installed but unused | r2_bridge.py + string xref | 1 gun | Yuksek | 5/5 |
| Binary Ninja | MLIL/HLIL katmanli IL | Konsept yok | multi_pass_simplifier.py | 5-8 gun | Orta | 3/5 |
| angr | CFGFast + Z3 symbolic execution | Yok | angr_bridge.py + opaque_predicate refactor | 3-6 gun | Yuksek | 4/5 |
| Cutter | Ghidra decomp + rizin backend | Ghidra zaten var | Gerekmiyor | N/A | Yok | 1/5 |
| webcrack | Visitor-merge + safety tags + sandbox | Yok | deep-deobfuscate.mjs refactor | 2-4 gun | Cok Yuksek | 5/5 |
| de4js | Eval/packer/JSFuck auto-detect | Kismen | exotic-deobfuscators.mjs | 1 gun | Orta | 3/5 |
| synchrony | obfuscator.io derinlemesine hedefli | CLI wrapper var | API gecisi | 0.5 gun | Orta | 4/5 |
| JStillery | Partial evaluation deobf | Yok | partial-eval.mjs | 2-3 gun | Orta | 3/5 |

---

## UYGULAMA YOL HARITASI

### Faz 0: Aninda Kazanimlar (Bu hafta, 3 gun)

| # | Gorev | Arac | Dosya | Efor |
|---|-------|------|-------|------|
| F0.1 | r2pipe string xref -- Ghidra S1 bug'a alternatif | radare2 | `karadul/analyzers/r2_bridge.py` | 1 gun |
| F0.2 | synchrony CLI -> API gecisi | synchrony | `scripts/synchrony-api.mjs` + wrapper guncelle | 0.5 gun |
| F0.3 | webcrack visitor-merge POC | webcrack | `scripts/deep-deobfuscate.mjs` refactor | 1.5 gun |

### Faz 1: JS Pipeline Guclendir (Hafta 2, 4 gun)

| # | Gorev | Arac | Dosya | Efor |
|---|-------|------|-------|------|
| F1.1 | Safety tagging tum transform'lara | webcrack | `scripts/deep-deobfuscate.mjs` | 1 gun |
| F1.2 | Eval packer + auto-detect | de4js | `scripts/exotic-deobfuscators.mjs` | 1 gun |
| F1.3 | Partial evaluation (basit) | JStillery | `scripts/partial-eval.mjs` | 2 gun |

### Faz 2: Binary Pipeline Guclendir (Hafta 3-4, 8 gun)

| # | Gorev | Arac | Dosya | Efor |
|---|-------|------|-------|------|
| F2.1 | Ghidra G5: xref_string_to_function | Ghidra | `karadul/ghidra/scripts/` | 1.5 gun |
| F2.2 | Ghidra G1+G3: SSA + type dump | Ghidra | `karadul/ghidra/scripts/` | 2 gun |
| F2.3 | angr CFGFast bridge | angr | `karadul/analyzers/angr_bridge.py` | 3 gun |
| F2.4 | Bidirectional type prop | Ghidra konsept | `karadul/reconstruction/c_type_recoverer.py` | 1.5 gun |

### Faz 3: Ileri Seviye (Hafta 5-8, 10 gun)

| # | Gorev | Arac | Dosya | Efor |
|---|-------|------|-------|------|
| F3.1 | Sandbox decoder execution | webcrack | `scripts/sandbox-decoder.mjs` | 2 gun |
| F3.2 | Multi-pass simplifier | Binja konsept | `karadul/reconstruction/multi_pass_simplifier.py` | 3 gun |
| F3.3 | Unresolved marker sistemi | RetDec konsept | `karadul/reconstruction/c_namer.py` + `binary_name_extractor.py` | 2 gun |
| F3.4 | Opaque predicate Z3 cozumleme | angr | `karadul/deobfuscators/opaque_predicate.py` | 3 gun |

---

## LLM STRATEGY: TEORIK SINIR VS LLM POTANSIYELI

### Mevcut Durum: LLM'siz Sinirlar

Codex-Consultant raporundan (`IMPOSSIBLE-RE-MATH-ANALYSIS.md`) ve PLAN_80_PERCENT.md'den cikarimlar:

| Hedef | Tip | LLM'siz Mevcut | LLM'siz Teorik Tavan | LLM ile Potansiyel |
|-------|-----|-----------------|----------------------|---------------------|
| Rectangle | Swift binary | %75 | %90 | %93-95 |
| Cursor | JS minified | %82 | %90 | %94-96 |
| Claude Code | JS esbuild | %55 | %80 | %88-92 |
| Steam | C++ binary | %18 | %54 | %65-70 |

**Teorik sinirlar:**

1. **JS (npm match varsa):** %90+ mumkun LLM'siz. Cunku donusum (minification) coktan-bire ama kaynak esleme ile enjektif hale geliyor. npm registy'deki 2M+ paketin cogunun fingerprint'i unique.

2. **Binary (C/C++):** %54 tavan LLM'siz. Fano esitsizliginden:
   ```
   H(N|C) = 10 bit iken max accuracy = %44 (genel)
   H(N|C) = 5 bit iken max accuracy = %75 (zengin context)
   ```
   Binary'de context genellikle 8-12 bit entropy tasir -> %50-60 araliginda tavan.

3. **Swift/Go/Rust binary:** %70-80 LLM'siz. Cunku bu diller metadata-zengin (section'lar, mangling, RTTI). Metadata entropy %50-70 isim bilgisini dogrudan verir.

### LLM Kullanmanin 3 Modu

| Mod | Maliyet | Hiz | Kalite | Kullanim |
|-----|---------|-----|--------|----------|
| Cloud API (GPT-4o, Claude) | $2-5 / 10K fonksiyon | 30-60 dk | Cok yuksek (%75-85) | Kritik hedefler, tek seferlik analiz |
| Local LLM (MLX/llama.cpp) | $0 | 2-4 saat / 10K fonksiyon | Yuksek (%65-75) | Batch naming, rutin analiz |
| Fine-tuned model | $50-200 egitim + $0 inference | 1-2 saat / 10K fonksiyon | En yuksek (%80-88) | Tekrarlayan domain (oyun, C++, web) |

### Cloud LLM Maliyet Analizi

10K fonksiyon icin:

```
Her fonksiyon: ~500 token decompiled C/JS + ~100 token prompt = ~600 token input
Output: ~50 token (isim + aciklama)
Toplam: 10K * 650 = 6.5M token

GPT-4o:     $2.50/M input + $10.00/M output = $16.25 + $5.00 = $21.25
Claude 3.5: $3.00/M input + $15.00/M output = $19.50 + $7.50 = $27.00
GPT-4o-mini: $0.15/M + $0.60/M = $0.975 + $0.30 = $1.28
Gemini Flash: $0.075/M + $0.30/M = $0.49 + $0.15 = $0.64
```

**Sonuc:** GPT-4o-mini veya Gemini Flash ile batch naming makul ($0.64-$1.28 / 10K fonksiyon).

### Local LLM Stratejisi (ONERILEN)

**Donanim:** Apple Silicon M-serisi (Berke'nin Mac'i) veya RTX 4090 laptop.

**Model secimi:**

| Model | Boyut | MLX Hizi (M4 Max) | llama.cpp Hizi | Naming Kalitesi |
|-------|-------|--------------------|--------------------|-----------------|
| Qwen2.5-Coder-7B-Q8 | 8GB | ~40 tok/s | ~35 tok/s | Orta (%55-65) |
| Qwen2.5-Coder-14B-Q6 | 12GB | ~25 tok/s | ~20 tok/s | Iyi (%65-72) |
| Qwen2.5-Coder-32B-Q4 | 20GB | ~12 tok/s | ~10 tok/s | Cok Iyi (%70-78) |
| DeepSeek-Coder-V2-16B-Q6 | 12GB | ~22 tok/s | ~18 tok/s | Iyi (%63-70) |
| CodeLlama-34B-Q4 | 20GB | ~10 tok/s | ~8 tok/s | Iyi (%65-73) |

**Onerilen:** Qwen2.5-Coder-32B-Q4 (MLX formatinda).
- Mac'te 20GB RAM kullanir (64GB veya 128GB makinede rahat calisir)
- RTX 4090'da 16GB VRAM'e sigar
- Naming kalitesi Cloud GPT-4o-mini'ye yakin

**10K fonksiyon suresini hesaplayalim:**

```
Her fonksiyon: ~600 token input + ~50 token output
Qwen2.5-Coder-32B-Q4 @ MLX:
  Prefill: ~600 tok * (1/200 tok/s prompt processing) = 3s
  Decode: ~50 tok * (1/12 tok/s) = 4.2s
  Toplam: ~7.2s/fonksiyon

10K fonksiyon: 10000 * 7.2s = 72,000s = 20 saat (SERI)

Batch optimization ile:
  - 4 parallel request (M4 Max 128GB'da mumkun): 5 saat
  - Context caching (ayni binary'den gelen fonksiyonlar benzer): 3-4 saat
  - Pre-filtering (zaten isimli/trivial fonksiyonlari atla): sadece ~4K fonksiyon kalir -> 1.5-2 saat
```

**Gercekci sure: 1.5-3 saat / 10K fonksiyon, $0 maliyet.**

RTX 4090'da (Berke'nin laptop'u):
```
  Qwen2.5-Coder-32B-Q4 @ CUDA:
  Prefill: ~600 tok * (1/1000 tok/s) = 0.6s
  Decode: ~50 tok * (1/40 tok/s) = 1.25s
  Toplam: ~1.85s/fonksiyon
  4K fonksiyon (filtered): 7400s = ~2 saat (SERI), ~30 dk (8 parallel)
```

### LLM Pipeline Mimarisi

```
Binary/JS Target
      |
      v
[Karadul Deterministic Pipeline]
  - Source matching (%90+ npm, %70+ library)
  - String/API/callee heuristic naming
  - Type recovery
  - RTTI/mangling
      |
      v
[Remaining Unnamed Functions]
  ~30-40% of total (after deterministic pipeline)
      |
      v
[LLM Naming Pipeline] (OPTIONAL, user flag: --llm-naming)
      |
      +---> [Batch Prompt Generator]
      |       - Decompiled code + context window
      |       - Known callee names (propagated)
      |       - String literals in scope
      |       - Type information
      |       |
      |       v
      +---> [LLM Backend] (configurable)
      |       - MLX local (default)
      |       - llama.cpp / Ollama
      |       - OpenAI API
      |       - Anthropic API
      |       |
      |       v
      +---> [Result Validator]
      |       - Isim kalitesi kontrolu (camelCase? anlam var mi?)
      |       - Duplicate check (ayni ismi baska fonksiyona da verdi mi?)
      |       - Confidence threshold (low conf -> UNRESOLVED birak)
      |       |
      |       v
      +---> [Name Merger] (mevcut name_merger.py ile entegre)
              - LLM onerisi vs deterministic isim conflict -> deterministic kazanir
              - LLM onerisi vs isimsiz -> LLM ismi kabul, confidence=medium
```

### LLM'siz Tavana Yaklasma Stratejisi

LLM kullanmadan teorik tavanlara nasil yaklasiliriz:

**JS icin (%90 tavana yaklasma):**
1. npm fingerprint DB genislet: Top 10K npm paketinin hash'leri -> %85-88
2. webpack/esbuild module ID -> name mapping -> +%3-4
3. Export name backpropagation -> +%2
4. DTS cross-match -> +%1-2
5. **Tahmini sonuc: %88-92 (LLM'siz)**

**Binary icin (%54 tavana yaklasma):**
1. FLIRT + byte pattern DB genislet: x86_64 + ARM64 Homebrew -> %25-30
2. RTTI vtable chain extraction -> +%5-6
3. String xref propagation (r2pipe/Ghidra fix) -> +%8-10
4. Debug path grouping -> +%3-4
5. Callee combo DB 30 -> 200+ -> +%3
6. **Tahmini sonuc: %44-53 (LLM'siz)**

**Fark:** JS'de kaynak esleme mumkun oldugu icin tavan yuksek. Binary'de bilgi kaybı (inlining, optimization) geri alinamaz -- LLM bu kaybi "tahmin" ederek doldurur.

### Pratik Oneri

```
Faz 1 (Simdi): LLM'siz pipeline'i maksimize et
  - PLAN_80_PERCENT.md'deki adimlari tamamla
  - Bu dokumandaki Faz 0-2 adimlari uygula
  - Hedef: JS %88+, Binary %45+

Faz 2 (2-3 hafta sonra): Local LLM entegrasyonu
  - Qwen2.5-Coder-32B-Q4 MLX formatinda indir
  - batch naming pipeline yaz
  - Sadece isimsiz kalan fonksiyonlara uygula
  - Hedef: JS %92+, Binary %60+

Faz 3 (Opsiyonel): Fine-tuned model
  - Karadul'un urettigi (isim, decompiled_code) ciftlerinden egitim seti olustur
  - Qwen2.5-Coder-7B'yi fine-tune et (LoRA, 4-8 saat RTX 4090'da)
  - Domain-specific naming kalitesi artisi
  - Hedef: Binary %65-70
```

### sentinel-reverse Entegrasyonu

GitHub'da `sgInnora/sentinel-reverse` projesi Apple MLX ile binary RE yapiyor:
- 6 task-specific prompt template
- Local LLM inference
- MPS GPU acceleration

Bu proje Karadul'un LLM pipeline'i icin referans olabilir. Ama dogrudan kullanilmaz -- Karadul'un pipeline'i cok daha kapsamli ve farkli bir mimaride.

---

## RISK ANALIZI VE UYARILAR

### Dependency Riskleri

| Dependency | Boyut | Risk | Mitigation |
|------------|-------|------|------------|
| angr | ~500MB | YUKSEK | Optional dependency, lazy import |
| r2pipe | ~1MB | DUSUK | Minimal, r2 zaten kurulu |
| isolated-vm | ~20MB | ORTA | Sadece sandbox deobf icin |
| Qwen2.5-Coder-32B | ~20GB | YUKSEK | Ayri indirme, optional |

### Lisans Uyarisi

| Arac | Lisans | Karadul Uyumu | Not |
|------|--------|---------------|-----|
| RetDec | MIT | Uyumlu | Konsept al, kod kopyala OK |
| Ghidra | Apache 2.0 | Uyumlu | Script'ler Ghidra'nin parcasi |
| radare2 | LGPL-3.0 | Runtime OK | Kod kopyalama: DIKKAT |
| Binary Ninja | Ticari | Sadece konsept | Entegrasyon YOK |
| angr | BSD | Uyumlu | Kod kopyala OK |
| webcrack | MIT | Uyumlu | Kod kopyala OK |
| de4js | MIT | Uyumlu | Kod kopyala OK |
| synchrony | GPL-3.0 | Runtime OK | Kod kopyalama: HAYIR |
| JStillery | GPL-3.0 | Runtime OK | Kod kopyalama: HAYIR, sifirdan yaz |

### Kapsam Kontrolu

Bu plandaki tum adimlar TOPLAM 25+ gun efor. Berke'nin "kapsam buyutme" egilimi goz onunde bulundurularak:

**ONCELIK SIRASI (kesinlikle bu sirada yapilmali):**
1. F0.1 (r2pipe xref) -- 1 gun, Steam icin kritik
2. F0.3 (webcrack visitor-merge) -- 1.5 gun, JS icin kritik
3. F0.2 (synchrony API) -- 0.5 gun, hizli kazanim
4. F2.1 (Ghidra G5 xref) -- 1.5 gun, Steam icin kritik
5. PLAN_80_PERCENT.md'deki adimlar -- bunlar oncelikli

Geri kalan adimlar ancak bu 5 tamamlandiktan sonra.

---

## SONUC

10 acik kaynak RE aracinin en iyi ozellikleri incelendi. Karadul'a entegrasyon icin 3 katmanli strateji belirlendi:

1. **Hizli kazanimlar** (r2pipe, webcrack visitor-merge, synchrony API) -- 3 gunde 3-5x JS hizlanma + binary string xref cozumu
2. **Orta vadeli** (angr CFGFast, Ghidra SSA/type, sandbox deobf) -- binary analiz dogrulugu %10-15 artis
3. **LLM katmani** (Local Qwen2.5-Coder-32B) -- LLM'siz %54 binary tavanindan %65-70'e cikmak icin tek yol

En onemli ogretim: **Hicbir araci butun olarak almak mantikli degil.** Her aracin TEK EN IYI ozelligini secerek Karadul'un mevcut pipeline'ina entegre etmek dogru yaklasim.
