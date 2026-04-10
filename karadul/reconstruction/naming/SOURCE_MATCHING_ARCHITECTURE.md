# Black Widow v1.0 -- npm Structural Matching Architecture
## Mimar: Architect Agent | 2026-03-21

---

## 1. MEVCUT DURUM ANALIZI

### node_modules Durumu

```
/opt/homebrew/lib/node_modules/@anthropic-ai/.claude-code-2DTsDk1V/
    cli.js          -- 9MB tek dosya bundle (esbuild minified)
    sdk.mjs         -- 500KB SDK
    yoga.wasm       -- WebAssembly layout engine
    node_modules/
        @img/sharp-darwin-arm64   -- sadece native image modulu
    vendor/
        ripgrep                   -- native binary
        claude-code.vsix          -- VS Code extension
```

**Sonuc:** node_modules'da orijinal npm kaynak kodu YOK. cli.js icindeki
19+ paket tek dosyada minified. Bu kaynagi dogrudan kullanaMAYIZ.

### Orijinal Kaynaklar (asar_extracted)

Claude Desktop analizi icin:
```
workspaces/Claude/.../raw/asar_extracted/node_modules/
    ws/           -- ORIJINAL kaynak (minified degil)
    node-pty/     -- ORIJINAL kaynak
    @ant/         -- Anthropic native modulleri
```

Sadece 3 paket. Gerisi bundled.

### Erisilebilir Kaynaklar

| Kaynak | Durum | Gecikme | Disk Etkisi |
|--------|-------|---------|-------------|
| node_modules (yerel) | 3 paket var | 0ms | Yok |
| unpkg.com CDN | Calisiyor, 302 redirect | ~100ms/istek | Yok (hafizada) |
| npm pack | Calisiyor (npm 11.11.0) | ~2-5s/paket | /tmp (gecici) |

---

## 2. PROBLEM TANIMLAMASI

### Problem A (COZULMUS): Modul Tespiti
"module_42.js hangi npm paketi?"
Mevcut NpmFingerprinter string-match ile yapıyor. 707 modulden ~350'sini eslestiriyor.

### Problem B (YENI): Degisken Ismi Geri Kazanimi
"Minified fonksiyon `a(b,c)` orijinalde `registerLanguage(name, lang)` mi?"

Bu problemi LLM OLMADAN, %100 deterministik cozmek istiyoruz.

---

## 3. MIMARI TASARIM

### 3.1 Dizin Yapisi

```
karadul/reconstruction/naming/
    __init__.py               -- [MEVCUT]
    result.py                 -- [MEVCUT] NamingResult, NamingManifest
    npm_fingerprinter.py      -- [MEVCUT] Hangi modul hangi paket?
    structural_analyzer.py    -- [MEVCUT] Export/class/function tespiti
    llm_namer.py              -- [MEVCUT] LLM katmani
    pipeline.py               -- [MEVCUT, DEGISECEK] Yeni katman eklenir

    source_matcher/              -- [YENI PAKET]
        __init__.py
        orchestrator.py          -- Ana pipeline: resolve -> fingerprint -> match -> map
        source_resolver.py       -- npm orijinal kaynak kodunu bul/indir
        ast_fingerprinter.py     -- JS fonksiyonlarini fingerprint'le
        structural_match.py      -- Fingerprint eslestirme algoritmasi
        name_mapper.py           -- Eslesmeden isim cikartma
        cache.py                 -- Sonuc cache (disk-based, tekrar hesaplama engelle)
```

### 3.2 Pipeline Akisi

```
                                 Pipeline Katmanlari
                                 ===================

[1] NpmFingerprinter (MEVCUT)
    module_42.js --> "Bu highlight.js@11.11.1"
    |
    | eslesen moduller + paket isimleri
    v
[2] SourceMatcher (YENI -- Bu mimari)
    |
    |-- [2a] SourceResolver
    |     Orijinal kaynak kodu bul:
    |     1. asar_extracted/node_modules/PKG/ --> var mi?
    |     2. unpkg.com/PKG@VER/dosya.js --> indir (hafizada tut)
    |     3. npm pack PKG@VER --> /tmp/karadul-cache/PKG/ --> isle --> sil
    |
    |-- [2b] ASTFingerprinter (PARALEL: minified + orijinal)
    |     Her fonksiyon icin:
    |     {arity, strings, branches, loops, returns, throws, calls, members, ...}
    |
    |-- [2c] StructuralMatcher
    |     Minified fingerprint <--> Orijinal fingerprint eslestir
    |     Sonuc: [(min_func, orig_func, score), ...]
    |
    |-- [2d] NameMapper
    |     Eslesmelerden isim haritasi olustur:
    |     {a: "registerLanguage", b: "name", c: "lang"}
    |
    | eslesen degisken isimleri
    v
[3] StructuralAnalyzer (MEVCUT)
    Kalan modulleri export/class/function isimlerinden isimlendir
    |
    v
[4] LLMNamer (MEVCUT, OPSIYONEL)
    Hala isimlendirilemeyenler icin LLM
    |
    v
[5] Conflict Resolution (MEVCUT)
```

### 3.3 ASTFingerprinter Detaylari

#### JS Parse Stratejisi

Python'da JavaScript AST parse etmek icin 3 secenek:

| Secenek | Artilari | Eksileri |
|---------|----------|---------|
| Node.js + acorn (subprocess) | En doğru, ES2024 desteği | Subprocess overhead |
| pyjsparser (pure Python) | Subprocess yok | ES6+ desteği eksik, yavaş |
| tree-sitter-javascript (C binding) | Hızlı, robust | Extra dependency |
| **Regex tabanli (onerilen)** | **Dependency yok, hizli** | **Kenar durumlarda hata** |

**KARAR: Hibrit yaklasim.**
- Birincil: Regex tabanli hizli fingerprint (mevcut StructuralAnalyzer'in genisletilmisi)
- Yedek: Node.js + acorn subprocess (buyuk/karmasik moduller icin)

Neden regex birincil? Cunku:
1. Minified kodda fonksiyon sinirlari genellikle net (`function X(` veya `=>`veya `{...}`)
2. String literal'ler minifier'dan etkilenmez -- en guvenilir sinyal
3. Dallanma sayisi (`if`, `switch`, `case`, `? :`) regex ile sayilabilir
4. Dependency eklemeden calisir

#### FunctionFingerprint Veri Yapisi

```python
@dataclass(frozen=True)
class FunctionFingerprint:
    """Bir fonksiyonun yapisal parmak izi."""

    # --- Temel metrikler ---
    arity: int                      # Parametre sayisi
    body_length: int                # Karakter sayisi (normalizasyona gore)

    # --- String sinyalleri (EN ONEMLI) ---
    string_literals: tuple[str, ...]  # Icindeki string'ler (sirali, frozen)
    regex_literals: tuple[str, ...]   # Icindeki regex pattern'ler

    # --- Kontrol akis metrikleri ---
    branch_count: int               # if + switch + ternary (? :) sayisi
    loop_count: int                 # for + while + do sayisi
    return_count: int               # return statement sayisi
    throw_count: int                # throw statement sayisi

    # --- Cagri metrikleri ---
    call_count: int                 # Fonksiyon cagrisi sayisi
    new_count: int                  # new X() sayisi
    member_access: tuple[str, ...]  # .push, .map, .filter, .call, .apply (sirali)

    # --- Yapi metrikleri ---
    has_try_catch: bool             # try/catch var mi
    nested_function_count: int      # Ic fonksiyon sayisi
    assignment_count: int           # = operatoru sayisi

    # --- Tanimlayici sinyaller ---
    property_keys: tuple[str, ...]  # Object literal key'leri ({key: val} icerisindeki key'ler)

    def similarity(self, other: 'FunctionFingerprint') -> float:
        """0.0 - 1.0 arasi benzerlik skoru.

        Agirliklar:
        - string_literals eslesmesi: %40 (en guvenilir sinyal)
        - arity eslesmesi: %10
        - branch/loop/return profili: %20
        - member_access eslesmesi: %15
        - property_keys eslesmesi: %15
        """
        score = 0.0

        # String eslesmesi (Jaccard similarity)
        s1 = set(self.string_literals)
        s2 = set(other.string_literals)
        if s1 or s2:
            string_sim = len(s1 & s2) / len(s1 | s2) if (s1 | s2) else 0.0
            score += 0.40 * string_sim
        else:
            # Iki tarafta da string yoksa, bu sinyal nötr
            score += 0.40 * (1.0 if not s1 and not s2 else 0.0)

        # Arity eslesmesi (tam eslesme veya +-1)
        if self.arity == other.arity:
            score += 0.10
        elif abs(self.arity - other.arity) == 1:
            score += 0.05  # default param eklenmis olabilir

        # Kontrol akis profili (kosinüs benzerligi)
        v1 = (self.branch_count, self.loop_count, self.return_count, self.throw_count)
        v2 = (other.branch_count, other.loop_count, other.return_count, other.throw_count)
        dot = sum(a * b for a, b in zip(v1, v2))
        mag1 = sum(a * a for a in v1) ** 0.5
        mag2 = sum(b * b for b in v2) ** 0.5
        if mag1 > 0 and mag2 > 0:
            score += 0.20 * (dot / (mag1 * mag2))
        elif mag1 == 0 and mag2 == 0:
            score += 0.20  # ikisi de sade fonksiyon

        # Member access eslesmesi (Jaccard)
        m1 = set(self.member_access)
        m2 = set(other.member_access)
        if m1 or m2:
            score += 0.15 * (len(m1 & m2) / len(m1 | m2))
        else:
            score += 0.15

        # Property keys eslesmesi (Jaccard)
        p1 = set(self.property_keys)
        p2 = set(other.property_keys)
        if p1 or p2:
            score += 0.15 * (len(p1 & p2) / len(p1 | p2))
        else:
            score += 0.15

        return round(score, 4)
```

#### Neden Bu Agirliklar?

1. **String literals %40**: Minifier string'leri DEGISTIRMEZ. `"className"` minified kodda
   da `"className"` kalir. Bu en guvenilir sinyal.

2. **Kontrol akis %20**: `if/else/switch` sayisi minifier tarafindan nadiren degisir.
   Dead code elimination yapilmadigi surece dallanma yapisi korunur.

3. **Member access %15**: `.push()`, `.map()`, `.prototype` gibi API cagrilari
   minifier'dan etkilenmez (property isimleri kisaltilmaz).

4. **Property keys %15**: `{type: "x", value: y}` icerisindeki `type`, `value`
   gibi key'ler korunur.

5. **Arity %10**: Parametre sayisi genellikle korunur ama default parametreler
   veya rest operatoru ile degisebilir.

### 3.4 SourceResolver Stratejisi

```python
class SourceResolver:
    """Orijinal npm kaynak kodunu bul.

    Oncelik sirasi:
    1. Yerel asar_extracted node_modules (disk I/O yok, en hizli)
    2. unpkg.com CDN (HTTP, hafizada tut)
    3. npm pack (son care, /tmp'ye indir, isle, sil)
    """

    def resolve(self, package_name: str, version: str | None = None) -> SourceBundle:
        """Paketin orijinal JS dosyalarini dondur.

        Returns:
            SourceBundle:
                files: dict[str, str]  -- {dosya_yolu: icerik}
                source: str            -- "local" | "unpkg" | "npm_pack"
                version: str           -- Gercek versiyon
        """
```

**Versiyon Tespiti:**
NpmFingerprinter eslestirme yaptiktan sonra, minified modul icinden versiyon
string'i aramaya calisir. Bulamazsa unpkg'den latest'i alir (302 redirect
gercek versiyonu dondurur).

```
curl -sI "https://unpkg.com/highlight.js/lib/core.js"
  --> Location: /highlight.js@11.11.1/lib/core.js
  --> versiyon: 11.11.1
```

**Dosya Kesfetme:**
Hangi dosyalari indirmeli? Paketin `package.json` dosyasindaki `main` ve `exports`
alanlarindan basla, sonra `lib/` veya `src/` altindaki tum `.js` dosyalarini cek.

```
GET https://unpkg.com/highlight.js@11.11.1/package.json
  --> main: "lib/core.js"
  --> exports: { "./lib/languages/*": ... }

GET https://unpkg.com/highlight.js@11.11.1/?meta
  --> dosya listesi (directory listing)
```

### 3.5 StructuralMatcher Algoritmasi

```
Eslestirme Algoritmasi (Hungarian/Greedy)
==========================================

Girdi:
  M = minified fonksiyon fingerprint'leri  (|M| adet)
  O = orijinal fonksiyon fingerprint'leri  (|O| adet)

Cikti:
  Eslesmeler: [(m_i, o_j, score_ij), ...] where score > threshold

Algoritma:
  1. NxM benzerlik matrisi hesapla: S[i][j] = M[i].similarity(O[j])

  2. Greedy eslestirme (Hungarian yerine -- daha hizli):
     a. S matrisini duz listeye cevir: [(score, i, j), ...]
     b. Score'a gore azalan sirala
     c. Kullanilmis i ve j'leri takip et
     d. Her (score, i, j) icin:
        - i veya j zaten kullanildiysa: atla
        - score < THRESHOLD (0.65): dur
        - Yoksa: eslesme ekle, i ve j'yi kullanilmis isaretle

  3. Dogrulama:
     - Eger |eslesmeler| / min(|M|, |O|) < 0.3 ise:
       eslesmeler guvenilir degil, bosalt
     - Bu "toplu tutarlilik" kontrolu -- tek tek dogru
       gorunen ama toplam anlamsiz eslesmeleri engeller
```

**THRESHOLD = 0.65** seciminin gerekceleri:
- 0.5 cok dusuk: false positive sayisi yukselir
- 0.8 cok yuksek: inlining/tree-shaking sonrasi eslesmeler kacrilir
- 0.65 deneysel olarak iyi bir denge (ayarlanabilir config'e konacak)

### 3.6 NameMapper

```python
class NameMapper:
    """Eslesmelerden isim haritasi olustur.

    Girdi: [(minified_func, original_func, score), ...]

    Cikti:
    {
        "functions": {
            "a": {"original": "registerLanguage", "confidence": 0.89},
            "b": {"original": "getLanguage", "confidence": 0.76},
        },
        "parameters": {
            "a": {
                "b": {"original": "languageName", "confidence": 0.89},
                "c": {"original": "languageDefinition", "confidence": 0.89},
            }
        },
        "variables": {
            "d": {"original": "result", "confidence": 0.72, "context": "a->local"},
        }
    }
    """
```

**Parametre eslestirme:** Fonksiyon eslestikten sonra parametreler POZISYONEL olarak
eslestirilir. `a(b, c)` ↔ `registerLanguage(name, lang)` ise:
- b -> name (1. parametre)
- c -> lang (2. parametre)

**Lokal degisken eslestirme:** Daha zor. Sadece yuksek confidence fonksiyon eslesmelerinde,
lokal degiskenlerin KULLANIM PATTERN'ine bakarak yapilir:
- Degisken bir string ile ataniyorsa: `var x = "className"` → orijinalde de "className" atanan degisken
- Degisken bir member access ile kullaniliyorsa: `x.push(y)` → orijinalde de `.push()` cagrilan degisken

---

## 4. DISK TEMIZLIGI STRATEJISI

```
Kaynak              | Disk'e yazma | Strateji
--------------------|-------------|-----------------------------
asar_extracted      | Hayir       | Zaten var, dokunma
unpkg.com           | Hayir       | response.text hafizada tut
npm pack            | /tmp gecici | shutil.rmtree() isle bitince
Fingerprint cache   | Evet        | workspaces/X/cache/fingerprints.json
Eslestirme sonucu   | Evet        | naming-manifest.json'a entegre
```

**Fingerprint cache:** Ayni paket icin fingerprint'i tekrar hesaplama.
```json
{
  "highlight.js@11.11.1": {
    "resolved_at": "2026-03-21T23:00:00Z",
    "source": "unpkg",
    "functions": {
      "registerLanguage": {"arity": 2, "strings": [...], ...},
      "getLanguage": {"arity": 1, "strings": [...], ...}
    }
  }
}
```

---

## 5. EDGE CASE'LER VE COZUMLERI

### 5.1 Tree Shaking
Bundler kullanilmayan fonksiyonlari siler. Minified kodda 20 fonksiyon, orijinalde 50
fonksiyon olabilir. Cozum: Greedy matcher zaten bunu handle eder -- eslestirme
orani duserse toplu tutarlilik kontrolu devreye girer.

### 5.2 Inlining
Kucuk fonksiyonlar cagiran fonksiyona gomulur. Cozum:
- `body_length` kontrol disi birakilir (agirlik verilmez)
- String literal'ler gomuldugu fonksiyona tasinir -- string Jaccard bunu yakalar

### 5.3 Ayni Fingerprint'e Sahip Farkli Fonksiyonlar
Iki farkli fonksiyonun ayni arity + branch + loop + return sayisi olabilir.
Cozum: String literal'ler bu durumda belirleyici olur (getter vs setter
genelde farkli string kullanir).

### 5.4 Wrapper Fonksiyonlar
Bundler her modulu `(function(module, exports, require) { ... })` ile sarar.
Cozum: Dis wrapper'i atla, icindekileri fingerprint'le.

### 5.5 ES Module vs CommonJS
Orijinal ESM, minified CJS olabilir (veya tersi).
Cozum: Export/import mekanizmasi fingerprint'e dahil DEGiL, sadece fonksiyon
govdeleri karsilastirilir.

---

## 6. PERFORMANS BEKLENTISI

```
707 modul, ortalama 5KB/modul

Adim                    | Tahmini Sure
------------------------|-------------
NpmFingerprinter        | ~2s (mevcut, string search)
SourceResolver (unpkg)  | ~5-10s (HTTP, parallel with asyncio)
ASTFingerprinter        | ~3-5s (regex tabanlı)
StructuralMatcher       | ~1s (greedy, NxM matris)
NameMapper              | <1s (pozisyonel mapping)
-----------------------|-------------
TOPLAM                  | ~12-18s (unpkg'den, ilk calisma)
                        | ~5-8s (cache'den, sonraki calismalar)
```

---

## 7. CONFIG ENTEGRASYONU

config.py'ye eklenecek yeni alanlar:

```python
@dataclass
class SourceMatchConfig:
    """Source matching ayarlari."""
    match_threshold: float = 0.65          # Minimum benzerlik skoru
    consistency_ratio: float = 0.3         # Toplu tutarlilik esigi
    max_unpkg_requests: int = 50           # Paralel HTTP istek limiti
    unpkg_timeout: int = 10                # Tek istek timeout (saniye)
    npm_pack_fallback: bool = True         # npm pack kullanilsin mi
    npm_pack_cache_dir: str = "/tmp/karadul-source-cache"
    fingerprint_cache: bool = True         # Fingerprint sonuclarini cache'le

    # Agirliklar (toplam = 1.0)
    weight_strings: float = 0.40
    weight_control_flow: float = 0.20
    weight_member_access: float = 0.15
    weight_property_keys: float = 0.15
    weight_arity: float = 0.10
```

---

## 8. UYGULAMA SIRASI (DEVELOPER'A YONERGE)

Mimari 5 bagimsiz modülden oluşuyor. Uygulanma sırası:

```
Adim 1: FunctionFingerprint dataclass + similarity() metodu
        --> Birim test: iki bilinen fonksiyonun benzerligini hesapla

Adim 2: ASTFingerprinter (regex tabanli)
        --> Birim test: bilinen bir JS dosyasini fingerprint'le

Adim 3: SourceResolver (unpkg.com oncelikli)
        --> Birim test: highlight.js orijinalini cek, dosya listesi dondur

Adim 4: StructuralMatcher (greedy eslestirme)
        --> Birim test: highlight.js minified vs orijinal fonksiyonlarini eslesir

Adim 5: NameMapper + pipeline.py entegrasyonu
        --> Entegrasyon testi: end-to-end bir modul icin isim geri kazanimi
```

Her adim bagimsiz test edilebilir. Adim N+1 adim N'e bagimlı,
ama mock'lanarak paralel gelistirilebilir.

---

## 9. RISK DEGERLENDIRMESI

| Risk | Olasılık | Etki | Azaltma |
|------|----------|------|---------|
| esbuild inlining yüzünden düşük eşleşme oranı | Orta | Orta | threshold'u düşür, string ağırlığını artır |
| unpkg.com rate limit | Düşük | Düşük | Cache kullan, npm pack fallback |
| Regex parser yanlış fonksiyon sınırı bulması | Orta | Orta | Wrapper detection + Node.js acorn fallback |
| Farklı paket versiyonu (minified vs unpkg) | Yüksek | Düşük | Versiyon string tespiti, fallback latest |
| Toplam eşleşme oranı %30'un altında kalması | Orta | Orta | Her paket için threshold ayarlanabilir |

---

## 10. BASARI KRITERLERI

MVP basarili sayilmasi icin:
1. highlight.js modulu icin en az 10 fonksiyon ismi dogru eslesmeli
2. Ortalama similarity score > 0.7 olan eslesmeler icin %80+ dogruluk
3. End-to-end pipeline 30 saniye altinda calismali
4. Disk'e sadece cache ve sonuc dosyasi yazilmali, gecici dosya kalmamali
