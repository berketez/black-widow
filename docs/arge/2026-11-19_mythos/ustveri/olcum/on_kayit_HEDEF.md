# Ön kayıt — HEDEF (P-ÜV8 kalem 1–4, P-ÜV9 kalem 1), 2026-11-20

Bu metin ölçümden ÖNCE commit'lenir. Tutmayan beklenti silinmez; eşik sonradan değişmez. Paket metni
`docs/arge/2026-11-20_dalga0/gonderim/HEDEF.md`, plan `ustveri/PLAN.md` P-ÜV8, P-ÜV9 kalem 1.

**Bu kayıttan önce görülenler (dürüstlük notu):** araştırma turunun hazır çıktıları (`$V` =
`~/karadul_olcum/runs/arge-2026-11-19/ustveri/`: `envanter.json`, `go/docker-cli.json`,
`objc/terminal-notifier.json`, `butce.json`) ve gösteri koşusunun `ghidra_functions.json` başlığı
(toplam 13 559 fonksiyon: 13 160 program + 399 thunk; adlı olanların kaynak dağılımı IMPORTED 921 /
DEFAULT 121 / ANALYSIS 6). Hedef ikililerin soyulmuş kopyası, GT ve ürün koşusu henüz yok.

## 1. Set ve bölme (kalem 1)

Veri kökü `~/karadul_olcum/ustveri_set/<ad>/{orig,bin,gt}` (depo dışı; ikili ve ad listesi commit'lenmez).

| Ad | Kaynak (§9) | Dilim | Dil | Lisans | Bölme |
|---|---|---|---|---|---|
| terminal-notifier | `/opt/homebrew/Cellar/terminal-notifier/3.1.0/terminal-notifier.app/Contents/MacOS/terminal-notifier` | ince (arm64) | Objective-C | MIT | **keşif** |
| docker-cli | `/Applications/Docker.app/Contents/Resources/bin/docker` | ince (arm64) | Go 1.24.4 | Apache-2.0 | **keşif** |
| docker-compose | `/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose` | ince (arm64) | Go 1.23.8 | Apache-2.0 | **sınama** |
| iTerm2 | `~/Applications/iTerm.app/Contents/MacOS/iTerm2` | evrensel → arm64 | ObjC + Swift + C++ | GPL-2.0 | **sınama** |
| llama-server | `/Applications/Ollama.app/Contents/Resources/llama-server` | evrensel → arm64 | C++ | MIT | **sınama** |

- Kaynak sha256 (ilk 16; tam değer manifest'te): eaec53d59e9ed9ba, 1b2b4029ea6ba83b, fc9b9e22a1134f55, 53b9badbabf1ab32, 3efd976f34a24699 (araştırma kopyalarıyla aynı; 2026-11-20 09:2x).
- Dilim: evrensel dosyanın arm64 dilimi bayt bayt kesilir (ürün de arm64'ü seçer: `universal_slice.json` kuralı).
- Soyma: `/usr/bin/strip -o <bin> <orig>` (conda `strip` değil; `macho_measure.strip_binary`). Denetim: `xcrun dyld_info -exports` ve `/usr/bin/nm -n -U` ile soyulmuş kopyada kalan fonksiyon sembolü.
- GT: özgün dilimin sembol tablosundan, `/usr/bin/nm -n -U`: fonksiyon GT'si = `T` / `t` sembolleri (adres → ad kümesi; `macho_f1.parse_nm`); C++ sınıf GT'si = adı `__ZTI` / `__ZTV` ile başlayan tanımlı semboller (veri). Mach-O'nun C sembol öneki (baştaki tek `_`) eşitlikte soyulur.
- **Kural:** sınama ikililerinde kanal kesinliği bu pakette hesaplanmaz (okuyucular dondurulunca, Dalga 2). Sınamada yalnız GT çıkarımı, H1 (soyma öncesi / sonrası kanal çıktısı) ve bütçe sayımı (GT'siz; sembol tablosu sütunu) koşulur.
- Test seti kilidi: beş adın kilitli havuzla kesişimi 0 (`test_seti_kura.POOL ∪ STRESS`; liste açılmadı, yalnız kesişim).

## 2. Ad eşitliği (kalem 2; özgün ad üstünden, `c_identifier` uygulanmadan)

Kurallar tek yerde: `scripts/measurement/ustveri_olc.py`. GT adı önce Mach-O C önekinden arındırılır (baştaki tek `_`).

- Go: birebir; ya da GT adının sonundaki `.abi0` / `.abiinternal` eki soyulunca birebir; ya da kanal adındaki orta nokta (`·`) nokta yazılınca birebir.
- ObjC: birebir; ya da GT adındaki kategori (`-[Sınıf(Kategori) seçici]` → `-[Sınıf seçici]`) soyulunca birebir.
- Swift erişim fonksiyonu: GT adının `xcrun swift-demangle` çıktısı kanal adıyla birebir (`type metadata accessor for <Tip>`).
- C++ sınıf adı: typeinfo adresinde GT adı = `_ZTI` + kanal adı; vtable adresinde GT adı = `_ZTV` + kanal adı.
- Ürün adı (kalem 4): yukarıdaki Go / ObjC kurallarından biri ya da birebir; ek olarak duyarlılık satırı "tam + biçim" (`ad_bicimi.harf_tam`, A-3).
- Sayım: adres başına. Kanal o adrese en az bir ad veriyorsa "ad verilen". GT'de o adreste ad yoksa "GT'siz" (kesinliğin paydasına girmez). Adreste kanalın verdiği adların HEPSİ GT adlarından biriyle eşitse "doğru", değilse "yanlış". Kesinlik = doğru / (doğru + yanlış), Wilson %95 (`ks1_olc.oran`). A-2 satırı: Wilson alt sınırı ≥ `naming_labels.AD_ESIGI` (= 10 / 11).

## 3. Hipotezler

- **HS (soyma temiz):** 5 / 5 soyulmuş kopyada export trie'de yalnız `__mh_execute_header` kalır ve `T` / `t` sembolü 0. Tutmayan ikili ürün koşusuna girmez (kanal ölçümünü etkilemez; kayda geçer).
- **H1 (P-ÜV8 H1'in bu paketteki kısmı):** araştırma okuyucusuyla 5 kanal (Go `pclntab`, ObjC yöntem, Swift erişim fonksiyonu, C++ typeinfo, C++ vtable) × 5 ikili, özgün dilim ↔ soyulmuş kopya kanal çıktısı (adres → ad) aynı: fark 0 / 25. Kanalın uygulanmadığı ikilide iki yanda da `veri_yok`.
- **HK (keşif; aracın araştırma çıktısını yeniden üretmesi):** soyulmuş kopyada, araştırma okuyucusuyla (etiket: "araştırma okuyucusu, ürün kanalı değil"):
  - docker-cli Go: ad verilen 35 048, doğru 35 048, yanlış 0, GT'siz 0; yazım kırılımı birebir 34 710 / `.abi0` 328 / orta nokta 10 (`$V/go/docker-cli.json` ile aynı). Wilson alt sınırı 0,99989 → A-2 satırı "evet".
  - terminal-notifier ObjC: ad verilen 32, doğru 32 (31 birebir + 1 kategori yazımı), yanlış 0, GT'siz 0. Wilson alt sınırı 1 / (1 + z² / 32) = 0,8928 < 0,909 → A-2 satırı **"hayır" (n küçük)** beklenir; bu, kanalın yanlış olduğu değil, keşif ikilisinin örneğinin küçük olduğu anlamına gelir.
  - Öbür kanallar keşif ikililerinde `veri_yok`.
- **HB (bütçe, kalem 4 planı):** `ustveri_olc.py butce`, `$V/butce.json`'daki 16 hedefin 16'sında nüfus / kesin / yuva / sembol / kalan sütunlarını aynı verir (araştırma okuyucularıyla; `$V/hedef/` kopyaları). Set ikililerinin soyulmuş kopyasında sembol sütunu 0 (HS tutarsa).
- **HÜ (bugünkü ürünün "önce" sayısı; ürün `~/karadul_olcum/urun-b6aceb9`, bayraklar öntanımlı):** yalnız tahmini süresi ≤ 60 dk olan ikili koşulur (aşağıda). terminal-notifier soyulmuş kopyasında: ürünün ad verdiği fonksiyon < 10 (92 fonksiyonun %10'undan az); ürünün verdiği adlardan üst veri kanalına ait olan 0 (ürün ObjC / Go / Swift üst verisi okumuyor). Doğru ad sayısı ilk ölçüm (yön yok). Ghidra'nın kendisinin adlandırdığı GT fonksiyonları ayrıca sayılır (ürünün adı değildir).

## 4. Koşu listesi ve TAHMİNİ süre (kalem 4)

Dayanak (hepsi ölçülmüş, yük altında): Mac tmux 2 572 fonksiyon → 223 sn (tek başına, S8 tabanı) / 412 sn (paralel 3); gösteri Ollama arm64 dilimi 13 559 fonksiyon (26,6 MB) → 7 762 sn. İki noktadan güç yasası üssü 2,14 (süre ∝ fonksiyon^2,14); alt sınır olarak gösterinin fonksiyon başına doğrusal maliyeti (0,57 sn / fonksiyon) de verilir.

| İkili | Fonksiyon (LC_FUNCTION_STARTS ya da `pclntab`) | TAHMİN (doğrusal alt sınır – güç yasası) | Karar |
|---|---|---|---|
| terminal-notifier | 92 | 1–5 dk (sabit maliyet baskın; küçük Debian ELF'leri 40–90 sn) | **koşulur** |
| llama-server arm64 | 17 211 | 164–215 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| docker-cli | 35 049 | 334–983 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| docker-compose | 90 078 | 859–7 378 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| iTerm2 arm64 | 109 608 | 1 046–11 219 dk | ölçülmedi: süre — gece kuyruğuna önerildi |

Komut (her ikili ayrı kuyruk çağrısı; süre sınırı 3 600 sn): `~/karadul_olcum/ghidra_kuyruk.sh HEDEF urun:<ad> python scripts/measurement/ustveri_olc.py urun-kos --ad <ad> --agac ~/karadul_olcum/urun-b6aceb9 --kok ~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/urun` (`PYTHONHASHSEED=0`, koşuya özel `KARADUL_CACHE_DIR`).

## 5. P-ÜV9 kalem 1 — Ghidra ↔ üst veri (gösteri çalışma alanı, salt okur)

Girdi: `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws/workspaces/Ollama/20261119_081103/` (`static/ghidra_functions.json`, `raw/Ollama_arm64`); üst veri araştırma okuyucusuyla aynı dilimden. Ghidra'nın "jenerik olmayan adı" = `function_f1.is_generic_name` yanlış.

- **G1 (yön):** `LC_FUNCTION_STARTS`'ın (12 952) en az %99'unda Ghidra bir fonksiyon açmıştır (Mach-O yükleyicisi bu tabloyu tohum olarak kullanır).
- **G2 (yön; P-ÜV8 H4'ün dayanağı):** `pclntab`'ın adlı 10 600 girişinin en az %90'ında (≥ 9 540) Ghidra'nın fonksiyonu vardır ve adı jeneriktir (Go kanalı oraya ad yazabilir).
- **G3 (yön, "0'a yakın"):** Ghidra'nın jenerik olmayan ad verdiği Go girişi ≤ %1 (≤ 106). Ghidra 12.1.2'nin Go verisi 1.25'te bitiyor ve ikili Go 1.26.0 ("Untested Go version" uyarısı, `DEFTER.md`).
- **G4 (açık, yön yok):** Ghidra'nın ObjC yöntemlerinden (151) kaçını adlandırdığı (P-ÜV8 H5).
- **G5 (açık):** Ghidra'nın jenerik olmayan adlarıyla üst veri adlarının kesişimi ve bu kesişimde ad eşitliği (§2 kuralları).
