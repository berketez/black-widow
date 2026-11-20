# P-ÜV9 kalem 1 — Ghidra ↔ üst veri (Ollama arm64, gösteri koşusu), 2026-11-20

- Ön kayıt (yön, koşudan önce): `docs/arge/2026-11-19_mythos/ustveri/olcum/on_kayit_HEDEF.md` §5 (G1–G5), commit `bbda937`.
- Betik: `scripts/arge/ustveri/acik_ghidra_ustveri.py` (Ghidra koşmaz; gösteri çalışma alanı salt okur). Çıktı (yalnız sayı): `~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/puv9_k1.json`.
- Girdi: `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws/workspaces/Ollama/20261119_081103/` — `static/ghidra_functions.json` (Ghidra 12.1.2), `raw/Ollama_arm64` (sha256 `7d5b1e847e1b1e9310eb2a82287fd182f325597d027b5aaf7d11287f8b13ddda` = araştırma kopyası `$V/hedef/Ollama.arm64`). Ghidra görüntü tabanı `0x100000000` = Mach-O `__TEXT` (adres eşlemesi doğrudan).
- Üst veri: araştırma okuyucuları (**araştırma okuyucusu, ürün kanalı değil**). "Jenerik olmayan ad" = `function_f1.is_generic_name` yanlış. Ad eşitliği `scripts/measurement/ustveri_olc.py` kalem 2 kuralları.

## G1 — Ghidra'nın fonksiyonları ↔ `LC_FUNCTION_STARTS`

| Ölçü | Sayı |
|---|---|
| `LC_FUNCTION_STARTS` | 12 952 |
| Ghidra fonksiyonu (program + thunk) | 13 559 (13 160 + 399) |
| Başlangıcın Ghidra'da fonksiyon olduğu | 12 916 / 12 952 = %99,72 (%99,62–%99,80) — 12 787'si program, 129'u thunk |
| Başlangıcı Ghidra'da fonksiyon olmayan | 36 |
| Ghidra'nın tablo dışında açtığı program fonksiyonu | 373 |

**G1 tuttu** (≥ %99).

## G2 / G3 — Go `pclntab` girişleri (10 600 adlı giriş; Go 1.26.0)

| Ghidra'nın o adresteki durumu | Sayı |
|---|---|
| Fonksiyon yok | 28 |
| Thunk | 112 (93'ü Ghidra'ca adlı: hepsi Go `…_trampoline` girişi, Ghidra atlama hedefinin libc adını vermiş; Go adıyla eşit 0) |
| Jenerik adlı program fonksiyonu (kanal buraya ad yazabilir) | **10 457 / 10 600 = %98,65 (%98,41–%98,85)** |
| Jenerik olmayan adlı program fonksiyonu | **3** (kaynak `IMPORTED`; üçü de Go adıyla eşit) |

- **G2 tuttu** (≥ %90; ≥ 9 540): P-ÜV8 H4'ün dayanağı ölçüldü — Go kanalı bu dilimde en çok 10 457 ada yer bulur (Ghidra'nın fonksiyon sınırı kanalın önünde engel değil; İ-11'in "Ghidra fonksiyon sınırı" sorusu bu ikilide kapandı).
- **G3 tuttu:** Ghidra'nın Go girişlerine verdiği jenerik olmayan ad 3 / 10 600 = %0,03 (thunk adlarıyla 96 = %0,91; ≤ %1). Ghidra 12.1.2 bu ikilide Go adlarını okumuyor ("Untested Go version [1.26.0]"; Go verisi 1.25'te bitiyor).

## G4 — Objective-C yöntemleri (151)

| Ghidra'nın o adresteki durumu | Sayı |
|---|---|
| Fonksiyon yok | 0 |
| Thunk | 1 (adlı) |
| Jenerik adlı program fonksiyonu | 2 |
| Jenerik olmayan adlı | **148 / 151 = %98,0 (%94,3–%99,3)**, kaynak `IMPORTED` |
| — bunlardan ad `-[Sınıf seçici]` ile eşit (kalem 2) | **0 / 148** |
| — bunlardan Ghidra adı = yalnız seçici (sınıf, fonksiyon adında yok) | **148 / 148** |

- **G4 (açık soru) cevabı:** Ghidra'nın ObjC çözümleyicisi 151 yöntemin 148'ini adlandırıyor ama adı **yalnız seçici** (`initWithFrame:` gibi); sınıf adı `ghidra_functions.json`'daki fonksiyon adında yok (Ghidra sınıfı ad alanı olarak tutuyor olabilir; dışa aktarımda görünmüyor — doğrulanmadı).
- **Sonuç (P-ÜV6'ya girdi):** P13b kuralı (aday yalnız Ghidra'nın adsız bıraktığı fonksiyona) olduğu gibi uygulanırsa ObjC kanalı Ollama'da yalnız 2 fonksiyona ad yazar; 148 yöntem rapora "seçici" adıyla, sınıfsız çıkar. Ya kanal Ghidra'nın seçici adını tam `-[Sınıf seçici]` adıyla zenginleştirmeli (Ghidra adıyla seçici eşitse çelişki yok) ya da `ghidra_functions.json`'a ad alanı eklenmeli. Karar P-ÜV6'nın; bu ölçüm yalnız sayıyı veriyor.

## G5 — Ghidra'nın jenerik olmayan adları ∩ üst veri adresleri

| Ölçü | Sayı |
|---|---|
| Ghidra'nın jenerik olmayan adı (toplam) | 1 047 (program 669, thunk 378; kaynak `IMPORTED` 920, `DEFAULT` 121, `ANALYSIS` 6) |
| Üst veri fonksiyon adresi (Go 10 600 + ObjC 151) | 10 751 |
| Ghidra adlı ∩ üst veri adresi | 245 (program 151: Go 3 + ObjC 148; thunk 94: Go 93 + ObjC 1) |
| — ad eşitliği (kalem 2) | Go program 3 / 3; ObjC 0 / 148 (yalnız seçici: 148 / 148); thunk 0 / 94 |
| Ghidra adlı, üst veri dışında | 802 (program 518; kaynak `IMPORTED` 768, `DEFAULT` 28, `ANALYSIS` 6) |

## Hüküm ve pakete dönüşüm

- G1, G2, G3 ön kayıttaki yönde tuttu; G4 / G5 açık sorulardı, sayıları yukarıda.
- **Pakete dönüşür:** ObjC adının sınıfsız gelmesi P-ÜV6'nın kanal bağlama kuralına girdi (yukarıdaki iki seçenek). Go için ek paket yok: Ghidra fonksiyon sınırı kanalın önünde engel değil (bu ikilide).
- **Sınır:** tek ikili (Ollama arm64, Go 1.26.0, `LC_FUNCTION_STARTS` var). Başlangıç tablosu olmayan Go ikilisi (`gh`) P-ÜV9 kalem 2'de ayrıca ölçülmeli; bu ölçüm onun yerine geçmez.
