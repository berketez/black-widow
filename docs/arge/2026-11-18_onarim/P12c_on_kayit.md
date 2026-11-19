# P12c ön kayıt — çok satırlı imza, gövde çıkarıcı ve imza ayrıştırıcıları (kod değişikliğinden ÖNCE)

- Tarih: 2026-11-19. Taban: `0984090` (`a62f15e` + oturum notları). Kod henüz değişmedi.
- Girdi: P12b taban kolunun 14 çalışma alanı (Ghidra çıktısı genel tarama, 1.23.1), `reconstructed` / `reports` hariç
  `~/karadul_olcum/runs/onarim-2026-11-19/P12c/girdi/`'ye kopyalandı.
- Sayım aracı: `P12c/arac/govde_say.py` (kimlik = dosya başlığındaki `// Function: <ad>`; imza sınıfı kodun deseninden
  bağımsız dengeli parantez sayımıyla). Yeniden oynatma: `arac/kol.sh` + `arac/yeniden.py` (P12a / P12b aracı).
- GT ölçüsü: `scripts/measurement/urun_olc.py olc / karsilastir` (13 C ikilisi; pzstd C++ dışarıda), tam eşitlik.

## 1. Taban sayımı (kalem 1; 14 alan, `govde_taban.json`)

| Ölçü | Sayı |
|---|---|
| Fonksiyon (`// Function:` adı, tekil) | 13 860 |
| İmza sınıfı: tek satır, iç parantez yok | 13 132 |
| İmza sınıfı: çok satırlı (parametre listesi sonraki satırda kapanıyor) | 688 |
| İmza sınıfı: tek satır, parametrede iç parantez (işlev işaretçisi vb.) | 4 |
| İmza sınıfı: dosyada `ad(` tanım satırı yok / belirsiz | 31 / 5 |
| **`_func_bodies`'e girmeyen** | **729** (çok satırlı 685, iç parantez 4, tanım satırı yok 31, belirsiz 5, tek satır 4) |
| bunların `FUN_` olanı (ad bekleyen nüfus) | **654** (çok satırlı 651, iç parantez 3); pzstd (C++, GT dışı) 106 → GT'li 13 ikilide 548 |
| Aynı `// Function:` adı birden çok dosyada (gövde son dosyanınki) | 3 129 ad (bu pakette onarılmaz; kayıt) |

**Öbür ayrıştırıcılar.** `_extract_sig_params` (`c_namer.py:1687`) ve `_strategy_body_param_naming`'in imza deseni
(`c_namer.py:4102`) aynı deseni kullanır: `[^;{]*` satır sonunu geçtiği için çok satırlı parametre listesini ve iç
parantezi doğru okur, AMA dönüş tipini adla aynı satırda ve yalnız `[\w\s*]` karakterleriyle ister. Gövdesi alınan
fonksiyonlarda bağımsız ayrıştırmayla uyuşmayan: **316** (dönüş tipi `undefined1  [16]` 216; dönüş tipi önceki
satırda — Ghidra uzun imzada dönüş tipini ayrı satıra yazıyor, gövde ad satırından başlıyor — 74; C++ `ns::sınıf::ad`
25; gövde çağrı satırından başlamış 1). Hepsinde sonuç `None` → bu fonksiyonların parametreleri parametre adlandırmaya
ve geçiş mirasına kapalı.

## 2. Değişiklik (planlanan)
A. `_extract_function_bodies`: ad + `(`'dan başlayan dengeli parantez sayımı (dizgi / karakter sabiti dışında),
   satırlar boyunca; kapanıştan sonra satırda yalnız `{` ya da boşluk; parantez içindeyken `;` `{` `}` görülürse tanım
   değildir. Tek satırlı düz imzalarda davranış aynı kalır. Belirlenimci (girdi sırası, set yok).
B. İmza ayrıştırıcıları (ayrı commit): dönüş tipi yoksa (gövde ad satırıyla başlıyor), `[N]` ve `::` içeren dönüş
   tipi / ad niteleyicisi kabul edilir; parametre bloğu dengeli parantezle alınır.

## 3. Hipotezler ve eşikler (yeniden oynatma, 14 ikili; taban `0984090` ↔ sonra = A + B)

| # | Ölçü | Beklenen | Tuttu / tutmadı eşiği |
|---|---|---|---|
| H1 | `_func_bodies`'e girmeyen (14 alan) | 729 → 40 (kalan: tanım satırı yok 31, belirsiz 5, pzstd tek satır 4) | tuttu: çok satırlı + iç parantez sınıfında 0 VE toplam ≤ 40 |
| H2 | Görünür olan fonksiyon | 689 (`FUN_` 654) | tuttu: ≥ 685 |
| H3 | `_extract_sig_params` uyuşmazlığı (gövdesi alınanlarda) | 316 → ≤ 5 | tuttu: ≤ 5 (çok satırlı yeni gövdeler dahil) |
| H4 | Yeni fonksiyon adı (GT, 13 C ikili; `ad yok → ad var` + `ad değişti`) | 0–80; ana kaynak `string_context/oz_ad` (gövde dizgileri yeni görünür). Önsel kesinlik bu kanalın bu setteki ölçüsü %44,6 (Wilson %37,6–%51,8) | — (sayı rapor) |
| H5 | **Kabul (paket metni):** yeni yanlış ≤ yeni doğru | önsel kesinlik %45 civarı → sınırda; tutmayabilir | tuttu: yeni yanlış ≤ kazanılan doğru |
| H6 | **Kaybedilen doğru** (silinen + yanlışa dönen; taban 441 doğru civarı) | ≤ 5 | tuttu: ≤ 5 (≈ %1,1) |
| H7 | Yeni adların kesinliği alt sınırı | ≥ %30 (tam eşitlik) | tuttu: kazanılan doğru / (kazanılan doğru + yeni yanlış) ≥ %30 |
| H8 | `per_function` (parametre / yerel) değişen anahtar | 500–10 000 (gövde ve imza ayrıştırma yeni fonksiyon açar); GT yok | — (sayı rapor) |
| H9 | Gevşek ölçüt | N0b kör L1 etiketli (adres, ad) çiftleriyle örtüşen yeni / kaybolan ad; örtüşme yoksa "veri yok" yazılır; bu pakette yeni etiketleme YOK | — |
| H10 | Belirlenimcilik | sonra kolunda 2 ikili (Debian tmux, zstd) ikinci kez: `naming_map.json` bayt bayt aynı | tuttu: aynı; zaman kalmazsa "bakılmadı" |

**Tutmazsa (H5 / H6):** düzeltme geri alınmaz ve bayrak arkasına konmaz (K-2). Yanlışı hangi strateji / alt kanalın
ürettiği köken kaydından gösterilir; o kanalın kanıtı bu pakette onarılabiliyorsa onarılır, değilse bulgu kayda yazılır.
Eşikler sonradan değiştirilmez.

## 4. Kalem 5 ve 6 (P13a kalanı)
- H11 (kalem 5): `enable_c_naming=False` iken ön adın birleştiriciye giriş güveni sabit 0,85 değil; kanalın ölçülmüş
  kesinliğinin Wilson alt sınırı (`naming_labels.MEASURED_PRE_NAME_PRECISION`), ölçülmemişse `None` (ad sayı uydurmaz).
  Öntanım yol (c_namer açık) etkilenmez: yeniden oynatmada fark 0.
- H12 (kalem 6): FID / Ghidra yer tutucu adları (`caseD_N`, `switchD_…`, `switchdataD_…`) ad haritasında ve köken
  kaydında ad sayılmaz: taban sayısı yeniden oynatmanın taban kolundan sayılır → sonra 0.
