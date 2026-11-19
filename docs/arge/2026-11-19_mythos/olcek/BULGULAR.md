# ÖLÇEK — bulgular (tur 1, 2026-11-19)

- **Kod okuması:** main `b52408e` (sürüm 1.24.1). Çalışma ağacında ürün kodu değişikliği yok.
- **Ölçüm tabanı:** birleşik koşu `a62f15e`, 119 ikili (`~/karadul_olcum/runs/urun-onarim-a62f15e`, `--paralel 3`, ortak makine, aynı anda 5–7 ajan).
- **Örneklem dışı nokta:** gösteri koşusu, Ollama.app 0.40.3 ana ikilisinin arm64 dilimi (26 627 984 bayt; kodu 5 509 156 bayt), commit `b4be6f3`, "Objective-C Message Analyzer" kapalı. **Koşu bu belge yazılırken sürüyordu** (`CIKIS` yok); yalnız biten Ghidra adımları kullanıldı. Bitince okunacak ölçüm `PLAN.md` ÖLÇ-0'da.
- Yeni Ghidra / `karadul analyze` koşusu yapılmadı. Kapalı kaynak kurulumlarda yalnız yol, boyut, `file` türü ve sha256 okundu; hiçbir ikili çalıştırılmadı.
- Betikler `scripts/arge/olcek/`, veri `~/karadul_olcum/runs/arge-2026-11-19/olcek/`. Her sayının betiği ve komutu yanında; komutların hepsi depo kökünden ve `PYTHONDONTWRITEBYTECODE=1` ile.

## 0. Özet

1. **Bugün dürüstçe:** uçtan uca ölçülmüş en büyük tek ikili 3,2 MB (redis-check-aof: 5 697 fonksiyon, 658–708 sn). Gösteri dilimi (26,6 MB; 5,5 MB kod; 13 559 fonksiyon): Ghidra köprüsü 3 815,4 sn (63,6 dk), statik aşamanın geri kalanı 912 sn; koşunun tamamı bu belge yazılırken sürüyordu (ÖLÇ-0). 100 MB ve üstü tek ikili ve çok bileşenli paket hiç uçtan uca koşulmadı.
2. **Envanter (§1):** 15 kurulum (6 açık kaynak, 9 kapalı; 34,24 GiB): 3 709 analiz edilebilir Mach-O (12,53 GiB); 2 701'i (%73) 1 MB'tan küçük, 98'i ≥ 25 MB, 22'si ≥ 100 MB (en büyüğü Google Chrome Framework, 531 683 616 B); 1 300'ü evrensel. Bugünkü bileşen kuralı FreeCAD.app'te 1 903 bileşen veriyor (867 tekil), KiCad.app'te 304 Mach-O'nun 298'ini ve Ollama.app'te asıl sunucu ikilisini kapsam dışında bırakıyor. Word ↔ Excel 34 Mach-O (466 MiB) bayt bayt aynı. Yol adına göre üçüncü taraf payı %0–100 (FreeCAD %68; doğrulanmamış).
3. **En kritik kırılma noktaları (§2):** (a) köprüde otomatik analiz ve decompile dışındaki 9 çıkarım adımında süre sınırı yok; gösteride bunların sekizi (fonksiyon listesi ilk adıma karışık ölçüldü) köprünün %78'i; (b) BSim köprünün %51'i (1 951,9 sn) ve 0 eşleşme (koşuya özel boş depo; sonuç zaten ad haritasına girmiyor); (c) takılan çözümleyici ve ilerlemesizlik (gösteri 1. denemede 27 dk, 2. denemede 113 dk boyunca günlükte tek satır yok); (d) paket kuralı bütçesiz ve sıralı, bağlı dosyaları ayrı bileşen sayıyor (FreeCAD.app: 1 903 bileşen, 867 tekil), asıl kodu kaçırabiliyor (KiCad.app: 298 / 304 Mach-O kapsam dışı; Ollama.app: asıl sunucu ikilisi kapsam dışı); kurulum dizini hedef verilemiyor; (e) bütün Ghidra çıktısı Python belleğinde ve iki kez serileştiriliyor; reconstruct fonksiyon başına 12,2 dosya yazıyor.
4. **Ölçekleme (§3):** örneklem içinde (119) çağrı grafiği, decompile, xref, CFG ve disk fonksiyon sayısına göre doğrusal üstü (b 1,14–1,58). Örneklem dışında (gösteri) yalnız decompile modelle tuttu (1,00×); çağrı grafiği, ilk adım, xref, CFG, BSim ve statik aşamanın köprü dışı kısmı (ikili istihbarat) 2,2–25,9 kat fazla sürdü (kod baytına göre iki noktalı üs 1,6–3,9; köprü bütünü 4,27 kat, üs 2,04). Dış değerleme TAHMİN: ~95 MB'lık açık kaynak C++ ikilisi (mlir-transform-opt, 163 141 fonksiyon) için Ghidra köprüsü A senaryosunda 14,5–39,4 saat (kötümser B 136,5); 646,6 MB'lık libtensorflow_cc 77,9–447,5 saat; FreeCAD.app'in tamamı bugünkü kuralla doğrusal 177–345 saat (statik aşama). Bellek ~100 MB'da Python tarafı 7,0–55,2 GB + JVM yığını 14,7 GB; disk 24–59 GB ve 2 milyon dosya (§3.5, §3.6).
5. **Öneri (§5):** yayından önce adım bütçeleri + takılan çözümleyici bekçisi + ilerleme olayları + BSim koşulları + paket yöneticisi (bağ / yineleme bir kez, ana bileşen önce, bütçe, kalıcı kuyruk, kapsam dışı listesi) + bellek / disk bekçisi; yayından sonra sha256 önbelleği, tembel derinlik, kimlikten bilinen bileşen. Birkaç GB'lık kurulumun TAMAMINI tam derinlikte analiz etmek karşılanamaz; söz verilebilecek olan "ana bileşen önce, gerisi bütçe içinde ve görünür".

## 1. Büyük yazılım neye benzer: üst veri envanteri (kalem 1)

- **Yöntem:** `scripts/arge/olcek/envanter.py` → `~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter/<kurulum>.json`; özet `scripts/arge/olcek/envanter_ozet.py` → `envanter_ozet.md`, `envanter_ozet.json`. Okunan yalnız üst veri: yol, boyut, `/usr/bin/file -b` türü, sha256; aday seçimi için çalıştırma biti ya da ikili uzantısı olan dosyaların ilk 4 baytı (sihirli sayı). Hiçbir dosya çalıştırılmadı; dizgi, sembol, fat başlığı okunmadı. Ön süzgeç süzgeçsiz taranan LLVM ve Ollama.app'te 215 / 215 Mach-O'yu yakaladı.
  Komut: `PYTHONDONTWRITEBYTECODE=1 nice -n 10 python scripts/arge/olcek/envanter.py --cikti-dizin ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter [--yalniz AD …]`; `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/envanter_ozet.py --envanter ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter_ozet.json`
- "Mach-O" bu tabloda analiz edilebilir türlerdir (çalıştırılabilir, dylib, bundle); statik arşiv, nesne, dSYM, kext hariç. "3. taraf payı" Mach-O baytının yol adından (Electron, Chromium, Qt, LLVM, Python, Java, Office paylaşılan, …; `envanter.py` `BILESEN_KALIPLARI`) sınıflanan kısmıdır: **doğrulanmamış**, yön gösterici.
- Tablolar betik çıktısıdır (ondalık ayırıcı nokta). 17 kurulum listelendi; IBM SPSS Statistics ve Anaconda taramaları gösteri koşusunu yük altında bırakmamak için yarıda durduruldu (DEFTER 13:05). Tabloda 15 kurulum var. Anaconda'daki büyük açık kaynak kitaplıklar (TensorFlow, torch) ayrıca ölçüldü (§3.5).

| kurulum | lisans | toplam GiB | dosya | Mach-O (adet / GiB) | evrensel | tekil sha (adet / GiB) | en büyük Mach-O (MiB) | ≥ 25 MB / ≥ 100 MB | < 1 MB | 3. taraf payı (bayt, yol adından) |
|---|---|---|---|---|---|---|---|---|---|---|
| Blender | açık kaynak (GPL-2.0-or-later) | 0.91 | 6632 | 206 / 0.67 | 0 | 206 / 0.67 | 200 | 6 / 1 | 162 | 19 % |
| ChatGPT | kapalı | 1.90 | 4125 | 91 / 0.97 | 12 | 91 / 0.97 | 268 | 6 / 3 | 69 | 14 % |
| Cursor | kapalı | 1.17 | 19786 | 40 / 0.73 | 40 | 40 / 0.73 | 354 | 5 / 2 | 21 | 82 % |
| Docker | kapalı | 1.93 | 216 | 77 / 1.25 | 1 | 77 / 1.25 | 166 | 13 / 3 | 31 | 14 % |
| FL Studio 2025 | kapalı | 2.20 | 28073 | 294 / 1.16 | 293 | 294 / 1.16 | 56 | 7 / 0 | 114 | 7 % |
| FreeCAD | açık kaynak (LGPL-2.1-or-later) | 2.48 | 31577 | 1817 / 1.89 | 1 | 1817 / 1.89 | 133 | 10 / 2 | 1464 | 68 % |
| Google Chrome | kapalı | 1.43 | 699 | 52 / 1.25 | 48 | 44 / 1.19 | 507 | 4 / 2 | 27 | 100 % |
| KiCad | açık kaynak (GPL-3.0-or-later) | 4.76 | 39959 | 299 / 0.78 | 299 | 299 / 0.78 | 93 | 8 / 0 | 223 | 50 % |
| LM Studio | kapalı | 1.09 | 35471 | 43 / 0.46 | 0 | 43 / 0.46 | 164 | 4 / 2 | 24 | 74 % |
| Microsoft Excel | kapalı | 2.36 | 37766 | 190 / 0.68 | 190 | 190 / 0.68 | 152 | 8 / 1 | 132 | 36 % |
| Microsoft Word | kapalı | 2.44 | 47215 | 198 / 0.75 | 198 | 198 / 0.75 | 128 | 9 / 2 | 145 | 33 % |
| Ollama | açık kaynak (MIT) | 0.61 | 66 | 34 / 0.29 | 8 | 34 / 0.29 | 52 | 4 / 0 | 4 | 53 % |
| TeX Live | açık kaynak (karışık özgür lisanslar) | 8.53 | 237406 | 163 / 0.50 | 163 | 163 / 0.50 | 96 | 5 / 1 | 125 | 0 % |
| Visual Studio Code | kapalı ikili (kaynak MIT) | 0.69 | 4673 | 39 / 0.47 | 39 | 39 / 0.47 | 335 | 3 / 1 | 27 | 79 % |
| llvm-23.1.6 | açık kaynak (Apache-2.0 WITH LLVM-exception) | 1.74 | 9298 | 166 / 0.67 | 8 | 166 / 0.67 | 162 | 6 / 2 | 133 | 63 % |

**Karadul'un bugünkü bileşen kuralıyla** (`karadul/core/target.py:244-311`'in aynı Python sürümüyle taklidi; ürün kodu çağrılmadı):

| kurulum | kök .app mı | Karadul bileşeni (S0) | tekil sha | bileşen GiB | kapsam dışı Mach-O (adet / MiB) | en büyük bileşen (MiB) | ilk bileşen sınıfları (bayt) |
|---|---|---|---|---|---|---|---|
| Blender | evet | 51 | 51 | 0.54 | 156 / 138 | 200 | sınıflanmamış 555 MiB; Python çalışma zamanı 132 MiB |
| ChatGPT | evet | 30 | 30 | 1.02 | 63 / 693 | 748 | sınıflanmamış 849 MiB; Node.js 121 MiB; Chromium / CEF 17 MiB; Güncelleyici (Sparkle / Squirrel) 2 MiB |
| Cursor | evet | 6 | 5 | 0.35 | 35 / 394 | 354 | Electron 396 MiB; Node.js 215 MiB; sınıflanmamış 136 MiB; ReactiveObjC / Mantle 1 MiB |
| Docker | evet | 32 | 32 | 0.43 | 45 / 840 | 166 | sınıflanmamış 1105 MiB; Electron 174 MiB; CUDA / Metal / ML 4 MiB; ReactiveObjC / Mantle 0 MiB |
| FL Studio 2025 | evet | 207 | 200 | 1.00 | 94 / 191 | 33 | sınıflanmamış 1104 MiB; Python çalışma zamanı 48 MiB; FFmpeg 36 MiB |
| FreeCAD | evet | 1903 | 867 | 2.69 | 964 / 781 | 133 | sınıflanmamış 626 MiB; Python çalışma zamanı 586 MiB; LLVM / Clang 352 MiB; VTK 132 MiB |
| Google Chrome | evet | 2 | 2 | 0.50 | 50 / 777 | 507 | Chromium / CEF 1280 MiB; sınıflanmamış 4 MiB |
| KiCad | hayır (7 .app) | 12 | 12 | 0.03 | 298 / 784 | 14 | sınıflanmamış 400 MiB; Python çalışma zamanı 187 MiB; OpenCASCADE 91 MiB; ICU 73 MiB |
| LM Studio | evet | 9 | 8 | 0.19 | 35 / 277 | 164 | Electron 189 MiB; Node.js 126 MiB; sınıflanmamış 123 MiB; Python çalışma zamanı 32 MiB |
| Microsoft Excel | evet | 58 | 58 | 0.56 | 132 / 120 | 152 | sınıflanmamış 445 MiB; Microsoft Office paylaşılan 252 MiB |
| Microsoft Word | evet | 61 | 61 | 0.54 | 137 / 211 | 128 | sınıflanmamış 513 MiB; Microsoft Office paylaşılan 252 MiB |
| Ollama | evet | 26 | 16 | 0.21 | 18 / 99 | 52 | sınıflanmamış 140 MiB; CUDA / Metal / ML 104 MiB; Güncelleyici (Sparkle / Squirrel) 52 MiB |
| TeX Live | hayır (.app yok) | — (hedef verilemez: `target.py:189-194`) | — | — | — | — | sınıflanmamış 517 MiB |
| Visual Studio Code | evet | 8 | 6 | 0.34 | 33 / 129 | 335 | Electron 377 MiB; sınıflanmamış 100 MiB; ReactiveObjC / Mantle 1 MiB; Güncelleyici (Sparkle / Squirrel) 1 MiB |
| llvm-23.1.6 | hayır (.app yok) | — (hedef verilemez: `target.py:189-194`) | — | — | — | — | LLVM / Clang 436 MiB; sınıflanmamış 255 MiB |

**Okuma:**
- 15 kurulum: 34,24 GiB, 3 709 analiz edilebilir Mach-O (12,53 GiB; `envanter_ozet.json`). Mach-O'ların çoğu küçük (< 1 MB: 2 701 / 3 709); birkaç GB'lık kurulumun ağırlığı birkaç büyük ikilide (≥ 25 MB: 98; ≥ 100 MB: 22). En büyük tek Mach-O Google Chrome Framework (531 683 616 B, evrensel).
- Evrensel (çok mimarili) Mach-O 1 300 / 3 709; Office, KiCad, VS Code, Cursor, TeX Live'da hepsi evrensel. Karadul tek dilim analiz eder (`karadul/analyzers/macho.py:251-263`); bayt yaklaşık yarıya iner (eşit bölme varsayımı; gösteride gerçek dilim / eşit bölme = 0,98).
- **Kurulum içi yineleme** sha256'ya göre az: 3 709 Mach-O'da 3 701 tekil (Chrome'da 8 kopya). Ama Karadul'un kuralı **bağlı dosyaları** ayrı bileşen sayıyor: FreeCAD.app'te 1 903 bileşen, 867 tekil. **Aynı kod farklı imzayla** sha256'dan kaçıyor: KiCad'de `_pcbnew.kiface` ↔ `_pcbnew.so` (aynı kod boyutu ve 59 712 fonksiyon başlangıcı, farklı sha256; DEFTER 12:45).
- **Kurulumlar arası yineleme** (aynı sha256'lı Mach-O): Microsoft Excel ↔ Microsoft Word 34 dosya, 466 MiB (bayt bayt aynı; Office uygulamaları paylaşılan çerçeveleri ayrı ayrı taşıyor). Bir kullanıcı ikisini de analiz ederse bugün 466 MiB iki kez analiz edilir (önbellek yok: K9).
- **Kapsam dışı:** bugünkü kural birçok uygulamada asıl kodu görmüyor: KiCad.app 298 / 304 Mach-O (asıl kod `PlugIns/*.kiface`), Chrome 50 Mach-O (777 MiB; yardımcılar ve `Libraries`), Docker 45 (840 MiB), ChatGPT 63 (693 MiB), FreeCAD 964 (781 MiB).
- **Hedef verilemeyen kurulumlar:** kökü `.app` olmayanlar (llvm, KiCad dizini, TeX Live; durdurulan Anaconda ve IBM SPSS Statistics de dizin) bugün tek hedef olarak verilemez (`karadul/core/target.py:189-194`).
- **Electron:** ChatGPT.app `app.asar` 747 MiB; Electron bileşeni ana bileşen katmanında (`karadul/analyzers/app_bundle.py:136`), JS hattı bu boyutta hiç koşulmadı.

## 2. Bugünkü akış nerede kırılır (kalem 2)

Her satır koddan okundu (main `b52408e`); "ölçüm" sütunu bu turdaki betiklerin çıktısıdır.

### 2.1 Tek büyük ikili

| # | Kırılma | Ne olur | Kanıt (dosya:satır) | Ölçüm |
|---|---|---|---|---|
| K1 | **Boyut kapısı yok** | Yerel ikilide (Mach-O / ELF / PE) boyut sınırı uygulanmıyor; `analysis.max_file_size_mb = 500` hiçbir yerde okunmuyor ve etkisiz ayarlar listesinde. `security.max_binary_size_bytes` (500 MB) yalnız PyInstaller / Python hatlarında. | `karadul/config.py:366`, `:1092-1094`; `karadul/analyzers/packed_binary.py:420-423`, `:1515`; `karadul/analyzers/python_binary.py:822` | — |
| K2 | **Süre sınırı yalnız iki adımda** | Sınır `timeouts.ghidra` = 7 200 sn; dosya 100 MB'ı aşarsa × 4 = 28 800 sn. Bu sınır otomatik analize ve toplam decompile süresine ayrı ayrı uygulanıyor; fonksiyon listesi, dizgi, çağrı grafiği, tip, xref, P-code, CFG, FunctionID ve BSim adımlarında **hiç sınır yok**. En kötü durumda köprü 2 × 8 sa + sınırsız. | `karadul/config.py:345`, `:632`, `:635`; `karadul/ghidra/headless.py:237-254` (sınır ve çarpan), `:319` + `:695` (analiz), `:403-409` + `:1207` (decompile), `:361`, `:372`, `:381`, `:426`, `:441`, `:463`, `:488`, `:504`, `:517-574` (sınırsız adımlar) | Gösteri diliminde sınırsız adımlar: dizgi 2,6 + çağrı grafiği 55,6 + tip 6,7 + xref 348,7 + P-code 3,1 + CFG 600,9 + FunctionID 0,1 + BSim 1 951,9 = 2 969,6 sn, köprünün (3 815,4 sn) %78'i (`gosteri_oku.py` `ghidra_adim_sn_mtime`) |
| K3 | **Takılan çözümleyici görünmez** | Otomatik analiz tek `analyzeAll` çağrısı; izleyici yalnız süreyi sayar. Bir çözümleyici tek fonksiyonda dönerse 7 200 sn dolana kadar hiçbir şey olmaz. | `karadul/ghidra/headless.py:695-700` | Gösteri 1. deneme: "Objective-C Message Analyzer" tek fonksiyonda 22+ dk; `deneme1_jstack.txt`'te `ObjcMessageAnalyzer.getAddressFromVarnode` 10 düzey özyineleme (`grep -c` = 10) |
| K4 | **İlerleme yok** | CLI'da ilerleme çubuğu `transient=True`, yalnız aşama düzeyinde; INFO günlüğü yalnız `--verbose` ile. Otomatik analizin içinden hiç ileti çıkmıyor. Statik aşama ilerlemesi yalnız 0,1 ve 0,7. | `karadul/cli.py:957-962`, `:979-999`; `karadul/stages.py:474-477`; `karadul/ghidra/headless.py:695-700` | Gösteri 1. deneme: `deneme1_kosu.log` 27 dk boyunca yalnız "Pipeline" başlığı (YAYIN_KAPISI G1); 2. denemede `kosu.log` 11:12'den 13:05'e (113 dk) hiç değişmedi (1 195 bayt; köprü, istihbarat, deobfuscate ve reconstruct boyunca) |
| K5 | **Python + JVM tek süreçte** | PyGhidra JVM'i Python sürecinin içinde açar; JVM yığını RAM'in %40'ı (bu makinede 14 745 MB, §3.4; en az 4, en çok 32 GB). Python tarafının belleği bunun üstüne eklenir; ikisi için tek bir bütçe yok. | `karadul/config.py:222`; `karadul/ghidra/headless.py:45-100` (`-Xmx` `:82`) | Gösteri 1. deneme `/usr/bin/time -l`: azami RSS 6 401 507 328 bayt, tepe ayak izi 7 379 524 304 bayt (otomatik analiz sırasında durduruldu) |
| K6 | **Bütün Ghidra çıktısı Python belleğinde** | Köprü her adımın çıktısını `scripts_output` sözlüğünde tutar ve sonunda topluca döndürür; decompile sonuçlarının tamamı (P-code dahil) liste olarak tutulur; `macho.py` aynı sözlükleri ikinci kez `json.dumps(indent=2)` ile diske yazar (her dosya iki kez). | `karadul/ghidra/headless.py:285`, `:362-605`, `:617-630`; `:1288`, `:1306` (`_all_functions`); `:2451-2457` (`_save_output`); `karadul/analyzers/macho.py:434-438`; `karadul/core/workspace.py:248` | `json.loads` bellek / disk = 3,46–6,14 (11 dosya; §3.4). Gösteri diliminde köprünün sözlükte tuttuğu JSON'ların boyutu ve bellek karşılığı §3.4'te |
| K7 | **xref ve CFG çıkarımı adres / komut başına Python↔Java çağrısı** | xref her fonksiyonun gövdesindeki **her adres** için `getReferencesFrom`; CFG her komut için `getMnemonicString`. Tek iş parçacığı. CFG'nin komut adı dökümünü yalnız K-1 ile bekletilen CFG-iso adımı okuyor. | `karadul/ghidra/headless.py:1737-1765` (xref), `:1792-1803` (bütün simgeler), `:2052-2074` (CFG); `karadul/pipeline/steps/cfg_iso_match.py:1-20`, `:43-62` | Örneklem içinde fonksiyon sayısına göre doğrusal üstü (xref b = 1,39, CFG 1,58), kod baytına göre doğrusal ya da sınırda (0,98; 1,12) (§3.2). Gösteri: kod MiB başına xref 66,4 sn, CFG 114,4 sn; örneklemde 6,9–9,5 ve 5,9–15,2 sn (7 kat sapma, nedeni ölçülmedi) |
| K8 | **Decompile parçaları statik** | Fonksiyonlar iş parçacığı sayısına eşit parçalara bölünür (parça = n / 9); yavaş fonksiyonlar bir parçada toplanırsa iş kuyruğu yok, kuyruk gecikmesi. Fonksiyon başına sınır 30 sn. | `karadul/ghidra/headless.py:1225-1229`, `:1260-1286`; `karadul/config.py:612` | Gösteri: 13 559 fonksiyon 523,3 sn (`decompiled.json` `duration_seconds`), 10 parça, 9 iş parçacığı |
| K9 | **Ghidra projesi her koşuda silinir; önbellek yok** | Analiz sonunda proje silinir; aynı ikiliyi ikinci kez açmak her şeyi baştan yapar. Aşama çıktıları için sha256 anahtarlı önbellek yok; her koşu yeni zaman damgalı çalışma alanı açar. | `karadul/analyzers/macho.py:1286-1300`; `karadul/ghidra/project.py:47-59`; `karadul/core/workspace.py:56`; `karadul/core/pipeline.py:333-337` | Gösteri projesi koşu sırasında 84 704 KiB (`du -sk`); 119'da `project.kept = false` |
| K10 | **Yeniden başlatma yok, kısmi sonuç zayıf** | `pipeline_result.json` yalnız en sonda yazılır; `--stage` yalnız "şu aşamada dur" der, "şuradan devam" yok. Köprü ortasında süreç ölürse `ghidra_output/*.json` kalır ama `static/ghidra_*.json` kopyaları (köprü dönünce yazılır) ve rapor oluşmaz; reconstruct koşamaz. | `karadul/core/pipeline.py:487`; `karadul/cli.py:636`; `karadul/analyzers/macho.py:430-438` | Gösteri 1. deneme: SIGTERM (143) sonrası `deneme1_ws`'de kullanılabilir rapor yok |
| K11 | **Reconstruct belleği** | Ad döngüsü bütün `.c` metinlerini bellekte tutar (`file_cache`); her yineleme sonunda yeniden okur. `functions.json`, `call_graph.json`, `cfg.json` farklı adımlarda ayrı ayrı yeniden ayrıştırılır. Yineleme süre sınırı yineleme bittikten SONRA denetlenir: ilk yineleme saatler sürse de kesilmez. | `karadul/pipeline/steps/feedback_loop.py:180-191`, `:341-352`; `karadul/pipeline/steps/ghidra_metadata.py:148-174`; `_feedback_naming_merger.py:125`; `_feedback_naming_candidates.py:228`; `_feedback_naming_refdiff.py:134-148`; `karadul/config.py:649` | 119'da reconstruct ↔ fonksiyon b = 0,71 [0,53; 1,01] (örneklem içi; büyük ikilide ölçülmedi) |
| K12 | **Disk ve dosya sayısı** | Reconstruct her fonksiyon için ~10 kopya `.c` yazar (`merged`, `merged_iter1`, `semantic_named`, `commented`, `annotated`, `struct_recovered`, `src`, `project`, `data_flow`, …). Çalışma alanı öntanımda proje kökünün altında. Disk bütçesi ya da ön denetim yok. | `karadul/core/pipeline.py:333-336`; dizin dökümü (en büyük ikili, `du -sk`) | 119: fonksiyon başına 12,2 dosya ve 80 900–93 900 bayt (alt / üst çeyrek medyanı); en büyük ikilide 649 MB ve 68 504 dosya (5 697 fonksiyon). Gösteri çalışma alanı 11:44'te (köprü sürerken, reconstruct'tan önce) 588 196 KiB (`du -sk`) |
| K13 | **Arayüz bütün fonksiyonları bir kerede yükler** | `build_model` her `.c` dosyasını belleğe okur, düzenli ifadeyle tarar, bütün fonksiyonları tek JSON'da döndürür. İş günlüğü her yoklamada baştan okunur. | `ui/server.py:351-460` (`:370-383` dosya okuma), `:2477-2483`; liste 600 satırla sınırlı (`ui/index.html:801`) | Ölçülmedi (gösteri bitince ÖLÇ-0) |
| K14 | **Aynı dosya iki kez analiz edilir** | sha256 ile yineleme denetimi yok. | `karadul/core/target.py:196-197` (sha256 hesaplanıyor; elle ad deposu ve hesaplama önbelleği anahtarı olarak kullanılıyor, yineleme denetiminde kullanılmıyor) | Geliştirme setinde bile: redis-check-aof ve redis-check-rdb aynı sha256 (65846e52…), 658 + 708 sn |
| K15 | **İkili istihbarat süresi sınırsız** | Köprüden sonra bütün dizgiler ve bütün `.c` dosyaları üstünde ikili istihbarat koşar; süre sınırı yok. | `karadul/analyzers/macho.py:472-531`; `karadul/analyzers/binary_intelligence.py:2088`, `:2142`, `:2211` | Gösteri: 12:14:43 → 12:29:30 = 887 sn (73 467 dizgi, 13 554 `.c`); örneklemde statik aşamanın köprü dışı kısmı sabit ≈ 5 sn (model c0), gösteride 912 sn (öngörü 35 [10; 77]) |

### 2.2 Çok bileşenli paket (`.app`)

| # | Kırılma | Ne olur | Kanıt (dosya:satır) | Ölçüm |
|---|---|---|---|---|
| P1 | **Bütçesiz, sıralı, eleme yok** | Her bileşen sırayla, tam derinlikte (Ghidra + decompile + çıkarım) analiz edilir; toplam ya da bileşen başına süre bütçesi, öncelik, eleme yok. Yorum "paralel" diyor, kod sıralı. | `karadul/analyzers/app_bundle.py:425-443`, `:525`; `karadul/stages.py:438` (eskimiş yorum), `:595-683` | §3.6 paket tahmini |
| P2 | **Bağlı dosyalar ayrı bileşen** | `Resources/**/*.dylib` taraması bağlı dosyaları da verir; aynı kitaplık sürüm adlarıyla 3 kez analiz edilir. | `karadul/core/target.py:281-289` | Ollama.app: 26 bileşen, 16 tekil sha256; FreeCAD.app: 1 903 bileşen, 867 tekil sha256 (1 036 bileşen aynı dosyanın bağ adı) (`envanter.py`) |
| P3 | **Kapsam dışı kalan Mach-O** | Yalnız `Contents/MacOS/*`, `Frameworks/**/*.framework/<ad>`, `Resources/**/*.jar`, `Resources/**/*.dylib`. `Resources`'taki çalıştırılabilirler, `Frameworks/*.dylib`, iç `.app` yardımcıları, XPC, PlugIns hiç analiz edilmez. | `karadul/core/target.py:244-311` | Ollama.app: 18 Mach-O (104 MB) kapsam dışı; aralarında asıl sunucu `Contents/Resources/ollama` (52 MB). KiCad.app: 6 bileşen (19,5 MB), 298 Mach-O (822 MB) kapsam dışı — asıl kod `Contents/PlugIns/*.kiface`. FreeCAD.app: 964 Mach-O (819 MB) kapsam dışı |
| P4 | **Ana bileşen sonradan seçilir** | Ana bileşen bütün bileşenler bittikten sonra seçilir (tür + fonksiyon sayısı); kullanıcıya ilk yararlı rapor ancak en sonda. | `karadul/analyzers/app_bundle.py:89-99`, `:445-447`; `karadul/stages.py:642-668` | — |
| P5 | **Paket durumu en sonda yazılır** | `bundle_analysis.json` döngü bitince yazılır; ortada ölürse hangi bileşenin bittiği kayıtta yok; devam yok. | `karadul/analyzers/app_bundle.py:469-474` | — |
| P6 | **Kurulum dizini hedef olamaz** | `.app` olmayan dizin (KiCad kurulumu, Homebrew şişesi, Python ortamı) hedef verilemez: `ValueError`. | `karadul/core/target.py:189-194` | Envanterde 4 kurulumun kökü `.app` değil (§1) |
| P7 | **Bileşen çalışma alanları tam** | Her bileşen kendi alt çalışma alanına tam statik çıktı yazar; yalnız ana bileşen yeniden kurulur, ötekilerin çıktısı yalnız özet için. | `karadul/analyzers/app_bundle.py:513-525`; `karadul/core/workspace.py:125-` | Statik çıktı 119'da çalışma alanının ≈ %26'sı (en büyük ikili: 169 / 649 MB) |

### 2.3 Küçük ama ölçeğe dokunan

- `TargetDetector.detect` CLI'da ve boru hattında iki kez çağrılıyor; tek dosyada sha256 iki kez (`karadul/cli.py:929-930`, `karadul/core/pipeline.py:301`). 1 GB'lık dosyada ölçülmedi.
- Geçici hata türlerinde (`TimeoutError` dahil) aşama baştan yeniden koşar (`karadul/core/error_recovery.py:230-235`, `karadul/core/pipeline.py:494-519`): saatlik bir statik aşamada `TimeoutError` yükselirse aşama 3 kez yinelenebilir. Bugün statik aşamada böyle bir yol görülmedi; risk notu.
- Paket dalı YARA ve capa taramasını atlıyor (`karadul/stages.py:439-440`, `:573-577`): ölçek değil kapsam kusuru; başka hat için not (D5).

## 3. Ölçekleme verisi (kalem 3)

### 3.1 Veri ve yöntem

- **Künye:** `scripts/arge/olcek/olcek_topla.py` → `olcek_a62f15e.json` (119 kayıt). Her ikilide: aşama süreleri (`reports/pipeline_result.json`), reconstruct'ın `timing_*` adımları, Ghidra köprüsü süresi ve fonksiyon sayıları (`static/ghidra_status.json`), "Otomatik analiz: N sn" (`static/ghidra_log.txt`), decompile süresi (`ghidra_output/decompiled.json`), disk (ayrılan bayt, dosya sayısı). **Ghidra köprüsünün adım süreleri** `ghidra_output/*.json` dosyalarının değişim zamanlarından: köprü her adımın çıktısını adım biter bitmez yazıyor (`karadul/ghidra/headless.py:362-604`).
  Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/olcek_topla.py --kok ~/karadul_olcum/runs/urun-onarim-a62f15e --etiket a62f15e --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/olcek_a62f15e.json`
- **Kod baytı:** `scripts/arge/olcek/metin_boyutu.py` (`llvm-size -A`; yalnız bölüm başlığı; geliştirme seti açık kaynak) → `olcek_a62f15e_metin.json`.
- **Gösteri (örneklem dışı):** `scripts/arge/olcek/gosteri_oku.py` (salt okur; dosya zamanları, JSON'ların ilk 600 baytı, `ghidra_status.json`) → `gosteri_<saat>.json`.
- **Eğri:** `scripts/arge/olcek/olcek_egri.py` → `egri.json`, `egri_ozet.txt`. (A) log-log OLS; (B) y = c0 + c1·x^b (log uzayında uydurma; c0 sabit gider). b için önyükleme %95 aralığı (400 yeniden örnek, tohum 20261119). "Doğrusal üstü" = (B)'nin b'sinin alt sınırı > 1,05.
  Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/olcek_egri.py --kunye ~/karadul_olcum/runs/arge-2026-11-19/olcek/olcek_a62f15e_metin.json --gosteri <gosteri_*.json> --kalibrasyon ~/karadul_olcum/runs/arge-2026-11-19/olcek/yogunluk.json --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/egri.json`
- **Sınırlar:** (1) örneklem 67 KB – 3,2 MB, 34 – 5 697 fonksiyon; 106'sı coreutils (aynı kod tabanı). (2) 119 koşusu `--paralel 3` ve 5–7 ajan yükü altında; gösteri koşusu da yük altında (12:33'te yanında ikinci bir `karadul analyze` vardı). Yük ayrılamadı. (3) Tepe bellek 119'da hiç kaydedilmemiş; yalnız gösteri 1. denemesinde `/usr/bin/time -l` var.
- **Bölme notu (dürüstlük):** gösteri sayılarını eğriyi uydurmadan önce gördüm; bu yüzden gösteri kıyası ön kayıtlı bir sınama değil, model biçiminin örneklem dışı denetimidir. Ön kayıtlı sınama ÖLÇ-0'dadır (PLAN; reconstruct henüz başlamamışken yazıldı).

### 3.2 Örneklem içi: hangi adım doğrusal üstü büyüyor

(B) modelinin üssü b, %95 aralığıyla; x = fonksiyon sayısı (`fonk_toplam`) ya da kod baytı (`metin_bayt`). Kaynak: `egri_ozet.txt`.

| Ölçü | b ↔ fonksiyon | b ↔ kod baytı | Hüküm |
|---|---|---|---|
| Uçtan uca süre | 0,84 [0,62; 1,16] | 0,67 [0,45; 0,92] | bu aralıkta sabit gider baskın (c0 ≈ 26–36 sn) |
| Ghidra köprüsü | 1,10 [0,90; 1,31] | 0,91 [0,75; 1,06] | belirlenemedi |
| Otomatik analiz | 0,76 [0,64; 0,89] | 0,57 [0,46; 0,70] | doğrusal altı (örneklemde) |
| Çağrı grafiği | **1,28 [1,13; 1,50]** | 0,91 [0,87; 0,93] | fonksiyona göre doğrusal üstü; kod baytına göre doğrusal (adres başına çağrı) |
| Decompile | **1,49 [1,35; 1,86]** | 1,15 [1,02; 1,31] | fonksiyona göre doğrusal üstü (büyük programın fonksiyonları da büyük) |
| xref | **1,39 [1,21; 1,59]** | 0,98 [0,95; 1,05] | fonksiyona göre doğrusal üstü; kod baytına göre doğrusal |
| CFG | **1,58 [1,32; 1,84]** | 1,12 [1,05; 1,24] | fonksiyona göre doğrusal üstü; koda göre sınırda |
| BSim | 1,17 [0,98; 1,38] | 0,85 [0,71; 0,98] | örneklemde belirlenemedi (örneklem dışında güçlü doğrusal üstü, §3.3) |
| Reconstruct | 0,71 [0,54; 1,01] | 0,53 [0,40; 0,81] | doğrusal altı (örneklemde) |
| reconstruct `c_naming_iter0` | 1,15 [1,05; 1,34] | 0,83 [0,75; 0,91] | fonksiyona göre sınırda |
| Çalışma alanı diski | **1,14 [1,06; 1,28]** | 0,79 [0,74; 0,89] | fonksiyona göre doğrusal üstü |
| Çalışma alanı dosya sayısı | 1,00 [0,99; 1,01] | — | fonksiyon başına sabit: alt / üst çeyrek medyanı 12,4 / 12,2 dosya |

### 3.3 Örneklem dışı: gösteri dilimi (26,6 MB; 5,5 MB kod; 13 559 fonksiyon)

Ghidra köprüsü 3 815,4 sn (`ghidra_status.json` `duration_seconds`). Adımlar (dosya zamanlarından; `gosteri_oku.py`):

| Adım | Süre (sn) | Pay | Örneklem modeli öngörüsü (kod ekseni; decompile ve BSim için de) | Gözlenen / öngörü | İki noktalı üs (redis-check-aof → gösteri, kod baytına göre) |
|---|---|---|---|---|---|
| JVM + içe aktarma + otomatik analiz + fonksiyon listesi | 320,6 (otomatik analiz 226,4) | %8,4 | 72,3 [48,1; 179,1] | 4,43 | 1,77 |
| Dizgiler | 2,6 | %0,1 | — | — | — |
| Çağrı grafiği | 55,6 | %1,5 | 25,3 [22,8; 28,2] | 2,20 | 1,58 |
| Decompile | 523,9 | %13,7 | 522,9 [368,5; 784,3] | **1,00** | 1,10 |
| Tipler | 6,7 | %0,2 | — | — | — |
| xref | 348,7 | %9,1 | 40,5 [35,6; 48,0] | 8,62 | 2,60 |
| P-code yazımı | 3,1 | %0,1 | — | — | — |
| CFG | 600,9 | %15,7 | 61,9 [46,3; 85,4] | 9,71 | 2,68 |
| FunctionID | 0,1 | 0 | — | — | — |
| BSim (ingest + sorgu) | 1 951,9 | **%51,2** | 303,3 [208,0; 423,8] | 6,44 | 2,47 (fonksiyona göre 3,46) |

- Statik aşamanın köprü dışı kısmı (otool / strings / nm / lief + ikili istihbarat): gösteride 912 sn, öngörü 35,2 [10,1; 77,4] (25,9 kat); bunun 887 sn'si ikili istihbarat (K15).
- **Okuma:** yalnız decompile modelle tuttu. Decompile işi Ghidra'nın ayrı yerel `decompile` süreçlerinde, 9 iş parçacığında koşuyor; sapan adımların hepsi JVM'in içinde ve Python↔Java köprüsünden tek iş parçacığıyla koşuyor. **Hipotez (sınanmadı):** büyüdükçe JVM yığın baskısı / çöp toplama ya da Python↔Java çağrı başına maliyet artıyor. Öbür adaylar: yük farkı, Go'ya özgü yapı (`ghidra_log.txt` "Xrefs" satırında 173 498 simge; örneklemin en büyüğünde, redis-check-aof, 55 449). Ayırt edici ölçüm: PLAN ÖL-3 adım 1 (JVM GC günlüğü `JAVA_TOOL_OPTIONS` ile, kod değişikliği gerekmez).
- **BSim'in sonucu:** "BSim query: 0 esleme", "BSim shadow dump: 0 fonksiyon" (`ghidra_log.txt`). Koşuya özel boş depoda program yalnız kendisiyle karşılaşıyor ve kendisi dışlanıyor (`karadul/ghidra/bsim.py:626-648`). Öntanımda BSim gölge kipte (`karadul/config.py` `BSimConfig.shadow_mode = True`): sonucu ad haritasına girmez. Yani gösteride köprünün yarısı, ada hiçbir katkısı olamayacak bir adıma gitti.
- Kalibrasyon (açık kaynak, `metin_boyutu.py --ek-liste`; `LC_FUNCTION_STARTS`): gösteri dilimi kod MiB başına 2 465 fonksiyon başlangıcı; LLVM 23.1.6'nın 5 MB üstü 9 Mach-O'sunda 1 547–3 342. Yani gösteri dilimi **kod başına** sıradan bir C++ ikilisi kadar yoğun; dosya baytı başına seyrek olması Go'nun veri bölümlerinden (`__rodata` 15,6 MB, `__gopclntab` 3,6 MB; `llvm-size -m`).

### 3.4 Bellek

- **Tek ölçüm:** gösteri 1. deneme (otomatik analizin 22. dakikasından sonra SIGTERM): azami RSS 6 401 507 328 bayt, tepe ayak izi 7 379 524 304 bayt (`deneme1_kosu.log`, `/usr/bin/time -l`). PyGhidra JVM'i Python sürecinin içinde açtığı için bu sayı Python + JVM'dir (`karadul/ghidra/headless.py:45-100`). JVM yığın sınırı bu makinede 14 745 MB (RAM'in %40'ı: `karadul/config.py:222`; `python -c "from karadul.config import GHIDRA_HEAP_MB, TOTAL_MEMORY_MB; print(GHIDRA_HEAP_MB, TOTAL_MEMORY_MB)"` → 14745 36864).
- **Python tarafı çarpanı:** `scripts/arge/olcek/bellek_carpani.py` (her dosya ayrı alt süreçte `json.loads(read_text())`, `ru_maxrss` farkı) → `bellek_carpani.json`. 11 dosyada (1,7–122 MiB) bellek / disk = 3,46–6,14; 122 MiB'lık gösteri `cfg.json` 4,64.
  Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/bellek_carpani.py --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/bellek_carpani.json <redis / tmux / gösteri ghidra_output JSON'ları>`
- **Köprü sözlüğü (K6):** gösteride köprünün sonunda `scripts_output`'ta tutulan çıktıların disk boyutu 202 701 708 bayt (`gosteri_oku.py` `kopru_sozluk_json_bayt`; `pcode.jsonl` 128 297 843 bayt ayrıca, decompile sonucu listesinin karşılığı). × 3,46–6,14 → **0,65–1,16 GiB** Python belleği yalnız bu sözlük için (TAHMİN: çarpan × boyut). Buna `macho.py:434-438`'in her dosyayı `json.dumps(indent=2)` ile ikinci kez metne çevirmesi eklenir (en büyük dosya `cfg.json` 122 MiB'lık metin).
- **Büyük ikili için (TAHMİN):** köprü JSON'unun toplam boyutu (örneklem modeli, fonksiyon ekseni) × 3,46–6,14 + JVM yığını (§3.5 tablosunun son sütunu, `olcek_egri.py --bellek-carpani`). T100 (163 141 fonksiyon): köprü JSON'u 2,0–9,0 GB → Python tarafı 7,0–55,2 GB; T300: 31,9–357,6 GB. 36 GB'lık bu makinede T100'ün üst ucu, T300'ün alt ucu bile sığmaz (JVM yığını 14,7 GB ayrıca). Ölçülmedi; ÖLÇ-1'in örnekleyicisi ölçecek.

### 3.5 Dış değerleme: tek ikili (TAHMİN)

**Hepsi TAHMİNDİR; hiçbiri ölçülmedi.** Yöntem (`olcek_egri.py` belge başı): gösteri dilimi çapa; her köprü adımı t = t_çapa × (x / x_çapa)^b; x kod baytı (otomatik analiz, çağrı grafiği, xref, CFG) ya da fonksiyon sayısı (decompile, BSim). b: örneklem (119) modelinin %95 aralığı → **A senaryosu [alt; üst]**. **B (kötümser)**: örneklemin en büyüğüyle gösteri arasındaki iki noktalı üs, en çok 2 (VARSAYIM: hiçbir adım algoritma olarak tümü-çiftlerden kötü değil; B yön göstericidir). Genel boyutlarda (25 MB … 1 GB) dosya → kod oranı ve kod MiB başına fonksiyon, açık kaynak 99 Mach-O'dan (LLVM 9, KiCad 27, FreeCAD 61, büyük 3 kitaplık: `yogunluk.json`) p10 / p90: kod oranı 0,376 / 0,668; kod MiB başına fonksiyon başlangıcı 1 700 / 5 325 (çapa 2 465). Adlı hedeflerde kod baytı ve fonksiyon sayısı hedefin kendi ölçüsü (`LC_FUNCTION_STARTS`; Ghidra / `LC_FUNCTION_STARTS` oranı çapada 1,047). Reconstruct, disk, dosya sayısı ve köprü JSON'u örneklem modelinden (çapasız; fonksiyon ekseni); Python köprü belleği = köprü JSON'u × bellek çarpanı (3,46–6,14).
Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/tahmin_tablo.py --egri ~/karadul_olcum/runs/arge-2026-11-19/olcek/egri.json`

| Hedef | Dosya (MB) | Kod (MiB) | Fonksiyon | Köprü A [alt; üst] (sa) | Köprü B kötümser (sa) | BSim alt uç (sa) | BSim hariç köprü alt (sa) | Reconstruct [alt; üst] (sa) | Çalışma alanı (GB) | Dosya (milyon) | Python köprü belleği (GB) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 25 MB | 26,2 | 9,4–16,7 | 15 995–88 920 | [1,5; 14,4] | 34,3 | 0,7 | 0,8 | [0,1; 1,1] | [1,9; 28,2] | [0,2; 1,1] | [0,7; 26,2] |
| 100 MB | 104,9 | 37,6–66,8 | 63 981–355 681 | [6,3; 128,5] | 530,0 | 2,6 | 3,7 | [0,2; 4,0] | [8,6; 154,6] | [0,8; 4,6] | [2,8; 143,8] |
| 300 MB | 314,6 | 112,9–200,4 | 191 943–1 067 044 | [20,5; 799,4] | 4 662,5 | 7,7 | 12,7 | [0,4; 11,0] | [28,1; 596,2] | [2,3; 13,9] | [8,3; 554,3] |
| 1 GB | 1 073,7 | 385,3–684,0 | 655 165–3 642 178 | [79,4; 6 683,0] | 53 161,8 | 25,8 | 53,6 | [0,8; 33,7] | [105,2; 2 694,2] | [7,9; 47,6] | [28,0; 2 503,4] |
| T100: mlir-transform-opt | 94,9 | 54,1 | 163 141 | [14,5; 39,4] | 136,5 | 6,6 | 8,0 | [0,4; 2,0] | [23,6; 59,3] | [2,0; 2,1] | [7,0; 55,2] |
| L169: libLLVM.23.1.dylib | 169,4 | 75,9 | 149 018 | [14,8; 37,3] | 151,8 | 6,0 | 8,8 | [0,4; 1,8] | [21,4; 53,1] | [1,8; 1,9] | [6,4; 49,4] |
| K92: _pcbnew.kiface | 97,4 | 26,1 | 59 712 | [5,3; 9,3] | 22,3 | 2,4 | 2,9 | [0,2; 0,8] | [8,0; 17,3] | [0,7; 0,8] | [2,6; 16,1] |
| T300: libtensorflow_cc.2.dylib | 646,6 | 210,2 | 746 814 | [77,9; 447,5] | 2 567,9 | 29,4 | 48,5 | [0,9; 7,9] | [121,2; 384,6] | [8,9; 9,7] | [31,9; 357,6] |
| B210: Blender | 210,0 | 102,7 | 223 745 | [22,4; 68,0] | 310,8 | 9,0 | 13,4 | [0,4; 2,6] | [33,1; 87,5] | [2,7; 2,9] | [9,6; 81,4] |

**Okuma:**
- Adlı açık kaynak hedeflerde: ~100 MB'lık C++ ikilisi (mlir-transform-opt: 54 MiB kod, 163 141 fonksiyon) için yalnız Ghidra köprüsü A senaryosunda **14,5–39,4 saat**, B'de 136,5 saat. 646,6 MB'lık `libtensorflow_cc.2.dylib` (746 814 fonksiyon) için A 77,9–447,5 saat.
- Bugünkü sınırlar tabloya girmedi: otomatik analiz ve toplam decompile süresi her biri `timeouts.ghidra` = 7 200 sn (100 MB üstü dosyada 28 800 sn) ile kesilir (K2). T100 (94,9 MB < 100 MB) için decompile alt ucu 16 214 sn > 7 200 sn → **decompile bugün kısmi kalır**; geri kalan sınırsız adımlar (xref, CFG, BSim) alt uçta yine 33 775 sn (`egri.json` T100 satırının adım değerleri).
- BSim alt uçta köprünün %38–45'i (T100 6,6 / 14,5 sa = 0,451; T300 29,4 / 77,9 sa = 0,377; `egri.json`). Boş depoda sorgu atlanırsa (ÖL-2) bu payın sorgu kısmı düşer.
- Bellek: T100'de köprü sözlüğü için Python tarafı 7,0–55,2 GB (TAHMİN) + JVM yığını 14,7 GB; üst uç 36 GB'lık makineye sığmaz. T300'de alt uç bile 31,9 GB.
- Disk: T100 çalışma alanı 23,6–59,3 GB ve 2,0–2,1 milyon dosya; T300 121–385 GB ve ~9 milyon dosya.
- Genel 100 MB satırının aralığı geniş, çünkü dosya → kod oranı (0,38–0,67) ve fonksiyon yoğunluğu (1 700–5 325 / MiB) kalibrasyonda geniş; adlı hedefler daha dar.

### 3.6 Dış değerleme: paket (TAHMİN)

**Hepsi TAHMİNDİR.** Yalnız statik aşama (her bileşen tam statik analiz alır; reconstruct yalnız ana bileşende ve burada sayılmadı → alt sınır). Bileşen başına: dilim = dosya / mimari sayısı (eşit bölme); kod = dilim × kod oranı (p10 / p90: 0,376 / 0,668); süre: kod ≤ örneklemin en büyüğü (1 633 076 B) ise örneklem modeli (`static_sn|metin_bayt`); örneklemin en büyüğü ile çapa (5 509 156 B kod) arasında iki noktalı üsle ara değerleme; çapadan büyükse çapa (gösteri statik aşaması 4 727 sn = köprü 3 815 + köprü dışı 912) × (kod / çapa kodu)^b, **doğrusal** b = 1, **kötümser** b = köprünün iki noktalı üssü 2,04 → 2 ile sınırlı. Senaryolar: S0 bugünkü kural (bağlar ayrı bileşen; JAR ve Electron JS bileşeni süreye katılmadı); S1 aynı sha256 bir kez; S2 yol adından üçüncü taraf çıkarılırsa (doğrulanmamış); S3 kurulumdaki bütün tekil Mach-O (kapsam tam).
Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/paket_tahmin.py --envanter ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter --egri ~/karadul_olcum/runs/arge-2026-11-19/olcek/egri.json --gosteri <gosteri_*.json> --kunye ~/karadul_olcum/runs/arge-2026-11-19/olcek/olcek_a62f15e_metin.json --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/paket_tahmin.json`

| kurulum | senaryo | bileşen | dilim (MiB, eşit bölme) | en büyük dilim (MiB) | örneklem üstü | statik süre, doğrusal [alt; üst] (saat) | kötümser (saat) |
|---|---|---|---|---|---|---|---|
| Blender | S0_bugun | 51 | 549 | 200 | 12 | [49.5; 88.8] | 1209.6 |
| Blender | S1_yineleme_bir_kez | 51 | 549 | 200 | 12 | [49.5; 88.8] | 1209.6 |
| Blender | S2_ucuncu_taraf_disi | 51 | 549 | 200 | 12 | [49.5; 88.8] | 1209.6 |
| Blender | S3_tum_tekil_macho | 206 | 686 | 200 | 25 | [56.3; 102.9] | 1228.7 |
| ChatGPT | S0_bugun | 29 | 296 | 267 | 2 | [27.2; 48.2] | 1525.6 |
| ChatGPT | S1_yineleme_bir_kez | 29 | 296 | 267 | 2 | [27.2; 48.2] | 1525.6 |
| ChatGPT | S2_ucuncu_taraf_disi | 28 | 296 | 267 | 2 | [27.2; 48.1] | 1525.6 |
| ChatGPT | S3_tum_tekil_macho | 91 | 987 | 268 | 16 | [90.2; 161.1] | 3624.6 |
| Cursor | S0_bugun | 5 | 178 | 177 | 1 | [16.7; 29.6] | 666.5 |
| Cursor | S1_yineleme_bir_kez | 5 | 178 | 177 | 1 | [16.7; 29.6] | 666.5 |
| Cursor | S2_ucuncu_taraf_disi | 1 | 0 | 0 | 0 | [0.0; 0.0] | 0.0 |
| Cursor | S3_tum_tekil_macho | 40 | 375 | 177 | 10 | [32.9; 59.9] | 933.7 |
| Docker | S0_bugun | 32 | 443 | 166 | 12 | [39.7; 71.6] | 849.9 |
| Docker | S1_yineleme_bir_kez | 32 | 443 | 166 | 12 | [39.7; 71.6] | 849.9 |
| Docker | S2_ucuncu_taraf_disi | 26 | 440 | 166 | 12 | [39.6; 71.4] | 849.7 |
| Docker | S3_tum_tekil_macho | 77 | 1283 | 166 | 37 | [116.3; 210.2] | 2092.3 |
| FL Studio 2025 | S0_bugun | 207 | 511 | 16 | 106 | [16.6; 39.2] | 46.0 |
| FL Studio 2025 | S1_yineleme_bir_kez | 200 | 498 | 16 | 104 | [16.1; 37.5] | 44.4 |
| FL Studio 2025 | S2_ucuncu_taraf_disi | 187 | 467 | 16 | 100 | [14.2; 33.4] | 38.7 |
| FL Studio 2025 | S3_tum_tekil_macho | 294 | 596 | 28 | 110 | [23.9; 52.0] | 75.8 |
| FreeCAD | S0_bugun | 1903 | 2750 | 133 | 203 | [177.2; 345.3] | 1958.1 |
| FreeCAD | S1_yineleme_bir_kez | 867 | 1155 | 133 | 77 | [77.1; 147.4] | 977.9 |
| FreeCAD | S2_ucuncu_taraf_disi | 533 | 425 | 44 | 36 | [25.4; 50.4] | 124.7 |
| FreeCAD | S3_tum_tekil_macho | 1817 | 1936 | 133 | 128 | [111.7; 212.9] | 1178.2 |
| Google Chrome | S0_bugun | 2 | 254 | 254 | 1 | [23.9; 42.3] | 1364.3 |
| Google Chrome | S1_yineleme_bir_kez | 2 | 254 | 254 | 1 | [23.9; 42.3] | 1364.3 |
| Google Chrome | S2_ucuncu_taraf_disi | 1 | 0 | 0 | 0 | [0.0; 0.0] | 0.0 |
| Google Chrome | S3_tum_tekil_macho | 44 | 630 | 254 | 11 | [57.4; 103.1] | 2768.3 |
| KiCad | S0_bugun | 12 | 14 | 7 | 2 | [0.6; 1.6] | 1.6 |
| KiCad | S1_yineleme_bir_kez | 12 | 14 | 7 | 2 | [0.6; 1.6] | 1.6 |
| KiCad | S2_ucuncu_taraf_disi | 12 | 14 | 7 | 2 | [0.6; 1.6] | 1.6 |
| KiCad | S3_tum_tekil_macho | 299 | 401 | 46 | 28 | [28.2; 53.0] | 178.6 |
| LM Studio | S0_bugun | 8 | 194 | 164 | 3 | [18.3; 32.4] | 577.2 |
| LM Studio | S1_yineleme_bir_kez | 8 | 194 | 164 | 3 | [18.3; 32.4] | 577.2 |
| LM Studio | S2_ucuncu_taraf_disi | 4 | 30 | 15 | 2 | [2.8; 5.0] | 9.7 |
| LM Studio | S3_tum_tekil_macho | 43 | 471 | 164 | 16 | [41.2; 74.8] | 1019.1 |
| Microsoft Excel | S0_bugun | 58 | 289 | 76 | 18 | [22.6; 42.2] | 203.1 |
| Microsoft Excel | S1_yineleme_bir_kez | 58 | 289 | 76 | 18 | [22.6; 42.2] | 203.1 |
| Microsoft Excel | S2_ucuncu_taraf_disi | 39 | 163 | 76 | 9 | [12.4; 23.1] | 143.2 |
| Microsoft Excel | S3_tum_tekil_macho | 190 | 348 | 76 | 28 | [25.0; 47.7] | 208.7 |
| Microsoft Word | S0_bugun | 61 | 277 | 64 | 18 | [21.5; 40.2] | 167.3 |
| Microsoft Word | S1_yineleme_bir_kez | 61 | 277 | 64 | 18 | [21.5; 40.2] | 167.3 |
| Microsoft Word | S2_ucuncu_taraf_disi | 41 | 151 | 64 | 9 | [11.2; 21.1] | 107.3 |
| Microsoft Word | S3_tum_tekil_macho | 198 | 383 | 64 | 27 | [29.1; 54.7] | 244.2 |
| Ollama | S0_bugun | 26 | 140 | 26 | 13 | [10.2; 19.3] | 51.8 |
| Ollama | S1_yineleme_bir_kez | 16 | 118 | 26 | 9 | [9.6; 17.4] | 50.0 |
| Ollama | S2_ucuncu_taraf_disi | 5 | 34 | 26 | 3 | [2.6; 4.7] | 14.6 |
| Ollama | S3_tum_tekil_macho | 34 | 179 | 26 | 12 | [13.1; 24.5] | 66.1 |
| TeX Live | S3_tum_tekil_macho | 163 | 258 | 48 | 17 | [19.4; 36.7] | 129.3 |
| Visual Studio Code | S0_bugun | 7 | 175 | 168 | 2 | [16.1; 28.9] | 597.3 |
| Visual Studio Code | S1_yineleme_bir_kez | 6 | 175 | 168 | 2 | [16.1; 28.9] | 597.3 |
| Visual Studio Code | S2_ucuncu_taraf_disi | 2 | 6 | 6 | 1 | [0.3; 0.9] | 0.9 |
| Visual Studio Code | S3_tum_tekil_macho | 39 | 239 | 168 | 7 | [20.8; 38.2] | 613.4 |
| llvm-23.1.6 | S3_tum_tekil_macho | 166 | 682 | 162 | 17 | [59.6; 106.8] | 1436.1 |

**Okuma:**
- FreeCAD.app (2,48 GiB) bugünkü kuralla doğrusal senaryoda **177–345 saat** (7–14 gün) statik analiz; bağ / yineleme bir kez sayılınca 77–147 saat; yol adından üçüncü taraf çıkarılınca (doğrulanmamış) 25–50 saat (S2 satırı). S0 → S1 oranı 177,2 / 77,1 = 2,30 ve 345,3 / 147,4 = 2,34.
- Tek bir büyük üçüncü taraf çerçeve paketi taşıyor: Chrome'da bugünkü kural yalnız 2 bileşen görüyor ama Chrome Framework dilimi (254 MiB) tek başına 24–42 saat. Electron uygulamalarında (Cursor, VS Code, LM Studio) S2'nin neredeyse sıfıra inmesi, statik sürenin tamamının Electron / Node çalışma zamanından geldiğini söylüyor (yol adına göre).
- KiCad'de bugünkü kural 0,6–1,6 saat görünüyor, çünkü asıl kodu (`PlugIns/*.kiface`) analiz etmiyor; kapsam tam (S3) 28–53 saat.
- Gösteri dilimi Go ağırlıklı (kod oranı 0,21 < p10 0,376): bu tablo Go bileşenlerini fazla öngörür (Ollama.app satırları). Kötümser sütun yalnız yön gösterir.
- Sonuç: "birkaç GB'lık kurulumun tamamı" bu makinede bugünkü akışla haftalar; yineleme / bağ ayıklama tek başına FreeCAD'de 2,3 kat kazandırır (S0 → S1), ama bütçe ve öncelik olmadan gün mertebesinden inmez.

## 4. Tasarım seçenekleri (kalem 4)

Her seçenek için: ne kazandırır, neye mal olur, hangi dosyalara değer, nasıl ölçülür. Kazanç sütunundaki sayılar bu turun ölçümüdür; "TAHMİN" yazılı olanlar dış değerlemedir.

| # | Seçenek | Kazanç | Bedel / risk | Dosyalar | Ölçüm |
|---|---|---|---|---|---|
| S1 | **Paket düzeyi yönetici:** envanter → bağ / yineleme ayıklama → kapsam dışı listesi → öncelik (ana bileşen önce) → bileşen başına ve toplam bütçe → kalıcı kuyruk | Bağ ve yineleme ayıklama tek başına Ollama.app'te 26 → 16 bileşen (§1). Ana bileşen önce: ilk yararlı rapor ana bileşen bitince (bugün en sonda). Bütçe: paket süresi üstten sınırlı. | Ana bileşen seçimi analizden önce (tür + boyut) yapılmalı; bugünkü "en çok fonksiyon" kuralı değişir. Bütçe dışı bileşen derin analiz edilmez (görünür kalır). ~400–700 satır + test. | `karadul/core/target.py:227-366`, `karadul/analyzers/app_bundle.py:393-481`, `karadul/stages.py:595-683`, `karadul/config.py` | Paket hedefinde ilk rapor zamanı, toplam süre, bileşen durumları; kesip sürdürme denemesi |
| S2 | **Bilinen bileşeni atlama ve yineleneni bir kez analiz** | Yineleme: §1'deki kurulumlarda tekil sha256 / toplam Mach-O. Bilinen üçüncü taraf (yol adından, doğrulanmamış): §1 bileşen payı sütunu. | Yol adı sahte olabilir (BICIM-11 sınıfı: zararlı dosyaya "Electron Framework" adı). Bu yüzden adından atlama YOK; yalnız sıra sonu + ucuz katman; gerçek "bilinen" kararı kimlikten (sha256 izin listesi, `LC_ID_DYLIB` + sürüm, KİMLİK hattı). | `karadul/core/target.py`, `karadul/analyzers/app_bundle.py`, yeni `karadul/core/bilesen_sinifi.py` | Masum / zararlı deney: üçüncü taraf adlı zararlı dylib atlanmamalı (yanlış "bilinen" 0) |
| S3 | **sha256 anahtarlı önbellek** (Ghidra projesi + `ghidra_output` + aşama çıktıları) | İkinci koşu, yarıda kalan tek ikiliyi sürdürme, KaradulLM "yeniden hesapla" (B-C4). Gösteri köprüsü 3 815 sn; önbellekle yalnız okuma. | Disk: gösteri projesi koşu sırasında 84 704 KiB (dilimin 3,3 katı) + `ghidra_output` JSON'ları 331,0 MB (köprü sözlüğü 202,7 MB + `pcode.jsonl` 128,3 MB) + 13 554 `.c` (125 940 KiB, `du -sk`). Anahtar Ghidra sürümü + ayar özeti içermeli (yanlış yeniden kullanım riski). | `karadul/analyzers/macho.py:1247-1300`, `karadul/ghidra/project.py:47-59`, yeni `karadul/core/onbellek.py`, `karadul/config.py` | İkinci koşu / birinci koşu süre oranı; JSON eşitliği |
| S4 | **Tembel derinlik:** önce ucuz katman (üst veri, içe aktarımlar, dizgiler, fonksiyon listesi, çağrı grafiği), decompile ve ad hattı yalnız seçilen fonksiyonlarda | 100 MB'lık tek ikilide köprünün büyük kısmı decompile + xref + CFG + BSim (gösteride 3 425 / 3 815 sn). İlk rapor otomatik analiz + liste süresine iner (gösteride ilk adım 320,6 sn). | En büyük değişiklik: ad hattı bütün `.c`'leri varsayıyor; KaradulLM ve arayüz "henüz decompile edilmedi" durumunu bilmeli. Ad ölçümü (119) tam kipte kalmalı. S3'e bağlı (sonradan decompile için proje). | `karadul/ghidra/headless.py`, `karadul/analyzers/macho.py`, `karadul/stages.py` (reconstruct girişi), `ui/server.py`, `karadul/lm/` | Seçilen kümede tam kiple eşitlik; T100'de ilk rapor süresi |
| S5 | **Ghidra çözümleyici profili ve takılan çözümleyici bekçisi** (E2, G2, G3) | Gösteri 1. deneme: tek çözümleyici 22+ dk, 2. denemede kapalıyken otomatik analiz 226,4 sn. Bekçi bu durumu ≤ 10 dk'da yakalar. | Çözümleyiciyi kapatmak çıktıyı değiştirir (P16c: "Decompiler Switch Analysis" kapatılınca `.c` değişiyor). Öntanım profili ancak ad / tip ölçüsüyle karar (E2 sorusu, ayrı ölçüm). | `karadul/ghidra/headless.py:672-716`, `karadul/config.py` | Takılma durumunda tetiklenme süresi; alt kümede çıktı eşitliği |
| S6 | **Adım bütçeleri, bellek bekçisi, disk bütçesi, akış biçimli çıktı** | Sınırsız 8 adım sınırlanır (K2). Köprü sözlüğü (gösteride 202,7 MB JSON → 0,65–1,16 GiB bellek, §3.4) akışla yazılır, çift yazım kalkar. Disk ön denetimi koşu ortasında dolmayı önler. | Kısmi çıktının aşağı akışta işlenmesi (şema "kismi" alanı). Bellek ölçüsü `ru_maxrss` (tepe; anlık değil). | `karadul/ghidra/headless.py`, `karadul/ghidra/bsim.py`, `karadul/analyzers/macho.py:425-470`, `karadul/core/pipeline.py`, `karadul/core/workspace.py` | Bütçe aşımında kısmi bitiş süresi; tepe RSS farkı; alt kümede eşitlik |
| S7 | **Arayüz ve rapor:** on binlerce fonksiyon, kısmi sonuç | `build_model` bütün `.c`'leri okuyor (K13); sayfalama + isteğe bağlı metin okuma. Kısmi / bütçe dışı durum raporda ve arayüzde görünür. | Arayüzün sayaç ve listeleri gerçek veriyle kalmalı (sahte sayı / animasyon yasak). | `ui/server.py:351-460`, `:2477-2530`, `ui/index.html`, `karadul/reporting/report_data.py` | Gösteri çalışma alanında `/api/model` süresi ve sunucu RSS'i |
| S8 | **BSim koşulları** (S6'nın parçası ama ayrı yazıldı: tek başına en büyük kalem) | Gösteride BSim 1 951,9 sn (köprünün %51'i), 0 eşleşme; öntanım gölge kipte, ad haritasına girmiyor. Boş depoda sorgu atlanınca çıktı aynı (0). | Ingest gelecekteki koşuların sorgusu için; kapatmak "kapsam küçültme" sayılır → bütçelenir. | `karadul/ghidra/headless.py:517-574`, `karadul/ghidra/bsim.py:585-624` | Gösteride BSim süresi; 119'da ad haritası eşitliği |
| S9 | **Kurulum dizinini hedef alma** (P6) | KiCad, Homebrew şişesi, Python ortamı gibi `.app` olmayan kurulumlar hiç hedef verilemiyor. | Dizin hedefi S1'in yönetici kuyruğunu gerektirir; ana bileşen kavramı yok (kullanıcı seçer ya da en büyük çalıştırılabilir). | `karadul/core/target.py:189-194`, S1 dosyaları | Envanterdeki dizin kurulumlarında bileşen listesi ve bütçeli koşu |

**Seçenekler arasında bağımlılık:** S4 → S3 (sonradan decompile için proje gerekir). S2'nin "bilinen" kararı → KİMLİK hattı. S1 → S6 (bileşen bütçesinin köprüye geçmesi için adım bütçeleri). S7, S1 ve S6'nın kısmi durumlarını gösterir.

## 5. Öneri (kalem 5)

**Hangi bileşim "birkaç GB" gereksinimini karşılar?** Yalnız şu bileşim: **S1 + S6 + S8 + S5 (yayından önce) ve S3 + S4 + S2 (yayından sonra).** Nedeni:
- Birkaç GB'lık kurulumun bütününü tam derinlikte analiz etmek bu makinede mümkün değil: tek bir 100 MB'lık C++ ikilisi için köprü TAHMİN aralığı §3.5'te; paket senaryoları §3.6'da. Bu yüzden gereksinim yalnız "paketi bütçeyle, öncelikle ve görünür kısmi sonuçla işlemek" biçiminde karşılanabilir (S1 + S6).
- Bugünkü sürenin en büyük, en ucuz düzeltilebilir kalemi BSim (gösteride %51, sonucu 0, ad haritasına girmiyor): S8.
- İlerleme ve takılan çözümleyici kullanıcının "dondu" sanmasını önler (G1, G2): S5 + ilerleme olayları.
- Tek büyük ikilide (100 MB+) kullanılabilir rapor ancak S4 (tembel derinlik) ile; o da S3'e bağlı. Yayından önce yetişmez; yayın notunda sınır açıkça yazılır.

**Yayından önce asgari (PLAN: ÖL-1, ÖL-4, ÖL-2, ÖL-3, ÖL-5a, ÖL-6; ÖLÇ-0, ÖLÇ-A, ÖLÇ-1, ÖLÇ-2):**
1. Her Ghidra adımı bütçeli; takılan çözümleyici ≤ 10 dk'da yakalanıp kapatılıyor; ilerleme en çok 60 sn aralıkla görünüyor.
2. BSim boş depoda sorgu yapmıyor, ingest bütçeli.
3. xref / CFG çıkarımı toplu yineleyicilerle ve akış biçiminde yazılıyor; çift serileştirme yok.
4. Paket: bağ ve yineleme bir kez; ana bileşen önce; toplam ve bileşen bütçesi; kapsam dışı Mach-O listesi raporda; bileşen başına kalıcı durum.
5. Disk ön denetimi ve bellek bekçisi.
6. Sonra ölçümü (ÖLÇ-2) ve yayın notu cümlesi.

**Dürüst sınır cümlesi (bugün, bu turun ölçümüyle):** "Karadul uçtan uca en çok 3,2 MB'lık tek ikilide (5 697 fonksiyon, 708 sn) ölçüldü. 26,6 MB'lık bir uygulama diliminde (13 559 fonksiyon) Ghidra aşaması 63,6 dakika sürdü; koşunun tamamı bu belge yazılırken sürüyordu. 100 MB ve üstü tek ikili ile çok bileşenli paket hiç uçtan uca koşulmadı." (Gösteri bitince ÖLÇ-0 cümleyi günceller.)

**Karşılanamayan (açıkça):**
- Birkaç GB'lık bir kurulumdaki **bütün** bileşenlerin tam derinlikte (her fonksiyon decompile + ad hattı) analizi: bu makinede günler mertebesi (TAHMİN, §3.6). Hiçbir seçenek bunu yayından önce sağlamaz; S4 ile bile "seçilen fonksiyonlar" sınırı kalır.
- 300 MB üstü tek ikili için bugün bellek sınırı da öngörülüyor (köprü sözlüğü + JVM yığını; §3.4–§3.5 TAHMİN); S6 ile "çökmek yerine kısmi bitmek" sağlanır, tam analiz değil.

## 6. Çakışmalar (kalem 7)

| Dosya | ÖLÇEK paketi | Yayın kapısı işi | Öbür hatlar | Öneri |
|---|---|---|---|---|
| `karadul/ghidra/headless.py` | ÖL-1, ÖL-2, ÖL-3, ÖL-6 (küçük) | G1 (ilerleme), G2 (bekçi), G3 (ObjC çözümleyicisi öntanımı: `ghidra_disabled_analyzers`, `:691-694`) | **KİMLİK PK-8** (`_extract_xrefs`'e `address_taken_by` alanı; `kimlik/PLAN.md` ≈ satır 436–450) — ÖL-3 aynı işlevi yeniden yazıyor | G1 + G2 = ÖL-1; G3'ün kararı ÖL-1'den sonra ölçümle (E2); tek ajan, sıralı. **ÖL-3 ile PK-8 aynı işlev:** önce ÖL-3 (akış biçimli xref), PK-8 alanı yeni yazıcıya ekler; ya da PK-8 önce ve ÖL-3'ün JSON-eşitlik ölçütü yeni alanı içerir |
| `karadul/config.py` | ÖL-1, ÖL-2, ÖL-5a, ÖL-6 | G2, G3 (öntanım listesi) | ÖZ KOD ÖK-1, ÖK-2, ÖK-3, ÖK-4b, ÖK-6; ÜST VERİ P-ÜV6; KİMLİK (bayraklar) | Tehlikeli dosya: bütün hatlarda sıralı; her paket yalnız kendi dataclass bölümüne yazar |
| `karadul/stages.py` | ÖL-5a (≈ 595–683), ÖL-10 | D3 (= ÖL-5a) | ÖZ KOD ÖK-4b (≈ 1751–1812); ÜST VERİ P-ÜV5 (`_recover_main_from_entry`, ≈ 1816–1876) ve P-ÜV6 (Faz 1 adım listesi, ≈ 2505–2530) | Bölgeler ayrık ama dosya ortak: sıralı |
| `karadul/core/target.py`, `karadul/analyzers/app_bundle.py` | ÖL-5a, ÖL-5b, ÖL-11 | D3 (BICIM-09), BICIM küçük 4 (`main_binary` en büyük dylib) | ÜST VERİ: evrensel ikilide Go dilimi (BICIM-10) `target.py`'de olabilir | ÖL-5a D3'ün yerine geçer; BICIM küçük 4 ÖL-5a adım 3'te çözülür |
| `karadul/analyzers/macho.py` | ÖL-3 (≈ 425–470), ÖL-9, ÖL-10 | D4 (anti-debug dilim tutarsızlığı) olası | — (ÜST VERİ planı `macho.py`'ye dokunmuyor: `ustveri/PLAN.md` ≈ satır 172) | Sıralı |
| `karadul/ghidra/bsim.py` | ÖL-2 | — | KİMLİK (BSim'i derlemeler arası ölçüyor; ürün kodunu değiştirmiyorsa çakışma yok) | KİMLİK planı BSim'e kod değişikliği önerirse ÖL-2'den sonra |
| `karadul/analyzers/binary_intelligence.py` | ÖL-3b | D2 (IMZA-01 kalanı: zayıf kanıtlı alt sistem satırları) | — | D2 ile sıralı |
| `karadul/cli.py`, `karadul/cli_common.py` | ÖL-4, ÖL-5b | G1 | P24 (MCP sunucusu; `gonderim/P24.md`) yeni giriş noktası ekleyebilir | Sıralı |
| `ui/server.py`, `ui/index.html` | ÖL-4 (`_job_progress`), ÖL-8 | G1; D5 (Hakkında paneli) | P22c / P22h (KaradulLM arayüzü) | ÖL-4 yalnız `_job_progress`; ÖL-8 KaradulLM paketlerinden sonra |
| `karadul/core/pipeline.py`, `karadul/core/workspace.py` | ÖL-6, ÖL-5b | — | — | Sıralı |
| `scripts/measurement/urun_kos.py` | — (ÖLÇ-A yeni dosya yazar, bunu içe aktarır) | — | ÖLÇÜ P-Ö* değiştiriyor | ÖLÇ-A yalnız içe aktarır, değiştirmez |

**HIZ hattıyla ilişki:** HIZ (`HIZ.md`) aynı gösteri verisinden "koşan adımı hızlandırma"yı ele alıyor (xref / CFG JPype döngüleri, BSim hızı, istihbarat taraması, decompile işçileri, JVM). Bu planın ÖL-3 adım 1–3'ü ve ÖL-3b'nin hız kısmı HIZ'la aynı işi yapar; ayrım önerisi `PLAN.md` §1. HIZ brifinde gösteri sırasında yük ortalamasının 40–60 olduğu yazılı (bu turda ölçmedim; §3.3'teki örneklem dışı sapmanın bir kısmı bu yük olabilir).

**Yayın kapısıyla ilişki:** G1 = ÖL-1 (olaylar) + ÖL-4 (gösterim); G2 = ÖL-1; G3 = ÖL-1 sonrası ölçüm (E2); G4 (Go adları) = ÜST VERİ hattı, ÖLÇEK'e değmez; D3 = ÖL-5a.

## 7. Olumsuz sonuçlar, belirsizlikler, başka hat için notlar

**Tutmayan / olumsuz (kayıtta kalır):**
- Örneklem (119) modeli gösteri diliminde 6 adımın 5'ini 2,2–9,7 kat az öngördü (§3.3). Örneklemden büyük ikiliye düz dış değerleme yanıltıcıdır; bu yüzden §3.5 çapalı ve geniş aralıklı.
- Dosya baytı ölçek değişkeni olarak kötü: decompile ↔ dosya baytı modeli gösteriyi 6,5 kat fazla öngördü (gözlenen / öngörü 0,15); kod baytına geçince 1,00.
- Envanterin ilk denemesi (süzgeçsiz) KiCad'de 29 dk'da bitmedi; sürenin ~%99'u `open()` çağrısında (`/usr/bin/sample`). Ön süzgeçle 133,6 sn. Neden (açılışta gerçek zamanlı tarama) doğrulanmadı.
- ÖLÇ-0'ın toplam süre ön kaydı (1 108 [727; 1 632] sn) daha koşu bitmeden tutmadı (köprü tek başına 3 815 sn).

**Belirsiz (ölçülmedi):**
- Gösteride xref / CFG / BSim / ikili istihbarat sapmasının nedeni (yük, JVM yığını, Go yapısı).
- Tepe bellek: 119'da hiç, gösteride yalnız yarıda kesilmiş 1. denemede.
- Gösteri koşusunun reconstruct, rapor, çıktı aşamaları ve uçtan uca süresi (ÖLÇ-0).
- Electron `.app` (JS hattı) büyük `app.asar` ile hiç koşulmadı (BICIM-09 notu); §1'de `.asar` sayıları var, süre yok.
- Yol adından üçüncü taraf sınıflamasının doğruluğu (doğrulayıcı yok; yalnız yön gösterici).

**Başka hat için notlar:**
- **KİMLİK:** gösteride BSim 0 eşleşme (koşuya özel boş depo). BSim'in derlemeler arası ölçümü depo dolulukla değişir; ÖL-2'nin "boş depoda sorgu atla" koşulu KİMLİK ölçümlerini etkilemez (dolu depo). PK-8 ile ÖL-3 aynı işlevde (`_extract_xrefs`): sıra §6.
- **ÜST VERİ:** gösterinin `ghidra_log.txt`'inde "FunctionID: 6 esleme"; Go RTTI uyarısı YAYIN_KAPISI G4'te. Ölçekle ilgisi: Go ikilisinde 173 498 simge xref adımının simge döngüsünü (`headless.py:1792-1803`) besliyor; ÖL-3 adım 1 bunu ayrı ölçer.
- **ÖLÇÜ:** `scripts/measurement/urun_kos.py`'ye tepe bellek ve adım süresi eklenmesi yararlı olur; ÖLÇEK bunu kendi yeni koşucusunda (ÖLÇ-A) yapıyor, `urun_kos.py`'ye dokunmuyor.
- **Yayın / D5:** paket dalında YARA ve capa taraması atlanıyor (`karadul/stages.py:439-440`): ölçek değil kapsam kusuru.
