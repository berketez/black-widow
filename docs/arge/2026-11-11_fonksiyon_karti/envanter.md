# Fonksiyon kartı envanteri: adsız fonksiyonlarda bugün dürüstçe gösterilebilecek kanıt

- **Tarih:** 2026-11-11. **Depo:** `main`. Betiğin son koşusunda HEAD `b1ee66f`, zaman 09:20 (`envanter_sayim.json` → `kunye`). Ürün kodu ve arayüz değişmedi; yalnız okuma ve sayım.
- **Soru:** Adı verilemeyen bir fonksiyon için çalışma alanında bugün hangi kanıt duruyor, ne kadarında duruyor? Arayüz bunun ne kadarını ve ne kadar dürüst gösteriyor? Kart hangi satırlardan kurulmalı?
- **Dosyalar:** `envanter_sayim.py` (betik), `envanter_sayim.json` (bütün sayılar), bu belge.
- **Girdi:** 8 ikili: Debian tmux, tree, sqlite3; coreutils'ten cat, ls, sort; Mac tmux, htop.
  - Hepsi **yeni ürün koşusundan** okundu (`~/karadul_olcum/runs/urun-yeni-93a2956`, kod 93a2956; sekizinin de dizininde `BITTI` var).
  - Betik, `BITTI` olmayan ikilide saklı taban koşusuna düşer (Debian `~/karadul_olcum/n1_debian13`, Mac `workspaces/olcum_mac/runs/ol7-c-b7faeac`). Bu koşuda düşmedi: JSON'da `ikililer[].kaynak` sekizinde de `yeni`.
  - Karşılaştırma için aynı betik eski ürünün çıktısıyla da koşuldu ("taban kolu", §9). Belgede eski ürüne ait her sayı öyle işaretli.
- **"Adsız" tanımı:** Ghidra'nın jenerik bıraktığı (`FUN_<onaltılık>`, thunk ve dış değil) ve yeni ürünün `reconstructed/src/naming_map.json` `global` sözlüğünde anahtarı olmayan fonksiyon.
  - Jenerik nüfus N4 sayımıyla birebir aynı: sekiz ikilide de `tablo_yuvasi_sayim.json` `ikililer[].isim_bekleyen` ile aynı (1 916, 115, 425, 101, 311, 238, 2 587, 597).
- **GT'siz:** simge doğrusu, dbgsym, DWARF, `macho_score.json`, `run.json` ve kilitli setler açılmadı. Karadul ve Ghidra koşulmadı.
- **Belgede ve JSON'da** fonksiyon adı, dizgi içeriği ve adres yok. Yalnız sayılar, dosya ve alan adları, ürünün kendi etiket adları (alt sistem, bileşim adı) ve BSim veritabanındaki program adları var.
- **İşaretler:** **[hesap]** dosyadaki sayılardan aritmetik. **[okuma]** kod okunarak çıkarılmış, sayılmamış. **[tahmin]** ölçülmemiş bir varsayıma dayanır.

## 0. Kısa sonuç

**En önemli üç bulgu:**

1. **Kart için kanıt büyük ölçüde var; ama arayüz onu bugün yanlış etiketliyor ve yanına ölçülmemiş iddialar ekliyor.**
   - **Çağrı bağlamı Ghidra'nın çağrı kenarı değil.** Arayüzün "çağıran / çağırdığı" listesi, decompile metninde geçen her `FUN_` adını sayıyor (`ui/server.py:244`).
     - Adsız fonksiyonların %34,8 (cat) – %61,6'sında (Mac htop) arayüz, adresini yalnız kullanan bir fonksiyonu "çağıran" diye çiziyor. Kullanım biçimi: gösterici ataması ya da argüman olarak verilme.
     - Bunların bir kısmının Ghidra'da hiç çağıranı yok: Mac tmux 411, Debian tmux 335, Mac htop 163 fonksiyon.
     - Arayüzün fazladan çizdiği kenarların neredeyse hepsi çağrı sözdizimi taşımıyor: Debian tmux'ta 3 510 kenarın 3 507'si, Mac tmux'ta 4 777'nin 4 709'u.
   - **İkili geneli satır her kartta.** "NEDEN İSİMSİZ?" kutusundaki hesaplama füzyonu satırı (`ui/server.py:617-625`) sekiz ikilide adsız fonksiyonların **%100**'ünde çıkıyor. Fonksiyona özgü değil.
   - **"İmza eşleşmesi yok" cümlesi bazı fonksiyonlarda yanlış.** Teşhis bu cümleyi kuruyor; oysa imza veritabanının bu fonksiyon için ad adayı ürettiği adsızlar var: sqlite3 40, Mac tmux 14, Mac htop 10, Debian tmux 8, tree 4, ls 4, sort 2.
   - **Karar etiketleri ölçülmemiş.** "Uygulamaya özgü", "kütüphane sarmalayıcı" ve "BSim adayı var" kararları (`ui/server.py:627-641`) hiçbir ölçüme dayanmıyor. Haritanın merkezindeki rol satırı (`ui/index.html:899-908`) adsızların %17,0 (tree) – %48,1'inde (Mac htop) bu karar etiketlerinden birini gösteriyor **[hesap]**.
2. **BSim gölge adayları kartta kullanılamaz.**
   - **Arayüzün yönlendirmesi:** ≥ 0,80 benzerlikte "BSim güçlü benzer buldu … füzyona açarsan otomatik isimlenebilir" diyor. Bu karar Mac tmux'ta adsızların %53,3'ünde (1 168) çıkıyor **[hesap]**.
   - **Adayların kaynağı aynı adlı program.** Gösterilen en iyi adayın programı incelenen programla aynı adlı: Mac tmux 1 080/1 177 (%91,8), Debian tmux 227/305 (%74,4) **[hesap]**.
     - İncelenen ikililer kesik: bütün iç fonksiyonlar Ghidra'da jenerik. BSim, Ghidra programını o anki adlarıyla kaydediyor (`karadul/ghidra/bsim.py:515-585`); jenerik adaylar arayüzde süzülüyor.
     - Öyleyse bu adlar aynı programın ya simgeli bir kopyasından (GT sızıntısı) ya da ürünün önceki koşularından (döngüsel kanıt) geliyor **[okuma]**. Hangisi olduğu doğrulanmadı.
   - **İçerik koşudan koşuya değişiyor.** Aynı ikilinin eski ve yeni koşusunda BSim'li fonksiyon sayısı (`bsim_shadow_functions`): Mac htop 597 → 35, sort 244 → 126, cat 42 → 107. Mac htop'ta BSim satırlı adsız 371'den 0'a indi.
     - Yeni koşuda adaylar, aynı koşuda birkaç dakika önce analiz edilen `redis-check-aof`'tan da geliyor: Debian tmux 23, ls 8, Mac tmux 6, cat 4.
     - `docs/arge/2026-11-10_cikti_saglamligi/rapor.md:325-330` aynı bağımlılığı eşzamanlılık açısından ölçmüştü.
3. **Kapsam: Ghidra'nın adres anahtarlı olguları neredeyse her adsız fonksiyonda bir şey söylüyor; "ne yaptığını adıyla söyleyen" kanıt (ithal çağrı ya da dizgi) ise adsızların %52,1 (Mac htop) – %83,9'unda (tree) var [hesap].**
   - Hiçbir Ghidra kanıtı ve adres başvurusu olmayan, yalnız boyut ve yerleşimi kalan fonksiyon (`kart_bos_tam`): %1,1 (cat) – %13,5 (sqlite3). Öbür altı ikilide %3,0-7,1.
   - İthal çağrı da dizgi de olmayan fonksiyon (`icerik_adsiz`): tree %16,1, sqlite3 %25,8, cat %34,8, ls %35,1, sort %40,2, Debian tmux %41,7, Mac tmux %47,3, Mac htop %47,9.
   - Bu fonksiyonların kartında yalnız ilişki (çağıran, çağrılan, adres başvurusu) ve yapı (boyut, karmaşıklık, uyarı) olur.

**Öbür bulgular:**

- **Diskte olmayan ya da fonksiyon başına yazılmayan kanıt:**
  - **Veri → fonksiyon başvurusu yok.** Hangi veri yuvası, tablo ya da kod bu fonksiyonun adresini tutuyor, bilinmiyor.
    - PyGhidra yolu (`karadul/ghidra/headless.py:1404-1500`) yalnız çağrı ve dizgi başvurusu yazıyor.
    - Eski CLI betiğinde `globals_accessed` alanı var (`karadul/ghidra/scripts/xref_analysis.py:82`), ama koşular o yoldan geçmiyor.
  - **Elenen adaylar yalnız sayı.** Susturulan ve elenen ad adayları ikili geneli sayı olarak kalıyor (`karadul/reconstruction/c_namer.py:372-388`, `:1842-1860`).
    - Adsız fonksiyonların çoğunun en iyi adayı yapısal süzgeçte eleniyor: Mac tmux'ta 1 762 genel anahtar, Debian tmux'ta 1 378. Fonksiyon başına kayıt yok.
- **Kullanıcıya giden ad haritasında uygulanmamış adlar.** `out/naming_map.json`, ürünün **vermediği** imza adaylarını da ad gibi listeliyor (`karadul/core/output_formatter.py:554-566`).
  - Yeni ürünle bu kayıtlar arttı. Eski ürünün c_namer adı artık üstlerine yazılmıyor: sqlite3 12 → 40, Mac tmux 2 → 14, Mac htop 0 → 10 (taban kolu → yeni).
  - Kartın konusu değil; ama bir dürüstlük sorunu (§8 madde 4).
- **Ölçülmemiş etiketlerin hepsi kartın dışında kalmalı:** algoritma, bileşim, zekâ raporu amaç metni, alt sistem etiketi, BSim, teşhis kararı.
  - Yeni ürün algoritma etiketini büyük ölçüde susturdu: adsızların %0-2,5'inde (taban kolunda %28,7-56,0).
  - Bileşim adları hâlâ ürünün çıktısında. tree için "Transient CFD Time-Stepping" ve "Rocket / Trajectory Simulation Loop" üretiliyor (`reconstructed/algorithm_compositions.json`).

## 1. Çalışma alanındaki fonksiyon başına kanıt (soru 1)

**Anahtar sütunu:**
- **adres** = Ghidra giriş adresi; tekil.
- **Ghidra adı** = `FUN_<adres>` ya da ithalin / Ghidra'nın verdiği ad. Jenerik fonksiyonda adresle bire bir; ithallerde tekil değil.
- **ürün adı** = Karadul'un verdiği ad (kaydın yazıldığı aşamadaki ad).

### 1.1 `static/` (Ghidra)

`karadul/analyzers/macho.py:286-290` her çıktıyı `static/ghidra_<ad>.json` olarak da kopyalar.

| Dosya | Alan | Yazan kod | Anahtar | Not |
|---|---|---|---|---|
| `ghidra_functions.json` | `name, address, size, is_thunk, is_external, source, return_type, parameters` | `headless.py:558` `_extract_functions`; yazım `:284` | adres (listede) | Jenerik fonksiyonda `return_type` hep `undefined`, `parameters` boş. Decompile'dan önce çıkarılıyor; sekiz ikilide 0 istisna (`ghidra_functions_imza_dolu`) |
| `ghidra_call_graph.json` | `nodes[adres].callers/callees` (ad + adres), `edges` | `headless.py:649`; yazım `:306` | adres | Çağrı kenarı |
| `ghidra_xrefs.json` | `function_xrefs[adres].strings_used` (adres + değer), `functions_called`, `called_by` | `headless.py:1404-1500` `_extract_xrefs`; yazım `:367` | adres | **Veri başvurusu yok.** Gelen başvurular yalnız `isCall()` (`:1456-1463`). Dizgi dışı veri başvurusu yazılmıyor. `total_globals_with_xrefs` yalnız ikili geneli sayı (`:1476-1497`) |
| `ghidra_strings.json` | `strings[].function` | `headless.py:597`; alan `:635-638` | — | `function` = dizginin **kendi adresini içeren** fonksiyon (`getFunctionContaining`). Dizgiler veri bölümünde olduğu için tree'de 371/371 `null`. Dizgi → fonksiyon bağı yalnız `ghidra_xrefs.strings_used`'da |
| `ghidra_output/decompiled/<Ghidra adı>.c` | C metni; başlıkta boyut, çağıran/çağrılan sayısı, yığın; sonda disassembly; Ghidra uyarı yorumları | `headless.py:896` `_decompile_functions` | Ghidra adı (dosya adı) | Dizgi, sabit, `DAT_`/`PTR_` veri etiketi ve imza tipleri buradan metinle çıkarılabiliyor |
| `ghidra_decompiled.json` | `functions[].xrefs.callers[].call_site`, `stack_frame`, `pcode_high_vars` | `headless.py:896`; liste kesimi `:1055` | adres (listede) | **İlk 500 fonksiyonla kesik** (`results[:500]`); büyük ikilide çağrı yeri bilgisi eksik |
| `ghidra_cfg.json` | `block_count, edge_count, cyclomatic_complexity, loop_headers, back_edges` | `headless.py:1711` | adres (listede) | Kapsam %100 |
| `ghidra_types.json` | yapılar, enum'lar, typedef'ler | `headless.py:1341` | — | İkili geneli; fonksiyona bağ yok |
| `ghidra_output/pcode.jsonl` | fonksiyon başına seçilmiş p-code ve yüksek değişken tipleri | `headless.py:1651` | adres (`a`) | Kart için ham |
| `bsim_matches.json` / `ghidra_bsim.json` | BSim eşleşmeleri | `headless.py:472` | adres | §0 madde 2 |
| `intelligence_report.json` | `architecture.function_analyses[].purpose/algorithms/system_calls/vulnerabilities`; ikili geneli `subsystems/algorithms/protocols/security` | `binary_intelligence.py:1463-1528`; yazım `macho.py:345-346` | Ghidra adı (dosya kökü) | Amaç metni regex ve anahtar sözcükle. İkili geneli etiketler içerikten bağımsız: "OpenGL" 119/119 ikili (`rapor.md:347`); tree'de "OpenGL", "IPsec" |
| `strings_raw.json`, `symbols.json`, `lief_analysis.json` | ikili geneli | `macho.py:261, 268, 275` | — | Fonksiyona bağ yok |

### 1.2 `reconstructed/` ve `out/` (Karadul)

| Dosya | Alan | Yazan kod | Anahtar | Not |
|---|---|---|---|---|
| `src/naming_map.json` | `global` (ad haritası), `per_function` (yerel adlar) | `c_namer.py:2453-2466` | Ghidra adı | Adsız = `global`'de yok |
| `src/naming_provenance.json` | `global[Ghidra adı]` (yalnız ad alanlar), `per_function[…]`, `silencing.candidates_dropped`, `eliminated_keys`, `below_min_confidence_candidates`, `name_validity.rejected` | `c_namer.py:224-490`; yazım `:2473-2493` | Ghidra adı. Susturma ve eleme **yalnız sayı** | Adsız fonksiyon için "neden ad almadı" kaydı yok: `ad_koken_global` sekiz ikilide 0 (§4) |
| `signature_matches.json` | `original, matched, library, confidence, purpose` | `pipeline/steps/ghidra_metadata.py:219-234` | Ghidra adı (`original`) | İthaller adla anahtarlı; bazı jenerik fonksiyonlar için de aday var (`FUN_…`). `library` gürültülü (`ui/server.py:517-519` kendisi söylüyor) |
| `bsim_shadow.json` | `matches[].function_addr`, `bsim_candidates[].name/similarity/binary` | `pipeline/steps/bsim_match.py:103-108` | adres | Gölge kip; ada girmiyor |
| `algorithms.json` | `algorithms[].function/name/category/evidence` | `pipeline/steps/algorithm_id.py:65-66` | Ghidra adı | Yeni üründe adsızların %0-2,5'inde. Eski kripto sahte pozitifi: 8 666 fonksiyon (`rapor.md:345`) |
| `algorithm_compositions.json` | `compositions[].name/domain/stages[].functions` | `pipeline/steps/_deep_tracing_helpers.py:271` | ürün adı | tree: "Transient CFD Time-Stepping", "Matrix Solve Pipeline", "Rocket / Trajectory Simulation Loop" |
| `param_naming_map.json` | `functions[ad].renames, domain` | `engineering/semantic_namer.py:2084-2102` | ürün adı | `domain` sekiz ikilide adsızların hepsinde `unknown` |
| `annotated/block_annotations.json` | `annotated_functions[].function_name`, `annotations[]` (döngü amacı, bellek işlemi) | `engineering/block_annotator.py:821` | ürün adı | Kodun yeniden anlatımı |
| `data_flow/data_flow.json`, `data_flow_pipelines.json` | `graph.edges[].source_func/target_func`, `pipelines[].functions` | `engineering/data_flow.py:2556, 2566` | ürün adı / ithal adı | Yeni üründe adsızların hiçbirinde yok (0/8 ikili). Kenarlar ithal fonksiyonlar arasında |
| `struct_recovered/struct_recovery.json` | `enriched_structs[].source_functions` | `engineering/struct_recovery.py:982-983` | ürün adı | Sekiz ikilide adsızların hepsinde boş |
| `commented/<Ghidra adı>.c` | `@size`, `@called_by`, `@calls`, satır yorumları, `VULN:`/`WARNING:` uyarıları | `c_comment_generator.py` (`VULN_PATTERNS` `:310`) | Ghidra adı (dosya) | Yorumlar kodu yeniden anlatıyor; uyarılar regex |
| `kesin_capalar.json` | KS-1 çapaları | `pipeline/steps/kesin_anchors.py:41, 126` | adres | Ad alan fonksiyonlar için; adsız kartına girmez |
| `project/analysis/subsystem_map.md` | alt sistem → ad listesi | `c_project_builder.py:432-435`, `:1168-1196` | ürün adı | **Her alt sistemde ilk 50 adla kesik** (`:1181-1184`). Listede olmayan ad: Mac tmux 2 394, Debian tmux 2 229, sqlite3 949. Makine okunur harita değil |
| `out/src/src/subsystem_<x>/<ad>.c` | yerleşim | `c_project_builder.py:359`; sınıflama `:690-729` (çağrılan API kuralı); topluluk `:735` | ürün adı (dosya adı; çakışmada adres eki) | Tam fonksiyon → alt sistem bilgisinin tek kaynağı; dosya yolundan çıkarılmak zorunda |
| `out/naming_map.json` (arayüzde `clean/`) | `mappings[anahtar].new_name/source/confidence/library/label/channel/evidence` | `core/output_formatter.py:529-703` | **Karışık:** imza kayıtları Ghidra adıyla (ithaller adla, `:554-566`), c_namer kayıtları `FUN_…` ile (`:636-698`) | Uygulanmamış imza adayları da ad gibi duruyor (§0) |

**Öbür çıktılar:** fonksiyon kartına doğrudan girdi vermiyorlar.
- `deobfuscated/` (Ghidra JSON kopyaları) ve `src_iter1/` (ikinci yinelemenin haritası).
- Ara `.c` dizinleri; `project/analysis/xref_index.md` (çağrı grafının ad anahtarlı md tekrarı) ve `call_graph.dot`.
- `call_traces.md`, `compositions.md`; `dispatch_resolution.json` (C ikililerinde 0) ve `engineering_*.json` (0).
- `out/dependency_graph.json`: adres anahtarlı çağrı grafı kopyası.
- `reports/report.sarif.json`: ikili geneli YARA; tree'de "ASPack_Packed".

### 1.3 `reports/`

- **`report.json`** → `pipeline.stages.reconstruct.stats`: yalnız ikili geneli sayaçlar. Arayüz `computation_fusion_matches/accepted` alanlarını okuyor (`ui/server.py:564-584`). Bu sayılar `pipeline/steps/computation_fusion.py:142-143`'te yazılıyor.
- **"N aday" sayısı adsızların adayı değil [okuma].** `computation_fusion_matches` anahtarları imza eşleşmesinin `original` adları (çoğu ithal) ve CFG eşleşmelerinin adresleri (`computation_fusion.py:109-135`).

### 1.4 Ada anahtarlı kayıtlar neden kırılgan

- **Ghidra adı ithallerde tekil değil.** Aynı adı taşıyan birden çok fonksiyon (PLT kökü + dış kayıt) Debian'da 63-239 ad: sqlite3 239, Debian tmux 222, sort 127, ls 115, tree 64, cat 63. Mac'te 1 (`nufus.ghidra_adi_birden_cok_fonksiyonda`).
- **Ürün adı aşamaya göre değişiyor.** Aynı fonksiyon `algorithms.json`'da `FUN_…` ile, `param_naming_map.json`'da ürün adıyla anahtarlanıyor. Kayıtları birleştirmek için ad haritasından geri çevirmek gerekiyor. Bu sayım iki anahtarı da deniyor.
- **Yeni üründe adsız fonksiyonun ürün adı yok** (`eski_urun_adi_var` sekiz ikilide 0). Anahtar `FUN_<adres>` ve tekil; ada anahtarlı kayıtlar adsız kart için bugün güvenle okunabiliyor.
  - Kırılganlık ad alan fonksiyonlarda ve ithallerde sürüyor.
  - Eski ürünün çıktısında (taban kolu), adı başka bir Ghidra fonksiyonunun adıyla aynı ya da haritada çift olan jenerik fonksiyonlar vardı: Debian tmux 5, sqlite3 4, sort 3, cat 1.
- **Arayüzün ipucu süzgeci ithal adıyla bakıyor** (`ui/server.py:526`, `cmap.get(name)`). Bu yüzden `FUN_…` anahtarlı uygulanmamış imza adayı da "bilinen çağrı" sayılıyor (§2).

## 2. Arayüz bugün ne gösteriyor (soru 2)

- Sayılar arayüzün kendi fonksiyonları içe aktarılarak üretildi: `build_model`, `_extract_strings`, `_external_call_hints`, `_naming_diagnosis`. `deriveRole` Python'a birebir çevrildi.
- Ölçüm düzeninde temiz harita `out/naming_map.json`'da; arayüzün `cmap` girdisi oradan verildi.
- Oran paydası her ikilinin adsız sayısı.

| Öğe | Kod | Okuduğu kaynak | Dürüstlük sorunu | Sayı (adsız içinde) |
|---|---|---|---|---|
| Çağrı bağlamı ("çağıran", "çağırdığı"), harita ışınları, `N çağırdığı · M çağıran` | `build_model` `ui/server.py:218-280` (`:244` `_FUN_RE.findall`); `_evidence` `:645-677`; `index.html:977, 1273-1292` | `static/ghidra_output/decompiled/FUN_*.c` metnindeki `FUN_` adları | **Çağrı ile adres başvurusu ayrılmıyor.** Fazla kenarların sınıfı (`arayuz.fazla_kenar_sinifi`): çağrı sözdizimi olmayan kullanım Debian tmux 3 507/3 510, Mac tmux 4 709/4 777 (63'ü yalnız çağrı sözdizimi, 5'i ikisi), Mac htop 874/879. İthaller ve Ghidra'nın adlandırdığı iç fonksiyonlar (`entry` gibi) düğüm değil | Fazladan "çağıran" gösterilen: %34,8 (cat) – %61,6 (Mac htop). Ghidra'da hiç çağıranı olmadığı hâlde çağıran gösterilen: Mac tmux 411, Debian tmux 335, Mac htop 163, sqlite3 85, ls 49, sort 29, tree 18, cat 15 |
| Referans dizgiler | `_extract_strings` `:491-502` | decompile metnindeki `"…"` sabitleri (ilk 20) | Olgu; sorun yok. Ghidra'nın adresli `strings_used` listesi kullanılmıyor | %9,0 (cat) – %47,3 (tree) |
| İpuçları ("⚗ İPUÇLARI · karadul analizi") | `_external_call_hints` `:514-530`; `index.html:1294-1301` | metinde `ad(` biçimindeki semboller; yalnız `out/naming_map.json`'da `library` alanı olanlar | (a) İmza veritabanı tanımazsa ithal çağrı düşüyor. (b) `FUN_…` anahtarlı **uygulanmamış imza adayı** da "bilinen çağrı" sayılıyor. (c) Fonksiyonun kendi adı da (imza satırından) ipucu sayılıyor: kendini "çağırıyor". (d) Başlık "karadul analizi" diyor; içerik Ghidra'nın ithal çağrısı | İpucu %38,4 (Mac tmux) – %82,1 (tree). (b): sqlite3 57, Mac tmux 21, Debian tmux 19, Mac htop 14, tree 6, ls 5, sort 5. (c): sqlite3 39, Mac tmux 14, Mac htop 10, Debian tmux 8, tree 4, ls 4, sort 2. (a): yalnız tree'de 1 |
| "◇ NEDEN İSİMSİZ?" sinyal 1: "Uygulanabilir imza/parmak izi eşleşmesi yok" | `_naming_diagnosis` `:596-599` | yok; adsızsa sabit metin | Fonksiyon için imza adayı varken de yazılıyor | Çelişki: sqlite3 40, Mac tmux 14, Mac htop 10, Debian tmux 8, tree 4, ls 4, sort 2 |
| Sinyal 2: "BSim: '<ad>' %N benzer — GÖLGE modunda" | `_bsim_shadow` `:533-561`, `:601-609` | `reconstructed/bsim_shadow.json` | Güvenilirliği ölçülmedi. Aday aynı adlı programdan ve koşudan koşuya değişiyor (§0 madde 2) | Mac tmux 1 177 (%53,7), Debian tmux 305 (%18,8), ls 30 (%10,0), cat 8 (%9,0), tree 6 (%5,4); sqlite3, sort, Mac htop 0 |
| Sinyal 4: "Bu binary genelinde hesaplama füzyonu hiçbir fonksiyona isim veremedi (N aday…)" | `:617-625` | `reports/report.json` | İkili geneli; fonksiyona özgüymüş gibi her kartta. "N aday" çoğunlukla ithal adlarının füzyonu (§1.3) | **%100**, sekiz ikilide |
| Karar ve gerekçe: `bsim_shadow` / `app_wrapper` / `app_specific` | `:627-641` | yukarıdaki sinyaller | Üçü de ölçülmemiş iddia. `bsim_shadow`: "füzyona açarsan otomatik isimlenebilir". `app_wrapper`: "kendisi standart bir fonksiyon değil — eşleşecek imza yok". `app_specific`: "programın kendi kodu" (statik bağlı kütüphane kodunu ayırt eden bir denetim yok **[okuma]**) | `bsim_shadow`: Mac tmux 1 168 (%53,3), Debian tmux 231 (%14,2). `app_specific`: %13,4 (tree) – %56,3 (Mac htop) **[hesap]** |
| Haritanın merkezindeki rol satırı | `deriveRole` `index.html:899-908`; `setMapRole :909`; `drawRadial :911-986` | sırayla: ipucu → ilk dizgi → karar etiketi | İpucu ve dizgi dalları olgu. Karar dalı ("uygulamaya özgü", "BSim adayı var (kapalı)") ölçülmemiş etiket | Karar dalına düşen: Mac htop 287 (%48,1), Mac tmux 1 036 (%47,3), Debian tmux 684 (%42,1), sort 87 (%38,8), ls 104 (%34,8), cat 29 (%32,6), sqlite3 97 (%23,8), tree 19 (%17,0) **[hesap]** |
| Ad kökeni ("◈ ADAY / MEVCUT İSİM") | `_provenance` `:453-474` | `out/naming_map.json` | Adsızda `None`; dürüst. Bayat kayıt koruması var (`:400-413`) | — |

**Ölçüm düzeni notu:** Arayüz temiz haritayı `clean/naming_map.json`'da arıyor (`_active_run_dir`, `:317-327`). Ölçüm koşularında bu dosya `out/`'ta. Arayüz bu dizinleri doğrudan açarsa ipucu ve köken hiç çıkmaz. Sayım, arayüzün kendi koşularında göreceği düzeni taklit etti.

## 3. Kapsam sayımı (soru 3)

### 3.1 Tanımlar (sayımdan önce yazıldı; sonradan eklenenler işaretli)

Tam metin `envanter_sayim.json` → `kunye.kanit_tanimlari` ve `kunye.bos_kart_tanimlari` alanlarında. Özet:

- **Ghidra kanıtları (adres anahtarlı):**
  - `cagiran`: Ghidra çağrı kenarı ile en az bir çağıran.
  - `cagrilan_ic`: en az bir iç fonksiyon çağırıyor.
  - `cagrilan_ithal`: en az bir ithal fonksiyon çağırıyor (thunk ya da dış, adı jenerik değil).
    - `cagrilan_ithal_ayirt`: bunlardan biri arayüzün gürültü listesinde (`ui/server.py:506-511`) değil.
    - *(sonradan)* `cagrilan_ithal_yalniz_gurultu`: ithal çağrıların hepsi gürültü listesinde.
  - `dizgi_xref`: Ghidra dizgi başvurusu. `dizgi_govde`: decompile gövdesinde dizgi sabiti.
  - `sabit_govde`: gövdede `0x…` sabiti. `veri_etiketi_govde`: gövdede `DAT_`/`_DAT_`/`PTR_` etiketi (Ghidra veri başvurusunun metin vekili).
  - `imza_parametreli`: decompile imzasında parametre var. `imza_adli_tip`: Ghidra'nın temel tipleri dışında bir tip adı var.
  - `ghidra_uyari`: Ghidra uyarı yorumu var. `ghidra_uyari_kuskulu`: "eksik ya da kuşkulu decompile" türünden uyarı (liste `rapor.md:149`'dan).
  - `boyut_karmasiklik`.
  - *(sonradan)* `adresi_baska_govdede`: adı başka bir jenerik fonksiyonun metninde geçiyor ama Ghidra çağrı kenarı yok.
- **Karadul kanıtları:** yerel ad kaydı, parametre adı, blok açıklaması, algoritma etiketi, bileşim aşaması, veri akışı, struct kaynağı, zekâ raporu amaç metni, zafiyet uyarısı, alt sistem yerleşimi, BSim adayı, uygulanmamış imza adayı, ad kökeni kaydı.
  - Ada anahtarlı olanlarda Ghidra adı da ürün adı da denendi.
  - *(Değişiklik, sayımın ilk koşusundan sonra)* Alt sistem kaynağı `subsystem_map.md`'den dosya yerleşimine çevrildi; md her alt sistemde 50 adla kesik.
- **Boş kart:**
  - `kart_bos_ghidra`: altı Ghidra kanıtının (çağıran, iç çağrılan, ithal çağrılan, iki dizgi türü, veri etiketi) hiçbiri yok.
  - `icerik_adsiz`: ithal çağrı yok ve dizgi yok.
  - `ui_bos`: arayüz hiçbir kanıt satırı çizmez.
  - *(sonradan)* `kart_bos_tam`: `kart_bos_ghidra` ve adres başvurusu da yok.
  - *(sonradan)* `iliski_yok`: çağıran, iç çağrılan ve adres başvurusu yok.

### 3.2 Nüfus

| | debian/tmux | debian/tree | debian/sqlite3 | coreutils/cat | coreutils/ls | coreutils/sort | mac/tmux | mac/htop |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Ghidra fonksiyonu | 2 588 | 250 | 1 144 | 296 | 665 | 625 | 2 821 | 790 |
| Jenerik (thunk/dış değil) | 1 916 | 115 | 425 | 101 | 311 | 238 | 2 587 | 597 |
| Yeni ürünün ad verdiği jenerik | 293 | 3 | 18 | 12 | 12 | 14 | 395 | 0 |
| **Adsız** | **1 623** | **112** | **407** | **89** | **299** | **224** | **2 192** | **597** |

- tree'de `global`'de 5 `FUN_` anahtarı var; bunların 2'si Ghidra'da jenerik değil. Örneğin Ghidra'nın `entry` dediği fonksiyonun anahtarı `FUN_…` olarak yazılmış (`rapor.md:357` aynı bulgu).

### 3.3 Ghidra kanıtları (adres anahtarlı; `adresi_baska_govdede` metin vekili)

| tür | debian/tmux | debian/tree | debian/sqlite3 | cat | ls | sort | mac/tmux | mac/htop |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `cagiran` | 1 069 (%65,9) | 63 (%56,2) | 192 (%47,2) | 37 (%41,6) | 164 (%54,9) | 141 (%62,9) | 1 483 (%67,7) | 381 (%63,8) |
| `cagrilan_ic` | 1 223 (%75,3) | 42 (%37,5) | 160 (%39,3) | 61 (%68,5) | 158 (%52,8) | 136 (%60,7) | 1 626 (%74,2) | 420 (%70,3) |
| `cagrilan_ithal` | 762 (%46,9) | 93 (%83,0) | 291 (%71,5) | 58 (%65,2) | 194 (%64,9) | 134 (%59,8) | 826 (%37,7) | 258 (%43,2) |
| `cagrilan_ithal_ayirt` | 286 (%17,6) | 81 (%72,3) | 275 (%67,6) | 20 (%22,5) | 90 (%30,1) | 74 (%33,0) | 396 (%18,1) | 138 (%23,1) |
| `cagrilan_ithal_yalniz_gurultu` | 476 (%29,3) | 12 (%10,7) | 16 (%3,9) | 38 (%42,7) | 104 (%34,8) | 60 (%26,8) | 430 (%19,6) | 120 (%20,1) |
| `dizgi_xref` | 361 (%22,2) | 51 (%45,5) | 152 (%37,4) | 8 (%9,0) | 29 (%9,7) | 32 (%14,3) | 704 (%32,1) | 137 (%22,9) |
| `dizgi_govde` | 531 (%32,7) | 56 (%50,0) | 170 (%41,8) | 8 (%9,0) | 43 (%14,4) | 33 (%14,7) | 710 (%32,4) | 134 (%22,4) |
| `adresi_baska_govdede` | 905 (%55,8) | 42 (%37,5) | 164 (%40,3) | 31 (%34,8) | 127 (%42,5) | 106 (%47,3) | 1 253 (%57,2) | 368 (%61,6) |
| `veri_etiketi_govde` | 383 (%23,6) | 90 (%80,4) | 120 (%29,5) | 37 (%41,6) | 81 (%27,1) | 65 (%29,0) | 500 (%22,8) | 218 (%36,5) |
| `sabit_govde` | 1 451 (%89,4) | 75 (%67,0) | 348 (%85,5) | 65 (%73,0) | 228 (%76,2) | 160 (%71,4) | 1 924 (%87,8) | 486 (%81,4) |
| `imza_parametreli` | 1 527 (%94,1) | 91 (%81,2) | 377 (%92,6) | 70 (%78,6) | 269 (%90,0) | 199 (%88,8) | 2 039 (%93,0) | 542 (%90,8) |
| `imza_adli_tip` | 18 (%1,1) | 6 (%5,4) | 10 (%2,5) | 17 (%19,1) | 38 (%12,7) | 36 (%16,1) | 24 (%1,1) | 17 (%2,9) |
| `ghidra_uyari` | 455 (%28,0) | 31 (%27,7) | 186 (%45,7) | 53 (%59,6) | 100 (%33,4) | 100 (%44,6) | 287 (%13,1) | 101 (%16,9) |
| `ghidra_uyari_kuskulu` | 25 (%1,5) | 4 (%3,6) | 67 (%16,5) | 3 (%3,4) | 8 (%2,7) | 3 (%1,3) | 29 (%1,3) | 14 (%2,4) |
| `boyut_karmasiklik` | %100 | %100 | %100 | %100 | %100 | %100 | %100 | %100 |

### 3.4 Karadul kanıtları

| tür | debian/tmux | debian/tree | debian/sqlite3 | cat | ls | sort | mac/tmux | mac/htop |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `yerel_ad_kaydi` | %88,0 | %83,0 | %82,8 | %65,2 | %82,9 | %81,2 | %89,8 | %88,1 |
| `param_adi` | %24,3 | %18,8 | %18,9 | %29,2 | %23,8 | %29,9 | %21,3 | %23,1 |
| `param_alan_bilinen` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `blok_aciklama` | %37,7 | %44,6 | %46,0 | %29,2 | %28,8 | %33,0 | %35,0 | %33,3 |
| `algoritma_etiketi` | 4 (%0,2) | 0 | 10 (%2,5) | 0 | 0 | 0 | 5 (%0,2) | 0 |
| `bilesim_asamasi` | 17 (%1,1) | 1 (%0,9) | 4 (%1,0) | 0 | 1 (%0,3) | 1 (%0,4) | 71 (%3,2) | 1 (%0,2) |
| `veri_akisi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `struct_kaynagi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `amac_metni_icerikli` | %29,7 | %33,9 | %30,7 | %27,0 | %36,8 | %29,9 | %4,4 | %3,9 |
| `zeka_algoritma` | %0,3 | 0 | %14,0 | 0 | 0 | 0 | %0,2 | 0 |
| `zafiyet_uyarisi` | %0,1 | %11,6 | %0,5 | 0 | %1,7 | 0 | 0 | 0 |
| `alt_sistem_anlamli` | %20,9 | %21,4 | %9,3 | %22,5 | %15,4 | %21,9 | %19,2 | %18,1 |
| `alt_sistem_grup` | %73,9 | %68,8 | %70,3 | %65,2 | %73,2 | %63,8 | %73,8 | %74,2 |
| `bsim_aday` | %18,8 | %5,4 | 0 | %9,0 | %10,0 | 0 | %53,7 | 0 |
| `imza_adayi_uygulanmamis` | 8 (%0,5) | 4 (%3,6) | 40 (%9,8) | 0 | 4 (%1,3) | 2 (%0,9) | 14 (%0,6) | 10 (%1,7) |
| `ad_koken_global` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

- `amac_metni_icerikli` Mac'te %3,9-4,4. Mach-O'da ithal adları `_` önekli; amaç regex'i büyük olasılıkla bu yüzden tutmuyor **[tahmin]**. Doğrulanmadı.
- `ad_koken_global` sekiz ikilide 0: adsız fonksiyon için "neden ad almadı" kaydı yok.
- `alt_sistem_*` ikisinin toplamından kalan pay `misc` dizininde. Yerleşimi bulunamayan adsız yok (`alt_sistem_kaydi_yok` 0).

### 3.5 Boş kart ve çağıransızlar

| tanım | debian/tmux | debian/tree | debian/sqlite3 | cat | ls | sort | mac/tmux | mac/htop |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `kart_bos_ghidra` | 62 (%3,8) | 5 (%4,5) | 61 (%15,0) | 1 (%1,1) | 16 (%5,3) | 22 (%9,8) | 98 (%4,5) | 24 (%4,0) |
| `kart_bos_tam` *(sonradan)* | 53 (%3,3) | 5 (%4,5) | 55 (%13,5) | 1 (%1,1) | 12 (%4,0) | 16 (%7,1) | 71 (%3,2) | 18 (%3,0) |
| `icerik_adsiz` | 677 (%41,7) | 18 (%16,1) | 105 (%25,8) | 31 (%34,8) | 105 (%35,1) | 90 (%40,2) | 1 037 (%47,3) | 286 (%47,9) |
| `iliski_yok` *(sonradan)* | 74 (%4,6) | 31 (%27,7) | 129 (%31,7) | 11 (%12,4) | 61 (%20,4) | 32 (%14,3) | 100 (%4,6) | 30 (%5,0) |
| `ui_bos` | 57 (%3,5) | 7 (%6,2) | 74 (%18,2) | 8 (%9,0) | 16 (%5,3) | 22 (%9,8) | 68 (%3,1) | 21 (%3,5) |
| çağıranı yok | 554 (%34,1) | 49 (%43,8) | 215 (%52,8) | 52 (%58,4) | 135 (%45,1) | 83 (%37,0) | 709 (%32,3) | 216 (%36,2) |
| çağıranı yok ve `icerik_adsiz` | 216 (%13,3) | 8 (%7,1) | 90 (%22,1) | 24 (%27,0) | 58 (%19,4) | 47 (%21,0) | 300 (%13,7) | 99 (%16,6) |

### 3.6 Okuma

- **Kart nadiren tamamen boş kalır.** `kart_bos_tam` sqlite3'te %13,5, öbürlerinde %1,1-7,1.
- **Fonksiyonun ne yaptığını adıyla söyleyen kanıt ithal çağrı ve dizgidir.**
  - İkisi de olmayan fonksiyonlar tmux ve htop türünde %41,7-47,9, coreutils'te %34,8-40,2.
  - Bu fonksiyonlarda kart ancak ilişki ve yapı gösterir; araştırmacının işi komşu fonksiyonların kartından ilerlemektir.
- **İthal çağıranların çoğu yalnız gürültü listesindeki çağrıları yapıyor** (`malloc`, `free`, `memcpy`, `strlen`, `__stack_chk_fail` …) **[hesap]**:
  - cat 38/58 (%65,5), Debian tmux 476/762 (%62,5), ls 104/194 (%53,6), Mac tmux 430/826 (%52,1);
  - Mac htop 120/258 (%46,5), sort 60/134 (%44,8);
  - tree 12/93 (%12,9), sqlite3 16/291 (%5,5).
  - Kart bu çağrıları göstermeli ama soluk ve sonda; ayırt edici çağrı ancak %17,6-72,3.
- **Çağıranı olmayan fonksiyonlar %32,3-58,4.**
  - Bunlar büyük olasılıkla bir veri yuvasından ya da adres alınarak çağrılıyor. N4 tablo sayımı (§3.2) bunu Mac htop'ta çağıransızların %61,6'sında veri yuvasıyla açıklıyor (eski koşu).
  - Ürün çıktısında veri yuvası başvurusu yok (§6).
  - Adres başvurusunun metin vekili bu fonksiyonların bir kısmını yakalıyor: Ghidra'da çağıranı olmayan ama adı başka bir gövdede geçen fonksiyonlar §2'deki 411 / 335 / 163 / ….
- **Eski ve yeni ürünün kapsam farkı küçük.** Ghidra katmanı aynı (`rapor.md:371`: ham Ghidra metni birebir aynı).
  - Değişen, adsız kümesi ve Karadul katmanı: algoritma ve bileşim etiketleri büyük ölçüde düştü, BSim içeriği değişti, temiz haritadaki uygulanmamış imza kayıtları arttı.
  - Taban kolunda `icerik_adsiz`: tree %15,7, sqlite3 %25,4, Mac tmux %40,4 (`taban_kol.json`, §9).

## 4. Hesaplanıp atılan kanıt (soru 4)

| Kaynak | Fonksiyon başına diskte mi? | Ölçülmüş güvenilirlik (belge, sayı) | Kartta "ipucu" satırı olabilir mi? |
|---|---|---|---|
| Susturulan `string_context` adayları (dizgiden ad) | **Hayır.** Yalnız alt kanal başına sayı: `silencing.candidates_dropped`. Örnekler: Mac tmux 700, Debian tmux 499, sqlite3 170, Mac htop 115, tree 54 aday. Bütün adayları susan genel anahtar: Mac tmux 75, Debian tmux 51, Mac htop 14, sqlite3 6. Aday listeden çıkarılıyor (`c_namer.py:1842-1860`) | Ad olarak ölçüldü: susan alt kanalların taban adları 14/4 321 doğru (%0,3) (`urun_olcumu_taban.md:74`). Alt kanal başına %0,0-1,1 (`:53-65`) | **Ad olarak hayır.** Dizginin kendisi `dizgi_xref` satırında olgu olarak görünür; ondan türetilmiş ad önerilmemeli |
| Yapısal süzgeçten elenen genel adaylar (`api_call`, `call_graph`) | **Hayır.** Yalnız strateji başına sayı: `eliminated_keys.global_structural_filter`. Mac tmux 1 762 (api_call 635, call_graph 1 127), Debian tmux 1 378, Mac htop 460, sqlite3 324, ls 274, sort 194, tree 102, cat 93 | Ölçülmedi. Bu adaylar hiçbir kolda ad olmadı; ürün ölçümünün kanal tablosunda yoklar | Ölçülene kadar hayır. `api_call` adayının dayandığı ithal çağrılar 1. satırda zaten görünüyor |
| Genel eşik (0,7) altında kalanlar | **Hayır.** `eliminated_keys.below_global_min_confidence`: sekiz ikilide de yalnız `dataflow` stratejisi (Debian tmux 337 … cat 32) | Ölçülmedi. Anahtarların fonksiyon mu veri mi olduğu kayıtta yok. `rapor.md:340`'a göre eşik altındaki genel kayıtlar 0,30 güvenli `DAT_` veri adlarıydı **[okuma]** | Fonksiyon kartına girmez (büyük olasılıkla veri adı) |
| Ad geçerliliği süzgecinin reddettikleri | Evet, tek tek: `name_validity.rejected[]` (anahtar, önerilen ad, neden) | Ölçülmedi | Hayır (geçersiz ya da çakışan ad) |
| Uygulanmamış imza adayları (`signature_matches.json`'da `FUN_…`) | Evet, Ghidra adıyla. Adsızlarda: sqlite3 40, Mac tmux 14, Mac htop 10, Debian tmux 8, tree 4, ls 4, sort 2 | Ölçülmedi; ürün ölçümü yalnız `global`'i ölçüyor. Adların biçimi genel (ör. `copy_buffer`, `parse_xml`) | Hayır. Gösterilecekse ad alanında değil, "ölçülmemiş imza adayı" etiketiyle. Öneri: gösterme |
| BSim gölge adayları | Evet, adresle | Ölçülmedi; makineye ve koşuya bağlı; aday çoğunlukla aynı adlı programdan (§0) | **Hayır** |
| N4 fiil kanıtı | **Hayır.** Üründe yok; yalnız tavan ölçümü var | Tavan (kusursuz kural varsayımıyla): Mac tmux dar %6,8 / geniş %11,1; Mac htop %17,6 / %20,6 (`fiil_tavani.md:117-118`). Başvuru tanımının elle yanlış sınıflaması %25,7 (`:187`) | Fiil (ör. "create") ölçülmedi. Fiilin dayandığı olgular (ayırıcı/bırakıcı çağrısı, geri çağrı olarak verilme) 1. ve 4. satırda zaten görünüyor |
| Tablo yuvası dizgileri (N4 A1) | **Hayır.** `tablo_yuvasi_sayim.py` fonksiyon başına hesaplıyor ama yalnız sayı yazıyor | Tablo tanımı 30 tabloda elle okundu: adım > 8 baytta 2/11 yanlış; adım 8'de 19/19 vtable benzeri (`tablo_yuvasi_sayim.md:242-245`). Kayıt dizgisi kesin okumada 10/10 tabloda doğru kayıtta (`:247`). Dizginin fonksiyon adı olarak doğruluğu ölçülmedi (`:270`) | **Evet, olgu olarak:** "şu tablonun N. kaydında; kayıttaki dizgi(ler)". Ad önerisi olarak değil. Önce ürün çıktısına yazılmalı (§6) |
| Kalan kanallardan `kebap_ad`, `api_param_reverse` | Yeni üründe ad olarak susuyor | Ad olarak 0/266 ve 0/55 (`kalan_kanal_dokumu.md:13-14`). `api_param_reverse` adlarının 53/55'i geri çağrı rolü adı | Rol ipucu olarak ölçülmedi. Dayandığı olgu ("X'e argüman olarak veriliyor") adres başvurusu satırında görünüyor |
| `oz_ad`, ön adlar (`binary_extract`) | Ad olarak üründe | `oz_ad` 207/332 (%62,3); ön adlar 963/1 420 (%67,8) (`kalan_kanal_dokumu.md:11`) | Adsız kartına girmez; bunlar ad veriyor |
| Eski ürünün adları (taban ölçümü, 6 394 ad) | — | %81,5 yanlış (`urun_olcumu_taban.md:13`) | Kart, eski ürünün adını "aday" diye göstermemeli |

## 5. Kart önerisi (soru 5)

- Kart yalnız adsız fonksiyon içindir.
- Satırlar olguyla çıkarımı ayırır. Olgu = Ghidra'nın ya da ikilinin doğrudan söylediği; ölçülmemiş çıkarım kartta yer almaz.
- Kapsam aralıkları §3'ten: sekiz ikilinin en düşüğü ve en yükseği.

### 5.1 Satırlar (önerilen sıra)

| Sıra | Satır | Kaynak (anahtar) | Kapsam | Güvenilirlik |
|---|---|---|---|---|
| 0 | **Decompile uyarı rozeti** (Ghidra'nın kendi uyarısı; kuşkulu türü ayrı renkte) | ham decompile metni (Ghidra adı = adres) | herhangi %13,1-59,6; kuşkulu %1,3-16,5 | Ghidra olgusu. Varlığı kartın geri kalanının da kuşkulu olabileceğini söyler |
| 1 | **Çağırdığı kütüphane fonksiyonları** (ayırt edici olanlar önce; gürültü listesindekiler sonda ve soluk) | `ghidra_xrefs.functions_called` + `ghidra_functions` (thunk/dış) (adres) | %37,7-83,0; ayırt edici %17,6-72,3 | Ghidra çağrı başvurusu; ad ithal simgesi. Doğruluğu ölçülmedi ama çıkarım değil. **İmza veritabanı süzgeci kaldırılmalı** |
| 2 | **Başvurduğu dizgiler** (adresli, tam metin) | `ghidra_xrefs.strings_used` (adres); yedek: gövde literalleri | xref %9,0-45,5; gövde %9,0-50,0 | Olgu. Dizgiden türetilen ad gösterilmez (%0,3 doğru, §4) |
| 3 | **Çağıranlar** (Ghidra çağrı kenarı) | `ghidra_call_graph` ∪ `ghidra_xrefs.called_by` (adres) | %41,6-67,7 | Ghidra olgusu |
| 4 | **Adresini kullananlar** ("çağırmıyor, adresini alıyor ya da aktarıyor") | Bugün metin vekili (`build_model` ters kenarı − çağrı kenarı); kalıcısı Ghidra veri başvurusu (§6) | %34,8-61,6 | Metin vekili. Fazla kenarların %98,4-100'ü çağrı sözdizimi taşımıyor **[hesap]**. Ayrı etiketle gösterilmeli |
| 5 | **Çağırdığı iç fonksiyonlar** (adlı olanlar adıyla) | `ghidra_call_graph.callees` (adres) | %37,5-75,3 | Ghidra olgusu |
| 6 | **Tablo kaydı** ("şu tablonun N. kaydı; kayıttaki dizgi") | Bugün yok; N4 sayımı ürüne taşınmalı | Jenerik nüfusta tablo kaydında (eski koşu, `tablo_yuvasi_sayim.json`): sqlite3 %32,2, tree %32,2, ls %21,9, Debian tmux %19,6, Mac tmux %17,2, Mac htop %10,9; cat ve sort 0 | Adım > 8'de tablo tanımı 2/11 yanlış; adım 8 (vtable benzeri) ayrı gösterilmeli. Kayıt dizgisinin ad olarak doğruluğu ölçülmedi |
| 7 | **Veri başvuruları** (`DAT_`/`PTR_` etiketleri) | Bugün metin vekili; kalıcısı Ghidra veri başvurusu | %22,8-80,4 | Metin vekili |
| 8 | **Boyut, blok, döngü, karmaşıklık, parametre sayısı** | `ghidra_functions.size`, `ghidra_cfg` (adres) | %100 | Ghidra olgusu; fonksiyon sınırı Ghidra'nın |
| 9 | **Dosya konumu** (`out/src/src/subsystem_<x>/…`) | dosya yerleşimi (ürün adı) | %100 | "Alt sistem" iddiası olarak değil, konum olarak. Etiket ya çağrılan API kuralından (1. satırın türevi) ya da çağrı grafı topluluğundan (`group_N`, anlamsız ad) geliyor. Doğruluğu başka bir ajan ölçüyor |

**Sıralama gerekçesi:**
- Uyarı rozeti en üstte, çünkü altındaki her şeyin güvenilirliğini düşürür.
- Ardından ad söyleyen iki olgu: 1 ve 2. Kart boş değilse araştırmacının ilk bakacağı yer bunlar.
- Sonra ilişkiler: 3-6. Fonksiyonun nerede kullanıldığı, ne olduğunu çoğu zaman söyler. Çağıranı olmayan %32-58 için 4 ve 6 tek bağlamdır.
- Yapı en sonda: 7-9. Her zaman dolu ama en az bilgi verir.
- `icerik_adsiz` fonksiyonlarda (1 ve 2 boş, %16-48) kart, "bu fonksiyon hakkında adını söyleyen kanıt yok; komşulara bak" diye açıkça yazmalı. Boşluğu bir etiketle doldurmamalı.

### 5.2 Kartta GÖSTERİLMEMESİ gerekenler

| Bugünkü öğe | Neden |
|---|---|
| "NEDEN İSİMSİZ?" karar ve gerekçe metinleri (`app_specific`, `app_wrapper`, `bsim_shadow`) ve haritadaki karar dalı | Ölçülmemiş iddia. "İmza eşleşmesi yok" cümlesi imza adayı olan fonksiyonlarda yanlış (§2). "Programın kendi kodu" diyen kararı statik bağlı kütüphane kodundan ayıran bir denetim yok |
| BSim satırı ve "füzyona açarsan isimlenebilir" yönlendirmesi | Ölçülmedi. Makineye ve koşuya bağlı. Mac tmux'ta adayların %91,8'i aynı adlı programdan (GT sızıntısı ya da döngüsel kanıt) |
| İkili geneli hesaplama füzyonu satırı | Fonksiyona özgü değil; kartların %100'ünde |
| "⚗ İPUÇLARI · karadul analizi" başlığı | İçerik Ghidra'nın ithal çağrısı. 1. satır olarak, doğru başlıkla verilmeli |
| Çağıran ve çağırdığı listesindeki adres başvuruları | Çağrı değil. 4. satır olarak ayrı verilmeli |
| Algoritma etiketleri, bileşimler, zekâ raporunun amaç metni ve ikili geneli etiketleri | Ölçülmedi. Kripto sahte pozitifi tabanda 8 666 fonksiyondu. Yeni üründe tree için CFD ve roket simülasyonu bileşimi var; "OpenGL" 119/119 ikilide |
| Uygulanmamış imza adayları | Ölçülmedi; ad gibi görünüyor |
| Dizgi kökenli ad adayları (susturulanlar), `kebap_ad`, `api_param_reverse` adları | Ad olarak %0-0,3 doğru |
| Üretilen satır yorumları, `VULN:` uyarıları, blok açıklamaları | Kodun yeniden anlatımı ya da regex; ölçülmedi. Zaten kod panelinde görünüyorlar |
| `param_naming_map` alanı (`domain`), struct kaynağı, veri akışı | Adsızda boş: `unknown` %100, struct 0, veri akışı 0 |
| Eski ürünün adı | %81,5 yanlış (`urun_olcumu_taban.md:13`) |

## 6. Eksikler (soru 6)

1. **Veri → fonksiyon başvuru listesi.**
   - `_extract_xrefs` (`headless.py:1404-1500`) giden başvurularda yalnız çağrıyı ve dizgi tipli veriyi (`:1432-1452`), gelenlerde yalnız çağrıyı (`:1456-1463`) yazıyor.
   - Eklenmesi gerekenler, adresle:
     - fonksiyonun girişine gelen veri başvuruları (hangi veri sözcüğü ya da kod konumu bu adresi tutuyor);
     - fonksiyondan çıkan dizgi dışı veri başvuruları.
   - CLI betiğinde benzeri var (`karadul/ghidra/scripts/xref_analysis.py:82` `globals_accessed`, `:85` `data_refs_from`); PyGhidra yolunda yok.
   - Ekleme yeniden Ghidra koşusu gerektirir.
   - Etkisi: 4. ve 6. satır metin vekilinden kurtulur. Çağıranı olmayan %32-58 için tek bağlam budur.
2. **Tablo yuvası bilgisinin ürün çıktısına yazılması.**
   - Bugün yalnız N4 sayım betiğinde (`docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.py`) ve yalnız sayı olarak var.
   - Adres anahtarıyla fonksiyon başına yazılmalı: tablo adresi, adım, kayıt sırası, kesin kayıt dizgileri.
3. **Adsız fonksiyonun "neden ad almadı" kaydı.**
   - Susturulan ve elenen adaylar yalnız sayılıyor (`c_namer.py:372-388`, `:1842-1860`).
   - Kart bunları ad olarak göstermemeli; ama ölçüm ve hata ayıklama için fonksiyon başına kayıt gerekli: anahtar, strateji, alt kanal, neden.
   - Kartta en çok şöyle bir satır olur: "N aday üretildi; hepsi ölçülmüş zayıf kanaldan ya da ölçülmemiş yapısal stratejiden".
4. **Makine okunur alt sistem haritası.**
   - `subsystem_map.md` 50 adla kesik (`c_project_builder.py:1181-1184`). Tam yerleşim yalnız dosya yolunda ve ürün adıyla anahtarlı.
   - `func_subsystem` sözlüğü (`:284-301`, ad anahtarlı) adres anahtarıyla JSON olarak yazılmalı.
5. **Çağrı yeri (call site) bilgisinin tamamı.**
   - `ghidra_decompiled.json` `functions` ilk 500 fonksiyonla kesik (`headless.py:1055`).
   - Mac tmux (2 821 fonksiyon) ve Debian tmux (2 588) çağrı yerlerinin çoğunu kaybediyor.
6. **Ada anahtarlı olup adrese çevrilmesi gereken kayıtlar:**
   - `param_naming_map.json` (`functions[ad]`), `annotated/block_annotations.json` (`function_name`), `algorithms.json` (`function`), `algorithm_compositions.json` (`stages[].functions`).
   - `data_flow*.json` (`source_func`, `target_func`, `functions`), `struct_recovery.json` (`source_functions`), `intelligence_report.json` (`function_analyses[].name`).
   - `subsystem_map.md` ve `out/src/src` dosya adları; `signature_matches.json` (`original`).
   - `out/naming_map.json` `mappings`: karışık anahtar (imza kayıtları adla, c_namer kayıtları `FUN_` ile). Arayüzün `_external_call_hints` (`ui/server.py:526`) ve `_clean_mappings` okuması bu karışık anahtara dayanıyor.
   - Adsız fonksiyonda bugün sorun çıkmıyor; anahtar `FUN_<adres>` ve tekil. Sorun ad alan fonksiyonlarda ve ithallerde: Debian'da 63-239 ithal Ghidra adı tekil değil (§1.4).
7. **`ghidra_strings.json` `function` alanı.** Dizginin kendi adresini içeren fonksiyonu arıyor (`headless.py:635-638`); veri bölümündeki dizgide her zaman boş. Ya kaldırılmalı ya da başvuran fonksiyonlarla doldurulmalı.
8. **`ghidra_functions.json` tip alanları.** Decompile'dan önce çıkarıldığı için jenerik fonksiyonda boş. İmza decompile metninden okunmak zorunda.
9. **Ölçüm düzeni ile arayüz düzeni farkı.** Arayüz `clean/` arıyor, ölçüm `out/`'a yazıyor. Saklı koşu arayüzde açılırsa ipucu ve köken görünmez.

## 7. Doğrulayamadıklarım ve sınırlar

- **Kanıtların doğruluğu ölçülmedi.** Bu belge yalnız "var mı" sorusunu sayıyor.
  - İthal çağrı ve dizgi Ghidra olgusu. Ama Ghidra'nın fonksiyon sınırı, çağrı çözümü ve dizgi tanımı da ölçülmedi.
- **Metin vekilleri** decompile metninden düzenli ifadeyle çıkarıldı: `dizgi_govde`, `sabit_govde`, `veri_etiketi_govde`, `adresi_baska_govdede`, imza tipleri. Ghidra'nın başvuru listesiyle karşılaştırılmadılar; liste yok (§6).
- **Fazla kenar sınıflaması** yalnız adın metinde hemen ardından `(` gelip gelmediğine bakıyor. Elle bakılan örnek yalnız tree'de 3 satır (gösterici ataması).
  - Mac tmux'taki 63 "yalnız çağrı sözdizimi" fazla kenarın (Ghidra'da çağrı kenarı olmayan ama metinde çağrı gibi görünen) nedeni incelenmedi.
- **BSim adaylarının kaynağı** (simgeli kopya mı, ürünün önceki adı mı) doğrulanmadı. Aday adlarına bakılmadı; yalnız program adı sayıldı.
- **Seçim temsiliyeti:** coreutils'in üç ikilisi elle seçildi (bilinen üç komut, farklı boyutta); 106 ikiliyi temsil ettikleri doğrulanmadı.
- **Mac'te amaç metninin düşük olmasının nedeni** (`_` önekli ithal adları) yalnız tahmin.
- **Arayüz tarayıcıda açılmadı.** Davranış, arayüzün Python fonksiyonları ve `index.html`'deki JavaScript okunarak çıkarıldı; `deriveRole` elle Python'a çevrildi.
- **Tablo kaydı kapsamı** (§5.1 satır 6) eski koşunun ad haritasıyla ve jenerik nüfusla sayılmış. Mac'te ol7-a koşusundan; adsız kümesiyle yeniden sayılmadı.

## 8. Berke'nin karar vermesi gerekenler

1. **BSim:** Kartta ve teşhiste kapatılsın mı? (Öneri: evet.)
   - Ölçüm hijyeni sorunu: BSim veritabanı (`~/.cache/karadul/bsim/`) aynı adlı programın adlı fonksiyonlarını döndürüyor ve koşu sırasında değişiyor. Gölge kipte ada girmiyor; ama füzyona açılırsa ölçüm GT sızıntısı ya da döngüsel kanıtla kirlenir.
   - Ürün ölçüm koşularında veritabanı ayrılsın ya da temizlensin mi?
2. **Teşhis metinleri:** Karar metinleri ("uygulamaya özgü", "sarmalayıcı", "imza eşleşmesi yok") ve ikili geneli füzyon satırı kaldırılsın mı? (Öneri: evet; yerine §5.1'deki olgu satırları.)
3. **Adres başvurusu:** Arayüzde "çağıran" yerine ayrı satır olsun mu? Kalıcı çözüm için `headless.py` `_extract_xrefs`'e veri başvurusu eklensin mi?
   - Ekleme yeniden Ghidra koşusu ister; 119 ikilinin saklı koşuları eskir.
   - "Yeniden hesapla" komutu başka bir ajanın kapsamında; onunla birlikte düşünülmeli.
4. **`out/naming_map.json`'daki uygulanmamış imza adayları:** Kullanıcıya ad gibi görünüyorlar ve yeni ürünle sayıları arttı (sqlite3 40). Ayrı bir bölüme mi taşınsın, kaldırılsın mı?
5. **Tablo kaydı satırı:** N4 tablo sayımının fonksiyon başına sonucu ürün çıktısına taşınsın mı? Hangi tanımla: kesin kayıt dizgisi, adım > 8?
6. **`icerik_adsiz` fonksiyonlarda kartın dili:** Mac'te yarıya yakın fonksiyon bu durumda. "Bu fonksiyon hakkında adını söyleyen kanıt yok" demek kabul mü?

## 9. Yeniden üretim

**Yeni kol (bu belgedeki tablolar):**

```
cd /Users/apple/Black_Widow
python3 -I -B docs/arge/2026-11-11_fonksiyon_karti/envanter_sayim.py \
  --cikti docs/arge/2026-11-11_fonksiyon_karti/envanter_sayim.json \
  --md-tablolar ~/karadul_olcum/runs/kart-envanteri-2026-11-11/tablolar.md
```

**Taban kolu** (eski ürünün çıktısı; yeni koşu yok sayılır):

```
python3 -I -B docs/arge/2026-11-11_fonksiyon_karti/envanter_sayim.py \
  --yeni ~/karadul_olcum/runs/kart-envanteri-2026-11-11/yok \
  --cikti ~/karadul_olcum/runs/kart-envanteri-2026-11-11/taban_kol.json \
  --md-tablolar ~/karadul_olcum/runs/kart-envanteri-2026-11-11/taban_kol_tablolar.md
```

- **Süre:** yaklaşık 12 sn; Python 3.12.7.
- **İçe aktarılanlar:** arayüz modülü (`ui/server.py`) ve ürün sabitleri: `c_namer._GHIDRA_AUTO_FUNC`, `c_algorithm_id._GHIDRA_WARNING_HEAD`, `c_comment_generator.VULN_PATTERNS`. `-B` ile `__pycache__` yazılmaz.
- **Künye:** JSON'da betiğin, `ui/server.py`'nin ve `ui/index.html`'in sha256'sı, HEAD ve zaman var.
- **Taban kolundan alınan sayılar** (§0, §3.6): `taban_kol.json`.
  - `bsim_shadow_functions`: Mac htop 597, sort 244, cat 42.
  - BSim satırlı adsız: Mac htop 371.
  - Algoritma etiketi: %28,7-56,0.
  - Temiz haritadaki uygulanmamış imza kaydı: sqlite3 12, Mac tmux 2, Mac htop 0.
  - `icerik_adsiz`: tree %15,7, sqlite3 %25,4, Mac tmux %40,4.
  - Eski ürün adı belirsiz: Debian tmux 5, sqlite3 4, sort 3, cat 1.
- **Bağımsız denetim:** Üç sayı ayrı bir betikle, arayüz kodu kullanılmadan, ara koşuda yeniden sayıldı; üçü de tuttu.
  - tree adsız 112 (115 jenerik − 3).
  - Debian tmux `dizgi_xref` 638/1 916 (o an taban koşusu).
  - Mac htop `cagiran` 381/597.
  - Mac htop ve tree sayıları yeni kolda değişmedi.
- **Diskte bırakılanlar:**
  - `~/karadul_olcum/runs/kart-envanteri-2026-11-11/`: ara koşu JSON'ları (`deneme*.json`), `taban_kol.json`, tablo çıktıları, yardımcılar `ozet.py` ve `turet.py`. Bunlarda ad ya da dizgi yok.
  - Depoda: bu dizindeki üç dosya. Commit yok.
