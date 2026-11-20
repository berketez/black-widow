# HZ1 — HZ-1 ölçüm kancaları (ilerleme dosyası)

Paket: Dalga 0, HZ1 (`docs/arge/2026-11-20_dalga0/gonderim/HZ1.md`). Plan: `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-1".
Taban: `e996200` (main, `git merge --ff-only main` sonrası; `b6aceb9` ile kod farkı yok). Başlangıç: 2026-11-20 08:15.

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Ön kayıt (`on_kayit_hz1.md`) + A/A eki | bitti | `df77fc7`, ek `114f4c6` |
| 2 | Kod (`headless.py`, `macho.py`) | bitti | `959106b` |
| 3 | Testler (`tests/test_hz1_olcum_kancasi.py`, 23 test) | bitti | `afa9751`, `f4ce353` |
| 4 | Mutasyon (hz1 13 / 13; macho 34 / 34, p16a 33 / 33, p16c 16 / 16, p16d 11 / 11) | bitti | `b3ddf97`, `acdb8a4` |
| 5 | S8 çıktı eşitliği (`scripts/arge/hiz/s8_esitlik.py`) | bitti: H1 **tutmadı 7 / 8** (htop: yalnız çağıran sırası; A/A'da aynı nitelikte fark tmux'ta), H2 8 / 8, H3 8 / 8, H4 8 / 8; `naming_map` 8 / 8 eşit | araç `f4ce353`, sonuç bu dosyada |
| 6 | Süre oranı | yapı gereği; ölçülmedi (gece HZ-0) | — |

## Kalem 2 — kod

- `karadul/ghidra/headless.py`
  - Modül sabitleri: `ADIM_*` (18 ad) ve `GHIDRA_ADIMLARI` (tek liste; ÖL-1 içe aktaracak), `DURUM_SURE_ALANLARI = ("analysis", "adim_sureleri", "decompile_parcalari")`.
  - Adlar ilerleme olayı sözleşmesine (`olcek/PLAN.md` §1, `adim=ghidra.<adım>`) göre: `ghidra.jvm_baslatma`, `ghidra.ice_aktarma`, `ghidra.otomatik_analiz`, `ghidra.gdt`, `ghidra.pdb`, `ghidra.functions`, `ghidra.strings`, `ghidra.call_graph`, `ghidra.decompile`, `ghidra.types`, `ghidra.xref`, `ghidra.pcode`, `ghidra.cfg`, `ghidra.function_id`, `ghidra.bsim.ingest`, `ghidra.bsim.query`, `ghidra.combined`, `ghidra.kapatma`. Planın 12 adımına JVM, içe aktarma, otomatik analiz, GDT, PDB ve `open_program` çıkışı (kapatma) eklendi; BSim sözleşmedeki `ghidra.bsim` altında iki alt adım.
  - `_AdimSaati`: `basla` / `bitti` (`time.monotonic`, üç basamak); listede olmayan ad `ValueError`. Adım süresi = çıkarım + JSON yazımı (try bloğunun tamamı); düşen adımın süresi düştüğü ana kadar yazılır; koşmayan adım (ayarı kapalı) ve köprü düşünce yarım kalan adım sözlükte yok.
  - `_analyze_pyghidra`: her adımın başına / sonuna `saat.basla` / `saat.bitti` (gövdeler değişmedi, satır girintisi değişmedi); sonuçta `adim_sureleri`; decompile sonucundan `_decompile_parcalari` `decompiled.json` yazılmadan önce ayrılır → sonuçta `decompile_parcalari`.
  - `_parallel_decompile_java_threads`: `_timed_chunk` sarmalayıcısı parça başına süreyi ölçer (iş parçacığında koştuğu süre; kuyruk beklemesi hariç); `_chunk_time_summary`: `yol`, `parca_sayisi`, `is_parcacigi`, `parca_boyu`, `parca_sn` (parça sırasında), `sure_sn` (en küçük / ortanca / en büyük). Seri yedek yolda tek parça (decompile'ın kendi toplam süresi).
- `karadul/analyzers/macho.py` `_record_ghidra_outcome`: `DURUM_SURE_ALANLARI`'ndan sonuçta olanlar `ghidra_status.json`'un sonuna aynen eklenir; yoksa (CLI / başka arka uç) dosya eskisiyle aynı.
- Dokunulmayan: adımların gövdeleri, `ghidra_output/*.json`, `scripts_output` (→ `static/ghidra_*.json`), `ghidra_log.txt`, `pipeline_result.json`, `stats`, `karadul/config.py`.
- Gerçek Ghidra'da ilk sonuç (S8 sonra, `debian/coreutils/cat`, yük altında: 1 dk yük 7,17): `analysis.analyzer_times` 28 çözümleyici; `adim_sureleri` 17 adım (GDT ayarı boş: yok), toplam 10,140 sn ↔ `duration_seconds` 10,139 (fark yuvarlama, ön kayıttaki 0,01 payının içinde); `decompile_parcalari` 10 parça / 9 iş parçacığı, parça 0,243–1,596 sn (ortanca 0,56).

## Kalem 3 — testler

`tests/test_hz1_olcum_kancasi.py` (23 test): sahte saatle (`headless_mod.time`) her adımın süresi tam eşitlikle ve liste sırasında; adım toplamı = köprü süresi; düşen adım; BSim ingest / query düşmesi; kapalı adımlar; JVM / içe aktarma düşünce yarım adım yok; decompile özeti `decompiled.json`'a ve `scripts_output`'a girmez, `ghidra_output`'a yazılan dosya kümesi aynı; gerçek paralel / seri decompile yolunda parça süreleri (sahte decompiler); P16c'nin `_run_auto_analysis`'inden `analyzer_times` sonuca geçer; `_record_ghidra_outcome` yeni alanları sona ekler, geri kalanı ve `stats` aynı, alan yoksa anahtar listesi eskisiyle aynı; `s8_esitlik.py` hariç alanlar, fark birimi, A/A sınıflaması, H4 toplam denetimi. Eski kodda içe aktarma düşer (kırmızı).

İlgili eski testler: `test_p16a_ghidra_sonuc`, `test_p16c_analiz_suresi`, `test_p16a_decompile_sirasi`, `test_p16a_proje`, `test_p16a_fonksiyon_sayaci`, `test_large_binary_support`, `test_pdb_loading` → 74 geçti.

## Kalem 4 — mutasyon

- `scripts/measurement/mutation_specs_hz1.json`: 13 mutant (10 ürün kodu + 3 `s8_esitlik.py`), 13 öldü, hata 0.
- Var olan tanımlar (değişiklik gerekmedi; `find` metinleri bayatlamadı): `macho` 34 / 34, `p16a` 33 / 33, `p16c` 16 / 16, `p16d` 11 / 11 öldü, hata 0. Not (bu paketten önce de böyleydi): `p16a` üç mutantta (`g10_istatistik_toplami_karisir`, `evrensel_x86_64_tercih`, `bc4_akibet_yazilmaz`) ve `p16c_analiz_suresiz`'de `replace` metni `find` ile aynı uzunlukta; `p16c` iki BSim mutantının `find` metni `bsim.py`'de iki kez geçiyor (tanımda `"occurrence": 2` var, hata değil). Bu dosyalar HZ1'in değil; dokunulmadı.
- Yeniden koşu (scratchpad ortak olduğu için sonuçlar kendi dizinimde; commit `614a8a4`, kod `959106b` ile aynı): `~/karadul_olcum/runs/dalga0-2026-11-20/HZ1/mutasyon/{hz1,macho,p16a,p16c,p16d}.log` → 13 / 13, 34 / 34, 33 / 33, 16 / 16, 11 / 11 öldü; hata 0; `git diff` temiz.

## Tam takım

- 1. koşu (08:35, yük 7–12): 10 200 geçti / 81 atlandı / 7 kaldı. 7'sinin hepsi worktree'de olmayan çalışma verisinden (`vendor/gnulib-ref` → `test_ps3b_*` 3 test; `scripts/node_modules` → `test_deobfuscator` 2, `test_project_reconstructor` 1, `test_pipeline::test_identify_and_static` 1); HZ1 değişikliğinden değil. ORTAK_D0 §2'deki bağlar kuruldu (`sigs`, `vendor`, `signatures_homebrew*.json`, `sigs_macos_system.json`, `signatures.lmdb`, `scripts/node_modules`; commit'lenmez — `sigs`, `vendor`, `scripts/node_modules` bağları `git status`'ta `??` görünüyor, dosyalar adıyla stage edildiği için girmez); 7 test ayrıca koşuldu: 21 / 21 geçti (dosyaların tamamı).
- 2. koşu (08:42–08:53, yük 12–17): 10 312 geçti / 11 atlandı / 0 kaldı (152 seçilmedi; main `b6aceb9` 10 289 + bu paketin 23 testi). Günlük ortak scratchpad'teydi; ana oturumun uyarısı üzerine kesin sonuç için 3. koşu kendi dizinimde: `~/karadul_olcum/runs/dalga0-2026-11-20/HZ1/tam_takim/`.
- **3. koşu (kesin; 08:59–09:09, yük 11–16, kod `959106b` + yalnız belge commit'leri): 10 312 geçti / 11 atlandı / 0 kaldı** (577 sn; `pytest.log`, `commit.txt`, `yuk.txt` aynı dizinde).
- **09:10 — bekliyorum:** S8 sonra kolu 4 / 8 bitti (cat, sort, tree, sqlite3); htop kuyrukta (önde OK5 ve KIMLIK). Kalan dört ikilinin taban süresi toplam ≈ 10 dk + kuyruk; TAHMİNİ bitiş 09:45–10:30. A/A koşusu da sürüyor.

## Kalem 5 — S8 çıktı eşitliği

- Araç: `scripts/arge/hiz/s8_esitlik.py --once <kök> --sonra <kök> [--aa <kök>] [--json …] [--md …]`; `S8_ANAHTARLARI`, `HARIC_ALANLAR` sabitleri sonraki paketler için.
- Önce: `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/` (ana oturum). A/A: `…/s8_taban_b6aceb9_AA/` (ana oturum). Sonra: `~/karadul_olcum/runs/dalga0-2026-11-20/HZ1/s8_sonra_959106b/`, ürün ağacı `~/karadul_olcum/urun-959106b` (`git worktree add --detach`, altı çalışma verisi bağı; `agac_kunyesi` geçti).
- **2026-11-20 08:40 — bekliyorum:** S8 sonra kolu Ghidra kuyruğunda (ANA A/A ve OK5 ile sırayla); cat bitti (08:34, eşit), 7 ikili kaldı. TAHMİNİ bitiş 09:40–10:40 (kuyruk payı belirsiz). Bu arada tam takım koşulacak.
- Sonra kolu bitti: 08:34–10:13, 8 / 8 `tamam` (çıkış 0). Kıyas çıktısı: `~/karadul_olcum/runs/dalga0-2026-11-20/HZ1/s8_esitlik.{md,json}` (ayrıntılı birimler orada; depoya yalnız sayı ve adres).

### T-HZ1 (önce `s8_taban_b6aceb9` ↔ sonra `s8_sonra_959106b`)

| İkili | JSON farklı / dosya | .c farklı / dosya | naming_map farklı / dosya | ghidra_status eski alan farkı | yeni alanlar (sonra) | pcode.jsonl (ek) |
|---|---|---|---|---|---|---|
| debian/coreutils/cat | 0 / 23 | 0 / 296 | 0 / 3 | 0 | analysis, adim_sureleri, decompile_parcalari | eşit |
| debian/coreutils/sort | 0 / 23 | 0 / 625 | 0 / 3 | 0 | aynı üç alan | eşit |
| debian/tree/tree | 0 / 23 | 0 / 250 | 0 / 3 | 0 | aynı üç alan | eşit |
| debian/sqlite3/sqlite3 | 0 / 23 | 0 / 1 144 | 0 / 3 | 0 | aynı üç alan | eşit |
| debian/htop/htop | **6 / 23** | **3 / 1 148** | 0 / 3 | 0 | aynı üç alan | eşit |
| debian/tmux/tmux | 0 / 23 | 0 / 2 588 | 0 / 3 | 0 | aynı üç alan | eşit |
| debian/zstd/zstd | 0 / 23 | 0 / 1 444 | 0 / 3 | 0 | aynı üç alan | eşit |
| mac/tmux | 0 / 23 | 0 / 2 821 | 0 / 3 | 0 | aynı üç alan | eşit |

### T-AA (önce ↔ A/A `s8_taban_b6aceb9_AA`; aynı ağaç, aynı komut, ikinci koşu)

| İkili | JSON farklı / dosya | .c farklı / dosya | naming_map farklı / dosya | ghidra_status eski alan farkı | pcode.jsonl (ek) |
|---|---|---|---|---|---|
| debian/coreutils/cat | 0 / 23 | 0 / 296 | 0 / 3 | 0 | eşit |
| debian/coreutils/sort | 0 / 23 | 0 / 625 | 0 / 3 | 0 | eşit |
| debian/tree/tree | 0 / 23 | 0 / 250 | 0 / 3 | 0 | eşit |
| debian/sqlite3/sqlite3 | 0 / 23 | 0 / 1 144 | 0 / 3 | 0 | eşit |
| debian/htop/htop | 0 / 23 | 0 / 1 148 | 0 / 3 | 0 | eşit |
| debian/tmux/tmux | **4 / 23** | **2 / 2 588** | 0 / 3 | 0 | eşit |
| debian/zstd/zstd | 0 / 23 | 0 / 1 444 | 0 / 3 | 0 | eşit |
| mac/tmux | 0 / 23 | 0 / 2 821 | 0 / 3 | 0 | eşit |

### Fark birimleri (adıyla; ad yerine adres)

- **debian/htop/htop, T-HZ1 (A/A'da yok → kurala göre "sonraya yüklenebilir"), 49 birim:** 5 fonksiyonun (`00112bb0`, `00127a50`, `00127f00`, `00128c20`, `00129400`) çağıran listesi — `call_graph.json` `nodes.<adr>.callers[].{address,name}`, `xrefs.json` `function_xrefs.<adr>.called_by[].{address,name}`, `decompiled.json` `functions[].xrefs.callers[].{address,name,call_site}` (her biri `ghidra_output/` ve `static/ghidra_*.json` kopyasında) — ve 3 `.c` dosyasında yalnız `// Callers:` yorum satırı.
- **debian/tmux/tmux, T-AA (yalnız A/A), 18 birim:** 2 fonksiyonun (`00174c40`, `00174cac`) çağıran listesinde aynı alanlar ve 2 `.c` dosyasında yalnız `// Callers:` satırı.
- Belirlenimsizlik kümesi (iki tabloda aynı ikili ve birim): boş.

### Ön kayıt hükmü (kurala göre; sonradan değiştirilmedi)

| Beklenti | Sonuç |
|---|---|
| H1 çıktı eşitliği 8 / 8 | **TUTMADI: 7 / 8.** htop'taki 49 birim A/A'da aynı ikilide görülmedi; ek kuralı gereği "sonraya yüklenebilir" sayıldı. |
| H2 durum dosyasında yalnız yeni alanlar farklı, 8 / 8 | tuttu: 8 / 8 (eski alanlarda fark 0; yeni üç alan 8 / 8 yalnız sonrada) |
| H3 `analysis.analyzer_times` dolu, 8 / 8 | tuttu: 8 / 8 (28 çözümleyici; mac/tmux 30), `analysis.status` 8 / 8 `ok` |
| H4 kayıt tutarlılığı, 8 / 8 | tuttu: 8 / 8 (17 adım, hepsi listede, ≥ 0; toplam ↔ `duration_seconds` farkı ≤ 0,002 sn; parça sayısı 10) |
| Ek: `naming_map.json` | 8 / 8 bayt eşit (24 / 24 dosya) — analistin gördüğü adlar değişmedi |
| Ek: `pcode.jsonl` | 8 / 8 bayt eşit |

### Kayıt dışı ek denetim (hükmü değiştirmez; htop farkının niteliği)

Hüküm yukarıda; aşağıdakiler ön kayıtta yoktu, sonradan bakıldı ve yalnız açıklama içindir.

1. **Fark yalnız sıra:** çağıran listeleri adrese göre sıralanıp `.c`'deki `// Callers:` satırı çıkarılınca htop'ta (önce ↔ sonra) kalan JSON farkı 0, `.c` farkı 0; 5 fonksiyonun çağıran kümesi ve sayısı aynı. A/A tmux farkı da aynı nitelikte (sıralayınca 0).
2. **Aynı sıra HZ-1'den önceki bir koşuda da çıkmış:** htop'un bu 5 fonksiyonunun çağıran sırası, eldeki 6 koşuda 4 farklı sınıfa düşüyor; HZ1 sonra kolunun sırası `urun-yeni2-f30ac9a` koşusununkiyle (HZ-1 kodu yok) birebir aynı; taban ile A/A ayrı bir sınıfı paylaşıyor; `urun-onarim-a62f15e` ve `urun-yeni-93a2956` birer ayrı sınıf. Debian tmux'ta taban ile sonra aynı sırada (2 / 6), A/A öbür üç eski koşuyla aynı sırada (4 / 6). Çağrı grafiği kodu `a62f15e` → `b6aceb9` arasında değişmedi (yalnız `pcode_high_vars` sıralaması, P16d).
3. **Kaynak:** çağıranlar `ReferenceManager.getReferencesTo(...)` yinelemesinin sırasıyla toplanıyor (`headless.py` `_extract_call_graph`, `_extract_func_xrefs`, `_extract_xrefs`; sıralanmıyor). Sıra, çok iş parçacıklı otomatik analizin başvuruları ekleme sırasına bağlı görünüyor (TAHMİN; Ghidra içi doğrulanmadı). HZ-1 bu işlevlere dokunmuyor; eklenen tek iş adımların etrafındaki `time.monotonic()` çağrıları.
4. Sonuç (yorum): htop farkı Ghidra'nın koşudan koşuya belirlenimsizliği ile tutarlı; ön kayıt kuralı bunu tek A/A koşusuyla ayıramadı. Bu yüzden H1 "tutmadı" olarak kalır.

### Sonraki paketlere not (S8)

- Çağıran sırası belirlenimsiz olduğu için her S8 kıyası rastgele birkaç ikilide fark verebilir (bu oturumda 16 kıyastan 2'sinde). Öneri (ana oturum kararı): (a) çağıran listelerini adrese göre sıralayan ayrı bir paket (çıktıyı değiştirir → `urun_olc` ölçümüyle; `// Callers:` satırı 5'ten fazla çağıranda farklı alt kümeyi gösterebiliyor, analiste görünen bir belirlenimsizlik); ya da (b) sonraki paketlerin ön kaydına "sıra-normal" ikinci satırının baştan yazılması. Hariç alan listesi koşudan sonra genişletilmemeli.
- `s8_esitlik.py` ve `--aa` hazır; `S8_ANAHTARLARI`, `HARIC_ALANLAR` buradan içe aktarılabilir.

## Kalem 6 — süre oranı

Plan kabulü "≤ 1,01" gündüz ölçülmedi (makine yüklü; ORTAK_D0 §3). Yapı gereği: eklenen iş yalnız adım başına iki `time.monotonic()` çağrısı, parça başına iki çağrı ve küçük sözlük yazımıdır; sayı uydurulmadı. Ölçüm gece HZ-0 / ÖLÇ-1'de (HZ-0 bu alanları zaten okuyabilir).

Yük altında görülen süreler (yalnız künye; oran değil): S8 sonra kolunun koşu başlangıcında 1 dk yük ortalaması 6,86–18,41 (`~/karadul_olcum/ghidra_kuyruk.log`, `HZ1 basladi` satırları); köprü süresi (`duration_seconds`) cat 10,1 sn … zstd 134,0 sn.

## Sonraki paketlere not

- **ÖL-1:** `from karadul.ghidra.headless import GHIDRA_ADIMLARI` (ve gerekirse tek tek `ADIM_*` sabitleri). İlerleme olaylarının `adim=` değeri bu adlar; ikinci zamanlayıcı yerine `_AdimSaati.basla` / `bitti` noktalarına olay satırı eklenmesi önerilir (başladı / bitti anları aynı yerde). Sözleşmedeki `ghidra.bsim` burada iki alt adım: `ghidra.bsim.ingest`, `ghidra.bsim.query`. `ghidra_status.json` alan listesi `DURUM_SURE_ALANLARI`.
- **HZ-0 / ÖLÇ-1 / zaman çizelgesi araçları:** `ghidra_status.json` → `adim_sureleri`, `analysis.analyzer_times`, `decompile_parcalari` artık var; alan yoksa (eski koşu, CLI yolu) dosya zamanı yoluna düşülmeli.
- **HZ-3:** `decompile_parcalari.parca_sn` parça dengesizliğini doğrudan veriyor (cat'te 0,243–1,596 sn, yük altında).

## Riskler

- S8 çağıran sırası belirlenimsizliği (yukarıda): sonraki "çıktıyı değiştirmez" paketleri de rastgele kırmızı görebilir.
- Ürün ağacı `~/karadul_olcum/urun-959106b` (detached worktree, altı bağ) silinmedi (ORTAK_D0 §3: ana oturum siler).
- Worktree'de çalışma verisi bağları (`sigs`, `vendor`, `scripts/node_modules` `git status`'ta `??`): commit'lenmedi; birleştirmede dikkat.
- `karadul/config.py`'ye ve sabit dosyalarına dokunulmadı; yama bırakılmadı.

## Commit'ler (dal `worktree-agent-a6926ad632ec03810`, push yok)

`df77fc7` ön kayıt · `959106b` kod · `afa9751` testler · `114f4c6` ön kayıt eki (A/A) · `b3ddf97` mutasyon tanımı · `f4ce353` s8_esitlik.py + testleri · `acdb8a4` mutasyon tanımına s8 mutantları · `614a8a4`, `923876e`, `bc06565` ilerleme · bu commit kapanış.

## PAKET BİTTİ
