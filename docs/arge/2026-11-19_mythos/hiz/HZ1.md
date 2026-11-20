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
| 5 | S8 çıktı eşitliği (`scripts/arge/hiz/s8_esitlik.py`) | araç bitti (`f4ce353`); sonra kolu kuyrukta | — |
| 6 | Süre oranı | yapı gereği; ölçüm gece HZ-0'da | — |

## Kalem 2 — kod

- `karadul/ghidra/headless.py`
  - Modül sabitleri: `ADIM_*` (18 ad) ve `GHIDRA_ADIMLARI` (tek liste; ÖL-1 içe aktaracak), `DURUM_SURE_ALANLARI = ("analysis", "adim_sureleri", "decompile_parcalari")`.
  - Adlar ilerleme olayı sözleşmesine (`olcek/PLAN.md` §1, `adim=ghidra.<adım>`) göre: `ghidra.jvm_baslatma`, `ghidra.ice_aktarma`, `ghidra.otomatik_analiz`, `ghidra.gdt`, `ghidra.pdb`, `ghidra.functions`, `ghidra.strings`, `ghidra.call_graph`, `ghidra.decompile`, `ghidra.types`, `ghidra.xref`, `ghidra.pcode`, `ghidra.cfg`, `ghidra.function_id`, `ghidra.bsim.ingest`, `ghidra.bsim.query`, `ghidra.combined`, `ghidra.kapatma`. Planın 12 adımına JVM, içe aktarma, otomatik analiz, GDT, PDB ve `open_program` çıkışı (kapatma) eklendi; BSim sözleşmedeki `ghidra.bsim` altında iki alt adım.
  - `_AdimSaati`: `basla` / `bitti` (`time.monotonic`, üç basamak); listede olmayan ad `ValueError`. Adım süresi = çıkarım + JSON yazımı (try bloğunun tamamı); düşen adımın süresi düştüğü ana kadar yazılır; koşmayan adım (ayarı kapalı) ve köprü düşünce yarım kalan adım sözlükte yok.
  - `_analyze_pyghidra`: her adımın başına / sonuna `saat.basla` / `saat.bitti` (gövdeler değişmedi, satır girintisi değişmedi); sonuçta `adim_sureleri`; decompile sonucundan `_decompile_parcalari` `decompiled.json` yazılmadan önce ayrılır → sonuçta `decompile_parcalari`.
  - `_parallel_decompile_java_threads`: `_timed_chunk` sarmalayıcısı parça başına süreyi ölçer (iş parçacığında koştuğu süre; kuyruk beklemesi hariç); `_chunk_time_summary`: `yol`, `parca_sayisi`, `is_parcacigi`, `parca_boyu`, `parca_sn` (parça sırasında), `sure_sn` (en küçük / ortanca / en büyük). Seri yedek yolda tek parça (decompile'ın kendi toplam süresi).
- `karadul/analyzers/macho.py` `_record_ghidra_outcome`: `DURUM_SURE_ALANLARI`'ndan sonuçta olanlar `ghidra_status.json`'un sonuna aynen eklenir; yoksa (CLI / başka arka uç) dosya eskisiyle aynı.
- Dokunulmayan: adımların gövdeleri, `ghidra_output/*.json`, `scripts_output` (→ `static/ghidra_*.json`), `ghidra_log.txt`, `pipeline_result.json`, `stats`, `karadul/config.py`.
- Gerçek Ghidra'da ilk sonuç (S8 sonra, `debian/coreutils/cat`, yük altında): `analysis.analyzer_times` 28 çözümleyici; `adim_sureleri` 17 adım (GDT ayarı boş: yok), toplam 10,140 sn ↔ `duration_seconds` 10,139 (fark yuvarlama, ön kayıttaki 0,01 payının içinde); `decompile_parcalari` 10 parça / 9 iş parçacığı, parça 0,243–1,596 sn (ortanca 0,56).

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
