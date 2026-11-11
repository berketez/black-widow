# Rapor sayaçları onarımı: tur sayısı, yakınsama nedeni, ithal sayısı (2026-11-11)

> Girdi: çıktı sağlamlığı denetimi (`docs/arge/2026-11-10_cikti_saglamligi/rapor.md` kalem 13;
> yeni üründe `yeni_urun_karsilastirma.md`): `sayi:tur_sayisi`, `yakinsama_nedeni_bilinmiyor` ve
> `ithal_sayaci_sifir` kusurları 119/119 ikilide. Bu belgedeki her sayı aşağıdaki komutların
> çıktısıdır. Kör setlere ve GT dosyalarına bakılmadı. Gerçek hat koşusu yalnız Debian `tree`
> üzerinde yapıldı; 119 ikilide yineleme yapılmadı.

## 0. Özet

| Sayaç (denetim kusuru) | Kök neden | Değişiklik | tree önce → sonra |
|---|---|---|---|
| `pipeline_iterations_run` (`sayi:tur_sayisi`) | Turları Faz 2'deki `feedback_loop` adımı sayıp yazıyor (`pipeline/steps/feedback_loop.py:254-258`); değer aşama istatistiğine `stages.py:3270`'te katılıyor. Step-registry kipinde eski döngü 0 tur koşuyor (`stages.py:3563`) ama döngü sonu koşulsuz `stats["pipeline_iterations_run"] = len(_iteration_stats)` yazıp (`stages.py:4821-4823`) değeri 0, ayrıntıyı `[]`, `timing_pipeline_loop`'u 0,0 ile eziyordu. Faz 3 sonucu `{**stats, **finalize}` ile birleşiyor (`stages.py:5178`); finalize bu anahtarları taşımadığı için ezilmiş 0 rapora gidiyordu. | `stages.py:4824-4833`: dört satır `if not _use_step_registry:` altına alındı (yalnız eski döngü gerçekten koştuğunda yazar). | 0 → 2 (gözlenen 2) |
| `convergence_reason` (`yakinsama_nedeni_bilinmiyor`) | `feedback_loop` nedeni adımın yapıtı olarak döndürüyor (`feedback_loop.py:278`), yapıt Faz 2 koşucusunda kalıyor (`stages.py:3252`). `finalize` Faz 3 koşucusunda; koşucu her `run`'da yeni `StepContext` kuruyor (`pipeline/runner.py:69`) ve Faz 3 tohumunda (`stages.py:5105-5142`) bu anahtar yoktu. `finalize.py:62` `ctx.artifacts.get("convergence_reason", "unknown")` hep öntanımlıya düşüyordu. | `stages.py:3267`: neden Faz 2 yapıtından alınıyor; `stages.py:5149-5151`: varsa Faz 3 tohumuna konuyor. Yoksa tohuma girmez, `finalize` mevcut sözlükteki "unknown"u yazar (uydurulmaz). `finalize.py` değişmedi. | "unknown" → "no_new_names" |
| `summary.total_imports` (`ithal_sayaci_sifir`) | `reporting/json_report.py:150` `static` istatistiklerinden `imports_found` okuyor, yoksa 0 yazıyordu. ELF/Mach-O/PE için statik çözümleyici `analyzers/macho.py` (`MachOAnalyzer`, `macho.py:54-58`); hiçbir çözümleyici `imports_found` üretmiyordu (`grep -rn imports_found karadul` yalnız raporlayıcıları gösteriyor). `_run_lief` (`macho.py:561-626`) ithal listesini okumuyordu. | `macho.py:629-636`: `_run_lief` lief'in `imported_functions` adlarını `imported_functions` anahtarına yazıyor (ayrı `try`; okunamazsa anahtar yok, öbür alanlar döner). `macho.py:278-280`: anahtar varsa `stats["imports_found"] = len(...)`. `json_report.py:150-152`: anahtar yoksa 0 yerine "N/A" (aynı işlevin "bilinmiyor" sözcüğü). | 0 → 63 |

İthal sayacının üretildiği dosyalar `karadul/analyzers/macho.py` (üretici) ve
`karadul/reporting/json_report.py` (rapor alanı). `core/output_formatter.py` ve
`reconstruction/c_project_builder.py` bu zincirde yok; dokunulmadı.

"İthal sayısı" tanımı: lief'in `imported_functions` listesi, yani ithal edilen **fonksiyon**
simgeleri. İthal veri nesneleri (`stdout`, `stderr`, `stdin`, `__stack_chk_guard`) ve tipsiz
zayıf simgeler (`__gmon_start__`, `_ITM_*`) sayılmaz.

## 1. Gerçek hat: Debian `tree` (önce / sonra)

Girdi (salt okunur):
`~/karadul_olcum/n1_debian13/tree/tree/ws/workspaces/tree/20261021_092848/raw/tree`
(ELF aarch64, stripped). Her iki koşuda sha256 aynı (`once/girdi.sha256`, `sonra/girdi.sha256`).

```
# worktree kökünde; önce: HEAD 1c78ec6, değişiklik yok. sonra: aynı komut, değişiklikten sonra
# (kod farkı: ~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/sonra/kod.diff)
GHIDRA_INSTALL_DIR=~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC PYTHONPATH=$PWD PYTHONDONTWRITEBYTECODE=1 \
  python -m karadul analyze <girdi> --skip-dynamic \
  --output-dir ~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/<once|sonra>/ws \
  --output ~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/<once|sonra>/out
```

İki koşu da çıkış kodu 0, `OK 280 dosya yazildi (275 kaynak, 2 rapor)`; süre 70,7 sn / 56,9 sn.

Ölçüm: denetim betiğinin kendi `kosu_denetle` işlevi değiştirilmeden içe aktarıldı ve iki koşuya
uygulandı; bağımsız kaynaklar aynı betikte okundu. Betik
`~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/sayac_olc.py`, çıktıları
`~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/{once,sonra}/sayac_olcum.json`:

```
python -I ~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/sayac_olc.py <worktree> ~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/<once|sonra>
```

| Ölçü | önce | sonra | Gerçek değer ve kaynağı |
|---|---|---|---|
| denetim `sayi:tur_sayisi` | 1 | 0 | |
| rapor `pipeline_iterations_run` | 0 | 2 | 2: `reconstructed/src` ve `src_iter1` dizinleri; `timing_c_naming_iter0/1` anahtarları (denetimin ölçüsü) |
| rapor `pipeline_iteration_details` | `[]` | 2 kayıt (yeni ad 5, 0; toplam 5, 5) | |
| rapor `timing_pipeline_loop` | 0,0 | 10,8 | `feedback_loop_duration_s` (koşucunun ölçtüğü adım süresi): 10,43 / 10,80 |
| denetim `yakinsama_nedeni_bilinmiyor` | 1 | 0 | |
| rapor `convergence_reason` | "unknown" | "no_new_names" | Yapılandırmada en çok 3 tur (`config.py:533`); 2 tur koştu, yani döngü erken durdu ("max_iter" olamaz). 2. turda yeni ad 0, `pipeline_min_new_names_per_iter` 1 → `_feedback_helpers.check_convergence` "no_new_names" döndürür |
| denetim `ithal_sayaci_sifir` | 1 | 0 | |
| rapor `summary.total_imports` | 0 | 63 | 63: Apple `objdump -T` dinamik simge tablosunda `DF *UND*` (tanımsız fonksiyon) satırı; lief `imported_functions` (ayrı süreçte, ham ikili) 63 |
| `static.imports_found` | yok | 63 | |
| Ghidra thunk (sayı / tekil ad) | 131 / 67 | 131 / 67 | 67 tekil ad = 63 ithal fonksiyon + `_INIT_0` + `__gmon_start__`, `_ITM_registerTMCloneTable`, `_ITM_deregisterTMCloneTable`; lief'in 63 adının hepsi thunk adları içinde |

`objdump -T` sayımı:
`objdump -T <girdi> | grep '\*UND\*' | grep -c ' DF \*UND\*'` → 63; kalan 7 `*UND*` satırı 4 veri
nesnesi (`DO`) ve 3 zayıf tipsiz simge.

Raporun öbür alanları: `report.json` iki koşuda karşılaştırıldı; süre alanları dışında fark
yalnız yukarıdaki dört reconstruct alanı, `static.imports_found` ve `summary.total_imports`
(süre dışı ek fark: `yara_scan_time_ms`, `flirt_load_seconds`, ikisi de süre ölçüsü).

### 1.1 Ad davranışı değişmedi

| Dosya | önce sha256 | sonra sha256 |
|---|---|---|
| `reconstructed/src/naming_map.json` | `79a3ddbd…7b7292` | `79a3ddbd…7b7292` (`cmp` aynı) |
| `reconstructed/src_iter1/naming_map.json` | `94cffe6c…14c2d` | `94cffe6c…14c2d` (`cmp` aynı) |
| `out/naming_map.json` | `eda53a1a…0b640` | `eda53a1a…0b640` (`cmp` aynı) |

`diff -rq once/out/src sonra/out/src`: 275 dosyanın 273'ü bayt bayt aynı; bütün `.c` dosyaları
aynı. Farklı iki dosya:

- `compile_commands.json`: yalnız `"directory"` alanındaki mutlak çalışma alanı yolu
  (`once/ws/...` ↔ `sonra/ws/...`).
- `include/types.h`: dört özdeş `recovered_struct` (003–006) kaynak fonksiyonu yorumunun sırası yer
  değiştirmiş (`Sources: FUN_00109600` ↔ `FUN_00109460`); yapı tanımları aynı. Kök neden bu
  onarımla ilgisiz: `reconstruction/c_type_recoverer.py:1131-1148` ayrıştırma sonuçlarını
  `as_completed` (iş bitiş) sırasıyla `_field_accesses`'e katıyor; yapı numaraları bu ekleme
  sırasından (`c_type_recoverer.py:1769`, `:1853-1855`). Bu değişiklikteki dosyalar bu yola veri
  vermiyor: `lief_analysis.json`'ı `macho.py` dışında okuyan yok (`grep -rn lief_analysis karadul`),
  `convergence_reason`'ı okuyan yalnız `finalize`, `imports_found`'u yalnız raporlayıcılar.
  Bu açıklama kod okumasına dayanır; aynı kodla iki koşu yapılıp sıranın değiştiği ayrıca
  gösterilmedi.

## 2. Testler

Yeni: `tests/test_rapor_sayaclari.py` (16 test). Sayaçları denetimin okuduğu yerden okur:

- Tur ve neden: `_execute_binary` sahte koşucuyla üç faz boyunca yürütülür; Faz 3'te gerçek
  `FinalizeStep` koşar. Tur sayısı, ayrıntısı ve `timing_pipeline_loop` Faz 2'deki değerle aynı;
  tur sayısı `timing_c_naming_iterN` anahtar sayısına eşit (denetim ölçüsü); neden Faz 3 tohumuna
  ve aşama istatistiğine gider; neden yoksa tohuma girmez ve "unknown" yazılır.
- `feedback_loop` adımı (üretici): turlar sahte `run_one_iteration` ile; 3. turda yeni ad
  kalmayınca 3 tur ve "no_new_names", sınıra (2) ulaşınca 2 tur ve "max_iter".
- İthal: `_run_lief` sahte lief nesnesinden adları döndürür; ithal tablosu hata verirse anahtar
  yazılmaz ama sonuç döner. `analyze_static`: liste 3 → `imports_found` 3; boş liste → 0 (gerçek
  sıfır); liste yok ya da lief sonucu yok → anahtar yok. `JSONReporter.generate` ile yazılan
  `report.json`: 63 → 63, 0 → 0, anahtar yok → "N/A".

Mutasyon: `scripts/measurement/mutation_specs_rapor_sayaclari.json`, 15 mutant (stages.py 5,
feedback_loop.py 3, finalize.py 1, macho.py 4, json_report.py 2; `feedback_loop.py` ve
`finalize.py` mutantları bu onarımda değişmeyen üretici/okuyucu satırların kilitlendiğini sınar).

```
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_rapor_sayaclari.json
== ozet: 15 killed, 0 survived, 0 error ==
```

15 mutantın 15'i gerçek test başarısızlığıyla öldü: her mutant uygulanıp hedef test `--tb=line`
ile koşturuldu, 15'inde de ölüm satırı `AssertionError`/`assert` (toplama hatası ya da beklenmeyen
istisna yok). İlk denemede `rs_neden_faz2den_alinmaz` `KeyError` ile ölüyordu; test `seed.get(...)`
ile okuyacak biçimde düzeltildi, sonra `assert None == 'no_new_names'` ile öldü.

Takım (worktree, `scripts/node_modules` yok):

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests -q -p no:cacheprovider -k "finalize or feedback or stages or report or pipeline"
→ 1 failed, 560 passed, 7 skipped, 7520 deselected
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests -q -p no:cacheprovider
→ 4 failed, 7900 passed, 31 skipped, 153 deselected
```

Düşen 4 test JS testi (`test_deobfuscator.py` 3, `test_pipeline.py::TestPipelineExecution::test_identify_and_static`;
Node betikleri `scripts/node_modules` bulamıyor). Ana depodaki `scripts/node_modules` geçici olarak
bağlanınca 4'ü de geçti (`4 passed`); bağ sonra kaldırıldı.

## 3. Sınırlar ve doğrulanmayanlar

- 119 ikilide yineleme yapılmadı; yalnız tree (Debian, ELF) koşuldu. Mach-O için yalnız lief
  yoklandı (tam koşu yok): Mac tmux ham ikilisinde (`workspaces/olcum_mac/runs/ol7-c-b7faeac/tmux`)
  lief `imported_functions` 232, `nm -u` 232, Ghidra tekil thunk adı 232. PE denenmedi.
- lief yoksa ya da ithal tablosu okunamazsa `summary.total_imports` artık "N/A" (önce 0). Bu
  alanı sayı bekleyen bir okuyucu varsa etkilenir; depoda `total_imports`'u okuyan kod yok
  (`grep -rn total_imports karadul ui scripts`).
- `markdown_report.py:221` `imports_found` yoksa hâlâ "0" yazıyor (bu görevin dosyası değil).
- `--verbose` kullanılmadığı için günlükte "Pipeline converged (reason=…)" satırı yok; neden,
  turların ayrıntısından ve yakınsama kuralından yeniden türetildi (§1).
- Her analiz `~/.cache/karadul/bsim/` ortak veritabanına yazıyor (denetim kalem 15); iki koşu bu
  dosyayı değiştirdi.
