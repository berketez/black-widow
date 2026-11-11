# Çıktıdaki beş küçük hata: onarım (2026-11-11)

> Girdi: rapor sayaçları (`docs/arge/2026-11-11_rapor_sayaclari/sonuc.md` §3) ve temiz harita
> (`docs/arge/2026-11-11_temiz_harita/sonuc.md` §7) onarımlarında görülüp dokunulmayan beş çıktı
> hatası. Hepsi kullanıcıya yanlış ya da eksik bilgi gösteriyordu; hiçbiri ad davranışını
> değiştirmez (§2.2'de ölçüldü). Bu belgedeki her sayı aşağıdaki komutların çıktısıdır. Kör
> setlere ve GT dosyalarına bakılmadı. Tam hat koşusu yalnız Debian `tree` üzerinde, bir kez.

Satır numaraları: "önce" HEAD `f30ac9a`, "sonra" bu dalın son commit'i.

## 1. Kalemler

| # | Belirti | Kök neden | Değişiklik |
|---|---|---|---|
| 1 | Markdown raporu ithal sayısı bilinmiyorken "0" | `reporting/markdown_report.py:221` `_safe_get(stats, 'imports_found', '0')`; JSON raporu aynı durumda "N/A" yazıyor (`reporting/json_report.py:152`) | `markdown_report.py:223`: öntanımlı "N/A" (`_safe_get`'in kendi öntanımlısı). Gerçek 0 korunur |
| 2 | `lief_analysis.json` kitaplık listesi ELF'te boş | `analyzers/macho.py:625` `getattr(lib, "name", None)`; lief 0.17 ELF ve PE'de `libraries`'i `str` listesi verir (Mach-O'da `DylibCommand`, `.name` var) | `macho.py:719`: `str` ise kendisi, değilse `.name` |
| 3 | `symbols.json` stripped ELF'te 0 simge | `macho.py:530` `nm -g`: dinamik simge tablosunu okumaz (`-D` yok). Bu ortamda PATH'teki `nm` conda cctools nm (`/opt/anaconda3/bin/arm64-apple-darwin20.0.0-nm`), ELF'i hiç okumuyor: çıktı boş, rc 0 | `macho.py:309-312`: ELF'te nm simge vermediyse (boş liste ya da başarısız) `_run_elf_dynsym` (`macho.py:610`) dinamik simge tablosunu lief ile okur. Kayıt biçimi `nm -gD` ile aynı (`address`, `type` harfi, `name`); harf kuralı `_elf_nm_letter` (`macho.py:60`, llvm-nm `getNMTypeChar`). Ad sürüm eki taşımaz. Dosyada `"source": "elf_dynamic_symbols"`. Mach-O ve PE'de davranış aynı |
| 4 | CLI "Imports" satırı ikililerde hiç çıkmıyor | `hacker_cli.py:265` ve `:987` yalnız `stats["imports"]` okuyor. **Düzeltme:** bu anahtarı "hiçbir yer" üretmiyor değil; JS çözümleyicisi üretiyor (`scripts/deobfuscate.mjs:594` `stats.imports`, `analyzers/javascript.py:178`). İkililerin sayısı `imports_found` (`macho.py`) | `hacker_cli.py:259` (aşama günlüğü) ve `:990` (canlı panel): `imports_found` da okunur; JS anahtarı kaldı. Değer yoksa satır yazılmaz (iki işlev de yok/0 değeri zaten atlıyor) |
| 5 | Temiz çıktının `report.html` ad tablosu adayları "Recovered" diye gösteriyor | `core/report_generator.py:702,705` "Name Recovery (Top 30)" / "Recovered"; tablo `reconstructed/binary_names.json` ve `reconstructed/signature_matches.json` kayıtlarını uygulanıp uygulanmadığına bakmadan listeliyor. Ayrımı yapan bilgi (1.1 haritası) `core/output_formatter.py`'de; rapor üreticisi yalnız `(result, workspace)` alıyor ve çağrısı düzenleme yetkim dışındaki `output_formatter.py:255`'te | Başlığı aday anlamına getirdim (ayrım yapılmadı): `report_generator.py:715` "Name Candidates (top 30 of N)" (N ≤ 30 ise "(N)"), sütun "Candidate" (`:720`), bir cümle: tablo uygulanmayı denetlemiyor. Ek bulgu: kayıt adres taşımadığı için aynı adlı iki thunk (PLT ve dış blok) iki özdeş kayıt üretiyor; `:669-673` özdeş satırları teke indiriyor, sayı tekil satır |

### Kalem 3'ün tüketicileri (ad davranışı denetimi)

Değişiklikten önce `nm` çıktısını kimin okuduğu arandı (`grep -rn` ile `symbols.json`, `"symbols"`,
`symbol_count`, `intelligence_report`, `BinaryIntelligence` üzerinde; `karadul`, `ui`):

| Tüketici | Okuduğu | Ad kanalı mı |
|---|---|---|
| `static/symbols.json` | `analyzers/rust_binary.py:86` | hayır: `RustBinaryAnalyzer` kayıtlı değil (`register_analyzer` yok) ve yalnız Mach-O; ürettiği dosyaları okuyan yok |
| `stats["symbol_count"]` | `hacker_cli.py:257, 988` | hayır: gösterim |
| `bi_symbols` → `BinaryIntelligence.analyze` → `static/intelligence_report.json`, `stats["intel_*"]` | `hacker_cli.py:357` (uyarılar), `reporting/html_report.py:304, 655` | hayır: gösterim. `reconstruction/`, `pipeline/`, `stages.py` okumuyor |
| c_namer | — | `reconstruction/name_validity.py:97`: "`symbols.json` c_namer'a verilmez" |

Go ve Swift çözümleyicilerinin kendi `_run_nm`'i var (`go_binary.py:963`, `swift_binary.py:882`), değişmedi.

## 2. Gerçek hat: Debian `tree`

Girdi (salt okunur): `~/karadul_olcum/n1_debian13/tree/tree/ws/workspaces/tree/20261021_092848/raw/tree`
(ELF aarch64, stripped; sha256 `62810aca…49f00c0`, `kucuk-hatalar-2026-11-11/tree/girdi.sha256`).
Taban ("önce", salt okunur): `~/karadul_olcum/runs/temiz-harita-dogrulama-2026-11-11/tree/`
(14:46'da koşmuş; sürüm etiketi 1.21.3, sürüm commit'i `f30ac9a`'dan önce; temiz harita 1.1 kodu).

```
# worktree kökünde, kalem 1-5'in commit'inden sonra (HEAD 0282a58); çıkış kodu 0, 59 sn
GHIDRA_INSTALL_DIR=~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC PYTHONPATH=$PWD PYTHONDONTWRITEBYTECODE=1 \
  python -m karadul analyze <girdi> --skip-dynamic \
  --output-dir ~/karadul_olcum/runs/kucuk-hatalar-2026-11-11/tree/ws \
  --output ~/karadul_olcum/runs/kucuk-hatalar-2026-11-11/tree/out
# önce/sonra ölçümü (R = ~/karadul_olcum/runs/kucuk-hatalar-2026-11-11)
PYTHONPATH=$PWD python $R/once_sonra.py ~/karadul_olcum/runs/temiz-harita-dogrulama-2026-11-11/tree $R/tree $R/hacker_cli_once.py
# kalem 5'in tekilleştirmesi (0b0960c) tam koşudan sonra geldi: aynı çalışma alanında, bellekte
PYTHONPATH=$PWD python $R/html_tablo_yeniden.py $R/tree/ws/workspaces/tree/20261111_120647
```

`hacker_cli_once.py` = `git show e18c8a5:karadul/hacker_cli.py` (kalem 4'ten önceki sürüm).
Çıktılar: `$R/once_sonra.txt`, `$R/html_tablo_yeniden.txt`.

### 2.1 Önce / sonra

| Kalem | Ölçü | önce | sonra |
|---|---|---|---|
| 1 | `reports/report.md` ithal satırı | `- **Imports found:** 63` | `- **Imports found:** 63` (tree'de `imports_found` var; hata yalnız değer yokken görülür, §3'teki testler) |
| 2 | `lief_analysis.json` `libraries` | `[]` | `["libc.so.6", "ld-linux-aarch64.so.1"]` |
| 3 | `symbols.json` `total` / kayıt | 0 / 0 | 70 / 70 (`U` 66, `w` 4; `source` `elf_dynamic_symbols`) |
| 3 | `static.symbol_count` | 0 | 70 |
| 4 | CLI aşama günlüğü (aynı koşunun `static` istatistikleriyle) | satır yok | `\|-- Imports: 63` |
| 4 | CLI canlı panel | satır yok | `├─ Imports: 63` |
| 5 | `out/report.html` başlık | `Name Recovery (Top 30)` | `Name Candidates (top 30 of 133)` (0282a58, tam koşu); `Name Candidates (top 30 of 70)` (0b0960c, bellekte) |
| 5 | sütunlar | Original, Recovered, Source, Confidence | Original, Candidate, Source, Confidence |
| 5 | satır / yinelenen özgün ad | 30 / 0 | 30 / 0 |

Doğrulamalar:
- Kalem 2: `/usr/bin/objdump -p <tree> | grep NEEDED` → `libc.so.6`, `ld-linux-aarch64.so.1` (listeyle aynı); lief
  0.17.6 ELF, PE (Ghidra'nın `demangler_gnu_v2_24.exe`: `KERNEL32.dll` …) ve Mach-O (`/usr/bin/true`)
  için öğe türü yoklandı: ELF `str`, PE `str`, Mach-O `DylibCommand`.
- Kalem 3, beş ELF'te `_run_elf_dynsym` = `/usr/bin/nm -gD` (llvm-nm; sürüm eki atılarak), adres + harf + ad
  birebir (`$R/dynsym_vs_nm.txt`):

  | ELF | lief | `nm -gD` | birebir |
  |---|---|---|---|
  | Debian `tree` (stripped) | 70 | 70 | 70 |
  | `tests/benchmark/fixtures/linux_elf_stripped/sample_elf_stripped` | 6 | 6 | 6 |
  | aynı dizinde `sample_elf` (stripped değil) | 6 | 6 | 6 |
  | Ghidra'nın jpype tekerleğindeki `_jpype…so` (B, D, T, U, V, W, u, w) | 2 357 | 2 357 | 2 357 |
  | Ghidra `demangler_gnu_v2_41` (x86-64) | 40 | 40 | 40 |

- Kalem 3 kök nedeni (`$R/nm_kok_neden.txt`): PATH'teki nm `-g` → rc 0, 0 satır, stderr boş;
  `/usr/bin/nm -g` → rc 0, 0 satır, stderr "no symbols"; `/usr/bin/nm -gD` → 70 satır.
- Kalem 5'in sayısı: `reconstructed/signature_matches.json` 133 kayıt, 70 tekil (özgün, aday); 63 kayıt
  özdeş. Ghidra `getcwd` için iki thunk veriyor (`00103d00`, `00135010`); kayıt adres taşımadığı için
  ikisi aynı satır. `binary_names.json` bu koşuda yok.

### 2.2 Ad davranışı değişmedi

| Dosya | önce sha256 | sonra sha256 |
|---|---|---|
| `reconstructed/src/naming_map.json` | `79a3ddbd87ac…` | `79a3ddbd87ac…` (bayt bayt aynı) |
| `reconstructed/src_iter1/naming_map.json` | `94cffe6c3d45…` | `94cffe6c3d45…` (bayt bayt aynı) |
| `out/naming_map.json` | `7c49aebbc27c…` | `7c49aebbc27c…` (bayt bayt aynı) |

`diff -rq önce/out/src sonra/out/src`: 275 dosyanın yalnız `compile_commands.json`'ı farklı (mutlak
çalışma alanı yolu). Çalışma alanında 27 dosya farklı; sınıflama (`$R/fark_turu.py`):
- Bu değişikliğin beklenen izi: `static/lief_analysis.json` (kitaplıklar), `static/symbols.json`,
  `static/intelligence_report.json` (`total_symbols_analyzed` 0 → 70; alt sistem 9 → 10: "Localization",
  kanıtı `setlocale`; birkaç alt sisteme simge kanıtı eklendi), `reports/*` (sayaçlar, zaman).
- Koşudan koşuya değişen, bu değişiklikle ilgisiz:
  - `ghidra_decompiled.json` (`pcode_high_vars`, süre, yol), `pcode*`, `reconstructed/data_flow/*`,
    `algorithm_compositions.json`, `compositions.md`, `struct_recovery.json` (yollar),
    `compile_commands.json` (yollar), `bsim_shadow.json`: bu dosyalar bu kodlara dokunmayan önceki
    çiftte de (`~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/{once,sonra}`, `diff -rq` + `fark_turu.py`)
    aynı türde farklarla farklı çıkıyor (sıra değişimi; `data_flow_pipelines.json`'da işlev adları).
  - `ghidra_bsim.json`, `ghidra_output/bsim_matches.json`, `ghidra_combined_results.json`
    (`summary.bsim_matches` 208 → 35): BSim sorgusu ortak `~/.cache/karadul/bsim/` veritabanına gidiyor;
    veritabanı bu koşudan sonra da değişti (`karadul_bsim.trace.db`, `bsim_lite_index.json` 15:15; koşu
    15:07'de bitti), yani başka analizler de yazıyor. Eşleşme farkının nedeni ayrıca doğrulanmadı.
  - Ghidra koşusu `nm`/lief çıktısını almıyor (`_run_ghidra(binary_path, workspace)`), yani bu
    değişikliğin Ghidra'ya veri yolu yok.

## 3. Testler ve mutantlar

Yeni: `tests/test_cikti_kucuk_hatalar.py` (42 test öğesi; parametreli dahil). Değişen:
`tests/test_output_formatter.py::test_html_contains_naming_table` ("Name Recovery" → "Name Candidates").

- Kalem 1: `MarkdownReporter.generate` ile yazılan `report.md`: 63 → "63", 0 → "0", anahtar yok → "N/A".
- Kalem 2: sahte lief (ELF düz metin, Mach-O nesne) ve gerçek lief ile depodaki stripped ELF (`libc.so.6`).
- Kalem 3: `_elf_nm_letter` 15 durum (w v W V U C u i A ? T B D R N); `_run_elf_dynsym` gerçek lief ile depodaki
  stripped ELF (`nm -gD` ile aynı 6 kayıt), sahte lief ile yerel/bölüm/adsız girişlerin atlanması ve
  ELF32 adres genişliği, okunamayan tablo → None; `analyze_static`: ELF'te nm boş liste ya da başarısız →
  dinamik tablo; nm simge verdiyse nm kalır; Mach-O'da dinamik tablo okunmaz.
- Kalem 4: `_format_stage_stats` ve `_show_stage_result` (kayıtlı Rich konsolu): `imports_found` 63 → satır,
  JS `imports` 12 → satır (korunur), değer yok → satır yok.
- Kalem 5: başlık ve sayı (133 → "top 30 of 133"; iki kaynak 25 + 10 → "of 35"; 2 → "(2)"), "Recover" geçmez,
  not cümlesi, tam `generate_html`, özdeş kayıtlar tek satır (40 × 2 → "of 40"), güveni farklı kayıtlar ayrı.

Mutasyon: `scripts/measurement/mutation_specs_cikti_kucuk_hatalar.json`, 27 mutant (markdown 2, lief
kitaplık 3, simge 7, nm harfi 4, CLI 3, HTML 8).

```
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_cikti_kucuk_hatalar.json
== ozet: 27 killed, 0 survived, 0 error ==
python ~/karadul_olcum/runs/temiz-harita-2026-11-11/betikler/olum_nedeni.py <worktree> scripts/measurement/mutation_specs_cikti_kucuk_hatalar.json
```

27'sinin 27'si `AssertionError`/`assert` ile öldü (`$R/olum_nedeni.txt`); her mutanttan sonra kaynak
baytları geri yazıldı, `git status` temiz.

Takım (worktree, `scripts/node_modules` yok):

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests -q -p no:cacheprovider -k "report or macho or cli or markdown or lief or symbols"
→ 584 passed, 2 skipped, 7686 deselected
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests -q -p no:cacheprovider
→ 4 failed, 8084 passed, 31 skipped, 153 deselected
```

Düşen 4 test JS testi (`test_deobfuscator.py` 3, `test_pipeline.py::TestPipelineExecution::test_identify_and_static`;
Node betikleri `scripts/node_modules` bulamıyor). Ana depodaki `scripts/node_modules` geçici olarak
bağlanınca 4'ü de geçti (`4 passed`); bağ sonra kaldırıldı.

## 4. Sınırlar ve doğrulanmayanlar

- Tam koşu yalnız tree (Debian ELF, stripped). Mach-O ve PE'de tam koşu yok; Mach-O'da kalem 3'ün yolu
  hiç çalışmaz (hedef türü denetimi), kalem 2'de Mach-O dalı birim testiyle sınandı.
- Kalem 3 "geri düşme" kuralı: nm bir simge bile verirse dinamik tablo okunmaz. Bu ortamda PATH'teki nm
  ELF okumadığı için stripped olmayan ELF'te de `symbols.json` artık dinamik tablodan gelir (yalnız
  dinamik simgeler; `.symtab`'ın yerel ve dinamik olmayan global simgeleri yok). `/usr/bin/nm` PATH'te
  önde olsaydı stripped olmayan ELF'te `nm -g` kalırdı (adlarda `@GLIBC_…` eki).
- Kalem 3 ELF'te `intelligence_report.json`'u ve `intel_*` sayaçlarını değiştirir (tree: alt sistem 9 → 10).
  Bunlar gösterimdir (`hacker_cli`, `reports/report.html`); ad kanalı okumuyor (§1 tablo).
- Kalem 5'te uygulanmış ad / aday ayrımı yapılmadı: ayrım `output_formatter._build_naming_map`'in 1.1
  haritasında; rapor üreticisine geçirmek `output_formatter.py`'yi değiştirmeyi gerektirir (yetki dışı).
  Tablo bu yüzden yalnız "aday" der ve uygulanmayı denetlemediğini yazar.
- Kalem 1'in hatası tree'de görünmez (`imports_found` var); yalnız lief yoksa ya da ithal tablosu
  okunamazsa ortaya çıkar. Gerçek hatta bu durum üretilmedi; birim testleri sınar.
- Kalem 4: `karadul analyze` (koşunun kullandığı komut) `cli.py`'nin sonuç tablosunu yazar, `hacker_cli`
  yalnız etkileşimli konsolda (TTY, alt komutsuz `karadul`) çalışır. CLI satırları gerçek koşunun
  `static` istatistikleriyle işlevler doğrudan çağrılarak üretildi; etkileşimli konsol açılmadı.
