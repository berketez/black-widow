# OLGU paketi — defter

Paket: fonksiyon başına olgu tablosu ve kapsam bütçesi (A1). Hat metni `../OLGU.md`, ortak kurallar `../ORTAK_BRIF.md`.
Ajan: Opus (ölçüm paketi). Başlangıç 2026-11-19.

## 0. Girdi ve kararlar (kalem 1)

- Taban koşusu: `~/karadul_olcum/runs/urun-onarim-a62f15e/{debian,mac}/<program>/<ikili>/{out,ws}`, 119 ikili (Debian 117, Mac 2).
- Ölçüm betikleri iki ağaçta aynı: `scripts/measurement/{urun_olc,ks1_olc,function_f1,macho_f1,macho_measure,dwarf_tip}.py`, `karadul/core/naming_labels.py`, `karadul/reconstruction/tarif/alt_kanal.py`, `tests/benchmark/metrics.py` ana ağaçla (b4be6f3) ürün ağacında (`~/karadul_olcum/urun-a62f15e`, a62f15e) `diff -q` ile birebir aynı (2026-11-19).
- Tablo betiği varsayılan olarak ürün ağacının ölçüm modüllerini içe aktarır (taban ölçümü oradan koşuldu, `sonuc.md` §0). `--olcum-agaci` ile ana ağaç da seçilebilir; kapı iki ağaçla da koşulacak.
- Hüküm, nüfus, kanal: `urun_olc.degerlendir_elf` ve `ks1_olc.gt_elf` / `gt_mac` doğrudan çağrılır (kopya yok).
- Kaynak sınıfı (ELF): `dwarf_tip.dosya_yukle` / `ek_yukle` / `Cozucu` ile dbgsym DWARF'ı (dwz ek dosyası dahil). Mac ikililerinde DWARF da stabs da yok (`nm -ap` ile `SO`/`OSO` 0): alan `bilinmiyor`.
- Mac tmux'un `target_info.json` yolu eski bir koşunun kopyasını gösteriyor; koşunun kendi `raw/<ad>` kopyası sha256 ile denetlenip o okunur.

### P-code dökümünün kapsamı (kalem 6b için ön bulgu)

- `pcode.jsonl` seçici: yalnız `COPY, LOAD, STORE, CALL, CALLIND, RETURN, INT_*, FLOAT_*, CBRANCH, PTRADD` (ürün `config.py` `pcode_selective_ops`). `PTRSUB`, `CAST`, `MULTIEQUAL`, `INDIRECT` yazılmıyor; işlem adresi (seq target) da yok.
- Debian tmux'ta ölçüldü (keşif betiği: bu defterin §6'sı): fonksiyon başı adresi P-code'da yalnız `CALL`'ın 0. girdisi (çağrılan) olarak geçiyor (14 225 / 14 225). Argüman olarak geçen fonksiyon işaretçisi P-code'da hiç yok (büyük olasılıkla `PTRSUB(0, adres)` biçiminde ve `PTRSUB` yazılmıyor).
- Dizgi sabiti yalnız `COPY(const)` girdisi olarak geçiyor (2 599); çıktısı `CALL` argümanına bağlanıyor (2 810 kullanım).
- Sonuç: 6(b)'nin "dizgi + fonksiyon işaretçisi" çifti P-code'dan çıkarılamıyor → alan `desteklenmiyor`. Çağrı yerindeki dizgi argümanı (çağrılan + dizgi) çıkarılabiliyor; ayrı alan olarak yazılacak.
- Not (sonraki paket için): `capstone` 5.0.7 kurulu. AArch64'te `adrp/add/adr` + `bl` izlemesiyle çağrı yerindeki fonksiyon işaretçisi argümanı ikiliden çıkarılabilir; bu paketin kapsamı dışında (hat metni P-code diyor).

## 1. Sıra

1 → 2 → 3 → 4 → 7 → ARA TESLİM → 5 → 6 → 8.

## 2. Çekirdek tablo ve tutarlılık kapısı (kalem 2–3)

- Komut (depo kökünden): `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olgu/olgu_tablosu.py uret --asama cekirdek --is 4 --dogrula`. Süre ~27 sn (4 işçi).
- Satır = Ghidra fonksiyonu: 66 983 satır, 119 ikili (sonuc.md B6'daki fonksiyon sayısıyla aynı; 33 547 thunk, 33 436 iç fonksiyon; adres tekrarı ve onaltılık olmayan adres 0).
- **Kapı: TUTTU, 30 / 30 denetim** (`~/karadul_olcum/runs/arge-2026-11-19/olgu/dogrulama.json`):
  - havuz: nüfus 21 371, ad verilen 1 800, doğru 1 681, yanlış 119, nüfusta ad 1 315, nüfusta doğru 1 212;
  - 10 birimin ad / doğru / yanlış'ı sonuc.md §2 tablosuyla, nüfusu ölçüm JSON'uyla aynı; ikili başına nüfus / ad / doğru 119 / 119 aynı;
  - öğe düzeyi: 1 800 ölçülen adın her birinin `urun_olc.oge_yaz` metni (`durum satır nüfusta etiket kanal`) `urun_olcumu_onarim.json` `ogeler` ile aynı, iki yönde fark 0.
- **Hangi ağaçla tuttu:** ürün ağacı (`~/karadul_olcum/urun-a62f15e`, a62f15e) ve ana ağaç (`/Users/apple/Black_Widow`, `--olcum-agaci`) ile ayrı ayrı koşuldu; iki tablo açılmış hâliyle bayt düzeyinde aynı (sha256 `26c45f6f…`, ilk sürümde), kapı ikisinde de tuttu. Ölçüm modülleri iki ağaçta aynı olduğu için beklenen.
- İlk çekirdek sürümden sonra yalnız kaynak sınıfı kuralı değişti (aşağıda); çekirdek alanlar (§1–§3) değişmedi, kapı her üretimde yeniden koşuldu.

## 3. Kaynak sınıfı (kalem 4) — kalıplar veriden

- 119 ikilinin dbgsym'indeki derleme birimi yolları tarandı (keşif komutu: pyelftools ile birim başlığı `DW_AT_name` + `DW_AT_comp_dir`; bu defterdeki sayılar o çıktıdan). Dizinler: coreutils `lib` (3 456 birim, gnulib), `src`; redis-tools `src`, `deps/{lua,hiredis,hdr_histogram,linenoise,fpconv}`, `modules/vector-sets`, LTO `<artificial>`; tmux kök + `compat`; zstd `programs`, `lib/*` (yol izi `programs/lib/*`, `lib/lib/*`), `contrib/pzstd`; openssl `apps`, `apps/lib`; htop kök + `linux`, `generic`, `zfs`; sqlite3 `shell.c`; tree kök.
- Sınıf, birim yolundan değil önce **tanım dosyasından** (`DW_AT_decl_file`) okunuyor: başlıkta tanımlı `static inline` kopyaları (gnulib başlıkları, glibc `bits/error.h`) böylece doğru sınıfa düşüyor. Kural SEMA.md §4.
- DWARF'sız 274 iç fonksiyon GT adıyla denetlendi (geliştirme seti): GT'de adı olan 157'nin hepsi araç zinciri (libgcc yüzer nokta 121, libgcc atomik 26, bağlayıcı kaplaması 10); GT'de adı olmayan 117'nin 117'si `.plt` bölümünde, 24 bayt: PLT başı (nüfus dışı; bölüm `olgu_ikili.elf_oku` ile okundu). Bu yüzden "DWARF yok + GT adı var" → `derleyici`. Bu denetim GT'ye bakan bir kural doğrulamasıdır; başka sette yeniden denetlenmeli.
- `aranges` ile eşleşen 145 satırın 82'si redis-tools'un LTO bölümü (`<artificial>`): ilk sürümde `program` sayılmıştı, birim adı kaynak dosyayı söylemediği için `bilinmiyor`'a çekildi (nüfusta 10 satır).
- Bir örnek (coreutils, `lib/base32.c`): fonksiyonun yalnız soyut (`DW_AT_inline`) DIE'si var, satır dışı kopyanın somut DIE'si yok → `aranges` eşleşmesi.

### Bütçenin ilk okuması (sayılar `BUTCE.md`'den)

- Nüfusun %53,3'ü gnulib (11 393), %23,3'ü programın kendi kodu (4 977), %14,7'si sınıfsız (3 152; 3 142'si Mac), %4,1'i üçüncü taraf (881), %3,4'ü zstd'nin libzstd kopyası (720).
- gnulib nüfusu 11 393 örnek ama 537 tekil fonksiyon (örnek / tekil 21,2). gnulib ön ad kanalının nüfustaki 733 doğru adı 10 (sınıf, GT adı) çiftinden: 8'i gnulib sınıfında, 2'si program sınıfında; çoğu ~100 ikilide tekrar (`olgu_denetim.py on_ad_tekil`; GT adıyla: `close_stdout`, `close_stream`, `rpl_fclose` 105'er, `version_etc_arn` 104, `usage` 102 (program), `rpl_mbrtoc32` 101, `xalloc_die` 97 + 1 (program), `safe_write` 8, `close_stdin` 5).
- Üçüncü taraf (881), uyumluluk (95), proje kitaplığı (720) ve derleyici (153) sınıflarında bugün doğru ad 0.

## ARA TESLİM: çekirdek + bütçe hazır

- Tablo: `~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` (çekirdek aşama: §1–§4 alanları; künye `olgu_kunye.json`, kapı `dogrulama.json`).
- Şema: `docs/arge/2026-11-19_mythos/olgu/SEMA.md`. Bütçe: `docs/arge/2026-11-19_mythos/olgu/BUTCE.md` (+ `~/karadul_olcum/runs/arge-2026-11-19/olgu/butce.json`).
- Tutarlılık kapısı tuttu (30 / 30, öğe düzeyi dahil).
- İkinci teslimde aynı dosya yerinde (atomik) yenilenecek; çekirdek alanlar aynı kalacak, kanıt ve kayıt çifti alanları eklenecek. Okuyan hat künyedeki `asama` alanına bakabilir (`cekirdek` → `tam`).

## 4. Kanıt alanları (kalem 5)

- `uret --asama tam`: 119 ikili, 66 983 satır, ~52 sn (4 işçi). Kapı yeniden koşuldu: **TUTTU 30 / 30**. Ürün ağacı ve ana ağaçla üretilen tam tablo açılmış hâliyle aynı (sha256 `1188d14c…`).
- Doğrudan dizgi kaynağı: `ghidra_xrefs.json` `strings_used`; `ghidra_strings.json` xref'lerinden kurulan kümeyle 66 983 / 66 983 fonksiyonda aynı (`olgu_denetim.py dizgi_kaynagi` → `~/karadul_olcum/runs/arge-2026-11-19/olgu/denetim/dizgi_kaynagi.json`). Bu koşuda GHIDRA-16'nın açtığı dizgi bağı dahil.
- Satır sayıları (`olgu_denetim.py ozet` → `denetim/ozet.json`): P-code'u olan 66 983; doğrudan dizgisi olan 8 997; yaprak 26 431 (thunk'lar dahil); `CALLIND`'li 3 072; çağrı dizgisi olan 8 806 (58 066 dizgi argümanı).
- Çağrılanın içe aktarım adı: çağrılan Ghidra'da thunk / dış fonksiyonsa onun adı (`memcpy`, Mac'te `_strlen` biçimi olduğu gibi).

## 5. Kayıt çiftleri (kalem 6)

- (a) veri: ELF'te `.rela.dyn` `R_AARCH64_RELATIVE` (117 ELF'in hepsi `ET_DYN`; sembollü `ABS64` / `GLOB_DAT` kaydı 0, künyede `rela` sayacı); Mac'te `dyld_info -fixups` rebase'leri. Toplam 48 185 yuva.
- Fonksiyon başı adresi bir yuvada duran satır 4 828 (7 474 yer; Debian'da 1 419 yer `.got`, komşusu yazılmadı). En az bir komşu dizgisi olan (kayıt çifti) satır 1 817; komşu dizgi 5 896, bunların 4 832'si Ghidra'nın tanımlı dizgisi.
- **Bağımsız denetim** (`olgu_denetim.py kayit_capraz` → `denetim/kayit_capraz.json`): hedef bir Ghidra dizgisinin başı ve Ghidra o dizgiye xref kaydetmişse, xref'lerden biri bizim yuvamız: Debian 2 528 / 2 564 (%98,6), Mac 1 586 / 1 586. Debian'da 682 hedefte Ghidra dizgiyi tanımlamış ama hiç xref kaydetmemiş (Ghidra'nın işaretçi tipi vermediği yuvalar); 1 061 hedef Ghidra dizgisi değil (577'si 4 karakterden kısa; kısa olanların bir kısmı bayt tablosu olabilir, `g` alanıyla ayıklanır).
- (b) çağrı yeri: **desteklenmiyor**. Neden §0: P-code dökümünde fonksiyon işaretçisi argümanı hiç yok (`PTRSUB` yazılmıyor), işlem adresi de yok. Dizgi tarafı `cagri_dizgileri`'nde.
- Gözlem (yorum değil, veri): tmux komut kayıtlarında `exec` işaretçisinin ±4 komşusu kaydın kendi ad / takma ad / şablon alanlarından çok bir sonraki kaydın alanlarına düşüyor; `args.cb` işaretçisinin −4..−2 komşuları kendi kaydının adı. Yuva farkı `o` alanında; hangi farkın "aynı kayıt" olduğu ÖZ KOD hattının sorusu.

## 6. Keşif ve denetim komutları (bu defterdeki sayıların kaynağı)

- P-code keşfi (§0; Debian tmux): `pcode.jsonl` satırlarında `CALL` girdileri, `COPY(const)` çıktıları ve fonksiyon başı adresleri sayıldı (geçici betik, depoya alınmadı; aynı sayım `olgu_ikili.cagri_dizgileri` ile tablonun `cagri_dizgileri` alanında tekrar üretiliyor). Sonuç tabloda: `CALL` dışında hiçbir P-code girdisinde fonksiyon başı adresi yok.
- DWARF birim yolları taraması (§3): pyelftools ile her dbgsym dosyasında birim başlığı `DW_AT_name` + `DW_AT_comp_dir` (geçici betik); kalıplar `olgu_tablosu.kaynak_sinifla`'da sabit, tablonun `dw_birim_yolu` alanında tekrar üretilebilir.
- `olgu_denetim.py dwarfsiz` → `denetim/dwarfsiz.json`: DWARF eşleşmesi olmayan 1 199 iç fonksiyon: CRT 925 (`.init` 117, `.fini` 117, `.text` 691), libgcc yüzer nokta 121, libgcc atomik 26 (22'si nüfusta), bağlayıcı kaplaması 10, GT'siz `.plt` başı 117.
- `olgu_denetim.py on_ad_tekil` → `denetim/on_ad_tekil.json`: `on_ad:gnulib` nüfusta doğru 733 = 10 tekil (sınıf, GT adı).
- `olgu_denetim.py kayit_capraz`, `ozet`, `dizgi_kaynagi`: §4–§5.

## 7. Sınama (kalem 8)

- `scripts/arge/olgu/test_olgu_tablosu.py`, 27 test: RELA ayrıştırma ve RELATIVE / sembollü / atlanan kayıtlar (AArch64 ve x86-64 kodları), C dizgisi okuma (orta, NUL'suz, denetim karakteri, kod bölümü, NOBITS), kırpma, kayıt çifti komşuları (±4 sınırı, yuvanın kendisi hariç, yalnız tam fonksiyon başı, iki yer), yeniden konumlanmayan ham yuvalar, Mach-O bölüm başlığı, P-code çağrı dizgisi (tek / çok tanımlı ara değer, doğrudan sabit, `CALLIND`), kaynak yolu sadeleştirme, 13 sınıflama örneği, şema (`CEKIRDEK_ALANLARI`) ve hüküm (`urun_olc.degerlendir_elf` ile; doğru, yanlış, Ghidra'nın adlandırdığı, nüfus dışı doğru, C++ / Mac), tutarlılık kapısının tutması ve bir hüküm bozulunca düşmesi, bütçe sayacı.
- Koşum: `PYTHONDONTWRITEBYTECODE=1 python -m pytest scripts/arge/olgu/test_olgu_tablosu.py -q -p no:cacheprovider -o addopts=""` → 27 geçti.
- Elle mutasyon (scratchpad kopyalarında, `OLGU_TEST_REPO` ile; depodaki dosyalara dokunulmadı): 8 mutant (komşuda yuvanın kendisi, RELATIVE ekleme, çok tanımlı ara değer, C++ nüfusu, `compat` sınıfı, kod bölümünden dizgi, Ghidra-adlı atlama, kapının nüfusta-ad sayımı). İlk turda 3'ü yaşadı; testler güçlendirildi (yuvanın kendisine dizgi gibi görünen hedef, kod bölümüne basılabilir bayt, nüfus dışı doğru ad); ikinci turda 8 / 8 öldü.
- Kapı betikte: `olgu_tablosu.py dogrula` (ya da `uret ... --dogrula`), çıkış 0 = tuttu.

## ARA TESLİM 2: kanıt + kayıt çiftleri hazır

- Tablo aynı yerde, atomik yenilendi: `~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` (künyede `asama: tam`; çekirdek alanlar değişmedi, kapı 30 / 30 tuttu).
- Yeni alanlar SEMA.md §5–§6; bütçenin 8–12. bölümleri (yaprak, doğrudan dizgi, veri yeri, kayıt çifti, çağrı dizgisi) BUTCE.md'de.

## 8. Kalan iş ve başka hatlar için notlar

- 6(b) çağrı yeri çifti için öneri (bu paketin dışında, ayrı paket): AArch64'te `adrp`+`add` / `adr` ile yazmaçlara yüklenen adresleri `bl` / `b` öncesinde izleyen ikili tarama (`capstone` 5.0.7 kurulu). Ölçüt önerisi: bu taramanın bulduğu dizgi argümanlarının P-code `cagri_dizgileri` ile örtüşmesi (doğrulayıcı), sonra fonksiyon işaretçisi argümanları.
- Mac'te kaynak sınıfı yok (nüfusun %14,7'si). Homebrew şişelerinde dSYM yok; sınıf için kaynaktan derleme ya da başka kanıt gerekir (yeni veri; indirme yok, liste ana oturuma).
- `uyumluluk` (tmux `compat/`) OpenBSD kopyalarıyla tmux'un kendi yamalarını ayırmıyor; KİMLİK hattı ayırmak isterse dosya listesi tabloda (`dw_tanim_dosyasi`).
- Başka hat için not (KİMLİK): gnulib nüfusu 11 393 örnek / 537 tekil; bugünkü 634 gnulib-sınıfı doğrunun düştüğü tekil fonksiyon 10 (her örneği doğru olan 8). Tekil düzeyde kapsam BUTCE §1 tablosunda.
- Başka hat için not (ÖZ KOD): kayıt çifti olan nüfus 1 330, bugün doğru 27; tmux Debian + Mac'te komut kaydı yapısı görünüyor (§5 gözlem).
