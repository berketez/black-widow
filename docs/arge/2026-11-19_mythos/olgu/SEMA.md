# OLGU tablosu — şema

- **Dosya:** `~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` (gzip'li JSON Lines; satır = bir ikilinin bir Ghidra fonksiyonu; sıra birim, ikili, adres). Künye `olgu_kunye.json` (girdi yolları, betik ve ölçüm modülü sha256'ları, ikili başına GT / DWARF künyesi, süre), kapı sonucu `dogrulama.json`.
- **Şema adı:** `karadul-arge-olgu/1`. Künyedeki `asama`: `cekirdek` (§1–§4) ya da `tam` (§5–§6 da var).
- **Üreten:** `scripts/arge/olgu/olgu_tablosu.py uret` (yardımcı `olgu_ikili.py`, bütçe `olgu_butce.py`).
- **Taban:** `~/karadul_olcum/runs/urun-onarim-a62f15e` (a62f15e, 1.24.1; 119 ikili, 66 983 Ghidra fonksiyonu).
- **Ölçüm tanımları içe aktarılır, kopyalanmaz:** `--olcum-agaci` (varsayılan ürün ağacı `~/karadul_olcum/urun-a62f15e`, taban ölçümünün koşulduğu ağaç) altındaki `scripts/measurement/{urun_olc,ks1_olc,function_f1,macho_f1,macho_measure,dwarf_tip}.py`. Ana ağaçla (b4be6f3) aynı dosyalar; iki ağaçla üretilen tablo bayt düzeyinde aynı (DEFTER §2).
- **Okuma:** `olgu_tablosu.tablo_oku(yol)` ya da `gzip.open(yol, "rt")` + `json.loads` satır satır.
- **Gizlilik:** tablo geliştirme setinin GT adlarını taşır (`gt_adlari`, `dw_adi`); depo dışında durur. Kilitli setlerden veri yok.

## 1. Kimlik ve Ghidra

| Alan | Tür | Tanım | Kaynak |
|---|---|---|---|
| `birim` | str | `platform/program` (ölçümün birimi; `ks1_olc.birim_anahtari`) | koşu dizini |
| `program`, `ikili`, `platform` | str | program, ikili adı, `debian` / `mac` | koşu dizini (`ks1_olc.elfleri_topla`) |
| `adres` | int | Ghidra adresi (fonksiyon girişi) | `static/ghidra_functions.json` `address` |
| `adres_hex` | str | `adres`'in onaltılığı (küçük harf, `0x`'siz; `urun_olc` öğe anahtarıyla aynı) | |
| `dosya_adresi` | int | ikilinin kendi sanal adresi = `adres` − ofset. ELF ofseti `ks1_olc.gt_elf` künyesinden (`goruntu_tabani+ghidra_entry`, PIE'de 0x100000); Mac'te 0 | `gt.kunye["ofset"]` |
| `boyut` | int | Ghidra gövde baytı | `ghidra_functions.json` `size` |
| `boyut_dilimi` | str | `<16`, `16-63`, `64-255`, `256-1023`, `1024-4095`, `>=4096` (`BOYUT_DILIMLERI`) | `boyut` |
| `komut_sayisi` | int \| null | temel blokların `instruction_count` toplamı; CFG'de yoksa null | `static/ghidra_cfg.json` |
| `thunk`, `dis` | bool | Ghidra `is_thunk`, `is_external` (içe aktarım kapısı / dış fonksiyon) | `ghidra_functions.json` |
| `ghidra_adi`, `ghidra_kaynagi` | str | Ghidra'nın adı ve kaynağı (`DEFAULT`, `IMPORTED`, `ANALYSIS`) | `ghidra_functions.json` |
| `ghidra_jenerik` | bool | `function_f1.is_generic_name(ghidra_adi, [adres])` (urun_olc'un ad bekleyen ölçütü) | |
| `cpp_disarida` | bool | ikili C++ (`ks1_olc.cpp_ikili_mi`); ölçü dışı (yalnız `debian/zstd/pzstd`) | |

## 2. GT ve nüfus

| Alan | Tür | Tanım | Kaynak |
|---|---|---|---|
| `gt_adlari` | list[str] \| null | o adresteki GT adları (takma adlar; ELF'te GLOBAL önce). Adreste GT fonksiyonu yoksa null | `ks1_olc.gt_elf` / `gt_mac` → `GtBirimi.adlar` |
| `gt_export` | bool \| null | dışa aktarılan GT fonksiyonu (`GtBirimi.export_gt`; Mac'te daima false) | |
| `gt_crt` | bool \| null | ELF: GT adlarının hepsi CRT adı (`function_f1.extract_gt` `crt`); Mac'te null | `function_f1.extract_gt` (ikinci çağrı) |
| `gt_klon` | bool \| null | GT adlarının hepsi derleyici ekli (`ks1_olc.gt_klon_mu`) | |
| `gt_sinif` | str \| null | Mac: GT JSON'unun `sinif` alanı (`program` / `cold` / `outlined`); ELF'te null | `macho_measure.gt_path` |
| `nufusta` | bool | `adres ∈ GtBirimi.nufus` ve ikili C++ değil. Nüfus = ad bekleyen: Ghidra'nın jenerik bıraktığı, thunk olmayan, yürütülebilir bölümde, GT'de adı olan, CRT / dışa aktarılan / klon olmayan | `ks1_olc.gt_elf` / `gt_mac` |

## 3. Ürünün adı ve hüküm

| Alan | Tür | Tanım | Kaynak |
|---|---|---|---|
| `urun_adi` | str \| null | ürünün ad haritasında `FUN_<adres>` anahtarının değeri; boş, anahtarın kendisi ya da jenerik ise null | `reconstructed/src/naming_map.json` `global` (`urun_olc.haritayi_oku`) |
| `urun_olcude` | bool | ad, taban ölçümünün havuzuna giriyor (`urun_olc.degerlendir_elf` kaydı var) | |
| `urun_atlama` | str \| null | haritada anahtar var ama ölçüye girmiyor: `ozdes`, `ghidra_adli`, `jenerik_ad` (urun_olc'un `ATLAMALAR`'ı), `olcu_disi` (C++ ikili); bilgi alanı | |
| `hukum` | `dogru` / `yanlis` / null | `urun_olc.degerlendir_elf` (`ks1_olc.capa_degerlendir`: tam eşitlik, Mach-O'da baştaki `_` soyulur, klon GT'de taban eşitliği; GT'de karşılığı olmayan ad yanlış) | |
| `satir` | `ana` / `klon` / `eslenemedi` / null | aynı kayıttan | |
| `proje` | bool \| null | proje normalleştirmesiyle eşitlik (duyarlılık satırı) | |
| `etiket` | str \| null | köken kaydındaki `label` (`urun_olc.etiket_oku`) | `naming_provenance.json` |
| `kanal` | str \| null | `urun_olc.kanal_oku` (ör. `on_ad:gnulib`, `string_context/oz_ad`, `ks1:func_kalibi`) | |
| `kanal_ana`, `alt_kanal` | str \| null | `kanal`'ın `/`'dan önceki ve sonraki parçası | |
| `kanal_grubu` | `susan` / `kalan` / null | `urun_olc.kanal_grubu` | |
| `guven`, `strateji`, `on_ad_turu` | | köken kaydının `confidence`, `strategy`, `pre_name_kind` alanları (adı ölçüye girmese de doluysa yazılır) | `naming_provenance.json` `global` |

Tutarlılık: `urun_olcude` satırlarının sayısı 1 800, `hukum == "dogru"` 1 681; `nufusta` 21 371, `nufusta ∧ dogru` 1 212; birim ve ikili başına sayılar ve her öğenin `urun_olc.oge_yaz` metni `docs/arge/2026-11-19_birlesik_olcum/urun_olcumu_onarim.json` ile aynı (`olgu_tablosu.py dogrula`).

## 4. Kaynak sınıfı (ELF: dbgsym DWARF'ı)

| Alan | Tür | Tanım |
|---|---|---|
| `dw_eslesme` | `subprogram` / `aranges` / `yok` / null | `subprogram`: `dosya_adresi`'nde `DW_AT_low_pc`'li bir `DW_TAG_subprogram` var. `aranges`: yok, ama `.debug_aranges` adresi bir derleme birimine bağlıyor. `yok`: ikisi de yok |
| `dw_adi` | str \| null | DWARF adı (`dwarf_tip.Cozucu.ad_bul`, köken zinciriyle) |
| `dw_birim` | str \| null | derleme biriminin `DW_AT_name`'i; LTO'da `<artificial>` atlanıp kökenin birimi (`dwarf_tip.Cozucu._fonksiyon_birimi` ile aynı kural; betik eşitliği denetler) |
| `dw_derleme_dizini` | str \| null | o birimin `DW_AT_comp_dir`'i |
| `dw_birim_yolu` | str \| null | `kaynak_yolu(dw_birim, dw_derleme_dizini)`: göreli ad derleme dizinine eklenir, sadeleşir, baştaki `../` atılır; mutlak yol paket-sürüm dizininden (`redis-8.0.2`) sonrasına indirilir |
| `dw_tanim_dosyasi` | str \| null | köken zincirinde `DW_AT_decl_file` taşıyan ilk DIE'nin satır tablosundaki yolu (`dwarf_tip.Cozucu.kaynak_dosyasi`), aynı sadeleştirmeyle. Fonksiyonun gövdesinin yazıldığı dosya: başlıkta tanımlı `static inline` kopyası başlığı gösterir |
| `dw_harici` | bool \| null | köken zincirinde `DW_AT_external` (`dwarf_tip.Cozucu.koken_degeri`) |
| `kaynak_sinifi` | str | aşağıdaki kural |
| `kaynak_alt_sinifi` | str \| null | sınıfı belirleyen dizin (`lib`, `src`, `deps/lua`, `compat`, `lib/compress`, `.` …) ya da `crt` / `dwarf_yok` |
| `kaynak_kaniti` | str | sınıfın geldiği olgu: `tanim_dosyasi`, `derleme_birimi` (tanım dosyası yok), `aranges_birimi`, `aranges_lto`, `gt_crt_adi`, `dwarf_yok`, `dwarf_yok_gt_yok`, `ice_aktarim`, `mac_dwarf_yok`, `gt_yok` |

**Sınıflama kuralı** (`olgu_tablosu._kaynak_alanlari`, `kaynak_sinifla`; sırayla, ilk tutan):

1. `thunk` ya da `dis` → `ice_aktarim` (kodu ikilide değil).
2. Mac → `bilinmiyor` (`mac_dwarf_yok`): Homebrew ikililerinde DWARF da stabs da yok (`nm -ap` ile `SO` / `OSO` 0).
3. DWARF eşleşmesi varsa yol = `dw_tanim_dosyasi` (yoksa `dw_birim_yolu`; `aranges` eşleşmesinde birimin yolu) ve:
   - `aranges` birimi LTO bölümüyse (`<artificial>`) → `bilinmiyor` (kanıt `aranges_lto`): birim adı kodun kaynak dosyasını söylemez;
   - `sistem`: `dwarf_tip.koken_sinifi` `sistem` (`/usr/include/`, `/usr/lib/gcc/` …; glibc'nin satır içi sarmalayıcıları, C++ STL);
   - `derleyici`: yol `csu/`, `sysdeps/`, `crtstuff.c`, `libgcc/` içeriyor (bu sette tutan yok);
   - `gnulib`: yol ikilinin gnulib dizinlerinden birinin altında (`dwarf_tip.gnulib_dizinleri`: içinde en az 2 farklı gnulib işaret modülü derlenmiş dizin; bu sette coreutils'te `lib`, alt dizinleri `lib/malloc`, `lib/unistr` dahil);
   - `ucuncu_taraf`: bir dizin bileşeni `deps`, `contrib`, `third_party`, `thirdparty`, `third-party`, `vendor`, `external`, `extern` (bu sette redis-tools `deps/lua`, `deps/hiredis`, `deps/hdr_histogram`, `deps/linenoise`, `deps/fpconv`; zstd `contrib/pzstd`). Alt sınıf işaretli dizin + bir alt dizin;
   - `uyumluluk`: dizin bileşeni `compat` (tmux `compat/`: OpenBSD libc işlevlerinin kopyaları ve tmux'un taşınabilirlik yamaları; ikisi ayrılmadı);
   - `proje_kitapligi`: yol `lib/` ya da `programs/lib/` ile başlıyor (bu sette yalnız zstd: ikiliye statik bağlı libzstd kaynağı; `programs/lib/` zstd derleme yolunun izi). openssl `apps/lib/` bu öneke uymaz → `program`;
   - `program`: geri kalan (programın kendi kodu).
4. DWARF eşleşmesi yok:
   - GT adları CRT → `derleyici` (alt `crt`, kanıt `gt_crt_adi`);
   - GT'de adı var → `derleyici` (alt `dwarf_yok`, kanıt `dwarf_yok`). Gerekçe: kaynaktan derlenen her nesne dbgsym'de DWARF taşıyor; hiçbir birimin kapsamadığı ama sembolü olan kod araç zincirinin hazır nesnelerinden geliyor. Geliştirme setinde 157 / 157 satırda GT adıyla denetlendi: libgcc yüzer nokta (`__*tf*`), libgcc atomik (`__aarch64_*`), bağlayıcı kaplaması (`e843419@…`);
   - GT'de de yok → `bilinmiyor` (`dwarf_yok_gt_yok`; PLT başı vb., nüfus dışı).
5. GT okunamadıysa → `bilinmiyor` (`gt_yok`; bu koşuda yok).

**Bilinen eksikler:**
- `aranges` eşleşmesi (145 satır): `DW_AT_low_pc`'li somut DIE'si olmayan satır dışı kopyalar (ör. coreutils'te yalnız soyut `DW_AT_inline` DIE'si olan bir fonksiyonun satır dışı kopyası) ve redis-tools'un LTO bölümleri. LTO dışındaki 63 satırda sınıf derleme biriminin yolundan (tanım dosyası okunamadı); LTO bölümündeki 82 satır `bilinmiyor`.
- `uyumluluk` sınıfı kopya ile tmux'un kendi yamasını ayırmaz.
- Mac'te kaynak sınıfı yok (3 142 nüfus satırı `bilinmiyor`).

## 5. Kanıt alanları (`asama: tam`)

Dizgi metni her yerde aynı kuralla: adres ikilide okunabilir bir C dizgisinin başıysa (`olgu_ikili.cstr_oku`: yürütülemez, dosyada verisi olan bölüm; 4 096 bayt içinde NUL; UTF-8; basılabilir ya da `\t\n\r\x1b`) ikiliden okunan metin, değilse Ghidra'nın `value`'su. Metin en çok 200 karakter; kırpıldıysa `k: true`. Dizgi adresleri Ghidra uzayında.

| Alan | Tür | Tanım | Kaynak |
|---|---|---|---|
| `dizgiler` | list[{a, m, k}] | Ghidra'nın bu fonksiyona bağladığı dizgiler (adrese göre sıralı, tekil). `a` adres, `m` metin, `k` kırpıldı | `static/ghidra_xrefs.json` `function_xrefs[adres].strings_used` (= `ghidra_strings.json` `xrefs[].from_func_addr`; 66 983 / 66 983 fonksiyonda aynı küme, `olgu_denetim.py dizgi_kaynagi`) |
| `dizgi_sayisi` | int | `len(dizgiler)` | |
| `cagrilanlar` | list[{a, ad, u}] | çağırdığı fonksiyonlar (adrese göre sıralı, tekil). `a` adres; `ad` çağrılan thunk / dış fonksiyonsa Ghidra adı (içe aktarım adı), değilse null; `u` çağrılanın `urun_adi`'sı | `static/ghidra_call_graph.json` `nodes[adres].callees` |
| `cagiranlar` | list[int] | onu çağıranların adresleri (sıralı, tekil) | aynı, `callers` |
| `cagrilan_sayisi`, `cagiran_sayisi` | int | | |
| `dolayli_cagri` | bool \| null | P-code'da `CALLIND` var; fonksiyonun P-code'u yoksa null (bu koşuda 66 983 / 66 983'ünde var) | `static/ghidra_output/pcode.jsonl` |
| `pcode_var` | bool | fonksiyonun P-code satırı var | |
| `yaprak` | bool | `cagrilan_sayisi == 0` ve `dolayli_cagri` true değil. Çağrı grafiği Ghidra'nınkidir (kuyruk çağrıları Ghidra'nın gördüğü kadar) | |
| `cagri_dizgileri` | list[{c, i, a, m, k, g}] | fonksiyonun içindeki bir `CALL`'a geçen dizgi sabitleri: `c` çağrılan adres, `i` argüman sırası (1 tabanlı), `a` dizgi adresi, `g` adreste Ghidra'nın tanımlı dizgisi var. Argüman ya doğrudan sabit, ya tek tanımı `COPY(sabit)` olan bir ara değer (`unique`); yazmaç ve çok tanımlı ara değer izlenmez | `pcode.jsonl` (`olgu_ikili.cagri_dizgileri`) |

## 6. Kayıt çiftleri (`asama: tam`)

| Alan | Tür | Tanım |
|---|---|---|
| `veri_yerleri` | list[{y, b, got, d}] | (a) fonksiyonun adresinin (tam fonksiyon başı) yazıldığı her veri yuvası: `y` yuvanın Ghidra adresi, `b` bölümü, `got` bölüm GOT mu. `d`: aynı kaydın ± 4 işaretçi genişliğindeki (8 bayt) komşu yuvalarından hedefi dizgi olanlar, `[{o, a, m, k, g}]`: `o` yuva farkı (−4..+4, 0 hariç; + daha yüksek adres), `a` dizgi adresi, `g` Ghidra'nın tanımlı dizgisi. GOT yuvasında `d` boş (GOT bir kayıt değil) |
| `veri_yeri_sayisi` | int | `len(veri_yerleri)` |
| `kayit_cifti_var` | bool | GOT dışı en az bir yerde en az bir komşu dizgi |
| `cagri_ciftleri` | `"desteklenmiyor"` | (b) çağrı yerinde birlikte geçen dizgi sabiti + fonksiyon işaretçisi argümanı. P-code dökümünde fonksiyon işaretçisi argüman olarak hiç yok (DEFTER §0); bu yüzden her satırda `desteklenmiyor`. Dizgi tarafı `cagri_dizgileri`'nde |

**Veri yuvası** (`olgu_ikili`): ELF'te `.rela.dyn` (`.rela.plt` hariç) kayıtları: `R_AARCH64_RELATIVE` (hedef = ekleme değeri) ve tanımlı dinamik sembole giden `ABS64` / `GLOB_DAT` (hedef = sembol + ekleme); bu sette 117 ELF'in hepsi `ET_DYN`, sembollü kayıt 0. Yeniden konumlanmayan ELF'te (`ET_EXEC`) yazılabilir veri bölümlerinin hizalı sözcükleri (bu sette yok). Mach-O'da `xcrun dyld_info -fixups` rebase satırları (`macho_f1.read_fixups` / `parse_dyld_fixups`; zincirli fixup'lar dahil; Mac'te koşunun kendi `raw/<ad>` kopyası, sha256'sı `target_info.json` ile denetlenir). İkili dosya okunur, Ghidra çalıştırılmaz.

**Bağımsız denetim** (`scripts/arge/olgu/olgu_denetim.py kayit_capraz`): komşu dizgi bir Ghidra dizgisinin başıysa ve Ghidra o dizgiye en az bir xref kaydetmişse, xref'lerden biri bizim yuvamızdır: Debian 2 528 / 2 564, Mac 1 586 / 1 586. 682 Debian hedefinde Ghidra dizgiyi tanımlamış ama hiç xref kaydetmemiş; 1 061 hedef Ghidra dizgisi değil (577'si 4 karakterden kısa).

**Bilinen eksikler:**
- Komşu dizgi kuralı yapı sınırını bilmez: ± 4 yuva bir önceki ya da sonraki kaydın alanlarına taşabilir (tmux'ta `exec` işaretçisinin +1 komşusu bir sonraki komut kaydının adı). Yorum hatların işi; tablo yalnız yuva farkını (`o`) verir.
- Ghidra'nın tanımlamadığı kısa hedefler (`g: false`, özellikle 1–3 karakter) bayt tablosu olabilir; ayıklamak için `g` ve uzunluk kullanılabilir.
- `cagri_dizgileri` yalnız `unique` ara değerleri izler; yazmaç üzerinden geçen sabit sayılmaz.
