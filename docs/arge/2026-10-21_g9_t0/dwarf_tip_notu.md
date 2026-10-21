# G9 / T0a: dwz farkında DWARF tip okuyucu — sonuç notu

- **Tarih:** 2026-10-21
- **Plan:** v2.2 §4 T0 (a); §1 "DWARF tip gerçeği dwz'li" satırı; §5 K1.
- **Araç:** `scripts/measurement/dwarf_tip.py` (betik sha256 `c20bcb49fd0363bd…`; bu dizindeki bütün JSON'lar bu sürümle üretildi).
- **Testler:** `tests/test_dwarf_tip.py` (41 test). **Mutantlar:** `scripts/measurement/mutation_specs_dwarf_tip.json` (8/8 öldü).
- **Kapsam:** yalnız geliştirme seti (coreutils 9.4 ve Debian 13'teki 8 program). Doğrulama setine, ağa ve Ghidra'ya dokunulmadı.

## 1. Yöntem

- Ana `.debug` dosyası ve `.gnu_debugaltlink`'in gösterdiği dwz ek dosyası pyelftools ile **iki ayrı ELF/DWARF** olarak açılır. pyelftools'un kendi ek dosya yolu kapalıdır (`follow_links=False`). DIE'ler betiğin kendi kayıtlarına aktarılır ve her DIE (dosya rolü, ofset) çiftiyle anılır: `ana:0x1c5f7`, `ek:0x365`.
- **Ek dosyanın bulunması.** `.gnu_debugaltlink` yolu (Debian ve Ubuntu'da mutlak: `/usr/lib/debug/.dwz/aarch64-linux-gnu/<paket>.debug`) ana dosyanın her atasının altında aranır. Göreli yol ana dosyanın dizinine göre çözülür. Bulunamazsa `.build-id` ve `.dwz/` taranır. Aday ancak build-id'si bağlantıdakiyle aynıysa kabul edilir.
- **Başvurular.** Başvuruların hepsi betiğin kendisinde çözülür:
  - birim içi biçimler (`ref1/2/4/8/udata`) birim başlığına göredir;
  - `ref_addr` aynı dosyaya gider;
  - `DW_FORM_GNU_ref_alt` ve `ref_sup4/8` ek dosyanın `.debug_info` ofsetine gider;
  - `DW_FORM_GNU_strp_alt` ve `strp_sup` ek dosyanın `.debug_str` ofsetine gider.
  Ek dosyanın içinden ek dosyaya başvuru hata sayılır.
- **Birimler.** Ana dosyanın bütün birimleri, `compile_unit` ve dwz'nin dosya içi `partial_unit`'leri dahil, ikiliye aittir. Ek dosya bütün paketin ortak deposudur. Ondan yalnız `DW_TAG_imported_unit` ile (geçişli) erişilen kısmi birimler bu ikiliye sayılır. Örnek: Debian 9.4 `pinky`, 879 ek birimden 169'una erişiyor. Bildirimden tanıma (`tanimlar`) giderken yalnız erişilen birimlere bakılır (mutant `t0a_ithal_kapanisi_yok`).
- **Fonksiyon.** `DW_AT_low_pc` taşıyan her `subprogram`. Ad, tip ve öznitelikler `abstract_origin`/`specification` zinciriyle bulunur; zincir dosyalar arasında da yürür.
- **Parametre sırası.**
  - `sira` bildirimdeki yerdir (1 tabanlı, Ghidra `param_1` sayımı). `somut_sira` somut DIE'deki yerdir.
  - `tekrar`: aynı bildirim parametresine ikinci kez bağlanan DIE (§4).
  - `yer`: DWARF konum bilgisinin biçimi (`loclist`, `exprloc`, `const_value` ya da boş).
- **Tip.** `ham` zincir (etiket, konum, ad) ve `kanonik` biçim:
  - typedef soyulur;
  - `const`, `volatile`, `restrict`, `_Atomic` atılır ve `niteleyiciler`'e yazılır;
  - işaretçi derinliği tutulur;
  - `struct foo`; anonimse `struct <anon@ek:0x48>`;
  - fonksiyon tipi `fonk(<dönüş>; <parametreler>)`, dizi `<eleman>[N]`.

  Sınıflar: `yapi*`, `void*`, `char*` (1 baytlık char ailesi), `skaler`, `skaler*`, `fonk*`, `yapi_degerle`, `ptr**`, `diger`. `union X *` de `yapi*` sayılır.
- **Klon bayrağı.** İki kaynak ayrı alanlarda tutulur:
  - `klon.sonekler`: `.symtab`'tan `.isra`, `.constprop`, `.part`, `.cold`;
  - `klon.abstract_origin` ve kökenin `DW_AT_inline` değeri (`origin_inline`).

  `bayrak` ikisinin birleşimidir. Dışarıda bırakma kararı K1 ön kaydındadır.
- **Yapı tablosu (`yapilar`).** Parametre köklerindeki yapı ve birlikler, ad taşıyanların erişilen birimlerdeki bütün tam tanımları ve üyeler (ad, ofset, kanonik tip, sınıf).

## 2. Çözülen tip payı

"Çözülen" şu demek: tipin tutulduğu DIE bulundu, zincirdeki her başvuru doğru dosyada bir DIE başına düştü, gereken adlar okundu ve zincir bir uca vardı.

**coreutils 9.4 (`~/karadul_olcum/downloads`):**

| Kopya | `.debug` | Fonksiyon | Parametre | Çözülen | Tipi ek dosyada | Bütün `formal_parameter` DIE'leri | DIE'nin kendi `DW_AT_type`'ı `ref_alt` |
|---|---|---|---|---|---|---|---|
| Debian 9.4-3 | 106 + 1 dwz | 12 164 | 28 655 | 28 655 (%100) | %78,3 | 127 574 / 127 574 | %81,5 |
| Ubuntu 9.4-3ubuntu6 | 106 + 1 dwz | 3 527 | 8 780 | 8 780 (%100) | %77,6 | 119 341 / 119 341 | %82,7 |

- dwz ek dosyalarının kendi `formal_parameter` DIE'leri: Debian 2 779 / 2 779, Ubuntu 4 155 / 4 155.
- Son sütun plan v2.2 §1'deki ölçünün tanımıdır. Plan 9 dosyada %81,7, Onuncu Adam başka 9 dosyada %75,5 buldu; 106 dosyada %81,5 çıkıyor.

**Debian 13 geliştirme seti (`~/karadul_olcum/downloads/debian13`, `dogrulama_seti_onkayit.md` §8.1 sürümleri):**

| Program | Sürüm | `.debug` | dwz | Fonksiyon | Parametre | Çözülen | Tipi ek dosyada | Bütün `formal_parameter` |
|---|---|---|---|---|---|---|---|---|
| tmux | 3.5a-3 | 1 | yok | 1 911 | 4 211 | %100 | — | 18 408 / 18 408 |
| htop | 3.4.1-5 | 1 | yok | 608 | 1 112 | %100 | — | 5 549 / 5 549 |
| tree | 2.2.1-1 | 1 | yok | 110 | 208 | %100 | — | 1 274 / 1 274 |
| zstd | 1.5.7+dfsg-1 | 2 (zstd, pzstd) | var | 1 907 | 6 514 | %100 | %51,2 | 118 536 / 118 536 |
| sqlite3 | 3.46.1-7+deb13u2 | 1 | yok | 418 | 993 | %100 | — | 5 269 / 5 269 |
| openssl | 3.5.7-1~deb13u2 | 1 | yok | 596 | 1 522 | %100 | — | 9 129 / 9 129 |
| redis-tools | 5:8.0.2-3+deb13u2 | 3 (4 ELF) | var | 5 794 | 11 578 | %100 | %51,4 | 71 867 / 71 867 |
| coreutils | 9.7-3 | 106 | var | 13 432 | 31 825 | %100 | %79,4 | 132 277 / 132 277 |
| **Toplam** | | 116 | | 24 776 | 57 963 | **%100** | %59,6 | 362 309 / 362 309 |

- dwz ek dosyalarının kendileri: zstd 2 409 / 2 409, redis-tools 16 821 / 16 821, coreutils 2 907 / 2 907.
- redis-check-aof ile redis-check-rdb aynı ikili, build-id'leri aynı. Künyede `ayni_build_id_ikililer` alanında görünüyor.
- **T0 ölçüsü (≥ %99) 8 programın hepsinde tutuyor.** Çözülemeyen parametre yok, bu yüzden neden listesi boş. Nedenler (`NEDENLER`) sahte DIE testleriyle sınandı.

## 3. Bağımsız çapraz denetim (Apple `/usr/bin/dwarfdump`)

**Yöntem.**
- Tohum: `karadul-g9-t0a-capraz-denetim-2026-10-21` (SHA-256'nın ilk 16 hex basamağı).
- Evren dosya, adres ve konuma göre sıralanır, sonra 50 parametre çekilir.
- Her parametre `dwarfdump -v -F --debug-info=<ofset>` ile baştan yürünür; bu yol pyelftools'u ve betiğin çözücüsünü kullanmaz. Karşılaştırılanlar:
  - ad ve `strp_alt` ofseti (dizgi, ek dosyanın `--debug-str` dökümünden);
  - tipi tutan DIE ve biçimi;
  - tip zincirinin her adımı (etiket, konum, ad);
  - basit uçlarda kanonik biçim.

**Sonuç:**

| Koşu | Evren | Tutarlı | Kanonik karşılaştırılan |
|---|---|---|---|
| Debian 9.4-3, tipi ek dosyada | 22 439 | **50 / 50** | 50 |
| Ubuntu 9.4-3ubuntu6, tipi ek dosyada | 6 811 | **50 / 50** | 50 |
| Debian 13 (zstd, redis-tools, coreutils), tipi ek dosyada | 34 553 | **50 / 50** | 50 |
| Debian 13 (8 program), tipi ana dosyada (dwz'siz yol dahil) | 23 410 | **50 / 50** | 49 |

- Ters sınama: bir JSON'da zincir ofsetleri ve adlar bilerek bozuldu; denetim 10 örneğin 10'unu tutarsız buldu.
- Kanıt: `capraz_*.json`.

## 4. Klonlar, sıra ve tekrar DIE'ler

- **LTO.**
  - Ubuntu 9.4'te somut gövdelerin %100'ü `abstract_origin`'li, ama hiçbirinin kökeni satır içi değil (`origin_inline` boş: erken hata ayıklama DIE'si). Debian 13 redis'te bu oranlar %81,7 ve %2,7; redis de LTO'lu.
  - Debian'ın LTO'suz programlarında `abstract_origin`'li gövdelerin hepsinin kökeni satır içi (ör. coreutils 9.7: 3 236 / 3 236).
  - **`abstract_origin` tek başına klon ölçütü olamaz.**
- **Sonekli klonlar:** Debian 9.4'te %1,9, Ubuntu'da %28,9, Debian 13 toplamında %3,0.
- **Sırası değişenler:** Debian 9.4'te 47, Ubuntu'da 430, Debian 13'te 165 fonksiyonda `sira ≠ somut_sira`. coreutils ve Ubuntu'da hepsi sonekli. Somut DIE parametreleri yeniden sıralıyor.
- **Tekrar DIE'ler.**
  - Ubuntu'da 228 constprop klonunda 382 tekrar DIE var: aynı bildirim parametresine ikinci bir `formal_parameter`. Örnek: `version_etc.constprop.0`'da `package` için ikinci DIE `DW_OP_addr 0x3ec8, DW_OP_stack_value`, yani sabit değer betimi.
  - Debian 13'te 6 tekrar var (htop 1, redis 5).
  - redis'teki 4 vaka sonek taşımıyor (`incrRefCount`, `getPositiveLongFromObjectOrReply`, `notifyKeyspaceEvent`, `vectorSetWaitAllBackgroundClients`). Sonek kuralı bunları kaçırır.
  - **`tekrar` ABI yargısı değildir.** redis `incrRefCount`'ta konumsuz DIE önce gelir, W0'daki gerçek parametre sonra. Tip için zararsızdır (aynı köken, aynı tip). T0b hizalaması konumu (`yer` ve konum ifadesi) okumalıdır.
- **Düşen parametreler:** Debian 13'te 20 fonksiyon, hepsi pzstd'de (C++). İki tür:
  - 15 yıkıcı: bildirimdeki yapay `__in_chrg` parametresi somut DIE'de yok;
  - 5 şablon üye fonksiyonu (`emplace_back<…>`, `_M_realloc_append<…>`): bildirimdeki adsız ikinci parametre somut DIE'de `formal_parameter` olarak yok.

## 5. K1 ön kaydı için notlar ("aynı tip" uygulanırken görülenler)

1. **Ad kimliği farklı yapıları birleştirebilir.**
   - redis-tools'ta aynı ikilide `struct dict`, `dictEntry`, `dictIterator`, `dictType` (ve `redis-check-aof`'ta `struct iovec`) iki farklı yerleşimle tanımlı: redis'in kendi `dict`'i 56 bayt, gömülü hiredis'inki 48 bayt. Üç ikilide toplam 13 ad.
   - Öbür programlarda 0.
   - Öneri: kimlik = etiket adı + yapısal yerleşim imzası (`yerlesim_imzasi`), ya da aynı adlı farklı tanımlar ayrı sayılır.
2. **Ofset kimliği anonim tipleri böler.** Aynı anonim yapının ayrı konumlu kopyaları:
   - Debian 13'te 31 grup (zstd 15, coreutils 12, redis 4);
   - coreutils 9.4'te 14 grup.

   Anonim tiplerde yapısal imza ya da typedef adı (zincirde `typedefler`) kullanılmalı. Adlı tiplerin kopyaları (Debian 13'te 330) ad kimliğinde zararsız.
3. **Bildirim kökler çok.** `yapi*` parametrelerinin kökü yalnız bildirim (`struct X;`) olabiliyor:
   - openssl 341 / 438 (OpenSSL tipleri CLI'da opak);
   - tmux 261 / 2 220, redis 338 / 4 799, sqlite3 132 / 398.

   Ad kimliği bunları birleştirir. Ama yerleşim yoksa "kalıtım ailesi" kuralı uygulanamaz. Tanım arandığında yalnız erişilen birimlere bakılmalı: ek dosya başka ikililerin aynı adlı tiplerini taşıyor.
4. **`yapi*` içinde birlik var:** tmux 2, zstd 26, redis 21 parametre. Ön kayıt birlikleri karar ölçüsüne alıp almadığını yazmalı.
5. **Klon dışlama.**
   - Sonek + `tekrar` + `sira ≠ somut_sira` birlikte kullanılmalı. `abstract_origin` LTO'da her şeyi işaretler.
   - `origin_inline` dolu olan `abstract_origin`'li gövdeler bildirim imzasını korur (LTO'suz Debian); dışlanmaları gerekmez.
   - Apple clang'ın soneksiz klonları ayrıca denetlenecek (plan T0 (c), Mac).
6. **C++.** pzstd C++ (55 `class` kökü, `this` parametreleri, yıkıcılarda yapay parametre). C K1'inden program olarak çıkarılmalı. redis'te az miktar C++ var; araç birim dilini henüz yazmıyor.
7. **Niteleyici etkisi büyük.** Debian 13'te 16 682 parametrede `const` atıldı, 164'te `restrict`, 2'de `volatile`. `_Atomic` hiçbir sette yok.
8. **`void *` joker.** Debian 13 parametrelerinin %8,2'si `void*`.
9. **Nüfus.** Debian 13'teki `yapi*` parametre sayıları:

   | Program | `yapi*` parametre |
   |---|---|
   | redis | 4 799 |
   | coreutils | 4 005 |
   | tmux | 2 220 |
   | zstd | 1 537 |
   | htop | 600 |
   | openssl | 438 |
   | sqlite3 | 398 |
   | tree | 30 |

   K1 çiftler üzerinden ölçüldüğü için büyük programlar baskın çıkar. Program başına makro ortalama ya da örneklem üst sınırı ön kayda yazılmalı.
10. **Adres.** `adres` DWARF `low_pc`'dir (bağlama zamanı adresi). Ghidra'nın PIE taban adresiyle eşlemek T0b'nin işi.

## 6. Bilinen sınırlar

- Ek dosya yalnız `.gnu_debugaltlink`'ten bulunur. DWARF 5 `.debug_sup` okunmaz; o biçimler ancak `--ek` ile çözülür.
- `DW_FORM_ref_sig8` (tip birimleri) desteklenmiyor. Verilerde görülmedi.
- Yalnız `DW_AT_ranges` taşıyan gövdeler çıkarılmaz. Bütün setlerde 0.
- Bit alanı üyelerinde `ofset` boş; `bit_ofseti` (`DW_AT_data_bit_offset`) ve `bit_boyutu` dolu.
- Konum ifadeleri çözülmez; yalnız biçim (`yer`) yazılır.
- Çapraz denetimde kanonik biçim yalnız basit uçlarda (temel, yapı, birlik, enum, void) karşılaştırılır. Fonksiyon ve dizi uçlarında yalnız zincir karşılaştırılır.
- coreutils 9.4-3, geliştirme setinin sürümü değil. Setin sürümü 9.7-3; o da ölçüldü (§2).
- Mac tarafı (dSYM, Apple clang) bu adımda yok.

## 7. Yeniden üretme

İkili başına JSON'lar depoya konmadı (coreutils 9.4 için 36 MB). Hepsi yaklaşık 1 dakikada yeniden üretilir:

```sh
T=scripts/measurement/dwarf_tip.py; O=~/karadul_olcum/downloads; D=$O/debian13; C=<çıktı dizini>
python3 -I $T toplu $O/x_coreutils-dbgsym_9.4-3_arm64/data/usr/lib/debug --ikili-kok $O/x_coreutils_9.4-3_arm64/data -o $C/debian-9.4-3
python3 -I $T toplu $O/x_coreutils-dbgsym_9.4-3ubuntu6_arm64/data/usr/lib/debug --ikili-kok $O/x_coreutils_9.4-3ubuntu6_arm64/data -o $C/ubuntu-9.4-3ubuntu6
python3 -I $T toplu "$D/x_tmux-dbgsym_3.5a-3_arm64/usr/lib/debug" --ikili-kok "$D/x_tmux_3.5a-3_arm64" -o $C/debian13/tmux   # öbür 7 paket aynı kalıpla
python3 -I $T ozet $C/debian-9.4-3 $C/ubuntu-9.4-3ubuntu6 --json ozet_coreutils_9.4.json --yalniz-gruplar
python3 -I $T capraz $C/debian-9.4-3 -o capraz_debian_9.4-3.json            # --evren ana: tipi ana dosyada olanlar
python3 -I $T cikar <dwz ek dosyası> -o <json>                                # ek dosyanın kendi DIE'leri
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_dwarf_tip.json
```

**Bu dizindeki kanıtlar:**
- `ozet_coreutils_9.4.json`, `ozet_debian13_gelistirme.json`, `ozet_dwz_ek_dosyalari.json`: grup ve toplam blokları.
- `capraz_debian_9.4-3.json`, `capraz_ubuntu_9.4-3ubuntu6.json`, `capraz_debian13_ek.json`, `capraz_debian13_ana.json`.
