# N4 ön kaydı (TASLAK): fiil — fonksiyonun ne yaptığını davranışından çıkarmak

- **Tarih:** 2026-11-10.
- **Durum:** Taslak. Yalnız belge; kural kodu yok. GT dosyalarına ve etiket verisine bakılmadan yazıldı; yalnız toplu sonuç tabloları okundu (§8.3). **[S…]** maddeleri karara bağlanmadan ve §6.10'daki araçlar yazılmadan kesinleşmez.
- **Plan:**
  - v2.2 §3 N4 (`2026-10-21_plan_v2_2.md:73`), §10 sıra değişikliği (`:205-218`), takvim G13-G14 (`:140-141`), Kapı 1 (`:72`);
  - v2.1 3.4 (`2026-10-19_plan_v2_1.md:97`): davranış özetlerinden fiil, TR-7 ve TR-10.
- **Dayanak:**
  - GT'siz ön sayım: `on_sayim.py` → `on_sayim.json` (bu dizin);
  - KS-1: ön kayıt taslağı `2026-10-21_g11_n1/ks1_onkayit_taslak.md` (10d69cd), kesin ön kayıt `ks1_onkayit.md` (a22d833) ve ölçüm sonucu `ks1_olcum.md` (5d0b528). Son ikisi bu taslak yazılırken depoya girdi; ölçüm sonucu en sonda okundu;
  - N0b: `2026-10-21_g10_n0b/alt_kanal_onkayit.md`, `kesinlik_tablosu.md`;
  - N2 taslağı: `2026-10-21_n2_onkayit_taslak.md`;
  - rubrik ve protokol: `etiket_rehberi.md` (sürüm 2), `etiket_protokolu_v2.md`.
- **Bu belgede olmayan:** kural kodu, API → fiil tablosunun satırları, ölçüm, etiket. KS-1 ve susturmanın bağlama tasarımı ayrı belgededir (`docs/arge/2026-11-10_n1_adim3/baglama_tasarimi_taslak.md`; bu taslak yazılırken oluştu, sonunda okundu). Burada yalnız N4'e özgü gereksinimler var (§7).
- **Sayılar:** her sayı ya `on_sayim.json`'dan ya da yanında yazan dosya:satırdan gelir. **[hesap]**, o kaynaklardan türetilmiş aritmetiktir.

**Dosyalar:**

| Dosya | İçerik | sha256 (ilk 16) |
|---|---|---|
| `docs/arge/2026-11-10_n4/fiil_onkayit_taslak.md` | bu belge | — |
| `docs/arge/2026-11-10_n4/on_sayim.py` | GT'siz ön sayım; yalnız `static/` okur, ad yazmaz | `ad6c0e6ec4934954` |
| `docs/arge/2026-11-10_n4/on_sayim.json` | sayım çıktısı: 10 birim, 119 ELF; fiil sözlüğü v0 künyede | `b0bfc0665b2cefb1` |

Yeniden üretim: `python3 -I -B docs/arge/2026-11-10_n4/on_sayim.py --mac-kosu workspaces/olcum_mac/runs/ol7-a-9a36142 --debian-kosu ~/karadul_olcum/n1_debian13 --cikti docs/arge/2026-11-10_n4/on_sayim.json`

**Çalışma kuralları (yaratıcılık protokolü): uygulandı mı?**

| Kural | Uygulandı mı |
|---|---|
| 1. Denetlenebilirlik | Evet. Her aile ve koruma bir sayaca, bir mekanik ölçüye (M1, §6.3) ya da kör etikete (M3, §6.5) bağlı. Sınanamayan iki öneri "yön gösterici" diye işaretli (§5.3 AD4, AD5) |
| 2. Uzlaşıyı bilerek kır | Evet. Aykırı öncül §5.1-§5.2'de işlendi; altı farklı aday ve öldürme ölçütleri §5.3'te. Farklı model ailesi karıştırılmadı (bu görevde başka model çağırmak yasaktı) |
| 3. Tek hatta kal, olumsuzları taşı | Evet. Sekiz olumsuz sonucun her biri için "N4 bunu nasıl yinelemez" §4.5'te |
| 4. Seçimi model yapmaz | Evet. 29 **[S…]** maddesi, öneri ve gerekçeyle §8.4'te. Berke'ye gitmesi gerekenler işaretli |

## 1. Amaç ve hipotezler

**Amaç.** KS-1'in çapalayamadığı isim bekleyenlere, davranıştan hesaplanan bir fiille ad ya da ipucu vermek. Ölçü planın yazdığıdır: fiil doğruluğu ve rubrikteki "yanlış fiil" oranı (`2026-10-21_plan_v2_2.md:73`).

**Neden şimdi.** N1 ve susturmadan sonra beklenen yakın kapsam tmux'ta ≈ %4,7, htop'ta ≈ %0'dır; Kapı 1 fiil katmanı yazılmadan ölçülürse büyük olasılıkla düşer (`2026-10-21_plan_v2_2.md:207-210`).

**Tanımlar:**
- **Fiil sınıfı:** aynı işi anlatan fiil belirteçlerinin kümesi (`free`, `destroy`, `release` → `destroy`). Sözlük §3.1'de.
- **Karşıt fiil:** rubriğin "yanlış fiil" saydığı çiftler: getter/setter, tahsis/serbest bırakma, hazırla/uygula ve ters eylem (`etiket_rehberi.md:35, 41-46`). Sözlükte 10 çift.
- **Aile:** aynı tür kanıttan fiil çıkaran kurallar (§4.2). Köken kaydında aile adıyla yazılır.
- **Ad:** `naming_map`'e giren tanımlayıcı. **İpucu:** ad değil, yorum satırı; `FUN_` kalır (`2026-10-19_plan_v2_1.md:99`).

**Hipotezler:**

| # | Hipotez | Ölçü | Tutmazsa |
|---|---|---|---|
| H-N4-0 (taban) | Var olan `rules.py` (tarif v0) kör protokol v2'de hiç ölçülmedi (§4.1). N4'ün adları aynı fonksiyonlarda v0'ınkilerden daha az yanlıştır | M2 ve M3'te sistem `T0`; eşli fark (§6.5) | D9 |
| H-N4-1 (kesinlik) | Ürüne açılan her ailede taze kör etiketle yanlış oranı (yanlış fiil dahil) "zayıf" değildir: Wilson alt sınırı ≤ %10 | M3, `karar()` (§6.6) | D6, D7 |
| H-N4-2 (yanlış fiil, mekanik) | İkilide adı görünen fonksiyonlarda ailenin karşıt fiil oranı "zayıf" değildir (eşik %5) ve aynı sınıf oranı ≥ %50'dir | M1 (§6.3) | D2, D3 |
| H-N4-3 (kapsam) | Fiil kökenli adlar Çerçeve A'da yakın kapsamı artırır | M3: fiil kökenli yakın adların Çerçeve A'daki payı (§6.5) | Eşik yok; Kapı 1 okur |
| H-N4-4 (aykırı öncül) | F-API adlarında "yan ayrıntı ya da yanlış" payı, iç çağrı sayısı ≥ 4 olan fonksiyonlarda ≤ 3 olanlardan yüksektir | M2 ve M3'te iki tabakanın `yalniz_alan` + `yanlis` oranları | D10 |
| H-N4-5 (biçim) | Genel nesneli adlar (`free_object`, `get_field`) kör rubrikte yakın sayılır: yakın oranı ≥ %50 | M2'de ad biçimi B4 tabakası (§3.2) | D5 |

Eşikler (%10, %5, %50) **[S17, S20]** maddeleridir. %10 Kapı 1'in sınırıdır (`2026-10-21_plan_v2_2.md:72`); öbür ikisi bu taslağın önerisidir.

## 2. Girdi ve davranış özeti

### 2.1 Bir fonksiyon için toplanan kanıt

Girdi yalnız Karadul'un `static/` çıktısıdır. Ghidra'nın decompile algoritmasına dokunulmaz; kanıt, dosya sonundaki gömülü disassembly'den ve xrefs'ten hesaplanır. Yalnız AArch64 (Mach-O ve ELF).

| Kanıt | Kaynak | Bugün (`tarif/evidence.py`) | N4'te |
|---|---|---|---|
| Doğrudan kütüphane çağrıları | `ghidra_xrefs.json` `functions_called`; `ghidra_functions.json` (thunk, ad) | Var: `apis` (`evidence.py:72-77`). Tekil hedef kümesi; çağrı yeri sayısı ve sırası yok | Aynı küme; adlar FK0 ile normalize; jenerik thunk hedefine çözülür |
| Çağrı yeri: sıra, çokluk | gömülü disassembly: `bl`, gövde dışı `b`, `blr` | Yok | `kesin.py` `CallSite` (`:343-352`), adres sırasıyla (`:651`) |
| Argüman kullanımı | disassembly, fonksiyon içi ileri veri akışı | Yalnız C metni regex'i (`rules.py:257-269`) | Çağrı anında x0-x7 ve taze yığın yuvaları: parametre ve adres sabiti (`kesin.py:147-149, :565-569`). Eklenecek değer türleri: çağrı sonucu, tam sayı sabiti, parametreden yüklenen alan |
| Dönüş değeri | disassembly: `ret` anında x0 | Yok | Bütün dönüşlerde ortak x0 (`exit_regs`, `kesin.py:517, :598-602`); türü: parametre, çağrı sonucu, yüklenen alan, 0/1 |
| Hata yolu | disassembly: temel bloklar | Yok. Yalnız log iletisinde sözcük listesi (`rules.py:153-156`) | Blok grafı (`kesin.py:523-552`). Hata yolu: yalnız dönmeyen bir çağrıya ulaşan bloklar |
| Bellek etkisi | disassembly: saklama ve yükleme komutları | Yok | Taban yazmacın kökeni: parametre, çağrı sonucu ya da global. Özet: neye yazıyor, neyi döndürüyor |
| Geri çağrı kaydı | disassembly: argümanda bir iç fonksiyonun adresi | C metni regex'i (`evidence.py:20-22, :81-86`) | Adres sabiti bir iç fonksiyon başıysa kayıt; rol API sözleşmesinden (`rules.py:213-248`) |
| Dizgiler | `ghidra_xrefs.json` `strings_used` | Var (`evidence.py:94`); log iletisinden ad (`rules.py:194-210`) | Fiil kaynağı değil (§4.5). Üç kullanım: API'nin sabit argümanı konumunda nesne; hata ve günlük çağrısını tanıma (FK3, FK4); ipucu |
| Çağıranlar | `ghidra_xrefs.json` `called_by` | Var (`evidence.py:93`) | İlk sürümde kullanılmaz (AD4) |
| p-code | `ghidra_output/pcode.jsonl` | Kullanılmıyor | Kullanılmaz: dışa aktarımda SSA kimliği yok (`2026-10-21_plan_v2_2.md:43`); T2 bitince yeniden bakılır |

**[S1] Veri akışı zemini: disassembly ve `kesin.py`'deki akışın uzantısı** (öneri). Gerekçe: akış yazılı ve mutant kanıtlı; Darwin'de değişken argümanları C metni göstermiyor (`ks1_onkayit_taslak.md:52`); SSA'lı p-code G14-G15'te geliyor (`2026-10-21_plan_v2_2.md:141-142`), N4'ten sonra.

### 2.2 GT'siz ön sayım

**Nüfus (vekil):** thunk ve dış olmayan, adı `FUN_<onaltılık>` olan Ghidra fonksiyonu. Gerçek "isim bekleyen" nüfusu GT ister; farkları §8.1 madde 1'de.

**Sınıflar** (çağrı kaynağı: xrefs ∪ disassembly'deki `bl` ve fonksiyon başına giden gövde dışı `b`; jenerik adlı thunk hedefine çözülür):
- **K:** en az bir kütüphane fonksiyonu çağırıyor. Derleyicinin eklediği çağrılar (`__stack_chk_fail`, `___chkstk_darwin`) ve CRT çağrıları sayılmaz.
- **I:** kütüphane çağırmıyor, en az bir iç fonksiyon çağırıyor.
- **Y:** hiçbir fonksiyonu doğrudan çağırmıyor (yaprak).

| Birim | ELF | İç fonksiyon | İsim bekleyen | K: kütüphane çağırıyor | I: yalnız iç çağrı | Y: yaprak |
|---|---|---|---|---|---|---|
| `mac/tmux` | 1 | 2 588 | 2 587 | 951 (%36,8) | 1 220 (%47,2) | 416 (%16,1) |
| `mac/htop` | 1 | 597 | 597 | 230 (%38,5) | 265 (%44,4) | 102 (%17,1) |
| `debian/tmux` | 1 | 1 920 | 1 916 | 766 (%40,0) | 850 (%44,4) | 300 (%15,7) |
| `debian/htop` | 1 | 609 | 239 | 103 (%43,1) | 107 (%44,8) | 29 (%12,1) |
| `debian/coreutils` | 106 | 14 120 | 13 485 | 8 092 (%60,0) | 3 193 (%23,7) | 2 200 (%16,3) |
| `debian/openssl` | 1 | 592 | 588 | 505 (%85,9) | 30 (%5,1) | 53 (%9,0) |
| `debian/redis-tools` | 4 | 10 531 | 2 103 | 727 (%34,6) | 1 115 (%53,0) | 261 (%12,4) |
| `debian/sqlite3` | 1 | 429 | 425 | 297 (%69,9) | 30 (%7,1) | 98 (%23,1) |
| `debian/tree` | 1 | 119 | 115 | 93 (%80,9) | 5 (%4,3) | 17 (%14,8) |
| `debian/zstd` | 2 | 1 931 | 1 908 | 934 (%49,0) | 490 (%25,7) | 484 (%25,4) |
| **toplam** | 119 | 33 436 | 23 963 | 12 698 (%53,0) | 7 305 (%30,5) | 3 960 (%16,5) |

Denetim: "İç fonksiyon" sütunu KS-1 sayımıyla on birimde de aynı (`ks1_onkayit.md:467-476`). Çağıranı olmayan isim bekleyen sayısı tmux'ta 787, htop'ta 216 çıktı; plan v2 de aynı sayıları yazıyor (`2026-10-17_plan_v2.md:54`).

**K sınıfının içi.** Kütüphane adları üç aileye ayrıldı (listeler `on_sayim.json` künyesinde; ön sayıma özgüdür, ürün sözlüğü değildir): dönmeyen ve ileti (`exit`, `abort`, `fprintf`, `strerror`, errno erişimi …), bellek ve dizgi temeli (`malloc`, `free`, `memcpy`, `strlen`, `strcmp` …), geri kalanı "ayırt edici". Yüzdeler isim bekleyen nüfusa orandır.

| Birim | Ayırt edici API | … iç çağrı ≤ 3 | … iç çağrı ≥ 4 | Yalnız bellek/dizgi | Yalnız hata/ileti | Karışım | Dönmeyen çağrı var | errno okuyor |
|---|---|---|---|---|---|---|---|---|
| `mac/tmux` | 405 (%15,7) | 229 (%8,9) | 176 (%6,8) | 489 (%18,9) | 49 (%1,9) | 8 | 28 | 69 |
| `mac/htop` | 114 (%19,1) | 82 (%13,7) | 32 (%5,4) | 113 (%18,9) | 3 (%0,5) | 0 | 7 | 12 |
| `debian/tmux` | 318 (%16,6) | 177 (%9,2) | 141 (%7,4) | 404 (%21,1) | 32 (%1,7) | 12 | 12 | 70 |
| `debian/htop` | 62 (%25,9) | 32 (%13,4) | 30 (%12,6) | 41 (%17,2) | 0 (%0,0) | 0 | 3 | 3 |
| `debian/coreutils` | 3 760 (%27,9) | 3 354 (%24,9) | 406 (%3,0) | 2 088 (%15,5) | 1 747 (%13,0) | 497 | 2 350 | 2 006 |
| `debian/openssl` | 488 (%83,0) | 407 (%69,2) | 81 (%13,8) | 17 (%2,9) | 0 (%0,0) | 0 | 10 | 18 |
| `debian/redis-tools` | 448 (%21,3) | 301 (%14,3) | 147 (%7,0) | 177 (%8,4) | 57 (%2,7) | 45 | 113 | 119 |
| `debian/sqlite3` | 268 (%63,1) | 241 (%56,7) | 27 (%6,4) | 12 (%2,8) | 17 (%4,0) | 0 | 7 | 2 |
| `debian/tree` | 42 (%36,5) | 32 (%27,8) | 10 (%8,7) | 11 (%9,6) | 35 (%30,4) | 5 | 11 | 0 |
| `debian/zstd` | 498 (%26,1) | 369 (%19,3) | 129 (%6,8) | 248 (%13,0) | 161 (%8,4) | 27 | 462 | 29 |

**I ve Y sınıflarının içi.** "Zincir k": iç çağrı grafında, doğrudan kütüphane çağıran bir fonksiyona en kısa uzaklık. "Yazar": yığın dışı bir adrese saklama komutu var (kaba işaret). "`cset w0`": dönüş yazmacına koşul sonucu yazılıyor (kaba yüklem işareti).

| Birim | I | zincir 1 | zincir 2 | zincir 3+ | zincir yok | tek iç hedefli | Y | yazmaz | yazar | ≤ 8 komut | `cset w0` | çağıranı yok |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `mac/tmux` | 1 220 | 707 | 339 | 86 | 88 | 488 | 416 | 254 | 162 | 192 | 21 | 121 |
| `mac/htop` | 265 | 169 | 40 | 7 | 49 | 100 | 102 | 50 | 52 | 49 | 2 | 27 |
| `debian/tmux` | 850 | 510 | 221 | 72 | 47 | 365 | 300 | 196 | 104 | 121 | 16 | 68 |
| `debian/htop` | 107 | 64 | 21 | 1 | 21 | 33 | 29 | 15 | 14 | 13 | 1 | 23 |
| `debian/coreutils` | 3 193 | 3 057 | 19 | 2 | 115 | 2 346 | 2 200 | 1 397 | 803 | 1 190 | 142 | 1 326 |
| `debian/openssl` | 30 | 26 | 2 | 0 | 2 | 25 | 53 | 44 | 9 | 40 | 2 | 27 |
| `debian/redis-tools` | 1 115 | 642 | 229 | 162 | 82 | 332 | 261 | 135 | 126 | 91 | 27 | 114 |
| `debian/sqlite3` | 30 | 26 | 0 | 0 | 4 | 21 | 98 | 60 | 38 | 55 | 7 | 82 |
| `debian/tree` | 5 | 5 | 0 | 0 | 0 | 4 | 17 | 13 | 4 | 8 | 1 | 9 |
| `debian/zstd` | 490 | 236 | 47 | 25 | 182 | 274 | 484 | 219 | 265 | 199 | 55 | 205 |

**Kanıt paketinin göstergeleri** (isim bekleyenler içinde fonksiyon sayısı):

| Birim | Kuyruk çağrılı | … xrefs'te eksik | Aynı kütüphane hedefine ≥ 2 çağrı yeri | `_chk` ya da `isoc` adlı import çağıran | Jenerik thunk çağıran | Aynı import adı iki adreste | Dolaylı çağrı (`blr`) | Çağıranı yok | Dizgisi var | Tek kütüphane hedefli |
|---|---|---|---|---|---|---|---|---|---|---|
| `mac/tmux` | 698 | 0 | 431 | 31 | 23 | 1 | 66 (%2,6) | 787 (%30,4) | 1 084 (%41,9) | 113 |
| `mac/htop` | 173 | 0 | 83 | 2 | 5 | 0 | 52 (%8,7) | 216 (%36,2) | 137 (%22,9) | 46 |
| `debian/tmux` | 586 | 0 | 395 | 37 | 1 | 0 | 52 (%2,7) | 630 (%32,9) | 638 (%33,3) | 81 |
| `debian/htop` | 90 | 0 | 49 | 21 | 0 | 0 | 23 (%9,6) | 186 (%77,8) | 81 (%33,9) | 11 |
| `debian/coreutils` | 2 864 | 0 | 2 250 | 1 086 | 106 | 2 | 508 (%3,8) | 6 853 (%50,8) | 1 927 (%14,3) | 1 035 |
| `debian/openssl` | 135 | 0 | 322 | 20 | 2 | 0 | 8 (%1,4) | 243 (%41,3) | 363 (%61,7) | 41 |
| `debian/redis-tools` | 493 | 0 | 261 | 152 | 0 | 0 | 242 (%11,5) | 937 (%44,6) | 863 (%41,0) | 93 |
| `debian/sqlite3` | 104 | 0 | 156 | 21 | 0 | 0 | 34 (%8,0) | 227 (%53,4) | 163 (%38,4) | 64 |
| `debian/tree` | 32 | 0 | 60 | 65 | 0 | 0 | 2 (%1,7) | 51 (%44,3) | 52 (%45,2) | 39 |
| `debian/zstd` | 337 | 0 | 537 | 376 | 24 | 2 | 106 (%5,6) | 692 (%36,3) | 635 (%33,3) | 206 |

**API'nin ayırt ediciliği.** "df": aynı ELF'te o kütüphane fonksiyonunu çağıran isim bekleyen sayısı. "Küme": fonksiyonun çağırdığı kütüphane adlarının kümesi.

| Birim | K | en seçici import df = 1 | 2-5 | 6-20 | ≥ 21 | tek import, küme paylaşılan | çok import, küme tekil | çok import, küme paylaşılan | tek import, küme tekil |
|---|---|---|---|---|---|---|---|---|---|
| `mac/tmux` | 951 | 52 | 118 | 236 | 545 (%57,3) | 535 | 239 | 152 | 25 |
| `mac/htop` | 230 | 48 | 63 | 50 | 69 (%30,0) | 108 | 83 | 14 | 25 |
| `debian/tmux` | 766 | 49 | 102 | 200 | 415 (%54,2) | 411 | 209 | 125 | 21 |
| `debian/htop` | 103 | 20 | 28 | 33 | 22 (%21,4) | 51 | 38 | 7 | 7 |
| `debian/coreutils` | 8 092 | 1 873 | 2 733 | 2 721 | 765 (%9,5) | 3 265 | 3 383 | 602 | 842 |
| `debian/openssl` | 505 | 231 | 161 | 54 | 59 (%11,7) | 39 | 386 | 49 | 31 |
| `debian/redis-tools` | 727 | 173 | 217 | 226 | 111 (%15,3) | 242 | 298 | 87 | 100 |
| `debian/sqlite3` | 297 | 34 | 73 | 139 | 51 (%17,2) | 78 | 172 | 31 | 16 |
| `debian/tree` | 93 | 14 | 27 | 21 | 31 (%33,3) | 44 | 36 | 7 | 6 |
| `debian/zstd` | 934 | 44 | 66 | 126 | 698 (%74,7) | 357 | 163 | 402 | 12 |

### 2.3 Ön sayımdan çıkanlar

1. **Doğrudan kütüphane çağrısı program türüne bağlı.** Toplamda %53,0. Etiket hattının okuyabildiği iki programda düşük: Mac tmux %36,8, Mac htop %38,5. Kütüphane istemcisi programlarda yüksek: openssl %85,9, tree %80,9, sqlite3 %69,9. (10-15 ölçümü tmux ve htop için %41-43 demişti, `2026-10-15_isimlendirme_plani.md:45`. O ölçümün tanımı belgede yazmıyor; burada derleyici ekleri kütüphane çağrısı sayılmadı.)
2. **Ayırt edici bir API çağıranlar azınlıkta.** Mac tmux'ta %15,7, Mac htop'ta %19,1. İç çağrısı en çok 3 olanlar (API'nin "asıl iş" olmasının bugünkü vekili, `rules.py:134-135, :272-277`) %8,9 ve %13,7.
3. **Yalnız bellek ve dizgi temeli çağıranlar ayırt edici API çağıranlar kadar çok.** Mac tmux %18,9, Mac htop %18,9. Bu fonksiyonlarda fiil çağrının adından değil, verinin akışından gelir (`free` parametreye mi uygulanıyor, `malloc` sonucu döndürülüyor mu).
4. **Nüfusun %30,5'i yalnız iç fonksiyon çağırıyor;** Mac tmux'ta %47,2, Mac htop'ta %44,4. Çağrı adından fiil bu fonksiyonlara ulaşmaz. Mac tmux'ta 488'i tek bir iç fonksiyon çağırıyor.
5. **Yapraklar %16,5.** Mac tmux'ta 416 yaprağın 254'ü yığın dışına yazmıyor, 192'si en çok 8 komut.
6. **xrefs kuyruk çağrılarını taşıyor;** eksik kalan fonksiyon 0 (5 512 kuyruk çağrılı fonksiyonda). Taşımadığı: çağrı yeri çokluğu ve sırası. Aynı kütüphane hedefini birden çok yerden çağıran 4 544 fonksiyon var.
7. **Kütüphane adları platforma göre değişiyor.** Debian'da `_chk` ya da `isoc` biçimli ad çağıran 1 778 fonksiyon var (tree'de 115'in 65'i); Mac'te 33. Debian coreutils'te en sık çağrılanlar errno erişimi (2 006), `abort` (1 827), `dcgettext` (1 290).
8. **htop türünde çağrı grafı kör.** Debian htop'ta isim bekleyenlerin %77,8'inin doğrudan çağıranı yok; Mac htop'ta %36,2. Dolaylı çağrı yapanlar %9,6 ve %8,7.
9. **coreutils örnek düzeyinde şişkin.** 13 485 isim bekleyenin komut dizisi 1 260 tekil değere iniyor (kaba ölçü: yalnız komut adlarının dizisi).

## 3. Fiil sözlüğü ve ad biçimi

### 3.1 Fiil sözlüğü v0

30 sınıf, 180 belirteç; her belirteç tek sınıfta (betikte `assert` ile denetlenir). 10 karşıt çift. Tek kaynak `on_sayim.py`'deki `FIIL_SOZLUGU` ve `KARSITLAR`'dır; `on_sayim.json` künyesi aynısını taşır. Son iki sütun, ikilide adı görünen (export) iç fonksiyonların adlarındaki sınıf sayısıdır (tekil ad; yalnız tek sınıf taşıyan adlar; §6.3).

| Sınıf (kanonik fiil) | Belirteçler | Karşıt sınıf | debian/htop | debian/redis-tools |
|---|---|---|---|---|
| `get` | get, fetch, peek, query | `set` | 23 | 319 |
| `set` | set, put, assign, update, store, modify, change | `get` | 52 | 178 |
| `is` | is, has, can, should, check, test, validate, verify, exists, contains | — | 8 | 147 |
| `create` | create, new, alloc, allocate, make, build, construct, dup, clone | `destroy` | 46 | 159 |
| `destroy` | destroy, free, delete, release, dealloc, dispose, unref | `create` | 27 | 175 |
| `init` | init, initialize, setup, prepare, configure | `fini`, `run` | 12 | 80 |
| `fini` | fini, finish, cleanup, teardown, deinit, uninit, shutdown, terminate | `init` | 4 | 9 |
| `reset` | reset, clear, zero, empty, wipe, flush | — | 4 | 57 |
| `add` | add, insert, push, append, prepend, enqueue, attach, register, link | `remove` | 16 | 241 |
| `remove` | remove, erase, pop, dequeue, detach, unregister, unlink, drop, discard | `add` | 5 | 57 |
| `find` | find, search, lookup, locate, match | — | 4 | 49 |
| `compare` | compare, cmp, equal, equals, diff | — | 7 | 42 |
| `copy` | copy, cpy, move, swap | — | 5 | 11 |
| `open` | open, connect, accept, listen, bind | `close` | 0 | 35 |
| `close` | close, disconnect | `open` | 0 | 19 |
| `read` | read, load, recv, receive, input | `write` | 7 | 86 |
| `write` | write, save, send, emit, output, dump | `read` | 9 | 114 |
| `print` | print, show, display, draw, render, paint, format, log, report, warn | — | 16 | 61 |
| `parse` | parse, decode, tokenize, scan, unpack, decompress, unescape | `encode` | 2 | 53 |
| `encode` | encode, serialize, pack, compress, escape | `parse` | 0 | 29 |
| `lock` | lock, acquire | `unlock` | 0 | 7 |
| `unlock` | unlock | `lock` | 0 | 2 |
| `start` | start, begin, spawn, launch, fork, enable, resume | `stop` | 3 | 34 |
| `stop` | stop, end, kill, cancel, abort, disable, suspend, pause, exit, quit | `start` | 1 | 46 |
| `run` | run, exec, execute, apply, perform | `init` | 3 | 11 |
| `compute` | compute, calc, calculate, count, sum, hash, measure | — | 4 | 72 |
| `sort` | sort | — | 2 | 2 |
| `wait` | wait, sleep, poll | — | 0 | 10 |
| `resize` | resize, grow, shrink, expand, extend, reserve, truncate | — | 3 | 22 |
| `handle` (genel) | handle, process, dispatch, do, on, callback, cb, handler, helper | — | 0 | 0 |

- **Sözlüğün iki işi var:** ürünün yazacağı kanonik fiiller (her sınıfın ilk belirteci) ve M1'de gerçek adlardan başvuru fiili çıkarmak.
- **Köken:** sınıflar rubriğin yanlış fiil aileleri (`etiket_rehberi.md:41-46`), plan v2.1 3.4'teki fiiller (`2026-10-19_plan_v2_1.md:97`) ve tarif kanıtları kataloğundan (`2026-10-15_makale/derleyici_sentez.md:188, :190-191`) yazıldı. Export adlarına bakılarak değiştirilmedi (§8.3).
- **[S3] Sözlük v0 bu hâliyle, sha256 ile dondurulur** (öneri). Gerekçe: M1'in başvurusu sözlüktür; sonradan değişirse M1 sayıları kıyaslanamaz.
- **[S4] Genel fiiller ad olmaz** (öneri: `handle` sınıfı yalnız ipucu). Gerekçe: rubrikte genel fiil `yalniz_alan`'dır (`etiket_rehberi.md:46, :51`); spekülatif rol adları Temmuz'da kapatıldı (§4.5).
- capa'nın ad alanları sözlüğe tohum olabilirdi (`2026-10-21_literatur/yontem_taramasi.md:19`). Kural lisansı doğrulanmadı (`:165`); kopyalanmadı.

### 3.2 Nesne: nereden gelir, nereden gelmez

| Biçim | Nesne kaynağı | Örnek (değerlendirme kümesinden değil) | İzinli mi | Dayanak |
|---|---|---|---|---|
| B1 | API'nin kendisi: sözleşmesi nesneyi sabitler | `list_directory`, `spawn_process` | Evet | API sözleşmesi; bugün `COMBOS` adları (`rules.py:61-131`) |
| B2 | API'nin nesne argümanındaki sabit | `get_env_home` | Evet; argüman konumu veri akışıyla doğrulanırsa | Bugün C metni regex'i (`rules.py:257-269`) |
| B3 | Modül öneki: iki KS-1 çapası arasındaki adres komşuluğu | `cache_free_object` | **[S6]** | `module.py`; 10-15 ölçümü: önek isimsizlerin %22'sinde, %96'sı doğru (`module.py:8`; protokol v1) |
| B4 | Yok: genel nesne (`object`, `field`, `value`, `buffer`) | `free_object`, `get_field` | **[S7]** | — |
| B5 | Rol adı (nesne yok) | `compare_for_sort`, `handle_signal` | Evet | API sözleşmesi (`rules.py:213-248`); rubrik kural 7 (`etiket_rehberi.md:49-52`) |
| — | Tip kümesi (alıcı tip sınıfı) | — | **Hayır** | G7: kâhin çapalarla bile nesne öneki %4,3 öneri, %36,7 kesinlik, %1,6 doğru (`2026-10-19_g7_alici_tip/rapor.md:80`). N5 ≥ %90 göstermeden tip girdisi yok (`2026-10-21_plan_v2_2.md:18, :53`) |
| — | Gövdedeki serbest dizgi | — | **Hayır** | N0b: `string_context` tek kanal okumasında yanlış %52,1 (`kesinlik_tablosu.md:25`) |
| — | Çağıranın ya da çağrılanın adı | — | **Hayır** (N6'nın işi) | Yayılım yalnız kesin çapalardan (`2026-10-21_plan_v2_2.md:75`) |

- **[S5] Nesne kaynakları yukarıdaki kapalı listedir** (öneri). Gerekçe: tip kümesi ve serbest dizgi ölçülmüş olumsuz sonuçlardır.
- **[S6] Modül öneki (B3) N4 ile birlikte açılsın mı?** (öneri: evet, ayrı ölçüm tabakası olarak; Berke'ye gider). Gerekçe: `module.py` hazır (84 satır) ve rubrikte modül + asıl iş rolü `dogru_tarif`'tir (`etiket_rehberi.md:50`). Bedeli: plan modülü N6'da sayıyor; modül yanlışsa ad `yanlis` olur (`etiket_rehberi.md:52`). Önek KS-1 çapalarına dayanır; ölçümde yalnız `func_kalibi` satırı `kesin` çıktı ve o satırın çapaları yalnız tmux ile openssl'de var (`ks1_olcum.md:11-14, :31, :36, :43`). htop türünde çapa olmadığı için etkisi yok (`ks1_onkayit.md:436`).
- **[S7] Genel nesneli adlar (B4) ad mı, ipucu mu?** (öneri: ölçüm yapısında ad adayı; ürün kararı D5 ve D6'dan; Berke'ye gider). Gerekçe: htop türünde modül ve sabit argüman yok; B4 ad sayılmazsa F-ETKİ orada yalnız yorum üretir. Rubrik bu biçimi açıkça karara bağlamıyor.
- **[S8] Rubrik sürüm 2 aynen kalır;** B4 için ek kural yazılmaz (öneri). Gerekçe: sürüm değişince etiketler birleştirilmiyor (emsal: sürüm 1 → 2, `etiket_rehberi.md:11`); G4, N0b ve N2 sürüm 2 ile ölçüldü. Alternatif: sürüm 3'te açık kural (Berke).

### 3.3 Ad biçimi

- Kalıp: `[modül_]fiil_nesne`; küçük harf, snake_case, ASCII. Rol adları B5 biçimindedir.
- Tek belirteçli ad yok. Gerekçe: rubrik kural 6 (`etiket_rehberi.md:48`); N0b'de `tek_sozcuk` %95,6 yanlış (`kesinlik_tablosu.md:17`).
- Ad, bir kütüphane fonksiyonunun adına eşit olamaz (rubrik kural 5, `etiket_rehberi.md:47`).
- Ada adres, `FUN_` parçası ya da sayaç gömülmez (`c_namer.py:1966-1974`).
- **[S9] "tarif" öneki** (öneri: önek yok; Berke'ye gider). Statü (`tarif`) köken ve güven kanalında taşınır ve fonksiyonun üstüne bir yorum satırı yazılır. Gerekçe: önek her çağrı yerini uzatır; kör pakette adayın hangi sistemden geldiğini ele verir, atılması için normalize gösterimin değişmesi gerekir (`etiket_protokolu_v2.md:383`). Alternatif: kısa bir önek; adın özgün olmadığı her başvuruda görünür.
- **[S10] Çakışma eki fiil adımında verilir:** aynı ad birden çok fonksiyona düşerse adres sırasıyla `_2`, `_3` … eklenir (öneri). Gerekçe: fiil adları ön ad kanalından girecek (§7); o kanal aynı adı ikinci anahtarda eklemeden, sessizce düşürüyor (`c_namer.py:1922`); ek yalnız c_namer'ın kendi adaylarına veriliyor (`:1988-1995`). Rubrik eki yok sayar (`etiket_rehberi.md:39`).

### 3.4 Köken ve güven etiketi

Her fiil adı ve ipucu şu bilgiyi taşır: strateji (`tarif_fiil`), aile, kural (kimlik ve sürüm), fiil sınıfı, biçim (B1-B5), nesne kaynağı, kanıt (çağrı yeri adresleri, kütüphane adları, yol türü), korumalar (geçilen ve eleyen), güven etiketi, güven. Köken şeması sürüm 1'de kalır; bunlar eklenen alanlardır (bağlama tasarımı `2026-11-10_n1_adim3/baglama_tasarimi_taslak.md:339-341`).

- **Güven etiketi:** `olculmedi` → ad verilmez (N0b ile aynı: ölçülmemiş kanal ad vermez, `alt_kanal_onkayit.md:245`); `dogrulanmadi`; `dogrulandi` (`alt_kanal_onkayit.md:234-239`).
- **[S11] Sayısal güven** = ailenin M3'te ölçülen 1 − yanlış oranı, nokta tahmini (öneri). Gerekçe: güven ölçülmüş isabetten türetilir (`derleyici_sentez.md:225`); kural başına elle puan (bugünkü 4-10 puanlar, `rules.py:61-131`) ölçülmedi.

## 4. Kurallar

### 4.1 Var olan `rules.py`: ne var, ne ölçüldü, ne ölçülmedi

Paket 2026-10-15'te depoya girdi (ff8abc6) ve hatta bağlı değil (`scripts/measurement/tarif_olc.py:2`); `run_tarif`'i yalnız iki ölçüm betiği (`tarif_olc.py`, `llm_pilot.py`) ve testler çağırıyor. O günden beri `rules.py` değişmedi. 10 test var (`tests/test_tarif.py`).

| Bileşen | Ne var | Ölçülen | Protokol | Bugünkü durum |
|---|---|---|---|---|
| Geri çağrı rolü | `callback_role` (`rules.py:213-248`): `qsort`, `bsearch`, `sigaction`, `atexit`, `pthread_create`, libevent; bağlam öneki Y1 (`propagate.py:47-55`) | %83 "amacı doğru anlatan" (`rules.py:13`; `propagate.py:4-5`) | v1 | v2'de ölçülmedi |
| Log iletisinden ad | `find_logger`, `name_from_log` (`rules.py:176-210`) | %49 (`rules.py:13`); tmux örnekleminde %56 yakın (`2026-10-15_isimlendirme_plani.md:47`) | v1 | v2'de ölçülmedi; dizgi kanallarının 9'u N0b'de zayıf çıktı (`kesinlik_tablosu.md:69`) |
| API birliktelikleri | `COMBOS` 68 satır, `GENERIC_APIS` 67 ad, eşik 5,0 (`rules.py:41-50, :61-132`); nesne için sabit argüman (`:138-146, :257-269`) | "~%50" (`rules.py:13-14`) | v1 | v2'de ölçülmedi. 3 satır eşiğin altında (puan 4; `:127-130`), hiç ad vermez |
| Tek-API sarmalayıcı | `free_structure`, `duplicate_string` (`rules.py:318-324`) | Ayrı ölçüm yok | — | `free_structure` kuralı fiilen ölü (E1) |
| Yayılım | Y2 sarmalayıcı, Y4 yardımcı ipucu (`propagate.py:58-70`) | Y3 fiil ailesi %0 çıktı, kaldırıldı (`propagate.py:11`) | v1 | N4'te kapalı **[S24]** |
| Modül | `module.py` | Kapsam %22, doğruluk %96; önekli log adları %32, öneksiz %49 (`module.py:8, :12`) | v1 | B3 için aday **[S6]** |
| Toplu | tarif v0: htop 43 ad, 21 yakın, 2 yanlış; tmux 171 tarif adı (129 kesinle 300), ≈ 30 yanlış (`2026-10-15_isimlendirme_plani.md:40, :42`) | — | v1 | Karar dayanağı olamaz |

**Neden karar dayanağı olamaz:** 15 Ekim paketi kör değildi ve yanlış fiilli adları `yalniz_alan` sayıyordu (`2026-10-17_plan_v2.md:59-62`; `etiket_protokolu_v2.md:14-17`). Sürüm 1 etiketleri sürüm 2 sayılarıyla birleştirilmez (`etiket_rehberi.md:11`). Yani "yanlış fiil" oranı v0 için hiç ölçülmedi.

**[S2] v0 önce ölçülür** (öneri: `rules.py` değiştirilmeden, M2 ve M3'te `T0` sistemi olarak). Gerekçe: taban olmadan N4'ün korumalarının işe yarayıp yaramadığı söylenemez; ölçülmeyen kural ürüne girmez (`2026-10-17_plan_v2.md:66`).

**Kanıt paketinin eksikleri** (koddan ve ön sayımdan):

| # | Eksik | Yer | Etkisi | Ön sayım |
|---|---|---|---|---|
| E1 | Çağrı sayısı hep 1 | `headless.py:1430` çağrılanları tekilleştiriyor; `evidence.py:91` | `free_structure` kuralı `free` sayısı ≥ 2 ister (`rules.py:321`); bu ancak aynı ad iki adreste durursa olur | 23 963 fonksiyonun 5'inde |
| E2 | Jenerik thunk API sayılıyor | `evidence.py:59-63, :74` | `thunk_FUN_…` bir kütüphane adı gibi `apis`'e girer; iç çağrı sayısı eksilir | 161 fonksiyon |
| E3 | Ad normalizasyonu yalnız baştaki alt çizgi | `evidence.py:28-30` | `__fprintf_chk` → `fprintf_chk`; `COMBOS` Darwin adlarıyla yazılı (`rules.py:57, :103, :106`). Darwin `___error` (errno) ile glibc `error` aynı ada iner | `_chk`/`isoc` adı çağıran: Debian 1 778, Mac 33 |
| E4 | Çağrı yeri bilgisi yok | xrefs yalnız hedef kümesi | Sıra, çokluk, hangi yol (ana, hata), hangi argüman bilinmiyor | 4 544 fonksiyonda aynı hedefe ≥ 2 çağrı yeri |
| E5 | Argümanlar C metninden | `evidence.py:20-22`; `rules.py:227-247, :264` | Darwin'de değişken argümanlar C'de görünmüyor (`ks1_onkayit_taslak.md:52`) | Ölçülmedi |
| E6 | Günlük fonksiyonu tanımı dar | `rules.py:160, :176-186`: `FUN_x("…%…")` biçimi, en az 20 farklı dizgi | İlk argümanı biçim olmayan günlükler (ör. `fprintf(stderr, …)` sarmalayıcıları) görünmez | Ölçülmedi |

### 4.2 Önerilen kural aileleri

| Aile | Kanıt | Üretebildiği fiil sınıfları | Biçim | Erişebildiği nüfus (ön sayım, üst sınır) | İlk sürüm |
|---|---|---|---|---|---|
| **F-ROL** | Geri çağrı kaydı: bir kütüphane çağrısının argümanında bu fonksiyonun adresi | Rol adları: karşılaştırıcı, sinyal işleyici, iş parçacığı girişi, çıkış temizliği, olay işleyici | B5 (+B3) | Sayılmadı: kayıt tespiti veri akışı ister | Evet |
| **F-API** | Ana yolda, fonksiyonun parametresine ya da dönüşüne veri akışıyla bağlı kütüphane çağrısı | `open`, `close`, `read`, `write`, `print`, `parse`, `encode`, `find`, `sort`, `lock`, `unlock`, `start`, `stop`, `wait` | B1, B2 (+B3) | Ayırt edici API çağıran: 6 403 (%26,7); Mac tmux %15,7, Mac htop %19,1. İç çağrı ≤ 3 ile: %8,9 ve %13,7 | Evet |
| **F-ETKİ** | Yan etki ve dönüş özeti: neye yazıyor, neyi döndürüyor, neyi ayırıp neyi bırakıyor | `create`, `destroy`, `init`, `get`, `set`, `is`, `copy`, `compare` | B4 (+B3) | Yaprak: 3 960 (%16,5); yalnız bellek/dizgi çağıran: 3 600 (%15,0) | Evet: `create`, `destroy`. `get`, `set`, `is`, `init`, `copy`, `compare` ölçüm adayı |
| F-SIRA | Çağrı sırası imzası | F-API ve F-ETKİ'nin sıralı biçimleri | — | — | Aday (AD3) |
| F-KULLANIM | Çağıranların dönüş değerini ve argümanları kullanışı | `create`, `is`, `get` | B4 | Çağıranı olanlar | Aday (AD4) |
| F-TÜME | Export adlarından öğrenilen imza → fiil tablosu | Hepsi | — | — | Aday (AD5) |

**F-API'nin tablosu.** Satır: (normalize kütüphane adı, fiil sınıfı, nesne, hangi argüman nesne, hangi argüman ya da dönüş fonksiyona bağlanmalı). Dayanağı API'nin belgelenmiş sözleşmesidir; geliştirme setinden yalnız "bu ad setimizde var mı" bilgisi alınır (`on_sayim.json` → `import.en_sik`). Satırlar bu belgede yazılmadı.

**F-ETKİ'nin kuralları** (taslak; hepsi "bütün yollarda" koşuluyla, tutucu):

| Fiil | Koşul |
|---|---|
| `destroy` | Ana yolda bırakma çağrısının argümanı fonksiyonun bir parametresi (ya da o parametreden yüklenen alanlar ve sonunda kendisi) |
| `create` | Ayırıcı çağrının sonucu bütün başarılı dönüşlerde döndürülüyor ve dönüşten önce o sonucun alanlarına yazılıyor |
| `init` | Ayırma yok; parametrenin birden çok ayrı ofsetine sabit ya da parametre yazılıyor |
| `get` | Çağrı yok; yığın dışına yazma yok; bütün dönüşler aynı parametrenin aynı ofsetinden yüklenen değer |
| `set` | Çağrı yok; bir parametre başka bir parametrenin sabit ofsetine yazılıyor; dönüş yok ya da ilk parametre |
| `is` | Yığın dışına yazma yok; bütün dönüşler 0 ya da 1 |
| `copy`, `compare` | İki parametre; biri okunup öbürüne yazılıyor (`copy`); yazma yok, dönüş işaretli üç değerli (`compare`) |

- "Bırakma" ve "ayırıcı" yalnız kütüphane fonksiyonu değildir: FK1'in tanıdığı kütüphane sarmalayıcıları da sayılır.
- **[S12] İlk sürümün aileleri:** F-ROL, F-API, F-ETKİ (öneri). F-SIRA, F-KULLANIM ve F-TÜME aday olarak ertelenir. Gerekçe: iki gün (`2026-10-21_plan_v2_2.md:140-141`); üç aile üç ayrı kanıt türünü kapsıyor.

### 4.3 Korumalar (FK0-FK8)

KS-1'deki K0-K5'in (`ks1_onkayit_taslak.md:175-182`) karşılığıdır. Hepsi tutucudur: koruma değerlendirilemiyorsa ad yazılmaz. Her koruma kendi eleme sayacını tutar; sayaçlar köken kaydına ve ölçüm çıktısına yazılır.

| # | Koruma | Tanım (mekanik) | Önlediği hata | KS-1'deki karşılığı |
|---|---|---|---|---|
| FK0 | Platform ve ad | Kütüphane adı normalize edilir: baştaki alt çizgiler, `$…` eki, `_chk` eki, `isoc99_`/`isoc23_` öneki, büyük dosya eki (`64`). errno erişimi platforma göre ayrı tanınır. Çağrı kuralı bilinmiyorsa ad yok | E3: kuralın sessizce kaçırması ya da yanlış ada bağlanması | Çağrı kuralı seçimi (`kesin.py:288-297`) |
| FK1 | Sarmalayıcı | Gövdenin çağrıları tek bir hedefe iniyor ve parametreler o hedefe değişmeden gidiyor. Hedef kütüphaneyse fiil F-API'den gelir, ayrı satırda ölçülür. Hedef iç fonksiyonsa ad yok | Sarmalayıcıya hedefin, çağırana sarmalayıcının fiilini yazmak | K2 tek sahip |
| FK2 | Çok davranış | Ana yol kanıtlarından birden çok fiil sınıfı çıkıyorsa: karşıtsa ad yok; karşıt değilse önceden yazılmış bir birliktelik yoksa ad yok. İç çağrı sayısı sınırı aşan fonksiyona F-API ad vermez | Aracın fiilini amaç sanmak | K3 gövdede tek ad |
| FK3 | Hata yolu | Yalnız dönmeyen bir çağrıya ulaşan bloklardaki çağrılar ve errno okuması kanıt değildir. Bütün yolları dönmeyen fonksiyon F-API'den ad almaz | Hata iletisini ana iş sanmak | K1 saf başvuru |
| FK4 | Günlük ve ileti | Günlük fonksiyonuna ve ileti ailesine yapılan çağrılar kanıt değildir; sonucu yalnız onlara giden çağrılar da (ör. zaman damgası) | Günlük çağrısını ana iş sanmak | K1 saf başvuru |
| FK5 | Teklik | Aynı kanıt imzası (normalize kütüphane kümesi ve sabit argümanlar) aynı ikilide k ya da daha çok fonksiyonda varsa birliktelik kuralı ad vermez | Inline edilmiş yardımcının kanıtını sahiplenmek | K0 başlık dosyası, K4 ad tekliği |
| FK6 | Zaten adlı | KS-1 çapalı, başka bir ön adı olan ya da Ghidra'nın adlandırdığı fonksiyona fiil adı yazılmaz; aday yalnız M1'e girer | Kesin adı ezmek | K5 zaten adlı |
| FK7 | Ad denetimi | §3.3'teki biçim koşulları: kütüphane adına eşit değil, tek belirteçli değil, adres taşımıyor | Rubrik kural 5 ve 6 | K4 (Ghidra adıyla çakışma) |
| FK8 | Genel fiil | `handle` sınıfından ad çıkmaz; ipucu olur | Rubrik kural 4 ve 7; spekülatif rol adı | — |

- **[S13] FK2 büyük gövde sınırı:** iç çağrı sayısı ≤ 3 (öneri; bugünkü `MAX_INTERNAL_FOR_ANY_API`, `rules.py:135`). Gerekçe: ölçülmüş bir değer yok; H-N4-4 bu sınırı sınar. Pay ölçütü (`MIN_API_SHARE`, `rules.py:134`) kaldırılır: sayılar tekil hedef sayısıdır (E1).
- **[S14] FK5 eşiği k = 3** (öneri). Gerekçe: iki fonksiyon bir çağıran-çağrılan çifti olabilir; üç ve üstü ortak bir yardımcıyı gösterir. Çok importlu kümesi paylaşılan fonksiyon sayısı: Mac tmux 152, Debian zstd 402 (§2.2).
- **[S15] Aileler arası çelişki:** karşıt sınıflar → ad yok. Farklı ama karşıt olmayan sınıflar → sabit öncelik F-ROL > F-API > F-ETKİ; öbür aday köken kaydına yazılır (öneri). Gerekçe: rol ve API sözleşmesi, yan etki sezgisinden daha dar tanımlı. Alternatif: her farkta sus.
- **[S29] FK0 normalizasyon listesi** yukarıdaki beş kuraldır (öneri). Gerekçe: Debian birimlerinde en sık görülen biçimler; liste kapalıdır, yeni biçim yeni sürüm ister.

### 4.4 Kural yazım disiplini

1. Kurallar yalnız geliştirme setinde ve yalnız `static/` çıktısına bakılarak yazılır. Doğrulama ve test setleri açılmaz.
2. Her kural ve tablo satırı künye taşır: kimlik, sürüm, dayanak (API belgesi ya da geliştirme birimi), bir örnek çağrı yeri adresi (`2026-10-17_plan_v2.md:82-83`; `derleyici_sentez.md:225`).
3. Hiçbir kural belirli bir program fonksiyonunun adına ya da ad listesine başvurmaz. Kurallar iç fonksiyon adlarını hiç okumaz (N4'te yayılım yok).
4. Sözlük, API tablosu ve kurallar M3 paketleri üretilmeden önce sha256 ile dondurulur.
5. Her kural ve koruma için test; her test mutant koda karşı sınanır (`2026-10-17_plan_v2.md:90`).
6. Belirlenimcilik: çıktı adrese göre sıralı; girdi sırasından ve `PYTHONHASHSEED`'den bağımsız; testle kilitli.
7. **`kesin.py`'ye dokunulmaz.** KS-1 ölçümü dosyanın sha256'sını denetliyor; değişirse ölçmüyor (`ks1_onkayit.md:384`). Veri akışı uzantıları yeni bir dosyada yazılır ve `kesin.py`'yi içe aktarır.

### 4.5 Önceki olumsuz sonuçlar: N4 bunları nasıl yinelemez

| Olumsuz sonuç | Kaynak | N4'te |
|---|---|---|
| Tip kümesinden nesne adı %1,6 doğru | `2026-10-19_g7_alici_tip/rapor.md:80`; `2026-10-21_plan_v2_2.md:38` | Nesne tip kümesinden alınmaz (§3.2). N5 ≥ %90 göstermeden tip girdisi yok |
| `api_call`, `call_graph`, `callee_based` 2026-07-12'den beri fonksiyon adına kapalı: `manage_memory`, `calls_X`, `helper_<adres>` | `c_namer.py:1966-1980` | Ada adres gömülmez; `calls_` biçimi yok; tek bir genel API (`malloc`, `free`) çağrısı tek başına ad vermez; fiil veri akışı bağıyla gelir (F-API, F-ETKİ). c_namer'daki strateji yeniden açılmaz |
| `string_context` alt kanallarının 9'u zayıf; tek kanal okumasında yanlış %52,1 | `kesinlik_tablosu.md:13-25, :69` | Dizgi fiil kaynağı değildir. `name_from_log` ad vermez. Dizgi yalnız API'nin sabit argümanı konumunda nesne olur, o da veri akışıyla doğrulanırsa |
| Hata iletisinden ad %84,6 yanlış | `kesinlik_tablosu.md:20` | Hata yolu kanıt değildir (FK3) |
| Tek sözcüklü ad %95,6 yanlış | `kesinlik_tablosu.md:17` | Tek belirteçli ad yok (FK7) |
| "dispatch_handler" türü spekülatif rol adları | `pcode_analyzer.py:624-637` | Genel fiil ad olmaz (FK8). Rol adı yalnız API sözleşmesinden (F-ROL). Sınıflandırma çıktısı ad değil köken alanıdır |
| Fiil ailesi yayılımı (Y3) %0 | `propagate.py:11` | N4'te yayılım yok; fiil komşudan taşınmaz **[S24]** |
| v1 "kör" ölçümleri geçersiz | `2026-10-17_plan_v2.md:59-62` | `rules.py`'deki %83, %49, %50 karar dayanağı değildir; v0 protokol v2'de yeniden ölçülür **[S2]** |

## 5. Aykırı öncül ve alternatif adaylar

### 5.1 Öncül: "Çağrı adından fiil tablosu tamamen doğru çalışsın"

Yani her kütüphane adı doğru fiile eşlensin. Üretilen ad yine de nerede yanlış olur?

| # | Nerede | Mekanizma | Rubrikteki sonucu | GT'siz gösterge (§2.2) | N4'teki karşılığı |
|---|---|---|---|---|---|
| AY1 | Çoğu fonksiyonda tablo susar | Fonksiyon kütüphane çağırmıyor ya da yalnız bellek/dizgi temeli çağırıyor | Kapsam yok | Mac tmux: ayırt edici API %15,7; I %47,2; Y %16,1 | F-ETKİ; kalan I sınıfı N6'ya kalır |
| AY2 | Araç ile amaç | Fonksiyon `open`, `read`, `close` çağırıyor ama işi "yapılandırmayı yüklemek"; ya da 12 iç çağrı arasında tek bir `write` var | `yalniz_alan` (yan ayrıntı, `etiket_rehberi.md:46`); hazırla/uygula karışırsa `yanlis` | Ayırt edici API çağıranların iç çağrısı ≥ 4 olanı: Mac tmux 176/405 | FK2; H-N4-4 |
| AY3 | Sarmalayıcı | Program `malloc`'u değil kendi sarmalayıcısını çağırır. Kanıt sarmalayıcıda kalır; çağıranlarda görünmez | Kapsam yok; sarmalayıcı inline edilmişse yanlış sahip | Tek kütüphane hedefli: Mac tmux 113; `free` çağıran: 493 | FK1; F-ETKİ sarmalayıcıyı ayırıcı ya da bırakıcı sayar |
| AY4 | Hata yolu | `strerror`, `fprintf`, `exit` yalnız hata dalında; tablo "yazdır" ya da "çık" der | `yanlis` ya da `yalniz_alan` | Ayırt edici API ile birlikte hata/ileti çağıran: coreutils 2 341/3 760; yalnız hata/ileti: coreutils 1 747, tree 35/115 | FK3 |
| AY5 | Günlük | Günlük ve zaman damgası çağrıları her yerde | `yalniz_alan` | Mac tmux'ta `%s:` biçimli 283 günlük yuvası (`ks1_onkayit.md:433`) | FK4 |
| AY6 | Inline edilmiş yardımcı | Küçük `static` yardımcının çağrıları çağıranın gövdesinde görünür; aynı kanıt birçok fonksiyonda | `yanlis` (başkasının işi) | Çok importlu kümesi paylaşılan: Mac tmux 152, zstd 402 | FK5 |
| AY7 | Yönü argüman belirler | `open` okuma mı yazma mı (bayrak işletim sistemine göre değişir, `derleyici_sentez.md:179`); `fcntl`, `ioctl`, `sysctl`, `setsockopt` al mı ver mi; `kill(pid, 0)` yoklama mı | `yanlis` (karşıt fiil) | Sayılmadı | Argüman sabiti veri akışıyla okunamıyorsa fiil yok; yön gerektiren API'ler tabloda işaretli |
| AY8 | Nesne yok | 40 fonksiyon `read_file`; hangisi ne okuyor? | Belirsiz: `dogru_tarif` ya da `yalniz_alan` | En seçici importu ≥ 21 fonksiyonda görülen: Mac tmux K'nin %57,3'ü | Biçim tabakaları (B1-B5); H-N4-5 |
| AY9 | Kütüphane adıyla çakışma | Fiil tek başına ad olursa (`open`, `free`) | `yanlis` (kural 5) | — | FK7 |
| AY10 | Derleyicinin ürettiği çağrılar | Döngü `memset`'e, kopya `memcpy`'ye çevrilir; FORTIFY adı değiştirir (`derleyici_sentez.md:178`) | `yalniz_alan` ya da kuralın kaçması | `_chk`/`isoc`: Debian 1 778 | FK0; bellek/dizgi temeli tek başına ad vermez |
| AY11 | Çağrı yeri kör noktası | Tablo yuvasından çağrılan ve dolaylı çağıran fonksiyonlar | Kapsam yok | Debian htop: çağıranı yok %77,8; `blr` %9,6 | N4 dışı (T1 çağrı grafı) |
| AY12 | Platform | Aynı API iki platformda ayrı adla; Darwin'de değişken argüman C'de görünmez | Kuralın kaçması ya da yanlış bağlanması | E3, E5 | FK0; disassembly akışı |

### 5.2 En güçlü itiraz

**Kütüphane çağrısı fonksiyonun aracını söyler, amacını söylemez; ve çağrıya dokunan kod programın ince bir kabuğudur.**

Dört sayı bunu destekliyor:
- Etiketlenebilen iki programda ayırt edici bir API çağıran fonksiyon, isim bekleyenlerin %15,7'si (Mac tmux) ve %19,1'i (Mac htop). API'nin asıl iş olduğu vekille %8,9 ve %13,7.
- İkilide adı görünen fonksiyonların adlarındaki fiillerin çoğu veri yapısı fiili: `get`, `set`, `is`, `create`, `destroy`, `init`, `copy`, `compare` sınıfları Debian htop'ta 263 adın 180'i (%68,4), redis-tools'ta 2 127 adın 1 111'i (%52,2). F-API'nin üretebildiği sınıflar (§4.2) 44 (%16,7) ve 547 (%25,7) **[hesap; §3.1 tablosu]**. Gruplama sayım görüldükten sonra yazıldı; betimseldir.
- Kusursuz tablo bile yönü bilemez (AY7): aynı çağrı argümana göre karşıt fiil verir. Rubrikte karşıt fiil `yanlis`'tır.
- Gömme tabanlı benzerlik ölçüleri karşıt fiilleri benzer sayabiliyor (`yontem_taramasi.md:84`); yani bu hata türünü ancak rubrik ya da karşıt çift sayımı görür.

Sonuç: çağrı tablosu tek başına ne kapsamı taşır ne de yanlış fiili önler. N4 tabloyu bir aile (F-API) olarak tutar, ama ad vermesini ana yol ve veri akışı bağına bağlar; fiilin öbür kaynağı yan etkidir (F-ETKİ).

### 5.3 Alternatif adaylar ve öldürme ölçütleri

| # | Aday | Fikir | Ulaştığı sınıf | Öldürme ölçütü | Durum |
|---|---|---|---|---|---|
| AD1 | Veri akışı rolü ve yan etki (F-ETKİ) | Fiil, fonksiyonun belleğe ve parametrelerine ne yaptığından gelir (§4.2) | Y, K (bellek/dizgi), küçük I | M1 tutma okumasında karşıt oranı zayıf (Wilson alt sınırı > %5) ya da aynı sınıf < %50; ya da M3'te B4 tabakası `zayif` | İlk sürüm |
| AD2 | Dönüş değeri ve hata kalıbı | (a) Dönüş 0/1 → `is`. (b) Çağrı sonucu sınanıp hata dalına gidiliyorsa çağrı ana yoldadır, dal hata yoludur (FK3'ün tanımı). (c) errno ve −1 dönüşü → sistem çağrısı sarmalayıcısı (`derleyici_sentez.md:593`, K12) | K, Y | FK3 açık ve kapalı ablasyonunda M1'de karşıt + farklı oranı düşmüyorsa koruma sadeleştirilir; `is` kuralı M1'de aynı sınıf < %50 ise kapanır | (a), (b) ilk sürümde; (c) aday |
| AD3 | Çağrı sırası imzası (F-SIRA) | Küme yerine sıra: aç → oku → kapat; kilitle → … → aç; ayır → yaz → döndür | K | Sıra koşulu eklenince M1'de F-API'nin aynı sınıf oranı artmıyor ve kapsamı düşüyorsa yazılmaz (ablasyon) | Aday |
| AD4 | Kullanım yerinden rol (F-KULLANIM) | Çağıranlar dönüşü bırakma çağrısına veriyorsa `create`; yalnız koşulda kullanıyorsa `is`; bir alana yazıyorsa `get`. Tip izindeki "kullanımdan" fikrinin fonksiyon karşılığı | Çağıranı olan her sınıf (I dahil) | M1'de n ≥ 10 olan sınıflarda aynı sınıf < %50; ya da öbür ailelerin ad vermediği export'larda verdiği ad payı < %5 | Aday; **yön gösterici** (ön sayımı yok) |
| AD5 | Tümevarımlı tablo (F-TÜME) | Elle tablo yerine: redis-tools export adlarında kanıt imzası → fiil sınıfı sayılır; saflığı yüksek ve n ≥ 10 olan imzalar kural olur, her girdi ölçülmüş saflığını taşır | Hepsi | Debian htop tutma okumasında aynı sınıf < %50 ya da karşıt zayıf: tablo tek programın adlandırma geleneğini ezberlemiştir | Aday; **yön gösterici** |
| AD6 | Modül komşuluğu | Fiil değil nesne ve önek kaynağı (B3) | KS-1 çapası olan programlar | M3'te B3 tabakası `zayif`; KS-1 ölçümünde hiçbir satır `kesin` çıkmazsa hiç açılmaz (D1) | **[S6]** |

Değerlendirilen ve önerilmeyenler:
- **Dizgiden fiil** (log iletisinin ilk sözcüğü): §4.5'teki olumsuz sonuçlar.
- **Çağrılanın tarif adından yukarı taşıma:** yayılımdır; N6'nın koşullarına bağlıdır.
- **Öykünmeyle tanıma** (`derleyici_sentez.md:192`): plan v2'de ayrı kalem (G25).
- **Tablo yuvası rolü** (TR-4): T1 çağrı grafına bağlı; N4 dışı.

### 5.4 Önerilen bileşim

Disassembly üstünde çağrı yeri, argüman, dönüş ve bellek etkisi özeti (S1). Üç aile: F-ROL, F-API, F-ETKİ (S12). Dokuz koruma; çelişkide sus (S15). Nesne yalnız kapalı listeden (S5). Çıktı ad ya da ipucu; her biri köken ve güvenle. Ölçüm üç basamak: mekanik fiil uyumu (M1), ayar etiketi (M2), taze kör etiket (M3).

## 6. Ölçüm

### 6.1 Üç ölçü, üç rol

| Ölçü | Veri | Platform | Rol | Kural ayarına açık mı | Ajan |
|---|---|---|---|---|---|
| M1 fiil uyumu (mekanik) | İkilide adı görünen iç fonksiyonlar: redis-tools (ayar), Debian htop (tutma) | ELF | Aile ayarı ve öldürme | Ayar birimi evet; tutma hayır | 0 |
| M2 ayar etiketi (kör) | G4'ün 482 fonksiyonu, donmuş amaç cümleleri | Mac | Rubriğin davranışını öğrenmek: biçim, yan ayrıntı | Evet | 2 çağrı |
| M3 karar etiketi (kör, taze) | N2 dalgası; tabaka = aile | Mac | Üründe hangi aile ad verir | Hayır | N2 bütçesinde |
| Kapı 1 | Doğrulama seti | — | Plan (`2026-10-21_plan_v2_2.md:72`) | Hayır | — |

M1 yalnız ELF'te, M3 yalnız Mac'te ölçer; ikisi birlikte iki platformu görür. Etiket hattı ELF satırını okumuyor (`2026-10-21_n2_onkayit_taslak.md:346`).

### 6.2 Nüfus ve birim

- **Birim:** (platform, program); rapor birimi 10 (§2.2). Karar kaynak program düzeyindedir: aynı programın iki platformu iki bağımsız kanıt sayılmaz (`ks1_onkayit.md:313-314`).
- **Nüfus (ölçümde):** N2'nin tanımı: `macho_score.json` satırlarından `sinif == "program"` ve durumu `tp`, `wrong` ya da `unnamed` olanlar (`2026-10-21_n2_onkayit_taslak.md:105`). Bu taslaktaki `FUN_` vekili yalnız ön sayım içindir **[S28]**.
- **[S25] C++ ikili (pzstd) N4 dışı** (öneri; KS-1 ile aynı işaret, `ks1_onkayit_taslak.md:260-262`). Gerekçe: adlar ve çağrı kalıpları farklı; geliştirme setinde tek örnek.
- **Eş değişken:** program sınıfı (dizgi zenginliği, boyut tabakası) KS-1'in kilitlediği değerlerle raporlanır (`ks1_onkayit.md:465-476`). Sınıf başına hedef yok (`2026-10-21_plan_v2_2.md:26-29`).

### 6.3 M1: fiil uyumu

**Fikir.** Bazı iç fonksiyonların adı strip'li ikilide de durur (dinamik simge tablosu). Bu fonksiyonlar adsızmış gibi kurallardan geçirilir; kuralın fiil sınıfı, adın içindeki fiil sınıfıyla karşılaştırılır. GT dosyası okunmaz; ad `static/ghidra_functions.json`'dadır. KS-1'in `export` türüyle aynı tanım (`ks1_onkayit_taslak.md:124-126`).

**Başvuru fiili.** Ad alt çizgiden ve küçük-büyük harf geçişinden belirteçlere bölünür. Belirteçlerin sözlük sınıfları toplanır (`handle` hariç). Tam bir sınıf varsa başvuru odur; yoksa ya da birden çoksa fonksiyon başvurusuzdur.

**Evren** (tekil ad; `on_sayim.json` → `adli`):

| Birim | Export (örnek) | Tekil ad | Tek sınıf | Çok sınıf | Fiilsiz | Yalnız genel | Tek sınıflıların K / I / Y dağılımı |
|---|---|---|---|---|---|---|---|
| `debian/htop` | 366 | 366 | 263 (%71,9) | 21 | 76 | 6 | 106 / 108 / 49 |
| `debian/redis-tools` | 8 394 | 3 855 | 2 127 (%55,2) | 260 | 1 409 | 59 | 687 / 1 101 / 339 |
| `debian/coreutils` | 211 | 3 | 0 | 0 | 3 | 0 | — |

Öbür birimlerde export yok. Mac'te strip'li kopyada export beklenmez (`ks1_onkayit_taslak.md:128`).

**Sonuç sınıfları** (aile ve birim başına; ad verilen ve başvurusu olan fonksiyonlarda):
- **aynı sınıf:** kuralın sınıfı başvuruyla aynı;
- **karşıt:** (kural, başvuru) sözlükteki 10 karşıt çiftten biri; "yanlış fiil"in mekanik karşılığı;
- **farklı:** öbür durumlar;
- ayrıca çekimser (ad yok) ve başvurusuz sayıları.
- Çok ELF'li birimde tekil öğe addır: bütün örnekleri aynı sınıfsa "aynı sınıf", biri karşıtsa "karşıt" (KS-1'in tekil kuralı, `ks1_onkayit.md:309`).

**Koşu kuralları:**
- Kurallar bu kipte de iç fonksiyon adlarını okumaz (§4.4 madde 3); export adları yalnız puanlamada kullanılır.
- **[S16] Ayar birimi redis-tools, tutma birimi Debian htop** (öneri; Berke'ye gider). Kurallar redis-tools sonuçlarına bakılarak düzeltilebilir. Debian htop kurallar donduktan sonra bir kez okunur; o okuma kural değiştirmez, yalnız aile kapatır (D3). Gerekçe: Debian htop'un export'ları Mac htop'un isim bekleyenleriyle aynı kaynak fonksiyonlardır; onlara bakarak ayar yapmak N2'nin Mac htop örneklemini taze olmaktan çıkarır. redis-tools etiket evreninde yok.
- **[S17] Öldürme eşikleri** (öneri): n ≥ 10 olan ailede karşıt oranının Wilson %95 alt sınırı > %5 ise ya da aynı sınıf oranı (nokta) < %50 ise aile ölür. Gerekçe: %5, yanlış bütçesinin (%10) yarısı; karşıt fiil rubrikte kesin `yanlis`. %50'nin altı, kanıtın o ailede fiili taşımadığını gösterir. "Farklı" eşik değildir: `find` yerine `get` rubrikte yanlış olmayabilir.

Karşıt oranı için sınırlar **[hesap; Wilson, z = 1,96]**:

| n | 10 | 20 | 35 | 50 | 100 | 263 |
|---|---|---|---|---|---|---|
| "zayıf" için en az karşıt | 2 | 3 | 5 | 6 | 10 | 21 |

**Başvurunun güvenilirliği.** KS-1 ölçümünde export adları 4 224 tekil adın 4 224'ünde doğru çıktı (`ks1_olcum.md:20`).

**Ek evren (isteğe bağlı):** KS-1'in `kesin` çıkan satırının çapaları: `func_kalibi`, Mac tmux 150, Debian tmux 97, openssl 15 (`ks1_olcum.md:31, :36, :43`). Bu adlardaki fiil kapsamı sayılmadı. `assert` satırı `kesin` çıkmadığı için evrene girmez.

### 6.4 M2: ayar etiketi

- **Evren:** G4'te etiketlenmiş 482 fonksiyon: tmux 385, htop 97 (`alt_kanal_onkayit.md:190`). Bunlar zaten N2'nin taze havuzunun dışında (`2026-10-21_n2_onkayit_taslak.md:118`); ayar tazelik harcamaz.
- **Yordam:** fonksiyonların donmuş amaç cümleleri yeniden kullanılır; yalnız aşama 2 yapılır. Adaylar: `N4` (bütün aileler ve biçimler) ve `T0` (v0). Çok adaylı kip, sistem kimliği gizli (`etiket_protokolu_v2.md:382-384`).
- **Değerlendirici:** tek ajan, program başına bir çağrı (2 çağrı). Gerekçe: ayar ölçüsüdür, karar değil; G4'te kör-kör uyum yakın/değil için κ 0,953 (`2026-10-19_g4_etiketleme/sonuc.md:42`).
- **Okunanlar:** aile × biçim başına yakın, yalnız alan, yanlış; `yanlis_turu` (§6.5); H-N4-4 ve H-N4-5.
- **Sınır:** G4 evreni Karadul'un ad verdiği fonksiyonlardır (`2026-10-19_g4_etiketleme/sonuc.md:13`); o adların hemen hepsi dizgiden geliyordu (`2026-10-21_plan_v2_2.md:36`). Nüfusun rastgele örneği değildir; sonuç yalnız ayar içindir.
- **[S18] M2 yapılsın mı?** (öneri: evet, yukarıdaki gibi). Gerekçe: M3 tek atıştır; taze etiketlere bakılarak kural değişmez (`2026-10-21_n2_onkayit_taslak.md:318`). Rubriğin B4'ü ve yan ayrıntıyı nasıl saydığı M3'ten önce öğrenilmezse düzeltme şansı kalmaz. Alternatifler: (a) tazeliğinden vazgeçilen küçük bir örneklemde iki aşamalı etiketleme; (b) M2'siz, doğrudan M3.
- **Eksik araç:** donmuş amaç cümleleriyle yalnız aşama 2 paketi üreten kip yok (`etiket_paketi.py` `uret-cok` her seferinde yeni amaç paketi üretir).

### 6.5 M3: karar etiketi (N2 dalgasında)

Plan, taze örneklemin susturma ve fiil sonrası ürün çıktısından çekileceğini yazıyor (`2026-10-21_plan_v2_2.md:218`). N4 ayrı bir dalga açmaz; N2'nin yordamına aşağıdakileri ekler.

- **Tabakalar (N2 Çerçeve B'ye):** aile başına bir tabaka: F-ROL, F-API, F-API sarmalayıcı satırı (FK1), F-ETKİ. S6 kabul edilirse modül önekli adlar (B3) beşinci tabakadır; o fonksiyonlarda öneksiz ad da aday olarak etiketlenir. Öbür biçimler tabaka içinde kırılım olarak raporlanır. Tabaka nüfusu ≤ 100 ise hepsi, değilse tohumlu 100 (`2026-10-21_n2_onkayit_taslak.md:150`). **[S19]**
- **Sistemler:** N2'nin KD1'i, N1 + susturma + fiil sonrası ölçüm yapısının adıdır (bütün aileler açık; §7 madde 8). Hangi ailenin üründe kalacağı bu etiketlerden çıkar (D6). Ek aday: `T0` (v0'ın aynı fonksiyonlara verdiği ad) **[S21]**.
- **Ablasyon etiketsizdir:** fiilsiz ürün = KD1'den kökeni `tarif_fiil` olan adların çıkarılması. Fiilin yakın kapsama katkısı, Çerçeve A'da fiil kökenli yakın adların payıdır (H-N4-3).
- **`yanlis_turu`:** N2'nin önerdiği alan (`2026-10-21_n2_onkayit_taslak.md:211`): `fiil` ya da `diger`. N4'ün "yanlış fiil oranı" = `yanlis` ve `yanlis_turu = fiil` olan adların, verilen fiil adlarına oranı.
- **Kademe sırası:** N2 ürünün kademe eğrisini önceden yazılmış sırayla okuyor (`2026-10-21_n2_onkayit_taslak.md:264-270`). **[S27]** Fiil aileleri KS-1'den ve `oz_ad`'dan sonra, M1 tutma okumasındaki karşıt oranına göre artan sırayla girer; sıra M3 paketlerinden önce N2 ön kaydına yazılır (öneri). Gerekçe: sıra etiket görülmeden, mekanik bir ölçüden gelir.
- **Örneklem büyüklüğü:** tabaka başına en çok 100. "Doğrulandı" için n ≥ 35 gerekir (0 yanlışla); n = 100'de en çok 4 yanlış. "Zayıf" için n = 35'te en az 7, n = 100'de en az 16 yanlış (`alt_kanal_onkayit.md:259-272`).
- **Yem, uyum, hakem:** N2'deki gibi (`2026-10-21_n2_onkayit_taslak.md:189-226`).

### 6.6 Karar kuralı

N0b'nin `karar()` kuralı aynen **[S20]** (`alt_kanal_onkayit.md:232-239`): yanlış oranının (yanlış fiil dahil) Wilson %95 aralığı [L, U], eşik %10.

| Karar | Koşul | Üründe | Güven etiketi |
|---|---|---|---|
| `dogrulandi` | U ≤ %10 | ad verir | doğrulandı |
| `belirsiz` | L ≤ %10 < U | ad verir | doğrulanmadı |
| `zayif` | L > %10 | ad vermez; ipucu olur **[S22]** | — |
| `olculemedi` | n = 0 | ad vermez | — |

- Karar aile düzeyinde, iki program birleşik; program başına satırlar raporlanır.
- B3 tabakası ayrı karar satırıdır: zayıfsa önek kapanır; öneksiz adın kararı kendi ailesinden gelir.
- Çoklu karşılaştırma düzeltmesi yapılmaz (N0b ve N2 ile aynı).
- **[S22] Zayıf aile ipucu olarak kalır,** M1'de karşıt oranı zayıf değilse (öneri). Gerekçe: ipucu ad değildir, Kapı 1'in yanlış sayacına girmez; ama karşıt fiilli ipucu okuyanı yanıltır.

### 6.7 Önceden yazılan dallar

| # | Durum | Ne yapılır |
|---|---|---|
| D1 | KS-1 satırlarının durumu. Ölçüm: `func_kalibi` kesin; `assert` kesin değil; `assert_ust` ve `func_aktarma` yetersiz (`ks1_olcum.md:11-14`) | FK6 üründe ad veren bütün KS-1 satırlarını korur ("kesin" ve "doğrulanmadı"; hangileri ad verir, bağlama kararıdır: bağlama `:190-197`). B3 yalnız `kesin` satırın, yani `func_kalibi`'nin çapalarına dayanır. Satır durumu değişirse bu dal yeniden okunur |
| D2 | M1 ayar biriminde (redis-tools) aile eşiği tutmuyor | Kural düzeltilir. Donma anında hâlâ tutmuyorsa aile kapanır |
| D3 | M1 tutma okumasında (Debian htop) aile ölüyor (S17) | Aile kapanır: ad da ipucu da vermez. Kural düzeltilmez; düzeltme yeni ön kayıt ister |
| D4 | M1 tutma okumasında ailede n < 10 | "Mekanik ölçülemedi" yazılır; aile M3'e girer, karar yalnız M3'ten |
| D5 | M2'de B4 biçiminin yakın oranı < %50 | B4 üründe ipucudur; M3'e ad adayı olarak girmez. Sonuç H-N4-5'in olumsuz okuması olarak kayda girer |
| D6 | M3'te aile `dogrulandi` / `belirsiz` / `zayif` / `olculemedi` | §6.6 tablosu; değişiklik Kapı 1 koşusundan önce tek commit'te (`2026-10-21_n2_onkayit_taslak.md:294`) |
| D7 | Bütün aileler `zayif` ya da `olculemedi` | Fiil katmanı üründe ad vermez. Kapı 1, KS-1 ve kalan alt kanallarla okunur; tutmazsa planın dalı işler: isim kuralları donar, olumsuz sonuç kayda girer (`2026-10-21_plan_v2_2.md:72`) |
| D8 | Fiil açıkken ürünün tabakalı yanlış oranının alt sınırı > %10 | N2'nin D10'u aynen: kademe sırasında geriye çekilir (`2026-10-21_n2_onkayit_taslak.md:307`) |
| D9 | `T0` bir ailede N4'ten düşük yanlış oranı veriyor | Raporlanır. Ürüne N4 sürümü girer; v0'a dönüş yeni ön kayıt ister **[S21]** |
| D10 | H-N4-4 tutmuyor | FK2 sınırı bu veriye bakılarak değiştirilmez; Kapı 1'den sonra yeni ön kayıtla gevşetilebilir |
| D11 | N2'de uyum ya da yem eşiği tutmuyor | N2'nin D3 ve D4'ü aynen; fiil ailelerinin kararı da verilmez ve ölçülmemiş aile ad vermez |
| D12 | N4 iki günü aşıyor | Kapı 1 kayar, ölçütler kaymaz (`2026-10-21_plan_v2_2.md:175`). Teslim sırası: F-ROL, F-API, sonra F-ETKİ |

### 6.8 Kapı 1 ile ilişki

- Kapı 1 ürünün çıktısını ölçer: yanlış ≤ %10 iken yakın kapsam ≥ kanıt tavanının %50'si. N4'ün kapısı yoktur; Kapı 1'de okunacak yapılandırmayı belirler (D6).
- Fiil eklendikten sonra da tutmazsa isim kuralları donar (`2026-10-21_plan_v2_2.md:214`).
- **Önceden yazılan beklenti** (karar dışı) **[hesap; §2.2]:**

| | Mac tmux | Mac htop |
|---|---|---|
| KS-1 dizgi çapalarının kapsamı (ölçüldü) | %6,8 (172/2 545); yalnız `kesin` satır `func_kalibi`: %5,9 (`ks1_olcum.md:43, :45`) | 0 |
| F-API'nin ad verebileceği üst sınır (ayırt edici API, iç çağrı ≤ 3) | %8,9 | %13,7 |
| F-ETKİ'nin aday havuzu (yaprak + yalnız bellek/dizgi) | %16,1 + %18,9 | %17,1 + %18,9 |
| Fiilin hiç ulaşamadığı (yalnız iç çağrı) | %47,2 | %44,4 |

- Okuma: htop türünde KS-1 ve dizgi kanalları boş olduğu için Kapı 1'in kapsamı tümüyle fiilden gelmek zorunda. F-API tek başına en çok %13,7 verir ve hepsi yakın olmaz. Geri kalan F-ETKİ'den, yani genel nesneli adlardan (B4) gelir. B4 rubrikte yakın sayılmazsa (H-N4-5) htop türünde kapı büyük olasılıkla tutmaz. Onuncu Adam aynı sonucu tahmin etmişti (`2026-10-21_v2_1/onuncu_adam.md:307-309`).
- Kanıt tavanı ölçülmedi; bu yüzden kapsam için eşik yazılmadı.

### 6.9 Maliyet

| Ölçü | Öğe | Ajan çağrısı |
|---|---|---|
| M1 | Başvurusu olan export adı: Debian htop 263, redis-tools 2 127 | 0 |
| M2 | En çok 482 fonksiyon; aday sayısı kurallar yazılınca belli olur, üst sınır 2 × 482 = 964 **[hesap]** | 2 (tek değerlendirici, program başına bir; yalnız aşama 2) |
| M3 | N2 paketine en çok 5 tabaka × 100 = 500 fonksiyon eklenir (B3 açılmazsa 400) **[hesap]**; N2 bugün ~500 fonksiyon öngörüyor (`2026-10-21_n2_onkayit_taslak.md:193`) | N2'nin 8 çağrısı (`:205`); paket ikiye bölünürse artar |

**[S26] N4'ün ek ajan bütçesi 2 çağrıdır;** aynı anda en çok 2 (`2026-10-21_plan_v2_2.md:132`). M3 yüzünden N2'nin çağrı sayısı artacaksa önce Berke'ye sorulur.

### 6.10 Kesinleşmeden önce

1. KS-1 ölçümü bitti (5d0b528). Hangi satırların üründe ad vereceği bağlama kararıyla kesinleşir (D1).
2. **[S…]** maddeleri karara bağlanır.
3. Araçlar yazılır, testli ve mutant kanıtlı: veri akışı uzantısı; fiil çıkarıcı ve korumalar; M1 puanlayıcı (bu betikteki `fiil_durumu` ile aynı başvuru tanımı); donmuş amaçla aşama 2 paketi; köken kaydına fiil alanları; `yanlis_turu` alanı.
4. Sözlük, API tablosu ve kurallar dondurulur; sha256'lar bu belgenin kesin sürümüne yazılır.
5. M1 tutma okuması yapılır (bir kez). Sonra N2 ön kaydı fiil tabakaları ve kademe sırasıyla güncellenir.

## 7. Ürüne bağlama: N4'e özgü gereksinimler

KS-1 ve susturmanın bağlama tasarımı ayrı belgededir: `2026-11-10_n1_adim3/baglama_tasarimi_taslak.md` (bu taslağın sonunda okundu; aşağıda "bağlama" diye anılır). O belge fiil için tek şey söylüyor: tarif adları da `pre_names` ve `pre_name_meta` (`kind: "tarif"`) kanalını kullanmalı, ikinci kanal açılmamalı; iki bağlama aynı güne konmamalı (bağlama `:524`). N4'ün o kanaldan istedikleri:

1. **Giriş.** `run_tarif(packs, kesin, population)` (`tarif/__init__.py:24-28`): `kesin`, üründe ad veren KS-1 satırlarının çapalarıdır (satır durumu: bağlama `:188-197`); kullanımı D1'de. Bugünkü köprü (`tarif_olc.py:29-39`, kesinliği ~0,74) kullanılmaz.
2. **Kanal.** Fiil adı ön ad kanalından girer; başka yol yok: birleştirici c_namer'ı ezemiyor (`2026-10-17_plan_v2.md:43`; bağlama `:59-62`).
3. **Ön ad kanalının üç tuzağı fiil adlarında daha ağır:**
   - **Aynı ad sessizce düşer.** Ön ad kanalı aynı adı ikinci anahtarda yazmıyor (`c_namer.py:1922`). Fiil adları doğası gereği yinelenir (`read_file`, `free_object`). Ek fiil adımında verilmeli (S10); düşen her ön ad sayılmalı.
   - **Her ön ad `binary_extract` ve 0,95 güvenle yazılıyor** (`c_namer.py:1925-1929`). Fiil adı `strategy = tarif_fiil`, ailesi ve ölçülmüş güveniyle yazılmalı; yoksa N2 tabaka kuramaz (§6.5).
   - **Ön ad her c_namer adayını yener** (`c_namer.py:1983-1986`). Bu, S23'teki sırayla çelişir: fiil adı `oz_ad` adayını da ezer. Seçim döngüsünde tarif türü için ayrı bir kural gerekir; bağlama tasarımında yok.
4. **Öncelik [S23]** (öneri):
   - Ön adlar arasında: tarif en sondadır, yalnız boş yuvaya yazılır; `elle`, `main_giris`, `ks1`, `faz1`, `gnulib`, `elf_onyuk` adlarının hiçbirini ezmez (sıra: bağlama `:236-243`).
   - c_namer adaylarına karşı: KS-1 > `oz_ad` > fiil > `kebap_ad`. Gerekçe: `oz_ad` adlarının %82,7'si tam (`kesinlik_tablosu.md:16`); `kebap_ad` adlarının %81,1'i yalnız alan, yakını %8,1 (`:19`). Fiil adı `kebap_ad`'ın yerine geçerse yakın kapsam artabilir; `oz_ad`'ın yerine geçerse tam ad kaybedilir.
   - Fiil ile `oz_ad` aynı anahtarda karşılaşırsa sayılır; sayı ölçüm çıktısına yazılır.
5. **Belirlenimcilik.** Aynı girdiyle iki koşu bayt bayt aynı ad haritasını vermeli (ÖL-7). Ekler adrese göre, seri dağıtılır; süreç havuzu eklerin dağılımını değiştiriyor (`alt_kanal_onkayit.md:81`).
6. **Yazım.** Fiil adları küçük harf snake_case'tir; temizleme onları değiştirmez. B3 açılırsa modül öneki büyük harf taşıyabilir; o zaman ad `exact` işaretiyle girmelidir (bağlama `:156-166`).
7. **Köken kanalı.** §3.4'teki bilgi `naming_provenance.json`'a, şema sürümü değişmeden yazılır. N2 tabakalarını köken kaydından kuruyor (`2026-10-21_n2_onkayit_taslak.md:144-149`); fiil adları orada aile adıyla görünmelidir. Etiket değerleri bağlamanın sözlüğüyle aynıdır ("doğrulanmadı", "doğrulandı"; bağlama `:328-335`). Fiil adı "kesin" etiketi alamaz.
8. **Aile başına aç/kapa.** Varsayılan kapalı. Ölçüm yapısında hepsi açık; üründe yalnız D6'nın açtıkları. Aç/kapa değerleri tek yerde tanımlanır.
9. **İpucu çıktısı.** İpucu ad haritasına girmez; fonksiyonun üstüne yorum olarak yazılır; `FUN_` kalır.
10. **Yayılım kapalı [S24].** `propagate.py`'deki Y1, Y2, Y4 ve `apply_modules`'ün ipucu üretimi N4'te çalışmaz (öneri). Gerekçe: yayılım N6'dadır ve yalnız kesin çapalardan yapılır (`2026-10-21_plan_v2_2.md:75`). B3 açılırsa (S6) yalnız `module.py`'nin iki çapa arası kuralı kullanılır.
11. **Dokunulmayan dosyalar.** `kesin.py` ve ön kayıtla sabitlenen öbür dosyalar (bağlama `:434-438`). `c_namer.py`, `stages.py`, `config.py`, `output_formatter.py` tek elden ve sıralı (`2026-10-21_plan_v2_2.md:62`); N4 bunlara KS-1 bağlaması bittikten sonra, ayrı günde dokunur.
12. **Uçtan uca sınama.** Fiil adı son `.c` dosyasında görünüyor mu; yalnız `naming_map.json` denetimi yetmez (`2026-10-17_v2/kod_haritasi.md:389`).

## 8. Sınırlar, riskler, bütünlük kaydı, seçimler

### 8.1 Bilinen sınırlar

1. **Ön sayım nüfusu vekildir.** `FUN_` adlı fonksiyonlar GT'li "ad bekleyen"lerle aynı değildir. KS-1 ölçümünün nüfusuyla karşılaştırma (`ks1_olcum.md:27-45`): Mac tmux 2 587'ye karşı 2 545; Debian tmux 1 916'ya karşı 1 851; openssl 588'e karşı 563; coreutils 13 485'e karşı 12 717; redis-tools 2 103'e karşı 1 458; zstd 1 908'e karşı 919 (pzstd C++ olduğu için orada dışarıda). Fark derleyici klonlarından, CRT fonksiyonlarından (CRT importu çağıran 236) ve C++ ikiliden gelir; redis-tools ve zstd yüzdeleri bu yüzden en az güvenilir olanlardır. `entry` vekilin dışındadır.
2. **Aile listeleri elle yazıldı** (dönmeyen, ileti, bellek/dizgi). §2.2'deki "ayırt edici" payı bu listelere bağlıdır. Listeler `on_sayim.json`'dadır; ürün sözlüğü değildir.
3. **"Yazar" ve `cset w0` kaba işaretlerdir:** veri akışı yok; taban yazmacın kökeni bilinmiyor.
4. **coreutils örnek düzeyinde sayıldı.** Aynı gnulib gövdesi birçok ELF'te yineleniyor (§2.3 madde 9); coreutils yüzdeleri program çeşitliliğini değil ELF sayısını yansıtır.
5. **M1'in evreni seçilmiş bir alt kümedir.** Debian htop ve redis-tools'ta export'lar `static` olmayan fonksiyonlardır; isim bekleyenler ise `static` olanlardır. Sınıf dağılımları yakın (Debian htop export'ları K/I/Y 106/108/49; isim bekleyenler 103/107/29) ama fonksiyon türleri farklı olabilir. M1 ayar ve öldürme içindir; raporlanan kesinlik M3'tür.
6. **M1'in başvurusu gürültülüdür.** Ad belirteçleri hem ad hem fiil olabilir (`log`, `lock`, `match`, `end`). Tek sınıf koşulu bunu azaltır ama gidermez. Fiilsiz adlar (htop %20,8, redis-tools %36,6) M1'e hiç girmez.
7. **M1 iki programa dayanır** ve biri ayar birimidir; tutma okuması tek programdır (263 ad).
8. **Tutma okuması Mac htop'un tazeliğine dokunur.** Bir aile Debian htop'a bakılarak kapatılırsa, kalan ailelerin Mac htop'taki M3 sonucu hafifçe iyimser olur. Kural ayarı yapılmadığı için etkisi küçüktür; ölçülmez.
9. **M3 yalnız Mac'te, iki programda.** Karar tabakalarının çoğu tmux'tan gelebilir. ELF'te kör etiket yok.
10. **Değerlendiriciler LLM** ve kural yazan modelle aynı aileden (`2026-10-19_g4_etiketleme/sonuc.md:95`). tmux ve htop ünlü programlardır; ezber dışlanamaz (`etiket_protokolu_v2.md:281`).
11. **Fiil sözlüğü İngilizce ve elle yazıldı.** Başka adlandırma gelenekleri (kısaltmalar, başka diller) M1'de başvurusuz kalır.
12. **Tanımları yazanın bilgisi.** Bu taslağı bir LLM ajanı yazdı (Claude Fable 5.2). tmux, htop, coreutils, redis, zstd ve sqlite kaynaklarını eğitiminden tanıyor olabilir. Önlem: kurallar yapıya dayanır, hiçbir kural bir program fonksiyonunun adına başvurmaz, kurallar ve sözlük ölçümden önce dondurulur.

### 8.2 Riskler

| Risk | Etki | Önlem |
|---|---|---|
| Rubrik genel nesneli adı `yalniz_alan` sayar | F-ETKİ ad veremez; htop türünde Kapı 1 kapsamı tutmaz | M2'de erken okunur (D5); karar Berke'de (S7, S8) |
| İki gün yetmez: veri akışı uzantısı, üç aile, dokuz koruma, M1 puanlayıcı, mutant kanıtlı testler | Kapı 1 kayar | D12 teslim sırası; F-ETKİ'nin ilk sürümü yalnız `create` ve `destroy` |
| KS-1'de yalnız `func_kalibi` kesin çıktı; `assert` çıkmadı | B3 yalnız tmux türünde çalışır; zstd, coreutils, redis-tools'ta modül öneki yok | D1; B3 ayrı tabaka |
| Kurallar geliştirme setine aşırı uyar | Kapı 1'de düşer | Tutma okuması; M3 taze; kurallar yapıya dayanır; künye |
| F-API tablosu Darwin adlarıyla yazılır, ELF'te susar | Debian'da kapsam kaybı | FK0; M1 ELF'te ölçer |
| Fiil adı doğru bir `oz_ad` adını ezer: ön ad her c_namer adayını yeniyor | Tam ad kaybı | Öncelik sırası (S23); seçim döngüsünde tarif türüne ayrı kural (§7 madde 3) |
| Yinelenen fiil adları ön ad kanalında sessizce düşer | Kapsam kaybı; sıra bağımlılığı | Ek fiil adımında (S10); düşenler sayılır |
| M2'nin evreni yanlı; ayar yanlış yöne gider | M3'te sürpriz | M2 yalnız biçim ve yan ayrıntı sorularını okur; aile kararı M3'ten |
| Çok sayıda `_N` ekli aynı ad | Okunurluk düşer | Sayısı raporlanır; B4 ipucuna inerse sorun kalkar |

### 8.3 Bütünlük kaydı: neye bakıldı, neye bakılmadı

**Bakılmadı:**
- GT: dbgsym `.debug` dosyaları, `*.gt.json`, `macho_score.json` (Mac koşu dizininde duruyor; açılmadı), dSYM, `nm` çıktıları;
- `naming_map.json`, kaynak ağaçları;
- G4 verisi (`docs/arge/2026-10-19_g4_etiketleme/veri/`), `sonuc.json`;
- N0b'nin `kayitlar_*.jsonl`, `ters_eslesme_*.json` ve `kesinlik_tablosu.json` dosyaları;
- `docs/arge/dogrulama_seti*`, `docs/arge/test_seti*`, `docs/arge/dogrulama_seti_kanit/`, `targets/`.

Karadul, Ghidra, ölçüm betiği ve test koşturulmadı. Başka model ya da ajan çağrılmadı.

**Bakıldı:**
- planlar: v2.2, v2.1, v2 (§2-§5), 10-15 planı;
- ön kayıtlar ve toplu sonuçlar: KS-1 taslağı, kesin ön kaydı ve `ks1_olcum.md` (toplu sonuç; ad içermez; `ks1_olcum.json` açılmadı), N2 taslağı, N0b ön kaydı ve `kesinlik_tablosu.md`, G4 `sonuc.md`, G7 `rapor.md`;
- `etiket_rehberi.md`, `etiket_protokolu_v2.md`, `yontem_taramasi.md`, `derleyici_sentez.md` (§3 ve N-R2 notu), `kod_haritasi.md` (tarif satırları), `2026-10-21_v2_1/onuncu_adam.md` (İ10);
- bağlama tasarımı taslağı (`2026-11-10_n1_adim3/baglama_tasarimi_taslak.md`): §0-§2, §3.1-§3.2, §4, §5.1-§5.2, §5.6. Bu taslak bittikten sonra okundu; §3.3 (S10), §3.4, §6.7 (D1), §7 ve §8.2'nin iki satırı ona göre düzeltildi. KS-1 ölçüm sonucu da sonda okundu; S6, D1, §6.3 (ek evren), §6.8 ve §8.1 madde 1 ona göre güncellendi. Kural aileleri, korumalar, sözlük ve ölçüm tasarımı bu iki okumadan önce yazılmıştı ve değişmedi;
- kod: `tarif/` paketinin beş dosyası, `kesin.py` (girdi ve veri akışı bölümleri), `tarif_olc.py`, `headless.py:1385-1474`, `c_namer.py:1908-1941`, `:1958-2006` ve `:2950-3079`, `pcode_analyzer.py:618-647`, `config.py:500-506`; `etiket_paketi.py` ve `etiket_puan.py`'nin yalnız komut satırı seçenekleri;
- geliştirme `static/` çıktıları: betik 119 dizinin hepsini okudu. Elle: Mac tmux'tan bir decompile dosyası (biçim için), `pcode.jsonl`'den bir kayıt, fonksiyon ve xrefs JSON'larının şeması; görülen adlar `FUN_…` ve kütüphane adlarıydı;
- `kosu_kunyesi.json`, `session.json` (künye).

**Gerçek ad içeren, okunan belgeler** (tasarımda kullanılmadı):
- G7 `rapor.md:120-138`: tmux ve htop'tan GT örnek adları ve önek dağılımları (11 fonksiyon adı).
- `alt_kanal_onkayit.md:49, :64-65, :82`: iki tmux fonksiyonunun adı.
- `etiket_protokolu_v2.md:283-306`: kuru koşudan beş tmux adı. KS-1 taslağı `:120`: bir Debian htop export adı. G4 `sonuc.md:91`: bir ad. Plan v2.1 `:96` ve G7 `rapor.md:34`: örnek olarak verilen iki tmux adı. Bağlama tasarımı `:158-166`: örnek olarak verilen üç ad.

**Export adlarının sayımı:**
- Betik Debian htop, redis-tools ve coreutils'in export adlarını belirteçlerine ayırdı ve sözlük sınıflarını saydı (§3.1, §6.3). Adlar ekrana ya da çıktıya yazılmadı; tek tek görülmedi.
- Sözlük sayımdan önce yazıldı ve sayımdan sonra değişmedi.
- §5.2'deki "veri yapısı fiilleri çoğunlukta" okuması bu toplu sayımdan çıktı ve tasarımın gerekçesinde kullanıldı. Bu, geliştirme setinin toplu bir özelliğidir; belirli bir fonksiyonun adına bakılmadı.
- Kütüphane (import) adları görüldü ve `on_sayim.json`'da listelendi; bunlar program fonksiyonu adı değildir.

**Betiğin geçmişi:** üç kez koşuldu. İlk koşudan sonra yalnız sayaç eklendi: kuyruk çağrısı, jenerik thunk, `_chk`/`isoc`, çağrı yeri çokluğu, aynı adın iki adresi. Sınıf tanımları, aile listeleri ve sözlük ilk koşudan beri aynı. Birim başına beklenen ELF sayısı `ks1_olc.py`'deki değerlerle eşitlendi. Ayrıca betiğin iki işlevi Mac ve Debian tmux'un `static/` dizinlerinde bir kez elle çağrıldı: disassembly'deki `bl` ve kuyruk çağrısı hedeflerinin xrefs'te olup olmadığını saymak için.

**Takım tartışma dosyası** (`~/.claude/team-state/discussion.md`) okundu; son girişler başka bir projeye ait. Görevin dosya kısıtı gereği o dosyaya yazılmadı.

### 8.4 [seçim] maddeleri (özet)

"B" sütunu: Berke'ye gitmesi gereken.

| # | Madde | Öneri | Tek cümle gerekçe | Yer | B |
|---|---|---|---|---|---|
| S1 | Veri akışı zemini | Disassembly; `kesin.py` akışının uzantısı, yeni dosyada | Akış yazılı ve sınanmış; SSA'lı p-code N4'ten sonra geliyor | §2.1 | |
| S2 | v0 (`rules.py`) önce ölçülsün mü | Evet; `T0` sistemi | v0'ın yanlış fiil oranı hiç ölçülmedi | §4.1 | |
| S3 | Fiil sözlüğü v0 | 30 sınıf, 10 karşıt çift; sha256 ile dondur | M1'in başvurusu sözlüktür | §3.1 | |
| S4 | Genel fiiller | Ad olmaz; ipucu | Rubrikte `yalniz_alan`; spekülatif rol adı dersi | §3.1 | |
| S5 | Nesne kaynakları | Kapalı liste: API, sabit argüman, (modül), (genel), rol | Tip kümesi ve serbest dizgi ölçülmüş olumsuz sonuç | §3.2 | |
| S6 | Modül öneki N4 ile açılsın mı | Evet; ayrı tabaka | Rubrikte modül + asıl iş rolü yakın; ama plan modülü N6'da sayıyor | §3.2 | ● |
| S7 | Genel nesneli ad (B4): ad mı, ipucu mu | Ölçümde ad adayı; ürün kararı ölçümden | htop türünde F-ETKİ'nin tek biçimi | §3.2 | ● |
| S8 | Rubrik sürümü | Sürüm 2 aynen | Değişirse eski sayılarla birleştirilemez | §3.2 | ● |
| S9 | "tarif" öneki | Önek yok; statü köken kanalında ve yorumda | Önek kör paketi ve normalize gösterimi bozar | §3.3 | ● |
| S10 | Çakışma eki | Fiil adımında, adres sırasıyla `_N`; adres gömülmez | Ön ad kanalı aynı adı sessizce düşürüyor | §3.3 | |
| S11 | Sayısal güven | Ailenin ölçülen 1 − yanlış oranı | Elle puanlar ölçülmedi | §3.4 | |
| S12 | İlk sürümün aileleri | F-ROL, F-API, F-ETKİ | İki gün; üç ayrı kanıt türü | §4.2 | |
| S13 | FK2 büyük gövde sınırı | İç çağrı ≤ 3; pay ölçütü kalkar | Bugünkü değer; H-N4-4 sınar | §4.3 | |
| S14 | FK5 eşiği | k = 3 | İki fonksiyon çağıran-çağrılan çifti olabilir | §4.3 | |
| S15 | Aileler arası çelişki | Karşıtsa sus; farklıysa F-ROL > F-API > F-ETKİ | Sözleşme, sezgiden dar tanımlı | §4.3 | |
| S16 | M1 birimleri | redis-tools ayar; Debian htop tek okumalık tutma | Debian htop export'ları Mac htop'un isim bekleyenleriyle aynı kaynak | §6.3 | ● |
| S17 | M1 öldürme eşikleri | Karşıt alt sınırı > %5 ya da aynı sınıf < %50; n ≥ 10 | %5 yanlış bütçesinin yarısı | §6.3 | |
| S18 | M2 ayar etiketi | Evet; G4 fonksiyonları, donmuş amaç, yalnız aşama 2 | M3 tek atış; tazelik harcamaz | §6.4 | |
| S19 | M3 tabakaları | Aile başına bir tabaka (B3 açılırsa beşinci), en çok 100; öbür biçimler kırılım | N2'nin tabaka kuralı | §6.5 | |
| S20 | M3 karar kuralı | N0b `karar()` aynen, eşik %10 | Kapı 1'in sınırı; öbür kanallarla aynı kural | §6.6 | |
| S21 | `T0`'ın rolü | Yalnız kıyas; ürüne N4 sürümü girer | Geriye dönüş etiketlere bakarak seçim olurdu | §6.5, D9 | |
| S22 | Zayıf aile | İpucu olarak kalır; M1'de karşıt zayıfsa o da kapanır | İpucu Kapı 1'in yanlışına girmez | §6.6 | |
| S23 | Ürün önceliği | Ön adlar arasında en son, yalnız boş yuvaya; adaylara karşı KS-1 > `oz_ad` > fiil > `kebap_ad` | `oz_ad` çoğunlukla tam; `kebap_ad` çoğunlukla yalnız alan | §7 | |
| S24 | Yayılım kuralları (Y1, Y2, Y4) | N4'te kapalı | Yayılım N6'da, yalnız kesin çapalardan | §7 | |
| S25 | C++ ikili | N4 dışı | KS-1 ile aynı | §6.2 | |
| S26 | Ajan bütçesi | N4 için 2 ek çağrı; M3 N2'nin bütçesinde | Plan sınırı aynı anda 2 | §6.9 | ● |
| S27 | Kademe sırasında fiilin yeri | KS-1 ve `oz_ad`'dan sonra; M1 karşıt oranına göre artan | Sıra etiket görülmeden, mekanik ölçüden | §6.5 | |
| S28 | Ölçümde nüfus | N2'nin GT'li tanımı; `FUN_` vekili yalnız ön sayım | Aynı payda | §6.2 | |
| S29 | FK0 normalizasyon listesi | Beş kural, kapalı liste | Debian'da en sık biçimler | §4.3 | |
