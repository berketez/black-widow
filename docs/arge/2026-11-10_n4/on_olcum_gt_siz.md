# N4 karar öncesi GT'siz iki ön ölçüm: riskli deyimler ve M1 temsil denetimi

- **Tarih:** 2026-11-10.
- **Dayanak:** `onuncu_adam.md` §7 madde 1 ve 2 (ölçütler `:156-157`), gerekçeler §2 ve §3; kurallar `fiil_onkayit_taslak.md` §4.2-§4.3 (`:302-331`), M1 §6.3 (`:435-471`).
- **Ne yapıldı:** `on_sayim.py` sürüm 2'ye yeni sayaçlar eklendi; sürüm 1'in bütün sayaçları aynı değerde kaldı (§7.1). Ürün kodu değişmedi.
- **İşaretler:** **[hesap]** çıktı sayılarından aritmetik. **[tahmin]** açık bir varsayıma dayanır. **[okuma]** decompile metninin elle okunmasıyla verilen yargı; GT değildir.
- Bu belgede program fonksiyonu adı ve adres yoktur. Kütüphane (import) adları ve fiil sözlüğü sözcükleri geçer.

**Dosyalar:**

| Dosya | İçerik | sha256 (ilk 16) |
|---|---|---|
| `docs/arge/2026-11-10_n4/on_sayim.py` | sürüm 2; yeni bölüm "Sürüm 2: N4 riskli deyim sayımı ve M1 temsil denetimi" | `d3e3b9ed955c2f89` |
| `docs/arge/2026-11-10_n4/on_sayim.json` | sürüm 1 alanları aynen + `birimler/*/n4`, `n4_ortanca`, `toplam_n4`, `n4_tabaka`, `olcum1_hukum`, `m1_temsil`, `kunye.n4` | `750c86a4d3d6b09b` |
| `tests/test_n4_on_sayim.py` | 24 test, sentetik `static/` | — |
| `~/karadul_olcum/runs/n4-on-olcum-2026-11-10/capalar.json` | KS-1 `func_kalibi` çapaları: adres + addaki fiil sınıfı; ad yok; depo dışı | `c8e1a7dcbfe07d39` |

**Yeniden üretim** (depo kökünden; ikinci komut, sürüm 1'in künyesindeki göreli Mac yolunu korumak için kökten koşulur):

```
python3 -I -B docs/arge/2026-11-10_n4/on_sayim.py --mac-kosu workspaces/olcum_mac/runs/ol7-a-9a36142 \
    --debian-kosu ~/karadul_olcum/n1_debian13 --capa-cikar ~/karadul_olcum/runs/n4-on-olcum-2026-11-10/capalar.json
python3 -I -B docs/arge/2026-11-10_n4/on_sayim.py --mac-kosu workspaces/olcum_mac/runs/ol7-a-9a36142 \
    --debian-kosu ~/karadul_olcum/n1_debian13 --capalar ~/karadul_olcum/runs/n4-on-olcum-2026-11-10/capalar.json \
    --ornekler ~/karadul_olcum/runs/n4-on-olcum-2026-11-10/ornekler.json --cikti docs/arge/2026-11-10_n4/on_sayim.json
```

## 0. Özet ve hüküm

| Onuncu Adam ölçütü (`onuncu_adam.md:156-157`) | Ölçülen | Hüküm |
|---|---|---|
| (a)-(d) bir kuralın ateşlemelerinin > %25'i ise kural M1'den önce yeni koruma alır | `is`: kalıp 1 payı toplamda %72 [69; 75], Mac tmux %66, Mac htop %45. `init`: kalıp 2 payı %5 [4; 7]. `destroy`: kalıp 3 ∪ 4 payı %80 [75; 84]; kalıp 4 hiç yok (0/301) | **`is`: yeni koruma gerekir** (elle okumayla da doğrulandı). **`init`: ölçüt aşılmadı.** **`destroy`: ölçüt aşıldı, ama yalnız kalıp 3'ün geniş tanımı yüzünden**; elle okumada `destroy` ateşlemelerinin 16/18'i gerçek yıkıcı (§3). Koruma kalıp 3'ün dar biçimine yazılmalı, `destroy` kuralının kendisi değil |
| Mac htop'ta `create` + `destroy` ateşlemesi isim bekleyenlerin < %5'i ise B4 sorusu htop'un Kapı 1'ini değiştirmez | 72/597 = %12,1 [9,7; 14,9] | **B4 sorusu htop'un Kapı 1'ini değiştirebilir; S7/S8 kararı gerekir.** Ama B4 adlarının hiçbiri ikilide tekil değil (0/72; §2.6) |
| M1 temsil: kuralın ateşleme oranı export ile isim bekleyen arasında [0,5; 2] dışındaysa ya da çağıransız pay farkı > 30 puansa M1 yalnız akıl sağlığı denetimi olur | Mac'te export yok (iki birimde 0). Debian htop export ↔ Debian htop isim bekleyen: çağıransız fark −66,9 puan; `create` 42'ye 0. Debian htop export ↔ **Mac htop** isim bekleyen: bütün kurallar bantta, çağıransız fark −25,3 [−30,1; −20,0]. redis-tools ve KS-1 çapaları: `create`/`destroy` bandın çok dışında | **tmux türü için M1 öldürme dayanağı olamaz** (redis-tools'ta F-ETKİ ateşlemesi yok denecek kadar az; çapalar temsil etmiyor). **htop türü için yalnız Debian htop export'ları savunulabilir, o da sınırda**: nokta tahminleri eşiklerin içinde, aralıkları dışına taşıyor |

En önemli üç bulgu:
1. **`is` kuralı (AD2(a), `:311`, `:399`) çoğunlukla yanlış fiil verir.** Ateşlemelerin %72'si en az bir çağrı yapan fonksiyonlarda. Bunların elle okunan 19'undan 13'ü (%68 [46; 85]) "işini çağrıda yapıp sabit bir durum kodu dönen" fonksiyon: Lua C API'sine verilen fonksiyonlar (dönüş = yığına konan sonuç sayısı), komut işleyicileri (dönüş = "yeniden çiz / işlendi" kodu), "ekle ve 1 dön". [okuma]
2. **Taslağın FK1'i hiçbir ayırıcı sarmalayıcısını tanımıyor** (119 ELF'te 0). `create` ancak "ayırıcı + hata bildirimi" sarmalayıcısı tanınırsa ateşliyor: Mac tmux 6'ya karşı 62, Mac htop 3'e karşı 39. Bu sarmalayıcı sayesinde `create` I sınıfına da ulaşıyor (Mac htop'ta I sınıfının %11,7'si); taslağın "fiilin hiç ulaşamadığı I sınıfı" (`:539`) okuması `create` için geçersiz.
3. **FK3, Onuncu Adam'ın tahmininden dört kat geniş, ama yine dar.** Dönmeyen iç fonksiyonlar (ölümcül hata bildiren sarmalayıcılar) sayılınca FK3 Mac tmux'ta %4,7, Mac htop'ta %4,5 fonksiyonda çalışıyor (Onuncu Adam: %1,1 / %1,2, `onuncu_adam.md:19`). `return -1` yolunda bırakma (kalıp 4) bu sette hiç yok; FK3'ün bu açığı burada boş.

## 1. İşlemsel tanımlar

Tanımlar sayımdan önce yazıldı; sayım sırasında dört düzeltme yapıldı (§1.4). Hepsi `on_sayim.json` → `kunye.n4.tanimlar` içinde de durur.

### 1.1 Zemin

- **Kaynak:** yalnız `static/` çıktısındaki gömülü AArch64 disassembly. p-code kullanılmadı (SSA kimliği yok; taslak `:78`). Decompile metninden yalnız iki şey alındı: imzadaki dönüş türü (`void` mi) ve Ghidra'nın "Subroutine does not return" uyarısı (yalnız denetim sayacı; yığın koruyucu çağrısından önceki uyarı sayılmaz).
- **Veri akışı:** fonksiyon içi, ileri, blok düzeyinde sabit nokta; birleştirme küme birleşimi (olası değerler). Değerler: `p_i` (girişteki x_i, i < 8), `k_c` (sabit; `w` hedefte 32 bit işaretli, yani `0xffffffff` = −1), `b` (0/1 üreten komut: `cset`, `csinc zr,zr`, `and #1`, `ubfx #,1`, `lsr #31/#63`), `r_pc` (pc'deki çağrının dönüşü), `f_{i,o}` (`p_i`'nin `o` ofsetinden yüklenen alan), `s` (yığın adresi), `?` (bilinmez). Çağrı x0-x18, x30 ve vektör yazmaçlarını öldürür, x0 = `r_pc`. `[sp]` ve `[x29]` yuvaları izlenir. Küme 8 öğeyi aşarsa `?`.
- **CFG:** blok sonu dallanma, `ret`, `br`, `brk/udf/hlt` ve dönmeyen hedefe `bl`. Dönen çıkış: `ret`, `br` (x0 bilinmez), gövde dışına dönen hedefli `b` ya da koşullu dal (kuyruk çağrısı; x0 = `r_pc`).
- **Dönmeyen çağrı:** kütüphane `donmez` ailesi (sürüm 1 listesi) ve `stack_chk_fail`; iç fonksiyon: girişten dönen çıkışa ulaşamayan iç fonksiyon, sabit nokta ile (dönmeyen hedefe `bl` blok sonudur).
- **Ana yol:** dönen bir çıkışa ulaşabilen blok. **Hata bloğu (FK3):** dönen çıkışa ulaşamayan ve gerçek dönmeyen çağrıya (`stack_chk_fail` değil) ulaşan blok.
- **Ayırıcı:** `malloc, calloc, realloc, reallocarray, strdup, strndup, aligned_alloc, valloc, memalign` ∪ FK1 ayırıcı sarmalayıcıları. **Bırakıcı:** `free` ∪ FK1 free sarmalayıcıları.
- **FK1 dar** (taslak `:324`'ün metni): bütün çağrılar tek kütüphane hedefine, dolaylı çağrı yok, her çağrıda x0 = `{p_0}`, bütün çıkışlar o çağrının dönüşü; ek koşul: ayrılan nesneye saklama yok (§1.4 madde 3). **FK1 geniş:** çağrılar ⊆ ayırıcı ∪ dönmez ∪ ileti ∪ errno ∪ dönmeyen iç fonksiyon, en az bir ayırıcı, her ayırıcı çağrısında x0 bir `p_i` içeriyor, ayrılan nesneye saklama yok, bütün çıkışlar ⊆ ayırıcı dönüşü ∪ `{k_0}`.
- **Çağrı yeri:** `bl`, `blr`, kuyruk çağrısı; derleyici eki ve CRT hedefleri hariç. **Yazar:** tabanı `sp`/`x29` olmayan saklama (sürüm 1'in `Y_yazar` işaretiyle aynı).
- **Nüfuslar:** `bekleyen` (sürüm 1'in vekili), `export` (sürüm 1'in tanımı; örnek düzeyinde), `export_tek` (export ve adı tek fiil sınıfı: M1'in evreni), `capa` (KS-1 `func_kalibi` çapası, parça değil; `kesin.py` sha256'sı KS-1 ölçümündekiyle aynı), `capa_tek`.

### 1.2 Taslağın kuralları

| Kural (taslak) | İşlemsel tanım |
|---|---|
| `destroy` (`:306`) | FK1 free sarmalayıcısı değil; ana yolda bir bırakıcı çağrısının x0'ı tam olarak `{p_i}`. Ek sayaç `destroy_her_yolda`: girişten bırakmaya uğramadan dönen çıkışa yol yok |
| `create` (`:307`) | Sarmalayıcı değil; bütün dönen çıkışların x0'ı ⊆ ayırıcı dönüşü ∪ `{k_0}` ve en az biri ayırıcı dönüşü; tabanı ⊆ ayırıcı dönüşü olan en az bir saklama. Dar: FK1 dar; geniş: FK1 geniş |
| `init` (`:308`) | Geniş ayırıcıya çağrı yok; tabanı `{p_i}`, kaynağı ⊆ `{k_*, p_*}` saklamalarla `p_i`'nin en az iki ayrı ofsetine yazılıyor |
| `is` (`:311`) | Dönüş türü `void` değil; "yazar" değil; en az bir dönen çıkış ve hepsinin x0'ı ⊆ `{k_0, k_1, b}` |

### 1.3 Onuncu Adam'ın dört kalıbı (§7 madde 1'in metniyle)

| Kalıp | İşlemsel tanım | Alt sayaçlar |
|---|---|---|
| 1: başarıda 1 / hatada 0 | Dönüş türü `void` değil; bütün dönen çıkışların x0'ı ⊆ `{k_0, k_1, b}`; en az bir çağrı yeri | `kalip1_is` = kalıp 1 ∩ `is` ateşliyor (doğrudan saklama yok). Onun içinde: `salt_okur` (bütün çağrılar `strlen, strcmp, memcmp, strchr …, ctype` listesine), `yan` (öbürleri), `yan_kutuphane` (liste dışı en az bir kütüphane çağrısı) |
| 2: alanları bırak, sıfırla | Bir bırakıcı çağrısının x0'ı `{f_{i,o}}`; `p_i`'nin en az iki ofsetine sabit/parametre yazılıyor; hiçbir bırakıcı çağrısı `p_i`'yi almıyor | `kalip2_init` = kalıp 2 ∩ `init` ateşliyor |
| 3: argümanı kullan ve bırak | `destroy` ateşliyor ve bırakıcı olmayan en az bir çağrı yeri daha var | `kalip3_arg`: o çağrılardan birinde x0 = `{p_i}` (bırakılan parametrenin kendisi) |
| 4: `return -1` yolunda bırak | `destroy`'u veren `p_i` için: girişten bırakmaya uğramadan dönen çıkış var ve biri negatif sabit dışında dönüyor; her bırakmadan sonra ulaşılan bütün dönen çıkışlar negatif sabit. Değerler **yol duyarlı**: bırakmasız yollar ve bırakma sonrası yollar ayrı akıtılır | `kalip4_sifir`: bırakma sonrası çıkışlar `{k_0}` (NULL/0), bırakmasız yolda başka değer |

Ayrıca: FK3 dar (hata bloğu doğrudan `donmez` kütüphane çağrısına iniyor) ve geniş (dönmeyen iç fonksiyon da); `ghidra_donmez` (denetim); ad tekilliği: B4 biçiminde ad = fiil + genel nesne, yani ELF içinde bir fiil tek fonksiyonda ateşliyorsa ad tekildir.

### 1.4 Sayım sırasında yapılan düzeltmeler (hepsi ilk tam koşudan sonra)

1. **Kalıp 4 yol duyarlı yapıldı.** İlk koşuda kalıp 4 her yerde 0 çıktı. Nedeni olası bir tasarım hatasıydı: ortak dönüş bloğunda `-1` ile `0` birleşince "bütün çıkışlar negatif" hiç tutmaz. Düzeltildi ve testle kilitlendi (`test_kalip4_ortak_donus_blogunda_yol_duyarli`, mutant m09). Düzeltmeden sonra da 0. Decompile metninde bağımsız arama yapıldı: `free(param_N)` ile sonraki üç satırda negatif sabit dönüş; Mac tmux, Mac htop, Debian tmux, zstd, htop, redis-tools'ta 0 aday. Bütün dosyada hem `free(param_N)` hem `return -1/0xffffffff` geçen dosya: Mac'te 2 (ikisi de aynı fonksiyonun iki çıktı kopyası; bırakma yolu 0 dönüyor), Debian tmux'ta 2 (okunmadı; aynı fonksiyonun Debian ikizi olması olası **[tahmin]**), zstd, redis-tools ve coreutils'te 0.
2. **Önceli olmayan bloklar.** İlk sürüm bu blokları (atlama tablosu hedefi olabilir) bilinmez durumla akıtıyordu. Sentetik testte koşulsuz dallanmadan sonraki dolgu komutu, hata bloğundaki parametre değerini kirletti. Artık yalnız fonksiyonda dolaylı dallanma (`br`) varsa akıtılıyor (mutant m11).
3. **FK1 kurucuyu yutmasın.** İlk geniş FK1, "ayır, alanlarına yaz, döndür" kurucusunu da sarmalayıcı sayıyordu; sarmalayıcı `create`'ten dışlandığı için `create` eksik sayılıyordu. Geniş FK1'e "x0 bir parametre içeriyor" ve "ayrılan nesneye saklama yok" eklendi. Dar FK1'e de "nesneye saklama yok" eklendi: taslağın FK1 metni (`:324`) boyutu parametreden alan bir kurucuyu sarmalayıcı sayar (mutant m12). Gerçek veride dar FK1 düzeltmeden önce de sonra da 0 sarmalayıcı buldu.
4. **Ghidra dönmez uyarısı** yığın koruyucu çağrısı hariç sayılır. Bu yapılınca Mac htop'ta uyarı ile FK3 arasındaki fark 60'tan 4'e indi; kalan 4'ü hiç dönmeyen fonksiyonlar (FK3 tanımı gereği dışarıda).

Ayrıca kalıp 1'in alt kırılımı (`salt_okur`, `yan`) ilk sayım görüldükten sonra eklendi; Onuncu Adam'ın tanımı değişmedi, hükümde o tanım kullanıldı.

## 2. Ölçüm 1: riskli deyim sayımı

### 2.1 Kural ateşlemeleri (isim bekleyen nüfus; yüzde birimin isim bekleyenlerine)

| Birim | n | is | init | create dar | create geniş | destroy | destroy her yolda |
|---|---|---|---|---|---|---|---|
| `mac/tmux` | 2 587 | 124 (%4,8) | 103 (%4,0) | 6 (%0,2) | 62 (%2,4) | 90 (%3,5) | 51 (%2,0) |
| `mac/htop` | 597 | 20 (%3,4) | 35 (%5,9) | 3 (%0,5) | 39 (%6,5) | 33 (%5,5) | 31 (%5,2) |
| `debian/tmux` | 1 916 | 97 (%5,1) | 77 (%4,0) | 2 (%0,1) | 60 (%3,1) | 65 (%3,4) | 49 (%2,6) |
| `debian/htop` | 239 | 5 (%2,1) | 10 (%4,2) | 0 (%0,0) | 0 (%0,0) | 14 (%5,9) | 14 (%5,9) |
| `debian/coreutils` | 13 485 | 352 (%2,6) | 122 (%0,9) | 79 (%0,6) | 100 (%0,7) | 66 (%0,5) | 66 (%0,5) |
| `debian/openssl` | 588 | 74 (%12,6) | 4 (%0,7) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/redis-tools` | 2 103 | 273 (%13,0) | 117 (%5,6) | 0 (%0,0) | 0 (%0,0) | 2 (%0,1) | 0 (%0,0) |
| `debian/sqlite3` | 425 | 31 (%7,3) | 35 (%8,2) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/tree` | 115 | 17 (%14,8) | 0 (%0,0) | 2 (%1,7) | 9 (%7,8) | 1 (%0,9) | 1 (%0,9) |
| `debian/zstd` | 1 908 | 89 (%4,7) | 197 (%10,3) | 42 (%2,2) | 44 (%2,3) | 30 (%1,6) | 8 (%0,4) |
| **toplam** | 23 963 | 1 082 (%4,5) | 700 (%2,9) | 134 (%0,6) | 314 (%1,3) | 301 (%1,3) | 220 (%0,9) |

- openssl, sqlite3 ve redis-tools'ta `create`/`destroy` hemen hiç ateşlemiyor: bu programlar kütüphanenin kendi ayırıcısını (`CRYPTO_free`, `sqlite3_free` …; sürüm 1 `import.en_sik`) ya da kendi ayırma katmanını kullanıyor. redis-tools'ta libc ayırıcısını doğrudan ya da FK1 biçimli sarmalayıcıyla çağıran isim bekleyen 5 (%0,2) **[nedeni doğrulanmadı]**.

### 2.2 Kalıplar

| Birim | kalıp 1 | 1 ∩ is | 1 ∩ is, yan etkili | kalıp 2 | 2 ∩ init | kalıp 3 | 3, arg | kalıp 4 | 4, sıfır |
|---|---|---|---|---|---|---|---|---|---|
| `mac/tmux` | 169 (%6,5) | 82 (%3,2) | 75 (%2,9) | 16 (%0,6) | 12 (%0,5) | 79 (%3,1) | 20 (%0,8) | 0 | 1 (%0,0) |
| `mac/htop` | 27 (%4,5) | 9 (%1,5) | 8 (%1,3) | 6 (%1,0) | 1 (%0,2) | 26 (%4,4) | 20 (%3,4) | 0 | 0 |
| `debian/tmux` | 149 (%7,8) | 76 (%4,0) | 75 (%3,9) | 11 (%0,6) | 6 (%0,3) | 55 (%2,9) | 7 (%0,4) | 0 | 1 (%0,1) |
| `debian/htop` | 10 (%4,2) | 5 (%2,1) | 4 (%1,7) | 3 (%1,3) | 1 (%0,4) | 13 (%5,4) | 11 (%4,6) | 0 | 0 |
| `debian/coreutils` | 422 (%3,1) | 222 (%1,6) | 197 (%1,5) | 30 (%0,2) | 12 (%0,1) | 43 (%0,3) | 27 (%0,2) | 0 | 0 |
| `debian/openssl` | 138 (%23,5) | 68 (%11,6) | 68 (%11,6) | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/redis-tools` | 357 (%17,0) | 244 (%11,6) | 228 (%10,8) | 0 | 0 | 2 (%0,1) | 2 (%0,1) | 0 | 2 (%0,1) |
| `debian/sqlite3` | 36 (%8,5) | 23 (%5,4) | 20 (%4,7) | 2 (%0,5) | 1 (%0,2) | 0 | 0 | 0 | 0 |
| `debian/tree` | 19 (%16,5) | 16 (%13,9) | 16 (%13,9) | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/zstd` | 70 (%3,7) | 34 (%1,8) | 29 (%1,5) | 15 (%0,8) | 2 (%0,1) | 22 (%1,2) | 7 (%0,4) | 0 | 4 (%0,2) |
| **toplam** | 1 397 (%5,8) | 779 (%3,3) | 720 (%3,0) | 83 (%0,3) | 35 (%0,1) | 240 (%1,0) | 94 (%0,4) | 0 | 8 (%0,0) |

### 2.3 Riskli pay: kuralın ateşlemelerinde kalıbın payı (Onuncu Adam'ın %25 ölçütü)

Köşeli ayraç: Wilson %95. **Kalın**: %25'i aşıyor (nokta tahmini).

| Birim | is ← kalıp 1 | is ← kalıp 1, yan etkili | init ← kalıp 2 | destroy ← kalıp 3 ∪ 4 | destroy ← kalıp 3, arg | destroy ← kalıp 4 | F-ETKİ ilk sürüm (create ∪ destroy) |
|---|---|---|---|---|---|---|---|
| `mac/tmux` | **82/124 = %66** [57; 74] | **75/124 = %60** | 12/103 = %12 [7; 19] | **79/90 = %88** [79; 93] | 20/90 = %22 [15; 32] | 0/90 [0; 4] | **79/152 = %52** [44; 60] |
| `mac/htop` | **9/20 = %45** [26; 66] | **8/20 = %40** | 1/35 = %3 [1; 15] | **26/33 = %79** [62; 89] | **20/33 = %61** [44; 75] | 0/33 [0; 10] | **26/72 = %36** [26; 48] |
| `debian/tmux` | **76/97 = %78** | **75/97 = %77** | 6/77 = %8 | **55/65 = %85** | 7/65 = %11 | 0/65 | **55/125 = %44** |
| `debian/htop` | **5/5** | **4/5** | 1/10 | **13/14** | **11/14** | 0/14 | **13/14** |
| `debian/coreutils` | **222/352 = %63** | **197/352 = %56** | 12/122 = %10 | **43/66 = %65** | **27/66 = %41** | 0/66 | **43/166 = %26** |
| `debian/openssl` | **68/74 = %92** | **68/74** | 0/4 | — | — | — | — |
| `debian/redis-tools` | **244/273 = %89** | **228/273 = %84** | 0/117 | **2/2** | **2/2** | 0/2 | **2/2** |
| `debian/sqlite3` | **23/31 = %74** | **20/31 = %65** | 1/35 | — | — | — | — |
| `debian/tree` | **16/17** | **16/17** | — | 0/1 | 0/1 | 0/1 | 0/10 |
| `debian/zstd` | **34/89 = %38** | **29/89 = %33** | 2/197 = %1 | **22/30 = %73** | 7/30 = %23 | 0/30 | **22/72 = %31** |
| **toplam** | **779/1 082 = %72** [69; 75] | **720/1 082 = %67** [64; 69] | 35/700 = %5 [4; 7] | **240/301 = %80** [75; 84] | **94/301 = %31** [26; 37] | 0/301 [0; 1] | **240/613 = %39** [35; 43] |

### 2.4 Sınıf kırılımı

| Mac tmux | n | is | 1 ∩ is | init | 2 ∩ init | create geniş | destroy | kalıp 3 | FK3 geniş |
|---|---|---|---|---|---|---|---|---|---|
| K | 951 | 25 (%2,6) | 25 | 48 (%5,0) | 12 | 31 (%3,3) | 90 (%9,5) | 79 | 90 (%9,5) |
| I | 1 220 | 56 (%4,6) | 56 | 35 (%2,9) | 0 | 31 (%2,5) | 0 | 0 | 32 (%2,6) |
| Y | 416 | 43 (%10,3) | 1 | 20 (%4,8) | 0 | 0 | 0 | 0 | 0 |

| Mac htop | n | is | 1 ∩ is | init | 2 ∩ init | create geniş | destroy | kalıp 3 | FK3 geniş |
|---|---|---|---|---|---|---|---|---|---|
| K | 230 | 3 (%1,3) | 3 | 12 (%5,2) | 1 | 8 (%3,5) | 33 (%14,3) | 26 | 25 (%10,9) |
| I | 265 | 6 (%2,3) | 6 | 13 (%4,9) | 0 | 31 (%11,7) | 0 | 0 | 2 (%0,8) |
| Y | 102 | 11 (%10,8) | 0 | 10 (%9,8) | 0 | 0 | 0 | 0 | 0 |

| Toplam | n | is | 1 ∩ is | init | 2 ∩ init | create geniş | destroy | kalıp 3 | FK3 geniş |
|---|---|---|---|---|---|---|---|---|---|
| K | 12 698 | 342 (%2,7) | 342 | 313 (%2,5) | 35 | 217 (%1,7) | 301 (%2,4) | 240 | 4 691 (%36,9) |
| I | 7 305 | 430 (%5,9) | 430 | 199 (%2,7) | 0 | 97 (%1,3) | 0 | 0 | 1 091 (%14,9) |
| Y | 3 960 | 310 (%7,8) | 7 | 188 (%4,7) | 0 | 0 | 0 | 0 | 0 |

- **Yapraklar:** `create`/`destroy` 0 (çağrı ister; Onuncu Adam §1.2 madde 1 doğrulandı). Yapraklarda `is` (Mac tmux 43, Mac htop 11) ve `init` (20, 10) ateşliyor.
- **I sınıfı:** `destroy` 0 (free sarmalayıcısı neredeyse yok; ELF'te FK1 free Mac'te 0). `create` geniş FK1 sarmalayıcısıyla I'ya ulaşıyor: Mac htop 31/265 (%11,7), Mac tmux 31/1 220 (%2,5).
- **`is`'in kalıp 1 olmayan kısmı tam olarak çağrısız fonksiyonlardır** (tanım gereği): Mac tmux 124 − 82 = 42, Mac htop 20 − 9 = 11, toplam 303 **[hesap]**. Bunların doğruluğu okunmadı.

### 2.5 Boyut kırılımları

Gövde boyutu (komut sayısı), Mac iki birim:

| Mac tmux | n | is | 1 ∩ is | init | create geniş | destroy | kalıp 3 |
|---|---|---|---|---|---|---|---|
| ≤ 8 | 321 | 23 | 7 | 11 | 2 | 1 | 1 |
| 9-32 | 1 000 | 65 | 41 | 26 | 17 | 52 | 43 |
| 33-128 | 962 | 32 | 30 | 41 | 31 | 27 | 26 |
| ≥ 129 | 304 | 4 | 4 | 25 | 12 | 10 | 9 |

| Mac htop | n | is | 1 ∩ is | init | create geniş | destroy | kalıp 3 |
|---|---|---|---|---|---|---|---|
| ≤ 8 | 96 | 10 | 2 | 8 | 0 | 0 | 0 |
| 9-32 | 255 | 7 | 4 | 15 | 13 | 33 | 26 |
| 33-128 | 194 | 3 | 3 | 7 | 22 | 0 | 0 |
| ≥ 129 | 52 | 0 | 0 | 5 | 4 | 0 | 0 |

- `init` büyük gövdelerde yoğun (≥ 129 komut: Mac tmux %8,2; toplam %6,6). Büyük gövdede iki ofsete sabit yazmak her işin yan ürünüdür; elle okunan kalıp 2 örneklerinin çoğu tuş işleyicisi, durum makinesi, dizin gezinme gibi büyük fonksiyonlardı (§3). FK2'nin büyük gövde sınırı (`:325`, `:333`) F-ETKİ'ye uygulanmıyor.

KS-1 boyut tabakası (program düzeyi, `ks1_sinif.json`):

| Tabaka | n | is | init | create geniş | destroy | is riskli | init riskli | destroy riskli |
|---|---|---|---|---|---|---|---|---|
| `debian/buyuk` (redis-tools) | 2 103 | 273 (%13,0) | 117 (%5,6) | 0 | 2 (%0,1) | 244/273 | 0/117 | 2/2 |
| `debian/kucuk` | 14 025 | 400 (%2,9) | 157 (%1,1) | 109 (%0,8) | 67 (%0,5) | 261/400 | 13/157 | 43/67 |
| `debian/orta` | 4 651 | 265 (%5,7) | 288 (%6,2) | 104 (%2,2) | 109 (%2,3) | 183/265 | 9/288 | 90/109 |
| `mac/buyuk` (tmux) | 2 587 | 124 (%4,8) | 103 (%4,0) | 62 (%2,4) | 90 (%3,5) | 82/124 | 12/103 | 79/90 |
| `mac/orta` (htop) | 597 | 20 (%3,4) | 35 (%5,9) | 39 (%6,5) | 33 (%5,5) | 9/20 | 1/35 | 26/33 |

Bütün tabakalarda `is` ve `destroy` için riskli pay %25'in üstünde; `init` için altında.

### 2.6 Ad tekilliği (B4: fiil + genel nesne)

| Birim | create dar | create geniş | destroy | is | init |
|---|---|---|---|---|---|
| `mac/tmux` | 0/6 | 0/62 | 0/90 | 0/124 | 0/103 |
| `mac/htop` | 0/3 | 0/39 | 0/33 | 0/20 | 0/35 |
| `debian/htop` | — | — | 0/14 | 0/5 | 0/10 |
| `debian/coreutils` | 10/79 | 13/100 | 4/66 | 51/352 | 13/122 |
| **toplam** | 10/134 | 13/314 | 7/301 | 51/1 082 | 13/700 |

(Pay: o fiilin ELF içinde tek fonksiyonda ateşlediği durum sayısı. coreutils'in tekilleri küçük ELF'lerdendir.) Mac'te B4 biçimli hiçbir F-ETKİ adı ekten önce tekil değil. Onuncu Adam'ın "bilgi taşıyan yakın" önerisi (`onuncu_adam.md:126`) kabul edilirse F-ETKİ'nin B4 adları Mac'te o sayıya **hiç** katkı vermez; nesne B3'ten (modül öneki) gelmedikçe. B3'ün erişimi burada ölçülmedi (KS-1 çapası ister; Mac htop'ta çapa 0).

### 2.7 FK3 ve FK1

| Birim | FK3 dar | FK3 geniş | Ghidra dönmez uyarısı | hiç dönmeyen | dönmeyen iç (ELF) | FK1 free | FK1 ayırıcı dar | FK1 ayırıcı geniş | ayırıcı çağıran | bırakıcı çağıran |
|---|---|---|---|---|---|---|---|---|---|---|
| `mac/tmux` | 10 (%0,4) | 122 (%4,7) | 141 (%5,5) | 19 | 20 | 0 | 0 | 5 | 472 (%18,2) | 493 (%19,1) |
| `mac/htop` | 3 (%0,5) | 27 (%4,5) | 31 (%5,2) | 4 | 4 | 0 | 0 | 6 | 97 (%16,2) | 84 (%14,1) |
| `debian/tmux` | 9 (%0,5) | 107 (%5,6) | 112 (%5,8) | 7 | 9 | 3 | 0 | 6 | 399 (%20,8) | 393 (%20,5) |
| `debian/htop` | 2 (%0,8) | 4 (%1,7) | 3 (%1,3) | 2 | 8 | 0 | 0 | 6 | 19 (%7,9) | 37 (%15,5) |
| **toplam** | 2 656 (%11,1) | 5 782 (%24,1) | 5 977 (%24,9) | 1 095 | 1 366 | 18 | **0** | 1 188 | 4 187 (%17,5) | 1 923 (%8,0) |

- Mac'te FK3 geniş ile Ghidra'nın uyarısı arasındaki fark tam olarak hiç dönmeyen fonksiyon sayısıdır (tmux 141 − 122 = 19, htop 31 − 27 = 4); FK3 tanımı onları dışarıda bırakır. Yani Mac'te bağımsız iki yol aynı kümeyi veriyor **[hesap]**. Debian birimlerinde fark bu kadar düzgün değil (ör. coreutils 4 772 − 4 646 = 126, hiç dönmeyen 911); nedeni incelenmedi.
- Onuncu Adam'ın %1,1 / %1,2'si `K_donmez`'den (doğrudan `donmez` kütüphane çağrısı; `onuncu_adam.md:19`). Dönmeyen iç sarmalayıcılar sayılınca FK3'ün iş gördüğü fonksiyon Mac'te ≈ dört kat **[hesap]**.

## 3. Elle okuma: sayacın yanlış ateşlemesi ve deyimin gerçekliği

Örnekler `--ornekler` ile, ölçü başına sha1 sırasıyla (tohumsuz) 10 tane seçildi; havuz bütün birimler, `@mac` yalnız Mac. Okuma uçbirimde, decompile C metninden yapıldı; adresler yalnız depo dışındaki `ornekler.json`'da. İki soru soruldu: (A) **Tanım tuttu mu?** (sayacın kendi tanımına göre doğru mu ateşledi) (B) **Deyim riskli mi?** (taslağın kuralı bu fonksiyona yanlış fiil verir mi) [okuma].

| Ölçü | Okunan | (A) tanım tuttu | (B) riskli deyim | Okunanların niteliği |
|---|---|---|---|---|
| `kalip1_is` (havuz) | 10 | 10 | 6/10 [31; 83] | 3 Lua C API fonksiyonu (dönüş = sonuç sayısı, iş yığına itmede), 1 "ekle ve 1 dön", 1 "iki dizin kur, başarıda 1", 1 "parametreyi bırak, 0 dön"; doğru yüklem 4 (karşılaştırma, tabloda var mı, dosya sistemi sınaması, ağaçta var mı) |
| `kalip1_is@mac` | 9 yeni + 1 ortak | 10 | 7/10 [40; 89] | 6 komut işleyicisi (iş çağrılarda; dönüş "işlendi / yeniden çiz" kodu), 1 "çağır, 0 dön"; doğru yüklem 3 |
| `kalip2` | 10 | 10 | deyim 10/10 | 1 söküm, 1 "eskiyi bırak, yenisini yaz"; 8 büyük ya da çok işli fonksiyon (tuş işleyicisi, akış durum makinesi, dizin gezinme, sıralayıp büyütme) içinde "alanı bırak, sıfırla" |
| `kalip2_init` | 10 | 10 | 10/10 [72; 100] | hepsinde `init` yanlış fiil: sıfırlama, söküm ya da büyük işin parçası |
| `kalip3` | 10 | 10 | 2/10 [6; 51] | 8 gerçek yıkıcı (alt nesneleri bırakıp kendini bırakan; geri sayımlı bırakma dahil); 2 riskli: verisini kullanıp bırakan geri çağrı, sahipliği alan ekleme fonksiyonu |
| `kalip3_arg` | 10 | 10 | 1/10 [2; 40] | 9 gerçek yıkıcı ("kendi alt işlevini çağır, sonra bırak"); 1 riskli: yeniden ayırma (eskiyi sil, yeniyi dön) |
| `kalip4` | 0 (havuz boş) | — | — | §1.4 madde 1'deki bağımsız arama da 0 |
| `kalip4_sifir` | 8 (hepsi) | 8 | 4/8 [22; 79] | 2 riskli: Lua ayırıcı geri çağrısı (boyut 0 ise bırak); 2 riskli: sahipliği alan ekleme (Debian ve Mac aynı fonksiyon); 4 doğru: 0'ın başarı olduğu zstd yıkıcıları |
| `fire_destroy` (havuz) | 10 | 10 | 0/10 [0; 28] | hepsi gerçek yıkıcı |
| `fire_destroy@mac` | 8 yeni + 2 ortak | 10 | 2/10 [6; 51] | 8 gerçek yıkıcı (ikisi satır içi ağaçtan çıkarma yüzünden 280-300 satır); 2 riskli: aldığı dizgiyi tüketen biçim geri çağrısı, kullanıp sayaç sıfırsa bırakan geri çağrı |
| `fire_create_genis` | 10 | 10 | 3/10 [11; 60] yanlış | 6 gerçek kurucu, 1 yakın (yapı açıp döndüren), 3 Onuncu Adam kalıp 6: okuyup yeni dizgi dönen (2'si aynı yardımcının iki ELF'teki kopyası) |

- **Sayacın kendi tanımına göre yanlış ateşlemesi: 0/95 okuma** (yinelemeler dahil; Wilson üst sınırı %3,9) **[hesap]**. Veri akışı sayaçları, tanımladıkları şeyi buluyor.
- **Ama Onuncu Adam'ın tanımları riskli deyimi ayırmakta çok farklı:** kalıp 1 ve kalıp 2 ∩ `init` neredeyse hep riskli; kalıp 3 (geniş) ve kalıp 3_arg çoğunlukla sıradan yıkıcı. Kalıp 3'ün "parametreyi bırakan ve başka çağrı da yapan" tanımı yıkıcının kendisini tarif ediyor: yıkıcılar alt nesnelerini bırakmak için başka çağrı yapar.
- **`destroy` kuralının kendisi kesin görünüyor:** okunan 18 farklı ateşlemenin 16'sı gerçek yıkıcı (%89 [67; 97]); yanlışların ikisi de "verisini/argümanını tüketen geri çağrı". Kalıp 3 ∪ 4 payı (%80) bu yüzden riski olduğundan çok büyük gösteriyor **[okuma]**.
- **`is` için kaba kestirim:** ateşlemelerin %72'si kalıp 1, kalıp 1'in okunan 19 farklı örneğinin 13'ü riskli → `is` ateşlemelerinin ≈ %49'u yanlış fiil **[tahmin; iki oranın çarpımı, n = 19]**.

## 4. Ölçüm 2: M1 temsil denetimi

### 4.1 Mac'te export yok

Mac tmux ve Mac htop'ta export sayısı 0 (strip'li Mach-O; sürüm 1 `adli.export`). M1'in Mac evreni yok. Onuncu Adam'ın önerdiği mekanik evren (KS-1 `func_kalibi` çapaları) aynı ölçülerle karşılaştırıldı: Mac tmux 150, Debian tmux 97, openssl 15; Mac htop 0. Çapaların adı `kesin.py`'nin dizgiden çıkardığı addır, GT değildir; sayım dosyasına ad yazılmadı.

### 4.2 Karşılaştırmalar

Oran farkı: A − B, yüzde puan, Newcombe %95. Oran: A/B, Katz %95. Bant: [0,5; 2]. Ortanca: komut sayısı ve çağrı yeri sayısı.

**(1) Debian htop export (A, n = 366) ↔ Debian htop isim bekleyen (B, n = 239).** Ortanca komut 32 / 42, çağrı yeri 2 / 3.

| Ölçü | A | B | fark (puan) | oran A/B |
|---|---|---|---|---|
| çağıransız | 40 (%10,9) | 186 (%77,8) | −66,9 [−72,5; −60,2] | 0,14 [0,10; 0,19] |
| yaprak (Y) | 71 (%19,4) | 29 (%12,1) | +7,3 [+1,2; +12,9] | 1,60 [1,07; 2,38] |
| `is` | 8 (%2,2) | 5 (%2,1) | +0,1 [−2,8; +2,5] | 1,04 [0,35; 3,16] |
| `init` | 15 (%4,1) | 10 (%4,2) | −0,1 [−3,8; +3,1] | 0,98 [0,45; 2,14] |
| `create` geniş | 42 (%11,5) | 0 (%0,0) | +11,5 [+8,2; +15,1] | — (B = 0) |
| `destroy` | 18 (%4,9) | 14 (%5,9) | −0,9 [−5,1; +2,6] | 0,84 [0,43; 1,66] |
| create ∪ destroy | 60 (%16,4) | 14 (%5,9) | +10,5 [+5,5; +15,3] | 2,80 [1,60; 4,89] |
| ayırıcı çağıran | 78 (%21,3) | 19 (%8,0) | +13,4 [+7,7; +18,6] | 2,68 [1,67; 4,31] |

Hüküm: **yalnız akıl sağlığı** (çağıransız 67 puan; `create` bandın dışında). Debian htop'ta `create` yalnız export'larda ateşliyor, static fonksiyonlarda hiç ateşlemiyor (ELF'te 6 geniş ayırıcı sarmalayıcısı bulunduğu hâlde). Onuncu Adam'ın "kolay vakalar export'ta yoğunlaşır" tahmini (`onuncu_adam.md:79`) `create` için doğrulandı.

**(2) Debian htop export (A) ↔ Mac htop isim bekleyen (B, n = 597).** M3'ün htop hedefi budur. Ortanca komut 32 / 26, çağrı yeri 2 / 2.

| Ölçü | A | B | fark (puan) | oran A/B |
|---|---|---|---|---|
| çağıransız | 40 (%10,9) | 216 (%36,2) | −25,3 [−30,1; −20,0] | 0,30 [0,22; 0,41] |
| `is` | 8 (%2,2) | 20 (%3,4) | −1,2 [−3,2; +1,2] | 0,65 [0,29; 1,47] |
| `init` | 15 (%4,1) | 35 (%5,9) | −1,8 [−4,5; +1,3] | 0,70 [0,39; 1,26] |
| `create` geniş | 42 (%11,5) | 39 (%6,5) | +4,9 [+1,3; +9,0] | 1,76 [1,16; 2,66] |
| `destroy` | 18 (%4,9) | 33 (%5,5) | −0,6 [−3,4; +2,5] | 0,89 [0,51; 1,56] |
| create ∪ destroy | 60 (%16,4) | 72 (%12,1) | +4,3 [−0,1; +9,1] | 1,36 [0,99; 1,87] |
| kalıp 1 ∩ is | 2 (%0,5) | 9 (%1,5) | −1,0 [−2,4; +0,6] | 0,36 [0,08; 1,67] |
| kalıp 3 | 13 (%3,5) | 26 (%4,4) | −0,8 [−3,2; +2,0] | 0,82 [0,42; 1,57] |

Yalnız tek sınıflı export'larla (M1'in evreni, n = 263): `create` 1,98 [1,28; 3,06], create ∪ destroy 1,61 [1,16; 2,23], çağıransız −26,3 [−31,3; −20,7].

Hüküm: **nokta tahminleriyle öldürme dayanağı olabilir; aralıklarla sınırda.** `create`'in oranının üst sınırı 2'yi, çağıransız farkın alt sınırı −30'u aşıyor. Neden yakın: Mac htop'ta bütün fonksiyonlar adsız, yani "isim bekleyen" bütün programdır; Debian htop'ta isim bekleyen yalnız static kısımdır. Onuncu Adam'ın "nüfus farklı" itirazı (§2.1) Debian htop'un static kısmı için tam doğru, M3'ün hedefi olan Mac htop için zayıf.

**(3) redis-tools (ayar birimi).** export ↔ isim bekleyen: `is` 0,41 [0,35; 0,47], `destroy` 30'a 2, `create` 4'e 0; çağıransız +7,8 puan. Tek sınıflı export ↔ **Mac tmux** isim bekleyen: `create` 0,04 [0,01; 0,10], `destroy` 0,03 [0,01; 0,07], ayırıcı çağıran 0,01, çağıransız +21,3 [+19,0; +23,6]. Hüküm: **yalnız akıl sağlığı; F-ETKİ'yi ayarlamak için malzeme yok** (tek sınıflı export'larda `create` 4, `destroy` 4 ateşleme).

**(4) KS-1 `func_kalibi` çapaları ↔ isim bekleyen.**

| | Mac tmux (150 / 2 587) | Debian tmux (97 / 1 916) | openssl (15 / 588) |
|---|---|---|---|
| ortanca komut | 87,5 / 31 | 96 / 41 | 202 / 67 |
| yaprak | 0 / %16,1 | 0 / %15,7 | 0 / %9,0 |
| çağıransız fark | −15,1 [−20,3; −8,2] | −17,4 | −34,7 |
| `is` oranı | 0,14 [0,02; 0,99] | 0,20 | 1,59 |
| `create` geniş oranı | 2,23 [1,09; 4,56] (8 ateşleme) | 1,98 (6) | — (0) |
| `destroy` oranı | 0,38 [0,10; 1,54] (2 ateşleme) | 0,30 (1) | — (0) |
| hüküm | yalnız akıl sağlığı | yalnız akıl sağlığı | yalnız akıl sağlığı |

Çapalar `__func__` dizgisini bir günlük çağrısına veren, büyük, yaprak olmayan fonksiyonlardır. F-ETKİ'nin ilk sürüm kuralları onlarda 10 (Mac tmux) ve 7 (Debian tmux) kez ateşliyor; n < 10 olan kural için taslağın D4'ü işler (`:518`).

### 4.3 Hüküm (Onuncu Adam §7 madde 2)

| M1 evreni | Hedef nüfus | Hüküm |
|---|---|---|
| Debian htop export (tutma) | Debian htop isim bekleyen | yalnız akıl sağlığı |
| Debian htop export (tutma) | Mac htop isim bekleyen (M3 hedefi) | nokta tahminiyle öldürme dayanağı olabilir; aralıklarla sınırda |
| redis-tools export (ayar) | redis-tools ve Mac tmux isim bekleyen | yalnız akıl sağlığı; F-ETKİ için ölçülecek ateşleme yok |
| KS-1 çapaları | Mac tmux, Debian tmux, openssl | yalnız akıl sağlığı; F-ETKİ'de n < 10 |

**M1'in fiil uyumu (export adındaki fiil ile kuralın fiili) bilerek hesaplanmadı.** Debian htop tutma birimidir ve taslak onun bir kez, kurallar donduktan sonra okunmasını şart koşuyor (`:460`). Bu ölçüm yalnız yapısal sayaçları ve ateşleme sayısını okudu; ateşleme × ad fiili çapraz tablosu üretilmedi.

## 5. Hüküm: hangi kural ve koruma etkileniyor

| Kural / koruma | Etki | Dayanak |
|---|---|---|
| AD2(a) `is` (`:311`, `:399`) | **M1'e girmeden yeni koruma gerekir.** Öneri: ilk sürümden çıkar ya da çağrısız fonksiyonlarla sınırla (Onuncu Adam §8 madde 2). Sınırlanırsa erişim Mac tmux 42, Mac htop 11; doğrulukları ölçülmedi | §2.3, §3 |
| `init` (`:308`) | Mekanik ölçüt aşılmadı (%5). Ama kalıp 2 ∩ `init`'in okunan 10'u da yanlış fiil. "Bırakma çağrısı yok" koşulunu eklemek ucuz ve 35 yanlışı siler. Büyük gövdelerde yoğunlaşma (≥ 129 komut %6,6) FK2'nin büyük gövde sınırını F-ETKİ'ye de istiyor | §2.3, §2.5, §3 |
| `destroy` (`:306`) | Ölçütün harfiyle aşıldı (%80); kanıta göre kural kesin (16/18 okuma). Koruma kalıp 3'ün **dar** biçimine yazılmalı: geri çağrı olarak kaydedilen ya da ayrıştırdığı/aldığı veriyi tüketip bırakan fonksiyon. Kalıp 3'ün geniş tanımı koruma olarak kullanılırsa `destroy`'un neredeyse hepsi elenir | §2.3, §3 |
| `create` (`:307`) | (a)-(d) uygulanmaz. Kalıp 6 (okuyup yeni dizgi dönen) okunan 10'un 3'ünde. Dar FK1 ile `create` neredeyse hiç ateşlemez | §2.1, §2.7, §3 |
| FK1 (`:314`, `:324`) | Metniyle hiçbir ayırıcı sarmalayıcısını tanımıyor (0/119 ELF). "Ayırıcı + hata bildirimi" biçimi ve "ayrılan nesneye yazmıyor" koşulu yazılmalı | §1.4, §2.7 |
| FK3 (`:73`, `:326`) | "Dönmeyen çağrı" dönmeyen iç fonksiyonları kapsamalı; o zaman Mac'te ≈ %4,5-4,7. Kalıp 4 açığı bu sette boş | §2.7 |
| FK2 (`:325`) | Büyük gövde sınırı yalnız F-API'de; F-ETKİ'nin `init` ve kalıp 2 ateşlemeleri büyük gövdelerde | §2.5 |
| M1, S16, S17 (`:460-461`) | tmux türü için öldürme dayanağı değil. htop türü için yalnız Debian htop, sınırda. redis-tools F-ETKİ'yi ayarlayamaz | §4 |
| B4, S7, S8 (`:239-240`, `:541`) | Mac htop'ta create ∪ destroy %12,1 ≥ %5 → B4 kararı htop'un Kapı 1'ini değiştirebilir. B4 adlarının hiçbiri tekil değil | §2.6 |

## 6. Taslakta değişmesi gereken yerler

`fiil_onkayit_taslak.md` (bu görevde düzenlenmedi):

1. **`:22-23`** sha256'lar eskidi: `on_sayim.py` → `d3e3b9ed955c2f89`, `on_sayim.json` → `750c86a4d3d6b09b`. **`:25`** yeniden üretim komutuna `--capa-cikar` adımı ve `--capalar` eklenmeli (bu belgenin başı).
2. **`:73`, `:326` (FK3):** "dönmeyen çağrı" tanımına dönmeyen iç fonksiyonlar (sabit nokta) ve `stack_chk_fail`'in hata yolu sayılmadığı yazılmalı.
3. **`:295` (F-ETKİ satırı) ve `:538-539` (§6.8):** "yaprak + yalnız bellek/dizgi" havuzu yerine ölçülen ateşleme: create ∪ destroy Mac tmux 152 (%5,9), Mac htop 72 (%12,1); yapraklarda 0; `create` I sınıfına ulaşıyor (Mac htop 31). "Fiilin hiç ulaşamadığı I sınıfı" satırı `create` için düzeltilmeli.
4. **`:302`:** "bütün yollarda" iki okumaya açık. `destroy` için ölçüldü: bırakmasız dönüş yolu olmayan ateşleme Mac tmux 51/90, Mac htop 31/33 (NULL denetimi bu yolu açar). Hangisinin kural olduğu yazılmalı.
5. **`:308` (`init`):** "bırakma çağrısı yok" eklenmeli; FK2'nin büyük gövde sınırı F-ETKİ'ye de uygulanmalı (`:325`, `:333`).
6. **`:311` ve `:399` (`is`, AD2(a)):** ilk sürümden çıkarılmalı ya da çağrısız fonksiyonlarla sınırlanmalı; "ilk sürümde" (`:399`) ile `:295` çelişkisi de böylece kalkar.
7. **`:314`, `:324` (FK1):** dar FK1 ölçümde 0 sarmalayıcı buldu. "Ayırıcı + hata bildirimi" sarmalayıcısı (ayırıcı, dönmez ve ileti çağrıları; parametre ayırıcıya gidiyor; nesneye yazmıyor; ayırıcı dönüşünü ya da 0 dönüyor) ve dar FK1'e "ayrılan nesneye yazmıyor" eklenmeli.
8. **`:460-461` (S16, S17) ve `:593` (§8.1 madde 5):** "K/I/Y dağılımı yakın" yerine bu ölçüm: Debian htop'ta çağıransız fark 67 puan, `create` 42'ye 0; Mac htop'a karşı sınırda. redis-tools ayar birimi olarak F-ETKİ için işe yaramıyor (`create` 0, `destroy` 2); F-ETKİ'nin ayarı için başka birim ya da M2 gerekir.
9. **`:471` (ek evren):** KS-1 çapaları "isteğe bağlı evren" olarak kalabilir ama F-ETKİ için D4'e düşer (n < 10) ve temsil etmez (§4.2 madde 4).
10. **`:541`:** htop okuması ölçüyle güncellenmeli: create ∪ destroy %12,1; B4 adlarının ikilide tekil oranı 0/72.
11. **§6.3 karşıt listesi:** Onuncu Adam §8 madde 1'deki ek çiftler bu ölçümde sınanmadı; ama `is` ↔ değiştiren sınıflar çiftinin ne kadar sık olacağını §3 gösteriyor (okunan 19'un 13'ü).

`onuncu_adam.md` için not (düzenlenmedi): `:19` ve `:46`'daki FK3 kapsamı (%1,1 / %1,2) dar tanımdır; geniş tanımla %4,7 / %4,5. §3 kalıp 4 bu sette hiç görülmedi. §7(c)'nin kalıp 3 tanımı yıkıcıları da kapsıyor; ölçüt olarak dar biçimi gerekir.

## 7. Doğrulama

### 7.1 Eski alanlar

`git show HEAD:docs/arge/2026-11-10_n4/on_sayim.json` ile yeni çıktı yaprak yaprak karşılaştırıldı: 2 347 yaprağın 2 345'i aynı, eksik 0. Farklı iki yaprak beklenen künye alanlarıdır: `kunye.surum` 1 → 2, `kunye.betik_sha256`. Ayrıca değiştirilmemiş sürüm 1 betiği aynı girdilerle koşuldu; çıktı depodaki `on_sayim.json` ile bayt bayt aynıydı (taban yeniden üretilebilir).

### 7.2 Belirlenimcilik

`PYTHONHASHSEED=0` ve `4242` ile iki tam koşu: `on_sayim.json` ve örnek dosyası bayt bayt aynı. Test `test_belirlenimcilik_iki_tohum` aynı şeyi sentetik girdide kilitler.

### 7.3 Testler ve mutantlar

`python -m pytest tests/test_n4_on_sayim.py -q`: 24 geçti. Yalıtılmış kopyada (`PYTHONDONTWRITEBYTECODE=1`, her mutant farklı uzunlukta, betik yolu `N4_ON_SAYIM_YOLU` ile) 12 elle mutant, 12'si öldü; değiştirilmemiş betik 24/24 geçti:

| # | Mutant | Öldüren test |
|---|---|---|
| m01 | parametre testi alanı da parametre sayar | `test_kalip2_alan_birak_sifirla` |
| m02 | `is`'te `void` denetimi yok | `test_void_donuslu_is_ateslemez` |
| m03 | kalıp 4'te 0 da negatif | `test_kalip4_ortak_donus_blogunda_yol_duyarli` |
| m04 | dönmeyen `bl` blok sonu türü vermez | `test_fk3` |
| m05 | geniş FK1'de dönmez çağrı izinsiz | `test_create_genis_ve_dar` |
| m06 | `cset` 0/1 üretmez | `test_kalip1_is_ve_alt_kirilim` |
| m07 | Ghidra uyarısında yığın koruyucu dışlanmaz | `test_c_ozeti_donus_turu_ve_donmez_uyarisi` |
| m08 | Newcombe alt sınırı eksik | `test_wilson_newcombe_katz` |
| m09 | kalıp 4 yol duyarsız | `test_kalip4_ortak_donus_blogunda_yol_duyarli` |
| m10 | ad tekilliği ≥ 1'i tekil sayar | `test_ad_tekil` |
| m11 | önceli olmayan bloklar hep bilinmez girişle akar | `test_kalip4_ortak_donus_blogunda_yol_duyarli` |
| m12 | geniş FK1 kurucuyu da kapsar | `test_create_genis_ve_dar` (ilk turda yaşadı; boyutu parametreden alan kurucu testi eklenince öldü) |

### 7.4 Doğrulanamayanlar

- **Veri akışının sınırları:** dolaylı dallanmalı (`br`) fonksiyonlarda dönüş bilinmez sayılır, `is` ve `create` orada kaçar (bu sayaçlar alt sınırdır). `sp` ile `x29` yuvaları arasındaki takma ad izlenmez (tutucu). Alan alanı (`p->a->b`) izlenmez. Yol duyarlılık yalnız kalıp 4'te.
- **Riskli deyim yargıları** benim okumamdır: ad yok, GT yok, n = 8-19. Aralıklar geniş.
- **Okunmayanlar:** `is`'in çağrısız kısmı (303), kalıp 2 dışındaki `init` ateşlemeleri, `create_dar` örnekleri, FK3 örnekleri. Bunların doğruluğu bilinmiyor.
- **Export nüfusu örnek düzeyinde** sayıldı (redis-tools 4 ELF, 8 394 örnek); M1 ad düzeyinde tekilleştirir.
- **`kesin.py` koşuldu:** çapaları çıkarmak için `--capa-cikar` kipi KS-1'in `kesin.py`'sini saklı `static/` çıktıları üstünde çalıştırdı (sha256 KS-1 ölçümündekiyle aynı denetlendi). Karadul hattı ve Ghidra koşulmadı. Çapa sayıları KS-1 ölçümüyle aynı (150, 97, 15).
- **redis-tools'ta ayırıcı sarmalayıcısının neden tanınmadığı** doğrulanmadı.
- **Tanımlar sayım sırasında dört kez düzeltildi** (§1.4). Düzeltmelerin üçü sentetik testin ya da bağımsız aramanın gösterdiği hatalardı; biri (yığın koruyucu uyarısı) denetim sayacının tanımıydı. Hiçbiri bir kuralın ateşleme sayısını hedefleyerek yapılmadı; ama hepsi gerçek sayılar görüldükten sonra yapıldı.

## 8. Bütünlük kaydı

- **Okunmadı:** GT dosyaları, dbgsym/DWARF, `macho_score.json`, `naming_map.json`, `ks1_olcum.json`, `docs/arge/dogrulama_seti*`, `docs/arge/test_seti*`, `targets/`, `~/karadul_olcum/downloads/`. Paylaşılan scratchpad'de başka bir oturumun bıraktığı ve bir tavan dosyasını okuyan betik çalıştırılmadı.
- **Okundu:** `onuncu_adam.md`, `fiil_onkayit_taslak.md`, `on_sayim.py/json`, `kesin.py` (veri akışı bölümleri), `ks1_onkayit.md` (sınıf tablosu), `ks1_sinif.json`, `ks1_say.json` (künye), `ks1_olc.py` (sayım kipi). Saklı `static/` çıktıları: 119 dizinin hepsi betikle; elle 95 örneğin decompile metni (Debian export'ların değil, isim bekleyenlerin).
- **Çıktılarda:** fonksiyon adı ve adres yok; `on_sayim.json`'da `FUN_` yalnız sürüm 1'in nüfus tanımında geçiyor.

**Depo dışında bırakılanlar** (`~/karadul_olcum/runs/n4-on-olcum-2026-11-10/`): `capalar.json` (adres + fiil sınıfı), `ornekler.json` ve `ornekler_t0.json` (elle okuma örnekleri, adresli), `son_t0.json` ve `son_t4242.json` (iki tohumlu koşu), `taban_v1.json` (sürüm 1'in yeniden üretimi), `v2_a.json` ve `v2_b.json` (ara koşular, düzeltmelerden önce), `on_sayim_HEAD.json`, `tablolar.md`, `araclar/` (okuma, denetim, tablo ve mutant betikleri), `mutantlar/m01-m12`.
