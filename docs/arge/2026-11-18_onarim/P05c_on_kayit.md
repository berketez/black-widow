# P05c — ön kayıt (parametre adları: kanıtsız genel adlar, tanınmayan imzalar, n-gram yerel adları)

Bu belge `karadul/` kodu değişmeden ÖNCE yazıldı ve commit'lendi. Kurallar, eşikler ve bölme sayılar görülmeden önce değil, taban sayıları görüldükten SONRA ama onarım kodu yazılmadan ÖNCE sabitlendi. Bir beklenti tutmazsa "tutmadı" yazılır; kural ya da eşik sonradan değiştirilmez.

**Önceden görülen (gizli değil):** P05 / P05b kayıtları; P05b'nin son kolu (`k4`; `semantic_namer.py` o günden beri değişmedi, bu yüzden bu paketin tabanı onunla aynı beklenir) ve onun kural başına D dökümü (aşağıda §3). Bölme (§1) ikili adının özetiyle, dökümün G / K kırılımı görülmeden önce hesaplandı. Daraltma kurallarının (§4) G'deki etkisi önceden denenmedi.

## 1. Araç, girdiler, bölme
- Betik: `scripts/measurement/p05_olc.py kos` (değişmedi), çözümleme `~/karadul_olcum/runs/onarim-2026-11-19/P05c/analiz.py` (kural başına D payı).
- Set Y: `~/karadul_olcum/runs/urun-yeni2-f30ac9a` (119 ikili; salt okur). Set D: T0b hizalaması olan 22 ikili (`~/karadul_olcum/runs/t0b-1acba60/hizalama`). Ghidra koşusu yok.
- Taban kol: `once-3435d68` (değişmemiş kod). Çıktı: `~/karadul_olcum/runs/onarim-2026-11-19/P05c/yeniden/<etiket>/`.
- **Bölme (kural geliştirme ↔ kabul ayrı ikililerde):** `sha256("p05c-bolme:" + ikili adı)` çiftse **G** (geliştirme), tekse **K** (kabul).
  - G (9): arch, htop, ln, logname, openssl, redis-check-aof, sha224sum, tr, zstd.
  - K (13): chgrp, dir, du, env, md5sum, nproc, pzstd, redis-benchmark, redis-cli, sqlite3, tmux, tree, unlink.
  - Kural kararları (§4) yalnız G'nin sayılarıyla verilir; K yalnız kabulde okunur.

## 2. Ölçüler
- P05 / P05b ölçüleri aynen: kusurlu ad (geçersiz / anahtar / tip / Ghidra adı / gövde çakışması), `isaretciye_skaler`, `str_ailesi`, D hükmü `tam` / `yakin` / `yanlis`.
- **Kanal kesinliği:** D'de hükümlü (tam + yakın + yanlış) adlar içinde doğru (tam + yakın) oranı. G, K ve D (G + K) ayrı yazılır.
- **Kural payı:** ad tabanı × kaynak (tip sezgisinde ayrıca gerekçedeki tip ve kullanım); her kural için G'de hükümlü / doğru.
- **Aday kaydı:** kanıtsız olduğu için koda yazılmayan ad, köken kaydında (`semantic_params` bölümü) `candidates` listesine girer (fonksiyon, parametre, aday ad, kanal, güven, gerekçe, ret nedeni `generic_name_without_evidence`). Sayısı yazılır.

## 3. Taban (P05b `k4` = beklenen `once-3435d68`)

| Ölçü | Taban |
|---|---|
| Y'de ad / kusurlu ad | 13 710 / 0 |
| D: doğru / hükümlü (kesinlik) | 136 / 5 100 (%2,67) |
| G: doğru / hükümlü | 96 / 2 913 (%3,30) |
| K: doğru / hükümlü | 40 / 2 187 (%1,83) |

Kanal × ad tabanı (D, doğru / hükümlü): tip sezgisi `count` 13 / 2 300, `enabled` 1 / 389, `value` 2 / 308, `byte_buffer` 0 / 18, `context` 0 / 32, `userdata` 0 / 9, `status` 0 / 29, `threshold` 0 / 11, `scalar` 0 / 6; çağıran yayılımı 106 / 1 492; `call_context` 10 / 153. Tip sezgisinin bütün adları: 20 doğru.

## 4. Onarımın ilkesi (kod yazılmadan önce sabit)

**Eşik (P05 / P05b'deki kanal tabanı):** bir kural, G'de kesinliği **≥ %6** VE G'de en az **1** doğru adı varsa koda ad yazar. Değilse önce aşağıdaki **tek** daraltma (kanıt şartı) uygulanır ve G'de yeniden ölçülür; daraltılmış kural eşiği geçerse kalır, geçmezse adı **aday kaydına** iner (koda yazılmaz; Ghidra'nın adı kalır; K-2). Daraltma sonradan değiştirilmez, ikinci daraltma denenmez.

**Kalem 2 — skaler şablonlar** (tip sezgisi; P05b'nin `SKALER_ADLAR`'ı):
- `count` (`int` karşılaştırma; `size_t` döngü sınırı), `n_size` (`int` döngü sınırı), `buffer_size` (`size_t` karşılaştırma), `counter` (`int` / `int *` artım). **Daraltma (sayı kanıtı):** parametre (i) bir döngü başlığının (`for` / `while`) koşulunda karşılaştırılıyor, ya da (ii) bilinen bir işlevin boyut / adet konumunda çıplak ya da tek cast'le argüman (`memcpy` / `memmove` / `memset` / `memcmp` 3., `strncpy` / `strncmp` / `strncat` 3., `strndup` 2., `malloc` 1., `calloc` 1. ve 2., `realloc` 2., `read` / `write` / `send` / `recv` 3., `fread` / `fwrite` 2. ve 3., `snprintf` / `vsnprintf` 2., `qsort` 2.; Mach-O `_` öneki ve `__X_chk` biçimleri), ya da (iii) `counter` için artım / azaltım (şablonun kendi kullanımı).
- `enabled` (`bool` şablonu; `int` / `uint` / `char` / `byte` / `undefined1` uyum grubu). **Daraltma (doğruluk değeri kanıtı):** bildirilen tip `bool` / `_Bool`, ya da parametrenin koddaki her kullanımı doğruluk sınamasıdır (`if (p)`, `if (!p)`, `p == 0`, `p != 0`, `p == '\0'`, `p != '\0'`, `p && …`, `… || p`, `p ? … : …`) ve en az bir kullanım var.
- `flags` (`uint` karşılaştırma). **Daraltma:** parametre bit maskesiyle sınanıyor (`p & …` ya da `… & p`).
- `value` (`int` genel, `uint` her kullanım), `status` (`int` dönüş değeri), `threshold` / `scalar` (`double`), `factor` (`float`), `handle` (`long` genel). **Daraltma:** tanımlı bir kanıt türü yok (ad tipten öte bilgi taşımıyor) → eşiği geçmezlerse doğrudan aday kaydı.

**Kalem 1 — `void *` ailesi** (tip sezgisi):
- `byte_buffer` (`unsigned char *` şablonu). **Daraltma (bayt kanıtı):** bildirilen tip bayt işaretçisi (`unsigned char *`, `uchar *`, `byte *`, `uint8_t *`, `undefined1 *`), ya da bayt cast'li erişim (`*(byte *)p` …; P05b'nin `_ELEMENT_CAST_TYPES`'ı), ya da bilinen bir işlevin tampon konumunda çıplak ya da tek cast'le argüman (`memcpy` / `memmove` 1. ve 2., `memset` / `memchr` 1., `memcmp` 1. ve 2., `read` / `recv` / `write` / `send` 2., `fread` / `fwrite` 1.).
- `context` (`void *`), `userdata` (`void *` tek okuma). **Daraltma (geri çağrı kullanıcı verisi):** parametre, işlev göstericisiyle yapılan bir çağrının (`(*f)(…)`, `(**(code **)(…))(…)`) argümanı olarak çıplak ya da tek cast'le geçiyor.
- `ctx` (`void *` ofset erişimi) ve öbür işaretçi yapı adları (`self`, `struct_ptr`, `index_array`, `data_ptr`) bu paketin kapsamında DEĞİL (erişim kanıtları var; sayıları yazılır).

Bütün kararlar dizisel ve paralel yolda aynı işlevden geçer. Kanıtlı şablon varsa kanıtsızın önüne geçer; hiçbir şablon kanıtlı değilse en iyi kanıtsız şablon aday kaydına iner.

**Kalem 3 — imza deseni.** `_FUNC_SIG_RE` dönüş tipinde herhangi bir tanımlayıcıyı (niteleyicilerle: `const` / `volatile` / `unsigned` / `signed` / `struct` / `union` / `enum`) ve işaretçiyi kabul eder; fonksiyon adı C anahtar sözcüğü olamaz. P05b K1'in parametre ayrıştırması değişmez. Beklenti: adlandırıcıya giren fonksiyon artar, `isaretciye_skaler` 0 kalır, kusurlu ad 0 kalır. Yeni adların D payı ayrıca yazılır (yön beklentisi yok).

**Kalem 4 — adlı küresel argüman kuralı.** Geliştirme seti dışında DWARF'lı bir doğrulama seti bu oturumda Ghidra koşusu olmadan yok; T0c / kilitli test seti geliştirmede kullanılmaz. Kalem bu pakette **ölçülmez**; kayıtta gerekçesiyle "yapılmadı" yazılır.

**Kalem 5 — n-gram yerel adları.**
- (a) Uygulanan her n-gram adı köken kaydına (`naming_provenance.json`, bölüm `ngram_locals`, kaynak `ngram`) girer: dosya, eski ad, ad, güven, kanıt (eşleşme puanı ve kullanım sayısı); reddedilenler neden × sayı. Kayıt yazılamazsa istatistiğe neden yazılır.
- (b) Ölçüm: D'nin ikililerinde ürünün yinelemesi yeniden oynatılır (P09'un `merged/` → tip kurtarma → XTRIDE → n-gram; birleşik koşunun `BITTI`'li ikililerinden, yoksa `urun-yeni2-f30ac9a`'dan). DWARF'ta yerel değişkenlerin konumu Ghidra yereline bu oturumda hizalanmıyor; bu yüzden **gevşek ölçüt**: uygulanan ad, aynı fonksiyonun (adresle) DWARF değişken + parametre adlarından birine `ad_hukmu` ile `tam` ya da `yakin` ise doğru. Bu, katı doğruluğun üst sınırıdır. Ayrıca katı-yakın sayı: ad DWARF adlarından birine `tam`.
- (c) Kapı: gevşek kesinlik G'de ≥ %6 ve en az 1 doğru ise ad yazılmaya devam eder. Değilse tek daraltma: güven ≥ 0,80 ve en az 2 kullanım; yine geçmezse n-gram adları aday kaydına iner (yazılmaz; köken kaydında aday olarak durur).

## 5. Kabul (paket metninden; D = G + K, `once-3435d68` ↔ son kol)
- Kanal kesinliği D'de **> %2,67** (birincil). Ayrıca K'de > %1,83 (yalnız kabul setinde).
- D'de doğru ad **≥ 136**.
- Kusurlu ad Y'de **0**; `isaretciye_skaler` 0; kanıtsız `str` ailesi (tip sezgisi) 0.
- Tutmazsa "tutmadı" yazılır; kural sonradan değiştirilmez.
