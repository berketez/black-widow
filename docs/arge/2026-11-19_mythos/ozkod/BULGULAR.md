# ÖZ KOD hattı — bulgular (tur 1, 2026-11-19)

- **Soru:** programın yalnız kendisinde bulunan koda yalnız ikilideki kanıttan hangi adlar hesaplanabilir; tavan nedir?
- **Zemin:** taban ürün koşusu a62f15e (119 ikili; bu hatta `redis-check-rdb` ≡ `redis-check-aof` olduğu için tek sayıldı: 117 C ikilisi, nüfus 20 747). Ghidra koşulmadı. Ürün kodu değişmedi.
- **Bölme (sayılara bakmadan yazıldı, `DEFTER.md` §0):** keşif = coreutils, debian/tmux, mac/tmux, openssl; sınama = sqlite3, redis-tools, zstd, debian/htop, mac/htop, tree.
- **Her sayı betik çıktısıdır.** Betikler `scripts/arge/ozkod/`, çıktılar `~/karadul_olcum/runs/arge-2026-11-19/ozkod/`. Komutların hepsi depo kökünden, `PYTHONDONTWRITEBYTECODE=1 python …` ile. **[hesap]** işareti: betik çıktılarından elle toplama / bölme.
- Aralıklar Wilson %95 (`ks1_olc.oran`). "norm" eşitliği: belirteç dizileri eşit (ayraç ve büyük-küçük harf biçimi serbest); "karakter" eşitliği: ürün ölçüsü.
- Geliştirme setinden örnek adlar yazılıdır; kilitli setlerden hiçbir şey yok.

## 0. Kısa sonuç

| Öncül / soru | Hüküm | Ana sayı |
|---|---|---|
| Aykırı öncül 1: ad taşıyan kanıt fonksiyonun içinde değil, onu **kaydeden** yerde | **TUTTU** (iki tarafta) | coreutils dışındaki nüfusun %15,8'i bir (dizgi, işaretçi) kaydında **[hesap]**; kayıt dizgisi GT adına "önek + dizgi + sonek" ile bağlanıyor: keşif %75,3, sınama %60,4 |
| Kuralla ad (K1: kayıt çifti + sütun eki), çapa kâhin | keşif **740 / 754 (%98,1)**; sınama **103 / 126 (%81,7)** — ön kayıtlı %90 eşiği **TUTMADI** | 843 doğru ad, hepsi bugün adsız fonksiyonlarda **[hesap]** |
| K1, bugün ürünün elindeki çapalarla | 98 ad, 95 doğru (%96,9; %91,4–%99,0) | yalnız Mac tmux; öbür tablolarda çapa yok |
| Kebap adının 0 / 239'u "yanlış hedef" mi? | **kısmen**: 28 / 239 başka fonksiyonla kayıtlı; 211'i hiçbir fonksiyonla kayıtlı değil (seçenek anahtarı) | 0 / 239 aynı kayıtta |
| `oz_ad`: doğru / yanlışı ayıran özellik | "çift yönlü teklik" (R1): keşif 77 / 80 (%96,2); sınamada ön kayıt **TUTMADI** | asıl neden başka: **40 "yanlış" ad yalnız küçük harfe çevrilmiş doğru ad** (zstd 37) |
| Aykırı öncül 2: "adların çoğu kanıt taşımaz" | **nicelendi**: programın kendi kodunda adın en az bir belirteci %52,1'inde, **bütün** belirteçleri %13,4'ünde bulunuyor | kâhin tavan %71,6 / %23,1 |
| Aykırı öncül 3: rol çağrısı ortak sarmalayıcıda | **karışık**: ayırt edici içe aktarıma doğrudan ulaşan %36,7, dolaylı %39,0; tmux'ta tutuyor, openssl / sqlite3'te tutmuyor | derinlik 1'dekilerin %75,2'si ortak sarmalayıcı üstünden |
| A6: modül öneki yayılımı | önek **çağrı grafiğinde değil adres sırasında**: çağrı çoğunluğu %55,2, iki adres komşusu %96,4 (kâhin) | bugünkü adlarla "sandviç" 2 216 / 2 545 (%87,1) |

Yasak cevaplar ("dizgiden anahtar sözcük + fiil / nesne", "dil modeli") sonuç olarak getirilmedi. Bu turun yeni bulgusu olan `oz_ad` harf hatası, tam da ilk yasak cevabın ürettiği bir kusur: kanıt dizgisi zaten adın kendisiyken ürün onu anahtar sözcüklere bölüp yeniden kuruyor.

## 1. Kalem 1 — `oz_ad` kanalının 196 adı

Betikler: `oz_ad_ayrim.py --taraf kesif|sinama`, `oz_ad_harf.py`, `oz_ad_uretici.py --taraf …`. Çıktılar: `oz_ad_kesif.txt`, `oz_ad_sinama.txt`, `oz_ad_harf.txt`, `oz_ad_uretici_{kesif,sinama}.txt`.

### 1.1 Ayrımcı özellikler (keşif: 141 ad, 92 doğru)

| özellik | değer | ad | doğru | kesinlik |
|---|---|---:|---:|---|
| kanıt dizgisini anan fonksiyon sayısı | 1 | 116 | 84 | %72,4 |
| | 2 | 21 | 8 | %38,1 |
| | 3+ | 4 | 0 | %0 |
| fonksiyonun andığı tanımlayıcı (alt çizgili) dizgi sayısı | 0–1 | 110 | 85 | %77,3 |
| | 2–3 | 21 | 7 | %33,3 |
| | 4+ | 10 | 0 | %0 |
| ad çakışması (`_2` eki ya da aynı dizgi > 1 ada kanıt) | yok | 122 | 88 | %72,1 |
| | var | 19 | 4 | %21,1 |
| dizgi fonksiyonun kendi xref listesinde | hayır | 6 | 0 | %0 |
| dizgi başka fonksiyonla kayıtlı (V ∪ C) | evet | 8 | 0 | %0 |
| ürünün güveni | 0,85 | 89 | 71 | %79,8 |
| | 0,80 | 52 | 21 | %40,4 |
| kullanım rolü: `%s` dolgusu / assert / düz argüman / atama / C metninde yok | | 26 / 17 / 70 / 5 / 23 | 21 / 11 / 45 / 0 / 15 | |

- **Tutmayan ilk aday (E5'in birinci yarısı):** "dizgi `%s` dolgusu ya da assert argümanı" → tutulan 38, doğru 31 (%81,6), doğruların yalnız %33,7'si. `__func__` çoğu kez bir yardımcıya düz argüman olarak geçiyor (tmux `screen_write_collect_flush(ctx, 0, __func__)`; 16 doğru ad); Mach-O'da 15 doğru adın dizgisi decompile edilmiş C'de sabit olarak hiç görünmüyor.
- **Kural adayı R1 "çift yönlü teklik":** dizgiyi yalnız bu fonksiyon anıyor ∧ fonksiyon en çok bir tanımlayıcı dizgi anıyor ∧ ad çakışması yok ∧ dizgi kendi xref'inde ∧ dizgi başka fonksiyonla kayıtlı değil.
  - Keşif: tutulan 80, doğru **77 (%96,2; %89,5–%98,7)**; doğruların 77 / 92'si (%83,7) tutuluyor; yanlışların 46 / 49'u (%93,9) atılıyor.
  - Sınama (dondurulmuş; ön kayıt "yanlışların ≥ %80'i atılır"): 55 ad (1 doğru); atılan yanlış **24 / 54 (%44,4) → TUTMADI.**

### 1.2 Asıl neden: ürün adı küçük harfe çeviriyor

- Sınamada R1'den geçen 30 "yanlış" adın kanıtı `__assert_fail`'in fonksiyon adı argümanı; ad doğru fonksiyonun adı, yalnız küçük harfli: GT `ZSTD_getCParamsFromCDict` ← ürün `zstd_getcparamsfromcdict`.
- Kaynak (okundu, değiştirilmedi): `karadul/reconstruction/c_namer.py` `_extract_keywords_from_string` (`[a-zA-Z]{3,}` sözcükleri, küçük harf) → `_strategy_string_context` klasik aşaması `"_".join(best_keywords[:3])` → `_sanitize_c_name` (küçük harf). Kanıt zaten tek bir tanımlayıcıyken ad ondan yeniden kuruluyor; ancak ≤ 3 sözcüklü, rakamsız, küçük harfli tanımlayıcılarda dizgiye eşit çıkıyor.
- Sayım (`oz_ad_harf.py`; kanıt dizgisinin kendisi ad sayılıp `ks1_olc.capa_degerlendir` ile hükme sokuldu):

| | ad | bugün doğru | kanıt harfleriyle doğru | yanlıştan doğruya dönen |
|---|---:|---:|---:|---:|
| keşif | 141 | 92 | 95 | 3 |
| sınama | 55 | 1 | 38 | 37 |
| **toplam** | 196 | 93 | **133** | **40** |

  - Birim: zstd 37, coreutils 1, openssl 1, mac/tmux 1.
  - R1 + harf koruma: keşif 78 / 80 (%97,5), sınama 28 / 31 (%90,3), toplam **106 / 111 (%95,5; %89,9–%98,1)**. Sınama sayısı ölçüm sonrası tanımdır (neden sınamada görüldü); ön kayıtlı sayılmaz.
- Etki: taban ölçümünde makro yanlış oranını taşıyan zstd'nin 46 yanlışının 37'si bu kusur (`sonuc.md` §2: zstd %83,6).

### 1.3 G1 — aynı kuralın üretici hâli (bütün nüfusa)

Kural (keşifte ayarsız, ilk hâliyle donduruldu): fonksiyon tam olarak bir tane alt çizgili, küçük harf içeren C tanımlayıcısı biçimli dizgi anıyorsa, o dizgiyi ikilide yalnız o anıyorsa ve dizgi başka fonksiyonla kayıtlı değilse ad = dizgi (dönüştürmeden).

| | nüfusta ad | doğru | doğruların bugün adsız / yanlış adlı / zaten doğru olanı |
|---|---:|---|---|
| keşif | 484 | 454 (%93,8; %91,3–%95,6) | 121 / 2 / 331 |
| sınama | 143 | 114 (%79,7; %72,4–%85,5) | 90 / 24 / 0 |

- Sınama ön kaydı: kesinlik ≥ %85 → **TUTMADI** (%79,7); "bugün adsız doğru ≥ 20" tuttu (90). Ön kayıt yarı kör yazıldı (zstd'nin `oz_ad` kayıtları görülmüştü; `DEFTER.md` §10).
- zstd 114 / 134 (%85,1); zstd dışı sınama (htop, redis-tools, sqlite3) **0 / 9**: `__func__` kullanmayan programda tek tanımlayıcı dizgi veri anahtarıdır. G1 kanıtın türünü bilmiyor.
- Keşifteki 331 "zaten doğru"nun 235'i `ks1:func_kalibi`, 84'ü `oz_ad`: G1, KS-1'in desen şartı aramadan aynı olguyu yakalıyor ve 121 + 90 yeni doğru ad ekliyor; bedeli ölçülmüş: keşifte 10, sınamada 26 yeni yanlış.

## 2. Kalem 2 — kayıt çifti tavanı (aykırı öncül 1)

Betikler: `kayit_cifti.py --taraf …` (erişim, ilişki), `ek_kurali.py --taraf …` (kural K1), `ek_kurali_belirtec.py`, `ek_kurali_hata.py`, `ek_kurali_capa.py`, `kebap_hedef.py`. Dondurma: `DEFTER.md` §4 (sha256'lar orada; sınama öncesi ve sonrası aynı).

Tanımlar: **V** = veri bölümünde fonksiyon yuvası ile aynı kayıttaki dizgi yuvası (N4 tablosu ya da çapa nesnesi); **C** = decompile edilmiş C'de aynı çağrının argümanlarında dizgi sabiti + `FUN_` işaretçisi; **P** = yuvanın ± 4 sözcük penceresi (OLGU tanımı).

### 2.1 Erişim

| birim | taraf | nüfus | veri yuvası | V | C | V ∪ C |
|---|---|---:|---:|---:|---:|---:|
| debian/coreutils | keşif | 12 717 | 269 | 0 | 12 | 12 (%0,1) |
| debian/openssl | keşif | 563 | 56 | 56 | 1 | 57 (%10,1) |
| debian/tmux | keşif | 1 851 | 383 | 366 | 25 | 391 (%21,1) |
| mac/tmux | keşif | 2 545 | 464 | 447 | 26 | 473 (%18,6) |
| debian/htop | sınama | 222 | 128 | 77 | 0 | 77 (%34,7) |
| mac/htop | sınama | 597 | 148 | 73 | 0 | 73 (%12,2) |
| debian/redis-tools | sınama | 834 | 272 | 167 | 0 | 167 (%20,0) |
| debian/sqlite3 | sınama | 389 | 148 | 0 | 28 | 28 (%7,2) |
| debian/tree | sınama | 110 | 38 | 1 | 0 | 1 (%0,9) |
| debian/zstd | sınama | 919 | 64 | 0 | 0 | 0 |
| **toplam** | | 20 747 | 1 970 | 1 187 | 92 | **1 279 (%6,2)** **[hesap]** |

- coreutils dışı: 1 267 / 8 030 (%15,8) **[hesap]**. coreutils'te komut tablosu yok; zstd bir kitaplık, tablosu yok.
- OLGU tablosuyla çapraz denetim (`olgu_capraz.py` → `olgu_capraz.txt`; OLGU `asama: tam`, sha256 `c9fa66cb…`): nüfus 20 747 = 20 747; pencere çifti OLGU 1 196 / bu hat 1 193 (3 fonksiyon farklı); doğrudan dizgili fonksiyon 5 088 = 5 088; D0 "en az bir belirteç" 2 504 / 2 507 (fark: OLGU uzun dizgiyi kırpıyor). OLGU'nun `cagri_ciftleri` alanı `desteklenmiyor` (P-code'dan çıkarılamadı); bu hattın C tanımı (C metninden) 92 fonksiyon veriyor. OLGU'nun kendi notundaki "kayıt çifti olan nüfus 1 330" 119 ikililik sayımdır (`redis-check-rdb` dahil); ortak 117 ikilide 1 196'dır. Çapraz denetim, OLGU'nun "ARA TESLİM 2" duyurusundaki tabloyla (aynı sha256) yapıldı.

### 2.2 Dizgi ↔ GT adı ilişkisi (fonksiyonun tek kaydı varsa, kayıttaki ilk ad biçimli dizgi)

| | tekil kayıtlı fonksiyon | tam (dizgi = ad) | ekli (ad = önek + dizgi + sonek) | belirteç örtüşmesi | ilgisiz |
|---|---:|---:|---:|---:|---:|
| V, keşif | 818 | 0 | 616 (%75,3) | 158 | 44 |
| V, sınama | 283 | 0 | 171 (%60,4) | 8 | 104 |
| C, keşif | 45 | 27 (%60,0) | 8 | 1 | 9 |
| C, sınama | 25 | 3 | 17 (%68,0) | 3 | 2 |

- Bu tablodaki V sayıları N4'ün faz seçimine bağlıdır ve iki tabloda faz kaymıştır (Mac tmux `window_copy_cmd_*`: 100 fonksiyon bir sonraki kaydın dizgisiyle eşlenmiş; redis-tools'ta "ilgisiz" 94). K1 faz varsaymaz (§2.3); gerçek ilişki bu yüzden bu tablodan yüksektir.
- "tam" yalnız çağrı yerinde var: tmux `cmdq_get_callback1("cfg_done", cfg_done, …)` (makro fonksiyon adını dizgiye çeviriyor).
- "ekli" örnekleri: `format_cb_client_termtype` ← "client_termtype"; `cmd_split_window_exec` ← "split-window"; `window_copy_cmd_cursor_right` ← "cursor-right"; `rand_main` ← "rand"; (sınama) `luaB_next` ← "next", `clusterManagerCommandInfo` ← "info", `DiskIORateMeter_display` ← "DiskIORate", `decimalMulFunc` ← "decimal_mul".

### 2.3 Kural K1 "kayıt çifti + sütun eki"

- Aday grup: tabloda (tablo, fonksiyon sütunu, dizgi ofseti δ) — faz varsayımı yok; tablo dışı nesnede (nesnenin tür dizisi, yuva ofseti, dizgi ofseti); çağrıda (çağrılan, argüman sayısı, fonksiyon argümanı, dizgi argümanı).
- Ek (önek, sonek), hedef dışındaki üyelerin adından öğrenilir; en çok oy alan ek ≥ 2 çapa fonksiyonundan gelmeli, ikinciden fazla olmalı ve gruptaki çapaların ≥ yarısını açıklamalı. Bir fonksiyon için birden çok farklı ad çıkarsa çekimser.
- Rol kendiliğinden çıkar: sonek sütuna bağlıdır (`cmd_entry` 10. yuva → `_exec`, 4. yuva → `_args_parse`; htop sınıf nesnesinde `Meter_display` / `Meter_updateValues`).

**Çapa kâhin** (hedef dışındaki üyelerin GT adı; "tabloda iki ad bilinseydi" üst sınırı):

| | adaylı | ad | doğru (norm) | karakter eşit | ayraçsız eşit | belirteç kesinliği / duyarlılığı |
|---|---:|---:|---|---:|---:|---|
| keşif | 921 | 754 | **740 (%98,1; %96,9–%98,9)** | 730 | 740 | %99,6 / %99,9 |
| sınama | 365 | 126 | **103 (%81,7; %74,1–%87,5)** | 35 | 108 | %94,6 / %93,2 |

- Birim (sınama): redis-tools 65 / 71 (%91,5), debian/htop 17 / 26, mac/htop 13 / 17, sqlite3 8 / 12.
- **Ön kayıt S1 (kesinlik ≥ %90, n ≥ 50): TUTMADI.** S2 (≥ 2 sınama biriminde erişim ≥ %5) tuttu; S3 ("tam ∪ ekli" ≥ %50) havuzda tuttu (%60,4).
- 843 doğru adın 839'u bugün adsız, 1'i bugün yanlış adlı, 3'ü bugün de doğru **[hesap: 736 + 103; 1; 3]**.
- Sınamadaki 23 yanlışın dökümü (`ek_kurali_hata.py --taraf sinama`; ölçüm sonrası): çoğu GT adının düzensizliği ya da belirteç sınırı — `FileDescriptorMeter_display` ← hesaplanan `file_descriptors_meter_display`; `ZfsArcMeter_*` ← `zfsarc_meter_*`; `recoverGetPage` ← `recover_getpage`; `ieee754func_from_blob` ← `ieee_754_from_blob_func`; `clusterManagerCommandDeleteNode` ← `…_del_node`. Gerçek yanlışlar: `SysArchMeter_updateValues` ← `system_meter_…`, `db_errorfb` ← `db_traceback`, `lua_cjson_new` / `json_decode` / `json_encode` ← `json_cfg_*`.
- Karakter eşitliği sınamada 35 / 126: kural adı snake_case yazıyor; GT camelCase. Ek, çapanın yüzey biçiminden öğrenilmeli — **ölçülmedi** (PLAN, açık ölçüm).
- Keşiften sınamaya düşüşün ölçülen nedeni programların ad düzeni: tmux ve openssl fonksiyon adını tablodaki dizgiden mekanik türetiyor; htop ve sqlite3 elle kısaltıyor.
- Yön gösterici değişke (keşifte sınanmadı; nesne grubunun anahtarı tür dizisi yerine uzunluk): sınama 152 / 175 (%86,9). htop'un sınıf nesneleri bitişik değil ve boş yuvaları farklı; katı anahtar onları gruplayamıyor.

**Çapa benzetimi** (GT'li fonksiyonların rastgele p payının adı biliniyor; 5 tohum toplamı):

| | p = %2 | p = %5 | p = %10 | p = %25 |
|---|---|---|---|---|
| debian/tmux: ad / hedef; doğru | 576 / 1 874; %98,1 | 1 240 / 1 809; %98,5 | 1 303 / 1 703; %98,5 | 1 164 / 1 429; %98,5 |
| sınama havuzu | 0 / 1 788 | 32 / 1 721; 32 doğru | 128 / 1 645; 108 doğru (%84,4) | 238 / 1 359; 202 doğru (%84,9) |

**Çapa bugün elde olanlarla** (`ek_kurali_capa.py`; hedef: o kipte adı olmayan nüfus):

| çapa kaynağı | ad | doğru (norm) | karakter eşit | doğru ve bugün adsız |
|---|---:|---|---:|---:|
| A: ürünün ön ad kanalları (`on_ad:*`, `ks1:*`) + Ghidra adları | 98 | 95 (%96,9; %91,4–%99,0) | 95 | 95 |
| B: A + R1'den geçen `oz_ad` (harf korunmuş) | 98 | 95 | 95 | 95 |
| C: A + G1 adları | 242 | 239 (%98,8; %96,4–%99,6) | 239 | 239 |
| D: ürünün bugünkü bütün adları | 98 | 95 | 95 | 95 |

- A'nın 97 adı Mac tmux'ta tek tablodan (`window_copy_cmd_*`; iki `ks1` adı tabloyu açıyor); 1 ad redis-tools'ta (yanlış). Debian tmux ve openssl tablolarında bugün çapa yok.
- C'de Debian tmux 121 / 121, Mac tmux 118 / 120. Sınama birimlerinde hiçbir kipte çapa yok (1 ad, 0 doğru): htop, redis ve sqlite3 `__func__` taşımıyor.
- **Darboğaz kural değil çapa.** Çapa kaynağı adayları: KS-1 çapaları (bugün), G1 (bağımsız sınama bekliyor), KİMLİK hattının başka derlemeden tanıdığı adlar, analistin elle verdiği ad (iki ad → tablo).

### 2.4 E3 — kebap kanalının 0 / 239'u

`kebap_hedef.py` → `kebap_hedef.txt` (1.22.1 koşusunun 239 `kebap_ad` kaydı):

| | kebap adı | anan = kayıtlı | dizgi başka fonksiyonla kayıtlı | hiçbir kayıtta yok |
|---|---:|---:|---:|---:|
| toplam | 239 | 0 | 28 | 211 |

- Başka fonksiyonla kayıtlı 28 dizgide o fonksiyonun GT adıyla ilişki: 26 "ekli", 2 "örtüşme". Yani o 28 ad gerçekten yanlış fonksiyona verilmişti.
- 211 dizgi (%88,3) hiçbir fonksiyonla kayıtlı değil: tmux seçenek anahtarları (`options_get(…, "monitor-bell")`); seçenek tablosunda fonksiyon işaretçisi yok. Bu dizgi fonksiyonun adını değil, okuduğu veriyi söyler.
- Hat metnindeki tahmin ("belki yanlış fonksiyona verildiği için 0 / 239") dokuzda bir oranında doğru.

### 2.5 N4'ün "tablo yuvası ≤ %10,6" sonucuyla fark

| | N4 (2026-11-10) | Bu tur |
|---|---|---|
| GT | kullanılmadı (yalnız erişim) | kullanıldı (ilişki ve tam eşitlik) |
| Ölçülen | tablo kaydında, ad biçimli dizgisi olan, **bugün adsız** fonksiyon: Mac tmux 274 (%10,6) | kayıt dizgisi olan nüfus: Mac tmux 447 (%17,6); bunların kaçında dizgi ada bağlanıyor ve kuralla tam ad çıkıyor |
| Kayıt sınırı | faz seçimi (çapa + sütun tutarlılığı) | faz yok: her δ ayrı aday, doğru δ'yı çapa seçer |
| Bitişik olmayan nesneler | dışarıda (zayıflık 2) | çapa nesnesi olarak içeride (N grupları) |
| Çağrı yeri çiftleri | yok | var (92 fonksiyon) |
| "Dizgi kaydı adlandırır, yuvayı değil" (zayıflık 7) | sorun olarak kayıtlı | sonek sütuna bağlı öğrenildiği için çözülüyor |

N4'ün sayısı erişim tavanıydı ve doğru büyüklükteydi; N4 tabloların çoğunda dizginin ada **kuralla** bağlandığını ölçmemişti. Aynı şeyi ölçmüyoruz: N4 "kaç fonksiyon tabloda", bu tur "tablodaki dizgiden ad hesaplanır mı".

## 3. Kalem 3 — belirteç tavanı (aykırı öncül 2)

`tavan.py` → `tavan.txt`. GT adının belirteçleri (≥ 2 karakter, rakam dışı; klon eki soyulmuş) kanıt kaynaklarının belirteç kümesinde arandı. Kaynak sınıfı OLGU tablosundan.

| kesit | fonksiyon | en az 1 belirteç: bugün / kâhin | bütün belirteçler: bugün / kâhin | belirteç (mikro): bugün / kâhin |
|---|---:|---|---|---|
| bütün nüfus | 20 742 | %33,7 / %59,3 | %7,6 / %16,1 | %24,2 / %43,9 |
| **programın kendi kodu (ELF)** | 4 777 | **%52,1 / %71,6** | **%13,4 / %23,1** | %33,1 / %51,9 |
| gnulib | 11 393 | %18,7 / %45,3 | %1,6 / %7,7 | %11,0 / %27,6 |
| proje kitaplığı (zstd `lib/`) | 720 | %63,5 / %83,8 | %39,6 / %50,3 | %53,6 / %71,6 |
| Mac (sınıf bilinmiyor) | 3 147 | %53,0 / %86,4 | %12,1 / %27,4 | %31,9 / %61,4 |

Kaynak başına, bütün nüfus (en az 1 belirteç / bütün belirteçler):

| kaynak | en az 1 | hepsi |
|---|---:|---:|
| doğrudan dizgi | %12,1 | %5,4 |
| — dosya yolu biçimli dizgi | %2,6 | %0,8 |
| derinlik 1 çağrılanın dizgisi | %10,4 | %0,8 |
| derinlik 2 | %6,9 | %0,4 |
| kayıt çifti dizgisi | %5,7 | %0,2 |
| çağrılan içe aktarımın adı | %8,3 | %0,3 |
| komşunun bugün bilinen adı | %11,2 | %1,1 |
| komşunun GT adı (kâhin) | %48,2 | %9,2 |

- "Bugün" = doğrudan dizgi ∪ derinlik 1 ∪ kayıt çifti ∪ içe aktarım adı ∪ komşunun bugünkü adı. "Kâhin" = buna derinlik 2 ve komşuların GT adı eklenir.
- Modül öneki (ilk belirteç) / son belirteç bulunma payı, programın kendi kodu: bugün %32,6 / %28,3; kâhin %56,9 / %42,5.
- **Okuma.** Programın kendi kodunda adın bir parçası fonksiyonların yarısında, tamamı yedide birinde ikilide yazılı. En büyük tek kaynak komşunun adı: adlar birbirinden (ortak önekten) türüyor. Kayıt çifti tek başına "bütün belirteçler"de küçük görünür (%0,2), çünkü ek (önek / sonek) dizgide yoktur; ek çapadan gelince tam ad çıkar (§2.3).
- **Sınır.** Tavan belirtecin varlığını sayar. Hangi belirtecin seçileceği ve sırası ayrı bir sorundur; bu yüzden bu sayılar ad tavanı değil, kanıt tavanıdır. Seçme / sıralama için bu turda kural kurulmadı (yasak cevap bölgesi).

## 4. Kalem 4 — rol derinliği (aykırı öncül 3)

`tavan.py`. d(f) = içe aktarım çağıran bir fonksiyona en kısa çağrı uzaklığı (0: kendisi çağırıyor). "Ayırt edici" = ikilinin iç fonksiyonlarının en çok %5'inin çağırdığı içe aktarım.

| kesit | fonksiyon | ayırt edici içe aktarım: derinlik 0 / 1 / 2 / 3 / yok | derinlik 1'de taşıyan ortak sarmalayıcı (≥ 5 çağıran) |
|---|---:|---|---|
| bütün nüfus | 20 747 | %36,7 / %29,3 / %6,5 / %3,2 / %24,2 | 4 579 / 6 086 (%75,2) |
| programın kendi kodu | 4 777 | %44,4 / %21,5 / %8,3 / %2,2 / %23,5 | 766 / 1 029 (%74,4) |
| debian/tmux | 1 851 | %26,2 / %31,4 / %15,9 / %4,4 / %22,0 | 502 / 582 (%86,3) |
| mac/tmux | 2 545 | %25,6 / %30,1 / %17,4 / %3,9 / %23,1 | 623 / 765 (%81,4) |
| debian/openssl | 563 | %79,0 / %7,3 / %1,1 / %0 / %12,6 | 30 / 41 |
| debian/sqlite3 | 389 | %57,6 / %10,3 / %0,3 / %0 / %31,9 | 19 / 40 |
| debian/zstd | 919 | %17,2 / %8,4 / %4,9 / %1,5 / %68,0 | 26 / 77 |

- Her içe aktarım sayılırsa derinlik 0 payı %62,6 (E6 bu okumayla tutmadı; ayırt edici okumayla tuttu).
- **Hüküm: karışık.** Bütün nüfusta dolaylı ulaşan (%39,0 **[hesap]**) doğrudan ulaşandan (%36,7) biraz fazla ve dolaylı ulaşanların dörtte üçü ortak bir sarmalayıcıdan geçiyor: öncül tmux türünde tutuyor. Kitaplık API'sini doğrudan çağıran programlarda (openssl, sqlite3) tutmuyor. Fonksiyonların dörtte birinin 3 çağrı içinde ayırt edici içe aktarımı yok; zstd'de %68.
- Sınır: hangi çağrının rolü verdiği etiketlenmedi; ölçülen, rol verebilecek bir çağrının uzaklığıdır.

## 5. Kalem 5 — modül öneki yayılımı (A6)

`tavan.py`. Önek = GT adının ilk belirteci (≥ 2 belirteçli adlarda).

| kesit | önekli fonksiyon | çağrı komşularının çoğunluğu (kâhin) | iki adres komşusu uzlaşıyor (kâhin) | bugünkü adlarla sandviç |
|---|---:|---|---|---|
| bütün nüfus | 16 625 | 5 362 / 9 712 (%55,2; %54,2–%56,2) | 8 665 / 8 987 (%96,4; %96,0–%96,8) | 2 216 / 2 545 (%87,1; %85,7–%88,3) |
| programın kendi kodu | 4 353 | 1 026 / 2 457 (%41,8) | 2 284 / 2 417 (%94,5) | 740 / 809 (%91,5) |
| keşif | 13 713 | %56,7 | 6 927 / 7 155 (%96,8) | 1 586 / 1 717 (%92,4) |
| sınama | 2 912 | %49,0 | 1 738 / 1 832 (%94,9) | 630 / 828 (%76,1) |

- **Modül önekini çağrı grafiği değil adres sırası taşıyor.** Çağrı komşularının çoğunluğu, komşuların hepsi doğru adlandırılmış olsa bile %55 (programın kendi kodunda %42). Adres sırasında önceki ve sonraki fonksiyon aynı öneki taşıyorsa fonksiyonun öneki %96 o. Neden: aynı kaynak dosyanın fonksiyonları ikilide yan yana durur ve aynı öneki taşır; çağrılar dosyalar arasıdır.
- Bugünkü adlarla "sandviç" (adsız fonksiyonun önündeki ve arkasındaki en yakın adlı fonksiyon aynı önekli): 2 545 fonksiyona önek, %87,1 doğru. Birim: debian/tmux 564 / 597 (%94,5), mac/tmux 879 / 888 (%99,0), zstd 421 / 464, debian/htop 70 / 82; redis-tools 139 / 282 (%49,3), coreutils 140 / 228 (%61,4). Aralık ≤ 2 fonksiyonla: 173 / 204 (%84,8).
- Kural olarak dondurulmadı ve keşif / sınama ayrımıyla sınanmadı (yalnız sayım). Önek ad değildir; kanıt satırıdır.
- P12b'nin adayı ("çağıranın modül öneki", kalem 5) çağrı grafiğine dayanıyor; bu ölçüme göre zayıf zemin.

## 6. Kalem 6 — bağımsız sınama nüfusu adayları

`aday_paket.py` → `aday_paket.txt`. Boyutlar yerel Debian 13 arm64 dizin dosyalarından (`~/karadul_olcum/downloads/debian13/indeks/`, 2026-10-21); hiçbir şey indirilmedi. Kilitli test ve doğrulama setlerindeki ve yedek sıralarındaki programlar dışlandı (kilit belgelerinden yalnız adlar okundu). "Beklenen kayıt çifti" sütunu kaynak bilgisine dayalı beklentidir, **ölçülmedi**.

| paket | sürüm | .deb (MiB) | -dbgsym (MiB) | beklenen kayıt çifti |
|---|---|---:|---:|---|
| bash | 5.2.37-2+b10 | 1,4 | 1,4 | builtin tablosu `{ad, işlev, …}` |
| nginx | 1.26.3-3+deb13u7 | 0,5 | 1,2 | `ngx_command_t {ad, …, işleyici}` |
| irssi | 1.4.5-1+b5 | 1,1 | 1,6 | çağrı yeri: `command_bind("ad", NULL, işlev)`, `signal_add("olay", işlev)` |
| hexchat | 2.16.2-1+b6 | 0,3 | 0,9 | komut tablosu + GTK sinyalleri |
| jq | 1.7.1-6+deb13u3 | 0,1 | 0,0 | `function_list {işlev, "ad", n}` |
| gawk | 1:5.2.1-2+b2 | 0,6 | 1,1 | `tokentab {"ad", …, işlev}` |
| tcl8.6 + libtcl8.6 | 8.6.16+dfsg-1 | 0,1 + 0,9 | 0,0 + 1,8 | `Tcl_CreateObjCommand(interp, "ad", işlev)` |
| lua-socket, lua-cjson | 3.1.0-1+b2, 2.1.0+dfsg-2.2+b2 | 0,1 + 0,0 | 0,5 + 0,1 | `luaL_Reg {"ad", işlev}` |
| gedit | 48.1-4 | 0,3 | 0,8 | `g_signal_connect(o, "olay", G_CALLBACK(işlev))`, `GActionEntry` |
| evince | 48.1-3+deb13u1 | 0,3 | 0,6 | `GActionEntry {"ad", işlev}` |
| mousepad | 0.6.3-1 | 0,3 | 0,0 | `GActionEntry` |
| xfce4-terminal | 1.1.4-1 | 0,4 | 0,3 | `g_signal_connect` |
| geany | 2.0-2 | 1,8 | 9,1 | `g_signal_connect` + tuş tabloları |
| pidgin | 2.14.14-1 | 0,5 | 1,5 | `purple_signal_connect(h, "olay", …, işlev)` |
| xterm | 398-1 | 0,8 | 0,8 | `XtActionsRec {"ad", işlev}` |
| mc | 3:4.8.33-1+deb13u1 | 0,5 | 1,5 | komut / tuş tabloları |
| busybox | 1:1.37.0-6+b9 | 0,4 | 1,4 | koşut diziler (ad dizisi + işlev dizisi; kayıt değil) |
| lighttpd | 1.4.79-2 | 0,3 | 0,9 | eklenti yapılandırma tabloları |
| neomutt | 20250510+dfsg-2 | 1,8 | 2,1 | komut tablosu |
| postgresql-17 | 17.11-0+deb13u1 | 15,4 | 18,8 | `fmgr_builtins {…, "ad", işlev}` |
| python3.13-minimal, libpython3.13-stdlib | 3.13.5-2+deb13u5 | 1,9 + 1,8 | dizinde yok | `PyMethodDef {"ad", işlev, …}` |

- Toplam indirme (.deb + bulunan -dbgsym): **78,0 MiB**. postgresql-17 tek başına 34,2 MiB **[hesap]**; çıkarılırsa 43,8 MiB **[hesap]**.
- python3.13'ün -dbgsym paketi yerel dizinde görünmüyor (ad farklı olabilir: `python3.13-dbg`); doğrulanmadı.
- Sınıf dengesi için: `__func__` / assert taşıyan (G1 için) ve taşımayan programlar ayrı tabaka olmalı; bunu indirmeden bilemem.

## 7. Ön beklentilerin dökümü (`DEFTER.md` §1, §4, §7, §10)

| # | Beklenti | Hüküm |
|---|---|---|
| E1 | tmux'ta kayıt çifti olan nüfus ≥ %5; coreutils < %2 | **tuttu** (%21,1 / %18,6; %0,1) |
| E2 | çiftli fonksiyonların ≥ %30'unda dizgi ada "tam / basit kuralla tam" bağlanır | **tuttu** (keşif %75,3) |
| E3 | kebap adı verilen fonksiyonların < %20'si o dizgiyle aynı kayıtta | **tuttu** (%0); nedensel okuma yalnız 28 / 239 için doğru |
| E4 | en az 1 belirteç ≥ %50; bütün belirteçler ≤ %15 | ilk yarı bütün nüfusta **tutmadı** (%33,7), programın kendi kodunda tuttu (%52,1); ikinci yarı tuttu (%7,6) |
| E5 | `oz_ad` ayrımı: kesinlik ≥ %90 ve doğruların ≥ %70'i | keşifte R1 ile **tuttu** (%96,2 / %83,7); "`%s`'siz tanımlayıcı" yarısı ayırt edici değil |
| E6 | içe aktarım çağıran nüfus < %50 | her içe aktarımla **tutmadı** (%62,6); ayırt edici olanla tuttu (%36,7) |
| S1 | K1 sınama kesinliği ≥ %90 | **tutmadı** (%81,7) |
| S2, S3 | K1 erişim ve ilişki | **tuttu** |
| S4 | ürün çapasıyla ad < 20, doğruluk ≥ %90 | sayı tuttu (1 ad); doğruluk ölçülemez (0 / 1) |
| R1-S1 | `oz_ad` yanlışlarının ≥ %80'i atılır | **tutmadı** (%44,4); neden §1.2 |
| G1-S1 | G1 sınama kesinliği ≥ %85 | **tutmadı** (%79,7) |
| G1-S2 | bugün adsız doğru ≥ 20 | **tuttu** (90) |

## 8. Yaratıcılık protokolü: uygulandı mı?

1. **Denetlenebilir soru:** evet. Her kalem sayım ya da tam eşitlikle sınanan bir kural; doğrulayıcı GT.
2. **Uzlaşıyı kır:** evet. Üç aykırı öncül sınandı; yasak cevaplar getirilmedi. Öncül 1 tuttu, 3 karışık, 2 nicelendi.
3. **Tek hatta kal:** evet. Başka hatlar için notlar §9'da.
4. **Seçimi insan uzman yapsın:** K1'in "yakın ad" sayılıp sayılmayacağı (sınamadaki 23 yanlışın çoğu) ÖLÇÜ hattının ve dış uzmanın işi; burada yalnız tam eşitlik ve belirteç ölçüleri ayrı ayrı verildi.

## 9. Başka hatlar için notlar

- **KİMLİK:** K1'in darboğazı çapa. Başka derlemeden tanınan her doğru ad bir tabloyu açabilir (iki çapa → tablo). Debian tmux'ta çapa benzetimi: adların %2'si bilinince hedeflerin 576 / 1 874'üne ad, %98,1 doğru.
- **ÖLÇÜ:** K1'in sınama yanlışları "yakın ad" ölçüsü için hazır bir etiket kümesi adayı (`ek_kurali_sinama_hata.txt`): `file_descriptors_meter_display` ↔ `FileDescriptorMeter_display`, `recover_getpage` ↔ `recoverGetPage`, `json_cfg_decode` ↔ `json_decode`. Üç eşitlik düzeyi (karakter / norm / ayraçsız) sınamada 35 / 103 / 108 veriyor: ölçünün seçimi sonucu üç kat değiştiriyor.
- **OLGU:** `cagri_ciftleri` alanı `desteklenmiyor`; bu hattın C metninden çıkarıcısı (`kayit_cifti.cagri_ciftleri_metin`) 92 nüfus fonksiyonu veriyor. Pencere çifti sayıları 3 fonksiyon dışında aynı.
- **Onarım (P12d):** `oz_ad` harf kusuru (§1.2) P12d ile aynı fonksiyonda (`c_namer._strategy_string_context`); iki onarım sıralı yapılmalı (PLAN ÖK-1).
- **Ölçüm aracı:** `urun_olc` hükmü karakter eşitliği; 40 `oz_ad` adı yalnız harf farkıyla yanlış. Proje normalleştirmesi sütunu (`proje`) bunu görmüyor mu, bakılmadı.
