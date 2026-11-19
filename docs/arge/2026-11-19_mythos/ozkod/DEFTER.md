# ÖZ KOD hattı — defter (tur 1, 2026-11-19)

Sıra: en yeni kayıt en altta. Her sayının yanında betik ve komut durur.

## 0. Bölme kararı (2026-11-19 10:30; hiçbir analiz betiği koşulmadan önce yazıldı)

Okuduğum sayılar yalnız zorunlu okumadaki (`sonuc.md` §2, §5) birim toplamlarıdır; fonksiyon düzeyinde hiçbir veriye bakmadım.

| Taraf | Birimler |
|---|---|
| **Keşif** (kural burada okunur) | `debian/coreutils` (106 ikili, tek birim), `debian/tmux`, `mac/tmux` (aynı kaynak, aynı tarafta), `debian/openssl` |
| **Sınama** (kural dondurulduktan sonra burada sayılır) | `debian/sqlite3`, `debian/redis-tools` (4 ikili; `redis-check-aof` ≡ `redis-check-rdb` aynı dosya, tek sayılır), `debian/zstd` (`pzstd` C++, ölçü dışı), `debian/htop`, `mac/htop` (aynı kaynak, aynı tarafta), `debian/tree` |

- Hat metninin önerisiyle aynı; değiştirmedim.
- Bilinen yanlılık (bölmeden önce yazıyorum): `oz_ad` yanlışlarının çoğu sınama tarafında (zstd 46, sqlite3 7; `sonuc.md` §0). Keşifte okunacak "yanlış" örnekleri az olabilir. Bölmeyi bu yüzden değiştirmiyorum; keşifte yanlış örneği yetmezse kural adayı "yön gösterici" kalır.
- Sınama birimlerinin GT'sine kural dondurulmadan bakılmaz. Dondurma anı deftere saatle yazılır; kuralın metni ve betiğin sha256'sı yanında durur.
- Tavan sayımları (kalem 2–5) kural kurmuyorsa bölmeye bağlı değildir (yalnız sayım); yine de keşif / sınama ayrı sütunda verilir. Tavan sayımından bir **ad kuralı** okunursa kural yalnız keşiften okunur.

## 1. Ön beklentiler (ölçümden önce; tutmayan silinmez)

Yazıldığı an: 2026-11-19 10:30, veri açılmadan.

| # | Beklenti | Eşik ("tuttu") |
|---|---|---|
| E1 | Aykırı öncül 1: nüfustaki (GT adlı, Ghidra'nın jenerik bıraktığı) fonksiyonların bir kısmı veri bölümünde bir dizgiyle aynı kayıtta durur. Beklentim: tmux'ta ≥ %5, coreutils'te < %2 (coreutils'te komut tablosu yok). | tmux'ta kayıt çifti olan nüfus payı ≥ %5 |
| E2 | Kayıt çiftindeki dizgi GT adına "tam / basit kuralla tam" bağlanır: çift sahibi fonksiyonların ≥ %30'unda. (Kebap kanalının 0 / 239'una karşı.) | keşifte ≥ %30 |
| E3 | Kebap kanalının 0 / 239'unun nedeni "yanlış hedef": kebap dizgisini **anan** fonksiyon çoğu kez dizgiyle **kaydedilen** fonksiyon değildir. | kebap adı verilen fonksiyonların < %20'si o dizgiyle aynı kayıtta |
| E4 | Aykırı öncül 2 (belirteç tavanı): GT adının belirteçlerinin en az biri herhangi bir kanıt kaynağında geçen fonksiyon payı ≥ %50; **bütün** belirteçleri geçen pay ≤ %15. | ikisi birlikte |
| E5 | `oz_ad`: doğru adlarda ad, dizgide **bütün bir tanımlayıcı** olarak (sözcük sınırlı, `%s`'siz) ve tek fonksiyonda geçer; yanlışlarda dizgi birden çok fonksiyonda geçer ya da ad başka bir fonksiyonun adıdır (çağrılanın / hata iletisindeki API'nin). | keşifte ayrımcı özellik AUC ≥ 0,8 ya da kural: kesinlik ≥ %90, doğruların ≥ %70'ini tutar |
| E6 | Aykırı öncül 3: içe aktarım çağrısı olan nüfus fonksiyonu < %50; yani rolün yarıdan fazlası derinlik ≥ 1'de. | derinlik 0 payı < %50 |


## 2. Veri katmanı ve tutarlılık kapısı (10:35)

- Betik: `scripts/arge/ozkod/ozkod_veri.py` (`kur`, `ozet`). GT ve hüküm ölçüm betiklerinden içe aktarılıyor (`ks1_olc.gt_elf` / `gt_mac`, `urun_olc.degerlendir_elf`); veri sözcükleri N4'ün okuyucusundan (`docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.py`: `elf_oku`, `macho_oku`, `tablolari_sec`). Önbellek: `~/karadul_olcum/runs/arge-2026-11-19/ozkod/onbellek/`.
- Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ozkod_veri.py kur` (118 ikili, 41 sn), sonra `… ozet` → `~/karadul_olcum/runs/arge-2026-11-19/ozkod/tutarlilik.json`.
- Kapı: nüfus 20 747, ad 1 796, doğru 1 678, yanlış 118, nüfusta doğru 1 212, `oz_ad` 196 / 93. Taban ölçümünden fark tam olarak `redis-check-rdb` (≡ `redis-check-aof`, aynı dosya; tek sayıyorum): nüfus 624, ad 4 (3 doğru, 1 yanlış; 1 `oz_ad`). 20 747 + 624 = 21 371; 1 796 + 4 = 1 800. **Tuttu.**
- **Disiplin notu:** `ozet` çıktısı birim başına `oz_ad` doğru sayısını da bastı; sınama birimlerinin bu toplamlarını (zstd 45 adın 1'i doğru, sqlite3 7'nin 0'ı, redis 2'nin 0'ı, htop 1'in 0'ı) kural dondurulmadan gördüm. Fonksiyon düzeyinde hiçbir sınama verisine bakmadım. Kalem 1'in sınama sayımı bu yüzden "toplamı önceden görülmüş" notuyla okunmalı; birim toplamları zaten `sonuc.md` §2'den biliniyordu (zstd 55 / 9 / 46).
- OLGU tablosu bu an itibarıyla yok (`docs/arge/2026-11-19_mythos/olgu/` oluşmamış); kendi çıkarımımla ilerliyorum.

## 3. Kalem 2 — kayıt çifti, keşif (10:40)

Betikler: `scripts/arge/ozkod/kayit_cifti.py` (erişim + ilişki), `scripts/arge/ozkod/ek_kurali.py` (kural K1). Çıktılar: `~/karadul_olcum/runs/arge-2026-11-19/ozkod/kayit_cifti_kesif.txt`, `ek_kurali_kesif.txt` (+ `kayit_cifti/`, `ek_kurali/` altında JSON).

Komutlar:
```
PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/kayit_cifti.py --taraf kesif --ornekli
PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ek_kurali.py --taraf kesif --ornekli
```

### 3.1 Erişim ve ilişki (keşif)

| birim | nüfus | V kayıt dizgisi | C çağrı çifti | V ∪ C | V'de ad dizgisinin GT ile ilişkisi (tekil kayıt): ekli / örtüşme / ilgisiz |
|---|---:|---:|---:|---:|---|
| debian/coreutils | 12 717 | 0 | 12 | 12 (%0,1) | — |
| debian/openssl | 563 | 56 | 1 | 57 (%10,1) | 52 / 0 / 1 (53) |
| debian/tmux | 1 851 | 366 | 25 | 391 (%21,1) | 302 / 36 / 4 (342) |
| mac/tmux | 2 545 | 447 | 26 | 473 (%18,6) | 262 / 122 / 39 (423; N4 fazıyla — aşağıda) |

- "tam" (dizgi = ad) veri kayıtlarında 0; çağrı yerinde 27 / 45 (tmux `cmdq_get_callback1("ad", ad, …)`: makro fonksiyon adını dizgiye çeviriyor).
- "ekli" = GT adı = önek + dizgi + sonek. Örnekler (keşif): `format_cb_client_termtype` ← "client_termtype"; `window_copy_cmd_cursor_right` ← "cursor-right"; `cmd_split_window_exec` ← "split-window"; `rand_main` ← "rand".
- **E1 tuttu** (tmux ≥ %5: %21,1 / %18,6; coreutils < %2: %0,1). **E2 tuttu** (çiftli fonksiyonlarda "tam ∪ ekli" ≥ %30: openssl %98, debian tmux %88, mac tmux %62 — N4 fazıyla).

### 3.2 Neden olmadı / düzeltme: N4 fazı Mac tmux'ta bir tabloda kaymış

- İlk sürümde kayıt sınırını N4'ün faz seçimine bıraktım. Mac tmux'ta 100 üyeli `window_copy_cmd_*` tablosunda kayıt `{S ad, Z, E, Z, Z, V, F}` (adım 7); N4 fazı F'yi sonraki kaydın dizgisiyle eşledi (`window_copy_cmd_history_top` ← "jump-again"). Tür dizisi iki uçta da bir fazla dizgi bıraktığı için tiplerden ayırt edilemiyor (tablodan sonra başka dizgi yuvaları geliyor).
- Düzeltme (kural v2): faz varsayımı yok. Her fonksiyon yuvası için −adım < δ < adım aralığındaki **her** dizgi ofseti ayrı bir aday gruptur; doğru δ'yı çapa seçer (yanlış δ'da çapaların adı dizgiyi içermez, ek çıkmaz).
- İkinci sorun: yanlış δ grubunda, ardışık kayıtlar aynı fonksiyonu paylaşınca (tmux `cmd_*_entry`: aynı dosyadaki komutlar aynı `exec`'i kullanır) rastlantısal ek oyu çıkıyor ve çelişki üretiyordu (debian tmux'ta 150 çekimser). Düzeltme: oy fonksiyon düzeyinde ve kazanan ek gruptaki çapa fonksiyonlarının en az yarısını açıklamalı (`MIN_ORAN` = 0,5). Çelişki 150 → 22.

### 3.3 Kural K1 "kayıt çifti + sütun eki" — keşif sonucu

| birim | adaylı | kâhin çapa: ad / doğru (norm) | doğruların bugün adsız olanı | ürünün bugünkü adlarıyla (≥ 2 çapa): ad / doğru |
|---|---:|---|---:|---|
| debian/openssl | 57 | 52 / 52 (%100; %93,1–%100) | 52 | 0 / 0 |
| debian/tmux | 382 | 321 / 316 (%98,4; %96,4–%99,3) | 315 | 0 / 0 |
| mac/tmux | 473 | 381 / 372 (%97,6; %95,6–%98,8) | 369 | 97 / 95 |
| debian/coreutils | 9 | 0 / 0 | 0 | 0 / 0 |
| **keşif toplamı** | 921 | **754 / 740 (%98,1; %96,9–%98,9)** | 736 | 97 / 95 |

- Karakter eşitliği (ürün ölçüsü): 730 / 754. Fark openssl'de: `asn1parse_main` için norm `asn_1_parse_main` (rakam sınırı); kural adı üretirken dizgiyi belirteçlemeden, yalnız ayraçları `_` yaparak yazarsa kapanır (PLAN'a).
- Yanlışların hepsi GT adının düzensizliği: `format_cb_start_command` ← dizgi "pane_start_command" (hesaplanan `format_cb_pane_start_command`); `layout_set_main_h` ← "main-horizontal"; `cmd_list_commands` (ek `_exec` yok); `window_copy_search_match_cb`.
- Çapa benzetimi (GT'li fonksiyonların rastgele p payının adı biliniyor, 5 tohum): debian tmux p = %2 → hedeflerin 576 / 1 874'üne ad, %98,1 doğru; p = %5 → 1 240 / 1 809, %98,5. Yani tabloda 2 doğru ad bilinince tablo açılıyor.
- **Bugünkü darboğaz çapa:** ürünün bugünkü adları debian tmux ve openssl tablolarında hiç çapa vermiyor (0 ad); Mac tmux'ta `window_copy_cmd` tablosunda 2 ürün adı 95 doğru ad açıyor.
- Eksiz (dizgi = ad; yalnız çağrı çifti): 45 ad, 27 doğru (tmux'ta 12 / 16 ve 15 / 19; coreutils'te 0 / 9: `parse_gnu_standard_options_only(…, "hostid", "coreutils", …, usage)` çağrısında dizgi program adıdır). Tek başına kural değil.

## 4. K1 DONDURMA ve sınama ön kaydı (10:44; sınama birimlerinde hiçbir kayıt çifti çıktısına bakılmadan)

- Dondurulan betikler (sha256):
  - `ek_kurali.py` 7d02a6b58e05f2dc8c70b8bb0764fd89b59e040079d7f470fca79ac6e994741c
  - `kayit_cifti.py` 69201c56df4b10ed347d3ecfa88337c95b8ba3c68f6ea5dd2580ad22f91e9cbc
  - `ozkod_veri.py` 8767bde0647f411ff092469f6a7dfbd4f148a672d0552283cc63295f9e94e6a9
- Kural: `ek_kurali.py` belge dizgisi (T / N / C aday grupları, `MIN_DESTEK` = 2, `MIN_ORAN` = 0,5, çelişkide çekimser). Değişke `--nesne-gevsek` keşifte ad üretmedi (4 ek ad, Mac tmux); sınamada **yön gösterici** olarak ayrıca basılır, hükme girmez.
- Sınama komutları:
```
PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/kayit_cifti.py --taraf sinama
PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ek_kurali.py --taraf sinama
```
- **Ön kayıt (sınama, kâhin çapa):**
  - S1 (kesinlik): ad verilenlerde doğru (norm) ≥ %90 ve n ≥ 50. Tutmazsa: K1 keşif birimlerine (tmux, openssl) aşırı uymuş demektir.
  - S2 (erişim): sınama nüfusunda V ∪ C çiftli pay, en az iki sınama biriminde ≥ %5. Beklentim: redis-tools ve htop'ta var (komut tablosu, sınıf nesneleri), zstd ve tree'de yok, sqlite3'te küçük.
  - S3 (ilişki): çiftli fonksiyonlarda belirlenimci ad dizgisinin "tam ∪ ekli" payı ≥ %50.
  - S4 (ürün çapası): bugünkü adlarla ≥ 2 çapalı ad sayısı küçük (< 20); varsa doğruluğu ≥ %90.
  - Tutmayan beklenti silinmez.

## 5. Kalem 2 — sınama sonucu (10:50; dondurulmuş betiklerle, sha256 aynı)

Çıktılar: `~/karadul_olcum/runs/arge-2026-11-19/ozkod/kayit_cifti_sinama.txt`, `ek_kurali_sinama.txt`, `ek_kurali_sinama_nesne_gevsek.txt`, `ek_kurali_sinama_hata.txt`.

| birim | nüfus | V ∪ C çiftli | K1 kâhin: ad / doğru (norm) | karakter | ayraçsız |
|---|---:|---:|---|---:|---:|
| debian/htop | 222 | 77 (%34,7) | 26 / 17 (%65,4; %46,2–%80,6) | 0 | 19 |
| mac/htop | 597 | 73 (%12,2) | 17 / 13 (%76,5; %52,7–%90,4) | 0 | 15 |
| debian/redis-tools | 834 | 167 (%20,0) | 71 / 65 (%91,5; %82,8–%96,1) | 35 | 65 |
| debian/sqlite3 | 389 | 28 (%7,2) | 12 / 8 (%66,7; %39,1–%86,2) | 0 | 9 |
| debian/tree | 110 | 1 (%0,9) | 0 | 0 | 0 |
| debian/zstd | 919 | 0 | 0 | 0 | 0 |
| **sınama toplamı** | 3 071 | 346 (%11,3) | **126 / 103 (%81,7; %74,1–%87,5)** | 35 | 108 |

Ön kayıt hükümleri:
- **S1 TUTMADI.** Kesinlik %81,7 (eşik %90), n = 126. Yalnız redis-tools eşiğin üstünde (%91,5).
- **S2 tuttu.** V ∪ C ≥ %5 olan sınama birimi 4 (htop × 2, redis-tools, sqlite3). zstd 0, tree 1 fonksiyon (beklendiği gibi).
- **S3 tuttu** (havuzda): belirlenimci ad dizgisi "tam ∪ ekli" V'de 171 / 283 (%60,4), C'de 20 / 25. Ama redis-tools'ta %42,5 (N4 fazına bağlı sayım; K1'in δ'sız sayımı bunu aşıyor).
- **S4:** ürün çapasıyla 1 ad, 0 doğru (redis). Sayı beklenen kadar küçük; doğruluk ölçülemez.

Neden tutmadı (dondurulmuş ölçümden SONRA yapılan döküm; `ek_kurali_hata.py --taraf sinama`; bu bölümden çıkan hiçbir düzeltme bu sette yeniden sayılmadı):
- 23 yanlışın çoğu GT adının düzensizliği ya da belirteç sınırı: `FileDescriptorMeter_display` ← `file_descriptors_meter_display` (çoğul), `ZfsArcMeter_*` ← `zfsarc_meter_*` (dizgi "ZFSARC"), `recoverGetPage` ← `recover_getpage`, `ieee754func_from_blob` ← `ieee_754_from_blob_func`, `clusterManagerCommandDeleteNode` ← `…_del_node`, `HugePageMeter_*` ← `huge_pages_meter_*`.
- Gerçek yanlış az: `SysArchMeter_updateValues` ← `system_meter_update_values`, `db_errorfb` ← `db_traceback` (Lua `{"traceback", db_errorfb}`), `lua_cjson_new` / `json_decode` / `json_encode` ← `json_cfg_*` (ek aynı tablodaki başka ailelerden öğrenilmiş).
- Belirteç düzeyi (`ek_kurali_belirtec.py`): sınamada belirteç kesinliği 382 / 404 (%94,6), duyarlılığı 382 / 410 (%93,2); keşifte %99,6 / %99,9.
- Karakter eşitliği sınamada 35 / 126: kural adı snake_case yazıyor, GT camelCase (`CPUMeter_updateValues`, `luaB_next`). Ek, çapanın yüzey biçiminden (karakter düzeyinde) öğrenilmeli; bu ölçülmedi (PLAN).
- Kâhin olmayan çapa: benzetimde p = %5 → redis 32 / 32; p = %10 → havuz 108 / 128 (%84,4). htop ve sqlite3'te grup küçük (3–6 üye): 2 çapa bulmak zor.
- Yön gösterici değişke (`--nesne-gevsek`; keşifte sınanmadı): sınamada 175 ad, 152 doğru (%86,9); htop'ta sınıf nesneleri bitişik değil ve tür dizileri farklı olduğu için katı anahtar gruplamıyordu (N4'ün zayıflık 2'si).

**Okuma:** aykırı öncül 1 iki tarafta da tuttu (ad taşıyan dizgi fonksiyonun yanında, kaydında duruyor ve ada kuralla bağlanıyor); K1'in keşifteki %98'i sınamada %82'ye indi. Düşüşün ölçülen nedeni kuralın bozulması değil, programların ad düzeni: tmux ve openssl adlarını dizgiden mekanik türetiyor, htop / sqlite3 elle kısaltıyor. Tam eşitlikle "≥ %90" iddiası yalnız tmux / openssl / redis türünde savunulabilir.

## 6. E3 — kebap kanalı "yanlış hedef" miydi? (10:51)

Betik / komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/kebap_hedef.py` → `~/karadul_olcum/runs/arge-2026-11-19/ozkod/kebap_hedef.txt`. Girdi: 1.22.1 koşusunun (`urun-yeni2-f30ac9a`) `kebap_ad` kayıtları (239) + bu turun V ∪ C adayları.

| birim | kebap adı | anan = kayıtlı | dizgi başka fonksiyonla kayıtlı | dizgi hiçbir kayıtta yok |
|---|---:|---:|---:|---:|
| debian/tmux | 101 | 0 | 4 | 97 |
| mac/tmux | 135 | 0 | 24 | 111 |
| openssl + sqlite3 | 3 | 0 | 0 | 3 |
| **toplam** | 239 | **0** | 28 | 211 |

- **E3'ün eşiği tuttu** (ad verilen fonksiyonların %0'ı o dizgiyle aynı kayıtta; eşik < %20), ama nedensel okuma yalnız kısmen doğru: 239 dizginin yalnız 28'i (%11,7) başka bir fonksiyonla kayıtlı; o 28'de kayıtlı fonksiyonun GT adıyla ilişki 26 "ekli" + 2 "örtüşme" (yani dizgi gerçekten o öbür fonksiyonun adını taşıyor). Kalan 211 dizgi (%88,3) hiçbir fonksiyonla kayıtlı değil: bunlar tmux'un seçenek anahtarları (`options_get(…, "monitor-bell")`); seçenek tablosunda fonksiyon işaretçisi yok. Bu dizgi fonksiyonun adını değil, **okuduğu veriyi** söyler.
- Sonuç: "kebap adı yanlış fonksiyona verildi" 28 / 239 için doğru; çoğunluk için dizgi hiçbir fonksiyonun adı değil. Kebap dizgisinden ad kuralı aramak yerine iki ayrı olgu: (a) kayıt çiftindeki dizgi → K1; (b) anahtar erişimi → kanıt satırı (bugünkü `string_roles`).

## 7. Kalem 1 — `oz_ad` ayrımı (keşif 10:52, DONDURMA 10:53)

Betik: `scripts/arge/ozkod/oz_ad_ayrim.py`; komut `… --taraf kesif --dok` → `~/karadul_olcum/runs/arge-2026-11-19/ozkod/oz_ad_kesif.txt` (ilk aday: `oz_ad_kesif_v1.txt`).

Keşif: 141 ad, 92 doğru (%65,2). Tek özellikle kesinlik:

| özellik | değer | ad | doğru |
|---|---|---:|---:|
| dizgiyi anan fonksiyon sayısı (`n_fn`) | 1 / 2 / 3+ | 116 / 21 / 4 | 84 / 8 / 0 |
| fonksiyonun andığı tanımlayıcı (alt çizgili) dizgi sayısı (`n_tanim`) | 0–1 / 2–3 / 4+ | 110 / 21 / 10 | 85 / 7 / 0 |
| ad çakışması (`_2` eki ya da aynı dizgi > 1 ada kanıt) | yok / var | 122 / 19 | 88 / 4 |
| dizgi fonksiyonun kendi xref listesinde | evet / hayır | 135 / 6 | 92 / 0 |
| dizgi başka bir fonksiyonla kayıtlı (V ∪ C) | hayır / evet | 133 / 8 | 92 / 0 |
| ürün güveni | 0,85 / 0,80 | 89 / 52 | 71 / 21 |
| kullanım rolü | biçim dolgusu / assert / anahtar / atama / metinde yok | 26 / 17 / 70 / 5 / 23 | 21 / 11 / 45 / 0 / 15 |

- **Neden olmadı (ilk aday, E5'in ilk yarısı):** "ad `%s` dolgusu ya da assert argümanı" kuralı tutmadı: tutulan 38 adın 31'i doğru (%81,6), doğruların yalnız %33,7'sini tutuyor. Neden: `__func__` çoğu kez bir yardımcıya düz argüman olarak geçiyor (tmux `screen_write_collect_flush(ctx, 0, __func__)`: 16 doğru ad, rol "anahtar"); Mach-O'da 15 doğru adın dizgisi C metninde sabit olarak hiç görünmüyor.
- **Tutan aday R1 "çift yönlü teklik":** `n_fn` = 1 ∧ `n_tanim` ≤ 1 ∧ çakışma yok ∧ kendi xref'inde ∧ başka fonksiyonla kayıtlı değil. Keşif: tutulan 80, doğru 77 (%96,2; %89,5–%98,7); doğruların 77 / 92'si (%83,7) tutuluyor; yanlışların 46 / 49'u (%93,9) atılıyor. Kalan 3 yanlıştan biri harf farkı (`process_certConf` ← `process_certconf`).
- Yorum: doğru `oz_ad` adı fonksiyonun kendi adının dizgisidir (`__func__`); o dizgi yalnız o fonksiyonda geçer ve fonksiyon başka tanımlayıcı dizgi anmaz. Yanlışlar veri anahtarıdır (`window_index` 10 fonksiyonda; `cmd_show_options_print` 13 tanımlayıcı dizgi anıyor) ya da satır içine alınmış çağrılanın `__func__`'ıdır (`grid_string_cells` ← "grid_peek_line": `n_fn` = 2).
- **E5:** ikinci yarısı tuttu ("yanlışlarda dizgi birden çok fonksiyonda geçer / başka fonksiyonun adıdır"); eşik "kesinlik ≥ %90 ve doğruların ≥ %70'i" keşifte tuttu (%96,2 / %83,7). Birinci yarısı ("sözcük sınırlı tanımlayıcı, `%s`'siz") ayırt edici değil: bütün `oz_ad` kanıtları zaten bütün bir tanımlayıcı.

**DONDURMA (10:53):** `oz_ad_ayrim.py` sha256 ccc73f5c5dbba90b09f7b5657ea810c5cb24dc24ea375042d94059f22e8c541b; kural `kural_tut`.

**Ön kayıt (sınama; 55 ad, toplamda 1 doğru olduğunu §2'deki kapıdan biliyorum):**
- R1-S1: yanlışların atılan payı ≥ %80.
- R1-S2: tek doğru ad tutulur (n = 1; anekdot).
- Sınama tarafında doğru ad olmadığı için R1'in duyarlılığı (doğruları tutma) burada sınanamaz; bağımsız nüfus ister (PLAN).
- Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/oz_ad_ayrim.py --taraf sinama`

## 8. OLGU ara teslimi (10:55; ana oturumun haberi)

- `~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` hazır (çekirdek + kaynak sınıfı; dizgi / komşu / kayıt çifti alanları ikinci teslimde). Kalem 3–5'te `kaynak_sinifi` alanını kullanacağım; dizgi ve çağrı kanıtı kendi önbelleğimden.
- Çapraz denetim (ana oturumun verdiği sayılar ↔ benim önbelleğim): aşağıda §9.

## 9. Kalem 1 — R1 sınama sonucu ve asıl neden: harf küçültme (R1 dondurmasından sonra)

Komut: `… oz_ad_ayrim.py --taraf sinama` → `oz_ad_sinama.txt` (dondurulmuş betik, sha256 aynı).

- Sınama: 55 ad, 1 doğru. R1 tutulan 31 (1 doğru), atılan 24 (0 doğru).
- **R1-S1 TUTMADI:** yanlışların atılan payı 24 / 54 (%44,4; eşik %80). R1-S2 tuttu (tek doğru ad tutuldu; anekdot).
- **Neden tutmadı (ölçümden sonra bakıldı):** zstd'nin 44 `oz_ad` adının kanıtı `__assert_fail`'in fonksiyon adı argümanı ve ad **doğru fonksiyonun adı, yalnız küçük harfe çevrilmiş**: GT `ZSTD_getCParamsFromCDict` ← ürün adı `zstd_getcparamsfromcdict`. Kaynak: `karadul/reconstruction/c_namer.py` `_extract_keywords_from_string` (`[a-zA-Z]{3,}` sözcükleri, küçük harf, en çok 4) + `_strategy_string_context` klasik aşaması (`"_".join(best_keywords[:3])`, `_sanitize_c_name` küçük harf). Yani `oz_ad`, kanıt dizgisi zaten bir tanımlayıcıyken onu parçalayıp yeniden kuruyor; ad ancak ≤ 3 sözcüklü, rakamsız, küçük harfli tanımlayıcılarda dizgiye eşit çıkıyor (tmux biçimi).
- Sayım (`scripts/arge/ozkod/oz_ad_harf.py` → `oz_ad_harf.txt`): kanıt dizgisi harfleriyle ad sayılsaydı 196 adın 133'ü doğru olurdu (bugün 93); yanlıştan doğruya dönen 40 (zstd 37, coreutils 1, openssl 1, mac/tmux 1). R1 tutulanlarda: keşif 78 / 80 (%97,5), sınama 28 / 31 (%90,3; **ölçüm sonrası tanım**, ön kayıtlı değil), toplam 106 / 111 (%95,5; %89,9–%98,1).
- Okuma: R1 doğruyu yanlıştan değil, "fonksiyonun kendi adı" olan dizgiyi "veri anahtarı" olan dizgiden ayırıyor; zstd'de yanlışların nedeni ayrım değil yazım. İki ayrı onarım: (1) harfi koru, (2) R1.

## 10. G1 — R1'in üretici hâli (keşif, ardından ayarsız DONDURMA; §9'dan sonra)

- Soru: `oz_ad` bugün yalnız ≤ 3 sözcüklü adları doğru yazabiliyor. Kural "tekil tanımlayıcı dizgi → ad, hiç dönüştürmeden" bütün nüfusa uygulanırsa ne verir?
- Betik: `scripts/arge/ozkod/oz_ad_uretici.py` (sha256 7ee4edfc59265ea9cce522ab04a0503c9a3ded1fd4876047f9ced82035ac0acb); kural belge dizgisinde (G1). Keşifte **ayar yapılmadı** (ilk yazılan hâl).
- Keşif (`oz_ad_uretici_kesif.txt`): nüfusta 484 ad, 454 doğru (%93,8; %91,3–%95,6). Doğruların 121'i bugün adsız, 2'si bugün yanlış adlı, 331'i bugün de doğru (235'i `ks1:func_kalibi`, 84'ü `oz_ad`). Yanlış 30: 10'u bugün adsız, 14'ü bugün de yanlış, 6'sı bugün doğru (`main` girişleri; G1 düşük öncelikli kalırsa ezmez).
- **Ön kayıt (sınama):** G1-S1: kesinlik ≥ %85 ve ad ≥ 30. G1-S2: bugün adsız olup G1'in doğru ad verdiği fonksiyon ≥ 20. Not: zstd'nin `oz_ad` kayıtlarını §9'da gördüm; G1'in zstd'de çok ad vereceğini bu yüzden biliyorum. Bu ön kayıt o bilgiyle yazıldı; bağımsız sayılmaz, "yarı kör" diye okunmalı.

## 11. G1 sınama sonucu (G1 dondurmasından sonra)

Komut: `… oz_ad_uretici.py --taraf sinama` → `oz_ad_uretici_sinama.txt`.

- Sınama: 143 ad, 114 doğru (%79,7; %72,4–%85,5). **G1-S1 TUTMADI** (eşik %85). **G1-S2 tuttu** (bugün adsız olup doğru ad alan 90; ayrıca bugün yanlış adlı 24 fonksiyon doğru ada dönüyor).
- Birim: zstd 134 ad / 114 doğru (%85,1). zstd dışı (htop 1, redis-tools 5, sqlite3 3): 9 ad, **0 doğru**.
- Neden: `__func__` kullanmayan programlarda "tek tanımlayıcı dizgi" fonksiyonun adı değil, veri anahtarıdır. G1 kanıtın **türünü** bilmiyor; yalnız tekliğe bakıyor. Keşifte bu görünmedi, çünkü keşif birimlerinin hepsi (tmux, coreutils, openssl) `__func__` / assert kullanıyor.
- Sonraki adım (PLAN): G1'e ikili düzeyinde "bu program `__func__` taşıyor" kanıtı (KS-1 çapası ≥ 1 ya da `__assert_fail` ailesi çağrısı) ya da dizgi düzeyinde kullanım rolü eklenip **bağımsız nüfusta** sayılmalı. Bu sette yeniden sayılmadı.

## 12. Kalem 3–5 — tavanlar (yalnız sayım, kural yok)

Betik / komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/tavan.py` → `~/karadul_olcum/runs/arge-2026-11-19/ozkod/tavan.txt`, `tavan.json`. Kaynak sınıfı OLGU tablosundan (`kaynak_sinifi`), kanıt kendi önbelleğimden. Tam set (117 C ikilisi; `redis-check-rdb` tekrar sayılmadı).

**Çapraz denetim (ana oturumun OLGU sayıları):** `oz_ad` sınıf kırılımı — program 96 / 49 (OLGU 97 / 49; fark `redis-check-rdb`'deki 1 ad), proje kitaplığı 27 / 0, gnulib 9 / 4, Mac 64 / 40. **Tuttu.**

### 12.1 Belirteç tavanı (kalem 3)

| kesit | fonksiyon | en az 1 belirteç: bugünkü kaynaklar / kâhin | bütün belirteçler: bugün / kâhin | belirteç (mikro): bugün / kâhin |
|---|---:|---|---|---|
| bütün nüfus | 20 742 | %33,7 / %59,3 | %7,6 / %16,1 | %24,2 / %43,9 |
| programın kendi kodu (ELF) | 4 777 | %52,1 / %71,6 | %13,4 / %23,1 | %33,1 / %51,9 |
| gnulib | 11 393 | %18,7 / %45,3 | %1,6 / %7,7 | %11,0 / %27,6 |
| proje kitaplığı (zstd `lib/`) | 720 | %63,5 / %83,8 | %39,6 / %50,3 | %53,6 / %71,6 |
| Mac (sınıf bilinmiyor) | 3 147 | %53,0 / %86,4 | %12,1 / %27,4 | %31,9 / %61,4 |

- "Bugünkü kaynaklar" = doğrudan dizgi ∪ derinlik 1 çağrılanın dizgisi ∪ kayıt çifti ∪ içe aktarım adı ∪ komşunun bugün bilinen adı. "Kâhin" = buna derinlik 2 dizgileri ve komşuların GT adı eklenmiş (komşuların hepsi doğru adlandırılmış olsaydı).
- Kaynak başına (bütün nüfus, en az 1 belirteç): doğrudan dizgi %12,1; derinlik 1 %10,4; derinlik 2 %6,9; kayıt çifti %5,7; içe aktarım adı %8,3; komşunun bugünkü adı %11,2; komşunun GT adı %48,2; dosya yolu dizgisi %2,6.
- Bütün belirteçleri tek kaynakta bulunan: doğrudan dizgi %5,4 (1 116; çoğu `__func__`), komşu GT adı %9,2, kayıt çifti %0,2 (ek dışarıda kaldığı için), içe aktarım %0,3.
- **E4:** ikinci yarı tuttu (bütün belirteçler ≤ %15: bugün %7,6); ilk yarı bütün nüfusta TUTMADI (en az 1 belirteç ≥ %50 beklenmişti: %33,7), programın kendi kodunda tuttu (%52,1).
- Okuma: programın kendi kodunda adın **yarısı** (belirteç olarak %33; kâhinle %52) ikilide bir yerde yazılı; adın **tamamı** yedi fonksiyondan birinde. En büyük tek kaynak komşunun adı: adlar birbirinden türüyor (ortak modül öneki). Belirtecin varlığı adı vermez: seçme ve sıra sorunu ayrıca çözülmeli; bu sayılar üst sınırdır.

### 12.2 Rol derinliği (kalem 4)

| kesit | fonksiyon | içe aktarım çağrısı: derinlik 0 / 1 / 2 / 3 / yok | ayırt edici içe aktarım: 0 / 1 / 2 / 3 / yok | derinlik 1'de taşıyan ortak sarmalayıcı |
|---|---:|---|---|---|
| bütün nüfus | 20 747 | %62,6 / %18,6 / %2,5 / %0,5 / %15,8 | %36,7 / %29,3 / %6,5 / %3,2 / %24,2 | 4 579 / 6 086 (%75,2) |
| programın kendi kodu | 4 777 | %65,2 / %17,4 / %2,4 / %0,3 / %14,7 | %44,4 / %21,5 / %8,3 / %2,2 / %23,5 | 766 / 1 029 (%74,4) |
| debian/tmux | 1 851 | %49,5 / %27,5 / %4,8 / %0,8 / %17,5 | %26,2 / %31,4 / %15,9 / %4,4 / %22,0 | 502 / 582 (%86,3) |
| mac/tmux | 2 545 | %40,3 / %26,0 / %11,4 / %2,2 / %20,1 | %25,6 / %30,1 / %17,4 / %3,9 / %23,1 | 623 / 765 (%81,4) |
| debian/openssl | 563 | %87,0 / %4,1 / … | %79,0 / %7,3 / … | 30 / 41 |

- "Ayırt edici" = ikilinin iç fonksiyonlarının en çok %5'inin çağırdığı içe aktarım (`malloc`, `strlen` gibi yaygınlar dışarıda).
- **E6:** "derinlik 0 payı < %50" — her içe aktarım sayılınca TUTMADI (%62,6); ayırt edici içe aktarımda tuttu (%36,7).
- **Aykırı öncül 3'ün hükmü: karışık.** Bütün nüfusta ayırt edici çağrıya doğrudan ulaşan %36,7, bir ya da daha çok çağrı ötede ulaşan %39,0; derinlik 1'dekilerin %75,2'sinde taşıyan çağrılan ortak bir sarmalayıcı (≥ 5 çağıranlı). tmux'ta öncül tutuyor (%26 doğrudan, %52 dolaylı); programın kendi kodu havuzunda ve openssl / sqlite3'te tutmuyor (doğrudan çağrı baskın). Dörtte bir fonksiyonun 3 çağrı içinde ayırt edici hiçbir içe aktarımı yok.
- Sınır: bu sayım rolü hangi çağrının verdiğini ölçmez (etiket yok); yalnız "rol verebilecek bir çağrı ne kadar uzakta" sorusunun vekili.

### 12.3 Modül öneki yayılımı (kalem 5, A6)

| kesit | önekli fonksiyon | çağrı komşularının çoğunluğu (kâhin): doğru / karar | iki adres komşusu uzlaşıyor (kâhin): doğru / karar | bugünkü adlarla sandviç (aralık sınırsız): doğru / karar |
|---|---:|---|---|---|
| bütün nüfus | 16 625 | 5 362 / 9 712 (%55,2) | 8 665 / 8 987 (%96,4; %96,0–%96,8) | 2 216 / 2 545 (%87,1; %85,7–%88,3) |
| programın kendi kodu | 4 353 | 1 026 / 2 457 (%41,8) | 2 284 / 2 417 (%94,5) | 740 / 809 (%91,5) |
| keşif | 13 713 | 4 429 / 7 807 (%56,7) | 6 927 / 7 155 (%96,8) | 1 586 / 1 717 (%92,4) |
| sınama | 2 912 | 933 / 1 905 (%49,0) | 1 738 / 1 832 (%94,9) | 630 / 828 (%76,1) |
| debian/redis-tools | 741 | 286 / 555 (%51,5) | 353 / 391 (%90,3) | 139 / 282 (%49,3) |
| debian/coreutils | 8 855 | 2 842 / 4 569 (%62,2) | 2 861 / 3 045 (%94,0) | 140 / 228 (%61,4) |

- Önek = GT adının ilk belirteci. "Sandviç" = bugün adsız fonksiyonun adres sırasında önündeki ve arkasındaki en yakın bugün adlı fonksiyonların öneki aynıysa o önek.
- **Sonuç: modül önekini çağrı grafiği değil adres sırası (derleme birimi yerleşimi) taşıyor.** Çağrı komşularının çoğunluğu kâhin adlarla bile %55 (programın kendi kodunda %42); iki adres komşusunun uzlaşması %96. P12b'nin "çağıranın modül öneki" adayı (kalem 5) bu yüzden zayıf zemin; doğru zemin adres aralığı.
- Bugünkü adlarla sandviç: 2 545 fonksiyona önek, %87,1 doğru (tmux %94–%99, zstd %91, htop %85; redis-tools %49, coreutils %61 — çapalar seyrek ve gnulib / üçüncü taraf araya giriyor). Kural olarak dondurulmadı; önek ad değil, kanıt satırıdır (`modül: tty_keys`).

## 13. Kalem 6 — bağımsız sınama nüfusu adayları (yazıldığı an: 11:03)

Betik: `scripts/arge/ozkod/aday_paket.py` (yerel Debian 13 arm64 dizininden boyut; hiçbir şey indirilmedi) → `aday_paket.txt`. Kilitli test / doğrulama setlerindeki ve yedek sıralarındaki adlar dışlandı (kilit belgelerinden yalnız program adları okundu; ör. git, vim, zsh, lua, weechat, php bu yüzden yok). Liste BULGULAR §6'da.

> **Saat notu:** `date` çıktısı olan saatler üç tanedir: başlangıç 10:30, K1 dondurma 10:44, R1 dondurma 10:53 (ve §13'teki 11:03). Öbür başlıklardaki saatler (10:35, 10:40, 10:50, 10:51, 10:52, 10:55) yaklaşıktır. §9–§12 saat taşımaz; sıraları yazıldıkları sıradır ve her dondurma, o kuralın sınama çıktısından önce yazılmıştır (dondurulan betiklerin sha256'ları ilgili bölümde).

## 14. K1'in bugünkü çapalarla getirisi (`ek_kurali_capa.py`; dondurulmuş `ek_kurali.py` değişmeden)

Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ek_kurali_capa.py` → `ek_kurali_capa.txt`.

| çapa kaynağı | ad | doğru (norm) | not |
|---|---:|---|---|
| A: ön ad kanalları (`on_ad:*`, `ks1:*`) + Ghidra adları | 98 | 95 (%96,9; %91,4–%99,0) | 97'si Mac tmux `window_copy_cmd_*` |
| B: A + R1'den geçen `oz_ad` (harf korunmuş) | 98 | 95 | R1 adları yeni tablo açmıyor |
| C: A + G1 | 242 | 239 (%98,8; %96,4–%99,6) | debian tmux 121 / 121, mac tmux 118 / 120 |
| D: ürünün bugünkü bütün adları | 98 | 95 | `ek_kurali.py` "urun" kipiyle aynı (denetim) |

- Sınama birimlerinde hiçbir kipte çapa yok (1 ad, 0 doğru): htop / redis / sqlite3 `__func__` taşımıyor; tabloları ancak dış çapa (KİMLİK, analist) açar.
- Doğrulama: G1'in yanlış olup ürünün bugün doğru olduğu 6 ad — hepsi `on_ad:main_giris` (`main`); satır içi denetimle sayıldı (`oz_ad_uretici.g1` + `capa_degerlendir`).

## 15. OLGU ikinci teslimi ve çapraz denetim

- `docs/arge/2026-11-19_mythos/olgu/DEFTER.md` "## ARA TESLİM 2" geldi; tablo sha256 `c9fa66cb…` — çapraz denetimi koştuğum tabloyla aynı.
- Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/olgu_capraz.py` → `olgu_capraz.txt`. Nüfus 20 747 = 20 747; pencere çifti OLGU 1 196 / bu hat 1 193 (3 fonksiyon farklı: redis-tools 2, mac/tmux 1); doğrudan dizgili fonksiyon 5 088 = 5 088; D0 "en az 1 belirteç" 2 504 / 2 507 (OLGU uzun dizgiyi kırpıyor). OLGU'nun `cagri_ciftleri` alanı `desteklenmiyor`; bu hattın C metni çıkarıcısı 92 nüfus fonksiyonu veriyor.
- Belirteç tavanı ve kayıt çifti tavanı baştan beri tam sette (117 C ikilisi) sayıldı; OLGU ile iki bağımsız çıkarım aynı sayıyı veriyor. Üç fonksiyonluk farkın nedenine bakılmadı (çapa / dizgi tanımı ayrıntısı olabilir).

## 16. Tur sonu — durum ve sonraki ajan için

- **Biten kalemler:** 1 (`oz_ad` ayrımı + harf kusuru + G1), 2 (kayıt çifti tavanı, K1, E3, N4 farkı), 3 (belirteç tavanı), 4 (rol derinliği), 5 (modül öneki), 6 (aday nüfus listesi). Hepsi tam sette.
- **Ölçülemeyenler** (`PLAN.md` ÖK-7): karakter düzeyinde ek; rolü hangi çağrının verdiği (etiket yok); koşut diziler; satır içi `__func__`; K1 çelişkilerinde seçim; gevşek nesne anahtarı; x86-64 / PE; belirteç seçimi; `urun_olc` proje normalleştirmesi ↔ harf farkı.
- **Bu sette artık yapılmaması gereken:** K1, R1, G1 kurallarına ayar. Keşif de sınama da görüldü; her yeni ayar aşırı uyumdur. Yeni ayar yalnız ÖK-V nüfusunun "ayar" tarafında.
- **Dondurulmuş betikler (sha256):** `ek_kurali.py` 7d02a6b5…, `kayit_cifti.py` 69201c56…, `ozkod_veri.py` 8767bde0…, `oz_ad_ayrim.py` ccc73f5c…, `oz_ad_uretici.py` 7ee4edfc… (tam değerler §4, §7, §10).
- **Yaratıcılık protokolü (tek satır):** (1) denetlenebilir soru — uygulandı (her kalem sayım ya da tam eşitlik); (2) uzlaşıyı kır — uygulandı (üç aykırı öncül sınandı; yasak cevap getirilmedi); (3) tek hatta kal — uygulandı (başka hatlara notlar `BULGULAR.md` §9); (4) insan uzman — "yakın ad" hükmü verilmedi; K1 eşiğe gelirse dış uzman okuması `PLAN.md` ÖK-5'ten sonra.
- Ana oturumun verdiği OLGU bütçe sayılarıyla çapraz denetim: `program` sınıfı nüfusu OLGU 4 977 (119 ikili) ↔ bu hat 4 777 belirteçli fonksiyon (117 ikili; fark `redis-check-rdb`'nin `program` sınıfı satırları, 200); `oz_ad` sınıf kırılımı §12'de birebir (program 96 + 1, proje kitaplığı 27 / 0, gnulib 9 / 4, Mac 64 / 40). "64 bayttan küçük fonksiyonlarda doğru ad yok" sayısı bu hatta yeniden sayılmadı (boyut kırılımı kalemlerimde yok).
