# P13a ön kaydı — ad yan yolları (AD-06, AD-09, AD-04/05, AD-11 + B-C6, AD-12) + bekletilen GHIDRA-16 (`808a7f8`)

Yazıldığı an: 2026-11-18 18:20, kod değişmeden ÖNCE (taban **d2f205d** = yerel `main` ucu, sürüm 1.24.1). Bu dosya
kod commit'lerinden önce commit'lenir; sonradan değiştirilmez. Tutmayan madde `P13a.md`'ye "tutmadı" diye yazılır,
kural sonradan gevşetilmez.

## Bu kayıttan önce görülenler
- Genel tarama çıktısı (`~/karadul_olcum/runs/genel-tarama-2026-11-18`, 14 ikili, 1.23.1): hiçbirinde
  `reconstructed/binary_names.json` yok, yani Faz 1 çıkarıcısı (BinaryNameExtractor) bugünkü ürünle bu ikililerde ad
  üretmiyor (`ghidra_strings.json`'da dizgi → fonksiyon bağı yok; GHIDRA-16 bekletildi). urun-yeni2'de 119 ikilide 2 ad
  (`debug_string`). Yani AD-06 / AD-09 bugünkü `main`'de geliştirme setinde etkisiz; etkisi `808a7f8` ile görünür.
- P16a kol B (`808a7f8`, 8 ikili): `on_ad:faz1` 60 ad, 2 doğru / 58 yanlış, 0,95 güvenle; gnulib'in 4 doğru adı ezildi;
  yanlış ad 31 → 77, kaybedilen doğru 4 / 54 (`docs/arge/2026-11-18_onarim/P16a.md` kalem 10). Hangi Faz 1
  stratejisinin kaç ad verdiğine (kaynak kırılımı) bakılmadı.
- Geliştirme setinde C++ ikili yalnız `debian/zstd/pzstd` (ad tablosunda `_M_append`, `~_State`); `urun_olc.py` C++
  ikilileri ölçüm dışında tutar (`ks1_olc.cpp_ikili_mi`), GT hükmü yok. Geliştirme setinde ObjC ikili yok.
- Kod okuması: `parallel_algo_eng.py:139-142` ham listeyi sözlüğe çeviriyor (son kazanır); `as_naming_map` eşik /
  fonksiyon başına en iyi / çift ad temizliği yapıyor. `stages._seed_recovery_pre_names` künyesiz bütün çıkarıcı
  adlarını `faz1` türüyle ön ad yapar. NameMerger'ın kararı yalnız c_namer'ın ad vermediği anahtarlarda koda ulaşır;
  `_add_binary_extractor` ön adları 0,85 ile ikinci kaynak sayar; `_add_c_namer` güveni olmayan anahtara 0,70 yazar.

## Kurallar (dondurulmuş)
1. **AD-06.** Ön ad sözlüğü `BinaryNameExtractor.as_naming_map()`'tir (eşik `min_naming_confidence`, fonksiyon başına
   en yüksek güven, aynı ad iki fonksiyona verilmez). `binary_names.json` fonksiyon başına SEÇİLEN kaydı yazar; seçilmeyen
   öneriler nedeniyle (`esik_alti`, `daha_iyisi_var`, `ad_baska_fonksiyonda`, `dizgi_kanali`) aynı dosyada aday olarak
   kalır (K-2: ad yerine kanıt satırı).
2. **AD-09.** Faz 1'in dizgi içeriğinden ad kuran önerileri (`string_intel`; `debug_string`'in dizgi kaynaklı dalı —
   dizgideki `Class::Method`; ihraç simgesinden gelen `debug_string` değil) ön ad kanalına GİRMEZ. Bunlar c_namer'a
   `string_context` adayı olarak gitmelidir (aynı susturma / ürün eşiği / ad geçerliliği). c_namer'ın aday arayüzü
   yoksa `c_namer.py`'ye dokunulmaz: yama (`yamalar/P13a__c_namer.py.patch`) bırakılır ve adaylar `binary_names.json`'da
   kanıt satırıyla kalır.
3. **AD-04 / AD-05.** c_namer koştuysa ön adlar birleştiriciye ikinci kez (`binary_extractor`) girmez; c_namer'ın ad
   verdiği anahtarın kararı c_namer'ındır (birleştirici onu yeniden puanlamaz, uydurma 0,70 yok). Birleştiricinin
   koda giden haritası `name_validity.reject_reason` + var olan fonksiyon adlarıyla çakışma süzgecinden geçer; c_namer'ın
   reddettiği ön ad anahtarı birleştiriciden ad almaz. Birleştiricinin kararı (koda gitsin gitmesin) köken kaydına
   (`naming_provenance.json`, `name_merger` bölümü) yazılır. Aynı mühendislik eşleşmesi iki kaynak sayılmaz.
4. **AD-11 + B-C6.** BinDiff / ReferenceDiffer elle, `main` ve KS-1 künyeli ön adı ezmez; elle ad birleştirmeden SONRA
   koda giden haritaya zorlanır (ad geçerliliğinden geçerse).
5. **AD-12.** Paralel ad koşucusu çağıran-yok kanıtıyla silinir.

## Ölçüm düzeni
- Ürün koşusu `kos_arsiv.py` (urun_kos.py'nin kendisi; ağaç `git archive` kopyası, commit `.agac_commit`'te),
  `PYTHONHASHSEED=0`, `--paralel 1`, koşu başına `KARADUL_CACHE_DIR`. Kök `~/karadul_olcum/runs/onarim-2026-11-18/P13a/`.
- İkililer (10): geliştirme setinden `debian/coreutils/{cat,expr,ls,sort}`, `debian/htop/htop`, `debian/sqlite3/sqlite3`,
  `debian/tree/tree`, `mac/htop` (P16a kol B'nin 8'i; GT'li), `debian/zstd/pzstd` (C++; GT hükmü yok) ve geliştirme
  seti DIŞINDAN `/usr/bin/defaults` (Mach-O, ObjC; kopya `corpus/defaults`, sha256 `07fa9d3c29f6b755…`; GT yok).
- Kollar: **T0** taban (d2f205d) 10 ikili; **T0b** aynı kod ikinci kez (cat, sqlite3) = gürültü tabanı; **S** kalem
  1–5 commit'lerinden sonra 10 ikili; **S808** S + `808a7f8` 10 ikili.
- Ad ölçüsü `urun_olc.py olc` / `karsilastir` (8 GT'li ikili; kanal kırılımı); GT'siz ikili ve kanal sayıları
  `binary_names.json` + `naming_provenance.json` + `report.json` stats'tan (`p13a_say.py`, ölçüm kökünde).

## Beklentiler
| # | Ölçü | Kol | Beklenti | Tutmadı sayılır |
|---|---|---|---|---|
| H1 | `on_ad:faz1` ön adlarının çıkarıcı güveni (10 ikili) | S | hepsi ≥ 0,70; aynı ad iki anahtarda 0 | < 0,70 ya da çift ad var |
| H2 | `on_ad:faz1` ön adlarından dizgi kaynaklı (`string_intel`, dizgi `debug_string`) | S, S808 | **0** | > 0 |
| H3 | `name_merger_exact_multi` (coreutils 4 ikili toplamı) | T0 → S | T0'da > 0 → S'de **0** | S'de > 0 |
| H4 | `reconstructed/src` ↔ `reconstructed/merged` arasında değişen `FUN_`/`DAT_` belirteci (9 geliştirme ikilisi) | S | T0'daki kadar ya da az; c_namer'ın reddettiği ön ad anahtarına birleştiriciden ad **0** | açıklanamayan artış |
| H5 | Fonksiyon adı farkı (`urun_olc karsilastir`, 8 GT'li ikili) | T0 → S | doğru / yanlış değişmez (fark yalnız T0 ↔ T0b gürültüsü kadar) | açıklanamayan değişim |
| H6 | `naming_provenance.json`'da `name_merger` bölümü | S | 10/10 koşuda var (karar sayıları gerçek) | eksik |
| H7 | `on_ad:faz1` adı (8 GT'li ikili) | S808 | P16a kol B'deki 60'tan **≤ 5**'e | > 5 |
| K6a | Yanlış ad (havuz, 8 GT'li ikili) | S → S808 | S808 ≤ S × 1,05 | aşarsa `808a7f8` alınmaz |
| K6b | Kaybedilen doğru ad (S → S808) | S → S808 | ≤ S'deki doğruların %5'i ve `on_ad:gnulib` kanalında kayıp **0** | aşarsa `808a7f8` alınmaz |

Karar: H1–H3 tutmazsa ilgili kalem commit'lenmez, fark açıklanana kadar durulur. K6a ve K6b birlikte tutarsa `808a7f8`
dala alınır (P12a'nın sıra yaması ve testi korunur); biri tutmazsa alınmaz, sayılar ve neden yazılır.

## Aykırı öncüller (sınanacak)
1. "Dizgi önerileri ön ad kanalından çıkınca Faz 1 hiç doğru ad vermez; P16a'nın 2 doğrusu kaybolur" → H7 ve S808'de
   `on_ad:faz1` doğru sayısı ayrıca yazılır (kayıp kabul: 2 doğru / 58 yanlışlık bir kanal; K-2 gereği adaylar kanıt
   satırında kalır).
2. "Birleştirici zaten koda ulaşmıyor; süzgeç eklemek hiçbir şey değiştirmez" → H4: değişmezse merger'ın kaldırılması
   ölçülerek tartışılır (silinmez).
3. "`808a7f8` c_namer'ın kendi `string_context` adaylarını da çoğaltır (dizgi → fonksiyon bağı c_namer'a da gelir);
   Faz 1 onarılsa bile yanlış ad artar" → K6a, kanal kırılımıyla.
