# P-ÜV6b ön kaydı (Swift ad kanalı + C++ RTTI kanıt satırı)

Yazıldığı an: 2026-11-24 13:16, ölçümden ÖNCE (kod henüz yazılmadı). Sayılar ve eşikler ana oturumun
(`docs/arge/2026-11-23_dalga1/gonderim/PUV6b.md` "Ön kayıt"); bu belge onları aynen kaydeder ve yöntemi
adıyla yazar. Tutmayan beklenti silinmez; eşik sonradan değişmez.

## Beklentiler (aynen)

> H1 (öntanım): bayraklar kapalıyken S8'in 5 ikilisinde (cat, tree, sqlite3, zstd, mac/tmux) `out/naming_map.json`,
> `decompiled/*.c` ve `out/src` tabanla (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b`: son main'in
> tabanı, 2026-11-24'te üretildi; aynı sıra, tek kök; kökte `BITTI` dosyası yoksa bekle) aynı; yeni iki adımın süresi
> ≤ 0,1 sn.
>
> H2 (bayraklar açık ↔ kapalı, aynı ağaç): aynı 5 ikili + debian `pzstd`'de değişen ad 0; `pzstd`'de RTTI kanıt
> satırı ≥ 1, RTTI kaynaklı ad 0.
>
> H3 (Swift, iTerm2, SINAMA, bir kez, dondurmadan sonra): aday düzeyinde yanlış ad oranı ≤ %1 ve Wilson alt sınırı
> ≥ `AD_ESIGI`; aday sayısı ilk ölçüm (okuyucu 2 627 tipe ad veriyor).
>
> H4 (RTTI, llama-server, SINAMA, bir kez): kanıt satırı sayısı 6 990 ± 42 (ürün bağı; belirsiz 42); RTTI kaynaklı
> ad 0.
>
> H5: üst veri kaynaklı hiçbir ad `kesin` etiketi taşımaz; Swift adlarının hepsinde etiket `üst veriden`,
> `ozgun_ad` dolu, güven tablodan.
>
> H6 (hedef seti, ürün koşusu, bayraklar açık): terminal-notifier'da ObjC adı 32 / 32 kalır (geriye gitme yok).
> Rectangle'da (soyulmuş, GT yok) Swift kanalının yazdığı ad sayısı ilk ölçüm (okuyucu 180 tipe ad veriyor);
> doğruluk ölçülmez.

## Yöntem (ölçümden önce sabitlenir)

- **H3 yöntemi = PUV6a'nın ObjC için kullandığı "Ghidra'sız aday listesi ↔ GT"** (`scripts/measurement/ustveri_urun.py
  aday-gt`, H8). Swift için aynı düzen: ürün adımının okuma yolu (`SwiftMetadataRecoveryStep._oku`) soyulmuş kopyada
  (`~/karadul_olcum/ustveri_set/iTerm2/bin/iTerm2`) → ürün kanalının süzgeci (koddaki işlev, ölçüm betiğine kopya
  değil) → adres → `ozgun_ad`; GT = özgün dilimin sembol tablosu (`ustveri_set/iTerm2/gt/iTerm2.gt.json`), Swift
  sembolleri `xcrun swift-demangle` ile (`ustveri_olc.swift_cozum`); hüküm `ustveri_olc.kanal_olc(…, KANAL_SWIFT,
  cozum)` (eşitlik: kanal adı = GT sembolünün çözülmüş hâli, birebir). Wilson alt sınırı `baglama.wilson` ile; tabloya
  4 basamağa aşağı yuvarlanmış alt sınır yazılır. Betik koşu kökünde (`PUV6b/olc_h3_h4.py`), commit'lenmez; yalnız
  sayılar `PUV6b/ozet/` altında.
- **H4 yöntemi:** ürün adımının tarama yolu (`RttiRecoveryStep._tara`, yuva üst sınırı ürün öntanımı) soyulmuş kopyada
  (`ustveri_set/llama-server/bin/llama-server`) → `islevler[]` → ürün kanalının (`_add_rtti`) kendisi, Ghidra dizini
  boş (kanıt satırı Ghidra'dan bağımsız yazılır) → kanıt satırı ve ad adayı sayısı. GT'ye bakılmaz (H4 sayı
  hükmüdür).
- **H1 / H2:** `scripts/measurement/urun_kos.py` kendi dalının ürün ağacıyla (`~/karadul_olcum/urun-<dondurma>`),
  ikili başına ayrı kuyruk çağrısı; karşılaştırma `scripts/arge/hiz/s8_esitlik.py` (H1) ve aynı ağacın kapalı kolu
  (H2). Süre `<adım>_duration_s` (yük altında; boş makine ölçümü değil).
- **H6:** `scripts/measurement/ustveri_urun.py kos` + `urun` (PUV6a'nın H3 yöntemi), bayraklar açık yaml.
- Sınama ikilileri (iTerm2, llama-server) yalnız dondurma commit'inden sonra, birer kez.
