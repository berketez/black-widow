# Ön kayıt — P-ÜV2 (Objective-C yöntem listesi okuyucu + `objc_metadata_recovery` üretici adımı), 2026-11-20

Bu metin koddan ve ölçümden ÖNCE commit'lenir. Tutmayan beklenti silinmez; eşik sonradan değişmez.
Paket metni `docs/arge/2026-11-20_dalga0/gonderim/PUV2.md`; plan `ustveri/PLAN.md` "P-ÜV2"; kararlar A-10, A-27, A-28.
Taban commit: `3eb32df` (main; `git merge --ff-only main`).

**Bu kayıttan önce görülenler (dürüstlük notu):**
- Araştırma okuyucusu `scripts/arge/ustveri/objc_meta.py` ve `macho.py` (kaynak kod).
- Başvuru çıktıları `$V/objc/<ad>.json` (`$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri`): yedi dosyanın sayım alanları
  (yöntem kaydı, sınıf, kategori, protokol, arite, IMP denetimleri, okuma hataları). terminal-notifier (keşif) ve
  Ollama'nın `sembol_tablosu` alanı da görüldü; **iTerm2'nin (sınama) `sembol_tablosu` alanı açılmadı.**
- `$V/objc/Ollama.arm64.tsv` ilk beş satırı (biçim için).
- `ustveri/olcum/HEDEF.md`: iTerm2 GT özet sayıları (108 776 fonksiyon adresi; ad türü objc 34 605 adres) ve
  HEDEF'in terminal-notifier kanal ölçümü (32 / 32). iTerm2 GT dosyası (`~/karadul_olcum/ustveri_set/iTerm2/gt/`) açılmadı.

## 1. Hipotezler (planın metni, aynen)

> H1: 6 / 6 hedefte yöntem kaydı sayısı ve (adres, ad) listesi başvuruyla aynı. H2: iTerm2'de ObjC sembolü olan
> 33 611 IMP'in tamamında ad sembolle aynı; farklı ad 0. H3: iTerm2'de ObjC sembolü olmayan IMP'lerin (7 694) en az
> %95'i Swift sınıfı kaydıdır. H4: seçici başvurusu yerine doğrudan dizgi okuyan mutant küçük biçimli listelerde 0
> doğru seçici üretir. H5: ObjC olmayan ikilide (`gh`) durum `veri_yok`.

Kabul ölçütü (plan): 6 hedefte sayılar `$V/objc/<ad>.json` ile aynı: terminal-notifier 32, iTerm2 arm64 41 305,
Ollama arm64 151, Ollama x86_64 151, limactl 102, Rectangle arm64 450 yöntem kaydı; IMP'lerin tamamı fonksiyon
başlangıcı (6 / 6 hedef). (adres, ad) listesi `$V/objc/<ad>.tsv` ile aynı. Sembollü iki ikilide ad = sembol: iTerm2
33 611 / 33 611, terminal-notifier 32 / 32 (kategori yazımı kuralıyla); eşik Wilson alt sınırı ≥ 0,999. Okuma hatası
sayaçları 0.

## 2. İşlem tanımları (ölçümden önce sabitlenir)

- **Girdi:** `$V/hedef/` araştırma kopyaları: `terminal-notifier.macho`, `iTerm2.arm64`, `Ollama.arm64`,
  `Ollama.x86_64`, `limactl`, `Rectangle.arm64`; H5 için `gh`. Okuyucu P-ÜV0 `Goruntu` üstünden çalışır (gerçek
  görüntü main'e girdikten sonra). İkililer çalıştırılmaz, yerinde değiştirilmez.
- **Yöntem kaydı sayısı:** okuyucunun bütün yöntem kayıtları (sınıf + meta sınıf + kategori; IMP'i 0 olanlar dahil) =
  başvurunun `yontem_kaydi` alanı.
- **(adres, ad) listesi aynı:** IMP'i 0 olmayan her kayıt için (IMP, tür, sınıf, kategori, seçici, protokolde, swift,
  tip kodlaması) sekizlisi; başvuru `.tsv`'nin sekiz sütunuyla **çoklu küme** olarak karşılaştırılır (sıra önemsiz).
  Başvurudaki `None` sınıf / seçici, okuyucudaki boş değere karşılık gelir. Hüküm: yalnız bir yanda olan satır 0.
  Ayrıca tam ad (`-[Sınıf seçici]` / `+[Sınıf seçici]`) okuyucu çıktısında seçiciden ayrı alandır (A-28).
- **IMP = fonksiyon başlangıcı:** her ayrık IMP `Goruntu.fonksiyon_baslangiclari()` kümesinde; 6 / 6 hedefte ayrık
  IMP'lerin tamamı.
- **Okuma hatası sayaçları:** okuyucunun sayaç sözlüğündeki hata sayaçlarının toplamı 0 (6 / 6).
- **H2 (sınama, bir kez):** okuyucu dondurulduktan sonra (dondurma commit'i ilerleme dosyasına yazılır) iTerm2 GT'si
  (`ustveri_set/iTerm2/gt/`, HEDEF paketinin çıkarımı) bir kez açılır. Sayım HEDEF'in kuralıyla
  (`scripts/measurement/ustveri_olc.py` `kanal_olc`, `objc_yazimi`: birebir ya da GT adındaki kategori soyulunca
  birebir; adres başına): ObjC sembolü (`-[` / `+[` ile başlayan GT adı) olan IMP adreslerinde doğru / yanlış.
  Beklenen 33 611 / 33 611, yanlış 0, Wilson alt sınırı ≥ 0,999. Okuma: H2 iTerm2'nin soyulmamış (`orig`) diliminde
  ad haritası ↔ GT; soyulmuş kopyada (`bin`) haritanın özgündekiyle aynı olduğu ayrıca yazılır.
- **Eşik notu (ölçümden önce):** terminal-notifier tek başına n = 32 ile Wilson alt sınırı 0,999'a ulaşamaz
  (32 / 32 → 0,8928). Bu yüzden 0,999 eşiği iTerm2 (n ≈ 33 611) için uygulanır; terminal-notifier (keşif) için ölçüt
  "farklı ad 0 ve 32 / 32 doğru"dur. İkisinin toplamı da ayrıca yazılır.
- **H3:** iTerm2'de IMP adresinde ObjC GT sembolü olmayan kayıtlar arasında `swift = true` olanların oranı ≥ %95.
- **H4:** mutant (küçük biçimde seçici başvurusu çözülmez; ad ofsetinin gösterdiği yer doğrudan dizgi okunur)
  geçici uygulanır; 6 hedefte küçük biçimli listelerdeki kayıtlarda başvuru seçicisiyle aynı seçici sayısı 0. Sentetik
  testte de aynı mutant ölür. (Hedeflerde küçük biçimli liste yoksa H4 o hedef için "veri yok".)
- **H5:** `gh` (Go, ObjC bölümü yok) için okuyucu / adım durumu `veri_yok`, yöntem kaydı 0.

## 3. Tutmazsa

Fark yazılır (hangi hedef, kaç satır, hangi sütun), başvuru betiği de denetlenir (hata iki yanda da olabilir). Eşik ve
tanımlar değişmez.
