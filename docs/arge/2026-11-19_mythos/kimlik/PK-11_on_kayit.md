# PK-11 ön kaydı — gömülü kitaplık kopyası (zstd `lib/` ↔ libzstd) (Dalga 0, 2026-11-20)

- Yazıldı: 2026-11-20 09:1x, libzstd'nin Ghidra koşusundan ve hiçbir sayımdan ÖNCE. Kendi commit'inde.
- Plan: `kimlik/PLAN.md` §3 PK-11. Veri: V5 (KARARLAR A-22) `~/karadul_olcum/n2_tabaka/kitaplik/`
  (`x_libzstd1/usr/lib/aarch64-linux-gnu/libzstd.so.1.5.7`, `x_libzstd1-dbgsym/usr/lib/debug/.build-id/42/…debug`;
  künye `kitaplik_veri.json`: sha256, URL, InRelease parmak izi).
- Kip: PK-3 yok → dondurulmuş araştırma betikleri (`esle.py` dört nokta, `hata_dok.py`, `tanik.py`,
  `urun_bindiff.py`); kimlik `kitaplik/libzstd` `scripts/arge/kimlik/d0_veri.py` ile bağlanır; grup
  `gomulu_kitaplik` `scripts/measurement/kimlik_ciftler.py`'de.

## 1. Planın ön kayıt metni (aynen)

> PK-11 ön kaydı. Açık ölçüm; beklenen sayı yok, eşikler var. `proje_kitapligi` sınıfında (nüfus 720): (a) tam ad
> kesinliği Wilson alt ≥ 0,95 → "kitaplık kopyası bu yolla ad alır (hat hedefi)"; ≥ 0,909 → "ad yazabilir";
> altı → "kanıt satırı". (b) Kapsam (doğru / 720) raporlanır; ≥ %40 → "A2'nin kitaplık kolu için kullanılabilir".
> (c) `program` sınıfında (zstd'nin kendi `programs/` kodu; başvuruda YOK) verilen ad sayısı: her biri yanlıştır
> (çekimserlik sınaması); nüfusa oranı ≤ %2 → "başvuruda olmayan koda ad yakıştırmıyor". Karşılaştırma için
> (beklenti değil): aynı derleyici, farklı program ölçümü tur 1'de 0,987–0,991, kapsam %48–56 (coreutils / gnulib).

## 2. Tanımlar (sayılara bakılmadan)

- **Grup `gomulu_kitaplik`, tek yön:** sorgu Q = `debian/zstd/zstd` (geliştirme seti, Debian 13 arm64; ürün a62f15e
  koşusu, yeniden koşulmaz), başvuru R = `kitaplik/libzstd` (Debian 13 arm64 `libzstd.so.1.5.7`, paketteki soyulmuş
  hâliyle; aynı kaynak paketi sürümü 1.5.7+dfsg-1, aynı derleyici ailesi). R'nin adları GT'den (tur 1 düzeni:
  başvuru soyulmuş analiz edilir, adları GT'den; BULGULAR §3.7: sembollü analizle fark ≤ %0,4).
- R'nin koşusu: ürün `~/karadul_olcum/urun-b6aceb9`, `python -m karadul analyze … --skip-dynamic --stage static`,
  `ghidra_kuyruk.sh KIMLIK PK11:libzstd`, koşuya özel `KARADUL_CACHE_DIR`, `PYTHONHASHSEED=0`, süre sınırı.
  GT: `ks1_olc.gt_elf` (build-id → `x_libzstd1-dbgsym`'deki `.debug`).
- **Kaynak sınıfı:** OLGU tablosunun `kaynak_sinifi` alanı (`~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz`,
  nüfus satırları; `olgu_capraz.olgu_oku` / `olgu_anahtari`), Q'nun nüfus fonksiyonları için. Sınıf başına: nüfus,
  tavan (GT adı R'de var), doğru, yanlış, kesinlik (Wilson), kapsam. Yükleyicinin nüfusu OLGU'nunkiyle
  karşılaştırılır; `proje_kitapligi` nüfusu 720'den farklı çıkarsa iki sayı da yazılır, (b)'nin paydası yükleyicinin
  nüfusudur ve fark nedeniyle kayda geçer.
- **Hüküm:** `esle.hukum` (tam ad eşitliği). Birincil nokta `kural`; dört noktanın her biri için (a)–(c) ayrıca
  yazılır.
- **(a)** `proje_kitapligi`: alt ≥ 0,95 → "hat hedefi"; 0,909 ≤ alt < 0,95 → "ad yazabilir"; altı → "kanıt satırı".
- **(b)** kapsam = doğru / `proje_kitapligi` nüfusu; ≥ %40 → "A2'nin kitaplık kolu için kullanılabilir".
- **(c)** `program` sınıfında verilen ad = eşleme kabul edilen ve hükmü doğru ya da yanlış olan Q fonksiyonu.
  Oran = verilen ad / `program` sınıfı nüfusu; ≤ %2 → "başvuruda olmayan koda ad yakıştırmıyor". Planın "her biri
  yanlıştır" varsayımı ayrıca sınanır: bu sınıfta hükmü "doğru" çıkan ad varsa sayısı ve örnek adları (geliştirme
  seti; kilitli değil) yazılır (ör. `programs/` ile `lib/` arasında ortak adlı yardımcı).
- Ek satırlar (hükme girmez): `hata_dok` sınıfları, `tanik` (tanıklı / tanıksız alt kanal, `--kmax 1000000000`),
  ürünün var olan yolları `urun_bindiff` (`BinaryDiffer` / `ReferenceDiffer`) aynı çiftte.
- Kilit denetimi: `libzstd`, `libzstd1`, `zstd`, `deps/hiredis` (redis) kilit belgelerindeki adlarla kesişmiyor
  (`kimlik_ciftler.kilit_denetimi`; `tabaka_indir.kilitli_adlar`, 136 ad). redis'in `deps/lua` kopyası için başvuru
  liblua olurdu: lua kilitli → bu çift ölçülmez (PLAN PK-11 "Veri").

## 3. Kendi tahminim (bağlayıcı değil)

- (a) tutar (aynı derleyici, aynı sürüm; tur 1 gnulib benzeri); (b) kapsam %40–60; (c) oran ≤ %2.
