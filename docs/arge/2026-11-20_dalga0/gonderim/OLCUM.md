# OLCUM — P-Ö1 (biçim satırı) → ölçüm aracı kusurları

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-3).

**Plan.** `docs/arge/2026-11-19_mythos/olcu/PLAN.md` §1 ve §3 "P-Ö1" (adımlar 1–7, kabul tablosu, ön kayıt metni, mutantlar). Kusurların kaynağı: `docs/arge/2026-11-18_onarim/gonderim/OKU.md` ("Ölçüm araçları" ve "Atanmamış bulgular → Ölçüm araçları"), `docs/arge/2026-11-19_birlesik_olcum/on_kayit.md` ("araç kusurları"), `docs/arge/2026-11-19_mythos/ozkod/NUFUS.md` §8 not 3, `docs/arge/2026-11-19_mythos/olcu/TABAKA_VERI.md`. `$H`, `$R`, `$V` kısaltmalarının açılımı planın başında.

**Yazabileceğin dosyalar.** `scripts/measurement/{ad_bicimi.py (yeni), urun_olc.py, ks1_olc.py, masum_kapi.py, saglamlik_denetle.py, function_f1.py, urun_kos.py}`; yeni `tests/test_ad_bicimi.py`, yeni `tests/test_olcum_araci_d0.py`, bu yedi betiğin var olan test dosyalarına yalnız ek sınama; yeni `scripts/measurement/mutation_specs_po1.json`, yeni `mutation_specs_olcum_araci.json`, var olan `mutation_specs_{urun_olc,ks1,function_f1}.json` (yalnız senin değişikliğinle bayatlayan `find` güncellemesi); belgeler `docs/arge/2026-11-19_mythos/olcu/{P-O1_on_kayit.md, P-O1.md}`; ilerleme `docs/arge/2026-11-20_dalga0/OLCUM.md`.
**Dokunma.** `karadul/` (ürün), `$H/*` (araştırma betikleri), öbür ölçüm betikleri. Ghidra koşusu YOK: her şey hazır çıktılar üstünde.

## Kalemler (sırayla; her biri ayrı commit; önce 1 ve 2'yi bitir, bütün ad paketleri bunlara bağlı)

1. **P-Ö1**, planın adımlarıyla. Ön kayıt koddan önce commit. Kabul tablosu iki kolda (a62f15e, f30ac9a). Plan bu commit'te `ks1_olc.py`'ye dokunmaz der: dokunma.
2. **`ks1_olc` `BITTI`.** (a) `debian_elfleri` `BITTI`'nin içeriğine bakmıyor: kısmi koşu (`3`) bitmiş sayılıyor; (b) `mac_elfleri` `BITTI`'ye hiç bakmıyor (yalnız `ws/`). Onarım: yalnız `0` bitmiş sayılır; kısmi / hatalı / dosyasız birimler ayrı sayılır ve özete "kısmi n, hatalı n" diye girer (sessizce düşmez, sessizce sayılmaz). Sonra P-Ö1'in iki kolunu yeniden koş: sayı değiştiyse hangi birimin kısmi olduğunu yaz; P-Ö1 kabul tablosuna bu düzeltmeyle bir satır ekle (ön kaydı değiştirme).
3. **`masum_kapi` `sarif`.** `sarif` katmanı KRDL001 / KRDL007'deki 12 doğru iddiayı yanlış sayıyor. Say → onar → masum sette ve doğru iddia setinde yeniden say. Eşiği yazma (`--esik-yaz` ana oturumun işi): onarımdan sonra eşiğin hangi komutla yazılacağını ilerleme dosyasına yaz.
4. **`saglamlik_denetle` "yazıldı".** `saglamlik_denetle.py:608` bugünkü çıktıdaki Türkçe `yazıldı` satırını tanımıyor. Say → onar → gerçek çıktıda yeniden koş (`~/karadul_olcum/runs/urun-onarim-a62f15e/` ya da `~/karadul_olcum/runs/genel-tarama-2026-11-18/`).
5. **`function_f1.read_elf_info` not sahibi.** SystemTap notu (sahibi `stapsdt`, tür 3) `NT_GNU_BUILD_ID` sanılıyor; onarım: yalnız `n_name == "GNU"` olan not. Sınama sentetik ELF'le (iki not). Gerçek iki ELF'te (postgresql-17, python3.13-minimal; yolları `~/karadul_olcum/ozkod_nufus/nufus.json`) yalnız BuildID'yi `scripts/arge/olcu/tabaka_indir.py` `elf_bilgisi` ile karşılaştır; kör taraftaki paketin adlarına, dizgilerine bakma.
6. **`urun_kos` künyesi.** Künyeye `KARADUL_CACHE_DIR` ve imza veritabanının şema sürümü (`signatures.lmdb`) eklensin. `agac_kunyesi(agac)` imzası ve var olan alanları DEĞİŞMEZ (başka betikler içe aktarıyor); yalnız alan eklenir.
7. **`urun_olc` sınıflayıcı sürümü.** `urun_olc` ad sınıflayıcısını betiğin kendi ağacından alıyor; ölçülen ürün ağacının `naming_labels.py` / `alt_kanal.py` sha256'sı betiğin ağacındakinden farklıysa ölçüm sessizce yanlış sınıflar. Birleşik ölçüm ön kaydı §2.2 kuralını betiğe taşı: fark varsa hata ver (ya da sınıflayıcıyı ürün ağacından yükleyen açık bir seçenek). `karsilastir` eski JSON'larla çalışmaya devam etmeli.

## Kabul

P-Ö1'in altı sayısı tutuyor ya da fark açıklandı; 2–7'nin her biri için önce / sonra sayısı, eski kodda kırmızı yeni kodda yeşil test, mutantlar öldü; `tests/test_urun_olc.py` ve ilgili testler yeşil; tam takım 0 hata. Süre hedefi 90–120 dk.
