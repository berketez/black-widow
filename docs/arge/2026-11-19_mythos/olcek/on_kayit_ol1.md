# ÖL-1 ön kayıt (ölçümden önce; 2026-11-23)

Paket OL1 (`docs/arge/2026-11-23_dalga1/gonderim/OL1.md`; plan `olcek/PLAN.md` "ÖL-1"). Bu metin S8 ve T25 koşularından ÖNCE commit'lenir; tutmayan beklenti silinmez, eşik sonradan değişmez.

## Planın ön kayıt cümlesi (aynen)

"Bekçi açıkken T25 1. deneme koşulunda tetiklenme ≤ 660 sn; 8 / 8 alt küme çıktısı aynı; ilerleme sessizliği ≤ 60 sn. Tetiklenen çözümleyici kapatılınca kalan analiz ≤ 600 sn'de biter (gösteri 2. denemede otomatik analiz 226,4 sn)."

## Beklentiler ve hüküm kuralı

| No | Beklenti | Nasıl ölçülür | Tuttu sayılır |
|---|---|---|---|
| B1 (kabul a) | T25'te bekçi tetiklenir, ≤ 660 sn | koşu günlüğünün zaman damgalarından (`ghidra_status.json` yazılmayacak, koşu durdurulacak): takılan çözümleyicinin `cozumleyici` alanıyla göründüğü **ilk** `suruyor` olayından bekçinin tetiklenme olayına (`neden` "… kapatılıyor") kadar geçen süre. Ek satır (hükümsüz, kayıt için): otomatik analiz adımının `basladi` olayından tetiklenmeye kadar | ≤ 660 sn |
| B2 (kabul a) | Kapatılan çözümleyici "Objective-C Message" ailesinden (gösteri 1. denemenin jstack'i: `ObjcMessageAnalyzer`) | bekçi olayının `cozumleyici` alanı | adı `Objective-C Message` ile başlıyor |
| B3 (ön kayıt) | Kalan analiz (2. `analyzeAll` turu) ≤ 600 sn | 2. turun bitişi: otomatik analiz adımının `bitti` / `kismi` olayının `gecen_sn`'si eksi tetiklenme anı | ≤ 600 sn |
| B4 (kabul c) | `ILERLEME` satırları arasındaki en uzun boşluk ≤ 60 sn | koşu günlüğündeki `ILERLEME` satırlarının zaman damgaları; aralık: ilk `ILERLEME` satırı → 2. turun bitiş olayı (koşu orada durdurulacak, aşağıya bkz.) | ≤ 60 sn |
| B5 (kabul b) | S8: 8 / 8 ikilide çıktı taban ile aynı | `scripts/arge/hiz/s8_esitlik.py --once ~/karadul_olcum/runs/dalga1-2026-11-23/P16e/s8_sonra_3 --sonra <OL1 kökü>` ham kıyas (sıra-normal değil; P16e main'de): `ghidra_output/*.json` (HARIC_ALANLAR dışında) eşit, `decompiled/*.c` bayt eşit, `naming_map.json` bayt eşit, `ghidra_status.json` eski alanlar eşit | 8 / 8; fark yalnız yeni alanlar ve mutlak yol |

**Bilinen kendiliğinden fark (P16e):** zstd `FUN_001063c0`'da Ghidra decompiler'ı 6 koşunun 1'inde iki geçici değişkeni yer değiştiriyor. Bir ikilide `.c` / `pcode` / `reconstructed` farkı görülürse o ikili **ayrı bir ek kökte** yalnız kendisiyle bir kez daha koşulur (aynı köke yeniden koşulamaz: `urun_kos` `BITTI` dosyası). Ek kökte BSim veritabanı önceki ikililerin birikimini taşımadığı için BSim dosyaları tabandan farklı çıkar (P16e'de ölçüldü); ek kıyasta BSim dosyaları ayrı satırda yazılır. İki sonuç da yazılır; fark yinelenmiyorsa bu pakete bağlanmaz. Hüküm (B5) yine ilk koşuyla verilir.

## Koşullar

- **Ayar:** yamasız ağaçta öntanım `cozumleyici_takilma_sn = 0` (bekçi kapalı). Ölçüm koşularında eşik ayar dosyasıyla verilir: `analysis: {cozumleyici_takilma_sn: 600, bekci_aralik_sn: 15}` (yamalı öntanımla aynı davranış).
  - S8: `scripts/measurement/urun_kos.py`'nin `--config` seçeneği yok; ürün süreci ürün ağacının kökünde koşar ve `Config.load` oradaki `karadul.yaml`'ı okur → aynı içerik ürün ağacının köküne `karadul.yaml` olarak konur (git izlemiyor; `agac_kunyesi` "kirli" saymaz) ve kopyası koşu köküne.
  - T25: `python -m karadul analyze … --config <kök>/ol1.yaml --verbose` (gösteri 1. denemesinin komutu + bu iki ayar; `--verbose` `karadul.*` INFO günlüğünü koşu günlüğüne akıtır; ÖL-4 gelene kadar `ILERLEME` satırları ancak böyle görünür). "Objective-C Message Analyzer" AÇIK: `ghidra_disabled_analyzers` verilmez (1. deneme `gosteri.yaml`'sız koştu).
- **Ürün ağacı:** `~/karadul_olcum/urun-<OL1 kod commit'i>` (`git worktree add --detach` + altı çalışma verisi bağı).
- **S8 sırası:** ORTAK_D0 §6 sırası (cat, sort, tree, sqlite3, htop, debian tmux, zstd, mac/tmux), tek kök, ikili başına bir kuyruk çağrısı (P16e: BSim veritabanı kökte birikir).
- **T25'in kapsamı (gönderim metni):** koşu kuyrukla arka planda, dış `timeout` en çok 75 dk; yalnız tetiklenme ve 2. `analyzeAll` turunun bitişi beklenir, sonra koşu durdurulur. Bu yüzden kabul (a)'nın "koşu biter (çıkış 0 ya da 3)" ve "`ghidra_status.json` `analysis.takilan_cozumleyici`" parçaları bu pakette **ölçülmez** (koşu Ghidra adımları bitmeden durdurulur; `ghidra_status.json` yazılmaz). Ölçülmediği açıkça yazılır.
- Süreler "yük altında" (ORTAK_D0 §3: gündüz süre ölçümü yok); koşu başında `uptime` künyesi.
- Makine: Apple M4 Max; aynı anda başka ajanların Ghidra koşuları (iki yuva).

## Kayıt dışı bırakılanlar

- Bekçi açıkken S8'de süre farkı (bekçi 15 sn'de bir ~1 ms okuma yapar; fizibilitede ortanca 1,23 ms): ölçülmez (yük altında anlamsız).
- Bekçinin meşru uzun çözümleyiciyi (büyük ikilide 600 sn'yi geçen ama ilerleyen) kesme riski: bu pakette ölçülmez; ÖL-2 / ÖL-10'a not.
