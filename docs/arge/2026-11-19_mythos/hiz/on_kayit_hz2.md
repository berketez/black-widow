# HZ-2 ön kayıt (ölçümden önce; sayılar ana oturumun, gönderim metninden aynen)

Paket: HZ2 (`docs/arge/2026-11-23_dalga1/gonderim/HZ2.md`). Kod commit'leri: `285ee3af` (kod), `af7dae70` (testler + imzalı fonksiyon sayımı). Bu dosya ölçümden önce ayrı commit'tir; tutmayan beklenti silinmez, eşik sonradan değişmez.

> **H1** (eşitlik, S8, ortak depo senaryosu: tek kök, ORTAK_D0 §6 sırası, `bsim.paralel_tarama: true`): taban `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_534e252b`. `bsim_matches.json` ve `bsim_shadow.json` zaman alanları ve `scan_mode` dışında bayt eşit 8 / 8; `decompiled/*.c`, öbür `ghidra_output/*.json` ve `out/naming_map.json` ham eşit 8 / 8.
>
> **H2** (bayrak kapalı): `bsim.paralel_tarama: false` ile S8'in 2 ikilisinde (cat, zstd) çıktı tabanla ham eşit (zaman alanları dışında).
>
> **H3** (süre, T25: Ollama dilimi, `--stage static`, taze depo, yük altında): ingest süresi ≤ 288 sn (ÖL-2'nin ölçümü 576,3 sn'nin yarısı); `bsim_status` ve eşleşme sayısı aynı (`atlandi`, 0); taranan fonksiyon 13 160 / 13 160.
>
> **H4** (bütçe): sqlite3'te `bsim.ingest_butcesi_sn: 2` ile ingest ≤ 2 + 10 sn'de `kismi` biter; JSON geçerli; `islenen` ≤ `toplam`.
>
> **H5** (olay): T25'te ingest içinde en uzun `ILERLEME` sessizliği — yön bildirilmez, ilk ölçüm (sayaç okunamıyorsa "okunamadı").
>
> **H6** (yedek yol): birim testte paralel tarama istisna atınca tekli yol aynı eşleşme listesini verir; `scan_mode: serial_fallback`.

Bilinen kendiliğinden fark: Ghidra decompiler'ı zstd `FUN_001063c0`'da 6 koşunun 1'inde iki geçici değişkeni yer değiştiriyor (P16e). Bir `.c` farkı görülürse o ikili bir kez daha koşulur, iki sonuç da yazılır.

## Uygulama notları (ölçüm kuralı; hüküm değil)

- "Zaman alanları": `query_duration`, `bsim_detail.ingest_s`, `bsim_detail.query_s`, `bsim_detail.lock_wait_s` (PLAN "HZ-2" kabul ölçütündeki liste). `scan_mode` yalnız sonra kolunda bulunur (`bsim_detail.scan_mode`); kıyasta yalnız bu anahtar düşülür. Yedek yolda ek alan (`scan_fallback_error`) ya da sayaç okunamadığında `scan_sayac` çıkarsa bu bir fark sayılır ve yazılır.
- Ürün koşuları dalın ürün ağacında (`~/karadul_olcum/urun-<kısa-hash>`, altı bağ); ayar ağaç kökündeki `karadul.yaml` ile verilir (`bsim.paralel_tarama: true`, H2'de `false`); kopyası koşu kökünde.
- H4'te ingest bütçesi `bsim.ingest_butcesi_sn: 2` (köprü ingest denetçisinin bütçesi `min(timeouts.ghidra_adim, ingest_butcesi_sn)`); süre köprünün `adim_sureleri["ghidra.bsim.ingest"]` değeri.
- H5: T25 koşusunun `ILERLEME` satırlarında `ghidra.bsim.ingest basladi` → `bitti|kismi` arasındaki ardışık iki satır arasındaki en uzun boşluk (sn).
