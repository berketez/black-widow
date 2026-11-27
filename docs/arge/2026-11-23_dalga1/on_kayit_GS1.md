# GS1 — ön kayıt (ölçümden önce; 2026-11-27)

Metin gönderim belgesinden (`docs/arge/2026-11-23_dalga1/gonderim/GS1.md` "Ön kayıt") aynen; tek değişiklik H2'nin taban yolu: ORTAK_D1 §7 gereği `s8_taban_534e252b` yerine `s8_taban_ed28e36b` (eskisi HZ2'nin `scan_mode` alanı yüzünden bayat). Kıyas yalnız tabanın kökünde `BITTI` dosyası varken yapılır.

> H1 (adım olayları, debian `cat`, `--verbose`, tek ürün koşusu): yeniden kurma aşamasında koşan her adım için tam bir `basladi` ve bir bitiş olayı (`bitti` / `kismi` / `atlandi`); olay sayısı = 2 × koşan adım sayısı; her aşama için bir baş ve bir son olayı.
> H2 (çıktı): aynı koşunun `out/` ağacı ve `out/naming_map.json`'ı S8 tabanındaki cat ile (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_ed28e36b/debian/coreutils/cat`) bayt eşit.
> H3 (kesin iptal): SIGTERM'i yok sayan alt süreç + torunu iptalden sonra ≤ 7 sn'de ölü; `sonlandirma: "kill"`. SIGTERM'e uyan alt süreçte `sonlandirma: "term"` ve ≤ 2 sn.
> H4 (neden): hüküm 7'nin üç koşulundan hangisinde süreç SIGTERM'le ölmüyor — yön bildirilmez, ilk ölçüm.
> H5 (maliyet): adım olaylarının koşu süresine eklediği pay ≤ %0,1 (olay sayısı × satır maliyeti; ölçerek).

Ölçüm yöntemleri (eşik değil, yalnız nasıl sayılacağı; sonradan değişmez):
- H1: koşunun stderr'indeki `ILERLEME` satırları `karadul/core/ilerleme.py` `ilerleme_ayristir` ile ayrıştırılır; `asama=reconstruct` ve `adim=reconstruct.<ad>` olaylar adım adına göre gruplanır. "Koşan adım" = koşu günlüğünde adım koşucusunun `Step '<ad>' tamam` satırı olan ya da başarısızlık satırı olan adım.
- H2: `out/` ağacındaki bütün dosyaların göreli yol kümesi ve her dosyanın sha256'sı; `naming_map.json` ayrıca. Zaman damgası, yol ya da süre taşıyan dosya varsa ayrıca adıyla yazılır (ayrılan alan yoksa ham bayt eşitliği).
- H3: `tests/test_gs1_kesin_iptal.py`'deki gerçek alt süreçlerle, duvar saatiyle (iptal çağrısının başından grup üyesi ölene kadar).
- H4: `scripts/arge/gs1/sigterm_olc.py` (a / b / c + denetim d), çıktı `~/karadul_olcum/runs/dalga1-2026-11-23/GS1/ozet/h7_*.json`.
- H5: olay üreticisinin satır başına maliyeti (günlükçü işleyicisi kurulu, gerçek dosyaya yazarken; çok sayıda tekrarın ortancası) × `cat` koşusundaki adım / aşama olayı sayısı ÷ koşunun duvar süresi.
