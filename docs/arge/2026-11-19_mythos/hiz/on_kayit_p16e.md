# Ön kayıt — P16e (Ghidra dökümünde belirlenimcilik: çağıran listelerinin sırası)

Yazıldı: 2026-11-23 08:2x, ölçümden (S8 koşularından) önce. Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/P16e.md`. Bu dosya ölçümden önce ayrı commit'lenir; tutmayan beklenti silinmez, eşik sonradan değişmez.

## Ölçülen kod

- Onarım commit'i `00b8a9c` (`karadul/ghidra/headless.py`: `caller_sort_key`; `_extract_call_graph`, `_extract_func_xrefs`, `_extract_xrefs`'te çağıran listesi tekilleştirmeden sonra tek `sort`).
- Ürün ağacı: `~/karadul_olcum/urun-00b8a9c` (`git worktree add --detach`, altı çalışma verisi bağı; `urun_kos.agac_kunyesi` denetler).

## Koşular

- S8'in 8 ikilisi iki kez: kökler `~/karadul_olcum/runs/dalga1-2026-11-23/P16e/s8_sonra_1` ve `…/s8_sonra_2`. Aynı ağaç, aynı komut (ORTAK_D0 §6; `--agac ~/karadul_olcum/urun-00b8a9c`, `--paralel 1`, taban yolları aynı), koşu başına boş önbellek (`KARADUL_CACHE_DIR=<kök>/cache`, kök yeni açılır), `PYTHONHASHSEED=0`. Her ikili ayrı kuyruk çağrısı (`ghidra_kuyruk.sh P16e S8:<ikili> …`). Sıra: htop ve debian tmux önce, sonra kalan altı.
- Karşılaştırma aracı: `scripts/arge/hiz/s8_esitlik.py` (bu paketin dalında; ham kıyas bugünkü kurallarla aynı; sıra-normal kıyas `--sira-normal` seçeneğiyle, aşağıda tanımlı).

## Beklentiler

> **H1 (belirlenimcilik):** onarımdan sonra S8'in 8 ikilisi iki kez koşulur (aynı ağaç, aynı komut, koşu başına boş önbellek); iki koşu arasında `ghidra_output/*.json`, `decompiled/*.c`, `naming_map.json` **ham** (sıra-normal olmayan) karşılaştırmada 8 / 8 aynı (fark yalnız mutlak yol ve zaman damgası alanları; bunlar `s8_esitlik.py`'nin bugünkü dışlama listesinde).

Ölçüm: `s8_esitlik.py --once s8_sonra_1 --sonra s8_sonra_2` (ham; `HARIC_ALANLAR` / `DURUM_HARIC_ALANLAR` bugünkü hâliyle, genişletilmez). Bir ikili "aynı" = JSON farklı dosya 0, `.c` farklı 0, `naming_map` farklı 0. `static/ghidra_*.json` kopyaları ve `ghidra_status.json` eski alanları da araç gereği kıyaslanır ve rapora yazılır. Sayılan: x / 8.

> **H2 (ad değişmez):** onarımdan sonraki `naming_map.json`, taban (`s8_taban_b6aceb9`) ile 8 / 8 aynı. Değişen ad olursa sayısı ve nedeni (çağıran sırasını okuyan kod) yazılır; paket durmaz ama ana oturuma ilk satırda bildirilir.

Ölçüm: `s8_esitlik.py --once s8_taban_b6aceb9 --sonra s8_sonra_1` satırındaki `naming_map` sütunu (üç yer: `out/`, `src/`, `src_iter1/`; bayt eşitliği). Bir ikili "aynı" = üç dosyanın üçü de bayt eşit. `s8_sonra_2` için de aynı sayı yazılır (ek satır).

> **H3 (yalnız sıra):** taban ↔ sonra, sıra-normal karşılaştırmada JSON ve `.c` farkı 0 (`.c`'de yalnız `// Callers:` satırları değişebilir; değişen satır sayısı raporlanır).

Sıra-normal kıyasın tanımı (ölçümden önce sabit): (a) JSON'da adı `callers` ya da `called_by` olan her liste kıyastan önce iki tarafta da `caller_sort_key` ile sıralanır; başka hiçbir liste sıralanmaz, hiçbir alan çıkarılmaz (`HARIC_ALANLAR` aynen). (b) `.c` dosyalarında `// Callers:` ile başlayan satırlar iki tarafta da çıkarılıp kalan bayt kıyaslanır; ham hâlde farklı olan `// Callers:` satırı sayısı ayrıca raporlanır. Ölçüm: `s8_esitlik.py --once s8_taban_b6aceb9 --sonra s8_sonra_1 --sira-normal`. Tuttu = 8 / 8 ikilide JSON farklı dosya 0 ve `.c` farklı 0.

Beklenen (yön): taban çıktısında çağıran listesi adres sırasında olmayan düğüm sayısı cat 13, sort 34, tree 36, sqlite3 151, htop 191, debian tmux 581, zstd 224, mac/tmux 813; 5'ten fazla çağıranlı olup ilk 5'i en küçük adresli 5'ten farklı fonksiyon cat 4 … mac/tmux 372 (envanter, `P16e.md`). Bu yüzden ham `.c` farkı (taban ↔ sonra) büyük olacak; hüküm sıra-normal kıyastadır.

> **H4 (süre; yük altında, yön gösterici):** döküm adımlarının toplamı (`adim_sureleri`) tabana göre ≤ %2 artar. Makine yüklü olduğu için hüküm "boş makinede yeniden" notuyla yazılır.

Tanım: `s8_taban_b6aceb9` HZ-1'den önceki koddur (`adim_sureleri` yok); süre tabanı bu yüzden HZ1'in sonra kolu `~/karadul_olcum/runs/dalga0-2026-11-20/HZ1/s8_sonra_959106b` (döküm kodu bugünküyle aynı: `git diff 959106b f2b0db5 -- karadul/ghidra karadul/analyzers/macho.py` boş; tek fark bu paket). "Döküm adımları" = `adim_sureleri`'nin `ghidra.jvm_baslatma`, `ghidra.ice_aktarma`, `ghidra.otomatik_analiz`, `ghidra.gdt`, `ghidra.pdb`, `ghidra.kapatma` dışındaki anahtarları. Oran = (8 ikilinin döküm adımı toplamlarının toplamı, `s8_sonra_1`) / (aynısı, taban) − 1. Ek satır: dokunulan üç adımın (`ghidra.call_graph`, `ghidra.decompile`, `ghidra.xref`) oranı ve ikili başına oranlar. Koşu başlangıcındaki yük (`ghidra_kuyruk.log` `yuk=`) künye olarak yazılır. Hüküm her durumda "yük altında; boş makinede yeniden" notuyla.

## Kayıt dışı (hükmü değiştirmez)

- `call_site` alanı (`decompiled.json` `xrefs.callers[].call_site`) değiştirilmedi: tekilleştirme bugünkü gibi çağıranın ilk görülen başvurusunu tutar. Taban, A/A ve HZ1 koşuları arasında bu alanın değeri 8 ikilide 0 kez farklı (envanter). Tabanda 35 kayıtta bu değer çağıranın gövde sırasındaki ilk çağrı yerinden (çağrılan listesindeki `call_site`) farklı; "en küçük çağrı yeri" kuralına geçmek bunların bir kısmını değiştirirdi (sıra dışı içerik farkı) — ana oturuma bırakıldı.
- Çağrılan listeleri, `edges`, `strings_used`, dizgi `xrefs` sıralanmadı (gövde adres sırası; dizgi başvuruları GHIDRA-16'dan beri sıralı). Ham H1 bunları da kıyaslar.
