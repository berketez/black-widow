# HZ2 — HZ-2: BSim hızlı yol (paralel tarama; çıktıyı değiştirmez) — ilerleme dosyası

Paket: uygulama oturumu 4 (2026-11-24), HZ2 (`docs/arge/2026-11-23_dalga1/gonderim/HZ2.md`). Plan: `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-2" (gönderim metnindeki hükümlerle).
Taban: main `cfe93cef` (`git merge --ff-only main` sonrası; ürün kodu `534e252b` ile aynı, arada yalnız belge). Başlangıç: 2026-11-24 13:13. Sert son: 15:20.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/HZ2/` (özetler `ozet/`).

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Ghidra API doğrulaması (`javap` + yerel kaynak zip'leri) | sürüyor | |
| 2 | Kod (`bsim.py`: paralel ingest taraması, sorguda ingest yöneticisi, izleyiciye bütçe, okuyucu iş parçacığı, yedek yol, kısmi ingest işareti) | bekliyor | |
| 3 | Testler (`tests/test_hz2_bsim_hizli.py`) | bekliyor | |
| 4 | Mutasyon (`mutation_specs_hz2.json` ≥ 6) + taşınan iki ÖL-2 tanımı + eski tanımlar (ol2, p16b, p16c) | bekliyor | |
| 5 | `config.py` yaması (`yamalar/HZ2__config.py.patch`; `git apply --check`; uygulanmaz) | bekliyor | |
| 6 | Ön kayıt (`on_kayit_hz2.md`; ölçümden önce ayrı commit) | bekliyor | |
| 7 | Fizibilite (kısmi ingest'i tamamlama: aynı yürütülebilir için ikinci `InsertRequest`) | bekliyor | |
| 8 | H4 (sqlite3, bütçe 2 sn) | bekliyor | |
| 9 | H1 / H2 (S8) | bekliyor | |
| 10 | H3 / H5 (T25) | bekliyor | |
| 11 | Tam takım (yamasız) | bekliyor | |
