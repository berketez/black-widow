# GS1 — GS-1: Ghidra sonrası adımların görünmesi ve iptalin kesinleşmesi (ilerleme dosyası)

Paket: uygulama oturumu 5 (2026-11-27), GS1 (`docs/arge/2026-11-23_dalga1/gonderim/GS1.md`; A-36).
Taban: main `c59d3c0e` (`git merge --ff-only main` sonrası; ürün kodu `ed28e36b` ile aynı, arada yalnız belge). Başlangıç: 2026-11-27 22:22. Sert son: 2026-11-28 00:45.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/GS1/` (özetler `ozet/`). `karadul.__file__` worktree'yi gösteriyor.
Takım tartışma dosyasına yazılmadı: gönderim yalnız listelenen dosyalara yazma izni veriyor (BA2 ile aynı).

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Hüküm 7: SIGTERM'e yanıtsızlığın nedeni (Ghidra'sız ölçüm) | sürüyor | |
| 2 | Ön kayıt (`on_kayit_GS1.md`) | | |
| 3 | Kesin iptal (`_kill_proc`, `cancel_job`, `_kill_jobs` / `_terminate_jobs`) + testler | | |
| 4 | Adım ve aşama olayları (`runner.py`, `core/pipeline.py`, `core/ilerleme.py`) + testler | | |
| 5 | `son_cikti_yasi_sn` + `index.html` | | |
| 6 | Mutasyon (yeni tanım + eski tanımlar) | | |
| 7 | Tek ürün koşusu (debian `cat`; H1, H2, H5) | | |
| 8 | Tam takım | | |
