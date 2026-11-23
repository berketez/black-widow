# OL10A — ÖL-10 alt paketi A: saf çekirdek (ilerleme)

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/OL10A.md`; tasarım: `olcek/OL10_TASARIM.md` §2, §1.3, §7.1 (bağlayıcı).
- Taban: main `7a1c8f4` (2026-11-23 20:29; `git merge --ff-only main`; ilk ileri sarma sırasında main bir kez daha ilerledi, ikinci ileri sarmayla eşitlendi).
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/OL10A/` (özetler `ozet/`).
- Başlangıç: 2026-11-23 20:32; `uptime` yük ortalaması 28,67 / 31,03 / 28,33 (makine yüklü). Disk kullanılan 716,5 GB.
- Sert son: 22:00.

## Kalemler

| # | Kalem | Durum |
|---|---|---|
| 1 | `tembel_secim.py` (sabitler, veri sınıfları, `sec`, `kes`) | başladı |
| 2 | `tembel_girdi.py` (K1 JSON + görüntüden girdi) | bekliyor |
| 3 | `tembel_xref.py` (`turet`) | bekliyor |
| 4 | ön kayıt `on_kayit_OL10A.md` (ölçümden önce ayrı commit) | bekliyor |
| 5 | testler (≥ 24) | bekliyor |
| 6 | `tembel_kuru.py` | bekliyor |
| 7 | dondurma commit'i | bekliyor |
| 8 | ölçüm H-A1 … H-A5, H-A7 | bekliyor |
| 9 | okuyucu envanteri (adım 6) | bekliyor |
| 10 | mutasyon (≥ 14) | bekliyor |
| 11 | SINAMA H-A6 (dondurmadan sonra bir kez) | bekliyor |
| 12 | tam takım | bekliyor |
