# P-S3b — gnulib ön ad kanalı: sürümden ve platformdan bağımsız varlık kanıtı + kalan gnulib ad kusurları — ilerleme

Brif: `ONARIM_BRIF.md`. Paket metni: `gonderim/PS3b.md`. Karar: K-2. Önceki paket: `P-S3.md` (H5 tutmadı).
Ön kayıt: `P-S3b_on_kayit.md` (kod değişmeden önce commit'lendi).

- Taban: worktree `origin/main`'den (d2f205d) açıldı; `git merge --ff-only main` → **cce2e8c** (yerel `main` ucu).
- `karadul.__file__` worktree yolunu gösteriyor. Çalışma zamanı verisi symlink (commit'lenmez).
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/`; dondurulmuş taban `taban_kod/` (cce2e8c'nin `git archive`'ı).

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt | bitti | (bu commit) |
| 1 — varlık işaretleri | sürüyor | |
| 2 — `usage` gelenek kanalı | bekliyor | |
| 3 — `sort` `full_write` (`_exit`) | bekliyor | |
| 4 — LTO'suz iç adlar | bekliyor | |
| 5 — aday kaydı raporda | bekliyor | |
