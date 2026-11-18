# P-S3 — `stages.py` 3. tur: gnulib ön ad kanalı kanıta bağlanır (AD-03, B-A3) + veri akışı belirlenimciliği — ilerleme

Brif: `ONARIM_BRIF.md`. Karar: K-2 (Berke: "amacımız isim üretmek; düzelt, yakın ve doğru isim üretmek, hesaplama ile"). Bulgular: AD-03 ve B-A3 (`docs/arge/2026-11-18_genel_tarama/kulvar_AD.md`), P-S2 bulgusu `data_flow_edges` (`P-S2.md` § Kalem 2). Ön kayıt: `P-S3_on_kayit.md` (kod değişmeden önce).

- Taban: worktree `origin/main`'den (e9d2d08) açıldı; `git merge --ff-only main` → **097fdff** (yerel `main` ucu).
- `karadul.__file__` worktree yolunu gösteriyor. Çalışma zamanı verisi symlink (`sigs`, `vendor`, `signatures_homebrew*.json`, `sigs_macos_system.json`, `scripts/node_modules`; commit'lenmez).
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3/`.

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt | sürüyor | |
| 1 — AD-03 / B-A3: gnulib kanalı kanıta bağlı | sürüyor | |
| 2 — veri akışı belirlenimciliği | bekliyor | |
| 3 — temizlik (kullanılmayan yereller / içe aktarımlar) | bekliyor | |

## Gürültü tabanı (B0a ↔ B0b)
Aynı kod (097fdff, worktree temiz), `urun_kos.py --paralel 1`, `PYTHONHASHSEED=0`, koşu başına ayrı `KARADUL_CACHE_DIR`; 7 geliştirme seti ikilisi (debian/tmux, mac/tmux, redis-cli, openssl, zstd, cat, expr). Koşu sürerken worktree'nin `karadul/` dosyaları değiştirilmedi.
