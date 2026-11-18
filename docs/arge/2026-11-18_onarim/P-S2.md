# P-S2 — `stages.py`: onaylı ölü kod silme (K-3 A1) ve çift koşan blok (K-3 A1b, BORU-01) — ilerleme

Brif: `ONARIM_BRIF.md`. Karar: K-3 (Berke, 2026-11-18 10:1x: "çöpler hangisiyse, asla kullanılmayacak olanlar hangisiyse onları sil"). Bulgular: BORU-12 (ölü kod haritası), BORU-01 (çift koşan blok), bağlam BORU-03 / BORU-04 (`kulvar_BORU.md`), P10.md § "P-S2'ye".

- Taban: worktree `origin/main`'den (e9d2d08) açıldı; `git merge --ff-only main` → fa010ad, ardından main ilerledi → yeniden ff → **112350e**.
- `karadul.__file__` worktree yolunu gösteriyor.

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt (`P-S2_on_kayit.md`) + gürültü tabanı | başladı | |
| 1 — A1 ölü monolit + `_execute_legacy` + yalnız onları sınayan testler | bekliyor | |
| 2 — A1b çift koşan blok (BORU-01) | bekliyor | |
| 3 — kalan çağrılmayan metotlar (silinmez, liste) | bekliyor | |
