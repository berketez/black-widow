# HEDEF — P-ÜV8 kalem 1–4 (hedef seti, GT, "önce" sayısı) ║ P-ÜV9 kalem 1

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/HEDEF.md`. Ortak brif: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`.

- Başlangıç: 2026-11-20 09:2x. Taban commit: `233f199` (main; `git merge --ff-only main` ile).
- `karadul.__file__` worktree yolunu gösteriyor (doğrulandı).
- Veri kökü: `~/karadul_olcum/ustveri_set/` (set), `~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/` (koşular).
- **Ön kayıt:** `on_kayit_HEDEF.md`, commit `bbda937` (ölçümden önce).

## Durum

| Kalem | Durum |
|---|---|
| 1 set + GT + bölme | ön kayıt commit'li (`bbda937`); set hazırlığı sürüyor |
| 2 ad eşitliği | bekliyor |
| 3 kanal ölçümü | bekliyor |
| 4 bütçe + ürün "önce" sayısı | bekliyor |
| 5 P-ÜV9 kalem 1 | yön ön kaydı commit'li (`bbda937`, §5) |
| 6 test + mutasyon | bekliyor |

## Koşu listesi (Ghidra kuyruğu) ve TAHMİNİ süre

Ayrıntı ve dayanak: `on_kayit_HEDEF.md` §4 (güç yasası üssü 2,14; tmux 223 sn, gösteri 7 762 sn).

| İkili | TAHMİN | Karar |
|---|---|---|
| terminal-notifier (soyulmuş) | 1–5 dk (yük altında) | koşulur: `ghidra_kuyruk.sh HEDEF urun:terminal-notifier …`, süre sınırı 3 600 sn |
| llama-server arm64 | 164–215 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| docker-cli | 334–983 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| docker-compose | 859–7 378 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| iTerm2 arm64 | 1 046–11 219 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
