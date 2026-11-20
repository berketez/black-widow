# KİMLİK — Dalga 0 paketi (PK-6 + PK-11): ilerleme

- Başlangıç: 2026-11-20 08:54. Dal: `worktree-agent-a2e74e17f3b864d9d`; taban `6551f2f` (main; `3ec5c77` atası).
- Gönderim metni: `docs/arge/2026-11-20_dalga0/gonderim/KIMLIK.md`. Plan: `kimlik/PLAN.md` §3 PK-6, PK-11.
- Kip: PK-3 (`kimlik_olc`) yok → ölçüm dondurulmuş araştırma betikleriyle (`scripts/arge/kimlik/`); yeni grup
  tanımları `scripts/measurement/kimlik_ciftler.py`, yükleyici eki ve sarmalayıcılar `scripts/arge/kimlik/d0_*.py`.
- Koşu çıktıları: `~/karadul_olcum/runs/dalga0-2026-11-20/KIMLIK/` (iş listesi `isler.txt`, günlük `kos.jsonl`).

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 1 Ön kayıtlar (`PK-6_on_kayit.md`, `PK-11_on_kayit.md`, grup tanımları) | bu commit | (bu commit) |
| 2 PK-6 `mimari`, `derleyici_surumu` | koşu sırada | — |
| 3 PK-6 `surum_esli` (V1) | derleme başlamadı | — |
| 4 `iyilestirme` | veri yok (tabaka C Dalga 2'de) | — |
| 5 PK-11 | koşu sırada (iş listesinde ilk) | — |
| 6 Kilit süzgeci sınaması + mutant | başlamadı | — |

## Ghidra koşu planı (kuyruğa girmeden önce)

- Koşu sayısı: **68** (`--stage static`, ürün `~/karadul_olcum/urun-b6aceb9`, her ikili ayrı `ghidra_kuyruk.sh` çağrısı):
  PK-11 1 (libzstd) + tabaka A 19 + tabaka B Debian 12 19 + tabaka B Ubuntu 24.04 19 + V1 10 (5 ikili × 2 derleyici).
  Debian 13 arm64 tarafı yeniden koşulmuyor (a62f15e koşusu).
- **TAHMİNİ süre** (yük altında; dayanak bugünkü kuyruk günlüğünün tam boru hattı süreleri: cat 33 sn, sort 57,
  tree 51, htop 81, sqlite3 102, tmux 285): saf Ghidra süresi ~105 dk [80–160]; kuyruk başka paketlerle
  paylaşıldığı için duvar saati **2,5–4,5 saat** [TAHMİN].
- **BİLDİRİM:** tahmini duvar süresi 3 saati aşabilir. Sıra buna göre: PK-11 (1 koşu) → `mimari` (küçükten büyüğe)
  → V1 (`surum_esli`; derleme bitince araya girer, küçükten büyüğe) → `derleyici_surumu` Debian 12 → Ubuntu 24.04
  (her biri küçükten büyüğe). Zaman yetmezse en sondaki büyük ikililer eksik kalır ve "ölçülmedi" yazılır.
