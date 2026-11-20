# OLCEK paketi (Dalga 0) — ilerleme ve gece koşusu planı

- Paket: `docs/arge/2026-11-20_dalga0/gonderim/OLCEK.md` (ÖLÇ-A → duman → ÖLÇ-0 → gece koşusu tasarımı; gece koşusu KOŞULMAZ).
- Taban: main `e996200` (worktree `--ff-only` ile ilerletildi; `karadul.__file__` worktree yolunu gösteriyor).
- Başlangıç: 2026-11-20 08:15 (`uptime` 1 dk yük 4,28).

## Kalem durumu

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | ÖLÇ-A `olcek_kos.py` + testler + mutantlar | bitti | (bu commit) |
| 2 | Uçtan uca duman (cat) | bekliyor | — |
| 3 | ÖLÇ-0 (`gosteri_son.json`, `OLC0.md`) | bekliyor | — |
| 4 | Gece koşusu tasarımı (ön kayıtlar, `hz0_ek.py`, `gece_kosusu.py`, bu belge) | bekliyor | — |
| 5 | Testler ve mutasyon (`gece_kosusu` dahil) | bekliyor | — |

## Kalem 1 — ÖLÇ-A (`scripts/measurement/olcek_kos.py`)

- Arayüz planın adım 1'iyle aynı; ek seçenekler: `--java-ek` (JFR / AppCDS gibi ek JVM seçenekleri; gece kuyruğu kullanır), `--ornek-aralik` (10), `--disk-aralik` (60), `--kill-bekle-sn` (60), `--komut` (yalnız test kancası).
- Ağaç denetimi `urun_kos.agac_kunyesi` içe aktarılarak (kod kopyalanmadı); koşu başında ve sonunda.
- Duvar: `time`'ın çocuğuna (karadul) SIGTERM, 60 sn sonra gruba SIGKILL. `time`'a SIGTERM gönderilmez: kısa kesilen koşuda da `time -l` satırları kalır (gösteri 1. denemedeki gibi).
- `pid.json` (time ve karadul süreç numarası) eşlik eden örnekleyiciler için (HZ-0 `hz0_ek.py`).
- Disk taraması uzarsa (çok dosya) bir sonraki tarama `max(60, 5 × tarama süresi)` sn sonra: ölçüm koşuyu boğmasın. Plandan küçük sapma; künyede `disk_tarama_en_uzun_sn`.
- Ghidra adım süreleri: `ghidra_status.json` `adim_sureleri` (HZ-1) varsa o, yoksa `ghidra_output` dosya zamanları (`olcek_topla.ghidra_adim_sureleri` mantığı buraya taşındı); kaynak künyede `ghidra.adim_kaynagi`. Köprü yarıda kaldıysa her çıktının koşu başından beri saniyesi, son biten adım ve `decompiled/` sayısı.
- Testler: `tests/test_olcek_kos.py` 16 test (koşucu gerçek alt süreç; sahte analiz komutu; Ghidra yok). PLAN kabulü: duvar 5 sn → `zaman_asimi`, süre ≤ 67 sn (ölçülen ≈ 5 sn); varsayılan aralıklarla 30 sn'lik sahte koşuda `ornekler.csv` ≥ 3 satır (testte).
- Mutasyon: `scripts/measurement/mutation_specs_olcek_kos.json` 6 / 6 öldü (duvar eşiği, SIGKILL, SIGTERM'in hedefi, tepe RSS seçimi, ağaç RSS'i, adım kaynağı önceliği); `git diff` temiz.
