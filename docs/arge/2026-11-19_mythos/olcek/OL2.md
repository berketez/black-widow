# OL2 — ÖL-2: Ghidra köprüsünde adım bütçeleri ve BSim koşulları (ilerleme dosyası)

Paket: uygulama oturumu 2, akşam dilimi, OL2 (`docs/arge/2026-11-23_dalga1/gonderim/OL2.md`). Plan: `docs/arge/2026-11-19_mythos/olcek/PLAN.md` "ÖL-2" (gönderim metnindeki hükümlerle).
Taban: main `0b4d948` (`git merge --ff-only main` sonrası; ürün kodu `152176b` ile aynı, arada yalnız belge). Başlangıç: 2026-11-23 19:37. Sert son: 22:05.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/OL2/` (özetler `ozet/`).

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Kod: döküm işlevlerine adım bütçesi + adım içi `suruyor` (`headless.py`) | başlıyor | — |
| 2 | Kod: BSim boş depo sorusu, ingest bütçesi, sorgu bütçe denetimi (`bsim.py` + `headless.py` BSim bloğu) | sırada | — |
| 3 | Testler (`tests/test_ol2_adim_butcesi.py`, `tests/test_ol2_bsim_kosul.py`) | sırada | — |
| 4 | Mutasyon (`mutation_specs_ol2.json` ≥ 10) + sekiz eski tanım | sırada | — |
| 5 | `config.py` yaması (`yamalar/OL2__config.py.patch`; `git apply --check`) | sırada | — |
| 6 | Ön kayıt (`on_kayit_ol2.md`; ölçümden önce ayrı commit) | sırada | — |
| 7 | sqlite3 (H2) | sırada | — |
| 8 | S8 (H3, H5) | sırada | — |
| 9 | T25 (H1, H4) | sırada | — |
| 10 | Tam takım (yamasız) | sırada | — |
