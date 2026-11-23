# OK1 — P12d (dalda bekleyen kod) + ÖK-1: `oz_ad` harf koruma (ilerleme)

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/OK1.md`; plan `ozkod/PLAN.md` ÖK-1; kararlar A-3, A-13, A-20, A-29.
- Taban: main `bf62e4a` (`git merge --ff-only main` ile; `karadul.__file__` worktree'yi gösterdi).
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/OK1/` (özet `ozet/`).
- Sert son: 21:30.

## Kalem 1 — P12d cherry-pick, testler, mutasyon

- `git cherry-pick 17a8a13 190ddb1 28657bd 3909043 459e74e c212db0` (taban `git merge-base main worktree-agent-a733cb2eb8bc2b9fd` = `2381dce`).
- Çakışma: dört belge commit'i (`17a8a13`, `3909043`, `459e74e`, `c212db0`) `P12d.md` / `P12d_on_kayit.md` / `yamalar/P12d__sonuc.md.patch` dosyalarına dokunuyor; bu dosyaların P12d dalındaki son hâli main'de `151433c` ile zaten var (iki dosya `git diff` ile birebir aynı). Çözüm: main'deki hâl (`--ours`) tutuldu; dört commit boş kaldığı için `--skip` edildi. İçerik kaybı yok.
- Kod commit'leri dalda: `4d3afca` (D1, `190ddb1`'in karşılığı), `45f7f85` (D2, `28657bd`'nin karşılığı). Çakışmasız uygulandı.
- Testler: `tests/test_p12d_erken_donus.py` + `tests/test_p12d_kanit_secimi.py` **18 geçti** / 0 kaldı.
- Mutasyon: `mutation_specs_p12d.json` **10 / 10 öldü** (günlük `p12d_mutasyon.log`); `git diff` temiz.
