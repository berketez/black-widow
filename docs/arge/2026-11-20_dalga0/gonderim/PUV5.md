# PUV5 — P-ÜV5 Mach-O `main` (üst veri hızlı hattı; KARARLAR A-27)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md` (kurallar aynen geçerli; §3 Ghidra kuyruğu ve sabit ürün ağacı), `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-27).

**Plan.** `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` "P-ÜV5" (kalem 1–7, kabul, ön kayıt metni, sınama ve mutasyon) — aynen uygula. Ölçülen boşluk: Mach-O'da `LC_MAIN` girişi GT `_main` 8 / 8, ürünün `main` verdiği 0 / 8. Başvuru betiği `scripts/arge/ustveri/macho_main.py`.

**Yazabileceğin dosyalar:** `karadul/stages.py` — YALNIZ `_recover_main_from_entry` ve onun yeni yardımcıları (adım listeleri ve başka yöntemler değişmez); yeni `tests/test_puv5_macho_main.py`; yeni `scripts/measurement/mutation_specs_puv5.json`; `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV5.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV5.md` (ilerleme); yama `docs/arge/2026-11-20_dalga0/yamalar/PUV5__config.py.patch`.
**Dokunma:** `config.py` (INERT yaması: bayrağı `getattr(…, "enable_macho_entry_main", False) is True` ile okuyunca `test_p15a` kaydın silinmesini ister → INERT satırını ve alan satırındaki `# ETKİSİZ` yorumunu kaldıran yamayı commit'le; tam takımı yama geçici uygulanmış koş, sonra geri al), `naming_labels.py`, `tarif/baglama.py`, `karadul/analyzers/ustveri/` (PUV0'ın).

## Zaman planı (sert son 15:15)

1. Ön kayıt (planın metni) → commit.
2. Kod + birim testleri (≥ 10, sahte `static` dizini ve sahte Ghidra fonksiyon listesiyle) + mutasyon (≥ 6).
3. **Gerçek veriyle yeniden oynatma (Ghidra'sız, öncelikli):** var olan çalışma alanları üstünde kuralı uygula ve say — Mac: `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/mac/tmux`, `~/karadul_olcum/runs/urun-onarim-a62f15e/mac/{htop,tmux}`, P-S3b kabul seti çalışma alanları (`~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/`; düzeni oradaki `kos_mac.sh`'tan); ELF: geliştirme setinin 5 ikilisi (`~/karadul_olcum/runs/urun-onarim-a62f15e/debian/…`). H1 / H3 / H6'nın yeniden oynatma hükmü.
4. **Ürün koşusu (zaman kaldıkça, Ghidra kuyruğuyla):** kendi dalının ürün ağacıyla (ORTAK_D0 §3), bayrak açık, önce htop ve tmux; sonra kabul setinin kalanı; bayrak kapalı kol (H2) en son. Her biri `~/karadul_olcum/ghidra_kuyruk.sh PUV5 <ad> …`.
5. Tam takım.

**15:15'te dur:** koşulamayan ürün koşularını ilerleme dosyasına "kalan" diye yaz, commit'le; yeniden oynatma ve birim kanıtıyla hüküm verilebilenleri ayrı yaz. `## PAKET BİTTİ` yalnız her şey bittiyse.
