# OLCEK — ÖLÇ-A → ÖLÇ-0 → gece koşusu hazırlığı (ÖLÇ-1 + HZ-0; koşma)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-8, A-9, A-18).

**Plan.** `docs/arge/2026-11-19_mythos/olcek/PLAN.md` §1 (ortak kurallar, ilerleme olayı sözleşmesi), §2 "ÖLÇ-0", "ÖLÇ-A", "ÖLÇ-1"; `docs/arge/2026-11-19_mythos/hiz/PLAN.md` §1 (boş makine tanımı, donanım künyesi, S8, hedefler K / O / B) ve "HZ-0"; `olcek/BULGULAR.md`, `hiz/BULGULAR.md` (tahminlerin kaynağı). A-18: ÖLÇ-1'in T100 / T300 / PAKET duvarları 2 saat; ÖLÇ-1 ile HZ-0 tek koşuda. Avast: `SONRAKI_OTURUM.md` §5 son iki satır (HZ-0 iki kolla; dışlamayı Berke yapar).

**Yazabileceğin dosyalar.** Yeni `scripts/measurement/olcek_kos.py`, yeni `tests/test_olcek_kos.py`, yeni `scripts/measurement/mutation_specs_olcek_kos.json`, yeni `scripts/arge/hiz/hz0_ek.py`, yeni `scripts/arge/olcek/gece_kosusu.py`, `scripts/arge/hiz/zaman_cizelgesi.py` (yalnız planın dediği küçük ek: `BASLADI` yoksa `kunye.json` başlangıcı); belgeler `docs/arge/2026-11-19_mythos/olcek/{OLC0.md, on_kayit_olc1.md, GECE_PLANI.md}`, `docs/arge/2026-11-19_mythos/hiz/on_kayit_hz0.md`; veri `~/karadul_olcum/runs/arge-2026-11-19/olcek/gosteri_son.json` (yeni) ve `~/karadul_olcum/runs/dalga0-2026-11-20/OLCEK/`. İlerleme dosyası `docs/arge/2026-11-19_mythos/olcek/GECE_PLANI.md`.
**Dokunma.** Ürün kodu (`karadul/`); `scripts/measurement/urun_kos.py` (OLCUM paketi değiştiriyor; `agac_kunyesi`'ni içe aktar); öbür betikler.

## Kalemler

1. **ÖLÇ-A**, planın adımlarıyla (`olcek_kos.py`; testler Ghidra'sız, sahte komutla; mutantlar). Künyedeki Ghidra adım süreleri: `ghidra_status.json`'da `adim_sureleri` / `analysis` alanları varsa (HZ-1 ekliyor, paralel yürüyor) onları oku; yoksa `scripts/arge/olcek/olcek_topla.py` `ghidra_adim_sureleri` mantığıyla dosya zamanlarından çıkar; hangi kaynağın kullanıldığı künyeye yazılsın.
2. **Uçtan uca duman.** Tek kısa gerçek koşu: girdi `~/karadul_olcum/runs/urun-onarim-a62f15e/debian/coreutils/cat/ws/raw/` altındaki ikili, ürün ağacı `~/karadul_olcum/urun-b6aceb9`, `~/karadul_olcum/ghidra_kuyruk.sh OLCEK duman:cat …`. Künye eksiksiz mi, `ornekler.csv` ≥ 3 satır mı, `gc.log` oluştu mu. Süre "yük altında".
3. **ÖLÇ-0**, planın adımlarıyla (salt okur) → `gosteri_son.json`, `OLC0.md` (ön kayıtla kıyas; her satıra tuttu / tutmadı).
4. **Gece koşusu tasarımı** (KOŞMA; ana oturum, ajanlar bitince boş makinede koşturacak):
   - a. `on_kayit_olc1.md`: plan taslağını A-18'e göre yeniden yaz. T100 / T300 / PAKET duvarı 7 200 sn; T25 = HZ-0'ın B hedefi (duvar 10 800 sn). Her öngörüyü 2 saatlik duvara göre yeniden ifade et; aralığı duvarı içeren öngörüyü "belirsiz" diye açıkça yaz (ör. T300 ilk adım TAHMİN A [5 041; 16 085] sn). Aralıklar BULGULAR'dan, kaynağıyla; uydurma sayı yok.
   - b. `hiz/on_kayit_hz0.md`: planın H0-a … H0-e metni aynen + Avast kolu (HZ-0 adım 7) için hüküm biçimi (dışlamalı / dışlamasız açma gecikmesi ve uçtan uca oranı; hangi farkın "anlamlı" sayılacağı koşudan önce).
   - c. `hz0_ek.py` (HZ-0 adım 2).
   - d. `gece_kosusu.py`: verilen ürün commit'i için (ağaç `~/karadul_olcum/urun-<commit>`; yoksa `git worktree add --detach` + `urun_kos.CALISMA_VERISI` bağları) bütün kuyruğu sırayla koşar: HZ-0 (K, O, B × 3; sıra K1 O1 B1 K2 O2 B2 K3 O3 B3), B_jfr (1), K AppCDS (4), Avast kolu (K ve O × 3; kök `~/karadul_olcum/runs/hiz-avast-dislama/<commit>/` — Berke bu dizini Avast'ta dışlar), ÖLÇ-1 (T100, T300, PAKET; isteğe bağlı PAKET-E). Her koşu `olcek_kos.py` ile, her biri `ghidra_kuyruk.sh` ile. Boş makine denetimi: koşu başında ve sonunda 1 dk yük < 0,25 × `os.cpu_count()`; aşılırsa koşu geçersiz işaretlenir, en çok 2 kez yinelenir. Kaldığı yerden sürdürme (`BITTI` varsa atla). `--kuru` kipi planı ve TAHMİNİ toplam süreyi basar; `--yalniz <grup>`; tek kök `~/karadul_olcum/runs/gece-<commit>/`; sonda özet JSON.
   - e. `GECE_PLANI.md`: kuyruk, her koşunun TAHMİNİ süresi (gösteri koşusu, 119'luk ölçüm, BULGULAR; kaynağıyla), toplam. Tek geceye (≈ 10 sa) sığmıyorsa iki geceye böl ve hangisinin önce gideceğini öner. Berke'nin yapacağı tek iş Avast dışlaması: yol, ne zaman eklenip ne zaman kaldırılacağı — tek paragraf, sade Türkçe.
5. **Testler ve mutasyon** (`olcek_kos`; `gece_kosusu`'nun boş makine denetimi ve sürdürme mantığı için de en az 2 mutant).

## Kabul

ÖLÇ-A planındaki kabul; duman koşusunun künyesi eksiksiz; `OLC0.md`; gece kuyruğu `--kuru` ile basılıyor, sürdürme ve boş makine denetimi testli; iki ön kayıt belgesi commit'li (koşu yapılmadı); tam takım 0 hata. Süre hedefi 90–120 dk.
