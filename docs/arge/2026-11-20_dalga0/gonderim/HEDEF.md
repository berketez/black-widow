# HEDEF — P-ÜV8 kalem 1–3 (hedef seti ve GT) + bugünkü ürünün "önce" sayısı ║ P-ÜV9 kalem 1

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-17).

**Plan.** `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 (ortak kurallar, test verisi kuralı, taşınacak betikler), "P-ÜV8" kalem 1–4, "P-ÜV9" kalem 1, §9 (veri), §10 (riskler); `ustveri/BULGULAR.md` §7. `karsi/KARSI.md` İ-1 ve §3 ("bitiş ölçümünü — hedef seti + T25 — ilk dalgada 'önce' sayısı olarak almak").

**Yazabileceğin dosyalar.** Yeni `scripts/measurement/ustveri_set.py`, yeni `scripts/measurement/ustveri_olc.py`, yeni `tests/test_puv8_olcum.py`, yeni `scripts/measurement/mutation_specs_puv8.json`, yeni `scripts/arge/ustveri/acik_*.py`; belgeler `docs/arge/2026-11-19_mythos/ustveri/olcum/` ve `docs/arge/2026-11-19_mythos/ustveri/acik_olcum/`; veri `~/karadul_olcum/ustveri_set/`, `~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/`. İlerleme `docs/arge/2026-11-19_mythos/ustveri/olcum/HEDEF.md`.
**Dokunma.** `karadul/` (ürün); `scripts/measurement/{urun_olc,ks1_olc}.py` (yalnız içe aktar); `scripts/arge/ustveri/` altındaki var olan betikler (başvuru; değiştirme). Hiçbir hedef ikili çalıştırılmaz; kapalı kaynak uygulama analiz edilmez; üçüncü taraf ikili ve çıkarılmış ad listesi depoya girmez.

## Kalemler

1. **Kalem 1 — set hazırlığı** (`ustveri_set.py`): §9'daki sembollü ikililer; `/usr/bin/strip` (conda'nınki değil); sha256 + sürüm kaydı; GT özgün ikilinin sembol tablosundan. Keşif / sınama bölmesi (keşif: terminal-notifier, docker-cli; sınama: docker-compose, iTerm2, llama-server) ölçümden önce ön kayıtla commit.
2. **Kalem 2 — ad eşitliği** kuralları tek yerde, sentetik verili testlerle.
3. **Kalem 3 — `ustveri_olc.py kanal`**: kanal çıktısı (adres → ad) ↔ GT; ad verilen / doğru / yanlış / GT'siz; Wilson %95 (`ks1_olc.oran`); A-2 satırı (alt sınır ≥ 0,909). Ürün okuyucuları (P-ÜV1–4) henüz yok: aracı yalnız **keşif** ikililerinde araştırma okuyucularının çıktısıyla doğrula (`$V/…` başvuru dosyaları; yoksa `scripts/arge/ustveri/*` ile yeniden üret) ve sonucu "araştırma okuyucusu, ürün kanalı değil" etiketiyle yaz. **Sınama ikililerinde kanal kesinliği bu pakette hesaplanmaz** (okuyucular dondurulunca, Dalga 2); sınamada yalnız GT çıkarımı ve H1 (soyma öncesi / sonrası kanal çıktısı aynı mı; araştırma okuyucusuyla) koşulur.
4. **Kalem 4 (bütçe) + bugünkü ürünün "önce" sayısı**: GT'li ikililerin soyulmuş kopyalarında ürün koşusu, bayraklar öntanımlı, ürün ağacı `~/karadul_olcum/urun-b6aceb9`, her biri `~/karadul_olcum/ghidra_kuyruk.sh HEDEF <ad> …`, süre sınırı 3 600 sn. Önce TAHMİNİ süreyi yaz (gösteri: 26,6 MB dilim 129 dk; 119'luk ölçümün süreleri); tahmini 60 dakikayı aşan ikiliyi KOŞMA ("ölçülmedi: süre — gece kuyruğuna önerildi" yaz). Sayılar: ürünün ad verdiği fonksiyon, GT'ye göre doğru / yanlış (kalem 2 kurallarıyla), kanal kırılımı. Bu, P-ÜV8 kalem 5'in "bayrak kapalı" koluyla aynı tanımdır (taban).
5. **P-ÜV9 kalem 1** — gösteri çalışma alanından (`~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws`, salt okur): Ghidra'nın fonksiyon sayısı ↔ `LC_FUNCTION_STARTS`; Ghidra'nın jenerik olmayan adları; üst veri adlarıyla kesişim ve ad eşitliği; Go 1.26 uyarısından sonra Go fonksiyonlarına verilen ad sayısı. Yön ön kaydı koşudan önce commit.
6. **Testler** (en az 10) ve **mutasyon** (en az 5; planın listesi).

## Kabul

Set + GT + bölme commit'li; araç testli, mutantlar öldü; keşifte araç araştırma çıktısını yeniden üretiyor; taban tablosu (koşulabilen ikililer) ve P-ÜV9 kalem 1 tablosu; tam takım 0 hata. Süre: kod 60–90 dk; Ghidra kuyruğu ayrıca.
