# KIMLIK — PK-6 (eldeki veriyle) ║ PK-11 (veri gelirse) — erken risk ölçümü, araştırma betikleriyle

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-14, A-15, A-17).

**Plan.** `docs/arge/2026-11-19_mythos/kimlik/PLAN.md` §2 (sıra, taşınacak betikler), §3 "PK-6", "PK-11", §4 (veri), §6 (riskler); `kimlik/BULGULAR.md`; `kimlik/DEFTER.md`. **Dalga 0 kipi:** PK-3 (`kimlik_olc`) henüz yok → ölçüm araştırma betikleriyle (`scripts/arge/kimlik/`; dondurulmuş dört nokta `KURAL`, `TUTUCU`, `KURAL_V2`, `TUTUCU_V2` değişmez). KARŞI risk sırası #3: "Çapalı eşleme başka programlarda, gömülü kitaplıkta ve C++'ta tutuyor mu?" — tutmazsa PK-2/3/4/7/8/9/10 yazılmaz.

**Veri durumu (ana oturum, 2026-11-20 08:1x).**
- Tabaka A (x86-64, Debian 13; 8 program) ve tabaka B (Debian 12 / Ubuntu 24.04 arm64): `~/karadul_olcum/n2_tabaka/{a,b}`, künye `~/karadul_olcum/n2_tabaka/tabaka_veri.json`, açıklama `docs/arge/2026-11-19_mythos/olcu/TABAKA_VERI.md`.
- Tabaka C (P-Ö6, clang iyileştirme merdiveni): YOK. V1 (kaynaktan derleme): Berke'nin izninde (A-12), YOK.
- V5 (libzstd1 + libzstd1-dbgsym, 1.5.7+dfsg-1, Debian 13 arm64): diskte YOK; ana oturum Berke'ye soruyor. Gelirse `~/karadul_olcum/n2_tabaka/kitaplik/` altına iner; o dizin yoksa PK-11 "veri yok" ile kapanır (ön kaydı yine yazılır).

**Yazabileceğin dosyalar.** Yeni `scripts/measurement/kimlik_ciftler.py` (PK-3 taşıma tablosundaki gibi `scripts/arge/kimlik/ciftler.py`'den; grup adları aynı kalır; PK-6 / PK-11 grupları eklenir); yeni `scripts/arge/kimlik/d0_*.py`; belgeler `docs/arge/2026-11-19_mythos/kimlik/{PK-6_on_kayit.md, PK-6.md, PK-11_on_kayit.md, PK-11.md}`; veri `~/karadul_olcum/runs/dalga0-2026-11-20/KIMLIK/`. İlerleme `kimlik/PK-6.md`.
**Dokunma.** Ürün kodu; `scripts/arge/kimlik/` altındaki var olan betikler (dondurulmuş); `scripts/measurement/ks1_olc.py` (yalnız içe aktar). Kilitli setler: indirme ya da grup tanımından önce program adlarını kilit belgeleriyle karşılaştır (`docs/arge/test_seti_kilidi.md`, `docs/arge/dogrulama_seti_kilidi.md`); `lua` kilitli.

## Kalemler

1. **Ön kayıtlar** (planın metinleri aynen + hangi grupların neden koşulamadığı) — koşudan önce commit.
2. **PK-6, koşulabilen gruplar:** `mimari` (tabaka A x86-64 ↔ Debian 13 arm64) ve `derleyici_surumu` (tabaka B ↔ Debian 13). Her ikilinin statik koşusu: ürün `~/karadul_olcum/urun-b6aceb9`, planın dediği aşama (`--stage static` ya da araştırma betiklerinin istediği çıktı), her biri `~/karadul_olcum/ghidra_kuyruk.sh KIMLIK <ad> …`, koşuya özel `KARADUL_CACHE_DIR`, süre sınırı. Debian 13 arm64 tarafı için hazır çalışma alanları (`~/karadul_olcum/n1_debian13/`, `~/karadul_olcum/runs/urun-onarim-a62f15e/`) araştırma betiklerinin istediği çıktıyı taşıyorsa yeniden koşma (hangi sürümle üretildiğini künyeye yaz). Kuyruğa girmeden önce koşu sayısını ve TAHMİNİ süreyi ilerleme dosyasına yaz; 3 saati aşıyorsa programları küçükten büyüğe sırala ve "BİLDİRİM:" satırıyla commit'le. Sayım yön başına (A-15); Wilson; x86-64'te `R_X86_64_RELATIVE` desteklenmiyorsa v2 o grupta "desteklenmiyor".
3. **Koşulamayan gruplar:** `iyilestirme` (tabaka C) ve `surum_esli` (V1) "veri yok / izin bekliyor" diye açık kalır. Genelleme hükmü (e) bu yüzden bu turda verilemez: açıkça yaz; `mimari` ve `derleyici_surumu`'daki program başına Wilson tablosu "genellemeye kısmi kanıt" etiketiyle.
4. **PK-11:** V5 gelirse planın adımları (1 Ghidra koşusu); gelmezse "veri yok" ile kapanır.
5. **Kilit süzgeci sınaması + mutant** (planın: süzgeç boş → kırmızı).

## Kabul

Koşulabilen her grubun künyesi tam; ön kayıtlı hükümler yazıldı; koşulamayanlar nedeniyle listeli. Süre: kod 30–45 dk; Ghidra kuyruğu ayrıca.
