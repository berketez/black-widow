# OK5 — ÖK-V adım 5–6 → ÖK-5 (erken risk ölçümü; ürün değişmez)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-14, A-17).

**Plan.** `docs/arge/2026-11-19_mythos/ozkod/PLAN.md` "ÖK-V" (adım 5–7) ve "ÖK-5" (adım 1–8; ön kayıt metni aynen); `ozkod/NUFUS.md` (adım 1–4 yapıldı: 24 paket indi, bölme 9 ayar / 15 kör, ELF seçimi `~/karadul_olcum/ozkod_nufus/nufus.json`); `ozkod/BULGULAR.md`; `ozkod/DEFTER.md` (dondurulmuş kural dosyalarının sha256'ları §4, §7, §10). Ek sayım: `karsi/KARSI.md` İ-1 düzeltme 3.

**Yazabileceğin dosyalar.** Yeni `scripts/measurement/ozkod_olc.py`; `scripts/measurement/ozkod_nufus_kur.py` (adım 5–6 için ek alt komut); yeni `tests/test_ozkod_olc.py`; yeni `scripts/measurement/mutation_specs_ozkod_olc.json`; `docs/arge/2026-11-19_mythos/ozkod/{NUFUS.md (yalnız yeni bölümler), on_kayit_OK5.md, OK5.md}`; veri `~/karadul_olcum/ozkod_nufus/runs/` (yeni) ve `~/karadul_olcum/runs/dalga0-2026-11-20/OK5/`. İlerleme dosyası `docs/arge/2026-11-19_mythos/ozkod/OK5.md`.
**Dokunma.** `scripts/arge/ozkod/*.py` (dondurulmuş: koşudan önce ve sonra sha256'larını DEFTER'le karşılaştır); `scripts/measurement/function_f1.py` (OLCUM paketi onarıyor; stapsdt sapması iki ELF'te NUFUS.md §8'deki gibi `tabaka_indir.elf_bilgisi` ile aşılır); ürün kodu.

**Körlük (kesin).** Kör taraftaki paketlerin fonksiyon adları, dizgileri, kaynak kodu hiçbir ekrana, dosyaya, commit'e, mesaja yazılmaz; sen de okumazsın. Kör tarafta yalnız betik sayar ve yalnız sayı yazar. Planın ÖK-5 adım 7'sindeki yanlış dökümü, ölçüm ve `OK5.md` commit'inden SONRA, yalnız `~/karadul_olcum/ozkod_nufus/runs/` altına yazılır; depoya girmez. Ayar tarafında da GT adı depoya girmez (depo herkese açık).

## Kalemler

1. **ÖK-V adım 5 — taban ürün koşusu.** `nufus.json`'daki seçili ELF'ler, bayraklar öntanımlı: `python -m karadul analyze <ikili> --skip-dynamic --output-dir <d>/ws --output <d>/out`. Ürün olarak SABİT ağaç `~/karadul_olcum/urun-b6aceb9` (cwd ve `PYTHONPATH` o ağaç; önce `karadul.__file__`'ı denetle). Her ikili ayrı çağrıyla `~/karadul_olcum/ghidra_kuyruk.sh OK5 <paket>:<elf> …`, `PYTHONHASHSEED=0`, koşuya özel `KARADUL_CACHE_DIR`, ikili başına süre sınırı 3 600 sn (aşan "zaman aşımı" diye kayda geçer, nüfus dışı kalmaz: ayrı sayılır). Sıra: önce "ayar" tarafı (adım 4'ün dondurması onu bekler), sonra "kör"; her tarafta küçükten büyüğe. Her koşu bitince `BITTI` (çıkış kodu) ve kısa künye; ilerleme dosyasına sayaç. Kuyruğa girmeden önce ELF sayısını ve boyuta göre TAHMİNİ toplam süreyi yaz; 6 saati aşacaksa ana oturuma bildir (dönüş mesajı değil, ilerleme dosyasına "BİLDİRİM:" satırı + commit; ana oturum izliyor).
2. **ÖK-V adım 6 — olgu önbelleği** (`ozkod_olc.py kur`); tutarlılık: nüfus > 0, GT eşleşmesi build-id ile hatasız.
3. **ÖK-5 adım 1–2.** `ozkod_olc.py`: kuralları içe aktar (kopyalama). Eşdeğerlik: geliştirme setinde keşif 754 / 740, sınama 126 / 103 aynen. Tutmazsa dur, ilerleme dosyasına yaz.
4. **Ön kayıt** (`on_kayit_OK5.md`): planın metni aynen + İ-1/3 satırı ("hedef setinde erişim — Ollama'nın Go dışı fonksiyonları, gösteri çıktısı salt okur: sayı raporlanır, eşik yok"). Kör sayımdan önce commit.
5. **ÖK-5 adım 4** — ayar tarafında yalnız G1 kapısı ve K1 karakter eki dondurulur; dondurma ayrı commit, kör sayımdan önce.
6. **ÖK-5 adım 5–6** — kör sayım; havuz ve paket başına; Wilson; karakter / norm / ayraçsız eşitlik ve belirteç ölçüleri ayrı.
7. **ÖK-5 adım 8** — `OK5.md`: ön kayıtlı her hükme "tuttu / tutmadı"; ÖK-3 / ÖK-4b / ÖK-6 için karar satırı (açılır / kapalı kalır / yeniden ön kayıt).
8. **Hedef erişimi (İ-1/3).** `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws` (salt okur) üstünde K1 / G1 / R1'in erişimi (kayıt çifti olan fonksiyon payı). btop ve llama-server bu pakette yok (Dalga 2, hedef setiyle).
9. **Testler ve mutasyon** (en az 5 mutant: kör / ayar karışması, Wilson, eşik karşılaştırması, kip A / C seçimi, birim listesi).

## Kabul

NUFUS.md adım 5–6 kabulü (en az 15 paket GT'li ve koşulmuş; iki tarafta en az 5'er paket; her ikilide build-id eşleşmesi); ÖK-5 ön kaydının her satırına hüküm; dondurulmuş betiklerin sha256'ları değişmedi; mutantlar öldü; tam takım 0 hata.

**Süre.** Ghidra kuyruğu uzun: kuyruğu beklerken `ozkod_olc.py`'yi, testleri ve ön kaydı yaz. Her 10 koşuda bir ilerleme commit'i.
