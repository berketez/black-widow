# OL1 — ÖL-1: Ghidra köprüsünde takılan çözümleyici bekçisi ve ilerleme olayları

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-8, A-9, A-18), `docs/arge/2026-11-19_mythos/olcek/PLAN.md` §1 (ilerleme olayı sözleşmesi: günlükçü `karadul.ilerleme`, satır biçimi, alanlar — SABİT, değiştirme) ve "ÖL-1" (adımlar 1–7, kabul, ön kayıt: aynen uygula), `docs/arge/2026-11-19_mythos/hiz/HZ1.md` (köprü adımlarının süre kaydı), `docs/arge/2026-11-19_mythos/hiz/P16e.md` (senden hemen önce aynı dosyaya giren paket).

## Neden

Gösteri koşusunda (Ollama dilimi, 26,6 MB) tek bir Ghidra çözümleyicisi ("Objective-C Message Analyzer") saatlerce döndü; koşu günlüğü 113 dakika boyunca tek satır yazmadı. Analist "çalışıyor mu, takıldı mı" bilemiyor. Bu paket (a) takılan çözümleyiciyi fark edip kapatır ve analizi sürdürür, (b) köprünün her adımında ilerleme olayı üretir. Büyük ikili hedefinin (A-8) ilk koşulu.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Zamanlayıcı tek:** adım başı / sonu olayları HZ1'in `_AdimSaati.basla / bitti` noktalarına bağlanır (`from karadul.ghidra.headless import GHIDRA_ADIMLARI`; ikinci bir zamanlayıcı kurma). Sözleşmedeki `ghidra.bsim` burada iki adımdır: `ghidra.bsim.ingest`, `ghidra.bsim.query`.
2. **`config.py`'ye yazmazsın.** Alanlar BAYRAK paketiyle var: `analysis.cozumleyici_takilma_sn` (bugün 0, INERT'te), `analysis.bekci_aralik_sn` (15, INERT'te). Yaman (`docs/arge/2026-11-23_dalga1/yamalar/OL1__config.py.patch`): iki INERT satırını siler, `# ETKİSİZ` yorumlarını "okuyan: …" diye düzeltir ve `cozumleyici_takilma_sn` öntanımını planın dediği **600**'e çeker (0 = kapalı). Öntanım değişikliği S8 eşitliğiyle (kabul b) korunur.
3. **Donanımdan bağımsızlık (A-9):** 600 sn bir süre eşiğidir, işlemciye göre ayarlanmış sayı değildir; yine de eşik ve aralık yalnız ayardan okunur, kodda sabit sayı kalmaz.
4. **Sahte ilerleme yok:** olay yalnız gerçek bir okuma ya da gerçek bir adım geçişiyle üretilir; "canlı görünsün" diye zamanlayıcıyla boş olay basılmaz. Çözümleyici adı okunamıyorsa alan yazılmaz (uydurma ad yok).
5. Fizibilite adımı (plan adım 1) için tek küçük Ghidra koşusu yeter (ör. debian `cat`); üç yoldan hangisini seçtiğini ve neden öbürlerini seçmediğini ilerleme dosyana yaz.

## Yazabileceğin dosyalar

- `karadul/ghidra/headless.py` — `_run_auto_analysis`, `_analyze_pyghidra` içinde yalnız olay satırları, yeni özel sınıf `_CozumleyiciBekcisi`. Döküm işlevlerinin gövdelerine (`_extract_*`; P16e sıraladı, ÖL-2 / ÖL-3 girecek) dokunma.
- Yeni `tests/test_ol1_kopru_bekci.py`, `scripts/measurement/mutation_specs_ol1.json`
- Belgeler: `docs/arge/2026-11-19_mythos/olcek/on_kayit_ol1.md`, `docs/arge/2026-11-19_mythos/olcek/OL1.md` (ilerleme dosyası)
- Yama: `docs/arge/2026-11-23_dalga1/yamalar/OL1__config.py.patch`

**Dokunma:** `karadul/config.py`, `karadul/analyzers/macho.py`, `karadul/cli.py`, `ui/`, `karadul/ghidra/bsim.py`, `karadul/core/pipeline.py`, `karadul/stages.py`, `karadul/pipeline/steps/`. `EXIT_ANALYSIS_PARTIAL` yolunda (`karadul/core/pipeline.py`) değişiklik gerekiyorsa yama bırak.

`headless.py`'de `find` metni tutan mutasyon tanımları: `mutation_specs_{hz1,p16a,p16c,p16d,p13a,p16e}.json`. Değişikliğinden sonra altısını yeniden koş; bayatlayan olursa ilerleme dosyana yaz.

## Ölçüm

- **S8 (kabul b):** 8 ikili, kendi dalının ürün ağacıyla, kuyrukla (`~/karadul_olcum/ghidra_kuyruk.sh OL1 S8:<ikili> …`; komut ORTAK_D0 §6). Taban: P16e'nin "sonra" kökü (`~/karadul_olcum/runs/dalga1-2026-11-23/P16e/s8_sonra_1`; P16e'den sonra ham karşılaştırma geçerli). Fark yalnız yeni alanlar (`takilan_cozumleyici` yok / boş) ve mutlak yol olmalı.
- **T25 (kabul a, c):** Ollama dilimi, "Objective-C Message Analyzer" AÇIK (gösteri 1. denemenin koşulu: `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/` altındaki `kos.sh` ve `deneme1_*` dosyaları). Bekçinin tetiklenmesi ≥ 600 sn sürer; koşunun tamamı saatler alabilir. Bu yüzden: koşuyu kuyrukla arka planda başlat, **yalnız tetiklenme + ikinci `analyzeAll` turunun bitişini** bekle (kabul a ve "kalan analiz ≤ 600 sn"), `ILERLEME` satır aralıklarını o ana kadarki günlükten ölç (kabul c), sonra koşuyu durdur (süre sınırı en çok 75 dk; `timeout`). Tamamı koşulmadıysa bunu açıkça yaz. Süreler "yük altında" etiketli.

## Sert son

Gönderim iletisinde yazılı. Öncelik: fizibilite → bekçi + testler + mutasyon → olaylar → S8 → T25.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: T25'te bekçi kaç saniyede tetiklendi, hangi çözümleyiciyi kapattı, ikinci tur kaç saniyede bitti, en uzun `ILERLEME` sessizliği kaç saniye (ölçülmediyse "ölçülmedi"). Sonra S8 x / 8, fizibilite hükmü, test / mutant sayıları, altı eski tanımın durumu, commit listesi, yama, ÖL-4 (gösterim) ve ÖL-2 (bütçeler) için notlar.
