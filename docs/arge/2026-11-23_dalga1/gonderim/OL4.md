# OL4 — ÖL-4: ilerlemenin CLI'da ve arayüz sunucusunda görünmesi

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 akşam eki dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-8, A-17, A-18), `docs/arge/2026-11-19_mythos/olcek/PLAN.md` §1 (ilerleme olayı sözleşmesi: SABİT) ve "ÖL-4" (adımlar 1–6, kabul: aşağıdaki hükümlerle uygula), `docs/arge/2026-11-19_mythos/olcek/OL1.md`'nin "ÖL-4 (gösterim)" notları (üretilen `durum` değerleri, satır biçimi, ayrıştırma kuralı), `docs/arge/2026-11-19_mythos/olcek/OL2.md` varsa (adım içi `suruyor` olayları; OL2 senden önce ya da seninle aynı anda main'e giriyor olabilir).

## Neden

ÖL-1 köprünün her adımında `karadul.ilerleme` olayı üretiyor, ama `analyze` `--verbose` olmadan INFO işleyicisi kurmadığı için kullanıcı hiçbirini görmüyor: gösteri koşusunda ekran 113 dakika sessiz kaldı. Arayüz sunucusu iş günlüğünü her yoklamada baştan sona okuyor (büyük ikilide günlük onlarca MB). Bu paket olayları `--verbose` olmadan gösterir ve sunucunun günlüğü artımlı okumasını sağlar. "Orta boy uygulamada kullanılır hâl" ara durağının kalemi.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Olay üretmezsin, gösterirsin.** `karadul/ghidra/headless.py`'ye ve olay sözleşmesine dokunma. Ayrıştırma tek yerde: `ILERLEME ` önekinden sonrası `shlex.split` ile (OL1 notu; tırnak ve kaçışlar). Aynı ayrıştırıcıyı CLI ve sunucu birlikte kullanır (iki kopya yok; yeri `karadul/cli_common.py` ya da yeni küçük bir modül — hangisini seçtiğini yaz; `ui/server.py`'nin içe aktarma düzenine uy).
2. **CLI kipleri:** `--quiet` / `--json` → olay basılmaz. `--verbose` → ayrı işleyici KURULMAZ (kök işleyici satırı zaten yazıyor; satır iki kez çıkmamalı — test). Öbür durumda: TTY değilse olay satırı stderr'e yazılır (her olay bir satır, sözleşme biçiminde); TTY'de satır basılmaz, ilerleme çubuğunun açıklaması son olayın `adim` + `islenen/toplam` + `gecen_sn`'sidir (çubuk `transient` kalır; stdout'un makine-okur çıktısı değişmez).
3. **Sunucu artımlı okur.** `_job_progress` her çağrıda günlüğü baştan okumaz: iş kaydında dosya ofseti ve birikmiş durum (aşama satırları, alt aşama eşleşmeleri, son olay, son 6 satır) saklanır; yalnız yeni baytlar okunur (yarım satır sonraki çağrıya bırakılır). Dönen JSON'un var olan alanları (ad, tür, anlam) DEĞİŞMEZ; yeni alan `ilerleme`: son olayın `adim`, `durum`, `islenen`, `toplam`, `gecen_sn`, `cozumleyici`, `neden`'i; olay yoksa `null` (sahte ilerleme yok; var olmayan alan uydurulmaz). İş bittiğinde birikmiş durum bugünkü tam okumanın verdiğiyle aynı olmalı (eşdeğerlik testi: aynı günlük tek seferde ↔ rastgele parçalara bölünmüş hâlde).
4. **`ui/index.html`'e dokunmazsın** (CSP karması ve başka paketlerin zinciri). `index.html`'in `_job_progress` JSON'undan bugün hangi alanları gösterdiğini oku ve yaz; yeni `ilerleme` alanını gösterecek değişiklik ≤ 20 satırsa YAMA olarak bırak (`docs/arge/2026-11-23_dalga1/yamalar/OL4__index.html.patch`; CSP karmasının nasıl yenileneceğini PUV6a'nın yaptığı gibi yaz), uygulamayı ana oturum yapar. Animasyon, dönen simge, "ilerliyor" metni EKLEME: yalnız gerçek olayın alanları.
5. **Gerçek koşu (tek, küçük):** kendi dalının ürün ağacıyla debian `cat` (≈ 1 dk), kuyrukla (`~/karadul_olcum/ghidra_kuyruk.sh OL4 cat …`), üç kip: öntanım (stderr dosyaya yönlendirilmiş → `ILERLEME` satırları var, her adım için `basladi` / `bitti`), `--quiet` (satır yok), `--verbose` (satır tam bir kez). T25 ölçümünü (en uzun boşluk ≤ 60 sn) ana oturum OL2 ve bu paket main'e girince Ollama koşusunda yapar; sen "ölçülmedi; ana oturumun koşusuna bırakıldı" yaz.
6. Aşama satırları (`OK / FAIL / SKIP <aşama>`; `_STAGE_LINE_RE`) ve `SUBSTAGE_PATTERNS` davranışı korunur.

## Yazabileceğin dosyalar

`karadul/cli.py` (yalnız `analyze` içindeki ilerleme kurulumu ve yardımcıları), `karadul/cli_common.py` (`make_progress_callbacks` ve yeni yardımcılar), `ui/server.py` (yalnız `_job_progress`, iş kaydının oluşturulduğu yerdeki yeni alanlar ve yeni yardımcılar); gerekiyorsa yeni `karadul/core/ilerleme.py` (yalnız ayrıştırıcı); yeni `tests/test_ol4_ilerleme.py`, `scripts/measurement/mutation_specs_ol4.json` (≥ 8 mutant); `docs/arge/2026-11-19_mythos/olcek/OL4.md` (ilerleme dosyası); yama `docs/arge/2026-11-23_dalga1/yamalar/OL4__index.html.patch` (varsa).

**Dokunma:** `karadul/ghidra/`, `karadul/core/pipeline.py`, `karadul/core/logging_config.py`, `ui/index.html`, `karadul/config.py`, `karadul/stages.py`, `cli.py`'nin öbür komutları.

`cli.py` / `cli_common.py` / `ui/server.py`'de `find` metni tutan mutasyon tanımlarını bul (`grep -l` ile; bugün en az `mutation_specs_{adim3_ui,p15a,p15b,p17,pguv,ui_cagri_kenari,ui_lm_api,surum_oncesi}.json`); değişikliğinden sonra dokunduğun dosyaya bakanları yeniden koş, bayatlayanı yaz.

## Kabul

- 10 MB'lık sahte günlükte `_job_progress`'in İKİNCİ ve sonraki çağrıları < 50 ms (yalnız yeni baytlar); ilk çağrının süresi ayrıca yazılır.
- Parçalı ↔ tek seferde okuma eşdeğerliği (hüküm 3).
- CLI'ın üç kipi (hüküm 2) birim testte ve gerçek `cat` koşusunda.
- Var olan CLI / arayüz testleri yeşil (`tests/test_cli.py`, `tests/test_ui_*.py`, `tests/test_p15a_cli_kucuk.py`, `tests/test_p15b_cli_metin.py` …).

Ön kayıt gerekmez (gösterim; ölçüt testte).

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek koşu sayısı: `cat` koşusunda öntanım kipinde stderr'e düşen `ILERLEME` satırı sayısı ve kapsanan adım sayısı; `--quiet` 0; `--verbose` yineleme 0; 10 MB günlükte ikinci çağrı kaç ms (önce: tam okuma kaç ms). Sonra `index.html`'in bugün gösterdiği alanlar ve yamanın durumu, test / mutant sayıları, eski tanımların durumu, commit listesi, ÖL-8 / OL10-G / OL10-H için notlar.
