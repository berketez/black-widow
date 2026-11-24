# OL4 — ÖL-4: ilerlemenin CLI'da ve arayüz sunucusunda görünmesi (ilerleme dosyası)

Paket: uygulama oturumu 4 (2026-11-24), OL4 (`docs/arge/2026-11-23_dalga1/gonderim/OL4.md`). Plan: `docs/arge/2026-11-19_mythos/olcek/PLAN.md` "ÖL-4" (gönderim metnindeki hükümlerle).
Taban: main `cfe93cef` (`git merge --ff-only main` sonrası; ürün kodu `534e252b` ile aynı, arada yalnız belge). Başlangıç: 2026-11-24 13:13. Sert son: 14:40.
Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/OL4/` (özetler `ozet/`). Ürün ağacı: `~/karadul_olcum/urun-75ecbc61` (kod + test commit'i `75ecbc61`; altı bağ; kökte `karadul.yaml` YOK: öntanımlarla koşar).

## Kalemler

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Ortak ayrıştırıcı (`karadul/core/ilerleme.py`) | bitti | `959632ad` |
| 2 | CLI: üç kip (`analyze` ilerleme kurulumu, `cli_common.py` yardımcıları) | bitti | `db9a6e01` |
| 3 | Sunucu: `_job_progress` artımlı okuma + `ilerleme` alanı | bitti | `def88cbc`, `107d9f31` |
| 4 | `index.html` incelemesi + yama (uygulanmadı) | bitti | `7c13409e` |
| 5 | Testler (`tests/test_ol4_ilerleme.py`, 52) | bitti: 52 / 52 | `75ecbc61` |
| 6 | Mutasyon (`mutation_specs_ol4.json` 22 / 22) + sekiz eski tanım (259 mutant: 256 öldü, 0 yaşadı; 4 bayat find düzeltildi, 3 bayat başka dosyada) | bitti | `75ecbc61`, `c1fe7145` |
| 7 | Gerçek koşu (debian `cat`, üç kip; kuyrukla) | bitti: öntanım 46 satır / 17 adım, `--quiet` 0, `--verbose` yineleme 0 | bu commit |
| 8 | Tam takım | koşuyor (13:49'da başladı) | |

**13:50 — bekliyorum (tam takım):** worktree kökünden, geçici çalışma verisi bağları kurulu (commit'lenmedi). 13:49:3x'te başladı; TAHMİNİ bitiş 14:00–14:15 (yük 20–40). 14:30'da bitmemişse "kalan" yazılır.

**13:33 — bekliyorum (geçti):** `cat` üç kip kuyrukta (`OL4 cat:ontanim` 13:30:13'te sıraya girdi; yuva 1'i ana oturumun S8 tabanı (mac/tmux, 13:27'de başladı), yuva 2'yi `ANA ollama:kabul` tutuyor). TAHMİNİ: yuva 1 13:35–13:45'te boşalır, üç kip yük altında 3 × 2–5 dk → bitiş 13:45–14:05. Eski sekiz mutasyon tanımı arka planda sırayla (TAHMİNİ bitiş 13:45–13:55); tam takım ondan sonra (TAHMİN 10–25 dk).

## Kalem 1 — ayrıştırıcı (`959632ad`)

- **Yer: yeni `karadul/core/ilerleme.py`** (hüküm 1; yalnız ayrıştırıcı). `cli_common.py` yerine ayrı modül seçildi: arayüz sunucusu `karadul.core.*`'u zaten aynı düzenle içe aktarıyor (`from karadul.core import overrides  # noqa: E402`), sunucunun Rich / Click'e bağlanması gerekmiyor. CLI de aynı işlevi kullanır (iki kopya yok).
- `ilerleme_ayristir(satir)`: satırda `ILERLEME ` öneki (satır başında ya da boşluktan sonra; ardından sözleşmenin ilk alanı `asama=`) aranır, sonrası `shlex.split` ile ayrılır (OL1 notu: tırnak, `\"`, `\\`). Sözleşme dışı satır → `None`: zorunlu alan (`asama`, `adim`, `durum`) yok, `durum` sözleşmede yok, bilinmeyen alan, `=`'siz parça, yinelenen alan, kapanmamış tırnak (yarım satır), sayı olmayan `islenen` / `toplam` / `gecen_sn`. Dönen sözlükte yalnız satırda geçen alanlar; `islenen` / `toplam` `int`, `gecen_sn` `float`.
- `gosterim_alanlari(olay)`: `adim, durum, islenen, toplam, gecen_sn, cozumleyici, neden` (satırda olmayan `None`); olay yoksa `None`.
- Sözleşme sabitleri (`ILERLEME_ONEKI`, `ILERLEME_GUNLUKCU`, `OLAY_DURUMLARI`, `OLAY_ISTEGE_BAGLI_ALANLAR`) üreticiden içe aktarılır (`karadul/ghidra/headless.py`; tek kaynak). Maliyet: `karadul.config`'in üstüne +14 ms içe aktarma (ölçüldü).

## Kalem 2 — CLI (`db9a6e01`)

`karadul/cli_common.py`: `ilerleme_kipi`, `ilerleme_aciklamasi`, `IlerlemeGosterici` (günlük işleyicisi), `ilerleme_gosterimi` (bağlam yöneticisi), `akim_tty`. `karadul/cli.py` `analyze`: yalnız ilerleme çubuğu dalında kip hesaplanır ve `pipeline.run` `ilerleme_gosterimi` içinde koşar (+ içe aktarma satırı).

| Kip | Ne zaman | Davranış |
|---|---|---|
| yok | `--quiet` (genel seçenek), `--json`, `--verbose` | işleyici kurulmaz. `--quiet` / `--json` olay basmaz; `--verbose`'da kök işleyici (`setup_logging`) satırı zaten yazar → tam bir kez |
| cubuk | stderr terminal VE çubuk terminalde çiziliyor (`console.is_terminal and not is_dumb_terminal`) | satır basılmaz; çubuğun (transient) açıklaması `<aşama etiketi> <adim> [islenen[/toplam]] [gecen_sn sn]` |
| satir | öbür durumlar | her olay stderr'e tek satır, sözleşme biçiminde (`ILERLEME asama=… adim=… durum=…`); çubuk varsa açıklaması da güncellenir |

- **Yorum (hüküm 2'nin "TTY"si):** hüküm hangi akımın TTY olduğunu söylemiyor. Satırlar stderr'e gittiği için ölçüt stderr; ek olarak çubuk çizilmiyorsa (stdout dosyada, stderr terminalde) satır yazılır, yoksa olay hiçbir yerde görünmezdi. İkisi de terminaldeyse satır basılmaz (çubuğu bozardı).
- **Rich Live tuzağı:** `Progress` terminalde `sys.stderr`'i konsola (stdout) yönlendiren bir vekille değiştirir. Akım çubuk açılmadan ÖNCE alınır (`ilerleme_akimi = sys.stderr`); yoksa stdout terminaldeyken satırlar stderr dosyası yerine ekrana düşerdi (test: `test_e2e_cubuk_terminalde_satir_stderr_e_gider`; mutant `ol4_akim_cubuk_icinde`).
- Bağlam boyunca `karadul.ilerleme` günlükçüsü INFO'ya çekilir ve yayılımı kapatılır (kökte önceki bir `--verbose` koşusundan kalan işleyici varsa satır iki kez çıkmasın); çıkışta düzey, yayılım ve işleyici listesi eski hâline döner (test).
- Değişmeyen: stdout'un makine-okur çıktısı (`--json` stdout'u `json.loads` ile okunur; testte), aşama satırları (`_log_stage_complete`), `make_progress_callbacks`, `--quiet` dalı.

## Kalem 3 — sunucu (`def88cbc`, `107d9f31`)

- **Okuma:** iş kaydında `gunluk` (`_GunlukDurumu`): dosya kimliği (`st_dev`, `st_ino`), ofset, işlenmemiş yarım satır, aşama satırları (`ended` / `errored`), alt aşama eşleşmeleri, son 6 satır, son olay. `_job_progress` önce `proc.poll()` (bitmiş sürecin bütün baytları dosyadadır), sonra yalnız yeni baytları okur (yeni bayt yoksa dosya açılmaz); yarım satır sonraki çağrıya kalır, iş bitince işlenir; dosya kısalır ya da değişirse baştan. Günlük okunamazsa bugünkü gibi boş günlük. Eşzamanlı iki yoklama tek kilitle (`_GUNLUK_KILIDI`). Eski biçimli iş kaydı (`gunluk` alanı yok; testler böyle kuruyor) çalışır.
- **Tam okumayla aynı çözümleme:** `read_text(errors="ignore")` = UTF-8 + evrensel satır sonu (`\r\n`, `\r` → `\n`). Artımlı yolda baytlar `\n`'de bölünür (UTF-8'de `\n` çok baytlı karakterin içinde olamaz), parça sonundaki `\r` bekletilir (ardından `\n` gelebilir). Aşama ve alt aşama desenleri satır sonunu aşmadığı için satır satır taramak metnin tamamını taramakla aynı (`_STAGE_LINE_RE` son eşleşme kazanır; `SUBSTAGE_PATTERNS` ilk eşleşme). Son 6 satır `str.splitlines()` ile aynı bölmeyle (satır sonuyla biten parça `\n` eklenerek bölünür; `\x0c` vb. de satır sınırı).
- `_parse_stage_log` aynı sonucu veren iki yardımcıya bölündü (`_scan_stage_lines`, `_stage_list`); imzası ve sonucu aynı (eski testler yeşil).
- **JSON:** var olan alanlar (ad, tür, anlam) değişmedi (`stages`, `substages`, `finished`, `workspace`, `elapsed`, `binary`, `rc`, `cancelled`, `outcome`, `clean_dir`, `tail`; testte anahtar kümesi denetleniyor). Yeni alan `ilerleme`: `{adim, durum, islenen, toplam, gecen_sn, cozumleyici, neden}` (satırda olmayan `null`), olay yoksa `null`. Son olay = günlükteki son geçerli `ILERLEME` satırı (sözleşme dışı satır atlanır). Bitişte `substages` yine `report.json`'dan (değişmedi).
- **Hız (kabul):** 10 MB'lık sahte günlükte (her 5 satırın biri `ILERLEME`), süren iş, yük altında: **ilk yoklama 281–291 ms; sonraki 5 yoklama 5,5–7,7 ms** (her birinde ~4 KB eklenerek; test sınırı 50 ms). Önce (tam okuma, aynı günlük, aynı makine): **207,5 ms her yoklamada**. İlk yoklama tam okumadan biraz yavaş (satır satır tarama); bir kez ödenir. Sonraki yoklamaların süresinin çoğu macOS'ta yeni yazılmış dosyanın `open` çağrısı (profil: 10 ms'nin ~10 ms'si `_io.open`; değişmemiş dosyada 0,1 ms).

## Kalem 4 — `index.html` (yama `7c13409e`; uygulanmadı)

- **`index.html` bugün `_job_progress` JSON'undan şunları gösteriyor:** `binary` (`anBin`), `elapsed` (`anEl`, saniye), `stages[]` (`key`, `label`, `status` → satır sınıfı ve ✓ / ✕ / –; `time` → "N.Ns", `running` ise "çalışıyor…" metni (bugünden var); `skip_reason` → "ATLANDI" etiketi + gerekçe), `substages[]` (`label`, `count`, `unit`, `name_label`; yalnız reconstruct satırının altında), `tail` (`anTail`), `finished` / `cancelled` / `workspace` (yoklamayı durdurma, sonuç ekranı), `rc` / `outcome` / `clean_dir` (`finishMessage`). `error` → `pollStep`.
- **Yama** `docs/arge/2026-11-23_dalga1/yamalar/OL4__index.html.patch` (11 satır değişikliği ≤ 20): `renderStages`'te statik aşama `running` iken ve `p.ilerleme` doluyken aşama satırının altına tek satır: `adim · durum · islenen / toplam · gecen_sn sn · cozumleyici · neden` (yalnız olayda olan alanlar; `textContent`, `innerHTML` yok; `.substage` sınıfı BİLEREK kullanılmadı: her yoklamada yeniden çizilince `slidein` animasyonu tekrar oynardı). Animasyon, dönen simge, "ilerliyor" metni yok. Olay yoksa satır yok.
- **CSP karması** PUV6a'nın yaptığı gibi (`test_ui_lm_panel.py::test_csp_betik_karmasi_ve_kisitlar` yöntemi): `<script>…</script>` içeriğinin UTF-8 SHA-256'sı base64 → meta etiketindeki `script-src 'sha256-…'`. Yama karmayı da değiştirir: `xVJqNUEkei+P+SvPklSpOiKzxcqoGLzYMI3zBxsoUfs=` → `miiFzXDZ74DTlQdObWP2e55EzZfBJiejT+/rFb66Tco=`. Betik yama ile başka bir değişiklikle birlikte uygulanırsa karma yeniden hesaplanmalı: `~/karadul_olcum/runs/dalga1-2026-11-23/OL4/betik/csp_karma.py <index.html> --yaz`.
- Denetim (ağaca uygulanmadan, kopyada): `git apply --check` temiz; yamalı betik `node --check` 0; yeni bloğun çıktısı node'da sahte DOM ile: decompile olayı → `ghidra.decompile · suruyor · 500 / 13559 · 45.3 sn`, bekçi tetiklenmesi → `… · 690.3 sn · Objective-C Message Analyzer · 600 sn tepede (eşik 600 sn); kapatılıyor`, `ilerleme: null` → satır yok, statik aşama bitmişse → satır yok (`yama/betik.js`, `yama/blok.js`).
- Neden yalnız statik aşama: olaylar bugün yalnız Ghidra köprüsünden (`asama=static`). Köprü bittikten sonra son olay (`ghidra.kapatma bitti`) günlükte son olay olarak kalır; reconstruct sürerken onu göstermek yanıltırdı. `ilerleme` alanı `asama`'yı taşımıyor (hüküm 3'ün alan listesi); başka aşamalar olay üretmeye başlarsa (ör. `paket`) ÖL-8'de `asama` eklenmeli.

## Kalem 5 — testler (`75ecbc61`)

`tests/test_ol4_ilerleme.py`, 52 test, ~3–4 sn (Ghidra yok):
- ayrıştırıcı (16): üreticinin satırıyla gidiş-dönüş (tırnak, `\"`, `\\`, `=`, satır sonu → boşluk, tipler), `--verbose` öneki ve `\r\n`, 13 sözleşme dışı satır, `gosterim_alanlari`;
- CLI birim (13): kip tablosu (8 durum), çubuk açıklaması (toplamlı / toplamsız / Rich kaçışı), satır kipi (akıma tam bir satır + çubuk açıklaması + çıkışta günlükçü eski hâli), çubuk kipi (satır yok), yok kipi (işleyici yok), kökte eski işleyici varken tek satır;
- CLI uçtan uca (6; sahte boru hattı olayları gerçek üreticiden `_ilerleme` ile basar, `CliRunner`): öntanım → stderr'de 6 / 6 satır sözleşme biçiminde, stdout'ta 0; `--quiet` 0, `--json` 0 (stdout JSON okunuyor); `--verbose` tam bir kez (kök işleyicinin biçimi); stdout terminal (Rich Live yönlendirmesi) → satırlar yine gerçek stderr'de, ekranda 0; çubuk kipi (stderr terminal) → satır 0;
- sunucu (17): rastgele parçalı ↔ tek seferlik tam okuma eşdeğerliği (8 tohum, 26+ parça; `\r\n` arasından ve çok baytlı UTF-8 ortasından bölme; `\x0c`, bozuk bayt, sona yarım satır, sözleşme dışı olay satırı; bitişte ve yeniden yoklamada), tek seferde beklenen değerler, yarım satır, `\r\n` parça sınırı, dosya kısalması, günlük yok, olay yoksa `null`, aynı parçada son olay, ikinci yoklamada yalnız yeni satırların taranması (ofset = dosya boyu), 10 MB günlükte sonraki yoklamalar < 50 ms.
- İlgili eski testler (değişiklikten sonra): `test_cli`, `test_p15a_cli_kucuk`, `test_p15b_cli_metin`, `test_skipped_stage_display`, `test_p17_durum`, `test_p17_iptal` 102 / 102; `tests/test_ui_*.py` (8 dosya) 118 / 118.

## Kalem 6 — mutasyon

- `scripts/measurement/mutation_specs_ol4.json`: **22 mutant, 22 öldü**, hata 0 (üretici `~/karadul_olcum/runs/dalga1-2026-11-23/OL4/betik/spec_uret.py`: her `find` tekil, `replace` farklı uzunlukta). Ayrıştırıcı 4 (shlex yok, durum denetimi yok, önek sınırı yok, sayaç metin), CLI 10 (verbose'da işleyici, kip ve / veya, çubuk kipinde satır, yayılım açık, işleyici kalır, düzey INFO değil, açıklamada toplam yok, akım stdout, verbose iletilmez, akım çubuk içinde alınır), sunucu 8 (baştan okuma, yarım satır hemen, `\r` bekletilmez, kısalma denetimi yok, ilk olay alınır, bitişte yarım satır kalır, `ilerleme` hep null, son 6 satır bölmesi). Günlük `…/OL4/mutasyon/ol4.log`.
- **Eski tanımlar** (`cli.py` / `cli_common.py` / `ui/server.py`'de `find` tutan sekiz tanım; `grep -l` ile; `cli_common.py`'ye bakan tanım yok), OL4 değişikliğinden sonra tam olarak yeniden koşuldu (13:29–13:48, sırayla, betik `betik/eski_mutasyon.zsh`, günlükler `…/OL4/mutasyon/<ad>.log`):

| Tanım | Mutant | Öldü | Yaşadı | Hata (find eşleşmedi) | Düzeltme |
|---|---|---|---|---|---|
| adim3_ui | 30 | 30 | 0 | 0 | — |
| p15a | 45 | 44 | 0 | 1 (`k_clean_varlik_sonra`, `cli.py`) | find düzeltildi → yeniden koşu 1 / 1 öldü |
| p15b | 25 | 25 | 0 | 0 | — |
| p17 | 54 | 54 | 0 | 0 | — |
| pguv | 34 | 30 | 0 | 4 | `g13_kok_kabul` (`cli.py`) düzeltildi → 1 / 1 öldü; **`g07_bool_donusum_yok`, `g07_yalniz_security_bolumu` (`karadul/config.py`) ve `m03_kaynak_esleme_ana_anahtarsiz` (`karadul/reconstruction/naming/pipeline.py`) düzeltilmedi**: dosyalar bu paketin değil, OL4 dokunmadı |
| ui_cagri_kenari | 13 | 12 | 0 | 1 (`a_grafik_hic_kullanilmaz`, `ui/server.py`) | find düzeltildi → 1 / 1 öldü |
| ui_lm_api | 30 | 30 | 0 | 0 | — |
| surum_oncesi | 28 | 27 | 0 | 1 (`so2_ag_anahtari_acilmaz`, `cli.py`) | find düzeltildi → 1 / 1 öldü |
| **toplam** | **259** | **252 + 4** | **0** | 7 → 3 kalan (başka dosyalarda) | `c1fe7145` |

- Bayatlamanın nedeni OL4 DEĞİL; hepsi daha önceki commit'ler: `7f158c45` (MEK-09 (d), CLI metinlerinin Türkçe karakterleri: `bulunamadi` → `bulunamadı`, `Gecersiz hedef adi` → `Geçersiz hedef adı`), `d6224bdc` (ağ ana anahtarı `cfg.network.enable(…)` oldu), `2be7e900` (ARAYUZ-11: `_call_graph_edges`'e `extra_hex`). Düzeltme yalnız `find` / `replace` metni (aynı mutasyon, aynı test); find HEAD'de tekil, replace farklı uzunlukta (`betik/bayat_denetle.py`); yeniden koşu `betik/bayat_yeniden.zsh` → 4 / 4 öldü. Kalan üç bayat tanım (config.py ×2, naming/pipeline.py ×1) ana oturuma bildirildi.
- Koşu sonunda `git diff` yalnız düzeltilen tanım dosyaları (kod dosyaları temiz).

## Kalem 7 — gerçek koşu: debian `cat`, üç kip (kabul: CLI'ın üç kipi gerçek koşuda)

- Ürün ağacı `~/karadul_olcum/urun-75ecbc61` (`git worktree add --detach` + altı bağ; kökte `karadul.yaml` yok → öntanımlar). Girdi: S8 tabanının `raw/` kopyası (`~/karadul_olcum/runs/urun-onarim-a62f15e/debian/coreutils/cat/ws/workspaces/cat/20261119_054950/raw/cat`). Komut (ağacın kökünden): `python -m karadul [--quiet] analyze <cat> --skip-dynamic --output-dir <kök>/ws --output <kök>/out [--verbose]`, stdout ve stderr AYRI dosyalara (ikisi de TTY değil → öntanım kipi `satir`), koşuya özel `KARADUL_CACHE_DIR`, `PYTHONHASHSEED=0`, dış `timeout 1200`. Sürücü `betik/cat_kos.zsh` + `betik/tek.zsh` (her kip ayrı kuyruk çağrısı), ölçüm `betik/cat_olc.py` → `ozet/cat_olc.json`.
- Kuyruk: `OL4 cat:ontanim` 13:30:13'te sıraya girdi, 13:34:59–13:35:59 (60 sn); `cat:quiet` 13:35:59–13:36:41 (42 sn); `cat:verbose` 13:36:41–13:37:22 (41 sn); yuva 1, 1 dk yük 25,1–26,8 (**yük altında**; süreler hüküm değil). Üçü de çıkış 0.

| Kip | stderr `ILERLEME` satırı | stdout `ILERLEME` satırı | Ayrışmayan | Biçim | Adım (`basladi` → kapanış) |
|---|---|---|---|---|---|
| öntanım | **46** | 0 | 0 | 46 / 46 yalın sözleşme satırı (`ILERLEME asama=static adim=… durum=…`) | **17 / 17** adımda `basladi` ve `bitti` (başlayıp kapanmayan 0); ayrıca `ghidra.gdt` `atlandi` (üretici bu adımı başlatmadan atlıyor: "ayar boş"), `ghidra.bsim.query` `basladi` → `atlandi` → `bitti` (taze depo, OL2); `suruyor` 10 |
| `--quiet` | **0** (stderr 0 bayt) | 0 | — | — | — |
| `--verbose` | 46 | 0 | 0 | 46 / 46 kök işleyicinin biçiminde (`SS:DD:ss INFO    [karadul.ilerleme] ILERLEME …`), yalın satır **0**, art arda aynı yük **0** → **yineleme 0** | öntanımla aynı 17 adım, aynı durum sayıları |

- 17 adım: `jvm_baslatma`, `ice_aktarma`, `otomatik_analiz`, `pdb`, `functions`, `strings`, `call_graph`, `decompile`, `types`, `xref`, `pcode`, `cfg`, `function_id`, `bsim.ingest`, `bsim.query`, `combined`, `kapatma` (hepsi `ghidra.` önekli).
- stdout öntanım ↔ `--verbose`: tek fark çıktı dizininin yolu (`Output: …/ontanim/out` ↔ `…/verbose/out`); olay stdout'a düşmedi.
- TTY kipi (çubuk açıklaması) gerçek koşuda sınanmadı: bu koşuda terminal yok (arka plan). Birim ve uçtan uca testlerde sınandı (`test_e2e_cubuk_kipi_stderr_terminal_satir_yok`, `test_cubuk_kipi_satir_basmaz`).
- **T25 (en uzun boşluk ≤ 60 sn): ölçülmedi; ana oturumun koşusuna bırakıldı** (OL2 ve bu paket main'e girince Ollama koşusunda).
- Özetler: `ozet/cat_olc.json`, `ozet/cat_ontanim_stderr.txt` (46 satır), `ozet/cat_verbose_ilerleme.txt`, `ozet/cat_quiet_stderr.txt` (boş), `ozet/kuyruk_OL4.txt`.

## Sonraki paketlere not

### ÖL-8 (arayüz ölçeği)

- `index.html` yaması (`yamalar/OL4__index.html.patch`) ana oturumca uygulanınca CSP karması yamadaki değerdir; ÖL-8 betiği değiştirirse karma yeniden hesaplanır (`betik/csp_karma.py`; yöntem `test_ui_lm_panel.py::test_csp_betik_karmasi_ve_kisitlar`).
- `renderStages` her yoklamada kutuyu baştan kurar: `.substage` sınıfının `slidein` animasyonu her yoklamada yeniden oynuyor (bugünkü reconstruct alt satırları dahil). Yama bu yüzden sınıfsız satır kullanıyor; ÖL-8 kutuyu yerinde güncellemeye geçerse animasyon tek seferlik olur.
- `ilerleme` alanı `asama`'yı taşımıyor (hüküm 3 listesi); olaylar bugün yalnız `asama=static`. Başka aşama olay üretmeye başlarsa `gosterim_alanlari`'na (`karadul/core/ilerleme.py` `GOSTERILEN_ALANLAR`) `asama` eklenmeli ve yamadaki `s.key==='static'` koşulu `e.asama===s.key` olmalı.
- `build_model`'e dokunulmadı.

### OL10-G (rapor, CLI satırı, `--derinlik`)

- `analyze`'da ilerleme çubuğu dalı artık `with ilerleme_gosterimi(…)` içinde `pipeline.run` çağırıyor; koşu sonu özet satırı bu bloğun DIŞINDA (çubuk kapandıktan sonra) basılmalı. `--quiet` / `--json` kipinde olay işleyicisi yok; aynı kural özet satırı için de geçerli.
- Tembel kip yeni olay üretirse (ör. `adim=tembel.secim`), sözleşme dışı alan eklenmez (üretici `ValueError` atar); CLI çubuğu `asama` etiketini `STAGE_LABELS`'tan alır.
- `mutation_specs_ol4.json`'un `cli.py` `find` metinleri: `ilerleme_akimi = sys.stderr`, `quiet=quiet, verbose=verbose, stderr_tty=akim_tty(ilerleme_akimi),`, `with ilerleme_gosterimi(kip, akim=ilerleme_akimi,` — `--derinlik` eklenirken bu satırlar tekil kalmalı.

### OL10-H (arayüz, KaradulLM)

- `_job_progress` iş kaydında `gunluk` (`_GunlukDurumu`) tutuyor; yeni uçlar günlüğü yeniden okumamalı, gerekirse bu durumdan beslenmeli. Tembel kipin "decompile edilmedi" sayaçları rapordan / sıra dosyasından okunmalı, günlükten değil.
- `mutation_specs_ol4.json`'un `ui/server.py` `find` metinleri `_GunlukDurumu.besle`, `_gunluk_ilerlet` ve `_job_progress`'in dönüşünde; bu işlevlere dokunan paket tanımı yeniden koşmalı.

### Riskler

- **İlk yoklama** 10 MB günlükte 281–291 ms (tam okumanın 207,5 ms'sinin 1,35–1,40 katı; satır satır tarama); sonra yalnız yeni baytlar. Onlarca MB'lık günlükte sunucu yeniden başlatılıp iş yeniden bağlanırsa ilk yoklama bir kez o kadar sürer (iş kaydı bellekte; sunucu yeniden başlayınca iş zaten "job yok").
- **Aynı boyda yeniden yazılan günlük** (aynı inode, aynı uzunluk) fark edilmez; tam okuma ederdi. Analiz günlüğü yalnız ekleniyor; olmayan bir durum.
- **Kodlama:** artımlı yol UTF-8 sabit; tam okuma yerel ayarın kodlamasını kullanıyordu (macOS'ta UTF-8). UTF-8 dışı yerel ayarda `tail` farklı çözülebilir.
- **TTY yorumu** (kalem 2): stdout dosyada, stderr terminaldeyse satır terminale yazılır (hükmün "TTY'de satır basılmaz"ının dışında; çubuk çizilmediği için olay başka türlü görünmezdi).
