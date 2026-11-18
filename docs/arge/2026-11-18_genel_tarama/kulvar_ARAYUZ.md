# Kulvar ARAYUZ — bulgular
Kapsam: `ui/server.py` (tamamı), `ui/index.html` (JS'in tamamı; CSS'e animasyon için baktım), `ui/app_window.py` (güncelleme/başlatma/kapanış kısımları), `karadul/core/output_formatter.py` (tamamı), `karadul/core/report_generator.py` (bölüm listesi, istatistik, stratejiler, ad tablosu, önce/sonra), `karadul/reporting/html_report.py` (veri okuyan bütün bölümler), `markdown_report.py` (veri okuma noktaları), `sarif_report.py` (sonuç üreticileri), `karadul/reconstruction/c_project_builder.py` (yalnız `types.h` ve dosya adı kısmı), `packaging/macos/build_mac_app.sh` (sürüm, yol, pycdc, stub), `Info.plist`, `pyproject.toml`, `LICENSE`, `README.md` (lisans), `docs/quickstart.md`, `docs/kullanim_kilavuzu.md` (komutlar `python -m karadul --help`, `analyze --help`, `config --help` ile karşılaştırıldı: tutuyor). Gerçek çıktı: `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` 119 ikilinin `reports/{report.md,report.html,report.sarif.json}`, `out/{README.md,report.html,naming_map.json,dependency_graph.json,src/include/types.h}`; arayüz modeli `build_model` ile gerçek çalışma alanlarında taklit edildi. Okunamayanlar: `karadul/core/hardening.py`, `json_report.py` kodu, paketleme betiklerinin çoğu (bkz. Bakamadıklarım).
Özet: 19 bulgu (KRİTİK 1, YÜKSEK 4, ORTA 12, DÜŞÜK 2) + Küçükler. En ağırları: (1) 119/119 raporda her ikiliye "CFD zaman adımı / roket yörüngesi / matris çözücü" bileşimi, 16 zararsız ikiliye "VPN Tunnel Setup Pipeline" yazılıyor (ARAYUZ-01); (2) SARIF kripto ve ad-güvenilirliği bulgusu hiç üretmiyor, paketsiz GNU araçlarına "MPRESS_Packed" basıyor (ARAYUZ-17); IOC bölümü yol VE şema yüzünden hiç dolamaz (ARAYUZ-02); temiz rapor paket/anti-debug uyarısını hiç içermiyor (ARAYUZ-08); (3) arayüzün "Hakkında" notu çürütülmüş F1 ~0.45-0.49 iddiasını "dürüstlük notu" olarak gösteriyor (ARAYUZ-03), "Maks. fonksiyon" ve "Çevrimiçi" düğmeleri etkisiz, "Kaydet" YAML'daki diğer ayarları siliyor (ARAYUZ-04/05/06). Arayüzde XSS ve jeton/Host/Origin açığı bulmadım.

## ARAYUZ-01 — Raporlar her ikilide "CFD", "roket yörüngesi", "matris çözücü" bileşimi; 16 ikilide "VPN tüneli kurulumu" iddia ediyor
- Önem: KRİTİK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/reporting/markdown_report.py:349-378`, `karadul/reporting/html_report.py:875-938`; kaynağı `karadul/reconstruction/engineering/composition_analyzer.py:117` ("VPN Tunnel Setup Pipeline"), `:629` ("Rocket / Trajectory Simulation Loop")
- Etkin mi: evet (çağıran: `ReportStage` `karadul/stages.py:5579`, `:5589`; aşama kaydı `karadul/cli_common.py:110`). Bileşim adımı öntanımlı koşuyor (119/119 raporda bölüm var).
- Ne: "Deep Algorithm Analysis → Algorithm Compositions" bölümü `reconstructed/algorithm_compositions.json`'daki şablon eşleşmelerini süzgeçsiz basıyor. Şablonlar yalnız libc ithallerinden doluyor: `cat`'te "Matrix Solve Pipeline" = `malloc/aligned_alloc` → `fflush` ("Factor") → `free`. Sonuç olarak HER rapor bir CFD/roket/matris çözücü bildiriyor; `cp`, `mv`, `mkdir`, `install`, `who` gibi coreutils programlarında "VPN Tunnel Setup Pipeline (Dns → Encryption)" yazıyor. HTML'de ayrıca alan adları tutmuyor: kayıt `stages[].functions` (liste) taşıyor, rapor `stg.get('function_name','?')` okuyor; bütün "Function" hücreleri `?` çıkıyor. Yani analist, arkasında tek bir fonksiyon adı göremediği bir "güven %48" iddiası okuyor.
- Kanıt: `~/karadul_olcum/runs/urun-yeni2-f30ac9a` altındaki 119 `reports/report.md`:
  `grep -h "^\- \*\*.*\*\* (.*confidence" -r --include=report.md .` → "Transient CFD Time-Stepping" 119, "Rocket / Trajectory Simulation Loop" 119, "Matrix Solve Pipeline" 119, "VPN Tunnel Setup Pipeline" 16 (debian/coreutils/{mkfifo,install,mknod,who,mkdir,mv,pinky,cp}, redis-tools ×4, htop, sqlite3, openssl, mac/htop). `cat` için `algorithm_compositions.json` → `{"name":"Matrix Solve Pipeline","stages":[{"name":"Allocate","functions":["aligned_alloc","malloc"]},{"name":"Factor","functions":["fflush"]},{"name":"Free","functions":["free"]}],"confidence":0.4778}`.
- Etki: Zararlı yazılım ayrımı yapan analist, zararsız bir sistem aracında "VPN tüneli kurulumu" görür; ya da bu bölümün her raporda çıktığını fark edip bütün raporu güvenilmez sayar. Ürünün en ağır kusur sınıfı (yanlış ve sahte güvenli iddia).
- Güven: kesin (119 gerçek raporda saydım, bir kaydı açtım)
- Onarım kapsamı: kısa vadede rapor tarafında bölümü kapatmak ya da yalnız ölçülmüş/kanıtı fonksiyon düzeyinde olan bileşimleri göstermek (`markdown_report.py`, `html_report.py`; S). Kök onarım `composition_analyzer.py`'de (yalnız ithal adından şablon eşleştirmeyi yasaklamak; M) — bu kulvarın dışında. HTML alan adı uyuşmazlığı (`function_name`/`functions`, `type`/`pattern`, `label`/`name`) ayrıca düzeltilmeli.
- Nasıl sınanır: 119 ikilinin raporunda alan sezgisi (CFD/roket/VPN) kanıtsız çıkmamalı; bileşim gösterilen her satırda en az bir yerel fonksiyon adresi görünmeli; boş tablo hücresi `?` olmamalı.

## ARAYUZ-02 — "Malware IOC" bölümü iki ayrı nedenle hiçbir zaman dolamaz (B-B6'nın eki: yol düzeltilse de dolmaz)
- Önem: YÜKSEK
- Tür: hiç çalışmayan özellik / tutarsızlık
- Yer: `karadul/reporting/html_report.py:564-646`, `karadul/reporting/markdown_report.py:699-780`; yazıcı `karadul/pipeline/steps/ghidra_metadata.py:218-242`; kayıt sınıfı `karadul/analyzers/signature_db.py:182-199`
- Etkin mi: evet (ReportStage her koşuda çağırıyor)
- Ne: (1) Bilinen B-B6: rapor `static/signature_matches.json` okuyor, dosya `reconstructed/` altına yazılıyor (119/119 koşuda yalnız `reconstructed/signature_matches.json` var). Yedek yol `result.stages["static"].stats["signature_matches"]` bir liste bekliyor; o anahtar bugün reconstruct'ta bir SAYI (`ctx.stats["signature_matches"] = len(sig_matches)`). (2) YENİ: dosya doğru yerden okunsa bile süzgeç `family`/`category`/`tier` alanlarına bakıyor; yazıcı yalnız `original, matched, library, confidence, purpose, address, method` yazıyor. `SignatureMatch`'te `family`/`tier` alanı hiç yok; `category` var ama dosyaya yazılmıyor. `malware_tier1.py`'deki Sliver/Cobalt Strike imzalarının `family`/`tier` bilgisi rapora hiçbir yoldan ulaşamaz.
- Kanıt: `cat` koşusu `reconstructed/signature_matches.json` → 183 kayıt, anahtar sayımı `Counter({'original':183,'matched':183,'library':183,'confidence':183,'purpose':183})`. 119 HTML raporun hiçbirinde "Malware IOC" başlığı yok (başlık sayımı: Anti-Debug 16, IOC 0).
- Etki: Sliver ya da Cobalt Strike implantı analiz edilse bile rapor IOC bölümü göstermez; bölüm gizlendiği için analist "IOC yok" sonucuna varır.
- Güven: yüksek (yazıcı ve okuyucuyu baştan sona izledim; gerçek bir Sliver ikilisiyle denemedim)
- Onarım kapsamı: `ghidra_metadata.py` (category + imza DB'sindeki family/tier'ı kayda taşı), `signature_db.py` (alan), iki raporlayıcının okuma yolu (S-M). Rapor bölümü "veri yok" ile "IOC yok"u ayırmalı.
- Nasıl sınanır: `malware_tier1` imzasıyla eşleşen sentetik bir kayıtla iki raporda IOC bölümünün çıktığını gösteren test; gerçek ikiliden üretilmiş `signature_matches.json` biçimiyle (sentetik şema değil).

## ARAYUZ-03 — "Hakkında" penceresi eskimiş ve çürütülmüş bir doğruluk iddiası gösteriyor ("F1 ~0.45-0.49")
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim
- Yer: `ui/server.py:1027-1031` (`_ABOUT_NOTES`), gösterim `ui/index.html:1478`
- Etkin mi: evet (`/api/about` → `_about_static` → `notes`; Ayarlar ve uygulama menüsünden açılıyor)
- Ne: Not metni "Dürüst deterministik isimlendirme F1'i ~0.45-0.49 bandında ölçüldü" diyor. Bu bant yalnız LTO'lu Ubuntu coreutils ölçümüdür (2026-09-25: Ubuntu 0,479, LTO'suz Debian 0,123). Güncel ürün ölçümü (yeni2): yanlış ad oranı havuzda %29,7, makroda %52,8; tam ad kapsamı %5,2. "Dürüstlük notu" başlığı altında en iyimser ve eskimiş sayı duruyor.
- Kanıt: `ui/server.py:1029-1030`: `"Dürüst deterministik isimlendirme F1'i ~0.45-0.49 bandında ölçüldü "` / `"(LLM'siz, CPU-only). İsimlerin bir kısmı yanlış ya da eksiktir."`; `docs/arge/2026-11-10_n1_adim3/urun_olcumu_sonuc_ek1.md:19,28`; `docs/arge/2026-09-25_lto_tani_ve_tasarim.md:197` (taban satırı Debian 0,123 / Ubuntu 0,479).
- Etki: Analist adların yaklaşık yarısının doğru olduğunu sanır; Debian/Mac gibi LTO'suz ikililerde gerçek tablo çok daha kötü.
- Güven: kesin (metni ve ölçüm belgelerini okudum)
- Onarım kapsamı: `ui/server.py` not metni; sayı tek kaynaktan (ölçüm belgesinden) gelmeli, elle yazılmamalı (S).
- Nasıl sınanır: `/api/about` notlarında ölçüm künyesi (tarih, set, sayı) ile son ölçüm belgesindeki sayının aynı olduğunu denetleyen test.

## ARAYUZ-04 — Ayarlardaki "Maks. fonksiyon" düğmesi hiçbir yerde okunmuyor
- Önem: ORTA
- Tür: okunmayan ayar
- Yer: `ui/index.html:608-611`, `ui/server.py:931`, `:990`; tanım `karadul/config.py:498`
- Etkin mi: evet (ayar panelinde görünür, YAML'a yazılır)
- Ne: `binary_reconstruction.max_functions_to_process` yalnız tanımlanıyor ve gösteriliyor; boru hattında okuyan tek satır yok. Arayüz "İşlenecek en fazla fonksiyon (0 = limitsiz)" diye vaat ediyor, "Kaydet" başarı iletisi "sıradaki analizde geçerli" diyor.
- Kanıt: `grep -rn "max_functions_to_process" --include=*.py karadul ui` → yalnız `config.py:498`, `cli.py:2092` (config show), `cli.py:2133`, `ui/server.py:931`, `ui/server.py:990`.
- Etki: Büyük ikiliyi hızlandırmak için sınır koyan analist, sınırın uygulandığını sanır; analiz yine bütün fonksiyonlarda koşar.
- Güven: kesin (grep)
- Onarım kapsamı: ya ayarı boru hattına bağla ya da panelden ve `config show`'dan kaldır (S).
- Nasıl sınanır: değer 10 iken decompile/ad adımına giren fonksiyon sayısının ≤10 olduğunu gösteren test; ya da düğmenin kaldırıldığını denetleyen arayüz testi.

## ARAYUZ-05 — "Çevrimiçi kaynak eşleştirme" düğmesi etkisiz
- Önem: ORTA
- Tür: okunmayan ayar / sahte gösterim
- Yer: `ui/index.html:617-620`, `ui/server.py:1811-1812`; tüketici `karadul/pipeline/steps/_feedback_naming_refdiff.py:90-94`; `karadul/config.py:339`
- Etkin mi: evet (düğme açılınca `--enable-network` geçiliyor)
- Ne: Düğme yalnız `network.enabled`'ı açıyor. Bu bayrağın boru hattındaki tek tüketicisi `reference_download_allowed()` ve o `network.allow_reference_download`'ı da istiyor (öntanımlı `False`). Arayüz bu ikinci anahtarı ne gösteriyor ne yazıyor; dahası ayar kaydı YAML'ı baştan yazdığı için (ARAYUZ-06) elle eklenmiş `allow_reference_download: true`'yu da siliyor. Düğme açık da olsa kapalı da olsa analiz aynı. Ayrıca `ui/server.py:853-855` yorumu ("Config._from_dict network bölümünü HİÇ işlemiyor") eskimiş: `config.py:1048` artık işliyor.
- Kanıt: `_feedback_naming_refdiff.py:93-94`: `return bool(net is not None and getattr(net, "enabled", False) and getattr(net, "allow_reference_download", False))`; `grep -rn "network" karadul | grep enabled` başka tüketici göstermiyor.
- Etki: Analist ağ eşleştirmesini açtığını sanır; çevrimdışı kalır. (Tersine yanılgı yok, ama arayüz yalan söylüyor.)
- Güven: yüksek (tek tüketiciyi izledim)
- Onarım kapsamı: düğme ya iki anahtarı birlikte yönetmeli ya da kaldırılmalı; eskimiş yorum silinmeli (`ui/server.py`, `ui/index.html`; S).
- Nasıl sınanır: düğme açıkken `reference_download_allowed(cfg)` True dönmeli; kapalıyken False.

## ARAYUZ-06 — Arayüzden "Kaydet" `karadul.yaml`'daki diğer bütün ayarları sessizce siliyor
- Önem: ORTA
- Tür: sessiz hata (veri kaybı)
- Yer: `ui/server.py:977-1011` (`_write_settings`), kılavuz `docs/kullanim_kilavuzu.md:85`
- Etkin mi: evet (`POST /api/settings`)
- Ne: `_write_settings` YAML'ı yalnız 7 bilinen anahtardan oluşan yeni bir sözlükle baştan yazıyor (`_atomic_write_yaml(_SETTINGS_YAML, data)`). Kullanıcının ya da CLI'ın aynı dosyaya koyduğu başka her anahtar (`tools.ghidra_headless`, `binary_reconstruction.enable_address_placement`, `network.allow_reference_download`, imza ayarları …) kaybolur. Kılavuz "Komut satırındaki `karadul config` ile aynı dosyayı yazar" diyor; ayrıca bu yalnız cwd = veri kökü olduğunda doğru (`cli.py:2054` cwd/karadul.yaml okur; paketli uygulamada arayüz `~/Library/...`'e yazar).
- Kanıt: `ui/server.py:986-1005` — `data = {"binary_reconstruction": {...5 anahtar}, "computation_recovery": {...}, "network": {"enabled": ...}, "name_merger": {...}}` ardından doğrudan atomik yazım; mevcut dosya okunup birleştirilmiyor.
- Etki: Elle ayarlanmış Ghidra yolu ya da deney bayrağı, arayüzden bir eşik değiştirilince kaybolur; sonraki analiz farklı yapılandırmayla koşar ve analist bunu bilmez.
- Güven: yüksek (kodu baştan sona izledim)
- Onarım kapsamı: mevcut YAML'ı okuyup yalnız whitelist anahtarları güncelle (`ui/server.py`; S). Kılavuzdaki "aynı dosya" cümlesi düzeltilmeli.
- Nasıl sınanır: içinde `tools.ghidra_headless` ve `network.allow_reference_download` olan bir YAML'a `POST /api/settings` sonrası iki anahtarın durduğunu doğrulayan test.

## ARAYUZ-07 — Raporlarda hiç dolmayan sayaçlar: "Coverage N/A%", "Modules N/A/0", "Deobf Steps N/A/0"; JSON'da 0 olarak yazılıyor
- Önem: ORTA
- Tür: sahte/yanlış gösterim / tutarsızlık
- Yer: `karadul/reporting/html_report.py:308-320`, `karadul/reporting/markdown_report.py:271`, `:304`, `:306`, `karadul/core/output_formatter.py:1092-1096`, `karadul/core/report_generator.py:294-300`
- Etkin mi: evet
- Ne: reconstruct aşaması `coverage_percent` ve `modules_extracted`, deobfuscate aşaması `steps_completed` anahtarını ikili hedefte hiç üretmiyor. HTML "N/A" basarken Markdown aynı alanı "0" basıyor (iki rapor aynı koşu için farklı şey söylüyor); temiz çıktının `report.json`'u `statistics.coverage_percent: 0`, `modules_extracted: 0` yazıyor — "bilinmiyor" değil "sıfır". Markdown "Coverage: N/A%" gibi birimli bozuk metin üretiyor.
- Kanıt: 119 `report.html`: `Coverage N/A%` 119, `Modules N/A` 119, `Deobf Steps N/A` 119. `cat` `report.md`: "Steps completed: 0", "Modules extracted: 0", "Coverage: N/A%". `output_formatter.py:1094-1096`: `st.get("modules_extracted", 0)`, `st.get("coverage_percent", 0)`.
- Etki: Analist (ya da makine okuyan araç) "kapsama %0" sonucunu ölçüm sanabilir; iki rapor arasında çelişki güveni zedeler.
- Güven: kesin (gerçek raporlarda saydım)
- Onarım kapsamı: veri yoksa satırı hiç yazma; JSON'da `null` (`html_report.py`, `markdown_report.py`, `report_generator.py`, `output_formatter.py`; S).
- Nasıl sınanır: ikili hedefli bir koşunun üç raporunda "N/A" ve kaynağı olmayan 0 bulunmamalı.

## ARAYUZ-08 — Analistin açtığı temiz rapor (`<--output>/report.html`) paketleyici, anti-debug ve IOC bölümlerini hiç içermiyor
- Önem: YÜKSEK
- Tür: eksik özellik / tutarsızlık
- Yer: `karadul/core/report_generator.py:149-202` (bölüm listesi), karşılaştırma `karadul/reporting/html_report.py:175-178`
- Etkin mi: evet (`OutputFormatter._format_clean` → `ReportGenerator.generate_html`, `output_formatter.py:264-274`)
- Ne: İki ayrı HTML rapor üreticisi var. Çalışma alanındaki `reports/report.html` (reporting/html_report.py) "PAKETLİ BINARY" uyarısını, anti-debug bulgularını ve IOC bölümünü içeriyor; temiz çıktıdaki `report.html` (core/report_generator.py) bunların hiçbirini içermiyor. Temiz çıktının README'si de çalışma alanı raporlarına işaret etmiyor. Paketli bir ikilide analist temiz çıktıyı açınca yalnız açıcı stub'ın birkaç fonksiyonunu "SUCCESS" başlığıyla görür.
- Kanıt: `report_generator.py:164-189` bölüm sırası: header, target, stats, timeline, strategies, before/after, naming table, dependency graph, stage details — packer/anti_debug/ioc yok. Gerçek çıktı: `cat/out/report.html` başlıkları "Target Info, Statistics, Pipeline Timeline, Analysis Strategies, Before / After Comparison, Name Recovery (Top 30), Dependency Graph, Stage Details"; aynı koşunun `reports/report.html`'inde 16 ikilide "Anti-Debug Findings" var.
- Etki: Paketli/anti-debug'lı zararlıda temiz rapor uyarısız "başarılı" görünür (sessiz başarısızlık yasağına aykırı). Arayüzde paket uyarısı var; temiz rapor ile arayüz birbirini tutmuyor.
- Güven: yüksek (iki üreticinin bölüm listesini ve gerçek çıktıları karşılaştırdım; paketli ikiliyle denemedim)
- Onarım kapsamı: güvenlik bölümleri tek bir yardımcıya alınıp iki üreticide kullanılmalı ya da iki üretici birleştirilmeli (M).
- Nasıl sınanır: `static/packer_fingerprints.json`'u dolu sentetik bir çalışma alanında temiz `report.html`'de paket uyarısının çıktığını gösteren test.

## ARAYUZ-09 — Aynı `--output` dizinine ikinci koşu eski dosyaları bırakıyor; "Names Recovered" eski kodla şişiyor
- Önem: ORTA
- Tür: hata
- Yer: `karadul/core/output_formatter.py:188-190`, `:441-459` (`_copy_project_tree`), `:811-835` (`_separate_candidates` diskteki `src/`'yi tarıyor), `:1237-1282` (README ağacı)
- Etkin mi: evet (`karadul analyze ... --output DIR` her koşuda; CLI dizin doluysa uyarmıyor, `cli.py:330-380`)
- Ne: Temiz çıktı yazımı hedef dizini boşaltmıyor; `_copy_project_tree` yalnız yeni projede adı geçen alt dizinleri silip yeniden kopyalıyor. Önceki koşudan kalan alt sistem dizinleri ve dosyalar yerinde kalıyor. Ad haritasının "uygulandı" denetimi diskteki bütün `src/`'yi taradığı için bayat koddaki bir tanım, yeni koşuda kodda olmayan bir adı "uygulanmış" sayıyor; README ağacı ve "Source Files" sayısı da bayat dosyaları sayıyor.
- Kanıt: geçici dizinde deneme (`_copy_project_tree` + `_scan_c_code` + `_candidate_reason`): yeni proje yalnız `subsystem_new/b.c` içerirken çıktı `['src/subsystem_new/b.c', 'src/subsystem_old/a.c']`; eski dosyadaki `eski_ad` tanımı nedeniyle `_candidate_reason('FUN_00200000','eski_ad',…)` → `None` (uygulandı).
- Etki: Aynı hedefi ayarı değiştirip yeniden analiz eden analist iki koşunun karışımını görür; ad sayacı gerçekte olmayan adları içerir.
- Güven: kesin (deneyle gösterdim)
- Onarım kapsamı: `_format_clean` başında hedef dizini temizle ya da boş değilse reddet/uyar (`output_formatter.py`, `cli.py`; S; tehlike: kullanıcının yanlış dizini vermesi — silmeden önce dizinin önceki bir Karadul çıktısı olduğu denetlenmeli).
- Nasıl sınanır: aynı dizine iki farklı proje ağacıyla iki kez yazınca yalnız ikincinin dosyaları kalmalı.

## ARAYUZ-10 — Analiz ekranında iptal yok; iş kaybolunca ya da sunucu hata verince ekran sonsuza dek "çalışıyor…" kalıyor
- Önem: ORTA
- Tür: eksik özellik / asılma
- Yer: `ui/index.html:747-750` (`pollProgress`), `:744`, `:865` (`newAnalysis`), `:509-510`; sunucu `ui/server.py:1790-1791`, `:1934-1938`
- Etkin mi: evet
- Ne: (1) `pollProgress` istek hatasında (`catch(e){ return; }`) ve sunucu `{"error":"job yok"}` ya da 403 döndürdüğünde (`if(p.error){ return; }`) hiçbir şey göstermeden dönüyor; `setInterval` her 1,2 sn'de yoklamayı sürdürüyor, radar animasyonu ve "çalışıyor…" metni kalıyor. Zaman aşımı yok. (2) Sunucuda iptal ucu yok (`/api/cancel` benzeri bir uç tanımlı değil), analiz ekranında geri/iptal düğmesi yalnız hata sonrası görünüyor. (3) Sayfa yenilenirse ya da sonuç ekranından "+ YENİ" ile çıkılırsa süren işin kimliği tutulmuyor; yeni analiz "zaten bir analiz sürüyor — bitmesini bekle" ile reddediliyor ama süren işe yeniden bağlanmanın yolu yok. Büyük ikilide (tmux 726 sn, redis-check-aof 1 831 sn ölçüldü) analist yarım saat kör bekler ya da uygulamayı kapatmak zorunda kalır.
- Kanıt: `index.html:749-750`: `try{ p=await (await fetch('/api/progress?job='+job)).json(); }catch(e){ return; }` / `if(p.error){ return; }`. `server.py:1790-1791`: `if _running_job(): return {"error": "zaten bir analiz sürüyor — bitmesini bekle"}`; `do_POST` uç listesi: analyze, rename, settings, open-fda-settings, update-download (iptal yok).
- Etki: Takılan Ghidra koşusunda arayüz "çalışıyor" görünür; analist ne olduğunu bilemez.
- Güven: yüksek (kodu izledim; sunucuyu öldürerek denemedim)
- Onarım kapsamı: `pollProgress`'te hata sayacı + görünür hata; sunucuda `POST /api/cancel` (killpg) ve `GET /api/jobs/current`; arayüzde iptal düğmesi (`ui/server.py`, `ui/index.html`; M).
- Nasıl sınanır: bilinmeyen iş kimliğiyle yoklamada arayüzün hata göstermesi; iptal sonrası Ghidra JVM'inin süreç tablosunda kalmaması.

## ARAYUZ-11 — Sonuç ekranı kısmi başarısızlığı gizliyor; desteklenmeyen hedefte "pipeline hata verdi" diye yanlış ileti veriyor
- Önem: ORTA
- Tür: sessiz hata / yanlış gösterim
- Yer: `ui/index.html:752-764`; `ui/server.py:126-135` (`find_ws`), `:285-294` (`build_model`), `:1958-1967`
- Etkin mi: evet
- Ne: (1) İş bittiğinde `workspace` bulunursa arayüz `rc`'ye ve aşama durumlarına bakmadan 0,6–2,4 sn sonra sonuç ekranına geçiyor; "static FAIL" ya da "reconstruct FAIL" işaretleri ekrandan kalkıyor, sonuç ekranında hiçbir başarısızlık izi yok. (2) Arayüz yalnız `reconstructed/src/naming_map.json` VE `FUN_*.c` dosyası içeren bir decompile dizini varsa model kurabiliyor. Sembolleri duran (stripped olmayan) bir ikilide Ghidra fonksiyonları adlarıyla yazar, `FUN_*.c` olmaz → `build_model` None → "sonuç modeli yüklenemedi". JS/Java/.NET/Python hedeflerinde `reconstructed/src/naming_map.json` yok → `workspace` None → "analiz başarısız (pipeline hata verdi)" — oysa boru hattı başarılı olabilir. (3) Model yalnız `FUN_*.c` dosyalarını sayıyor: `cat`'te arayüz "toplam 101" gösterirken rapor "Functions 296" diyor; Ghidra'nın adlandırdığı `entry`, `_DT_INIT` gibi fonksiyonlar arayüzde hiç açılamıyor.
- Kanıt: `server.py:131`: `if d.is_dir() and next(d.glob("FUN_*.c"), None)`; `index.html:762-763`: `analyzeFail('analiz başarısız (pipeline hata verdi)')`. `cat` koşusunda `deobfuscated/decompiled`: 296 dosya, 101'i `FUN_`; `build_model` taklidi `total 101`.
- Etki: Analist yarım kalmış analizi tam sanır; ya da başarılı bir analizi "pipeline hatası" sanıp yeniden koşar. Giriş metni "Bir stripped ELF seç" diyor ama README ve kılavuz Mach-O/PE/JS/APK/.NET/Python desteği vaat ediyor.
- Güven: yüksek (1 ve 3 için kodu ve gerçek koşuyu izledim; 2'yi stripped olmayan ikiliyle koşarak denemedim — şüphe payı orada)
- Onarım kapsamı: sonuç başlığına başarısız/atlanan aşama şeridi; desteklenmeyen hedef için ayrı ileti; model Ghidra adlı fonksiyonları da düğüm olarak almalı (`ui/server.py`, `ui/index.html`; M).
- Nasıl sınanır: reconstruct'u FAIL olan sentetik çalışma alanında sonuç ekranında uyarı; FUN_ dosyası olmayan çalışma alanında "pipeline hata verdi" yerine doğru ileti.

## ARAYUZ-12 — Fonksiyon listesi 600 satırda sessizce kesiliyor ve sayaç kesilmiş sayıyı "toplam" gibi gösteriyor
- Önem: ORTA
- Tür: yanlış gösterim
- Yer: `ui/index.html:868-886` (`buildList`), `:535`, `:820`
- Etkin mi: evet
- Ne: `buildList` süzülen listeyi çıkış derecesine göre sıralayıp `.slice(0,600)` ile kesiyor, sonra `$('cnt').textContent=rows.length` yazıyor. `enterResult` önce `cnt`'ye gerçek toplamı yazıyor, hemen ardından `buildList` bunu 600 ile eziyor. Başlıkta "D: [SYMBOL.MAP] 600" görünür; 600'ün ötesi için "daha fazla" satırı yok. Mac tmux'ta 2 587 `FUN_` fonksiyonu var: düşük dereceli 1 987 fonksiyon (çoğu adsız yaprak fonksiyonlar) ancak arama ile bulunabilir, analist varlığından haberdar edilmez. Süzgeç çipleri doğru toplamı (`MODEL.unnamed`) gösterirken liste başlığı 600 gösteriyor; iki sayı çelişiyor.
- Kanıt: `index.html:871-872`: `.sort((a,b)=> b.out-a.out || b.in-a.in).slice(0,600);` `:885`: `$('cnt').textContent=rows.length;`
- Etki: Büyük ikilide analist listenin tamam olduğunu sanır; "İsimsiz" süzgecinde de yalnız ilk 600 görünür.
- Güven: kesin (kod)
- Onarım kapsamı: sayaçta "600 / N" yaz, sona "N-600 daha — aramayı daralt" satırı ekle ya da sanal kaydırma (`ui/index.html`; S).
- Nasıl sınanır: 1 000 fonksiyonlu sahte modelle başlıkta "600 / 1000" ve kesilme satırının görünmesi.

## ARAYUZ-13 — Arayüz her ad atanmış fonksiyonu "çözüldü" ve "RECONSTRUCTED" sayıyor; zayıf ve doğrulanmamış adlar dahil
- Önem: ORTA
- Tür: sahte/yanlış gösterim
- Yer: `ui/index.html:523-527`, `:537`, `:817-819`, `:1092-1097`, `:1099-1107`; `ui/server.py:138-143`, `:342-356`
- Etkin mi: evet
- Ne: Üst şeritteki "RECONSTRUCTED %" ve sol paneldeki "İSİMSİZ İŞ KUYRUĞU — X / Y çözüldü" sayacı `named + weak` toplamını kullanıyor. `named` = adı `FUN_` ile başlamayan ve `_<hex>` ile bitmeyen her ad; etiketine (kesin / doğrulandı / doğrulanmadı) bakılmıyor. `weak` (adres sonekli) adlar da "çözüldü" sayılıyor. Ölçülmüş yanlış ad oranı havuzda %29,7, makroda %52,8; "çözüldü" kelimesi ve yeşil "NAMED" rengi doğruluk ima ediyor. Etiket sistemi (ARAYUZ dışındaki iyi tasarım) listede rozetle var ama sayaçlara yansımıyor.
- Kanıt: `index.html:1094-1095`: `resolved=(MODEL.named||0)+(MODEL.weak||0); $('ivQTxt').textContent=resolved+' / '+total+' çözüldü';` `server.py:356`: `"recovered": n_named + n_weak`.
- Etki: Analist "%12 çözüldü"yü "%12'si doğru adlandı" diye okur; doğrulanmamış adlar da bu orana giriyor.
- Güven: yüksek
- Onarım kapsamı: sayaçlar etikete göre ayrılmalı ("kesin N · doğrulandı N · doğrulanmadı N · zayıf N"); "çözüldü" yerine "ad atandı" (`ui/index.html`, `ui/server.py`; S).
- Nasıl sınanır: etiketli sahte modelde sayaçların etiket dağılımını göstermesi; "çözüldü" metninin kalmaması.

## ARAYUZ-14 — Ad düzeltme: kalıcılık sessizce düşebiliyor, yanlış ikiliye bağlanabiliyor, çakışan ad engellenmiyor
- Önem: ORTA
- Tür: sessiz hata
- Yer: `ui/server.py:803-842` (`_do_rename`), `:413-450` (`_active_binary_hash`), `:400-410`; kılavuz `docs/kullanim_kilavuzu.md:84`
- Etkin mi: evet (`POST /api/rename`)
- Ne: (1) `overrides.set_name` yalnız `ValueError` için sarılı ve yutuluyor (`pass`); ikili özeti bulunamazsa (`bh` None) kalıcı kayıt hiç yazılmıyor. Her iki durumda uç `{"ok": true}` dönüyor, arayüz "manuel" rozeti basıyor; kılavuz "Ad kalıcıdır" diyor. `set_name`'in `OSError`'ı yakalanmıyor: `naming_map` zaten yazılmışken istek yanıtsız kopuyor, model önbelleği temizlenmiyor. (2) `clean/report.json` bulunamazsa (sunucu bir çalışma alanı argümanıyla açıldığında) özet `resolve_binary(_ws_binary_name(ws))` ile ADA göre aranıyor: `ls` adı `shutil.which("ls")` → `/bin/ls`'e çözülür ve düzeltme analiz edilen ikilinin değil sistemdeki aynı adlı dosyanın özetine kaydedilir. (3) Yeni adın başka bir fonksiyonun mevcut adıyla çakışması ya da C anahtar sözcüğü olması (`int`, `return`) denetlenmiyor; sonraki koşuda bu ad zorla uygulanıp çift tanım/derlenmez kod üretebilir.
- Kanıt: `server.py:834-839`: `bh = _active_binary_hash(ws)` / `if bh: try: overrides.set_name(...) except ValueError: pass`; `:431-432`: `bin_path = resolve_binary(_ws_binary_name(ws))`; `:810`: tek denetim `re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)`.
- Etki: Analistin emeği (elle verdiği adlar) haber verilmeden kaybolur ya da başka bir ikilinin kaydına karışır.
- Güven: yüksek (1, 3 kod); (2) için şüphe: yalnız sunucu argümanla açıldığında ve `clean/` yoksa olur.
- Onarım kapsamı: override yazılamazsa 500 + açık ileti; özet yalnız çalışma alanındaki `raw/<ikili>` ya da `reports/report.json`'dan; çakışma/anahtar sözcük denetimi (`ui/server.py`, `karadul/core/overrides.py`; S).
- Nasıl sınanır: `overrides_dir` yazılamazken `POST /api/rename` hata dönmeli; aynı adı ikinci fonksiyona vermek reddedilmeli.

## ARAYUZ-15 — Teşhis kartı analisti var olmayan bir ayara yönlendiriyor
- Önem: DÜŞÜK
- Tür: yanlış gösterim
- Yer: `ui/server.py:749-752`
- Etkin mi: evet (adsız fonksiyonda güçlü BSim adayı varsa)
- Ne: Teşhis metni "İmzalar → BSim'i füzyona açarsan otomatik isimlenebilir" diyor. Arayüzde "İmzalar" adlı bir bölüm ya da BSim düğmesi yok (ayar panelinde yalnız 7 düğme + imza yolları); sunucunun yazdığı YAML'da da BSim anahtarı yok. Ayrıca "otomatik isimlenebilir" iddiası ölçülmemiş (B-B9: BSim 78 ikilide yedeğe düşüyor, B-D2: adaylar ortak depodan sızıyor olabilir).
- Kanıt: `server.py:751-752`: `"modunda kapalı. İmzalar → BSim'i füzyona açarsan otomatik isimlenebilir."`; `grep -n "BSim\|İmzalar" ui/index.html` → yalnız teşhis etiketleri.
- Etki: Analist olmayan bir denetimi arar; açılabilseydi ölçülmemiş bir kanalı açmaya teşvik edilmiş olurdu.
- Güven: kesin
- Onarım kapsamı: metni olgusal bırak ("BSim adayı: X, %Y benzer; ad kanalına bağlı değil") (`ui/server.py`; S).
- Nasıl sınanır: teşhis metninde arayüzde karşılığı olmayan yönlendirme kalmaması.

## ARAYUZ-16 — Uygulama her açılışta GitHub'a "güncelleme var mı" isteği atıyor; "varsayılan çevrimdışı" sözüyle çelişiyor
- Önem: DÜŞÜK
- Tür: güvenlik (operasyonel gizlilik) / tutarsızlık
- Yer: `ui/app_window.py:509-514`, `:189-210`; `ui/server.py:1145-1148`, `:1323-1330`; arayüz metni `ui/index.html:618`
- Etkin mi: evet (her pencere açılışında, 24 saatte bir önbellekle)
- Ne: Pencere açılır açılmaz `_check_update_async` sunucunun `/api/update-check` ucunu çağırıyor; o da `User-Agent: black-widow-update-check` ile `github.com/berketez/black-widow/releases/latest/download/appcast.json`'a gidiyor. Kapatacak ayar yok. Ağ düğmesinin açıklaması "varsayılan çevrimdışı" diyor. Zararlı yazılım analistleri çoğu zaman izole ağda ya da araç kullanımını sızdırmamak isteyerek çalışır; ayrıca B-F1'e göre GitHub'da sürüm yok, istek her seferinde boşa gidiyor.
- Kanıt: `app_window.py:512`: `threading.Thread(target=_check_update_async, daemon=True).start()`; `server.py:1324-1330`: `urllib.request.Request(_UPDATE_MANIFEST_URL, headers={... "User-Agent": "black-widow-update-check"})`.
- Etki: Araç kullanımı dışarıya duyurulur; izole ortamda gereksiz bağlantı denemesi.
- Güven: kesin (kod)
- Onarım kapsamı: güncelleme denetimi ayara bağlanmalı, öntanımlı kapalı ya da ilk açılışta sorulmalı (`ui/app_window.py`, `ui/server.py`, `ui/index.html`; S).
- Nasıl sınanır: ayar kapalıyken açılışta dışarıya bağlantı olmadığını gösteren test (urlopen taklidi çağrılmamalı).

## ARAYUZ-17 — SARIF raporu kripto ve ad güvenilirliği bulgularını hiç üretmiyor, YARA isabetlerini yanlış kurala ve yanlış paket iddiasıyla basıyor
- Önem: YÜKSEK
- Tür: hiç çalışmayan özellik / sahte gösterim
- Yer: `karadul/reporting/sarif_report.py:295-342` (KRDL001), `:344-422` (YARA → KRDL003/4/5), `:424-481` (KRDL002); veri üreticileri `karadul/pipeline/steps/algorithm_id.py:82`, `karadul/stages.py:315-322` (YARA `detected_tech`)
- Etkin mi: evet (`ReportStage`, `stages.py:5596-5600`; 119/119 koşuda `report.sarif.json` var)
- Ne: (1) KRDL001 (kripto) `static` aşamasının `algorithms_detected` LİSTESİNİ okuyor; algoritma tespiti `reconstruct` aşamasına bir SAYI yazıyor. OpenSSL'de `algorithms.json` 72 algoritma içerirken SARIF'te 0 KRDL001 var. (2) KRDL002 (ad güvenilirliği düşük) `coverage_percent` (öntanımlı 100) ve `avg_naming_confidence` (öntanımlı 1.0) anahtarlarına bakıyor; ikisi de hiç üretilmiyor → uyarı hiçbir koşuda çıkmıyor; SARIF tüketicisine "adlar güvenilir" sessizliği gidiyor (ölçülmüş yanlış oran %29,7). (3) YARA isabetleri `detected_tech`'e `"MPRESS_Packed (packer,mpress)"` biçiminde DİZGİ olarak yazılıyor; SARIF dizgi dalında `tech_type="unknown"` atıyor, böylece paketleyici isabeti KRDL004 yerine KRDL003'e düşüyor ve mesaj "(…) (unknown)" oluyor. Bu isabetlerin bir kısmı açıkça yanlış: GNU `ls`, `sort`, `dircolors`, `dir`, `vdir`, sqlite3, openssl, zstd, htop gibi paketsiz ikililerde "MPRESS_Packed" ve "Delphi_Compiler" bildiriliyor. HTML/Markdown raporu ve arayüz (packer_fingerprints'e bakar) aynı ikiliye "paket yok" diyor: üç çıktı birbirini tutmuyor.
- Kanıt: 119 SARIF: 88'i sonuçsuz; tüm sonuçlar KRDL003 (81). En sık iletiler: "AntiDebug_Timing (antidebug,timing) (unknown)" 23, "Stack_String_Construction" 19, "MPRESS_Packed (packer,mpress) (unknown)" 13, "Delphi_Compiler (compiler,delphi) (unknown)" 2. MPRESS/Delphi bildirilen ikililer: debian/coreutils/{sort,dircolors,dir,ls,vdir}, debian/redis-tools/{redis-check-rdb,redis-check-aof}, debian/htop, debian/sqlite3, debian/zstd/{pzstd,zstd}, debian/openssl, mac/htop.
- Etki: SARIF'i CI/SIEM'e bağlayan güvenlik ekibi zararsız GNU araçları için "paketli" uyarısı alır, gerçek kripto kullanımını hiç görmez.
- Güven: kesin (gerçek SARIF dosyalarını saydım, okuyucu ve yazıcı anahtarları kodda karşılaştırdım)
- Onarım kapsamı: `sarif_report.py` okuma yolları (reconstruct'tan ve `reconstructed/algorithms.json`'dan), YARA kaydının sözlük olarak taşınması (`stages.py`/ilgili adım), ad güvenilirliği için ölçülmüş etiket dağılımı (S-M). YARA kurallarının yanlış pozitifi ayrı kulvarın işi.
- Nasıl sınanır: OpenSSL koşusunda KRDL001 sonuçlarının çıkması; paketsiz ikilide KRDL004 olmaması; MPRESS kuralı yalnız gerçek MPRESS örneğinde.

## ARAYUZ-18 — Çıktıdaki `types.h`'de kurtarılan yapıların 1 168'i kendi açıklamasındaki ofsetlerle çelişen, üst üste binen alanlar taşıyor
- Önem: ORTA
- Tür: yanlış gösterim (başlık ↔ tanım uyuşmazlığı)
- Yer: çıktı `<--output>/src/include/types.h` (`karadul/reconstruction/c_project_builder.py:1384-1437` `_build_types_h` mevcut `typed/types.h`'yi kopyalıyor); kök neden yapı kurtarma adımında (bu kulvar dışı)
- Etkin mi: evet (117/118 ikilinin çıktısında)
- Ne: `recovered_struct_*` tanımlarında alanların yanına yazılan ofset açıklaması (`/* 0x0A */`, `/* 0x0C */`) alan boyutlarıyla çelişiyor: 8 baytlık `undefined8 field_0x0a` 0x0A'da başlayıp 0x12'de biterken bir sonraki alan 0x0C'de gösteriliyor. C derleyicisi bu tanımı hizalayıp bambaşka ofsetlere koyuyor; "Size: 0x18" açıklaması da gerçek `sizeof` ile tutmuyor. Her alanın yanında "confidence: 0.80" yazıyor.
- Kanıt: `cat/out/src/include/types.h:574-579`: `struct recovered_struct_001 { char padding_0x00[10]; /* 0x00 */ … undefined8 field_0x0a; /* 0x0A */ … undefined8 field_0x0c; /* 0x0C */ … char padding_0x14[4]; /* 0x14 */ };` Bütün koşularda tarama (alan boyutu + açıklama ofseti): 118 `types.h`, 7 183 `recovered_struct`, 1 168'inde üst üste binen alan; 117 ikili etkilenmiş.
- Etki: Analist yapıyı bellek düzeni sanıp alan erişimlerini yanlış ofsete eşler; "confidence 0.80" yanlışı güvenilir gösteriyor.
- Güven: kesin (sayım betiğiyle; boyut tablosu temel tiplerle sınırlı, bilinmeyen tipli yapılar sayılmadı → gerçek sayı daha yüksek olabilir)
- Onarım kapsamı: yapı kurtarma çıktısında çakışan alanların birleştirilmesi ya da `union` olarak yazılması; rapor/çıktı tarafında en azından çakışan yapıya uyarı yorumu (M; kök onarım başka kulvarda).
- Nasıl sınanır: çıktıdaki her `recovered_struct` için açıklama ofsetleri + boyutlar çakışmasız olmalı; `offsetof` ile açıklama aynı olmalı (derlenebilir başlıkta `_Static_assert`).

## ARAYUZ-19 — Vizyona göre arayüzde eksik olanlar (eksik özellik; 6 kalem)
- Önem: ORTA
- Tür: eksik özellik
- Yer: `ui/index.html`, `ui/server.py`; hazır ama kullanılmayan parçalar aşağıda
- Etkin mi: — 
- Ne:
  1. **KaradulLM sohbeti, yan panel ve ajanı canlı gösteren görünüm yok.** Sunucuda `/api/lm/*` ucu yok, sayfada sohbet ya da ajan izi yok; `karadul/lm/backend.py:54` tasarımdaki `/api/lm/status`'a atıf yapıyor ama uç yazılmamış. Berke'nin onayladığı "widow örümceği gerçek araç çağrısında çağrı grafiğinde yürür" görünümünün hiçbir parçası yok (B-E1'in arayüz yüzü).
  2. **Fonksiyonlar arası ilişki tek adım.** Harita yalnız seçili fonksiyonun doğrudan çağırdıklarını/çağıranlarını (taraf başına en çok 42) gösteriyor; çağrı yolu (A'dan B'ye nasıl gelinir), veri/dizgi xref'i, alt sistem görünümü yok. `out/src/analysis/xref_index.md`, `subsystem_map.md`, `call_graph.dot` diskte üretiliyor ama arayüz bunları kullanmıyor.
  3. **Ad düzeltme yalnız fonksiyon adı için ve yalnız arayüz katmanında.** `karadul/core/overrides.py:197` `set_param` (parametre adı) hazır, sunucu `DAT_` adresini de kabul ediyor (`server.py:808`), ama arayüzde veri/parametre/yerel değişken düzeltme yok. Düzeltme temiz çıktının `src/`'sine, `naming_map.json`'una ve raporlara yansımıyor (yalnız `reconstructed/src/naming_map.json` ve kalıcı depo güncelleniyor); geri alma/silme (`overrides.remove`, `:213`) ve dışa aktarma yok.
  4. **Arama/süzme sığ.** Arama yalnız ad/adres alt dizgisi; decompile metninde, dizgi sabitlerinde, çağrılan ithal adında arama yok. Etiket (kesin / doğrulandı / doğrulanmadı) varken etikete göre süzgeç yok.
  5. **Adın kanıtı kısmen.** Kanıt kartı köken, etiket, puan, kanal ve kısa kanıtı gösteriyor (iyi); ama yalnız temiz haritadaki kayıt tutarsa — bayat kayıtta sadece "elle" yazıyor; adayların (uygulanmamış `candidates`) neden elendiği (`reason`) arayüzde hiç görünmüyor, oysa `clean/naming_map.json` bunu taşıyor.
  6. **Sunucuda hazır ama kullanılmayan uç:** `GET /api/binaries` (`server.py:1695-1720`, `:2072-2073`) — arayüz "HIZLI" çiplerini sabit diziden çiziyor (`index.html:718`).
- Kanıt: `grep -n "api/lm\|chat\|sohbet" ui/server.py ui/index.html` → boş; `grep -rn "set_param\|overrides.remove" ui karadul --include=*.py` (overrides.py dışında) → boş; `grep -n "api/binaries" ui/index.html` → boş.
- Etki: Arayüz bugün "tek fonksiyon + komşuları" görüntüleyicisi; vizyondaki analist iş akışının (ajanla birlikte inceleme, ilişki izleme, kalıcı düzeltme) çoğu yok.
- Güven: yüksek (grep ve okuma)
- Onarım kapsamı: L (her kalem ayrı iş; 1 en büyüğü).
- Nasıl sınanır: kalem başına kabul ölçütü ayrıca yazılmalı; sahte animasyon yasağı gereği widow hareketi yalnız gerçek araç çağrısı olayından beslenmeli (test: olay yokken hareket yok).

## Küçükler
- `ui/index.html:739`: analiz ekranı her hedefin adına `.stripped` ekliyor (`j.binary+'.stripped'`); `/bin/ls` için "ls.stripped" yazar — sahte ayrıntı.
- `ui/index.html:718`: "HIZLI" çipleri sabit `['expr','cat','ls','sort','wc','tr','date']`; `~/coreutils_gt` yoksa `resolve_binary` bunları `shutil.which` ile macOS sistem ikililerine çözer (`server.py:1745-1758`) — analist GNU coreutils sanır. `server.py:1711`, `:1746` kişisel yol `~/coreutils_gt`.
- `ui/server.py:1790-1794`: `_running_job()` denetimi ile işin `_JOBS`'a eklenmesi arasında kilit yok; eşzamanlı iki `POST /api/analyze` iki analizi birden başlatabilir (`/api/progress` biten işi `WS` olarak etkinleştirdiği için hangisinin görüneceği yarışa kalır).
- `ui/server.py:1835`, `:1968-1975`: iş günlüğü dosya tanıtıcısı yalnız `/api/progress` biten işi yoklayınca kapanıyor; arayüz ayrılırsa tanıtıcı süreç boyunca açık kalıyor.
- `ui/server.py:2074-2080`: `/api/progress` eski bir işin kimliğiyle yoklanınca o işin çalışma alanı yeniden etkin oluyor (`activate_workspace`); başka sekmede açık sonuç sessizce değişir.
- `ui/server.py:1937-1942` + `:1981`: `_job_progress` her 1,2 sn'de bütün `analyze.log`'u okuyup üzerinde dört düzenli ifade koşturuyor; `--verbose` ile büyük ikilide günlük büyüdükçe yoklama pahalılaşır (ölçmedim).
- `ui/index.html:1565-1592`: `bwPollDownload` köprü çağrısı başarısız olunca durum `idle` kalır ve 1,2 sn'de bir sonsuza dek yoklar; ekranda "0%" kalır.
- `ui/index.html:1021-1022` (`highlight`): dizgi içindeki `//` (ör. `"http://..."`) yorum düzenli ifadesine yakalanıyor; satırın geri kalanı yorum renginde ve iç içe `<span>` bozuk çıkıyor (görünüm hatası; XSS değil, `<`/`>` önceden kaçırılıyor).
- `karadul/core/output_formatter.py:1288-1305` (`_clean_c_source`, yalnız yedek yolda): `"undefined"` sözcük sınırı olmadan değiştiriliyor; denemede `undefined3 x; puts("undefined symbol"); int undefined_behavior;` → `uint8_t3 x; puts("uint8_t symbol"); int uint8_t_behavior;` — dizgi sabitini bile bozuyor. 119 koşuda yedek yol hiç kullanılmadı.
- `karadul/core/output_formatter.py:359-393` (yedek yol): `rglob("*.c")` alt dizinleri düzleştirip `modules/<ad>`'a yazıyor; aynı adlı iki dosya birbirini sessizce eziyor, birden çok `main.c` varsa yalnız sonuncusu kalıyor. `category` hesaplanıp kullanılmıyor (`:388`).
- `karadul/reconstruction/c_project_builder.py:1399`: `typedef void* undefined;` — Ghidra'nın `undefined`'ı 1 bayt; çıktıdaki tip boyutu yanlış, `output_formatter._clean_c_source` aynı tipi `uint8_t` yapıyor (iki yer birbirini tutmuyor).
- `karadul/core/output_formatter.py:982-1040`: `dependency_graph.json` düğüm kimliği çıplak adres; ne Ghidra adı ne kurtarılan ad var (Ghidra grafiği `from_name`/`to_name` taşıdığı hâlde).
- `karadul/core/report_generator.py:523-617`: "Before / After" örnekleri ilk farklı dosyalardan seçiliyor; `cat`'te 5 örneğin ilki yalnız `undefined *` → `uint64_t *` değişen bir PLT kaydı — gösterim değeri yok.
- `karadul/reporting/markdown_report.py` / `html_report.py`: "Strings found 193" ile aynı raporun zaman çizelgesindeki `string_count=283` farklı şeyleri sayıyor, etiket ayrımı yok.
- `ui/server.py:1027-1030` dışında `ui/index.html:504`, `:576` "LLM'siz çekirdek" ifadesi doğru; ama `index.html:614` "daha doğru tip çıkarımı" ölçülmemiş iddia (B-C3: CFG-iso 0/14 376, füzyon 0/3 106).
- `ui/server.py:853-855` yorumu eskimiş (network bölümü artık yükleniyor, `config.py:1048`).
- `packaging/macos/build_mac_app.sh:89`: Python çalışma zamanı öntanımlı olarak başka bir projenin dosyasından (`$HOME/HRMA/packaging/runtime/pbs-mac.tar.gz`) alınıyor; özet sabit, ortam değişkeniyle ezilebilir, ama Karadul deposu kendi başına paketlenemiyor.
- `packaging/macos/app/Info.plist:17-22`: yedek sürüm değerleri 1.21.1 (betik PlistBuddy ile 1.23.1'e eziyor; betiksiz okunursa eski).
- `docs/kullanim_kilavuzu.md:85`: "Komut satırındaki `karadul config` ile aynı dosyayı yazar" — yalnız cwd = veri kökü olduğunda doğru (`cli.py:2054` cwd'yi, paketli arayüz `KARADUL_DATA_DIR`'i kullanır).
- Arayüz XSS denetimi temiz: ikiliden gelen ad, dizgi, kod, paketleyici adı, teşhis sinyalleri `esc()` (5 karakter, nitelik bağlamında da güvenli) ya da `textContent` ile basılıyor; `highlight` kodu önce kaçırıyor; güncelleme sürümü `esc` ile. Jeton/Host/Origin denetimi bütün uçlarda (`do_GET` başında, `do_POST` başında); `/api/ping` jetonu jetonsuz döndürüyor ama Host/Origin denetimi tarayıcıdan okunmasını engelliyor. Yol geçişi yok (adres düzenli ifadeyle sınırlı).

## Bilinenlerin durumu
| Kalem | Durum | Kanıt |
|---|---|---|
| B-B5 README yapısı diskle tutmuyor | kapanmış (kod) / kısmen | `output_formatter.py:1175-1179`, `:1237-1282` ağacı diskten kuruyor; `cat/out/README.md` ağacı diskle aynı. Kalan: aynı `--output`'a ikinci koşuda bayat dosyaları da listeliyor (ARAYUZ-09). |
| B-B6 IOC bölümü `static/signature_matches.json` okuyor | duruyor + genişledi | `html_report.py:570`, `markdown_report.py:708`; dosya yalnız `reconstructed/`'da (119/119). Yol düzeltilse bile `family/tier/category` alanları kayıtta yok (ARAYUZ-02). |
| B-B7 "NSA-grade… 300+ rules", "Source Matching… names recovered" | duruyor | `report_generator.py:438-443` (ikili hedefte de `variables_renamed` ile tetikleniyor; 119/119 `out/report.html`'de var), `:459-464`. |
| B-B8 yedek yolda `types.h` iki kez | duruyor (yalnız yedek yol) | `output_formatter.py:395-407`: `source_dir`'deki `types.h` önce `types/`'a yazılıyor, sonra `reconstructed/types.h` üstüne yazıyor. 119 koşuda yedek yol kullanılmadı. |
| B-B10 `app_wrapper` "eşleşecek imza yok" | duruyor | `server.py:754-757` gerekçe metni koşulsuz; `no_candidate` (`:715`) False iken de "eşleşecek imza yok" yazıyor. |
| B-E1 KaradulLM arayüze bağlı değil | duruyor | `server.py`/`index.html`'de `/api/lm` ya da sohbet yok (ARAYUZ-19 madde 1). |
| B-E6 "Yeniden hesapla" düğmesi süs olur | konu dışı kaldı | Arayüzde böyle bir düğme bugün yok (`grep -i "yeniden hesapla\|recompute" ui/index.html` boş). |
| B-E7 fonksiyon kartı önerisi | kısmen | "İNCELE · KANIT" kartı köken/etiket/puan/kanal/kanıt, dizgiler, çağrı bağlamı ve teşhis gösteriyor; önerinin §5.1 ayrıntısıyla karşılaştırmadım. Aday gerekçeleri (`candidates.reason`) yok. |
| B-F1 lisans çelişkisi | kapanmış | `LICENSE` MIT, `pyproject.toml:11,29` MIT, `README.md:200` MIT, `Info.plist:25` "MIT Lisansı". |
| B-F1 en düşük macOS (stub minos) | duruyor | `build_mac_app.sh:241`: `clang -arch arm64 -O2 -o … bw_stub.c` — `-mmacosx-version-min` yok; `Info.plist:28` 12.0 diyor. |
| B-F1 GitHub'da sürüm yok / notarization yok | doğrulayamadım (ağa çıkmadım) | Güncelleme denetimi bu yüzden her açılışta boşa gidiyor (ARAYUZ-16). |
| B-F2 kurulu `.app` eski | durum değişti | `/Applications` ve `~/Applications` altında Black Widow bulunamadı (kurulu uygulama yok). |
| B-F2 `vendor/pycdc` pakete girmiyor | kapanmış | `build_mac_app.sh:201-213`: `--full`'da pycdc yoksa derleme duruyor; `vendor/pycdc/{pycdc,pycdas}` mevcut. |

## Bakamadıklarım
- `karadul/reconstruction/c_project_builder.py` (1 833 satır) yalnız dosya adı/`types.h` kısmına baktım; harf duyarsız dosya adı çakışması için `_FileLedger` (`:424-450`, casefold) ve `_assign_file_stems` (`:1056-1100`) yeni yazılmış görünüyor, derinlemesine sınamadım. Yerleşim (`enable_address_placement`, öntanımlı kapalı) yoluna bakmadım.
- `karadul/core/hardening.py` (190 satır) okumadım.
- `karadul/reporting/json_report.py` yalnız gerçek çıktıdaki `summary` üzerinden baktım (`coverage_percent: 0`, `deobfuscation_steps: "N/A"`, `total_modules: 0` — ARAYUZ-07 ile aynı sınıf).
- `report_generator.py`'nin bağımlılık grafiği SVG'si (`:841-946`) ve gömülü JS'i (`_JS`) okumadım.
- `ui/app_window.py`'nin menü yaması (`_patch_app_menu`) ve `packaging/macos/build_dmg.sh`, `bw_launch.sh`, `first_launch.command`, `protect_modules.py`, `encrypt_strings.py` okumadım.
- Arayüzü gerçek tarayıcıda/WKWebView'da açıp tıklamadım; 10 000+ fonksiyonlu gerçek bir modelle başarım ölçmedim (tmux 2 587 `FUN_` en büyüğüydü).
- Stripped olmayan ikili ile ve JS/APK/.NET/Python hedefleriyle arayüz akışını koşmadım (ARAYUZ-11 madde 2 koddan çıkarım).
- `CHANGELOG.md`'nin içeriğini sürüm başlığı dışında denetlemedim; sürüm 1.23.1 pyproject, `__init__`, CHANGELOG başlığında aynı.

## KULVAR BİTTİ
