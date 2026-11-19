# Paket: ÖLÇEK — birkaç GB'lık yazılımda çalışabilmek (E1, E3, E4, D1, BICIM-09) — plan paketi

Opus mimari / plan paketi. Kod yazmıyorsun; ölçüyor, okuyor ve uygulanabilir plan yazıyorsun. Önce `ORTAK_BRIF.md` ("yasak cevap / aykırı öncül" sana uygulanmaz), sonra `KARARLAR.md`.

Dizinlerin: `docs/arge/2026-11-19_mythos/olcek/` (belgeler), `scripts/arge/olcek/` (ölçüm betikleri), `~/karadul_olcum/runs/arge-2026-11-19/olcek/` (veri).

## Gereksinim (Berke, 2026-11-19)

"Sadece 50 MB'de de olmayacak; birkaç GB'lık yazılımlarda da çalışabilmesi lazım."

## Bugün bilinenler (ana oturum doğruladı)

- Gösteri koşusu: Ollama.app ana ikilisinin 26,6 MB'lık arm64 dilimi. İlk denemede Ghidra'nın "Objective-C Message Analyzer" çözümleyicisi tek fonksiyonda 22 dk döndü, koşu durduruldu; çözümleyici kapalı ikinci koşu 20. dakikasında hâlâ sürüyordu (`~/karadul_olcum/runs/gosteri-2026-11-19/ollama/`; `CIKIS` dosyası oluşunca bitmiş demektir). Ayrıntı `docs/arge/2026-11-19_yayin/YAYIN_KAPISI.md` §5.
- `AnalysisConfig.max_file_size_mb = 500` tanımlı ama `karadul/` içinde okuyan kod yok (grep ile; sen de doğrula).
- `.app` paketinde her Mach-O ve her çerçeve ikilisi bileşen listesine giriyor ve sırayla, süre sınırı olmadan Ghidra'ya veriliyor (`karadul/core/target.py:240-270`; BICIM-09, `docs/arge/2026-11-19_yayin/denetim_B.md`).
- Ghidra yığını RAM'in %40'ı (`karadul/config.py` `GHIDRA_HEAP_MB`; bu makinede 36 GB). Otomatik analiz süre sınırı 7 200 sn, büyük ikilide × 4 (`large_binary_timeout_multiplier`).
- Ghidra projesi koşudan sonra siliniyor (B-C4); aşama çıktıları için sha256 anahtarlı önbellek yok (liste E3).
- `decompiled.json` 500 fonksiyonla sınırlı, kayıtlı; tam liste `pcode.jsonl`'de (P16a).
- Taban koşusu (119 ikili, hepsi küçük): ikili başına medyan 80,9 sn; Mac tmux 412 sn (yük altında; `docs/arge/2026-11-19_birlesik_olcum/sonuc.md` §9).

## Kalemler (hepsi)

1. **Büyük yazılım neye benzer?** Makinedeki birkaç GB'lık kurulumların envanteri: çalıştırılabilir dosya sayısı, boyut dağılımı, tür (Mach-O çalıştırılabilir / dylib / çerçeve / evrensel dilim), aynı dosyanın yinelenmesi (sha256), bilinen üçüncü taraf bileşen payı (Electron, Chromium, Qt, LLVM vb. dosya adından ve yolundan). **Yalnız üst veri** (yol, boyut, tür, sha256): kapalı kaynak uygulamaların içeriğini analiz etme, dizgi dökme. Açık kaynak örnek: `/opt/homebrew/Cellar/llvm/` (birkaç GB, yüzlerce ikili). En az 5 kurulum; sonuç tablo.
2. **Bugünkü akış nerede kırılır?** Koddan oku (dosya:satır): büyük tek ikili ve çok bileşenli paket için sıra, eşzamanlılık, süre sınırları, bellek (Ghidra yığını, Python tarafında belleğe alınan JSON'lar), disk (çalışma alanı boyutu), yeniden başlatılabilirlik, ilerleme bildirimi, kısmi sonuç. Her kırılma noktası için: ne olur, kanıt.
3. **Ölçekleme verisi.** Var olan koşulardan (yeni Ghidra koşusu yok): 119 ikilinin künyesinden süre ↔ boyut / fonksiyon sayısı; çalışma alanı diski ↔ fonksiyon sayısı; gösteri koşusu bittiyse aşama kırılımı, tepe bellek, disk. Eğriyi uydur, belirsizliğiyle yaz; 100 MB, 1 GB, 5 GB için dış değerlemeyi **tahmin** etiketiyle ve aralığıyla ver. Hangi aşama doğrusal üstü büyüyor?
4. **Tasarım seçenekleri** (her biri için: ne kazandırır, neye mal olur, hangi dosyalara değer, nasıl ölçülür):
   - paket düzeyi yönetici: envanter → ön eleme → öncelik → bileşen başına bütçe → yeniden başlatılabilir kuyruk;
   - bilinen bileşeni atlama (dosya sha256'sı ya da kitaplık kimliğiyle; KİMLİK hattı ve liste C5 ile bağ) ve yinelenen dosyayı bir kez analiz;
   - sha256 anahtarlı önbellek (Ghidra projesi ve aşama çıktıları; disk maliyeti);
   - tembel derinlik: önce ucuz katman (içe aktarımlar, dizgiler, üst veri, fonksiyon listesi), decompile ve pahalı adımlar yalnız analistin ya da KaradulLM'in dokunduğu fonksiyonda;
   - tek büyük ikili için Ghidra çözümleyici profili (liste E2) ve takılan çözümleyici bekçisi;
   - bellek bekçisi ve disk bütçesi; akış biçimli çıktı (tek dev JSON yerine);
   - arayüz ve rapor: on binlerce fonksiyonda gezinme, kısmi sonuç.
5. **Öneri.** Seçeneklerden hangi bileşim "birkaç GB" gereksinimini karşılar; yayından önce asgari ne gerekir (dürüst sınır: "şu boyuta kadar denendi" cümlesi), yayından sonra ne. Karşılanamayan kısmı açıkça yaz.
6. **PLAN.** Opus paketleri: amaç, dokunacağı / dokunmayacağı dosyalar (tam yol; `ls` / `grep` ile doğrulanmış), adım adım kalemler (5–8), kabul ölçütü (sayı: süre, tepe bellek, disk, ilk kullanılabilir rapora kadar geçen süre), ön kayıt metni, sınama beklentisi, bayrak adı. Ölçüm paketleri ayrı: üç boyutta tek ikili (≈ 25 MB, ≈ 100 MB, ≥ 300 MB) ve bir çok GB'lık açık kaynak kurulum; hedefleri adıyla, lisansıyla ve boyutuyla say.
7. **Çakışma.** Planın yayın kapısı işleriyle (G1–G4, D3) ve KİMLİK / ÜST VERİ hatlarıyla kesişen dosyaları yaz.

## Kurallar

- Ghidra koşma (gösteri koşusu kullanıyor; aynı anda ikinci Ghidra belleği taşırır). Ürün kodunu, testleri, ortak ölçüm betiklerini değiştirme.
- Git'te durumu değiştiren komut yok. İndirme, silme yok. Alt ajan ya da codex çağırma.
- Kilitli setlere ve `~/karadul_olcum/ozkod_nufus/`'a dokunma.
- Her sayı betikten; dış değerleme "tahmin" etiketiyle ve aralıkla. Uydurma sayı yok.
- Çıktı: `DEFTER.md`, `BULGULAR.md`, `PLAN.md`, `BERKE.md` (ortak brif §6). `PLAN.md` yazanı olmadan uygulanabilir olmalı.
- Zaman kısıtın yok; kalemleri atlama. Türkçe yaz, Türkçe karakterleri doğru kullan.
- Son mesaj: en çok 10 satır özet + yollar + `## PAKET BİTTİ`.
