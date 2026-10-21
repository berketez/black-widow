# Görülmemiş dilim: ön kayıt taslağı

- **Tarih:** 2026-10-19
- **Durum:** Taslak, sürüm 2 (2026-10-19 öğleden sonra). Aday seçilmedi ve aday listesi çekilmedi. Bu belge yalnız yöntemi yazar. Berke onaylayıp commit'lediğinde ön kayıt olur. Aday listesi bu commit'ten **sonra** çekilir, yani kurallar sonuç görülmeden konur.
- **Sürüm 2'de değişen (Berke'nin kararları, 2026-10-19):** Birincil model Qwen3.8-27B oldu; sınır tarihi **S = 2026-08-05**. G8 kararı geçici, dilimin koşulu G34'te kesinleşir (§9, seçenek A). "Sürüyor" tanımı kabul edildi (§8). Fizibilite sayımları yeni sınırla yeniden yapıldı (§10). Sürüm 1 (952018f) S = 2026-06-01 kullanıyordu.
- **Plan bağlantısı:** `docs/arge/2026-10-17_plan_v2.md` §5. G6'da dilimin ön kaydı yapılır, G8 karar kuralı dilime bakar, G31'de dilim açılır. Onuncu Adam İ3 (`docs/arge/2026-10-17_v2/onuncu_adam.md`).
- **Model bağlantısı:** `model_secimi.md`. Birincil Qwen3.8-27B (GGUF Q4_K_M), ikinci model Gemma 4 26B-A4B-it (QAT, MLX).
- **Ölçüm bağlantısı:** `pilot_protokolu.md`. Koşullar, istemler ve değerlendirme pilotla aynı.

## 0. Amaç ve ilkeler

- **Soru:** LLM'in geliştirme setindeki (htop, tmux) olası üstünlüğü, bu kodu eğitimde görmüş olmasından mı geliyor? Görülmemiş dilim aynı ölçümü, modelin eğitim verisinde **bulunamayacak** insan yazımı C projelerinde tekrarlar.
- Dilim Karadul için de yenidir. Tarif kuralları bu projeler üstünde yazılmadı; Karadul'un geliştirme setine aşırı uyumu da burada sınanır.
- **İlkeler** (plan §3 madde 1-2, `docs/arge/test_seti_kilidi.md`):
  - Kurallar sonuç görülmeden yazılır.
  - Projeler kurayla seçilir.
  - Seçilen projelerin kaynağına ve derleme çıktısına bakılmaz.
  - Projeler G31'den önce Karadul ile analiz edilmez.
  - Kural, eşik ya da sözlük bu projelere göre ayarlanmaz.

## 1. Sınır tarihi

### 1.1 Tanım

- **S = 2026-08-05** (UTC; Berke'nin kararı, 2026-10-19). Dayanağı Qwen3.8-27B'nin ağırlık deposunun açıldığı gün (`model_secimi.md` K20).
- Pilot modellerinin tarihleri:

| Model | Tarih | Kaynak |
|---|---|---|
| Qwen3.8-27B (birincil) | Depo 2026-08-05'te açıldı; son değişiklik 2026-08-14 | HF API (`model_secimi.md` K20) |
| Gemma 4 26B-A4B-it (ikinci) | Yayım 2026-04-02; QAT deposu 2026-04-29. Ön eğitim kesimi Ocak 2025 (beyan) | `model_secimi.md` K5 |

- **Gerekçe:** Bir model, ağırlıkları yayımlanmadan önce herkese açık olmayan bir kodu göremez. Sınır üreticinin kesim beyanına dayanmaz; Qwen3.8 zaten kesim beyan etmiyor. Gemma 4'ün yayımı daha erken olduğundan aynı sınır onun için de geçerlidir.
- **Duyarlılık katmanı:** Depo 2026-08-05'te açıldı, ağırlıklar en geç 2026-08-14'te herkese açıktı. Bu iki tarih arasında ilk kez açılmış bir projenin eğitim verisine girmesi pratikte olanaksız, çünkü eğitimin yayımdan önce bitmesi gerekir. Yine de bu aralıkta açılmış projeler (`created` 2026-08-05..2026-08-14) künyede işaretlenir ve sonuç onlar olmadan da raporlanır.
- **Sürüm 1'den fark:** Sürüm 1, Nisan 2026'da yayımlanan Qwen3.6-27B'ye göre S = 2026-06-01 kullanıyordu. Model değişince sınır iki ay ileri kaydı ve aday penceresi daraldı (§10).

### 1.2 Model ya da revizyon değişirse

- Pilotta S'den sonra yayımlanmış bir model de kullanılırsa, o modelin sonuçları bu dilimde "görülmemiş" diye raporlanamaz. Bu durumda S o model için yeniden tanımlanır ve yalnız yeni S'den sonra açılmış projeler kullanılır.
- Ağırlıkları değiştiren yeni bir revizyon kullanılırsa S, o revizyonun tarihinden yeniden hesaplanır.

### 1.3 İsteğe bağlı ikinci katman (yalnız Gemma 4; varsayılan: kapalı)

- Gemma 4, ön eğitim kesimini Ocak 2025 diye beyan ediyor (`model_secimi.md` K5).
- İstenirse bir "beyan sonrası" katmanı eklenebilir: ilk herkese açık görünümü 2025-04-01 ile 2026-08-04 arasında olan projeler.
- Bu katman yalnız Gemma sonuçları için geçerlidir ve ana analize girmez. Son eğitim verisinin tarihi açıklanmadığı için "olası görülmüş" uyarısıyla raporlanır.

### 1.4 G33'e öncü model eklenirse

- Berke G33'te öncü bir model kullanmaya karar verirse, o modelin kesim ya da yayım tarihi büyük olasılıkla S'den sonradır. O zaman bu dilim o model için görülmemiş sayılmaz.
- Bu durumda daha geç ayrı bir sınır (S2) ve ayrı bir kura gerekir.
- Kararın kura gününden önce verilmesi önerilir; aynı ham listeden iki katman çekilebilir.

## 2. Aday arama kuralı

- **Kaynak:** Yalnız GitHub. GitLab, Codeberg ve SourceHut kapsam dışı; bu bir yanlılık olarak raporlanır (§11).
- **Sorgu:** GitHub REST `GET /search/repositories`:

  `language:C created:2026-08-05..<T> stars:>=50 fork:false archived:false mirror:false is:public`

  - T = kura günü − 30 gün. Böylece yeni depolar yıldız toplayacak zaman bulur.
  - Kura günü, bu belgenin onaylı sürümünde sabitlenir. Öneri: G30 ile G31 arası, doğrulama seti kilitlendikten sonra.
- **Sayfalama:** Arama API'si sorgu başına en çok 1.000 sonuç döndürür. Bu yüzden `created` aralığı aylara, gerekirse haftalara bölünür; her parça 1.000'den az sonuç verecek kadar küçültülür.
- **Ham liste:**
  - Alanlar: sayısal depo kimliği, tam ad, `created_at`, `pushed_at`, `stargazers_count`, `language`, `license.spdx_id`, `default_branch`, `topics`, `description`.
  - Sorgu zaman damgasıyla JSON olarak kaydedilir; sha256'sı künyeye yazılır.
  - Sonra sayısal depo kimliğine göre sıralanır.
- **Kura betiği:** Bu belgeyle aynı commit'te ya da daha önce depoya girer; ham liste ondan sonra çekilir. Örnek: test seti kurasındaki `scripts/measurement/test_seti_kura.py`. Önerilen ad `scripts/measurement/gorulmemis_kura.py`; betik henüz yok.

## 3. Uygunluk ölçütleri

- Ölçütlerin hepsi betikle denetlenir. İnsan kaynak kodu okumaz; kilit belgesi kural 2'nin karşılığı budur.
- Betik yalnız şunları okur: depo meta verisi, dosya yolları ve boyutları, commit meta verisi, lisans başlıkları, README ve açıklama metni, derleme günlüğünün başarı durumu, `nm` ve dSYM çıktısı.
- Ölçütler §5'teki sırayla uygulanır. Her ret, nedeniyle birlikte kayda geçer.

| # | Ölçüt | Denetim |
|---|---|---|
| U1 | İlk herkese açık görünüm ≥ S | Depo `created_at` ≥ S. Varsayılan daldaki **bütün** commit'lerin yazar ve işleyici tarihleri ≥ S; eski tarihli geçmiş içe aktarılmışsa ret. Software Heritage'ta bu depo adresinin S'den önce bir ziyareti varsa ret (eski bir deponun yeniden adlandırılmış ya da taşınmış hâli olabilir). README ya da açıklamada başka bir projenin devamı ya da kopyası olduğunu söyleyen ifadeler varsa ret: "fork of", "forked from", "port of", "rewrite of", "successor to", "continuation of", "mirror of". "based on" çok genel olduğu için (ör. "based on SDL2") burada aranmaz; yalnız §4'teki türev kuralında, dışlanan bir programın adıyla birlikte aranır |
| U2 | Dil | GitHub dil dağılımında C (kaynak ve başlık dosyaları) ≥ %90. Ana kod C++, Objective-C, Rust, Zig ya da Go değil |
| U3 | Boyut | Satıcı ve üretilmiş dosyalar (U6, U7) düşüldükten sonra 2.000 ≤ C satırı ≤ 100.000. Boş ve yorum satırları sayılmaz; araç `cloc` ya da eşdeğeri |
| U4 | Etkinlik | Varsayılan dalda ≥ 20 commit. İlk ve son commit arası ≥ 30 gün. En az bir insan yazar, yani bot olmayan |
| U5 | LLM yardımı işaretleri | Aşağıdakilerden herhangi biri varsa ret: (a) dosyalar: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/`, `.windsurfrules`, `.github/copilot-instructions.md`, `.aider*`, `.claude/`, `.codex/`, `.continue/`. (b) commit iletisi ya da trailer'ında `Co-Authored-By` ile birlikte şu adlardan biri: claude, copilot, cursor, codex, gemini, devin, aider, chatgpt, openai, anthropic. "Generated with" ifadesi. (c) bot yazarlar: `copilot-swe-agent`, `devin-ai-integration`, `claude[bot]`, `cursor[bot]`, `gemini-code-assist[bot]` ve benzerleri. (d) README ya da açıklamada: "vibe", "AI-generated", "generated by AI", "LLM-assisted"; "written with" ya da "written by" ile birlikte ChatGPT, Claude, Copilot, Cursor, Gemini, Codex ya da LLM. Listeler kura betiğinde sabitlenir |
| U6 | Satıcı (vendored) ve kopya kod | Yol kuralı: `third_party/`, `thirdparty/`, `vendor/`, `deps/`, `external/`, `extern/`, `contrib/`, `subprojects/`, `lib/<bilinen kütüphane>/`. Bilinen tek dosyalık kütüphaneler, betikte sabit bir listeyle: stb_*, miniz, cJSON, sqlite3.c, linenoise, utf8proc, xxhash, lz4, zlib, mbedtls, lua, jsmn, inih, uthash, klib, tinyexpr vb. Lisans başlığında başka bir projenin adı ya da S'den önceki bir telif yılı geçen dosyalar. Bu dosyalardaki fonksiyonlar örneklenmez. Satıcı ve kopya kod, C satırlarının %50'sinden fazlasıysa proje reddedilir |
| U7 | Üretilmiş kod | `lex.yy.c`, `*.tab.c`, `y.tab.c`, `*_generated.c` ve başlığında "generated by", "DO NOT EDIT" ya da "automatically generated" geçen dosyalar. Fonksiyonları örneklenmez. C satırlarının %30'undan fazlasıysa proje reddedilir |
| U8 | Derlenebilirlik | §6'daki yordamla derlenir: kaynak değiştirilmez, yalnız kura günündeki Homebrew bağımlılıkları kullanılır, süre en çok 15 dakika. En az bir Mach-O çalıştırılabilir (`MH_EXECUTE`) üretmeli; yalnız kütüphane üreten projeler reddedilir |
| U9 | Yeterli fonksiyon | Seçilen ikilinin `nm` çıktısında, U6 ve U7 dışındaki kaynak dosyalarından gelen `T`/`t` (`__TEXT,__text`) sembolü ≥ 60. Dosya bilgisi dSYM'deki `DW_AT_decl_file`'dan alınır. Bu sayım Ghidra ve Karadul kullanmaz |
| U10 | Alan dışı | Çapraz derleyici gerektiren gömülü yazılım; çekirdek modülü ve sürücü; yalnız test ya da benchmark deposu. Ödev ve eğitim depoları da dışarıda: ad ya da açıklamada betikteki sabit listeden bir sözcük geçerse (assignment, homework, tutorial, exercise, leetcode, course, cs50 vb.). Yalnız Linux ya da yalnız Windows API'si kullanan projeleri U8 zaten eler |
| U11 | Dışlama listeleri | §4 |
| U12 | Lisans | OSI onaylı bir lisans. GitHub `license.spdx_id` boş, `NOASSERTION` ya da `other` ise ret |
| U13 | Sahip başına | Aynı sahipten (kullanıcı ya da kuruluş) en çok bir proje |

## 4. Dışlama listeleri

- **Test seti** (`docs/arge/test_seti_kilidi.md`):
  - Ana küme: unzip, memcached, dash, dcraw, gifsicle, mawk, dnsmasq, GnuPG (`gpg`), nasm, rsync, OpenSSH (`ssh`), zsh, vim, git, haproxy.
  - Stres alt kümesi: wget, nano, screen, lua, pigz.
  - Yedekler: ag, less, cmus, tcpdump, lynx.
- **Geliştirme seti** (`docs/arge/2026-10-15_makale/test_seti_adaylari.md` §1):
  - GNU coreutils ve gnulib, tmux, htop, redis, zstd, libjxl, CalculiX, gnulib hashbench, tree, sqlite3, OpenSSL ve macOS sistem araçları.
  - §1.2'deki C dışı programlar.
  - §1.4'te adı geçenler: ffmpeg, libxul, content_shell, libpng, JavaScriptCore.
- **Doğrulama seti (G5):** Kilitlendiğinde listesi buraya eklenir. Kura, doğrulama seti kilitlenmeden yapılmaz.
- **Türev kuralı:**
  - Yukarıdaki programların fork'u, yeniden yazımı, eklentisi ya da klonu olan projeler: README ya da açıklamada program adı "fork of", "port of", "based on", "plugin for", "clone of" gibi bir ifadeyle geçiyorsa.
  - Bu programların kaynak dosyalarını taşıyan projeler (U6'nın yol kuralıyla).
  - Örnek sınıflar: tmux eklentileri, htop türevleri, coreutils yeniden yazımları.
- **Not:** Dilimdeki projeler tanım gereği 2026-08-05'ten sonra açılmış; listedekiler ise eski programlar. Doğrudan çakışma olamaz; önemli olan türevler.

## 5. Kura yöntemi

- **Tohum:** `int(SHA-256("karadul-gorulmemis-dilim-kura-2026-10-19")[:16], 16)` = **15147333502067250940** (hex `d2362390ed1796fc`).
  - Tohum bu belgeyle birlikte sabitlenir; kura günü değişse de değişmez.
  - Hesap yöntemi test seti kurasıyla aynı. Aynı yöntem, kilit belgesindeki 1357717698366421230 değerini yeniden üretiyor.
- **Karıştırma:** Sayısal depo kimliğine göre sıralanmış ham liste `random.Random(tohum).shuffle` ile karıştırılır.
- **Ölçütlerin sırası** (ucuzdan pahalıya): U1, U2, U4, U12, U13, U10, U11, U5, U6, U7, U3 (klon gerekir), U8 (derleme gerekir), U9 (`nm` ve dSYM).
- **Seçim:**
  - Karışık sırada ilerlenir. Bütün ölçütleri geçen ilk **N = 10** proje seçilir; en az 8.
- **Alan kotası:**
  - Aynı alan sınıfından en çok 3 proje alınır.
  - Sınıflar: emülatör ve sanal makine; oyun; ağ; sıkıştırma ve arşiv; metin, ayrıştırma ve dil; sistem aracı ve kabuk; grafik ve medya; diğer.
  - Sınıf, yalnız açıklama ve konu etiketlerinden, betikteki sabit bir anahtar sözcük tablosuyla atanır.
  - Kotası dolmuş sınıftan gelen proje atlanır ve atlama kayda geçer.
- **Kura günlüğü:**
  - Her adayın sonucu ve ret nedeni yazılır.
  - Yeniden çekim yapılmaz. Liste bittiğinde N'ye ulaşılamamışsa eldekilerle devam edilir ve bu raporlanır.
- **Sabitleme** (ilk analizden önce; kilit belgesi kural 5'in karşılığı). Her proje için:
  - depo adresi ve kura anındaki HEAD commit'i;
  - kaynak arşivinin sha256'sı;
  - derleme komutu, bayraklar ve araç zinciri sürümleri;
  - ikilinin sha256'sı ve UUID'si; dSYM'in UUID'si.
  Bu bilgiler kilit belgesine benzer bir tabloya yazılır.

## 6. Derleme ve gerçek veri (macOS)

- **Araç zinciri:** Apple clang (`xcrun clang --version`) ve macOS SDK sürümü künyeye yazılır. Homebrew bağımlılıkları kura günündeki sürümleriyle kullanılır; sürümleri künyeye yazılır.
- **Yordam:**
  - Projenin kendi derleme sistemi (make, CMake, Meson ya da autotools) ve varsayılan "release" ayarı kullanılır.
  - Tek ek `-g`'dir: `CFLAGS`'e ve `LDFLAGS`'e eklenir. `-O` düzeyi değiştirilmez.
  - CMake: `-DCMAKE_BUILD_TYPE=Release`, proje başka bir varsayılan tanımlamıyorsa. Meson: `--buildtype=release`. autotools: `./configure` ve `make`, `CFLAGS`'e `-g` eklenerek.
  - Derleme, sistemdeki Homebrew kurulumunu değiştirmeyen yalıtılmış bir önekte yapılır. İlke `test_seti_kilidi.md` §4.4 ile aynı.
- **Optimizasyon düzeyi:** Her proje için kaydedilir. Analizde katman olarak raporlanır (O0, O1, O2, O3, Os).
- **Hangi ikili:** Birden çok çalıştırılabilir varsa `__TEXT,__text` bölümü en büyük olan seçilir. Bu sabit bir kural.
- **dSYM:** `dsymutil` ile üretilir ve saklanır.
- **GT:** Strip'siz ikilinin `/usr/bin/nm -n -U` çıktısındaki `T`/`t` sembolleri. Kural Mac ölçüm hattınınkiyle aynı (`scripts/measurement/macho_f1.py gt`). Fonksiyonun kaynak dosyası DWARF'ın `DW_AT_decl_file` alanından alınır; U6 ve U7 dışlamaları için gerekir.
- **Analiz girdisi:** Aynı ikilinin `/usr/bin/strip` ile soyulmuş kopyası. Export trie'nin boş olduğu `xcrun dyld_info -exports` ile doğrulanır. Conda strip tuzağına dikkat: hafıza `feedback-mac-strip.md`.
- Derleme sırasında kaynak koda ve derleme çıktısına bakılmaz. Yalnız derlemenin başarısı ve ikilinin varlığı denetlenir (`test_seti_kilidi.md` §4.4).

## 7. Fonksiyon örneklemi

- **Popülasyon:** İsim bekleyen ve `sinif == "program"` olan fonksiyonlar; U6 ve U7 ile dışlanan dosyalardan gelenler hariç.
  - Popülasyon G31'de, Karadul koşusundan sonra hesaplanır, çünkü Ghidra'nın adlandıramadıklarını bilmek gerekir.
- **Kota:** Proje başına en çok 30 fonksiyon; proje daha azını veriyorsa hepsi alınır.
- **Tohum:** `int(SHA-256("karadul-gorulmemis-dilim-orneklem-2026-10-19")[:16], 16)` = 6491880641897428695 (hex `5a17cb0c6087f6d7`).
  - Tek bir `random.Random(tohum)` kullanılır. Projeler kura sırasıyla gezilir; her projede popülasyon adrese göre sıralanır.
- **Gövde şartı:** Değerlendiricinin amaç cümlesi için kaynak gövdesi gerekir. `etiket_paketi.py` kuralıyla, gövdesi tek anlamlı bulunamayan fonksiyonlar dışlanır ve sayıları kayda geçer.
  - Değerlendiriciler bu kaynakları G32'de görür. O tarihte test seti açılmış olacağı için bu, kural ihlali değildir.
- **"Olası görülmüş" denetimi** (G31'de, otomatik):
  - Örneklenen her fonksiyonun gövdesinden en az 12 karakterlik ayırt edici dizgi sabitleri alınır.
  - Bu dizgiler GitHub kod aramasında aranır. Bulunan bir depo S'den önce açılmışsa fonksiyon "olası görülmüş" diye işaretlenir, ana analizden çıkarılır ve ayrı raporlanır.
  - Sınırlama: Ayırt edici dizgisi olmayan kopyalar bu yolla yakalanamaz.

## 8. Ölçüm ve analiz

- **Koşullar:** Pilotla aynı: A, B, B-Ç, C, C-Ç; pilotta yapılmışsa B-D ve C-D da.
  - Aynı istem dosyaları (sha256 eşleşmeli), aynı model revizyonu, aynı çözme ayarları.
  - Karadul, G30'da dondurulmuş sürümüyle koşar.
- **Değerlendirme:** Kör protokol v2. G32'de iki insan değerlendirici ve bir vekil (plan G32).
- **Ana ölçü:** Δb_görülmemiş = yakın(B) − yakın(A), proje başına makro ortalama (plan §3 madde 4). Δc de aynı biçimde.
- **GA:** Proje kümeli, iki aşamalı bootstrap: önce projeler, sonra proje içinde fonksiyonlar yeniden örneklenir. 10.000 tekrar, tohum 20261019.
- **"Sürüyor" tanımı** (Berke'nin kararı, 2026-10-19; `pilot_protokolu.md` §11.3): Δb_görülmemiş ≥ 10 puan ve %95 GA alt sınırı > 0. LLM tarafında önceden yazılmış koşulların en iyisi, Karadul tarafında A1 kullanılır.
- **İkincil ölçüler:**
  - Δb_geliştirme − Δb_görülmemiş: LLM'in ezberden gelen kazancının ölçüsü.
  - Tam oranlarının iki kümede karşılaştırılması.
  - Karadul'un geliştirme setinden görülmemiş dilime düşüşü: kuralların geliştirme setine uyumunun ölçüsü.
- **Güç:**
  - Hesap: ~300 fonksiyon, ~10 küme. Küme içi korelasyon 0,02-0,05 varsayılırsa tasarım etkisi 1,6-2,5 ve etkin örneklem 120-190 olur.
  - Sonuç: q = 0,4 için Δ'nın %95 GA yarı genişliği ≈ ±9-11 puan.
  - Önerilen "sürüyor" ölçütü bu genişlikle okunabilir. "≥ 15 puan" ölçütü ise sınırda kalır.

## 9. Zamanlama: G8 kuralıyla çelişki (karar verildi)

- Plana göre dilimin ön kaydı G6'da yapılıyor, dilim G31'de açılıyor. G8 kuralının ikinci koşulu ("fark görülmemiş dilimde de sürüyor") G8'de ölçülemez.
- **Karar (Berke, 2026-10-19): seçenek A.**
  - G8 kararı geliştirme setiyle **geçici** olarak verilir.
  - Dilim G31'de açılır; kesin okuma G34'te yapılır.
  - G31 sonucu G8'deki geçici yönle çelişirse makale G31 sonucunu izler.
- Sürüm 1'deki seçenek B (3 pilot projesi) uygulanmaz; §5'teki kura bu yüzden yalnız kilitli parçayı (N = 10) çeker.

## 10. Fizibilite (yalnız sayım)

2026-10-19 13:07'de GitHub arama API'sinde yalnız `total_count` değeri okundu. Depo adları görüntülenmedi ve aday seçilmedi. Sorguların hepsi `language:C fork:false archived:false mirror:false` içeriyor.

**Sürüm 2 (S = 2026-08-05):**

| `created` aralığı | Yıldız | Sonuç |
|---|---|---|
| 2026-08-05..2026-10-15 | ≥ 20 | 710 |
| 2026-08-05..2026-10-15 | ≥ 50 | 308 |
| 2026-08-05..2026-10-15 | ≥ 100 | 146 |
| 2026-08-05..2026-09-19 (bugün kura yapılsaydı T = bugün − 30 gün) | ≥ 50 | 163 |
| 2026-08-05..2026-08-14 (§1.1 duyarlılık katmanı) | ≥ 50 | 47 |
| Kıyas: 2024-08-05..2024-10-15 | ≥ 50 | 243 |

- U2-U13'ten sonra ne kadar aday kalacağı bilinmiyor. Gömülü yazılım, Linux'a özgü projeler ve ödev depoları büyük bir pay tutabilir.
- Bugün kura yapılsaydı ≥ 50 yıldızlı 163 aday olurdu; %5-10'u kalsa 8-16 uygun proje. N = 10 için **sınırda**.
- Kura G30-G31 arasında yapılırsa pencere 3 ay civarına çıkar ve aday sayısı artar. Bu, bugünkü sayımdan bir tahmindir.
- Önerilen önlem (Berke onaylar): Uygun proje sayısı 8'in altında kalırsa yıldız eşiği bir kez, önceden yazılmış biçimde ≥ 20'ye iner. Kura günlüğüne yazılır.
- Gözlem: 2026'nın Ağustos-Ekim penceresindeki ≥ 50 yıldızlı yeni C deposu sayısı (308), iki yıl önceki aynı penceredekinden (243) fazla. Oysa eski depolar iki yıl daha fazla yıldız topladı. Bu, yapay zekâ destekli geliştirmenin artmasıyla tutarlı olabilir; **kanıtlanmadı**. Her durumda U5'in önemini artırıyor.

**Sürüm 1'in sayımları (S = 2026-06-01; kayıt için):**

| `created` aralığı | Yıldız | Sonuç |
|---|---|---|
| 2026-06-01..2026-10-15 | ≥ 20 | 1.365 |
| 2026-06-01..2026-10-15 | ≥ 50 | 580 |
| 2026-05-01..2026-10-15 | ≥ 20 | 1.636 |
| 2026-05-01..2026-10-15 | ≥ 50 | 699 |
| 2026-05-01..2026-10-15 | ≥ 100 | 330 |
| 2026-09-01..2026-10-15 | ≥ 20 | 472 |
| 2026-09-01..2026-10-15 | ≥ 50 | 205 |
| 2025-04-01..2026-04-30 (§1.3 katmanına yakın pencere) | ≥ 50 | 1.449 |
| Kıyas: 2024-05-01..2024-10-15 | ≥ 50 | 606 |

## 11. Riskler ve sınırlamalar

- **LLM yardımı:** 2026 projelerinde yapay zekâ desteği yaygın. U5 yalnız açık işaretleri yakalar; işaretin olmaması kodun insan yazımı olduğunu kanıtlamaz. Onuncu Adam'ın uyarısı ("LLM'e tipik isimler LLM lehine yanlılık yaratır") tamamen giderilemez; bu yüzden raporlanır.
- **Genç projeler:** S = 2026-08-05 ile projeler kura gününde en çok ~4 aylık olur; ünlü programlardan daha küçük ve daha az olgun. "Görülmemiş" etkisi "genç proje" etkisinden ayrılamaz.
- **Kaynak yanlılığı:** Tek forge (GitHub) ve yıldız eşiği, popüler projelere doğru bir yanlılık getirir.
- **Kopya kod:** U6 ve §7'deki denetim yalnız bilinen kopyaları ve ayırt edici dizgisi olanları yakalar. Modelin gördüğü eski bir koddan uyarlanmış fonksiyonlar dilimde kalabilir.
- **Derlenebilirlik süzgeci:** macOS'ta derlenen projeler seçilir; Linux'a özgü projeler dışarıda kalır.
- **Sınır tarihinin kapsamı:** S yalnız pilot modelleri için geçerli (§1.4).
- **Karadul'un ön bilgisi:** Karadul'un imza kataloğu ve sözlükleri G30'da dondurulur. Dondurmadan sonra bu projelerden hiçbir veri kataloğa giremez. Kataloğa daha önce giren ortak kütüphaneler (U6) zaten örneklenmez.

## 12. Onay bekleyenler

**Karara bağlananlar (Berke, 2026-10-19):** S = 2026-08-05; zamanlama seçenek A; "sürüyor" = Δb ≥ 10 puan ve %95 GA alt sınırı > 0; LLM tarafında önceden yazılmış koşulların en iyisi, Karadul tarafında A1.

**Bekleyenler:**
1. §1.3 katmanı (varsayılan kapalı).
2. Eşikler: yıldız ≥ 50; commit ≥ 20; boyut 2.000-100.000 satır; U9 için ≥ 60 GT fonksiyonu; N = 10; proje başına 30 fonksiyon. §10'daki eşik indirme kuralı.
3. U5'in işaret listesi ve U6'nın kütüphane listesi. İkisi de kura betiğinde sabitlenir.
4. Alan kotası (sınıf başına en çok 3).
5. Kura günü ve T'nin tanımı (kura günü − 30 gün).
6. G33'te öncü model kullanılıp kullanılmayacağı; gerekirse S2 ve ikinci kura (§1.4).
7. Kura betiğini kimin yazacağı. Betik, ham liste çekilmeden önce commit'lenmeli.
