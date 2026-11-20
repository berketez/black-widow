# Sonraki oturum: uygulama planı (2026-11-19 ARGE oturumunun teslimi)

Bu belge tek giriş noktasıdır. ARGE oturumu (Mythos) plan çıkardı; uygulamayı Opus ajanları yapar. Paketlerin ayrıntısı hat planlarındadır; bu belge sırayı, önkoşulları ve kararları verir.

- **Taban:** main `6d9b4e3` sonrası (bu belgenin commit'i). Tam takım `b4be6f3`'te 10 289 geçti / 11 atlandı / 0 kaldı; o commit'ten beri main'e yalnız belge ve `scripts/arge/` girdi (ürün kodu ve `tests/` değişmedi). Push yapılmadı: origin `a62f15e`.
- **Kararlar (bağlayıcı):** `KARARLAR.md` (A-1 … A-20). Hat planlarıyla çelişirse KARARLAR geçerlidir.
- **Karşı görüş:** `karsi/KARSI.md` (13 itiraz; ana sayıların 27 / 28'i bağımsız yeniden türetildi), `karsi/CAKISMA.md` (dosya çakışma haritası, dalga önerisi).

## 0. Yeni oturumun ilk mesajı (Berke yapıştırır)

```
Karadul uygulama oturumu. Önce oku: docs/arge/2026-11-19_mythos/SONRAKI_OTURUM.md, sonra KARARLAR.md ve
karsi/CAKISMA.md. Dalga 0'dan başla. Bütün ajanlar Opus (xhigh); aynı anda en çok <N> ajan.
Her paket: kendi worktree'si, ön kayıt ölçümden önce commit'li, mutasyon, ana oturumun bağımsız doğrulaması
(docs/arge/2026-11-18_onarim/ONARIM_BRIF.md). Dalga bitmeden sonraki dalgaya geçme; her dalga sonunda bana
sade özet ver.
```

## 1. Bugün ne öğrenildi (hepsi ölçüm; kaynak yanında)

| Bulgu | Sayı | Kaynak |
|---|---|---|
| Ad bekleyen nüfusun yarısından fazlası aynı kitaplığın kopyası | 21 371'in 11 393'ü gnulib (537 tekil fonksiyon); tekil nüfus 9 257 | `olgu/BUTCE.md` |
| Gerçek uygulamada bugünkü ürün | Ollama 26,6 MB dilim: 129 dk, çıkış 3 (kısmi), 13 160 fonksiyon, **17 ad** | `../2026-11-19_yayin/YAYIN_KAPISI.md` §5.1 |
| Aynı dilimde üst veride hazır ad | 10 751 / 12 952 (%83); Go araçlarında %92–100; ObjC + Swift %41; Swift %26; C ve C++'ta 0 | `ustveri/BULGULAR.md` |
| Başka derlemeden tanıma (aynı sürüm) | kapsam %80–88, doğruluk 0,990; başka sürüm 0,935; BSim 0,610 | `kimlik/BULGULAR.md` |
| Kayıt tablosundan ad (K1) | keşif 740 / 754; sınama 103 / 126 (%81,7; eşik %90 tutmadı); bugünkü çapalarla 95 ad | `ozkod/BULGULAR.md` |
| "Yanlış" sayılan 119 adın 40'ı yalnız biçim farkı | yanlış %6,6 → %4,4; makro %31,0 → %19,1 | `olcu/BULGULAR.md` §4 |
| "Yakın ad"ı sayan mekanik ölçü yok | en iyi AUC 0,790; insan etiketi hiç yok | `olcu/BULGULAR.md` §2 |
| Büyük yazılım | uçtan uca ölçülmüş en büyük ikili 3,2 MB; 95 MB için Ghidra aşaması **tahmin** 14–39 saat | `olcek/BULGULAR.md` |
| Ghidra aşamasının yarısı boşa | BSim 32,5 dk, 0 eşleşme; 9 adımda süre sınırı yok | `olcek/BULGULAR.md`, `hiz/BULGULAR.md` |
| KaradulLM gerçek modelle çalışıyor | Qwen 27B Q4: açılış, hız (16,1 jeton/sn), açıkla, kapanış geçti; 76 sn | `YAYIN_KAPISI.md` §5.2 |
| Onarım denetimi | 137 bulgunun 115'i kapandı, 17'si kısmen, 1'i bekletildi, 4'ü açık (düşük) | `../2026-11-19_yayin/denetim_A.md`, `denetim_B.md` |

## 2. Sorun → nasıl düzeltilecek → paket

| # | Sorun (ölçülmüş) | Çözüm | Paket (plan belgesi) |
|---|---|---|---|
| 1 | Go / ObjC / Swift / C++ üst verisi okunmuyor; evrensel Mach-O'da Go hattı hiç açılmıyor (G5, G6) | Ortak ikili okuyucu; dil başına okuyucu ve üretici adım; adlar `üst veriden` etiketiyle; tutarlılık denetiminin yakaladığı ad yazılmaz | P-ÜV0, P-ÜV1, P-ÜV2, P-ÜV3, P-ÜV4, P-ÜV7, P-ÜV6 (`ustveri/PLAN.md`) |
| 2 | Mach-O'da `main` bulunmuyor (0 / 8; `LC_MAIN` = `main` 8 / 8) | Giriş adresini `main` say | P-ÜV5 |
| 3 | Ghidra adımında ilerleme görünmüyor; takılan çözümleyici saatlerce döner (G1, G2, G3) | Bekçi + ilerleme olayları; CLI ve arayüzde gösterim | ÖL-1, ÖL-4 (`olcek/PLAN.md`) |
| 4 | Otomatik analiz ve decompile dışındaki 9 Ghidra adımında süre sınırı yok; BSim boş depoda 32,5 dk koşuyor | Adım bütçeleri; BSim'i boş depoda atla; BSim hızlı yol | ÖL-2, HZ-2 (`hiz/PLAN.md`) |
| 5 | Python ↔ Java geçişi pahalı (1 714 sn); döküm adımları yavaş | Tek başvuru geçişi, yineleyiciler, akış biçimli yazım; gerekirse Java yardımcı sınıfı | ÖL-3 + HZ-4a, HZ-3, HZ-4b (koşullu) |
| 6 | İstihbarat taraması 26 MB'de 14,7 dk; masum ikililerde zayıf alt sistem iddiaları (IMZA-01; `bi / macos` 217 > 215) | Kanıt kuralı ve "zayıf ipucu" etiketi; taramanın ölçeklenmesi | D2, ÖL-3b, HZ-6 |
| 7 | `.app` paketinde yanlış ikililer seçiliyor, tekrarlar ayıklanmıyor, bütçe ve sürdürme yok (BICIM-09, G9) | Paket yöneticisi: envanter → yineleme ayıklama → öncelik → bütçe → kalıcı kuyruk; sürdürme | ÖL-5a (= D3), ÖL-5b |
| 8 | Bellek ve disk bekçisi yok; yeniden kurma döngüsü sabit 600 sn'de kesiliyor (G8) | Bekçiler; döngü sınırı ikili boyutuna göre | ÖL-6, ÖL-7, HZ-7 |
| 9 | 100 MB üstü tek ikili bugünkü akışla bitmez | Önbellek; tembel derinlik (önce ucuz katman, pahalı adım dokunulan yerde); bilinen bileşeni atla | ÖL-9, **ÖL-10 (önce tasarım turu, A-18)**, ÖL-11 |
| 10 | İşçi sayısı ve JVM yığını yer yer sabit sayıyla yazılı | Donanım künyesi; formülle türetme; oranla kabul | HZ-5 (A-9) |
| 11 | `oz_ad` adı küçük harfe çeviriyor (zstd 37 ad); eşit puanda yanlış kanıt seçiyor (19 doğru ad); kendine fazla güveniyor (0,83 ↔ 0,47) | Harf koruma; kanıt seçimi (P12d, dalda); teklik kapısı; güven ölçülmüş kesinlikten | ÖK-1, P12d, ÖK-2 (`ozkod/PLAN.md`; A-20) |
| 12 | Kayıt tablolarındaki adlar kullanılmıyor | Kayıt çifti çıkarıcısı (kanıt) → kör ölçüm → ad kanalı (bayrak arkasında) | ÖK-4a, ÖK-5, ÖK-4b, ÖK-3, ÖK-6 (ÖK-5'in hükmüne bağlı, A-17) |
| 13 | "Başvuru ikilisi ver" özelliği yanlış ad yazıyor (328 doğru / 174 yanlış; her ada 0,95) | Yöntem kapısı: ölçülmemiş yöntem ad yazmaz | **PK-1** (`kimlik/PLAN.md`) |
| 14 | Başka derlemeden tanıma üründe yok; dağıtımın hata ayıklama dosyasından ad alınmıyor | Çapalı eşleyici (bayrak arkasında); build-id ile ayrık `.debug` | PK-2, PK-3, PK-4, PK-5; genelleme PK-6, PK-11 önce (A-17) |
| 15 | Ölçüm tam eşitlikten başka bir şey saymıyor; biçim farkı yanlış sayılıyor | `urun_olc` biçim satırı; ad bölgeleri | P-Ö1, P-Ö2 (`olcu/PLAN.md`) |
| 16 | Set dışı ölçüm yok; sayılar 119 küçük C ikilisinden | Hedef seti (sembollü Go / Swift / C++ uygulamaları); tabaka A / B / C; kör nüfus | P-ÜV8, P-Ö6, P-Ö7, ÖK-V adım 5–6, P-Ö8 |
| 17 | .NET çıktısında `Directory.Build.props` / `.targets` süzülmüyor (kod yürütme riski) | Bu adları proje köküne kopyalama | D1 |
| 18 | Evrensel Mach-O'da anti-debug dedektörü başka dilimi okuyor | Analiz edilen dilimi oku | D4 |
| 19 | Rapor ve arayüzde bayat / çelişkili bilgi (Hakkında paneli 1.22.1; gnulib güveni 0,706; README "SUCCESS" ↔ çıkış 3; "Language: C/C++") | Gösterilen her sayı güncel ölçümden; durum tek kaynaktan | D5, G7 |
| 20 | Bekletilen katmanlar ölçülüp karara bağlanmadı | Ölç, kapıdan geçiyorsa aç | P10b, P08b, P03b (`../2026-11-18_onarim/gonderim/`) |
| 21 | Analist kendi modeliyle (Claude / GPT) kullanamıyor | MCP sunucusu: KaradulLM araç kaydının bağdaştırıcısı | P24 (`gonderim/P24.md`) |
| 22 | Onarımdan kalanlar: son doğrulama mutasyonları, 9 bayat mutasyon tanımı, P18 yaması + 78 test, ölçüm aracı kusurları, parametre adı yeniden ölçümü, P23 | `gonderim/OKU.md` "2026-11-19 sonrası" | onarım paketleri |
| 23 | KaradulLM: beklenen süre gerçek sürenin yarısı; duman kalemi 4–6 ve büyük çalışma alanı denenmedi | Duman listesinin kalanı; süre kestirimi | Y7 |
| 24 | Yeniden kurmanın 953 sn'sinin 481 sn'si düzenli ifade derlemesi (3,68 M derleme); 96 338 dosya okuması 135 sn (Ghidra'sız profil, mac/tmux kopyası, yük altında) | Desen önbelleği; tek yazım, paralel okuma, metin önbelleği. Çıktı bayt bayt aynı kalmalı | HZ-7a (ilk kod paketi; **tahmin** uçtan uca −%6–10), HZ-6, HZ-7b |
| 25 | Yeniden kurma döngüsünün ikinci turu 118 / 119 ikilide 0 yeni ad üretiyor, döngü süresinin %36,7'sini alıyor | Turu koşula bağla (çıktıyı değiştirebilir: ön kayıtlı ölçümle) | HZ-7c |
| 26 | JVM yığın tavanı 32 768 MB ≥ 80 GB makinede sıkıştırılmış göstericileri kapatıyor; Windows'ta bellek algılanmıyor (yığın hep 4 096 MB); 8 yerde sabit işçi sayısı | Donanım künyesi ve formüller | HZ-5 |

## 3. Dalgalar

Kaynak: `karsi/CAKISMA.md` §3 (ana oturum A-13 … A-20 ile kabul etti). `→` sıralı, `║` paralel. Aynı dosyaya yazan iki paket aynı anda gitmez. Süreler **tahmin**dir (dünkü hız: 5–7 ajanla günde 25–30 paket); Ghidra kuyruğu ayrıca.

### Dalga 0 — zemin ve "önce" sayıları (ürün davranışı değişmez) — tahmin: yarım gün + bir gece koşusu

| İş | Neden önce |
|---|---|
| Onarım kapanışı: tam takım → son doğrulama mutasyonları (p18, p20b, lm_kesif, lm_oturum, p20, p09, p16d) → 9 bayat mutasyon tanımı → push (Berke'ye sor) | her şeyin tabanı |
| **Bayrak ön paketi** (yeni; A-19): bütün planların `karadul/config.py` alanları, öntanım kapalı; ad eşiği sabiti `naming_labels.py`'de (A-13). Alan listesi `karsi/CAKISMA.md` §2.1 | 17 paketin `config.py` sırasını kaldırır |
| P-Ö1 (biçim satırı) → ölçüm aracı kusurları (`ks1_olc` `BITTI`, `masum_kapi` `sarif`, `saglamlik_denetle` "yazıldı", `function_f1.read_elf_info` not sahibi) | bütün ad paketlerinin "önce / sonra" sayısı bu araçtan |
| ÖLÇ-A ║ HZ-1 → ÖLÇ-0 → ÖLÇ-1 + HZ-0 (tek koşu; duvarlar 2 saat, A-18); **boş makinede, gece** | ÖLÇEK ve HIZ'ın "önce" sayısı |
| P-ÜV8 kalem 1–3 (hedef seti GT'si) ║ P-ÜV9 (gösteri çıktısından Ghidra adları) | hedef nüfusun "önce" sayısı (A-17) |
| Erken risk ölçümleri, araştırma betikleriyle: ÖK-V adım 5–6 → ÖK-5 (kör nüfus; veri indi) ║ PK-6 ║ PK-11 | tutmazsa 10 ürün paketi yazılmaz |
| ÖL-10 tasarım turu (belge; kod yok) | bitiş çizgisinin en az belirlenmiş parçası |

### Dalga 1 — ölçülmüş kusur onarımları ve ortak altyapı — tahmin: yarım gün

| Hat | Paketler | Ortak dosya |
|---|---|---|
| `c_namer` zinciri | P12d → ÖK-1 (aynı ajan, sırayla; A-20) | `karadul/reconstruction/c_namer.py` |
| Başvuru yolu | PK-1 | `_feedback_naming_*.py` |
| Okuyucu zemini | P-ÜV0 | yalnız yeni dosya |
| Köprü | ÖL-1 ║ ÖL-4 | `karadul/ghidra/headless.py` (HZ-1'den sonra), `cli.py`, arayüz |
| `main` | P-ÜV5 | `stages.py` |
| Küçükler | D1 ║ D4 ║ P24 ║ P18 (yama + 78 test) | ayrık |

### Dalga 2 — okuyucular, bütçeler, bekletilen katmanlar — tahmin: bir gün

| Hat | Paketler |
|---|---|
| Üst veri okuyucuları | P-ÜV1 ║ P-ÜV2 ║ P-ÜV4 → P-ÜV3 ║ P-ÜV7 → P-ÜV8 kalem 4 |
| Kayıt çifti / eşleyici (Dalga 0 hükmü tuttuysa) | ÖK-4a ║ PK-2 (ikisi de P-ÜV0 üstüne) → PK-3 |
| Köprü zinciri (tek sıra) | ÖL-2 → HZ-2 ; ÖL-3 + HZ-4a → HZ-3 → ÖL-6 |
| Paket yöneticisi | ÖL-5a (= D3) |
| İstihbarat (tek sıra) | D2 → ÖL-3b → HZ-6 |
| `c_namer` zinciri | ÖK-2 |
| Bekletilen katmanlar | P10b (P18'den sonra) ║ P08b ║ P03b |
| Ölçü | P-Ö2 ║ P-Ö5 ║ P-Ö3′ (A-16) ║ P-Ö6 ║ P-Ö7 adım 4–7 |

### Dalga 3 — kanal bağlama (ortak dosyalar; tek sıra) — tahmin: bir gün

- `_feedback_naming_candidates.py`, `_feedback_naming_merger.py`, `naming_labels.py`, `stages.py`, `baglama.py` üstünde tek sıra: **PK-5 → P-ÜV6 → PK-4 → PK-7 → ÖK-4b**.
- `c_namer.py` üstünde: ÖK-3 → ÖK-6.
- Paralel gidebilenler: ÖL-5b, ÖL-9, HZ-5, HZ-8, PK-9, P-Ö8 (kura + ön kayıt, sonra indirme).
- Her kanal paketi iki sette ölçülür (119 + hedef seti); 119'da beklenti "yeni yanlış 0".

### Dalga 4 — büyük ikili ve kapanış — tahmin: bir–iki gün

ÖL-10 (tasarım turundan çıkan metinle) → ÖL-7 ║ ÖL-8 ║ ÖL-11 ║ PK-8 ║ PK-10 ║ HZ-7 → ÖLÇ-2 + HZ-9 (birleşik "sonra" ölçümü) → 119 birleşik ölçüm + hedef seti ölçümü → K-1 / K-4 bayrak kararları (ölçümle) → P23 → D5, D7, G7 → **Y8: uygulamanın derlenip Berke'nin Mac'ine kurulması** → Y7 (KaradulLM duman listesinin kalanı) → Y6 (gerçek büyük uygulamada uçtan uca) → sürüm, değişiklik günlüğü, kılavuz.

### Toplam

KARŞI'nın sayımıyla 74 iş paketi. Tahmin: 4–5 tam Opus günü ve 2–3 gece koşusu. Dalga 0'daki erken risk ölçümleri tutmazsa bağlı paketler (10 kadar) yazılmaz, liste kısalır; tutmayan her ön kayıt ise ek tur getirebilir.

## 4. Değişmez kurallar (uygulayan oturum için)

1. Onarım brifi geçerli: `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md` (worktree, iş kalemi başına commit, ön kayıt ölçümden önce, mutasyon, ana oturumun bağımsız doğrulaması). Worktree'de ilk iş `git merge --ff-only main`.
2. Her yeni yöntem bayrak arkasında, öntanımı kapalı girer; ölçülüp A-13 / A-14 koşulunu sağlayınca açılır.
3. Motor LLM'siz. Kilitli setler (`targets/test_seti`, `targets/dogrulama_seti`) ve ÖK-V'nin kör tarafı (`ozkod/NUFUS.md`) kural yazarken açılmaz.
4. `config.py`'ye bayrak ön paketinden sonra kimse yazmaz; `headless.py`, `c_namer.py`, `stages.py`, `_feedback_naming_*.py` için sıra §3'teki gibidir (`karsi/CAKISMA.md` §1 tam liste).
5. Ghidra kuyruğu tek; aynı anda en çok 1 ağır Ghidra koşusu ajanlar çalışırken, hız ölçümleri yalnız boş makinede.
6. Araştırma betiklerinden ürüne taşınacaklar hat planlarında adıyla yazılı ("nereden → nereye"); ürün kodu `scripts/arge/`'dan içe aktarmaz.
7. Disk: yeni koşular `~/karadul_olcum/` altına (Spotlight dışı). Bugünkü ARGE verisi: `~/karadul_olcum/runs/arge-2026-11-19/` (kimlik 1,6 GB, ustveri 0,8 GB) ve `runs/gosteri-2026-11-19/` (2,2 GB); silme Berke'nin onayına bağlı.

## 5. Berke'den bekleyenler

| Konu | Durum |
|---|---|
| İndirilen kodu çalıştırma izni: Go derleyicisi (133 MB; P-ÜV9) ve kaynak paketlerinden derleme (KİMLİK V1) | cevap bekliyor (A-12); o ölçümler dışında hiçbir şeyi tutmuyor |
| Push (main, origin'in önünde) | Dalga 0'da mutasyonlardan sonra sorulur |
| ÖL-10 tasarım turunu kim yapsın | öneri: tek bir Mythos ajanı (tasarım işi); istemezsen Opus mimar ajanı |
| ARGE verisinin silinmesi (yaklaşık 4,6 GB) | bitiş çizgisine kadar durması önerilir (kanıt) |
| Karşı görüş (Astra) | KARŞI hattı Mythos ile yapıldı; ayrı model ailesinden görüş kota açılınca isteğe bağlı |
| Avast dışlama denemesi (`hiz/PLAN.md` §6 K-HZ-1) | Bu makinede var olan dosyayı açmak 0,6–0,9 ms, yeni dosya yazmak 0,04 ms; Avast etkin ve tablo erişimde taramayla tutarlı, ama nedeni kanıtlanmadı. Karadul'un çalışma dizinlerini Avast'ta dışlayıp ölçmek Berke'nin kararı (güvenlik ayarı; ajan değiştirmez). **Berke (2026-11-19 13:5x): "bir dahaki oturum yaparız"** → HZ-0'dan önce Berke dışlamayı yapar, HZ-0 iki kolla ölçer (dışlamalı / dışlamasız) |
| HIZ planı KARŞI tarafından denetlenmedi | `hiz/PLAN.md` KARŞI bitirirken yarımdı; Dalga 0'da HZ-0 koşmadan önce ana oturum dosya yollarını ve kabul ölçütlerini bir kez denetlesin |

## 6. Belge dizini

| Ne | Nerede |
|---|---|
| Kararlar | `docs/arge/2026-11-19_mythos/KARARLAR.md` |
| Yön kararı, ortak brif, hat metinleri | `YON.md`, `ORTAK_BRIF.md`, `HAT_*.md`, `OLGU.md`, `OLCEK.md`, `HIZ.md` |
| Hat planları (her biri: `BULGULAR.md`, `PLAN.md`, `BERKE.md`, `DEFTER.md`) | `kimlik/` (PK-1 … 11), `ozkod/` (ÖK-1 … 7, ÖK-V; `NUFUS.md`), `olcu/` (P-Ö1 … 9; `TABAKA_VERI.md`), `ustveri/` (P-ÜV0 … 9), `olcek/` (ÖLÇ-0 … 2, ÖL-1 … 11), `hiz/` (HZ-0 … 9) |
| Karşı görüş ve çakışma haritası | `karsi/KARSI.md`, `karsi/CAKISMA.md` |
| Olgu tablosu ve kapsam bütçesi | `olgu/SEMA.md`, `olgu/BUTCE.md`; veri `~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` |
| Yayın kapısı, denetimler, gösteri ve KaradulLM koşuları | `docs/arge/2026-11-19_yayin/` |
| Onarımın kalanı ve paket metinleri (P12d, P24, P10b, P08b, P03b, P18, P23) | `docs/arge/2026-11-18_onarim/gonderim/` |
| P12d kodu | dal `worktree-agent-a733cb2eb8bc2b9fd` (6 commit, `2381dce` üstünde); rapor `docs/arge/2026-11-18_onarim/P12d.md` |
| İndirilen veri | `~/karadul_olcum/ozkod_nufus/` (24 paket; 9 ayar, 15 kör), `~/karadul_olcum/n2_tabaka/` (tabaka A / B) |

## 7. Bitiş çizgisi (A-7)

- [ ] Bütün dalgalar bitti; koşullu paketler ya uygulandı ya da tutmayan ön kaydıyla kapandı.
- [ ] Bekletilen katmanlar (P10b, P08b, P03b, K-1 / K-4 bayrakları) ölçülüp karara bağlandı.
- [ ] 119 birleşik ölçüm + hedef seti ölçümü: yeni yanlış yok; hedef setinde kapsam ön kayıtlı beklentiyle karşılaştırıldı.
- [ ] Ölçek: en az bir 100 MB üstü tek ikili ve bir çok GB'lık paket, ön kayıtlı süre / bellek / disk sınırı içinde, kaldığı yerden sürdürülebilir biçimde koştu.
- [ ] Masum ikili kapısı main'de geçiyor (bugün `bi / macos` 217 > 215).
- [ ] MCP sunucusu ve KaradulLM gerçek modelle çalışıyor (duman listeleri tam).
- [ ] Uygulama derlendi, Berke'nin Mac'ine kuruldu, gerçek büyük bir uygulamada uçtan uca çalıştı.
- [ ] Tam takım, mutasyonlar, push.

## 8. 2026-11-20 sonrası (uygulama oturumu 1'in teslimi) — SONRAKİ OTURUM BURADAN

Canlı kayıt `docs/arge/2026-11-20_dalga0/DURUM.md`; kararlar A-21 … A-30 (`KARARLAR.md`). Ortak brif `docs/arge/2026-11-20_dalga0/ORTAK_D0.md` sonraki dalgalarda da geçerli (Ghidra kuyruğu sarmalayıcısı, paket bekletme, scratchpad kuralı).

**Biten:** Dalga 0'ın gündüz işleri (BAYRAK, OLCUM, OLCEK, HZ1, HEDEF, MUTBAKIM, OK5, KIMLIK) + üst veri hızlı hattı (P-ÜV0, P-ÜV1, P-ÜV2); hepsi main'de, bağımsız test + mutasyonla doğrulandı. **Ertelenen:** gece koşusu (HZ-0 + ÖLÇ-1; A-26; sabit ürün `be9550e`). **Mythos'a:** ÖL-10 tasarımı (A-24).

**Sonraki oturumun sırası (öneri; gerçek uygulama ölçütüyle — A-17, A-27):**
1. **P-ÜV6 — üst veri adlarını ürün çıktısına bağlama** (ilk iş; bugün ürün kodu Ollama'da 10 600 Go + 151 ObjC, terminal-notifier'da 32 ObjC adı okuyor ama çıktıya yazmıyor). Kabul: terminal-notifier 0 → ~32, Ollama 17 → ≥ 9 540 (P-ÜV8 H4), 119'da yeni yanlış 0. Notlar: A-28 (ObjC tam ad seçici adının yerine); iTerm2'de 7 420 Swift köprüsü + 274 işaretsiz adres ObjC adı almamalı; Go `pcsp_kapsama` `kisa` / `tasan` fonksiyona ad yazılmaz (E türü bozma); durum sabitleri `goruntu.py`'de tek tanım; INERT satırları yama ile.
2. **PK-1** (BinaryDiffer 34 doğru / 93 yanlış: yanlış ad yazan yolun kapısı) ║ **OKUMA-ENVANTERİ** (`gonderim/OKUMA.md`, A-27) ║ **P-ÜV5** (`gonderim/PUV5.md`; `stages.py` → P-ÜV6 ile sıralı).
3. P-ÜV3 (Swift) ║ P-ÜV4 (C++ RTTI) ║ P-ÜV7 (Go tutarlılık).
4. KİMLİK ürün: PK-2 → PK-3 → PK-4 (A-30; PK-4 öntanımı `TUTUCU`).
5. Dalga 1'in kalanı: P12d → ÖK-1, ÖL-1 ║ ÖL-4 (HZ-1'in `GHIDRA_ADIMLARI`'nı kullanır), D1, D4, P24, P18 + bugün eklenen **P16e** (çağıran sırası belirlenimciliği) ve **MUTBAKIM-2** (8 tanımda 11 bayat mutant, 9 çoklu eşleşme, 30 aynı uzunluk; `mutation_probe.py` sıkılaştırması).
6. P03b'ye ek: x86-64'te capa süreç içinde ve süre sınırsız koşuyor (`capa_timeout` etkisiz).
7. Berke'nin izniyle gece koşusu (`gece_kosusu.py --commit be9550e --gece 1`, sonra `--gece 2`); KIMLIK'in kalan 35 çifti (`~/karadul_olcum/runs/dalga0-2026-11-20/KIMLIK/isler.txt`).

**Yazılmayacaklar (A-29):** ÖK-3, ÖK-4b, ÖK-6 (ÖZ KOD kuralları kör nüfusta tutmadı). ÖK-2 R1 sonucuyla (%79,8) yeniden ele alınır.

**Bugünün dersleri (uygulayan oturum için):**
- Ajan dalını main'e alırken aralık tabanı `git merge-base main <dal>` ile bulunur (ajan `--ff-only main`'i gönderimden biraz sonra yapınca taban kayar; bugün bir kez çakıştı, geri alındı).
- Kuyrukta kısa işler uzun işlerin arkasında aç kalıyor: `~/karadul_olcum/ghidra_kuyruk.bekle.<PAKET>` ile uzun işli paket geçici bekletilir. Süre ölçmeyen koşular için 2 yuva önerildi (Berke'nin kararı bekliyor).
- Her gönderimde sert son (saat) yazılır; ajanlar "kalan" listesiyle döner.
- Gerçek uygulama sayısı her raporun ilk satırıdır ([[feedback-gercek-uygulamada-olc]] hafıza kaydı).
