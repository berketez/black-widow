# Yayın kapısı (taslak, 2026-11-19)

Berke (2026-11-19): "uygulamayı iyice toparlayalım, artık yayına almak istiyorum, biraz erkenden"; "KaradulLM kullanmak istiyorum"; "50 MB'lık bir uygulamayı tersine mühendislikle görmek istiyorum: analist kullanır mı, işine yarar mı, IDA Pro rakibi olur mu".

Bu belge yayından önce tutması gereken koşulları sayar. Her satırın kanıtı bir dosya ya da komut çıktısıdır; "yapıldı" beyanı yetmez.

## 1. Kapı koşulları

| # | Koşul | Durum (2026-11-19 10:5x) | Kanıt |
|---|---|---|---|
| Y1 | Tam test takımı main'de 0 hata | **tuttu**: 10 289 geçti / 11 atlandı / 0 kaldı (b4be6f3) | oturum günlüğü; yeniden: `python -m pytest -q` |
| Y2 | Son doğrulama mutasyonları + 9 bayat mutasyon tanımı | açık | `gonderim/OKU.md` "2026-11-19 sonrası" |
| Y3 | Genel taramanın 137 bulgusu: kritik ve yüksek olanlarda açık kalan yok ya da gerekçeli erteleme | **denetim bitti** (HEAD 2381dce): 137 bulgunun 115'i kapandı, 17'si kısmen, 1'i bekletildi, 4'ü açık (hepsi düşük). Kritik 11'in 10'u kapandı, 1'i kısmen (IMZA-01); yüksek 47'nin 45'i kapandı, 2'si kısmen (BICIM-09, LM-08). Ek: .NET çıktısında `Directory.Build.props` / `.targets` süzülmüyor (numarasız risk). Ayrıntı §4 | `denetim_A.md`, `denetim_B.md` |
| Y4 | Masum ikili kapısı geçiyor (yanlış iddia eşiklerin içinde) | **main'de tutmadı** (doğrudan kip, 4 set, 2381dce): tek aşım `bi / macos` yanlış 217 > eşik 215; öbür katmanlar eşik içinde. Çıktı kipi main'de koşulmadı (119 ikilik ürün koşusu ister) | `~/karadul_olcum/runs/yayin-2026-11-19/masum_dogrudan/masum_kapi.md` |
| Y5 | Bilinen ad kusuru: `oz_ad` erken dönüşü (19 doğru ad) | P12d sürüyor | `P12d.md` |
| Y6 | Gerçek büyüklükte uygulamada uçtan uca koşu: çökmeden biter, süre ve bellek kayıtlı, çıktı okunur | **ilk deneme tutmadı:** Ollama.app 0.40.3 ana ikilisinde (51,8 MB, arm64 dilimi) Ghidra'nın "Objective-C Message Analyzer" çözümleyicisi tek fonksiyonda 22 dk döndü; ekrana ve günlüğe 27 dk hiçbir şey yazılmadı; öntanımlı süre sınırı 7 200 sn (büyük ikilide × 4). Koşu durduruldu; çözümleyici kapalı ikinci koşu sürüyor. Ayrıntı §5 | `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/` (`deneme1_jstack.txt`, `gosteri.yaml`) |
| Y7 | KaradulLM gerçek modelle çalışıyor (duman listeleri: `P21.md`, `P22b.md`, `P22e.md`) | hiç koşulmadı; Y6'dan sonra | `gosteri/` |
| Y8 | macOS uygulaması derleniyor, açılıyor, bir ikiliyi uçtan uca analiz ediyor | açık (son derleme eski sürümden) | — |
| Y9 | Sürüm numarası, değişiklik günlüğü, kılavuz güncel; herkese açık depoda gizli anahtar / üçüncü taraf metni taraması temiz | açık | — |
| Y10 | Rapordaki ve arayüzdeki her sayı ölçülmüş; "ne yapmıyor" bölümü yazılı (kapsam %5,7; set içi ölçüm) | açık | — |

## 2. Yayına bilerek girmeyecekler (bayrak arkasında, kapalı)

Bekletilen katmanlar oldukları gibi kalır: yapı yeniden yazımı (P10b), FLIRT bayt imzaları (P08b), capa kod beslemesi (P03b), füzyon ad kanalı, K-4 ad kanalları (PDB dışı), yerleşim bayrağı. ARGE hatlarının (KİMLİK, ÖZ KOD, ÖLÇÜ) sonuçları yayını beklemez; sonraki sürüme girer.

## 4. Denetimden çıkan yayın işleri (sonraki oturum, Opus)

Kaynak: `denetim_A.md` §6–§8, `denetim_B.md` (yayını durduranlar, ertelenebilirler). Durdurucu sayılıp sayılmayacağı Berke'nin kararı; aşağıdaki sıra ana oturumun önerisi.

| # | İş | Neden | Dosya |
|---|---|---|---|
| D1 | .NET çıktısında `Directory.Build.props` / `*.targets` / `*.props` adlı gömülü kaynakları proje köküne kopyalama | Analist projeyi açınca MSBuild kendiliğinden içe alır: kod yürütme riski (BICIM-04 sınıfı). Küçük onarım | `karadul/analyzers/dotnet_binary.py` |
| D2 | IMZA-01 kalanı: zayıf kanıtlı alt sistem satırları (119 ikilide 455 iddia) raporda "zayıf ipucu, doğrulanmadı" etiketi alsın ya da kanıt kuralı sıkılaşsın; `bi / macos` 217 > 215 aşımının nedeni bulunsun | Kritik bulgunun kısmen kalan yarısı + Y4 | `karadul/analyzers/binary_intelligence.py`, `scripts/measurement/masum_kapi_esik.json` (yalnız ana oturum yazar) |
| D3 | BICIM-09: `.app` paketindeki çerçeve ve dylib'ler süre sınırı olmadan Ghidra'ya veriliyor | Büyük `.app` saatler sürer; Electron `.app` uçtan uca hiç koşulmadı | `karadul/core/target.py` |
| D4 | Evrensel Mach-O'da anti-debug dedektörü x86_64 dilimini, ürün arm64 dilimini okuyor | Tutarsız dilim (denetim A'nın yeni gözlemi) | anti-debug tarayıcısı |
| D5 | Hakkında paneli hâlâ 1.22.1 ölçümünü gösteriyor; gnulib güven satırı 0,706 (ölçülen 733 / 733) | Y10: gösterilen her sayı güncel ölçüm olmalı | arayüz, `karadul/core/naming_labels.py` + `tests/test_p12a_on_ad_guveni.py` |
| D6 | LM-08 / Y7: KaradulLM gerçek modelle hiç koşulmadı | Ölçüm işi; gösteri koşusundan sonra | — |
| D7 | Yayın notu "bilinen kusurlar": PDB kanalı gerçek koşuda ölçülmedi; imza veritabanı (2,9 GB) depoda yok, kaynaktan kuran ~7,7 bin yerleşik adla çalışır; parametre adı kesinliği %2,8–%6,7; `undefined8 → uint64_t` öntanımı %74 yanlış (P18 yaması 78 testi kırıyor); capa'da zaman aşımı yok (P03b) | Dürüst yayın notu (Y10) | değişiklik günlüğü, kılavuz |

## 5. Gösteri koşusundan çıkan yayın işleri (sonraki oturum, Opus)

| # | İş | Kanıt |
|---|---|---|
| G1 | Ghidra otomatik analizinde ilerleme görünmüyor: 27 dk boyunca ekran ve `kosu.log` yalnız "Pipeline" başlığını gösterdi. Kullanıcı donmuş sanır. Çözümleyici adı + geçen süre + işlenen fonksiyon sayısı akmalı | `deneme1_kosu.log` |
| G2 | Takılan çözümleyici bekçisi: tek çözümleyici N dakikadır ilerlemiyorsa (ör. aynı iş parçacığı aynı yığında) uyar, kapatıp sürdürmeyi öner ya da öntanımlı kural koy. Öntanımlı sınır 7 200 sn × 4 büyük ikili çarpanı fazla uzun | `karadul/config.py` `Timeouts.ghidra`, `large_binary_timeout_multiplier`; `karadul/ghidra/headless.py:_run_auto_analysis` |
| G3 | Mach-O + Go içeren ikilide "Objective-C Message Analyzer" öntanımda kapatılsın mı: ölçerek karar (çıktıya etkisi; `objc_msgSend` çözümlemesi kaybı) | `deneme1_jstack.txt` (10 düzey `getAddressFromVarnode` özyinelemesi) |
| G4 | Go ikilisi: Ghidra "Untested Go version [1.26.0] … unable to extract Go RTTI info" diyor; Karadul'un Go kanalı (pclntab) K-4 ile kapalı. Bu ikilide Go adlarının ne kadarı kurtarılabilir, ölçülmeli | Ghidra `application.log` 2026-11-19 10:42 |

## 3. Açık sorular (Berke'ye)

- Yayın biçimi: yalnız kaynak (GitHub) mı, DMG de mi?
- Push: main origin'in önünde; Y2'den sonra sorulacak.
