## [1.24.1] - 2026-11-18 (genel taramanın onarımı: güvenlik, dürüst tespit, ad çekirdeği, arayüz)

Yeni özellik ve hata düzeltmesi birlikte: 1.23.1 → 1.24.1. 2026-11-18 genel taramasının (137 bulgu)
onarımının ilk günü: güvenlik açıklarının hepsi ve analisti yanıltan çıktıların çoğu kapandı. Her
paketin önce / sonra sayıları, ön kayıtları ve tutmayan hipotezleri `docs/arge/2026-11-18_onarim/`
altında (`DURUM.md` özet). Ad haritası bilerek değişti (aşağıda "Ad çekirdeği"); 119 ikilik birleşik
ürün ölçümü henüz koşulmadı — ad sayılarının tabanı hâlâ 1.22.1 ölçümü. Tam test takımı: TAKIM.

### Güvenlik
- Hedef çalıştırma kapıları: YAML'daki `"false"` dizgisi çalıştırma kapısını açıyordu; `karadul run`
  analiz edilen kodu kapısız ve ağ ayarına bakmadan çalıştırıyordu; Frida ile başlatılan süreç
  kancasız sürdürülüyor ve öldürülmüyordu. Üçü de kapandı; hedef yalnız açık izinle çalışır.
- Ağa çıkan yollar `network.enabled` kapısından geçiyor: JS ad hattı ağ ayarına bakmadan
  unpkg.com'a gidiyordu; kaynak eşleme ve `.d.ts` indirmesi ana anahtarı izliyor, indirip derleyen
  başvuru yolu yalnız açıkça `true` ise.
- Native olmayan hatlarda düşman girdiler (ASAR, JAR, .NET, PyInstaller): yol geçişi ve başka
  dosyaya yazma kapandı; ASAR ağdan indirilen `npx` paketi yerine Python'da açılıyor.
- Uygulamanın açılıştaki GitHub güncelleme sorgusu öntanımlı KAPALI ve ağ ayarına bağlı.
- `karadul clean . --yes` bütün çalışma alanlarını siliyordu → reddediliyor.

### Dürüst tespit (sahte iddialar kaldırıldı)
- İkili istihbarat: geliştirme setinde iddia 2 267 → 646 (Bluetooth / OpenGL / Browser Engine
  sahte iddiaları 0).
- Anti-debug / paketleyici: masum PE'de MED/HIGH 21 → 0, FSG 30 → 0; UPX korundu.
- YARA: masum setlerde yanlış iddia 70 / 127 / 71 → 0. capa ilk kez çalışıyor (desteklenmeyen
  biçimlerde neden yazıyor); koda yorum / ad olarak girmesi öntanımlı kapalı.
- Algoritma ve güvenlik etiketleri: Galois 172 → 0, sahte `@security` yorumları 0 (çağrı kanıtlı
  olanlar kaldı). Bileşim şablonları ve yapısal yorumlar doğrulanana kadar raporda bekletiliyor.
- Raporlar tek veri katmanından: dört üretici aynı durumu söylüyor; uydurma sayaç 42 → 0.
- Tarama aşamaları her koşulda gerçek durumunu yazıyor (`calisti / kismi / hata / arac_yok /
  desteklenmiyor / kapali` + neden).

### Ad çekirdeği
- Ad haritası `PYTHONHASHSEED`'den bağımsız (aynı girdi, iki tohum: ad haritası ve `out/src` bayt
  bayt aynı).
- Ön adlara sabit 0,95 yerine kanalın ölçülmüş kesinliği (Wilson alt sınırı); ölçülmemiş kanalda
  `null`.
- Yerel adlar fonksiyon başına numaralanıyor (açıklanamayan `buf_308` türü ek 46 730 → 0).
- Geri çağrı / karşılaştırıcı rolü fonksiyon adı yapılmıyor; rol kanıtı köken kaydında
  (`role_evidence`). Kanıtlı "rol + öğe" adı sonraki iş.
- Parametre adları: kodda geçersiz / anahtar sözcük / tip adı parametre adı 2 249 → 0; işaretçiye
  skaler ad 656 → 0; kanıtsız `str` 725 → 0.
- İmza veritabanı yeniden kuruldu (kitaplık iddiası kesinliği 0,695 → 0,975); yeni veritabanı
  henüz kendiliğinden devreye girmiyor.
- GNULIB

### Tip ve yapı
- `types.h`'ye kanıtsız yapı 4 109 → 0 (adaylar ayrı dosyada); Ghidra'nın somut tipini ezen
  yazım 1 254 → 0.
- Yapı kurtarma ikinci kez koşmuyor, kaynak ağaca kopya dosya yazmıyor; Ghidra alan adını ezmiyor.
- MaxSMT yapı kurtarmada alan ofseti doğru varnode'dan (ofset 433 olan erişim 173 882 → 0); CFG-iso
  gerçek komut adlarıyla; hesaplama füzyonu ölçülmüş kesinlikle (öntanımda ad haritasına bağlı değil).

### Boru hattı ve CLI
- Çıkış kodları: 0 tam / 1 başarısız / 2 kullanım-ayar / 3 kısmi; katı YAML yükleyicisi (hatalı
  anahtar artık açık hata); okunmayan ayarlar uyarıyor.
- Belirlenimci hata aşamayı 4 kez yerine 1 kez koşturuyor; aynı saniyede başlayan koşular ayrı
  çalışma dizini alıyor; paralel adımlar arasındaki yerinde yazma yarışı kapandı; `karadul batch`
  hedef durumunu dürüst sayıyor.
- Ghidra: decompile sırası ve dosya adları belirlenimci, kırpma ve atlama kayıtlı, sayaç program
  fonksiyonunu sayıyor; BSim süreçler arası kilitli, sembollü kopyadan ad sızdırmıyor.
- `stages.py`: ölü monolit ve her ikilide ikinci kez koşan blok silindi (5 985 → 2 885 satır; çıktı
  aynı). Eski Ghidra betikleri (`legacy/`) ve kullanılmayan kalibrasyon modülü silindi.

### Arayüz
- Hakkında notu ölçülmüş sayıları gösteriyor; ayarlar dosyayı birleştirerek yazıyor; etkisiz
  "Maks. fonksiyon" kalktı; ağ düğmesi gerçek etkisini gösteriyor.
- Analiz iptal edilebiliyor, sayfa yenilenince süren işe bağlanıyor; kısmi / başarısız aşama
  görünüyor; ad düzeltme doğru ikiliye kalıcı yazılıyor; uydurma kısa ad ve "çözüldü" sayacı yok.

### KaradulLM
- Denetim katmanı (kanıtsız ad, enjeksiyon), kopma / iptal / yetim sunucu düzeltmeleri.
- KARADULLM_P22A

### Bilinen açıklar
- Birleşik ürün ölçümü (119 ikili) koşulmadı. Bekletilen katmanlar (K-1: bileşim şablonları,
  yapı yeniden yazımı, capa'nın kod beslemesi, füzyon ad kanalı) öntanımda kapalı.
- Sıradaki paketler ve açık bulgular: `docs/arge/2026-11-18_onarim/gonderim/OKU.md`.
