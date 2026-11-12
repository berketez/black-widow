# Karadul — kısa kullanma kılavuzu

Sürüm 1.23.1 için. Yöntemlerin ayrıntısı kitaplarda; bu sayfa yalnız günlük kullanımı anlatır.

## 1. Ne yapar, ne yapmaz

- Derlenmiş bir programı Ghidra ile C benzeri koda çevirir. Üstüne fonksiyon adı önerir, bazı tipleri kurtarır, yorum ve rapor yazar.
- Motor LLM kullanmaz; aynı girdi aynı çıktıyı verir. Ağ kapalıdır, hedef program çalıştırılmaz.
- **Ad konusunda temkinlidir.** Emin olmadığı fonksiyona ad vermez; küçük bir programda hiç fonksiyon adı çıkmayabilir. Adsız fonksiyon `FUN_<adres>` olarak kalır.

## 2. Kurulum

```bash
git clone https://github.com/berketez/black-widow.git && cd black-widow
python -m venv .venv && source .venv/bin/activate
pip install -e ".[ghidra,binary,perf]"
export GHIDRA_INSTALL_DIR=/yol/ghidra_12.1.2_PUBLIC
```

- Python 3.11 ya da üstü, Ghidra **12.1.2** ve Ghidra'nın desteklediği bir JDK gerekir.
- Başka Ghidra sürümü uyarıyla çalışır; çıktı farklı olabilir.

## 3. Komut satırı

`karadul …` ile `python -m karadul …` aynıdır.

| Ne istiyorsun | Komut |
|---|---|
| Tam analiz, temiz çıktıyla | `karadul analyze /yol/ikili --output ./cikti` |
| Yalnız decompile et, orada dur | `karadul analyze /yol/ikili --stage static` |
| Sonucu JSON olarak al | `karadul analyze /yol/ikili --json` |
| Dosya türü, dil, boyut, SHA-256 | `karadul info /yol/ikili` |
| Önceki analizleri listele | `karadul list` |
| Bir hedefin çalışma alanını sil | `karadul clean <hedef>` |
| Etkin ayarları gör, doğrula | `karadul config show`, `karadul config validate` |
| İki ikiliyi karşılaştır | `karadul diff <a> <b>` |

Sık kullanılan seçenekler (`analyze`):

- `--output DIR`: temiz çıktı dizini. Vermezsen yalnız çalışma alanı yazılır.
- `--output-dir DIR`: çalışma alanının kökü (öntanımlı `./workspaces`).
- `--deep` ya da `--compute full`: daha ağır tip ve yapı kurtarma; yavaştır.
- `--config dosya.yaml`: ayar dosyası.
- `--online`: ağ erişimini açar (öntanımlı kapalı).
- `--dynamic`: **hedefi Frida ile çalıştırır.** Yalnız güvendiğin ikilide kullan.
- `-q`: yalnız son sonucu yazar.

## 4. Çıktıyı okumak

Temiz çıktı (`--output DIR`):

```
DIR/
  src/                   # yeniden kurulmuş proje: Makefile, CMakeLists.txt, include/,
                         #   src/ (alt sistemlere ayrılmış C dosyaları), analysis/
  naming_map.json        # eski ad → yeni ad
  dependency_graph.json  # çağrı ilişkileri
  report.json, report.html
  README.md
```

Her adın yanında bir etiket vardır:

| Etiket | Anlamı |
|---|---|
| `kesin` | Ad, ikilinin kendi ad yuvasından okundu. Bu kanalın tam ad doğruluğu ölçümde hedefi tuttu |
| `doğrulandı` | Kanal ölçüldü, yanlış oranı hedefin altında |
| `doğrulanmadı` | Kanal ölçülmedi ya da hedefi tutmadı. İpucu say, ad sayma |

- Güven sayıları kalibre değildir; sıralama için kullan, olasılık sanma.
- `ALGORITHM:` yorumları örüntü sezgiseldir; doğruluğu ölçülmedi.
- Ham ara çıktılar çalışma alanındadır: `workspaces/<hedef>/<zaman>/{raw,static,reconstructed,reports}`.

## 5. Arayüz

```bash
python ui/server.py        # tarayıcıda http://127.0.0.1:8000 (kapı: KARADUL_PORT)
```

1. **Giriş:** ikilinin yolunu ya da uygulama adını yaz, **ANALİZ ET**'e bas. Aşamalar gerçek ilerlemeyle gösterilir.
2. **Sonuç:** ortada çağrı haritası, solda fonksiyon listesi. Haritada seçili fonksiyonun çağırdıkları solda, çağıranları sağdadır.
3. **Arama ve süzgeç:** ad ya da adres ara. Süzgeçler: Tümü, İsimsiz, Zayıf, Düzeltilen.
4. **Kod paneli:** fonksiyona tıklayınca decompile edilmiş kod açılır. Adsız fonksiyonda en üstte **NEDEN İSİMSİZ?** bölümü, altında kanıt görünür: çağırdıkları, çağıranları, başvurduğu dizgiler.
5. **Ad düzeltme:** kod panelinde yeni adı yaz. Ad kalıcıdır (`~/.karadul/overrides/<sha256>.json`); aynı ikiliyi yeniden analiz edince geri gelir ve "manuel" rozetiyle görünür.
6. **Ayarlar (⚙):** profil (Hızlı, Dengeli, Derin), ad güven eşiği, kendi imza dosyaların, disk erişimi. Komut satırındaki `karadul config` ile aynı dosyayı yazar.

## 6. Sorun çıkarsa

| Belirti | Bakılacak yer |
|---|---|
| "Ghidra bulunamadı" | `GHIDRA_INSTALL_DIR` doğru mu; `karadul config validate` |
| Çok az fonksiyon | Arayüzdeki paketleyici uyarısı; ikili sıkıştırılmış olabilir |
| Hiç fonksiyon adı yok | Beklenen durum olabilir (bölüm 1). Kanıt için kod panelindeki teşhise bak |
| Analiz yarıda kaldı | Çalışma alanındaki `reports/` ve komutun çıktısı; `--stage static` ile yalnız Ghidra aşamasını dene |

## 7. Bugünkü sınırlar

- Ölçüm yalnız arm64 Mach-O ve arm64 ELF üzerinde yapıldı. Öbür biçimler tanınır ama ölçülmedi.
- C++ programları düz fonksiyon listesi olarak yazılır; sınıflar kurulmaz.
- Akış sadeleştirme öntanımlı kapalıdır.
- Hazır sürüm (DMG) yayımlanmadı; uygulama `packaging/macos/build_mac_app.sh` ile derlenir.
- Arayüzde model katmanı ("yapay zekâya sor") henüz yok.
