# Karadul genel tarama (2026-11-18) — bütün kulvarlar için ortak brif

Depo: `/Users/apple/Black_Widow` (dal `main`, HEAD e9d2d08, sürüm 1.23.1, çalışma ağacı temiz).
Görev: kendi kulvarındaki kodu **hata, eksik ve yanlış** için taramak ve bulguları tek bir dosyaya yazmak.
Bu bir TARAMA işidir; hiçbir şey düzeltilmez. Düzeltmeyi sonra başka ajanlar yapacak; senin dosyan onların iş emri olacak.

## 1. Ürünün amacı (bulguların önemini buna göre tart)
Karadul (Black Widow) bir tersine mühendislik aracıdır: derlenmiş bir ikiliyi (ELF, Mach-O, PE; ayrıca JS/Electron,
Java/APK, .NET, Python paketleri) alır, Ghidra'nın decompile çıktısı üstünde HESAPLAMAYLA (motor LLM kullanmaz) şunları yapar:
fonksiyon ve değişkenlere özgün ada yakın adlar verir, tip ve yapıları kurtarır, fonksiyonlar arası ilişkiyi çıkarır,
analistin okuyabileceği bir kaynak ağacı ve rapor üretir. Hedef kullanıcı: bir yazılımın zararlı olup olmadığını anlamaya
çalışan güvenlik analisti. Ölçüt: analisti YANILTMAMAK. Yanlış ad, sahte güven değeri, "başarılı" görünen boş çıktı,
dolmayan rapor bölümü, yalan sayaç en ağır kusurlardır. KaradulLM: motorun araçlarını kullanan, yerel modelle çalışan
yardımcı analist ajanı (`karadul/lm/`); arayüz: `ui/` (yerel web sunucusu + tek sayfa).

## 2. Kesin kurallar
1. **Salt okur.** Depoda YALNIZ kendi bulgu dosyanı yazarsın (`docs/arge/2026-11-18_genel_tarama/kulvar_<AD>.md`).
   Başka hiçbir dosyayı değiştirme, silme, taşıma. `git add/commit/stash/checkout/reset/worktree` YASAK. Geçici dosya
   gerekirse yalnız `$TMPDIR` altında kendi alt dizininde (`mktemp -d`).
2. Alt ajan açma. `codex`, `gemini` ya da başka bir model CLI'ı çağırma. Ağdan bir şey indirme.
3. Tam test takımını KOŞMA (ana oturum koşuyor). Bir hatayı göstermek için hedefli küçük deneme serbest:
   `PYTHONDONTWRITEBYTECODE=1 python -c "..."` ya da tek test dosyası `PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider tests/test_x.py`.
   Ghidra koşusu başlatma (ağır). Hazır gerçek çıktı gerekiyorsa SALT OKUR bak: `~/karadul_olcum/runs/urun-yeni2-f30ac9a/`
   (119 ikilinin 1.22.1 çıktısı; ad davranışı bugünküyle aynı) ve `~/karadul_olcum/runs/cikti-hatalari-2026-11-12/`.
4. Bu depoda `mdfind` boş döner (Spotlight dışı); `grep -rn` / `find` kullan.
5. Gizli dosyalara dokunma (`~/.ssh`, `.env`, anahtarlar). Bir sır görürsen değerini yazma, yalnız yerini bildir.
6. Türkçe yaz, Türkçe karakterleri doğru kullan (ç ğ ı İ ö ş ü). Kod simgeleri olduğu gibi kalır.

## 3. Önce bunu bil (tuzaklar)
- **Etkin kod ↔ ölü kod.** `karadul/stages.py`'deki monolit metotların çoğu emekli; etkin akış `karadul/pipeline/`
  (`runner.py`, `registry.py`, `steps/`). Bir kusuru raporlamadan önce o kodun bugün ÇAĞRILDIĞINI göster
  (çağıranı `grep` ile bul, bayrağın öntanımlı değerine `karadul/config.py`'den bak). Ölü koddaki hata "hata" değil
  "ölü kod" bulgusudur; ayrı etiketle.
- **Bayrak arkasındaki özellik.** Öntanımlı kapalı bir bayrağın arkasındaki kusuru bayrağı belirterek yaz.
- **Bilinenler.** `docs/arge/2026-11-18_genel_tarama/00_bilinenler.md` taramadan önce bilinen açık kusurlardır.
  Kulvarına düşenlerin bugünkü durumunu koddan doğrula ve bulgu dosyanın sonundaki "Bilinenlerin durumu" tablosuna yaz
  (duruyor / kapanmış / kısmen + kanıt). Bunları yeni bulgu diye sayma.
- **Uydurma yok.** Dosya yolu, satır numarası, fonksiyon adı, sayı: hepsi bu oturumda gözünle gördüğün şey olmalı.
  Emin olmadığını "şüphe" diye etiketle. Az ama sağlam bulgu, çok ama çürük bulgudan iyidir.
- Biçim, adlandırma zevki, eksik docstring, "şurası daha zarif olurdu" BULGU DEĞİLDİR. Aranan: yanlış sonuç üreten kod,
  sessizce yutulan hata, yanlış/sahte sayı ya da metin, hiç çalışmayan özellik, okunmayan ayar, birbirini tutmayan iki yer,
  kaynak sızıntısı / asılma, güvenlik açığı, belirlenimsizlik, test edilmemiş kritik yol, vizyona göre eksik parça.

## 4. Çalışma biçimi
- Süre hedefi 40–50 dakika. Kulvarın büyük; her satırı okuyamazsın. Önce giriş noktalarını ve veri akışını çıkar,
  sonra riskli yerlere in (hata yutan `except`, sayaçlar, eşikler, dosya yazımı, eşleme/ad atama, sınır durumları).
- **Bulguyu bulduğun an dosyana ekle** (dosyayı baştan oluştur, her bulguda büyüt). Ajan yarıda kesilirse yazdıkların kalır.
- En çok 30 bulgu. Daha fazlası varsa en önemsizleri tek satırlık "Küçükler" listesine indir.
- Bitince dosyanın sonuna tam şu satırı yaz: `## KULVAR BİTTİ`

## 5. Bulgu dosyasının biçimi

```
# Kulvar <AD> — bulgular
Kapsam: <okunan dosyalar; okunamayanlar ayrıca>
Özet: <3-5 satır: en ağır üç şey>

## <AD>-01 — <tek cümlelik başlık>
- Önem: KRİTİK | YÜKSEK | ORTA | DÜŞÜK
- Tür: hata | sessiz hata | sahte/yanlış gösterim | ölü kod | okunmayan ayar | tutarsızlık | güvenlik | belirlenimsizlik | eksik özellik | test boşluğu
- Yer: `dosya.py:satır` (gerekirse birden çok)
- Etkin mi: evet (çağıran: `x.py:satır`) | bayrak arkasında (`bayrak` öntanımlı kapalı) | ölü
- Ne: <ne yanlış; 2-6 cümle>
- Kanıt: <kod alıntısı en çok 8 satır, ya da çalıştırdığın komut + çıktısı>
- Etki: <analist ne görür / ne kaybeder>
- Güven: kesin (çalıştırıp gösterdim) | yüksek (kodu baştan sona izledim) | şüphe (şu nedenle emin değilim)
- Onarım kapsamı: <dokunulacak dosyalar; tahmini büyüklük S/M/L; varsa tehlike>
- Nasıl sınanır: <onarımdan sonra neyin geçmesi gerekir>
```

Önem ölçütü: KRİTİK = analisti yanıltan yanlış çıktı, veri kaybı, güvenlik açığı, ya da ana akışı durduran hata.
YÜKSEK = sık görülen yanlış sonuç ya da hiç çalışmayan önemli özellik. ORTA = sınırlı durumda yanlış ya da bakım yükü
doğuran ölü kod/tutarsızlık. DÜŞÜK = kozmetik olmayan ama etkisi küçük.

Son bölümler: `## Küçükler` (tek satırlık kalemler), `## Bilinenlerin durumu` (tablo), `## Bakamadıklarım` (dürüstçe),
`## KULVAR BİTTİ`.

## 6. Dönüş mesajın
Ana oturuma kısa bir özet dön: bulgu sayısı (önem dağılımıyla), en ağır üç bulgu birer cümle, bakamadığın yerler.
Bulguların tamamı dosyada; mesajda yineleme.
