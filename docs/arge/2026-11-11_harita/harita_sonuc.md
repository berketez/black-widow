# Harita ölçümü: sonuç

- **Tarih:** 2026-11-11.
- **Ön kayıt:** `onkayit.md` (commit fdb4d80; ölçümden önce). Sapma yok.
- **Ölçülen ürün:** commit 93a2956 (`karadul` 1.21.1), yeni ürün koşusu. Nüfus: geliştirme seti, Debian arm64 ELF; dosya düzeyine 114 ikili, 7 program girdi. Mach-O ölçülemedi (GT derleme birimi taşımıyor).
- **Çıktı:** `harita_olcumu.json` / `.md`. Bu belgede fonksiyon adı ve kaynak dosya adı geçmez.

## 1. Sonuç (dosya düzeyi, karar düzeyi)

Soru: ürünün fonksiyonları ayırdığı modüller, fonksiyonların gerçek kaynak dosyalarıyla örtüşüyor mu? Ölçü: düzeltilmiş Rand indeksi (ARI; 0 = rastgele, 1 = tam örtüşme), program düzeyi makro.

| Bölme | ARI | Çift kesinliği | Çift duyarlılığı |
|---|---|---|---|
| Ürün (çağrı grafı toplulukları + API kuralları) | 0,097 | 0,153 | 0,418 |
| Rastgele atama (B0) | 0,000 | 0,076 | 0,267 |
| Adres sırasına göre eşit bölme (B1) | 0,424 | 0,538 | 0,447 |

| Karar | Sonuç | Beklenti (ölçümden önce) |
|---|---|---|
| (a) Rastgeleye karşı | `rastgeleden_iyi`: 7 programın 7'sinde ürün B0'ın 95. yüzdeliğinin üstünde | Tutması bekleniyordu (H1); makro ARI 0,02–0,15 öngörülmüştü, 0,097 çıktı |
| (b) Adres sırasına karşı | `taban_gecer`: makro fark −0,327; 7 programın 6'sında negatif | Tutmaması bekleniyordu (H2); B1 için 0,15–0,50 öngörülmüştü, 0,424 çıktı |

Program başına (ürün / B1): coreutils 0,335 / 0,296; htop 0,019 / 0,515; openssl 0,083 / 0,412; redis-tools 0,078 / 0,354; tmux 0,009 / 0,432; tree 0,077 / 0,492; zstd 0,079 / 0,464. Ürün yalnız coreutils'te öndedir (+0,039; eşiğin altında).

- **Ön kayıt §7 (c) dalı:** `rastgeleden_iyi` + `taban_gecer`. README'de yalnız yöntem anlatılır; alt sistem dizinlerinin kaynak yapısını yansıttığı YAZILMAZ. Plana iş kalemi açılır: yerleşimde adres sırasının kullanılması (tek başına ya da çağrı grafıyla birlikte). Bu ölçüm o işin tabanıdır.
- Aynı modüle konan iki fonksiyonun aynı kaynak dosyadan olma oranı: topluluk modüllerinde 0,040, kural modüllerinde 0,128, `misc`'te 0,056 (havuz).

## 2. Yalnız raporlananlar

- **Kaynak dosyalar adres sırasında bitişik:** bitişiklik makro 0,860; LTO'suz programlarda 0,987–1,000 (coreutils, htop, openssl, tmux, tree); zstd 0,705; LTO'lu redis-tools 0,338.
- **H3 (LTO):** redis-tools'ta B1'in üstünlüğü küçülüyor (−0,276; öbür beş negatif programın ortalaması −0,410 **[hesap]**) ama tersine dönmüyor.
- **H4 (dizin düzeyi):** `ayrismiyor` (makro fark +0,014; 3 pozitif, 3 negatif). Dizin düzeyinde ne ürün ne adres sırası kaynak dizin yapısını iyi yansıtıyor (ARI 0,085 ve 0,070).
- **H5 (`misc`):** `misc` üyeleri tekil sayılınca ARI 0,097 → 0,098; fark yok.
- GT sınıf sayısıyla bölünen adres tabanı (`b1_gt`) 0,299: daha çok parça, eşit bölmede duyarlılığı düşürüyor.

## 3. Ne anlama geliyor

- Ürünün haritası rastgele değildir, ama kaynak dosya yapısını zayıf yansıtır. Hiçbir çözümleme yapmayan "adres sırasına diz, eşit böl" yöntemi dört kattan fazla daha iyi örtüşür (ARI 0,424 ↔ 0,097).
- Neden (ölçümden önce yazılan gerekçe, taslak §1): bağlayıcı aynı derleme biriminin fonksiyonlarını yan yana bırakır; ürünün API kuralları ve çağrı grafı toplulukları ise kaynak dosyaları keser.
- Bu bir düzeltme fırsatıdır: yerleşimde adres sırası birincil sinyal yapılırsa harita belirgin iyileşir. Yeni yöntem bu sette geliştirilirse sonucu "geliştirme setinde ayarlanmış" sayılır; bağımsız iddia için doğrulama seti ve yeni ön kayıt gerekir.

## 4. Bütünlük ve sınırlar

- Betik ön kayıt commit'ini ve yedi dosyanın özetini kendisi denetledi; ölçüm koştu, yani denetim tuttu. Nüfus 119 bitti, sorun yok; koşu künyesi commit 93a2956, kirli dosya 0.
- Dışarıda kalanlar: Mach-O iki ikili (GT yok), `pzstd` (C++), dosya düzeyinde iki ikili (tek kaynak dosya; küçük nüfus).
- Eşikler (0,05 fark; 2/3 çoğunluk) keyfidir; sonuç eşikten uzak (−0,327).
- B1 tek bir basit tabandır; adres sırasından çıkarılabilecek en iyi bölme değildir.
- Yalnız Debian 13, AArch64, GCC derlemeleri; geliştirme seti. Mac için sonuç yok.
- Öbür sınırlar taslak §10'da.
