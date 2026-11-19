# Yayın kapısı (taslak, 2026-11-19)

Berke (2026-11-19): "uygulamayı iyice toparlayalım, artık yayına almak istiyorum, biraz erkenden"; "KaradulLM kullanmak istiyorum"; "50 MB'lık bir uygulamayı tersine mühendislikle görmek istiyorum: analist kullanır mı, işine yarar mı, IDA Pro rakibi olur mu".

Bu belge yayından önce tutması gereken koşulları sayar. Her satırın kanıtı bir dosya ya da komut çıktısıdır; "yapıldı" beyanı yetmez.

## 1. Kapı koşulları

| # | Koşul | Durum (2026-11-19 10:5x) | Kanıt |
|---|---|---|---|
| Y1 | Tam test takımı main'de 0 hata | **tuttu**: 10 289 geçti / 11 atlandı / 0 kaldı (b4be6f3) | oturum günlüğü; yeniden: `python -m pytest -q` |
| Y2 | Son doğrulama mutasyonları + 9 bayat mutasyon tanımı | açık | `gonderim/OKU.md` "2026-11-19 sonrası" |
| Y3 | Genel taramanın 137 bulgusu: kritik ve yüksek olanlarda açık kalan yok ya da gerekçeli erteleme | denetim sürüyor | `denetim_A.md`, `denetim_B.md` |
| Y4 | Masum ikili kapısı geçiyor (yanlış iddia eşiklerin içinde) | a62f15e'de geçti; main'de yeniden koşulacak | `scripts/measurement/masum_kapi.py` |
| Y5 | Bilinen ad kusuru: `oz_ad` erken dönüşü (19 doğru ad) | P12d sürüyor | `P12d.md` |
| Y6 | Gerçek büyüklükte uygulamada uçtan uca koşu: çökmeden biter, süre ve bellek kayıtlı, çıktı okunur | gösteri koşusu sürüyor (Ollama.app 0.40.3 ana ikilisi, 51,8 MB) | `gosteri/` |
| Y7 | KaradulLM gerçek modelle çalışıyor (duman listeleri: `P21.md`, `P22b.md`, `P22e.md`) | hiç koşulmadı; Y6'dan sonra | `gosteri/` |
| Y8 | macOS uygulaması derleniyor, açılıyor, bir ikiliyi uçtan uca analiz ediyor | açık (son derleme eski sürümden) | — |
| Y9 | Sürüm numarası, değişiklik günlüğü, kılavuz güncel; herkese açık depoda gizli anahtar / üçüncü taraf metni taraması temiz | açık | — |
| Y10 | Rapordaki ve arayüzdeki her sayı ölçülmüş; "ne yapmıyor" bölümü yazılı (kapsam %5,7; set içi ölçüm) | açık | — |

## 2. Yayına bilerek girmeyecekler (bayrak arkasında, kapalı)

Bekletilen katmanlar oldukları gibi kalır: yapı yeniden yazımı (P10b), FLIRT bayt imzaları (P08b), capa kod beslemesi (P03b), füzyon ad kanalı, K-4 ad kanalları (PDB dışı), yerleşim bayrağı. ARGE hatlarının (KİMLİK, ÖZ KOD, ÖLÇÜ) sonuçları yayını beklemez; sonraki sürüme girer.

## 3. Açık sorular (Berke'ye)

- Yayın biçimi: yalnız kaynak (GitHub) mı, DMG de mi?
- Push: main origin'in önünde; Y2'den sonra sorulacak.
