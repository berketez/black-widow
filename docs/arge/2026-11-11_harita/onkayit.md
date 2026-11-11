# Harita ölçümü: ürünün modül ataması ↔ kaynak dosya yapısı — KESİN ön kayıt

- **Tarih:** 2026-11-11.
- **Durum:** KESİN. Bu belge, `harita_olc.py olc` gerçek veride hiç koşmadan ve ürün modülü ile GT etiketi hiç çaprazlanmadan önce commit'lendi. Betik bu commit'i ve `harita_sabitler.json`'daki özetleri kendisi denetler; tutmazsa ölçmez.
- **Kapsam:** kesin ön kayıt = taslak (`onkayit_taslak.md`, sha256 `1c763544199a9e2d9753c6d7579a65a143521720076e9d33a01bbad701edebc8`) + bu belgedeki kararlar. Taslağın §1–§11'i aynen geçerlidir: soru, hipotezler ve ölçümden önceki beklentiler (§1), okuma kuralları (§3), nüfus (§4), ölçüler (§5), tabanlar (§6), önceden yazılmış kararlar ve bütünlük koşulları (§7).
- **Ölçülen kol:** yeni ürün koşusu, commit 93a2956, kök `~/karadul_olcum/runs/urun-yeni-93a2956` (119 ikili bitti; ürün ölçümünün koşusuyla aynı). Mach-O ikilileri ölçüye girmez (GT'leri derleme birimi taşımıyor; taslak §3.3).
- Bu belgede fonksiyon adı ve kaynak dosya adı geçmez.

## 1. [seçim] maddeleri: karar

On yedi maddenin hepsi taslaktaki önerilen değerle karara bağlandı (taslak §12).

| # | Madde | Karar |
|---|---|---|
| 1 | Karar ölçüsü | Düzeltilmiş Rand indeksi (ARI) |
| 2 | Karar düzeyi | Dosya; dizin düzeyi yalnız raporlanır |
| 3 | Dosya etiketi | Derleme biriminin kaynak dosyasının yolu (satır tablosunun 0. dosyası) |
| 4 | LTO'lu program (redis-tools) | Karara girer; etiket köken birimi |
| 5 | İkilinin girişi | Ortak nüfus ≥ 10; GT'de en az iki sınıf ve bir çift |
| 6 | Birimin değeri | Giren ikililerin eşit ağırlıklı ortalaması |
| 7 | B1 (adres sırası) | Ürünün modül sayısı kadar, eşit, bitişik parça |
| 8 | B0 (rastgele) | 200 karma, ikiliye bağlı sabit tohum, 95. yüzdelik |
| 9 | Fark eşiği | 0,05 ARI |
| 10 | Çoğunluk | Programların 2/3'ü |
| 11 | `subsystem_misc` | Olduğu gibi modül; tekil görünüm yalnız rapor |
| 12 | Mach-O | Kapsam dışı |
| 13 | C++ ikili | Dışarıda |
| 14 | Thunk, CRT, gövdesiz adres | Nüfus dışı |
| 15 | Yolu satır tablosundan okunamayan etiket | O ikili dışarıda, sayılır |
| 16 | Adres eşleme alt sınırı | Yok (kuru koşuda oran 1) |
| 17 | Tek kaynak dosyalı ikili | Dosya düzeyinde dışarıda |

- **Karar veren:** ana oturum (Claude). Bunlar ölçümün teknik ayrıntılarıdır; Berke'nin 2026-11-11 tarihli genel "devam" talimatı altında verildi, Berke'ye tek tek sorulmadı. Eşik 9 ve 10 keyfidir (taslak §10); sonuç bu eşiklere yakın çıkarsa `ayrismiyor` okunur ve öyle yazılır.
- Ölçümden önceki beklenti (taslak §1): H1 tutar (ürün rastgeleden ayırt edilir), H2 tutmaz (adres sırası tabanı ürünü geçer; 7 programın en az 5'inde).

## 2. Ana oturumun ölçümden önce baktıkları

- Ajanın raporu ve GT'siz kuru koşu (`kuru_kosu.md`): iki taraf ayrı ayrı okundu; 116 Debian ikilisinde adres eşleme oranı 1; ortak nüfus 28 620 fonksiyon; dosya düzeyine 7 program giriyor.
- Betiğin testleri ana ağaçta koşuldu: 50 geçti.
- Koşu künyesi: commit 93a2956, kirli dosya yok, koşu boyunca ağaç değişmedi.
- Ürün modülü ile GT etiketi yan yana konmadı; `olc` çalıştırılmadı.

## 3. Komut

```
K=~/karadul_olcum/runs/urun-yeni-93a2956
python scripts/measurement/harita_olc.py olc --debian-kosu $K/debian --mac-kosu $K/mac \
    --mac-veri workspaces/olcum_mac --json docs/arge/2026-11-11_harita/harita_olcumu.json \
    --md docs/arge/2026-11-11_harita/harita_olcumu.md
```

`--eksik-izinli` kullanılmaz.
