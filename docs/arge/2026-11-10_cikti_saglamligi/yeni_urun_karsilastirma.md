# Çıktı sağlamlığı: düzeltmelerden sonra yeni ürün koşusunda yineleme

- **Tarih:** 2026-11-11.
- **Ne yapıldı:** dünkü denetim betiği (`denetle.py`, değiştirilmeden) yeni ürün koşusuna (commit 93a2956, `~/karadul_olcum/runs/urun-yeni-93a2956`, 119 ikili) yöneltildi. Sarmalayıcı: `denetle_yeni_urun.py` (betiğin kök sabitlerini değiştirir). Çıktı: `sonuc_yeni_urun.json`. GT okunmaz.
- **Karşılaştırılan:** dünkü `sonuc.json` (düzeltmelerden ÖNCEKİ ürün; 126 koşu: 119 ikili + yineleme koşuları) ↔ bugünkü (119 koşu). Dünkü sayım yineleme koşularını da içerdiği için "ikili" sütunları bire bir aynı küme değildir; büyüklük sırası karşılaştırılır.
- Komut: `python3 docs/arge/2026-11-10_cikti_saglamligi/denetle_yeni_urun.py <çıktı.json>` (3 işçi, 18 dk).
- Ghidra uyarı yorumları: ham 78186, son çıktıda 78186 (dün: 78182 / 0).

## 1. Giderilen kusurlar (32 kalem; yeni koşuda 0)

| Kusur | Eski: ikili | Eski: adet | Yeni: ikili | Yeni: adet |
|---|---|---|---|---|
| `ag_indirme_denemesi` | 2 | 2 | 0 | 0 |
| `akis_anlami_bozulan_fonksiyon` | 117 | 4930 | 0 | 0 |
| `akis_anlami_bozulan_fonksiyon_ihtiyatli` | 117 | 4243 | 0 | 0 |
| `akis_sadelestirmenin_bozdugu_fonksiyon` | 117 | 5148 | 0 | 0 |
| `akis_sadelestirmenin_bozdugu_fonksiyon_ihtiyatli` | 117 | 4661 | 0 | 0 |
| `ayracsiz_kosula_blok_gomuldu` | 117 | 4288 | 0 | 0 |
| `ayracsiz_kosula_blok_sonda_gorulen` | 117 | 3485 | 0 | 0 |
| `basarili_ama_eksik_cikti` | 35 | 35 | 0 | 0 |
| `basliksiz_c_dosyasi` | 11 | 24 | 0 | 0 |
| `belge_adres_farkli` | 119 | 20546 | 0 | 0 |
| `bozuk_govde` | 117 | 2351 | 0 | 0 |
| `cagri_azalan_fonksiyon` | 74 | 525 | 0 | 0 |
| `degisim_haritadan_farkli` | 7 | 15 | 0 | 0 |
| `disasm_satiri_degisen` | 9 | 15 | 0 | 0 |
| `dizgi_ici_undefined_degisen_fonksiyon` | 1 | 5 | 0 | 0 |
| `dizgi_kaybeden_fonksiyon` | 3 | 7 | 0 | 0 |
| `dizgi_kaybeden_sozdizimi_saglam` | 1 | 5 | 0 | 0 |
| `dusmeli_etiket_silindi` | 117 | 6988 | 0 | 0 |
| `dusmeli_etiket_silindi_ihtiyatli` | 117 | 4512 | 0 | 0 |
| `gecersiz_c_adi:anahtar_sozcuk` | 5 | 9 | 0 | 0 |
| `gecersiz_c_adi:tip_adi` | 1 | 1 | 0 | 0 |
| `ghidra_kritik_uyarisi_gizlenen` | 119 | 3092 | 0 | 0 |
| `ghidra_uyarisi_gizlenen_fonksiyon` | 119 | 41106 | 0 | 0 |
| `guven_1_yazilan_koken_dusuk` | 119 | 15674 | 0 | 0 |
| `guven_1_yazilan_koken_esik_alti` | 119 | 9211 | 0 | 0 |
| `ic_ice_yorum` | 117 | 6721 | 0 | 0 |
| `karadul_yarattigi_cift_ad_grup` | 17 | 35 | 0 | 0 |
| `out_eksik_fonksiyon` | 35 | 52 | 0 | 0 |
| `out_harita_ws_haritadan_farkli` | 3 | 3 | 0 | 0 |
| `sayi:decompile_sayisi` | 5 | 5 | 0 | 0 |
| `sayi:proje_dosya` | 31 | 31 | 0 | 0 |
| `veri_yeni_ad_kodda_yok` | 1 | 7 | 0 | 0 |

## 2. Süren kusurlar (23 kalem)

| Kusur | Eski: ikili | Eski: adet | Yeni: ikili | Yeni: adet |
|---|---|---|---|---|
| `baslik_tanim_farkli` | 5 | 20 | 5 | 20 |
| `bsim_yedege_dustu` | 82 | 82 | 78 | 78 |
| `cift_tanim_adres` | 1 | 106 | 1 | 5 |
| `decompiled_json_kirpik` | 21 | 25640 | 21 | 25640 |
| `eski_fonksiyon_adi_kodda_kalan` | 6 | 6 | 1 | 2 |
| `eski_fonksiyon_adi_yorumda_kalan` | 119 | 5209 | 117 | 1929 |
| `fonksiyon_anahtari_ghidrada_yok` | 117 | 234 | 117 | 234 |
| `gecersiz_c_adi` | 6 | 17 | 2 | 7 |
| `gecersiz_c_adi:gecersiz_karakter` | 2 | 7 | 2 | 7 |
| `harita_uygulanmayan` | 119 | 6466 | 119 | 6675 |
| `ithal_sayaci_sifir` | 119 | 119 | 119 | 119 |
| `out_harita_ozdes_esleme` | 119 | 9823 | 119 | 9823 |
| `out_proje_agacindan_farkli` | 1 | 1 | 1 | 1 |
| `readme_yapi_uyusmuyor` | 119 | 119 | 119 | 119 |
| `sayi:readme_kaynak_dosya` | 1 | 1 | 1 | 1 |
| `sayi:tur_sayisi` | 119 | 119 | 119 | 119 |
| `turlar_arasi_fonksiyon_adi_farki` | 7 | 21 | 1 | 2 |
| `yakinsama_nedeni_bilinmiyor` | 119 | 119 | 119 | 119 |
| `yeni_ad_var_olan_fonksiyonla_cakisiyor` | 18 | 35 | 1 | 1 |
| `yerel_ad_uygulanmamis_fonksiyon` | 116 | 2470 | 116 | 2420 |
| `yerel_ilk_tur_baska_adla_fonksiyon` | 30 | 110 | 34 | 122 |
| `yerel_son_tur_baska_adla_fonksiyon` | 38 | 10057 | 37 | 5356 |
| `yetim_anahtar` | 117 | 234 | 117 | 234 |

## 3. Yalnız yeni koşuda görülen (0 kalem)

| Kusur | Eski: ikili | Eski: adet | Yeni: ikili | Yeni: adet |
|---|---|---|---|---|
| — | | | | |

## 4. Sarmalayıcı kaynaklı, kusur olmayan kayıtlar

Yeni koşunun koşucusu (`scripts/measurement/urun_kos.py`) dünkü koşuculardan farklı dosya yazıyor; denetim bunları kusur sayıyor ama ürünle ilgisi yok:
- `bitmedi` 119 / 119: denetim Debian'da `BITTI` dosyasının "ok" ile başlamasını, Mac'te `run.json` bekliyor; yeni koşucu `BITTI`'ye "0" yazıyor. Koşunun bittiği koşucu künyesinden (119 tamam, 0 bitmeyen) ve ürün ölçümünün nüfus denetiminden biliniyor.
- `log_yok`, `log_yapisi_beklenmedik`, `log_yazildi_satiri_yok` ve `sayi:…` satırlarının Mac'e düşen 2-3 kaydı: denetim Mac'te `karadul.log` arıyor; yeni koşucu `kosu.log` yazıyor.

## 5. Okuma

- Dün düzeltilen sınıflar yeni koşuda sıfır: akış sadeleştirmenin bozduğu fonksiyonlar (adım öntanımlı kapalı), eksik ve düşen fonksiyonlar, iç içe yorum, yanlış `@address`, gizlenen Ghidra uyarıları, sabit 1.0 güven, C anahtar sözcüğü adlar, Karadul'un yarattığı çift adlar, değişen dizgiler, ağdan indirme denemesi.
- Süren başlıca kalemler dünkü raporun "açık" listesindekilerdir: ad haritasının kodda uygulanmayan adları listelemesi, rapor sayaçları (`tur_sayisi`, yakınsama nedeni, ithal sayacı), `decompiled.json`'ın 500'de kesilmesi, yerel adların turlar arasında farkı, eski fonksiyon adının yorumda kalması, BSim'in paralel koşuda yedeğe düşmesi.
- Küçük ama gerçek üç kalem: Mach-O'da `$` içeren ad (`signature_db` kaynağı ad süzgecinden geçmiyor; 2 ikili), Debian htop'ta var olan fonksiyonla çakışan bir gnulib adı (derlemeye bağlı üç girdiden biri), C++ `pzstd`'de çift tanım.
- Bu denetim adların doğru olup olmadığını yargılamaz; o ölçüm `docs/arge/2026-11-10_n1_adim3/urun_olcumu_sonuc.md`'dedir.
