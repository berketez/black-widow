# KS-1 ön kaydı: sapma kaydı 1

- **Tarih:** 2026-11-10.
- **Ön kayıt:** `ks1_onkayit.md`, commit a22d833 (kod 0ef69b8). Bu kayıt onu değiştirmez; yalnız aşağıdaki maddeleri ekler. Çelişen yerde bu kayıt geçerlidir.
- **Durum:** Ölçüm sonucu görülmeden yazıldı (§2). Bu belge ve `ks1_sapma_1_sabitler.json` aynı commit'te depoya girer; `ks1_olc.py olc` sha256'ları o commit'ten okur ve o commit'in ön kayıt commit'inden sonra geldiğini denetler.

## 1. Ne oldu

Ön kayıt commit'inden (a22d833) hemen sonra ölçüm koşuldu:

```
python scripts/measurement/ks1_olc.py olc --mac-kosu workspaces/olcum_mac/runs/ol7-a-9a36142 \
    --debian-kosu ~/karadul_olcum/n1_debian13 --json … --md …
DURDU: libstdbuf.so: ofset Ghidra entry'den türetilemedi (kaynak: default)
```

Betik çıkış kodu 2 ile durdu ve hiçbir çıktı dosyası yazmadı.

**Neden:** ön kayıt §6 ve §11, ELF'te ofsetin Ghidra'nın `entry` fonksiyonundan türetilmesini şart koşuyordu (taslaktaki "sessizce varsayılan tabana düşme" açığını kapatmak için). Bu koşul dondurulmadan önce geliştirme setinin bütün ELF'lerinde sınanmamıştı. Sınanınca (GT'siz, §3) 117 ELF'in 6'sında Ghidra'da `entry` adlı fonksiyon olmadığı görüldü:

| ELF | Birim | `e_entry` | Neden `entry` yok | İç fonksiyon | Dizgi çapası | Export çapası |
|---|---|---|---|---|---|---|
| `libstdbuf.so` | `debian/coreutils` | 0 | giriş noktası olmayan paylaşımlı nesne | 9 | 0 | 0 |
| `htop` | `debian/htop` | 0x13080 | `-rdynamic`: Ghidra girişi dinamik simge tablosundan `_start` diye adlandırıyor | 609 | 0 | 366 |
| `redis-benchmark` | `debian/redis-tools` | 0xa000 | aynı | 477 | 13 | 384 |
| `redis-check-aof` | `debian/redis-tools` | 0x7fa00 | aynı | 4710 | 9 | 3786 |
| `redis-check-rdb` | `debian/redis-tools` | 0x7fa00 | aynı | 4710 | 9 | 3786 |
| `redis-cli` | `debian/redis-tools` | 0x29d40 | aynı | 634 | 25 | 438 |

Koşul olduğu gibi kalsaydı `debian/redis-tools` biriminin tamamı (`assert` satırının üç programından biri) ölçülemezdi. Hata ön kaydı yazan ana oturumundur: koşul, ölçülebilirliği GT'siz denetlenmeden donduruldu.

## 2. Ölçüm sonucu görüldü mü

Hayır.
- Duran koşu sırayla Mac tmux, Mac htop ve coreutils'in `libstdbuf.so`'dan önceki ELF'leri için GT'yi bellekte yükledi ve çapaları değerlendirdi; ardından istisnayla durdu. Hiçbir kesinlik, kapsam ya da GT adı ekrana ya da dosyaya yazılmadı. Betiğin tek çıktısı yukarıdaki `DURDU` satırıdır.
- §3'teki teşhis betikleri `function_f1.extract_gt`'yi 117 ELF için çağırdı ve sonucu attı; yazdıkları yalnız "tamam" sayısı ve hata iletileridir. Amaç, ikinci denemenin başka bir ön koşulda durmayacağını görmekti.
- Bu kayıttaki karar yalnız ELF başlıklarına ve Ghidra çıktısına dayanır; hiçbiri GT değildir.

## 3. GT'siz teşhis (2026-11-10)

Girdi: analiz edilen (strip'li) ikililerin ELF başlıkları (`raw/target_info.json`'daki yol), `ghidra_functions.json`, `ghidra_combined_results.json`.

| Ölçü | Sonuç |
|---|---|
| ELF türü | 117/117 `ET_DYN` |
| En düşük `PT_LOAD` sanal adresi | 117/117 `0x0` |
| Ghidra'nın kaydettiği görüntü tabanı (`program_info.image_base`) | 117/117 `0x100000` |
| `entry` fonksiyonu olan ELF | 111 |
| Bunlarda `entry` adresi − `e_entry` = görüntü tabanı − en düşük `PT_LOAD` | 111/111 |
| `entry` yok, `e_entry` ≠ 0 | 5; hepsinde `görüntü tabanı + e_entry` adresinde thunk olmayan bir Ghidra fonksiyonu (`_start`) başlıyor |
| `entry` yok, `e_entry` = 0 | 1 (`libstdbuf.so`) |
| Ön koşulların kuru denetimi (sha256, build-id için tam bir hata ayıklama dosyası, `extract_gt` istisnası) | 117/117 tamam; 0 hata |

PIE tabanının 0x100000 olduğu T0b'de (a10fde3) 22 ikilide üç bağımsız yoldan ayrıca doğrulanmıştı.

## 4. Sapma

**S1. Ofset kanıtı** (ön kayıt §6 "Adres eşleme" ve §11'deki "ofset Ghidra'nın `entry`'sinden türetilmiş" maddesinin yerine):
- ELF'te ofset = Ghidra'nın görüntü tabanı (`ghidra_combined_results.json`, `program_info.image_base`) − ELF'in en düşük `PT_LOAD` sanal adresi (analiz edilen ikilinin başlığından).
- Çapraz denetimler; biri tutmazsa ölçüm durur:
  1. Ghidra'da `entry` fonksiyonu varsa, ondan türetilen ofset (`function_f1.derive_image_offset`) bununla aynı olmalı.
  2. ELF'in giriş adresi sıfır değilse, Ghidra'da `ofset + giriş adresi`'nde bir fonksiyon başlamalı.
- Görüntü tabanı kayıtlı değilse ölçüm durur; varsayılan tabana düşülmez.
- Çıktıda ELF başına kanıt yazılır: `goruntu_tabani+ghidra_entry` (iki kanıt) ya da `goruntu_tabani` (`entry` yok).
- Gerekçe: görüntü tabanı Ghidra'nın programı yüklediği adresin doğrudan kaydıdır; `entry` adı ise girişin dinamik simge tablosunda bulunup bulunmamasına bağlıdır. Yeni kural taslaktaki açığı (kanıtsız varsayılan) kapalı tutar ve 117 ELF'in hepsini ölçülebilir kılar.
- `libstdbuf.so` yalnız görüntü tabanına dayanır (giriş adresi yok). Dizgi çapası olmadığı için hiçbir karar satırını etkilemez; yalnız coreutils'in kapsam paydasına 9 fonksiyonun bir bölümüyle girer.

**S2. Sapma kaydının denetimi** (ön kayıt §11'e ek):
- `olc`, ön kayıt commit'inin HEAD'in atası olduğunu denetlemeyi sürdürür.
- Ek olarak bu belgeyi depoya ilk ekleyen commit HEAD'in atası ve ön kayıt commit'inin torunu olmalıdır; aynı commit olamaz.
- Ölçümü belirleyen altı dosyanın sha256'sı o commit'teki `ks1_sapma_1_sabitler.json` ile karşılaştırılır. Kod bundan sonra değişirse betik ölçmez; yeni bir sapma kaydı gerekir.
- Çıktıya iki commit de yazılır.

**Değişmeyenler:** çıkarıcı (`kesin.py`, sha256 aynı), ad karşılaştırması, kesinliğe giren öğeler, karar kuralı ve eşikler, nüfus tanımı, birimler, program sınıfı kilidi, GT'siz sayım (`ks1_say.json`, `ks1_sinif.json`). Ön kayıt §8'deki "ölçümden önce bilinenler" aynen geçerlidir.

## 5. Değişen dosyalar

`git diff a22d833 -- scripts/measurement/ks1_olc.py tests/test_ks1_olc.py scripts/measurement/mutation_specs_ks1.json tests/test_tarif_kesin.py`

- `scripts/measurement/ks1_olc.py`: `ghidra_goruntu_tabani`, `en_dusuk_yukleme_adresi`, `elf_ofseti`; `gt_elf` ofseti bunlardan alır; `onkosullari_denetle` sapma kaydını tanır; `sabitle --sapma`; özet çıktısında sapma commit'i.
- `tests/test_ks1_olc.py`: ofset kanıtı (iki kanıt, yalnız taban, giriş adresinde fonksiyon yok, taban yok, çelişki, sıfır olmayan yükleme adresi, giriş noktasız nesne), sapma kaydı ön koşulları, görüntü tabanının okunması.
- `scripts/measurement/mutation_specs_ks1.json`: bir mutant çıktı (`olc_ofset_kaynagi_denetlenmez`; denetlediği satır kalktı), sekiz mutant eklendi.
- `tests/test_tarif_kesin.py`, `kesin.py` ve ölçüm yardımcıları değişmedi.

**Sabitlenen dosyalar** (tam sha256'lar `ks1_sapma_1_sabitler.json`'da):

| Dosya | sha256 | Ön kayda göre |
|---|---|---|
| `karadul/reconstruction/tarif/kesin.py` | `2a412e8a4467cff152a8ed271d0216a5fcb3038f1299ca6e8927e3319838cc48` | aynı |
| `scripts/measurement/ks1_olc.py` | `975c4d1265d8610efd03e5a9c9d55cdd784b1ba9b7720d304ff00e7776418fb9` | **değişti** |
| `scripts/measurement/function_f1.py` | `edc782981f98abc6683dec0ee948c7caafcbeaf01759fdc8ddc14dd8586c4bdc` | aynı |
| `scripts/measurement/macho_f1.py` | `bc48eac6fe1f2879374f17a5ba198672718f43e648df0b84d18b3e21e7705f43` | aynı |
| `scripts/measurement/macho_measure.py` | `d4d517fd43e835ea1546f51186e7167b732d7b4551826ef3353e6009916667d8` | aynı |
| `tests/benchmark/metrics.py` | `114456c29af17fb9451a23ede4a2bf071cb02295372b91c25d46878c8240fd09` | aynı |
| `tests/test_tarif_kesin.py` | `02c716c633ba4d8b99cfe9e4ece1fbd5459e6482eb4fdc6464bd1ea074d9c76a` | aynı |
| `tests/test_ks1_olc.py` | `9ffacd25bd5b298724b2e86fa8e43959867c49eb3bcb64be43c3964bddbb24b2` | **değişti** |
| `scripts/measurement/mutation_specs_ks1.json` | `4628af9877f7d7802843942c5832b211238223dd954ba91e90a7bc9e15e05db8` | **değişti** |

**Testler ve mutasyon:**
- `python -m pytest tests/test_tarif_kesin.py tests/test_ks1_olc.py -q -p no:cacheprovider`: 143 test geçti.
- `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_ks1.json`: 67 mutant, 67'si öldü (0 hayatta, 0 hata) (deponun yalıtılmış kopyasında; kopyadaki dosyaların sha256'ları yukarıdakilerle aynı).

## 6. Ders

Ölçümü durduran bir ön koşul, dondurulmadan önce bütün nüfusta GT'siz kuru koşuyla sınanır. Bu oturumda sınanmadığı için ilk ölçüm denemesi boşa gitti ve bu kayıt gerekti. `olc`'ye GT'ye dokunmadan yalnız ön koşulları denetleyen bir kuru kip eklenmesi sonraki ön kayıtlar için açık iştir.
