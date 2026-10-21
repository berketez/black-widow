# ÖL-7 yeniden: belirlenimcilik düzeltmesinden (b7faeac) sonra iki koşu

- **Tarih:** 2026-10-21
- **Plan:** v2.2 §3, N0 (a). Yalnız ölçüm; kod değişmedi.
- **Soru:** b7faeac'teki düzeltmeden sonra aynı kodla iki koşu aynı çıktıyı veriyor mu? Düzeltme adları ve puanı değiştirdi mi?
  - Düzeltme: işçi sonuçları bitiş sırası yerine gönderim sırasıyla birleştiriliyor; fonksiyon içindeki küme dolaşımları sıralı.
- **Motor kodu:**
  - c koşusu b7faeac'te, d koşusu 1f69b35'te başladı. İkisi arasında `karadul/` farkı yok (`git diff b7faeac 1f69b35 -- karadul` boş).
  - d sürerken ana oturum motor dışı dosyaları commit'ledi (a10fde3: T0b ve literatür). Koşum aracı `engine_paths`'i boş buldu; iki koşu da geçerli.
  - İki koşuda da ağaçta motor dışı 3 kirli dosya vardı: `dwarf_tip.py`, mutasyon spec'i ve testi. Bunlar T0b'nin o anki çalışmasıydı.
- **Dosyalar:** sayılar `ol7_sayilar_b7faeac.json`'da; üreten betik değişmeden `ol7_analiz.py`. Çıktıda ad, GT adı ya da kanıt dizgisi yok.

## Yöntem

Koşular depo kökünden, sırayla yapıldı. Ortam: Ghidra 12.1.2, Python 3.12.7, `--jobs 1`. PYTHONHASHSEED tanımsızdı; ürün de böyle koşuyor, yani iki koşunun karma tohumları farklıydı.

```
python scripts/measurement/macho_measure.py analyze --tree . --label ol7-c-b7faeac
python scripts/measurement/macho_measure.py score --label ol7-c-b7faeac --reach
python scripts/measurement/macho_measure.py analyze --tree . --label ol7-d-b7faeac
python scripts/measurement/macho_measure.py score --label ol7-d-b7faeac --reach
python3 -I docs/arge/2026-10-21_g9_n0/ol7_analiz.py --data-dir workspaces/olcum_mac \
    --out docs/arge/2026-10-21_g9_n0/ol7_sayilar_b7faeac.json \
    --pair c_vs_d:ol7-c-b7faeac:ol7-d-b7faeac:htop,tmux \
    --pair c_vs_a:ol7-c-b7faeac:ol7-a-9a36142:htop,tmux
```

a koşusu (9a36142) düzeltmeden önceki koddur (`ol7_sonuc.md`).

## Sonuç

### c ↔ d: aynı kodla iki koşu

| Program | c_namer girdileri | `naming_map.json` | FUN_ farkı | Yerel ad farkı | Puan durumu değişen |
|---|---|---|---|---|---|
| htop | aynı (790/790 .c) | **bayt bayt aynı** | 0/101 | 0/2 519 | 0/597 |
| tmux | aynı (2 821/2 821 .c) | **bayt bayt aynı** | 0/875 | 0/10 977 | 0/2 561 |

Strateji başına ad sayıları da aynı. Karma tohumu farklı iki koşuda çıktı aynıdır. Düzeltmeden önce iki koşu tmux'ta 46 FUN_ adında farklıydı (`ol7_sonuc.md`).

### c ↔ a: düzeltmeden önce ve sonra

| Program | FUN_ farkı | Bunun yalnız sonek farkı olanı | Yerel ad farkı (fonksiyon) | Bunun yalnız sonek farkı olanı | Puan durumu değişen | Strateji sayıları |
|---|---|---|---|---|---|---|
| htop | 2/101 | 2 | 2 061/2 519 (630) | 2 061 | 0/597 | aynı |
| tmux | 81/875 | 81 | 9 284/10 977 (2 409) | 9 284 | 0/2 561 | aynı |

- Bütün farklar `_<sayı>` sonekinde. Sonek atılınca ad kümeleri aynı (sonek gruplarında `different_name_set` 0).
- Puan satırlarında durum geçişi yok. Tahmin metni htop'ta 2, tmux'ta 80 satırda değişti, hepsi aynı durumda kaldı.
- Girdiler (Ghidra JSON'ları, decompile .c dosyaları) iki koşuda aynı. Fark yalnız c_namer'dan doğuyor.

## Yorum

- **ÖL-7 sağlandı:** aynı girdiden, karma tohumundan bağımsız olarak aynı `naming_map` üretiliyor. Bundan sonraki A/B ölçümlerinde koşudan koşuya ad gürültüsü yok.
- **Düzeltme ad kümesini ve puanı değiştirmedi;** yalnız sonek atamasını belirlenimci yaptı. Yerel adların çoğunun sonekli olması ayrı bir ürün sorunudur: sonek havuzu bütün fonksiyonlarda ortak (C seçeneği, Faz 2).
