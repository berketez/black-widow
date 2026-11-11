# N1 adım 3: ürün adlarının GT'ye karşı ölçümü — KESİN ön kayıt

- **Tarih:** 2026-11-11.
- **Durum:** KESİN. Bu belge, yeni kol (kanıtlı adlandırma açık) GT'ye karşı okunmadan önce commit'lendi.
- **Kapsam:** kesin ön kayıt = taslak (`urun_olcumu_onkayit_taslak.md`, sha256 `f1d3ed15ed5c5777c9037778e9a831021009d90b5330fef0e177146b4dd5c6cb`, commit 325c740) + bu belgedeki kararlar ve değişiklikler. Taslağın §1–§10'u, aşağıda değiştirilen yerler dışında, aynen geçerlidir. Çelişki olursa bu belge geçerlidir.
- **Karar veren:** Berke, 2026-11-11 ("önerilen değerlerle kesinleştir" sorusuna "olur"). Değerler taslağın önerileridir; yeni bir eşik eklenmedi.
- Bu belgede fonksiyon adı geçmez.

## 1. [seçim] maddeleri: karar

On üç maddenin hepsi taslaktaki önerilen değerle karara bağlandı.

| # | Madde | Karar |
|---|---|---|
| 1 | Hüküm | Tam eşitlik. Proje normalleştirmesi yalnız duyarlılık satırı |
| 2 | Kesinliğin paydası | Ad verilen bütün fonksiyonlar (nüfus dışındakiler dahil) |
| 3 | Sayım düzeyi | Örnek düzeyi (ikili başına ad). Tekil görünüm duyarlılık satırı |
| 4 | Makro | Program düzeyi; `N_MIN` = 10; `EN_AZ_PROGRAM` = 2 (`ks1_olc.py`) |
| 5 | Ad haritası | İlk yineleme (`reconstructed/src/naming_map.json`) |
| 6 | Ölçüye girmeyen girişler | `ozdes`, `ghidra_yok`, `ghidra_adli`, `jenerik_ad` sayılır, ölçülmez |
| 7 | Mac taban koşusu | `ol7-c-b7faeac`. Taban dosyası `urun_olcumu_taban_ol7c.json` (commit 1b0a930) |
| 8 | (a) yanlış oranı hedefi | Program düzeyi makro ≤ %10 (`YANLIS_HEDEFI`). Tutması beklenmiyor |
| 9 | (a) yön koşulu | İki kolda da en az 10 ad verilen her birimde yeni kolun yanlış oranı tabandan düşük |
| 10 | (b) "kesin" kesinliği | Program düzeyi makro ≥ %95 (`KESIN_ETIKET_ESIGI`). Wilson ihlali yalnız raporlanır |
| 11 | (c) kayıp sınırı | Kayıp oranı > %15 (`KAYIP_INCELEME_SINIRI`), havuzda ya da tabanda en az 10 doğru adı olan birimde → `incele` |
| 12 | (d) dallar | Taslak §7 (d) tablosu aynen: (b) tutmazsa derleme yok; (a) tutmaz (b) tutarsa derleme var, "yanlış ad vermiyor" iddiası yok |
| 13 | Bütünlük koşulları | B1–B6; biri tutmazsa ölçüm geçersiz (dal 1) |

## 2. Taslağa göre değişen yerler

1. **Taban kol (taslak §2, §5).** Karşılaştırmanın tabanı `urun_olcumu_taban_ol7c.json`'dır (Mac koşusu `ol7-c-b7faeac`; Debian koşusu aynı, `n1_debian13`). Taslağın §5 tabloları `ol7-a` tabanından yazılmıştı. İki taban arasındaki fark yalnız mac/tmux'ta: 875 addan 3'ünün hükmü değişiyor. Düzeltilmiş tabanın toplamları: havuz 6 394 ad, 1 185 doğru, 5 209 yanlış (%81,5); program düzeyi makro yanlış %92,2; kapsam 5 381 / 21 371 (%25,2); tam ad kapsamı 945 / 21 371 (%4,4). mac/tmux: 875 ad, 102 doğru. Taslağın §6 ve §7'sindeki beklentiler ve eşikler bu farktan etkilenmez.
2. **Koşum komutu (taslak §8).** `karsilastir`'ın `--taban` girdisi `urun_olcumu_taban_ol7c.json`'dır.
3. **Nüfus sayısı.** Koşulan iş sayısı 119'dur (117 Debian ELF + 2 Mac ikilisi); C++ ikili (`pzstd`) koşulur, ölçüye girmez (118).

## 3. Yeni kol: ürün ve koşu

| | |
|---|---|
| Ürün commit'i | `93a29569e4…` (93a2956; `karadul` sürümü 1.21.1). Kanıtlı adlandırma öntanımlı açık (6af0e73), ad geçerliliği süzgeci (93a2956) dahil |
| Ürünün yüklendiği ağaç | `~/karadul_olcum/urun-93a2956` (o commit'te ayrık git ağacı; izlenen dosyalarda değişiklik yok). İzlenmeyen çalışma zamanı verisi (`sigs`, `vendor`, `signatures_homebrew.json`, `signatures_homebrew_bytes.json`, `sigs_macos_system.json`) ana depodakilere bağ |
| Neden ayrı ağaç | Koşu sürerken ana ağaçta başka işler commit'leniyor; ölçülen kod karışmasın |
| Koşucu | `scripts/measurement/urun_kos.py` (bu commit). Ürünün gerçekten o ağaçtan yüklendiğini ve çalışma zamanı verisinin varlığını koşudan önce denetler; her girdinin sha256'sını taban koşusunun `raw/target_info.json` kaydıyla karşılaştırır |
| Girdi | Taban koşularının çalışma alanındaki `raw/` kopyaları (`~/karadul_olcum/n1_debian13`, `workspaces/olcum_mac/runs/ol7-c-b7faeac`) |
| Komut | `python -m karadul analyze <girdi> --skip-dynamic --output-dir <d>/ws --output <d>/out` |
| Koşu kökü | `~/karadul_olcum/runs/urun-yeni-93a2956/{debian/<program>/<ikili>,mac/<ikili>}`; künye `kosu_kunyesi.json` |
| Ortam | Ghidra 12.1.2 (`~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`), Python 3.12.7, 3 paralel, ikili başına zaman aşımı 3 600 sn, `PYTHONHASHSEED` verilmedi |
| Ayar dosyası | Yok (`--config` verilmedi); kol kimliği çıktıdan okunur (B2) |

Koşu iki çağrıyla yapıldı: önce yalnız `debian/tree/tree` (duman testi), sonra kalan 118 iş. İkisi de aynı ağaç ve aynı komut. Künye dosyası ikinci çağrıda yeniden yazıldığı için tree'nin süresi künyede yok; `BITTI` ve `kosu.log` yerinde.

## 4. Sabitlenen dosyalar (sha256, tam)

| Dosya | sha256 |
|---|---|
| `scripts/measurement/urun_olc.py` | `06131cdc55f752bcebc7a8bcfd2921ad39a2b63db3f627b9945c3e2c384380ae` |
| `tests/test_urun_olc.py` | `7ea45ab6417e096c32925095b957143a17be70b4c941d0177cb1b643aef26450` |
| `scripts/measurement/mutation_specs_urun_olc.json` | `a68ad11acec146352a07862c8159e5260829fdd403b7d9bf0e0b42e871ec12aa` |
| `scripts/measurement/ks1_olc.py` | `975c4d1265d8610efd03e5a9c9d55cdd784b1ba9b7720d304ff00e7776418fb9` |
| `scripts/measurement/function_f1.py` | `edc782981f98abc6683dec0ee948c7caafcbeaf01759fdc8ddc14dd8586c4bdc` |
| `scripts/measurement/macho_f1.py` | `bc48eac6fe1f2879374f17a5ba198672718f43e648df0b84d18b3e21e7705f43` |
| `scripts/measurement/macho_measure.py` | `d4d517fd43e835ea1546f51186e7167b732d7b4551826ef3353e6009916667d8` |
| `tests/benchmark/metrics.py` | `114456c29af17fb9451a23ede4a2bf071cb02295372b91c25d46878c8240fd09` |
| `karadul/core/naming_labels.py` | `f9c2e1d5e4b826ed4b039067ea364302ec8c337031f3e785523b4862bd220d81` |
| `karadul/reconstruction/tarif/alt_kanal.py` | `d222c812f4be18050cf084dda9fe2e70d8eae421618f98f49393da07cb133b8c` |
| `docs/arge/2026-11-10_n1_adim3/urun_olcumu_taban_ol7c.json` | `76af78b2df82cabf799193c7fd632b429adbfee11d9d1fb228eaa85252f89481` |
| `docs/arge/2026-11-10_n1_adim3/urun_olcumu_taban_ol7c.md` | `41005933958e26eb3bb6fb2ae0ceab9416fa9d0bed8b180e4a1c798794163f5d` |

- İlk on dosyanın özeti taslaktaki 16 haneli değerlerle aynı: taslaktan beri değişmediler.
- `urun_olc.py` ön kayıt commit'ini ve özetleri kendisi denetlemez. Ölçümü yapan oturum, `olc` komutundan hemen önce bu tablodaki özetleri yeniden hesaplar ve sonuç belgesine "aynı / farklı" diye yazar. Biri farklıysa ölçüm yapılmaz.
- Ölçüm ana ağaçtan koşulur; ölçüm betiği ürün sınıflayıcısını (`alt_kanal.py`, `naming_labels.py`) ana ağaçtan içe aktarır. Bu iki dosya ölçüm anında yukarıdaki özetlerde değilse ölçüm, ürün ağacı (`~/karadul_olcum/urun-93a2956`) `PYTHONPATH`'e konarak ve `--mac-veri` verilerek oradan koşulur.

## 5. Ölçüm komutları

```
K=~/karadul_olcum/runs/urun-yeni-93a2956
python scripts/measurement/urun_olc.py olc --kok-debian $K/debian --kok-mac $K/mac \
    --kol yeni --json docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni.json \
    --md docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni.md
python scripts/measurement/urun_olc.py karsilastir \
    --taban docs/arge/2026-11-10_n1_adim3/urun_olcumu_taban_ol7c.json \
    --yeni docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni.json \
    --json docs/arge/2026-11-10_n1_adim3/urun_olcumu_fark.json \
    --md docs/arge/2026-11-10_n1_adim3/urun_olcumu_fark.md
```

`--eksik-izinli` kullanılmaz. Koşucu bir ikiliyi bitiremezse (zaman aşımı ya da sıfır dışı çıkış) nedeni günlükten okunur, o ikili aynı komutla yeniden koşulur; yine bitmezse B1 tutmaz ve dal 1 işler.

## 6. Kararlar nasıl okunur

Taslak §7'deki gibi, `urun_olc.py`'nin çıktısından mekanik: (a) `kol_kararlari` yanlış oranı ve yön koşulu, (b) "kesin" etiketli adların makro kesinliği, (c) `karsilastir` kayıp oranı, (d) dallar tablosu, B1–B6 bütünlük koşulları. Beklentiler taslak §1 (H1–H4) ve §6'da ölçümden önce yazıldı: H1, H2, H4'ün tutması, H3'ün tutmaması bekleniyor.

## 7. Bütünlük kaydı (bu belge yazılırken)

**Bakıldı (yeni kol, GT'siz):**
- Duman testi çıktısı, yalnız `debian/tree/tree`: köken kaydının `silencing.enabled` (açık) ve `global_min_confidence` (0,7) alanları; ad haritasında `FUN_` anahtarlı giriş sayısı (5) ve veri anahtarı sayısı (0). Bunlar B2 ve taslak §6 madde 6 ile uyumlu.
- Koşunun ilerleme günlüğü (`kos.log`): biten ikili sayısı.

**Bakılmadı:**
- Yeni kolun hiçbir çıktısı GT ile karşılaştırılmadı; `urun_olc.py olc --kol yeni` çalıştırılmadı.
- `docs/arge/dogrulama_seti*`, `test_seti*`, `dogrulama_seti_kanit/`, `targets/`.

**Eşzamanlı işler:** bu belge yazılırken beş ajan ayrı işlerde çalışıyordu (fonksiyon kartı envanteri, harita ölçümü hazırlığı, ön ad onarımı, "yeniden hesapla" fizibilitesi, N4 yeniden kurma). Hiçbiri yeni kolun çıktısını GT ile karşılaştırmıyor; ön ad onarımı ayrı bir ağaçta ve ölçülen ürüne girmiyor.

**Yazan:** ana oturum (Claude). Eşikler taslaktaki önerilerdir; onay Berke'nin.
