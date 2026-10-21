# ÖL-7: aynı commit'le iki koşu, aynı çıktı mı?

- **Tarih:** 2026-10-21
- **Plan:** v2.2 §3, N0 (a). Yalnız ölçüm; kod değişmedi.
- **Motor kodu:** 9a36142.
  - a koşusu sürerken ana oturum tip izinin dosyalarını commit'ledi (6cf0ae3). Değişen yollar motor dışıdır: `docs/arge/2026-10-21_g9_t0/`, `scripts/measurement/dwarf_tip*`, `tests/test_dwarf_tip.py`.
  - b, s0a ve s0b künyeleri bu yüzden 6cf0ae3 gösterir. Dört koşuda da `engine_paths` boştur ve dördü de puanlamada geçerli sayıldı.
- **Dosyalar:** sayılar `ol7_sayilar.json`'da, onu üreten betik `ol7_analiz.py`'de. Çıktıda ad, GT adı ya da kanıt dizgisi yok.

## Yöntem

Koşular depo kökünden, sırayla yapıldı; paralel koşu yok. Ortam: Ghidra 12.1.2, Python 3.12.7, `--jobs 1`.

```
python scripts/measurement/macho_measure.py analyze --tree . --label ol7-a-9a36142
python scripts/measurement/macho_measure.py score --label ol7-a-9a36142 --reach
python scripts/measurement/macho_measure.py analyze --tree . --label ol7-b-9a36142
python scripts/measurement/macho_measure.py score --label ol7-b-9a36142 --reach
PYTHONHASHSEED=0 python scripts/measurement/macho_measure.py analyze --tree . --label ol7-s0a-9a36142 --only htop
python scripts/measurement/macho_measure.py score --label ol7-s0a-9a36142 --only htop --reach
PYTHONHASHSEED=0 python scripts/measurement/macho_measure.py analyze --tree . --label ol7-s0b-9a36142 --only htop
python scripts/measurement/macho_measure.py score --label ol7-s0b-9a36142 --only htop --reach
```

- **PYTHONHASHSEED:** a ve b'de tanımsız (ürün böyle koşuyor); s0a ve s0b'de 0.
- **Süreler (sn):**

  | | htop | tmux |
  |---|---|---|
  | a | 201,0 | 912,6 |
  | b | 190,9 | 910,4 |
  | s0a | 194,8 | – |
  | s0b | 196,6 | – |
  | taban v2 | 193,3 | 923,7 |

- **Önbellek:** `~/.cache/karadul/cfg_cache` her koşunun önünde ve ardında aynı.

Karşılaştırılanlar (program başına):
- `c_namer` girdileri: dört Ghidra JSON'u ayrıştırılmış içerikle, decompile `.c` dosyaları baytla.
- Puanlanan harita `reconstructed/src/naming_map.json` (c_namer iter0):
  - global bölüm, önek grubuna göre ayrı sayıldı (`FUN_`, `DAT_`, diğer);
  - `per_function` (yerel adlar).
- `macho_score.json` satırları: adres başına `status` ve `pred`.
- `report.json` → `naming_by_strategy`.
- a ↔ b ve s0a ↔ s0b için `naming_provenance.json`.

Tanımlar:
- **Yalnız son ek farkı:** iki ad, sondaki `_<sayı>` atılınca aynı.
- **Grup:** aynı taban adı taşıyan adların kümesi. Global ve yerel adlar birlikte sayılır, çünkü c_namer'ın son ek havuzu (`used_new_names`) ikisine ortaktır.

## Sayılar

| | Ghidra girdisi | farklı `.c` | FUN_ farklı | DAT_ farklı | yerel farklı | son ek grupları (aynı ad kümesi) | iter1 FUN_ / yerel | durum geçişi | `pred` değişen satır | `naming_by_strategy` |
|---|---|---|---|---|---|---|---|---|---|---|
| a ↔ b, htop | aynı | 0/790 | 0/101 | 0/104 | 1127/2519 (%44,7) | yerel 30/30 | 2 / 1117 | 0 | 0/597 | aynı |
| a ↔ b, tmux | aynı | 0/2821 | 46/875 (%5,3) | 0/269 | 5593/10977 (%51,0) | FUN_ 21/21, yerel 43/43 | 52 / 5456 | 0 | 44/2561 | aynı |
| a ↔ taban v2, htop | aynı | 0/790 | 4/101 | 0/104 | 1116/2519 (%44,3) | FUN_ 2/2, yerel 30/30 | 2 / 1125 | 0 | 4/597 | aynı |
| a ↔ taban v2, tmux | bir listenin sırası* | 0/2821 | 41/875 (%4,7) | 0/269 | 5741/10977 (%52,3) | FUN_ 19/19, yerel 42/42 | 49 / 5284 | 0 | 39/2561 | aynı |
| s0a ↔ s0b, htop | aynı | 0/790 | 4/101 | 0/104 | 1111/2519 (%44,1) | FUN_ 2/2, yerel 26/26 | 0 / 1032 | 0 | 4/597 | aynı |

\* tmux'ta taban v2'ye göre `ghidra_call_graph.json` ve `ghidra_xrefs.json`'da bir düğümün `callers` / `called_by` listesinin sırası farklı; öğeler aynı. c_namer bu listeleri okumuyor.

Tablonun okunuşu:
- **Farkların türü:** her satırda farklı adların tamamı yalnız son ekte farklı.
- **Gruplar:** her grup iki koşuda aynı ad kümesini kullanıyor. Yani yeni ad yok; aynı adlar anahtarlar arasında yer değiştiriyor.
- **Puan özetleri** her karşılaştırmada birebir aynı:
  - htop: TP 0, yanlış 101, isimsiz 496;
  - tmux: TP 105, yanlış 766, isimsiz 1690, P 0,1206, R 0,041.

Köken kaydı (a ↔ b ve s0a ↔ s0b):
- **Kazanan aday aynı:** bütün farklı adlarda kazanan strateji, güven ve kanıt iki koşuda aynı. Önerilen ad (son ek öncesi) da aynı. Hepsi "son ek sırası" sınıfında; eşitlik yüzünden çevrilen ya da farklı aday kaynaklı fark yok.
- **Farklı FUN_ adlarının stratejisi:** hepsi `string_context` (tmux a ↔ b 46, s0a ↔ s0b 4).
- **Farklı yerel adların stratejisi:**

  | | local_var | body_param | dataflow | api_param | type_based |
  |---|---|---|---|---|---|
  | htop a ↔ b | 661 | 393 | 30 | 19 | 24 |
  | tmux a ↔ b | 3604 | 1667 | 177 | 95 | 50 |
  | htop s0a ↔ s0b | 641 | 417 | 19 | 15 | 19 |

- **Son ek yükü (tek koşuda):**
  - htop: yerel adların 2419/2519'u (%96) ve FUN_ adlarının 12/101'i son ekli;
  - tmux: yerel 10844/10977 (%98,8), FUN_ 239/875 (%27).
- **Adı aynı, ikincil aday listesi farklı kayıt (a ↔ b):** tmux 28, htop 1; s0a ↔ s0b'de 0.

## Kaynak

1. **Ghidra aşaması c_namer girdisi için belirlenimci.** Aynı commit'teki koşularda dört JSON ve bütün `.c` dosyaları bayt bayt aynı. Fark c_namer'da doğuyor.
2. **Adaylar aynı, yalnız işlenme sırası değişiyor.**
   - Seçim döngüsü (`c_namer.py:1925`) anahtarları `self._candidates`'in ekleme sırasıyla dolaşıyor.
   - Bu sıra işçi sonuçlarının bitiş sırasıdır: `as_completed` (`:1822`) ve birleştirme (`:1843-1845`).
   - Çakışan adlarda taban adı ilk işlenen anahtar alır, sonrakiler `_2`, `_3` … alır (`:1971`).
   - Son ek havuzu (`used_new_names`, `:1885`) bütün fonksiyonlara ve iki kapsama ortak tek bir kümedir. Bu yüzden anahtarların sırası (tmux'ta 13 385 anahtar) yerel adların neredeyse hepsinin numarasını belirliyor.
3. **Karma tohumu baskın kaynak değil.**
   - s0a ↔ s0b tohum sabitken de farklı ve büyüklük a ↔ b ile aynı (yerel 1111'e karşı 1127).
   - Baskın kaynak işçi süreçlerinin bitiş sırası.
   - Karma tohumu ikinci bir kaynaktır. `_strategy_dataflow` bir fonksiyon içinde anahtarları `set` sırasıyla ekliyor (`:3283`, `:3310`, `:3327`). G9 adım 1'deki seri deneyde sıra sabitken tohum 0 ile 1 farklı çıktı verdi, aynı tohum aynı çıktıyı verdi.
4. **Gizli risk.**
   - tmux'ta 5 FUN_ anahtarında en üstte eşit güvenli rakip var.
   - 4'ü aynı işçiden: `string_context|api_call`. Strateji sırası sabit olduğu için belirlenimci.
   - 1'i farklı işçilerden: `api_param_reverse|string_context`. Kazananı birleştirme sırasına bağlı; bu koşularda çevrilmedi.
5. **Yan gözlem:** `~/.cache/karadul/bsim/` dosyalarının zaman damgası koşular sırasında değişti (`trace.db` 3,8 KB büyüdü). BSim gölge kipte (`shadow_mode=True`), ada girmiyor; `bsim_shadow.json` dökümleri yalnız `timestamp` alanında farklı.

## Sonuç

- **Çıktılar bayt bayt aynı değil, ama fark tek türden:** çakışma son eklerinin yer değiştirmesi. Taban adlar, kazanan stratejiler, kanıtlar, puan durumları ve `naming_by_strategy` aynı.
- **Ölçümler için anlamı:**
  - Puanlayıcı sondaki `_<rakam>` ekini soyduğu için (`function_f1.normalize_name`) F1, P, R ve satır durumları oynamıyor (0 geçiş).
  - Adı dize olarak karşılaştıran her ölçüm ya da birleştirme son ek yüzünden kayar. tmux'ta `pred`'i değişen satır 39-44 (%1,5-1,7).
  - Adres anahtarıyla birleştirme güvenli; etiketlenen öğeler adresle eşlenmeli.
- **Önerilen düzeltme:** uygulanmadı; ayrı karar.
  - **A. Birleştirmeyi gönderim sırasına bağla (`c_namer.py:1822-1845`).**
    - `as_completed` döngüsünde sonucu işlevin `func_list` indeksiyle sakla.
    - Havuz bitince `self._candidates`'e indeks sırasıyla ekle.
    - Böylece hem anahtar sırası hem aynı anahtarın aday sırası zamanlamadan bağımsız olur. Aday kümesi ve karar kuralları değişmez.
  - **B. Fonksiyon içi `set` dolaşımlarını sıralı yap.**
    - `_strategy_dataflow` `:3283`, `:3310`, `:3327`: `set(re.findall(...))` yerine `dict.fromkeys(re.findall(...))` (ilk görülme sırası).
    - `_strategy_api_call` `:2993`: `callee_names`'i sıralı dolaş.
    - `_strategy_api_call` `:3023-3027`: `sorted(..., key=len)` için ikinci anahtar `(len(n), n)`.
    - `_strategy_call_graph` `:3128`: `known_callees`'i sıralı dolaş.
    - Son üçü bugün ad değiştirmiyor, ama ikincil aday ve güveni etkiliyor.
  - **A ve B birlikte** aynı girdiden aynı `naming_map.json`'u üretir. Yalnız PYTHONHASHSEED sabitlemek yetmez (s0a ≠ s0b).
  - **C. Yapısal seçenek (adları değiştirir, yeniden taban ister).**
    - Yerel adlar için son ek havuzunu fonksiyon başına ayır.
    - Son ek yalnız fonksiyon içi çakışmada çıkar; yerel adlardaki %96-99'luk son ek yükünün ve sıra duyarlılığının çoğu kalkar.
