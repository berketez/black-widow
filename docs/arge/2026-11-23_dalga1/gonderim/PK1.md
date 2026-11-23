# PK1 — PK-1: var olan başvuru yollarına yöntem kapısı

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-2, A-13, A-14, A-15, A-25, A-30), `docs/arge/2026-11-19_mythos/kimlik/PLAN.md` §0–§2 ve "PK-1" (adımlar 1–7, kabul, ön kayıt metni, sınama ve mutasyon: aynen uygula; `A/` ve `K/` kısaltmalarının yolları §0'da), `docs/arge/2026-11-19_mythos/kimlik/BULGULAR.md`'nin ürün yolları bölümü, `docs/arge/2026-11-19_mythos/kimlik/PK-11.md` (aynı kusurun taze çiftteki ölçümü), `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` (senden hemen önce `_feedback_naming_candidates.py`'ye giren paket).

## Neden

Analist ürüne "başvuru ikilisi" verdiğinde (`reference_binary` / `ref_db`) iki yol ad yazıyor ve her ada 0,95 güven basıyor: `BinaryDiffer` tmux'ta 328 doğru / 174 yanlış, `ReferenceDiffer` 366 / 769; PK-11'in taze çiftinde 34 / 93 ve 175 / 116. Analisti yanıltan en ağır kusurlardan biri: yanlış ad, sahte güvenle. Bu paket ölçülmüş kesinliği ad eşiğinin altında kalan eşleme yöntemlerini ad yazmaktan çıkarır (kanıt satırı olur) ve sabit 0,95'i ölçülmüş değerle değiştirir. Susturma değil: yöntem ölçülmüş kuralla sınıflanır (K-2).

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Eşik:** `AD_ESIGI`'ni `karadul/core/naming_labels.py`'den içe aktar (A-13, A-25: `L / (L + 1)`, yuvarlanmış 0,909 yazma; kendi sabitini tanımlama). Plan mutantı m1 "`0.909` → `0.0`" yerine "karşılaştırma kaldırılır / eşik 0 alınır" biçiminde yazılır.
2. `OLCULMUS_YONTEM` tablosunun sayıları ön kayıttaki "TÜM GRUPLAR" satırlarıdır; Wilson alt sınırı kodda elle yazılmaz, sınama betikle yeniden hesaplayıp karşılaştırır (`tests/test_p12a_on_ad_guveni.py` örneği).
3. **PUV6a ile aynı dosya:** `_feedback_naming_candidates.py`'de yalnız `_add_bindiff` ve `_add_refdiff`'e dokun; PUV6a'nın eklediği üst veri kanallarına, `K4_CHANNEL_FLAGS`'a, `GhidraFunctionIndex`'e dokunma. `_feedback_naming_merger.py`'ye dokunma (plan adım 5: ayrı küçük yazıcı `_feedback_naming_bindiff.py`'de).
4. Kanıt satırı köken kaydında `reference_evidence` bölümü; PUV6a'nın üst veri kanıtı için kurduğu düzen varsa onunla aynı biçemi kullan (iki farklı kanıt şeması olmasın; fark gerekiyorsa gerekçesini yaz).
5. Adım 7 (uçtan uca duman): başvuru verisi hazırsa tek ürün koşusu, kuyrukla (`~/karadul_olcum/ghidra_kuyruk.sh PK1 <etiket> …`); hazır değilse "veri yok" yaz ve atla. Yeni indirme yok.
6. PK-11'in taze çiftinde (`~/karadul_olcum/runs/dalga0-2026-11-20/KIMLIK/` ve `kimlik/PK-11.md`'deki komut) kapıdan sonraki sayıyı da ölç: `BinaryDiffer` 34 / 93 → ?, `ReferenceDiffer` 175 / 116 → ? (ön kayda H5 olarak yaz: yeni yanlış 0; kalan adların Wilson alt sınırı raporlanır, ilk ölçüm).

## Yazabileceğin dosyalar

`karadul/pipeline/steps/_feedback_naming_bindiff.py`, `karadul/pipeline/steps/_feedback_naming_refdiff.py`, `karadul/pipeline/steps/_feedback_naming_candidates.py` (yalnız `_add_bindiff`, `_add_refdiff`); yeni `karadul/reconstruction/kimlik/__init__.py`, `karadul/reconstruction/kimlik/yontem_kapisi.py`; yeni `tests/test_pk1_basvuru_yontem_kapisi.py`, `scripts/measurement/mutation_specs_pk1.json`; araştırma betiği `urun_bindiff.py` (planın `A/` dizini; yalnız `--kapi` seçeneği); `docs/arge/2026-11-19_mythos/kimlik/PK-1_on_kayit.md`, `docs/arge/2026-11-19_mythos/kimlik/PK-1.md` (ilerleme dosyası).

**Dokunma:** `karadul/analyzers/bindiff.py`, `karadul/reconstruction/reference_differ.py`, `karadul/config.py`, `karadul/core/naming_labels.py`, `karadul/stages.py` (PUV5 aynı anda yazıyor olabilir), `_feedback_naming_merger.py`, `tests/test_bindiff.py`, `tests/test_reference_differ.py` (yeşil kalmalı).

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır: tmux'ta `BinaryDiffer` 328 / 174 → x / y, `ReferenceDiffer` 366 / 769 → x / y; PK-11 çiftinde 34 / 93 → x / y ve 175 / 116 → x / y; yeni yanlış. Sonra H1–H5, kanıt satırına inen ad sayıları, test / mutant sayıları, commit listesi, PK-2 / PK-4 için notlar (`karadul/reconstruction/kimlik/` paketine PK-2 başka dosyalar ekleyecek).
