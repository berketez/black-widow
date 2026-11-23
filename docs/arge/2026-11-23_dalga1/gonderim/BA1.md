# BA1 — BA-1: blok açıklama kalıplarında üstel geri izleme (`memcpy` / `memset` / `memmove`)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 akşam eki dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-17, A-27, A-35), `docs/arge/2026-11-23_dalga1/DURUM.md`'nin "Ollama uçtan uca koşusu" bölümü, `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_ustveri/ozet/OZET.md`.

## Neden

Üst veri bayrakları açıkken Ollama diliminin uçtan uca ürün koşusu bitmiyor. Blok açıklama adımı (`engineering_annotation` → `CodeBlockAnnotator._detect_memory_ops`) 13 554 dosyanın 7 310'unu 36 sn'de yazdı, sonra `FUN_100295d40.c` satır 211'de 31 dakika döndü; süreç SIGTERM'e de yanıt vermedi. Satır `runtime_memmove(field_ptr_3,iVar14,status_2 << 3,ctx,…,` (Ghidra uzun çağrıyı satıra böldüğü için kapanan ayraç yok). Kalıp `karadul/reconstruction/engineering/block_annotator.py` içinde üç yerde aynı yapıyı taşıyor (`memcpy`, `memset`, `memmove`; bugün satır 324 / 332 / 340): `((?:[^()]+|\([^)]*\))+)` — iç içe niceleyici, eşleşme bulunamayınca üstel geri izleme. Ana oturumun ölçümü: üçüncü argümanın ilk 20 / 24 / 28 karakteri 0,043 / 0,693 / 11,1 sn; 32 karakter 20 sn'de bitmedi. Kusur eski; Go adları (`runtime_memmove`) kalıbı erişilir kıldı. Aynı çalışma alanında bu üç addan birini çağıran 1 262 dosya / 3 631 satır var.

Üst veri bayraklarının öntanımda açılması ve "Ollama boyunda uygulama uçtan uca biter" ara durağı bu pakete bağlı.

## Ana oturumun hükümleri

1. **Davranış korunur.** Eski kalıbın makul sürede bittiği her girdide yeni kalıp aynı eşleşmeyi (aynı gruplar, aynı açıklama metni) verir. Bu paket bir süre onarımıdır; hangi adın eşleşeceği kuralını değiştirmez (kelime sınırı ekleme, önekli adları dışlama vb. YOK). Önekli adların sayımı ayrı kalem (hüküm 5).
2. **Geri izlemesiz yazım.** Proje `requires-python >= 3.11` (`pyproject.toml`): atomik grup `(?>…)` ve sahiplenici niceleyici kullanılabilir; ya da seçenekleri örtüşmeyecek biçimde yeniden yaz. Hangisini seçtiğini ve nedenini ilerleme dosyana yaz. Kabul: eşleşmeyen girdide süre girdi uzunluğuyla en çok karesel büyür (ölçümle göster: 100 / 1 000 / 10 000 / 100 000 karakterlik kapanan ayraçsız satır).
3. **Süre testi takılmaz.** Eski kalıp geri konduğunda (mutant) test asılı kalmamalı, kırmızı olmalı: süre ölçen sınama kalıbı AYRI SÜREÇTE zaman aşımıyla koşar (`subprocess.run(…, timeout=…)`; C düzeyindeki eşleşme iş parçacığından kesilemez). Mutasyon koşusunun toplam süresini yaz.
4. **Dosyanın bütün kalıpları taranır.** `block_annotator.py`'deki her düzenli ifade (bugün 52 `re.` kullanımı) aynı sınıf için (iç içe niceleyici; örtüşen seçenekli yineleme; `.*` … `.*` zinciri) elden geçirilir: üstel olan onarılır, yalnız karesel / kübik olan listelenir ve gerçek veride en kötü süresi ölçülür. Tarama yöntemi yazılı olmalı (ör. `re._parser` ağacında yineleme içinde yineleme + düşmanca girdiyle süre ölçümü); "baktım, yok" yeterli değil.
5. **Önekli adlar (yalnız sayım).** Üç kalıp `\b` taşımadığı için `runtime_memmove(`, `_memcpy(`, `__memcpy_chk(` gibi adlarda da eşleşiyor. Ollama çalışma alanında üç kalıbın eşleştiği satırları say: çıplak ad / tek alt çizgi önekli / başka önekli (en sık 10 önek, sayılarıyla). Karar ana oturumda; kodu değiştirme.
6. **Kapsam dışı (not olarak yaz, yapma):** (a) Ghidra sonrası adımlar için takılma bekçisi / SIGTERM'e yanıt (ayrı paket); (b) başka dosyalardaki kalıpların onarımı. (b) için yalnız ENVANTER: `karadul/reconstruction/` ve `karadul/pipeline/steps/` altındaki düzenli ifadelerde aynı taramayı koş; üstel sınıfa giren her kalıbı dosya:satır + en kısa düşmanca girdi + ölçülen süreyle listele (`BA1.md`'de tablo). Onarımı sonraki paket yapar.

## Yazabileceğin dosyalar

`karadul/reconstruction/engineering/block_annotator.py`; yeni `tests/test_ba1_blok_kalip_suresi.py`; yeni `scripts/measurement/mutation_specs_ba1.json`; `scripts/measurement/mutation_specs_p04a.json` (yalnız `block_annotator.py`'ye bakan dört tanımın `find` metni bayatlarsa; başka değişiklik yok); yeni `scripts/arge/ba1/` (tarama ve yeniden oynatma betikleri); `docs/arge/2026-11-23_dalga1/on_kayit_BA1.md`, `docs/arge/2026-11-23_dalga1/BA1.md` (ilerleme dosyası).

**Dokunma:** `karadul/pipeline/steps/engineering_annotation.py`, `karadul/config.py`, `karadul/stages.py`, `karadul/reconstruction/` altındaki öbür dosyalar, var olan testler (yeşil kalmalı: `tests/test_step_engineering_annotation.py` ve `block_annotator`'ı sınayan her dosya).

## Ön kayıt (`on_kayit_BA1.md`; ölçümden önce ayrı commit; sayılar ana oturumun, değiştirme)

> H1: Kusurlu satır (`FUN_100295d40.c` satır 211, 89 karakter) yeni kalıplarla ≤ 0,1 sn'de sonuçlanır (eski: 32 karakterde 20 sn'de bitmedi).
> H2: Ollama çalışma alanında (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_ustveri/ws`, salt okur) adımın işleyeceği 13 554 dosyanın hepsi yeni kodla işlenir; toplam süre ≤ 300 sn (yük altında; eski kod ilk 7 310 dosyayı 36 sn'de yazmıştı); tek dosyada en uzun süre ≤ 5 sn.
> H3: Eski koşunun yazmayı bitirdiği 7 310 dosyada yeni çıktı eskiyle bayt eşit (7 310 / 7 310). Adımın çıktısı girdi dışında bir şeye bağlıysa (sıra, zaman damgası) bunu ayır ve karşılaştırmayı o alan dışında yap; ayırdığını yaz.
> H4: S8'in 8 çalışma alanında (`~/karadul_olcum/runs/dalga1-2026-11-23/P16e/s8_sonra_3`, salt okur) adımın çıktısı eski kodla yeni kod arasında bayt eşit 8 / 8.
> H5: `block_annotator.py`'de üstel sınıfa giren başka kalıp sayısı: yön bildirilmez, ilk ölçüm.
> H6: Envanterde (`karadul/reconstruction/` + `karadul/pipeline/steps/`) üstel sınıfa giren kalıp sayısı: yön bildirilmez, ilk ölçüm.

## Sıra

1. Kusuru yeniden üret (gerçek satır, ayrı süreç, zaman aşımı) → ön kayıt → commit.
2. Onarım + birim testleri (≥ 8: gerçek satır; kapanan ayraçsız uzun satırlar; iç içe ayraçlı geçerli çağrılar; eski kalıpla aynı gruplar — eşdeğerlik tablosu en az 30 gerçek satırla, Ollama ve S8 çalışma alanlarından) + mutasyon (≥ 6; biri eski kalıbın geri konması).
3. Dosyanın öbür kalıplarının taranması (hüküm 4) → bulunan üsteller için aynı onarım + test.
4. Ghidra'sız yeniden oynatma: adımın girdi / çıktı dosyalarını `karadul/pipeline/steps/engineering_annotation.py`'den çıkar; Ollama çalışma alanında H2 ve H3, S8'de H4. Çıktılar kendi koşu kökünde (`~/karadul_olcum/runs/dalga1-2026-11-23/BA1/`), çalışma alanlarına YAZMA.
5. Önekli ad sayımı (hüküm 5) ve envanter (hüküm 6b).
6. İlgili takım, sonra tam takım. `mutation_specs_p04a.json`'ı yeniden koş (bayat tanım varsa yaz / düzelt).

Ghidra koşusu YOK. Uçtan uca Ollama koşusunu ana oturum, paket main'e girince kendisi koşar.

## Sert son

Gönderim iletisinde yazılı. Öncelik: 1 → 2 → 4 (H1–H3) → 3 → H4 → 5 → 6.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: Ollama çalışma alanında adım x / 13 554 dosyayı kaç saniyede işledi, kusurlu satır kaç ms, eski çıktıyla eşit dosya x / 7 310. Sonra H1–H6, seçilen yazım ve gerekçesi, dosyada bulunan öbür kalıplar, önekli ad sayımı, envanter tablosu (sonraki paketin girdisi), test / mutant sayıları, commit listesi, koşu kökünün yolu ve boyutu.
