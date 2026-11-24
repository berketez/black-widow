# BA2 — BA-2: kalan üstel düzenli ifadeler ve tam takımda kalıp denetimi kapısı

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 akşam eki dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-35, A-36), `docs/arge/2026-11-23_dalga1/gonderim/BA1.md` ve `docs/arge/2026-11-23_dalga1/BA1.md` (senden önceki paket: yöntem, tarama aracı, envanter tablosu, doğrulanamayan 39 aday, taranmayan 113 dinamik kalıp), `scripts/arge/ba1/kalip_tara.py` ve `scripts/arge/ba1/kalip_sure.py`.

## Neden

BA-1 tek bir düzenli ifadenin Ollama koşusunu 31 dakika kilitlediğini ve sürecin SIGTERM'e yanıt vermediğini gösterdi; onarım yalnız `block_annotator.py`'yi kapsadı. Envanter aynı sınıftan iki kalıp daha buldu ve 39 adayı doğrulayamadı. `re` eşleşmesi GIL'i bırakmadığı için takılma anında süreç içinden hiçbir bekçi koşamaz (A-36): bu sınıf ancak koda girmeden önlenebilir. Bu paket kalanları onarır ve taramayı tam takıma kapı olarak ekler: üstel sınıfa giren yeni bir kalıp eklendiğinde takım kırmızı olur.

## Ana oturumun hükümleri

1. **İki bilinen üstel kalıp onarılır:** `karadul/reconstruction/c_namer.py`'deki `_ZN(\d+\w+)+E` (BA-1'de satır 3436; OK1'den sonra satır kaymış olabilir: `grep -n` ile bul) ve `karadul/reconstruction/recovery_layers/constraint_solver.py`'deki `_LINKED_LIST_RE` (`(?:\w+\s*)*`). Kural BA-1'deki gibi: eski kalıbın makul sürede bittiği her girdide yeni kalıp aynı eşleşmeyi ve çağıran kodun okuduğu aynı grupları verir. Çağıran kodun hangi grubu okuduğunu yaz; okunmayan grubun değerini korumak zorunda değilsin ama bunu gerekçesiyle belirt. `constraint_solver.py`'deki "geri izlemeyi sınırlar" yorumu ölçümle çelişiyor: düzelt.
2. **39 aday karara bağlanır:** her biri için daha güçlü düşmanca girdi dene (yineleme gövdesinin kabul ettiği iki farklı bölünüşü üreten girdi + eşleşmeyi bozan son karakter; uzunluk 20 → 40 → 80). Sonuç üç sınıftan biri: üstel (onar), polinom (derecesi ve gerçek veride en kötü süresiyle listele), güvenli (neden). "Doğrulanamadı" kalan olursa sayısını ve nedenini yaz.
3. **113 dinamik kalıp:** çalışma anında kurulan kalıpların (şablon + ad yerleştirme, birleştirilmiş seçenek listeleri) ŞABLONLARINI tara; yerleştirilen parça `re.escape`'ten geçiyor mu denetle (geçmiyorsa ayrı bulgu). Taranamayanı say.
4. **Kapsam genişler (envanter):** taramayı `karadul/` altının tamamına ve `ui/server.py`'ye uygula (BA-1 yalnız `reconstruction/` + `pipeline/steps/` taramıştı). Bulunan üstel kalıp, aşağıdaki "Dokunma" listesindeki bir dosyadaysa ONARMA: yama bırak (`docs/arge/2026-11-23_dalga1/yamalar/BA2__<dosya>.patch`) ve tabloya yaz; o dosyanın paketi main'e girince ana oturum uygular.
5. **Kapı:** tarama mantığı `scripts/arge/ba1/`'den kalıcı bir yere taşınır (`scripts/measurement/kalip_denetimi.py`; `scripts/arge/ba1/` betikleri onu içe aktarır, iki kopya kalmaz). Yeni `tests/test_kalip_denetimi.py`: (a) `karadul/` + `ui/server.py`'deki sabit kalıplarda üstel sınıf 0; (b) bilinen kusurlu üç eski kalıp (BA-1) ve bu paketin iki eski kalıbı araca verildiğinde "üstel" bulunur (aracın körleşmediğinin denetimi); (c) istisna listesi boş başlar — yanlış alarm çıkarsa kalıp, gerekçe ve ölçülen süreyle listeye girer, liste testte sayılır. Testin süresi ≤ 60 sn olmalı (ölç; aşarsa taramayı önbelleğe almadan hızlandırmanın yolunu yaz, kapsamı daraltma).
6. **Süre sınamaları takılmaz:** BA-1'deki gibi ayrı süreçte, zaman aşımıyla.
7. **Kapsam dışı:** polinom kalıpların onarımı (yalnız liste; en kötü gerçek süre > 1 sn olan varsa ayrıca işaretle); Ghidra sonrası adım olayları ve kesin iptal (GS-1).

## Yazabileceğin dosyalar

`karadul/reconstruction/c_namer.py` (YALNIZ üstel bulunan kalıp satırları ve doğrudan çağıranı; stratejilere dokunma), `karadul/reconstruction/recovery_layers/constraint_solver.py` (yalnız kalıp ve yorumu); taramada üstel bulunan ve "Dokunma" listesinde OLMAYAN öbür dosyalarda yalnız o kalıp satırları (her biri ilerleme dosyasında gerekçesiyle); yeni `scripts/measurement/kalip_denetimi.py`; `scripts/arge/ba1/*.py` (yalnız içe aktarmaya çevirme); yeni `tests/test_kalip_denetimi.py`, `tests/test_ba2_kalip_onarimi.py`, `scripts/measurement/mutation_specs_ba2.json` (≥ 6 mutant; her onarılan kalıp için eskisini geri koyan bir mutant + kapının istisna denetimini kaldıran bir mutant); `docs/arge/2026-11-23_dalga1/on_kayit_BA2.md`, `docs/arge/2026-11-23_dalga1/BA2.md` (ilerleme dosyası); yamalar.

**Dokunma (başka paketlerin zinciri; bulgu varsa yama):** `karadul/ghidra/`, `karadul/analyzers/ustveri/`, `karadul/core/output_formatter.py`, `karadul/pipeline/steps/__init__.py`, `karadul/stages.py`, `karadul/pipeline/steps/_feedback_naming_*.py`, `karadul/core/naming_labels.py`, `karadul/cli.py`, `karadul/cli_common.py`, `ui/server.py`, `karadul/config.py`, `karadul/reconstruction/engineering/block_annotator.py` (BA-1 kapattı; yalnız tara), `karadul/reconstruction/api_param_db.py` ve `c_namer.py`'nin `_strategy_dataflow` / `_strategy_local_var_naming` işlevleri (HZ-7a girecek).

Dokunduğun dosyalara bakan mutasyon tanımlarını (`grep -l`) değişiklikten sonra yeniden koş; bayatlayanı yaz.

## Ön kayıt (`on_kayit_BA2.md`; ölçümden önce ayrı commit; sayılar ana oturumun)

> H1: İki bilinen kalıbın BA-1'deki düşmanca girdileri onarımdan sonra ≤ 0,1 sn'de sonuçlanır (önce: 28 tekrarda 5 sn'de bitmedi; 30 karakterde 1,13 sn).
> H2 (eşdeğerlik): geliştirme setinin çalışma alanlarından (`~/karadul_olcum/runs/urun-onarim-a62f15e/`, salt okur) ve Ollama çalışma alanından toplanan gerçek girdilerde eski ↔ yeni kalıp aynı sonucu verir; farklı 0 (girdi sayısı ilk ölçüm; her kalıp için en az 200 gerçek girdi ya da "bu kalıp gerçek veride N kez denendi").
> H3 (ad haritası): `c_namer`'ın Ghidra'sız yeniden oynatmasında (OK1 / P12d'nin yöntemi; S8'in 8 ikilisi) ad haritası onarımdan önce ↔ sonra bayt eşit 8 / 8.
> H4: 39 adaydan üstel çıkan sayısı: yön bildirilmez, ilk ölçüm.
> H5: genişletilmiş taramada (`karadul/` tamamı + `ui/server.py`) yeni üstel kalıp sayısı: yön bildirilmez, ilk ölçüm.
> H6: kapı testi ≤ 60 sn; istisna listesi boş.

## Sıra

1. Ön kayıt → commit. 2. İki kalıbın onarımı + testler + eşdeğerlik (H1, H2) + H3. 3. 39 aday (hüküm 2) ve dinamik şablonlar (hüküm 3). 4. Genişletilmiş tarama (hüküm 4) + bulunanların onarımı / yaması. 5. Kalıcı araç + kapı testi (hüküm 5) + mutasyon. 6. Tam takım. Ghidra koşusu YOK.

## Sert son

Gönderim iletisinde yazılı. Öncelik: 1 → 2 → 5 → 3 → 4 → 6.

## Dönüş mesajı

İlk satır: onarılan üstel kalıp sayısı (dosya:satır), bırakılan yama sayısı, kapı testinin taradığı kalıp sayısı ve süresi, S8 ad haritası x / 8 eşit. Sonra H1–H6, 39 adayın sınıf dağılımı, dinamik şablon bulguları, polinom listesinde gerçek süresi > 1 sn olanlar, test / mutant sayıları, commit listesi, yamalar, GS-1 ve HZ-7a için notlar.
