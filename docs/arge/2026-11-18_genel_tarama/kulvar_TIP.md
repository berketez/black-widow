# Kulvar TIP — bulgular
Kapsam: adımlar `cfg_iso_match.py`, `computation_fusion.py`, `computation_struct_recovery.py`, `struct_recovery.py`, `flow_simplify.py`, `_feedback_computation.py`, `_feedback_typing_extras.py` (tamamı); `computation/cfg_iso/*` (tamamı), `computation/fusion/{fuser,model,features,calibration}.py`, `computation/config.py`; `reconstruction/c_type_recoverer.py` (işçi, birleştirme, `recover`, `_propagate_types_v2`, `_infer_type_from_context`, `_synthesize_structs`, `_apply_struct_types`, tip yazımı), `engineering/struct_recovery.py` (`recover`, çıkarma, genel adlandırma, işaretçi eşleme, yeniden yazım), `c_algorithm_id.py` (sabit/yapısal/API katmanları, birleştirme), `c_comment_generator.py` (başlık ve `@security`), `xtride_typer.py` (`infer_types`, kayan nokta kuralı), `c_flow_simplifier.py` (ard koşul ve fonksiyon akışı), `quality/scorer.py` + `metrics/function_names.py`. Gerçek çıktı: `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` (salt okur). Okunmayanlar: `## Bakamadıklarım`.
Özet: (1) Tip katmanları değişken kullanımını ikili genelinde yalnız ada göre birleştiriyor ve dizgi sabitindeki "8.0.2"yi kayan nokta sanıyor; yanlış fonksiyona `char *`, sds dizgisine `double` yazılıyor ve ürüne giriyor (TIP-06, XTRIDE'da aynısı + Ghidra'nın `long`'unu ezme TIP-11). (2) `out/src/include/types.h`'deki 5 585 `recovered_struct` ölçeklenmemiş işaretçi aritmetiğinden ve ilgisiz `param_1`'lerden kuruluyor, "0,80 güven" taşıyor, koda bağlanan yalnız 3'ü (TIP-07). (3) Yapısal algoritma katmanı `mode`/`mode_t`'dan "Galois field (ECC, AES-GF)" gibi kripto etiketlerini ürün koduna basıyor (TIP-09). "Hesaplama" kolları: CFG-iso biçim uyuşmazlığından hiç aday üretemiyor (TIP-01), füzyon kabule matematiksel olarak ulaşamıyor ve sonucu hiçbir yere bağlı değil (TIP-02), MaxSMT ofseti P-code alan kimliği 433'ten okunuyor (TIP-03).

## TIP-01 — CFG-iso hiçbir zaman eşleşemez: sorgu düğümleri `{"instr": N}` histogramı taşıyor, şablonlar gerçek mnemonik; WL renkleri 0. adımda ayrışıyor, LSH hiç aday döndürmüyor
- Önem: YÜKSEK
- Tür: eksik özellik (koşuyor ama sonuç üretmiyor; B-C3'ün kök nedeni)
- Yer: `karadul/pipeline/steps/cfg_iso_match.py:30-80` (`_ghidra_cfg_to_attributed`), `karadul/computation/cfg_iso/fingerprint.py:48-56` (`initial_color`), `karadul/computation/cfg_iso/lsh_index.py:236-246`, `karadul/computation/cfg_iso/matcher.py:147-153`, `karadul/computation/cfg_iso/template_db.py:84-217, 330-371`
- Etkin mi: evet (`ComputationRecoveryConfig.enable_cfg_iso = True` öntanımlı, `karadul/config.py:702`; adım `cfg_iso_match` kayıtlı)
- Ne: Adım Ghidra `BasicBlock`'undan yalnız `instruction_count` alabildiği için her düğüme `{"instr": ic}` histogramı veriyor (`cfg_iso_match.py:66`). 8 elle yazılmış şablonun düğümleri `{"push":2,"mov":3,...}`, 307 JSON şablonunun gövde düğümü `mov/cmp/jz...` anahtarlı 24 yuvalı sentetik histogram taşıyor. WL ilk rengi histogramın metnini içeriyor (`fingerprint.py:54-56`), sonraki her yineleme bu rengi komşulara yayıyor; dolayısıyla sorgu ile hiçbir şablon arasında ortak WL rengi olamaz → MinHash Jaccard 0 → LSH bant eşleşmesi yok → `matcher.match` adayı boş görüp `[]` dönüyor (`matcher.py:152-153`). Topoloji birebir aynı olsa bile sonuç değişmiyor. Ek olarak adım `api_calls=[]`, `string_refs=[]` veriyor (`cfg_iso_match.py:80`), yani çapa (anchor) denetimi de hiçbir zaman "somut çapa" bulamaz; küçük CFG'lerde 0,4 cezası kaçınılmaz. JSON şablonlarında gerçek CFG yok (yorum `template_db.py:295-299` bunu kabul ediyor): giriş→gövde(öz döngü)→çıkış biçiminde 3 düğümlük sahte grafik ve "24 heuristik float × 100" mnemonik sayısı; bu şablonlar düzeltilmiş bir sorguyla da ancak rastlantısal eşleşir.
- Kanıt: aynı quicksort topolojisini adımın ürettiği biçimde sorguladım:
  ```
  bank 315
  self-query quicksort: [('quicksort', 1.0, 'exact')]
  lsh cand (instr-hist ayni topoloji): 0 sim 0.0
  match: []
  json topoloji instr sorgu cand: 0 match []
  ```
  (`HybridCFGMatcher(ComputationRecoveryConfig(), default_template_bank())`; sorgu = şablonun düğüm/kenarları, histogram `{"instr": toplam}`.)
- Etki: Ürün "hesaplamayla algoritma tanıma" iddiasının bu kolu her ikilide boş; 14 376 fonksiyonda 0 eşleşmenin sebebi eşik değil biçim uyuşmazlığı. Eşiği gevşetmek hiçbir şey değiştirmez. Adım her fonksiyon için WL + MinHash hesabı yapıp CPU harcıyor (boşa).
- Güven: kesin (çalıştırıp gösterdim)
- Onarım kapsamı: iki yol. (a) Ghidra betiğinden blok başına mnemonik histogramı çıkarıp `BasicBlock`'a taşımak + şablonları gerçek derlenmiş koddan üretmek (L; şablon bankası baştan kurulmalı, 307 JSON girdisi kullanılamaz). (b) Gerçek veri gelene dek adımı kapatmak ve raporlarda "çalıştı, 0" yerine "devre dışı" göstermek (S). Tehlike: (a)'da yalnız topolojiye (histogramsız) dayanan eşleme küçük CFG'lerde yığınla yanlış pozitif üretir; çapa için `api_calls`/`string_refs` de doldurulmalı.
- Nasıl sınanır: gerçek bir ikiliden (ör. bilinen `qsort` uygulaması) çıkarılmış CFG, düzeltilmiş adımdan geçince doğru şablonu ≥ eşikle döndürmeli; rastgele 1 000 fonksiyonda yanlış pozitif oranı ölçülmeli.

## TIP-02 — Hesaplama füzyonu kabul eşiğine matematiksel olarak ulaşamaz, iki kanıtı hiç birleştirmez ve sonucunu tüketen etkin adım yok
- Önem: YÜKSEK
- Tür: eksik özellik (koşuyor ama sonuç üretmiyor; B-C3'ün kök nedeni) + sahte/yanlış gösterim
- Yer: `karadul/pipeline/steps/computation_fusion.py:36-64, 109-135`, `karadul/computation/fusion/model.py:51-76`, `karadul/computation/fusion/features.py:93-115`, `karadul/computation/fusion/fuser.py:90-94`, `karadul/computation/config.py:67-73`
- Etkin mi: evet (`ComputationConfig.enable_computation_fusion = True`, `karadul/computation/config.py:73`); tüketici yok (yalnız `karadul/stages.py:4828` altındaki `if not _use_step_registry:` bloğu, `_use_step_registry` `stages.py:3100`'de zorla True → ölü)
- Ne: Dört ayrı kusur üst üste biniyor. (1) Adım bir adaya yalnız `byte_score` (imza) ya da yalnız `cfg_hash`+`decompiler_conf` (CFG) dolduruyor; bağlam (`callgraph_pos`, `import_context`), prototip (`param_count`, `return_type`, `cc_match`) ve `func_size` hep boş/0, `compiler_bucket` hep `"unknown"` (0,5). `bias = -3.5` olduğundan en iyi tek kanıtlı adayın logiti −1,5, olasılığı 0,182 → her aday "reject"; kabul (≥0,90) için logit ≥ 2,20 gerekiyor. (2) `fuser.fuse(candidates)` her adayı AYRI puanlıyor (`fuser.py:94`); imza ve CFG kanıtı aynı fonksiyonda bulunsa bile tek olasılıkta birleşmiyor — "füzyon" adı yanıltıcı. (3) Birleşme anahtarları uyuşmuyor: imza eşleşmeleri `original_name` (fonksiyon adı), CFG eşleşmeleri fonksiyon ADRESİ ile anahtarlanıyor (`computation_fusion.py:111, 122`); aynı fonksiyon iki ayrı anahtara düşer. (4) CFG adayında `cfg_hash` ile `reference_cfg_hash` ikisi de şablon adı (`computation_fusion.py:56, 60`) → `cfg_hash_similarity` kendisiyle kıyaslanıp her zaman 1,0; bu kanıt değil, totolojidir. Ağırlıklar elle seçilmiş, Platt kalibratörü hiç `fit` edilmeden kimlik (A=1, B=0) çalışıyor; "kalibre olasılık" adıyla taşınan sayı kalibre değil.
- Kanıt:
  ```
  sig-only byte=1.0 -> -1.5 0.1824 reject
  cfg-only conf=1.0 -> -1.5 0.1824 reject {'__bias__': -3.5, 'cfg_hash_similarity': 1.2, 'compiler_match': 0.2, 'decompiler_conf': 0.6}
  ikisi tek adayda (adim bunu yapmiyor) -> 0.3 0.5744 abstain
  ```
  (`SignatureFuser.from_computation_config(ComputationConfig())` ile, adımın ürettiği alan kümesiyle.) `grep -rn fused_matches karadul/ ui/` → `stages.py` dışında üretici adımdan başka eşleşme yok.
- Etki: 3 106 adayda 0 kabul kaçınılmaz; eşik değil, model girdisi eksik. Kabul olsaydı bile hiçbir etkin adım `fused_matches`'ı okumadığından ad haritasına ulaşmazdı. `ui/server.py:742-746` analiste "hesaplama füzyonu hiçbir fonksiyona isim veremedi (N aday üretildi, hiçbiri güven eşiğini geçemedi)" diyor; bu, geçseydi ad vereceği izlenimini doğuruyor — doğru değil.
- Güven: kesin (çalıştırıp gösterdim; tüketici yokluğu `grep` ile)
- Onarım kapsamı: `computation_fusion.py` (aynı fonksiyonun kanıtlarını tek adayda birleştir; anahtarı adrese çevir), bağlam/prototip alanlarını gerçek veriyle doldur, ağırlık + Platt'ı etiketli veriyle fit et, tüketici adım (ad birleştirici) bağla. M–L. Tehlike: totolojik `cfg_hash_similarity` kaldırılmadan ağırlık fit edilirse model sahte kanıta güvenir. Kısa yol (S): adımı kapatıp UI cümlesini "füzyon ad haritasına bağlı değil" diye düzeltmek.
- Nasıl sınanır: aynı fonksiyon için imza+CFG kanıtı tek `FusedMatch` üretmeli; etiketli doğrulama setinde kabul edilen adların hassasiyeti ölçülmeli; kabul edilen ad `naming_map`'te görünmeli.

## TIP-03 — MaxSMT yapı kurtarmanın ofset kök nedeni: LOAD/STORE'un ilk sabit girdisi alan kimliği (433 = `ram`), alan ofseti sanılıyor; sonuç da hiçbir etkin adıma bağlı değil
- Önem: ORTA (bayrak arkasında; açılırsa YÜKSEK — her erişim tek sahte ofsete düşer)
- Tür: hata + eksik özellik (çıktının tüketicisi yok)
- Yer: `karadul/pipeline/steps/computation_struct_recovery.py:72-116`
- Etkin mi: bayrak arkasında (`ComputationConfig.enable_computation_struct_recovery = False`, `karadul/computation/config.py:51`); adım `stages.py:3234-3238` koşucusunda listede, bayrak kapalı olduğu için boş döner
- Ne: Çıkarıcı LOAD/STORE/PTRADD için "girdilerden ilk sabit varnode'un `offset`'i, 0 ≤ x < 4096 ise alan ofsetidir" kuralını uyguluyor (`:94-99`). Ghidra P-code'unda LOAD ve STORE'un `input0`'ı adres alanının kimliğini taşıyan sabittir; gerçek ofset işaretçi girdisinin içinde (önceki INT_ADD/PTRSUB'da) durur. Gerçek çıktıda bu sabit her erişimde 433'tür, dolayısıyla her erişim `offset=433` alır. Kompakt JSONL'de varnode `[alan, ofset, boyut]` üçlüsü olduğundan `high_variable` hep `None`, `var_name` = `f"{fn_name}_var_1b1"` → bir fonksiyondaki bütün erişimler tek değişkenin aynı ofsetine yığılır. PTRADD'da ilk sabit indeks ya da eleman boyutudur (çarpım değil). Asıl alan ofseti işlemi PTRSUB listede yok (`:76`). Üstelik `recovered_struct_candidates` / `computation_struct_result` hiçbir etkin adımda okunmuyor (yalnız `stages.py`'de geçiyor); docstring'deki "eski StructRecoveryEngine'a aday olarak aktarılır" (`:6-11`) gerçekleşmemiş.
- Kanıt: `~/karadul_olcum/runs/urun-yeni2-f30ac9a/debian/zstd/pzstd/.../ghidra_output/pcode.jsonl` üzerinde sayım:
  ```
  [['LOAD', [0, 268435549, 8], [[2, 433, 4], [1, 16384, 8]]], ...]
  [(('LOAD', (2, 0)), 12219), (('LOAD', (2, 1)), 5502), (('STORE', (2, 0, 2)), 2843), ...]
  ilk sabit girdi: [(('LOAD', 433), 17740), (('STORE', 433), 9511)]
  ```
  17 740 LOAD'un ve 9 511 STORE'un tamamında ilk sabit 433.
- Etki: Bayrak açılırsa çözücü her fonksiyon için "433. baytta tek alan" yapısı üretir; kurtarılan yapılar anlamsız olur ve `computation_struct_confidence` erişimlerin çoğunu "açıklanmış" sayarak yüksek bir oran gösterir. Bugün bayrak kapalı ve çıktı bağlı olmadığı için analiste yansımıyor; ama "hesaplamayla yapı kurtarma" kolu fiilen yok.
- Güven: yüksek (çıkarıcıyı ve gerçek P-code'u izledim; çözücüyü bayrak açık koşturmadım)
- Onarım kapsamı: `computation_struct_recovery.py` — ofseti işaretçi girdisinin tanım zincirinden (INT_ADD base+sabit, PTRSUB) çıkar; `input0`'ı atla; değişken kimliğini taban işaretçi varnode'undan kur; tüketici adım bağla. M. Tehlike: tanım zinciri için JSONL'de SSA bağlantısı yok (yalnız varnode üçlüsü); `unique` varnode'ları aynı fonksiyonda yeniden kullanılabilir.
- Nasıl sınanır: bilinen bir yapıya `p->a`(0), `p->b`(8) erişen küçük C fonksiyonunun P-code'undan {0, 8} ofsetleri çıkmalı; 433 hiçbir erişimde görünmemeli.

## TIP-04 — Öntanımlı açık mühendislik yapı kurtarması yalnız Ghidra'nın sistem yapılarını alıp gerçek alan adlarını genel tahminlerle eziyor, koda hiç bağlanmıyor; çıktısını kimse okumuyor
- Önem: ORTA
- Tür: eksik özellik + ölü çıktı + sahte/yanlış gösterim (sayaç)
- Yer: `karadul/reconstruction/engineering/struct_recovery.py:856-858` (Ghidra yapılarını taban alma), `:896-897` (koddan çıkarma yalnız taban boşsa), `:1269-1368` (`_generic_enrich_fields`), `:1705-1761` (`_build_global_ptr_struct_map`), `:963-969`; çağıran `karadul/pipeline/steps/struct_recovery.py:57-98`
- Etkin mi: evet (`binary_reconstruction.enable_struct_recovery = True`, `karadul/config.py:465`; adım `stages.py:3234-3238` Faz 2 koşucusunda)
- Ne: Adım `existing_type_result` vermiyor; motor taban yapı olarak `ghidra_types.json`'daki `ghidra_structs`'ı alıyor (`:857-858`). Her ELF'te Ghidra `_IO_FILE`, `Elf64_Ehdr`, `Elf64_Phdr` gibi sistem yapılarını verdiği için taban hiç boş kalmıyor ve asıl "koddan çıkarma" (`_extract_structs_from_code`, `:896-897`) hiçbir zaman çalışmıyor. Algoritma şablonu eşleşmeyen her yapı `_generic_enrich_fields`'a düşüyor; bu yol alanın Ghidra'dan gelen GERÇEK adını hiç dikkate almadan offset/tipe göre `size`, `n_items`, `tolerance`, `coeff_2`, `field_0x0` gibi adlar veriyor. Ghidra yapılarının `source_functions`'ı boş olduğundan `func_to_structs` boş → `ptr_map` boş → kod yeniden yazımı hep 0. Üretilen `struct_recovered/types.h` (`enriched_types_header` artefaktı) etkin hiçbir adımda okunmuyor; son `out/src/include/types.h` `typed/` sürümünden geliyor. Rapor istatistiklerine yine de `structs_enriched` (ikili başına ~27) yazılıyor.
- Kanıt: `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` altındaki 117 `struct_recovery.json`:
  ```
  files 117 structs 3213 rewrites 0
  [('_IO_FILE', 117), ('_IO_marker', 117), ('eh_frame_hdr', 117), ('Elf64_Dyn_AARCH64', 117), ...]
  source_functions median 0 max 0
  alan 21354 ad korunan 0 ad degisen {'generic_heuristic': 21354}
  ```
  `tail/.../struct_recovered/types.h`: `byte field_0x0; /* ... was: e_ident_magic_num */`, `string field_0x1; /* was: e_ident_magic_str */`. `grep -rn enriched_types_header karadul/` → yalnız üretici ve `stages.py`.
- Etki: Bugün ürüne yansımıyor (çıktı tüketilmiyor), ama (1) "yapı kurtarma" iddiası fiilen boş — kullanıcı kodundaki yapılar hiç kurtarılmıyor; (2) bu `types.h` bir gün bağlanırsa 21 354 doğru alan adını yanlışıyla değiştirir; (3) her `.c` dosyası iki kez kopyalanıyor (`struct_recovered/` + `originals/`), raporda `structs_enriched` sayısı iş yapılmış izlenimi veriyor.
- Güven: yüksek (kodu izledim, 117 gerçek çıktıyla doğruladım)
- Onarım kapsamı: `engineering/struct_recovery.py` — (a) Ghidra/DWARF kökenli yapıların alan adları korunmalı (gerçek ad varken sezgisel ad verilmemeli); (b) taban, kullanıcı kodundan çıkarılan yapılardan oluşmalı (Ghidra sistem yapıları ayrı tutulmalı); (c) bağlanamayan yapı "kurtarıldı" sayılmamalı. Kapsam M. Ayrıca bkz. TIP-05 (koddan çıkarma yolu çalıştırılırsa ad tabanlı birleştirme hatası).
- Nasıl sınanır: Ghidra'nın verdiği bir yapının alan adları çıktıda aynen kalmalı; kullanıcı kodunda `*(long *)(p + 8)` erişen fonksiyon için kurtarılan yapı `source_functions`'ta o fonksiyonu taşımalı ve en az bir yeniden yazım üretmeli.

## TIP-05 — Yapı kurtarmanın koddan çıkarma ve yeniden yazma yolları değişkeni yalnız ADIYLA tanıyor: farklı fonksiyonlardaki `param_1`'ler tek yapıya birleşir, yeniden yazım her dosyada aynı ada uygulanır
- Önem: ORTA (bugün TIP-04 yüzünden tetiklenmiyor; TIP-04 onarılırsa YÜKSEK — analiste yanlış `->alan` kodu gösterir)
- Tür: hata (gizli)
- Yer: `karadul/reconstruction/engineering/struct_recovery.py:1019-1036` (`all_accesses[pat.base_ptr]`, bütün dosyalar), `:1713-1761` (`ptr_map[base_ptr]`, ilk gelen kazanır, dosyalar arası), `:1812, 1849` (yeniden yazmada `ptr_struct_map.get(base)`), `:1828`
- Etkin mi: kod etkin adımdan çağrılıyor ama bugün tetiklenmiyor (bkz. TIP-04: taban hiç boş değil ve `source_functions` boş)
- Ne: `_extract_structs_from_code`, erişimleri `base_ptr` METNİNE göre bütün `.c` dosyaları boyunca topluyor; Ghidra her fonksiyonda `param_1`, `lVar3` gibi aynı adları yeniden kullandığından, yüzlerce ilgisiz fonksiyonun `param_1` ofsetleri tek `recovered_struct_NNN`'e karışır. `_build_global_ptr_struct_map` aynı biçimde `ptr_map`'i ad başına bir kez doldurup (`:1747-1748`, ilk gelen kazanır) `_rewrite_access_patterns` bu eşlemeyi her dosyadaki her fonksiyona uyguluyor; yani bir fonksiyonda `param_1` için seçilen yapı, başka bir fonksiyondaki tamamen farklı `param_1`'in `*(int *)(param_1 + 4)` erişimini `param_1->alan` diye yeniden yazar. Yeniden yazım değişkenin bildirilen tipini değiştirmediğinden (`long param_1` kalır) çıkan C derlenmez. Ofset, tabanın işaretçi tipine göre ölçeklenmiyor (`int *p; *(p + 4)` = bayt 16); Ghidra çoğunlukla bayt aritmetiği yazsa da bu varsayım denetlenmiyor (şüphe).
- Kanıt:
  ```python
  for func_name, func_body, _ in functions:            # :1030
      patterns = self._extract_access_patterns(func_body, func_name)
      for pat in patterns:
          if not pat.is_array:
              all_accesses[pat.base_ptr].append(...)   # anahtar: yalnız ad
  ...
  if base_ptr in ptr_map: continue                     # :1747 dosyalar arası ilk gelen
  es = ptr_struct_map.get(base)                        # :1812 her dosyada aynı ad
  ```
- Etki: Yol etkinleşirse analist, fonksiyonun gerçekte kullanmadığı bir yapının alan adını kodda görür; `/* was: ... */` yorumu olsa da üstteki ad yanıltıcıdır.
- Güven: yüksek (kodu izledim; çalıştırmadım)
- Onarım kapsamı: anahtarı `(fonksiyon, değişken)` yapmak; yeniden yazımda fonksiyon kapsamı; değişken bildirimi tipini de güncellemek ya da yeniden yazmayı tip uyumuna bağlamak. M.
- Nasıl sınanır: iki fonksiyonda farklı ofsetlerle erişilen iki `param_1` iki ayrı yapı (ya da hiç yapı) üretmeli; A'nın yapısı B'nin kodunda yeniden yazım yapmamalı.

## TIP-06 — Tip kurtarma değişken kullanımını ikili genelinde yalnız ADA göre birleştiriyor ve dizgi sabitindeki "8.0.2"yi kayan nokta sanıyor: yanlış fonksiyona yanlış tip yazılıyor, ürüne ulaşıyor
- Önem: YÜKSEK
- Tür: hata (analisti yanıltan yanlış çıktı)
- Yer: `karadul/reconstruction/c_type_recoverer.py:1464-1468` (`_type_usage[var].extend`, anahtar yalnız ad), `:2162-2183` (katman 2a), `:2433-2452` (`_find_var_function` ilk `return_in` fonksiyonunu döndürüyor), `:147-150` + `:294-298` (`_float_assign_re`, dizgi sabitlerini örtmeden), `:2314-2322` (katman 2g)
- Etkin mi: evet (`binary_reconstruction.enable_type_recovery = True`, `karadul/config.py:457`; çıktı `typed/` → `out/src`)
- Ne: (1) İşçi her `.c` dosyasından `değişken → [etiket]` toplar; ana süreç bunları yalnız değişken adına göre birleştirir. Ghidra her fonksiyonda `uVar1`, `local_10`, `param_1` gibi adları yeniden kullandığından, A fonksiyonundaki `strlen(uVar1)` etiketi B fonksiyonundaki `uVar1`'e de yapışır. Katman 2a çıkarılan tipi, `_find_var_function`'ın bütün etiketler içinden bulduğu İLK `return_in:` fonksiyonuna yazar; yani tipin kanıtı bir fonksiyondan, uygulandığı bildirim başka fonksiyondandır. (2) `_float_assign_re` = `(\w+)\s*=\s*[^;]*\b(\d+\.\d+...)\b` satırın tamamına bakıyor; işçi dizgi sabitlerini örtmüyor (yalnız Ghidra uyarıları örtülüyor, `:119`). `x = f(x, "8.0.2", 5)` gibi bir satır `x`'i `double` yapıyor.
- Kanıt: üç küçük dosyayla `CTypeRecoverer(Config()).recover(...)`:
  ```
  == FUN_00001000.c      (uVar1 = FUN_00003000(param_1); return uVar1;)
    char * uVar1;        <- kanıt FUN_00002000'deki strlen(uVar1)'den
  == FUN_00002000.c      (uVar1 = FUN_00004000(...); strlen(uVar1);)
    uint64_t uVar1;      <- asıl dizgi olan burada genel öntanım
  == FUN_00005000.c      (uVar2 = FUN_00006000("libfoo 1.2 ready");)
    double uVar2;
  ```
  Gerçek ürün çıktısı: `debian/redis-tools/redis-check-rdb/out/src/src/subsystem_group_0/lolwutUnstableCommand.c:25` → `double sdsnewlen_ret_164;` (kaynak satırlar: `= _sdsnewlen("Redis ver. ",0xb,0);`, `= sdscatlen(sdsnewlen_ret_164,"8.0.2",5);` — sds bir `char *`). 117 ikilide `merged/`↔`typed/` karşılaştırması: `undefined*` → `void *` 236, `uint32_t` 153, `int` 139, `char *` 124, `double` 21 (bunların hangilerinin yanlış olduğu ayrıca ölçülmeli).
- Etki: Analist, opak bir dönüş değerini `char *`, sds dizgisini `double` olarak görür; tip ad önerilerini ve okumayı yanlış yönlendirir. Kanıtı olmayan tip, Ghidra'nın dürüst `undefined8`'inden daha kötüdür.
- Güven: kesin (çalıştırıp gösterdim; gerçek çıktıda örnek)
- Onarım kapsamı: `c_type_recoverer.py` — etiketleri `(fonksiyon, değişken)` ile anahtarlamak (işçi zaten `current_func`'u biliyor), 2a'da yalnız aynı fonksiyonun etiketleriyle karar vermek; etiket desenlerini `_C_NONCODE_TOKEN` ile dizgi/yorumu örttükten sonra çalıştırmak. M. Tehlike: `_find_var_function`'ı çağıran 2g ve `_infer_type_from_context` aynı varsayımı paylaşıyor; hepsi birlikte değişmeli.
- Nasıl sınanır: yukarıdaki üç dosyalık deneme `FUN_00001000`'de `undefined8`/genel tip, `FUN_00002000`'de `char *`, `FUN_00005000`'de `double` OLMAYAN tip üretmeli; redis `lolwutUnstableCommand` yeniden koşulduğunda `double` görünmemeli.

## TIP-07 — Ürünün `types.h`'sindeki `recovered_struct_NNN`'ler ölçeklenmemiş işaretçi aritmetiğinden ve ilgisiz fonksiyonların aynı adlı değişkenlerinden kuruluyor: yanlış ofset, üst üste binen alan, 0,80 "güven"; 5 585 yapının koda bağlanan yalnız 3'ü
- Önem: YÜKSEK
- Tür: hata + sahte/yanlış gösterim (güven değeri)
- Yer: `karadul/reconstruction/c_type_recoverer.py:189-201` (işçi, `(base, offset_str, ...)`), `:1405-1428` (`_merge_parse_result`: anahtar yalnız `base` adı; ilk erişime sabit `confidence 0.8`), `:1780-1840` (`_synthesize_structs`: ofset < `prev_end` için örtüşme denetimi yok), `:2597-2646` (`_apply_struct_types`)
- Etkin mi: evet (`enable_type_recovery = True`; `typed/types.h` → `out/src/include/types.h`)
- Ne: (1) Ofset, `*(T *)(base + N)` metnindeki `N`'dir; tabanın bildirilen tipi (`uint64_t *param_1`) hesaba katılmaz. Ghidra bayt aritmetiği için tabanı `long` yazar, ama taban tipli işaretçiyse `+ 1` = `sizeof(*base)` bayttır; kod bunu bayt 1 sayıyor. (2) `_field_accesses` yalnız değişken adıyla anahtarlı ve ikili genelinde birleşiyor; `param_1` için beş ilgisiz fonksiyonun erişimleri tek yapıya yığılıyor. (3) Ardışık ofsetlerdeki alanlar (1, 2, 3'te `int`) örtüşüyor; denetim yok, C bildirimi alanları sıralı dizdiği için derleyicinin yerleşimi yorumdaki ofsetlerle tutmuyor. (4) Her alan ilk görüldüğünde `confidence: 0.80` alıyor; kanıt sayısıyla ilgisi yok. (5) Yapının kendi ofset kümesi kendi değişkeniyle zorunlu olarak eşleştiğinden `_apply_struct_types` puanı her zaman 1,0; ama uygulama yalnız `undefined8 <ad>` bildirimine yapıldığından (Ghidra çoğunlukla `long`/`T *` yazar) yapıların neredeyse hiçbiri koda bağlanmıyor.
- Kanıt: 116 ikilinin `out/src/include/types.h` + `out/src/**/*.c` taraması:
  ```
  ikili 116 recovered_struct 5585 koddaki kullanim 3
  en buyuk (alan sayisi): [(212, 'debian/zstd/zstd', 'recovered_struct_010'), (83, ..., 'recovered_struct_081'), (82, 'debian/tmux/tmux', ...)]
  ```
  `zstd/out/src/include/types.h:2282-2293`:
  ```
  /* Size: 0x76B8 (30392 bytes)
   * Sources: FUN_0010ce08, FUN_0010ea80, FUN_001150ec, FUN_00115d80, FUN_00117700 */
  struct recovered_struct_010 {
      char padding_0x00;  /* 0x00 */ /* confidence: 0.30 */
      int field_0x01;  /* 0x01 */ /* confidence: 0.80 */
      int field_0x02;  /* 0x02 */ /* confidence: 0.80 */
  ```
  Kaynak `typed/FUN_0010ce08.c:11,19`: `uint64_t FUN_0010ce08(uint64_t *param_1,int param_2)` ... `*(int *)(param_1 + 1) = ...` → gerçek ofset 8.
- Etki: Analist `types.h`'de binlerce "0,80 güvenli" yapı görür; bunlar ne bir veri türüne karşılık gelir ne de kodda kullanılır. Kullanıldığı 3 yerde alan ofsetleri yanlıştır. "Yapı kurtarma" sayacı (`total_types_recovered`) bu sahte yapıları sayar.
- Güven: kesin (gerçek çıktıda gösterdim; kaynak satırla ölçek hatasını eşledim)
- Onarım kapsamı: `c_type_recoverer.py` — anahtar `(fonksiyon, değişken)`; ofseti tabanın bildirilen işaretçi tipine göre ölçekle (bildirimi işçide zaten `declared:` etiketiyle görüyor); örtüşen alanları birlik/çakışma olarak işaretle ya da yapı üretme; güveni kanıt sayısından türet; koda bağlanamayan yapıyı `types.h`'ye yazma ya da ayrı "bağsız aday" bölümüne koy. M–L. Tehlike: `struct_recovery` (TIP-04/05) ve `type_recovery_consumer` bu yapıları okuyabilir; hepsinin anahtar değişikliğine uyması gerekir.
- Nasıl sınanır: `uint64_t *p; *(int *)(p + 1)` içeren tek fonksiyonluk girdi, ofset 8'de `int` alanı üretmeli; iki fonksiyonda farklı `param_1` erişimleri iki ayrı yapı (ya da yapı yok) vermeli; yeniden koşuda `recovered_struct` sayısı ile koddaki kullanım sayısı birbirine yakın olmalı.

## TIP-08 — `@security` başlık etiketi fonksiyon adında alt dizgi aramasıyla veriliyor: "dispatch"→"Code injection/hooking", "Token"→"authentication", Redis `Key`→"sensitive key material"
- Önem: ORTA
- Tür: sahte/yanlış gösterim
- Yer: `karadul/reconstruction/c_comment_generator.py:1818-1841` (`_detect_security_relevance`), çağıran `:1665-1668`
- Etkin mi: evet (`binary_reconstruction.enable_comment_generation = True`, `karadul/config.py:459`; başlık `out/src/**/*.c`'ye giriyor)
- Ne: Etiket, adın küçük harfli halinde `"patch"`, `"hook"`, `"token"`, `"key"`, `"sha"`, `"rsa"`, `"root"` gibi parçaların GEÇMESİNE bakıyor; sözcük sınırı, bağlam ya da çağrı kanıtı yok. "patch" ⊂ "dis**patch**er", "rsa" ⊂ "trave**rsa**l"/"conve**rsa**tion", "sha" ⊂ "**sha**red"/"**sha**dow", "token" ⊂ sözcük çözümleyici adları, "key" ⊂ veritabanı anahtarları. Etiket Doxygen `@security` alanı olarak, kanıt gibi yazılıyor. Ad, Karadul'un kendi (yanlış olabilen) ad önerisi de olabilir; yanlış ad → yanlış güvenlik iddiası zinciri kuruluyor. Ayrıca `"Receives sensitive parameters"` parametre metninde `"key"` arıyor (`monkey`, `keyboard` da eşleşir).
- Kanıt: 119 ikilinin `out/src` taraması (4 291 `@security` etiketi), etiketten sonraki fonksiyon adıyla:
  ```
  9 Code injection/hooking mechanism ['RedisModuleCommandDispatcher', 'luaLdbLineHook', 'sqlite3session_patchset', 'notify_insert_one_hook', ...]
  70 Handles authentication/credentials ['getlogin', 'exprTokenRelease', 'exprNewToken', 'exprTokenRetain', 'authRequired', ...]
  869 Handles sensitive key material [..., 'RM_ClusterCanonicalKeyNameInSlot', 'decodeTimeoutKey', ...]
  ```
- Etki: Zararlı yazılım arayan analist, olağan bir komut dağıtıcısında "kod enjeksiyonu/kancalama", bir ifade çözümleyicisinde "kimlik bilgisi işleme" görür; bu tam olarak yanlış alarm ya da yanlış önceliklendirme demek. Doğru pozitifler (OpenSSL `SHA256_*`) de yalnız adın kendisinden çıkarıldığı için yeni bilgi taşımıyor.
- Güven: kesin (gerçek çıktıda saydım)
- Onarım kapsamı: `c_comment_generator.py` — ad parçalarını `_split_name` ile sözcüklere bölüp tam sözcük eşleşmesi; ad kaynaklı etiketi "adına göre" diye nitelemek ya da yalnız çağrı kanıtıyla (`@calls` içinde gerçek kripto/kanca API'si) vermek. S.
- Nasıl sınanır: `RedisModuleCommandDispatcher`, `exprNewToken`, `tree_traversal`, `shared_mem_init` için `@security` üretilmemeli; `SHA256_Update`, `SSL_set_verify` için korunmalı.

## TIP-09 — Yapısal algoritma katmanı hâlâ alt dizgi ve tek eşleşmeyle kripto etiketi basıyor: `mode`/`mode_t` → "Galois field operations (ECC, AES-GF)", ürün koduna `ALGORITHM:` yorumu olarak giriyor
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim (ab986da'nın onarmadığı kalan yol)
- Yer: `karadul/reconstruction/c_algorithm_id.py:536-677` (`STRUCTURAL_PATTERNS`), `:1296-1350` (`_scan_structural`); yorum yazımı `c_comment_generator.py:1657-1663` ve satır içi `/* ALGORITHM: ... via structural */`
- Etkin mi: evet (`binary_reconstruction.enable_algorithm_id = True`, `karadul/config.py:458`)
- Ne: ab986da yalnız sabit katmanını onardı. Yapısal katmanın desenleri gövdenin TAMAMINDA (dizgi sabitleri, tanımlayıcılar dahil) sözcük sınırı olmadan arıyor ve çoğu tek ya da iki eşleşmeyle karar veriyor. `galois_field` (`min_matches 3`): `mod\s*\w+` deseni `mode`, `mode_t`, `__mode`, `modem` gibi her tanımlayıcıyı "modüler aritmetik" sayıyor; `%\s*0x...`/`* x % y` sıradan karma tablosu modülünü de sayıyor. `pbkdf_loop`: dizgideki "iteration"/"rounds" → "Password-based key derivation". `compression_lz`: `MATCHLEN` → LZ. `sbox_lookup`: onaltılık yazdırma tablosu `"0123456789abcdef"[x & 0xf]` → "S-box substitution (AES, DES)". `xor_encrypt_loop` (min 1): `^=` içeren her döngü → "XOR-based encryption". `key_schedule` (min 1, IGNORECASE): `for(...)` başlığında `nr`/`round` geçmesi yeter (`nrows` vb.). `elliptic_curve` (min 1): "affine", "p384" geçmesi yeter. Güven 0,40–0,85; Galois için örneklerde 0,55–0,70.
- Kanıt: 117 `reconstructed/algorithms.json` (kanıtı `: matched` olanlar):
  ```
  yapisal etiket 204
  162 Galois field operations (ECC, AES-GF) ikili: 30
      ('md5sum', 'FUN_00103c50', 0.55, "galois_field: matched 'mode'")
      ('mkfifo', 'umask_00102aa4', 0.4, "galois_field: matched 'mode_t'")
  6 Password-based key derivation (PBKDF2, scrypt) ('tail', ..., "pbkdf_loop: matched 'iteration'")
  3 S-box substitution (AES, DES) ('openssl', ..., 'sbox_lookup: matched \'pcVar6[1] = "0123456789abcdef"[... & 0xf]')
  ```
  Ürün: `debian/coreutils/chmod/out/src/src/subsystem_group_0/FUN_00102f00.c:21,24` → `@algorithm Galois field operations (ECC, AES-GF) (asymmetric, confidence: 55%)` ve `/* ALGORITHM: ... (confidence: 55%, via structural) */`; fonksiyonda yalnız `uint __mode;` ve `"%s"` biçim dizgileri var. `out/` altında bu etiket 26+12 başlık ve `analysis/algorithms.md` bölümlerinde görünüyor.
- Etki: chmod/cp/mkfifo gibi zararsız araçlarda "asimetrik kripto (ECC)" ve "parola tabanlı anahtar türetme" iddiası; kötü amaçlı yazılım arayan analist için doğrudan yanlış alarm. Güven yüzdesi kanıt gibi okunuyor.
- Güven: kesin (gerçek çıktıda saydım ve ürün dosyasında gösterdim)
- Onarım kapsamı: `c_algorithm_id.py` — desenleri dizgi/yorum örtülmüş gövdede ve sözcük sınırıyla çalıştırmak (`_C_NONCODE_TOKEN` benzeri), anahtar sözcük desenlerini (`mod`, `iteration`, `ctr`, `affine`) kaldırmak ya da yalnız destekleyici kanıt saymak, tek başına yapısal eşleşmeyle etiket vermemek (sabit katmanındaki "en az iki ayırt edici kanıt" kuralının karşılığı). ab986da'daki mutant/ölçüm düzeni burada da kurulmalı. M.
- Nasıl sınanır: coreutils `chmod`, `mkfifo`, `md5sum`, `tail` için yapısal kripto etiketi 0 olmalı; openssl `BN_mod_exp` gibi gerçek durumlar korunmalı (ya da API katmanından gelmeli).

## TIP-10 — `karadul score` okunabilirlik puanı doğruluğu ölçmüyor: her FUN_ olmayan İngilizce köklü ad "anlamlı" sayılıyor, "temel" puan sabit 100
- Önem: DÜŞÜK (yalnız ayrı CLI komutu; raporlara girmiyor)
- Tür: sahte/yanlış gösterim
- Yer: `karadul/quality/metrics/function_names.py:64-100`, `karadul/quality/metrics/comments.py:59`, `karadul/quality/scorer.py:186-213`, `karadul/quality/config.py:33`; çağıran yalnız `karadul/cli.py:1873` (`score` komutu)
- Etkin mi: evet ama yalnız `karadul score` komutunda (`grep -rn "karadul.quality" karadul/ ui/` → `cli.py:1873` ve `deep_tracer.py:42`'deki bir regex içe aktarımı)
- Ne: Fonksiyon adı boyutu = (1 − FUN_ oranı) × (İngilizce kök oranı); adın DOĞRU olup olmadığı hiç denetlenmiyor — B-A1'deki %29,7 yanlış ad puanı yükseltir. Yorum boyutu yorum satırı/fonksiyon oranı; TIP-08/TIP-09'daki sahte `@security`/`ALGORITHM:` yorumları da puanı artırır. `compare` temel puanı DWARF'tan ölçmüyor, `baseline.available` ise sabit `GROUND_TRUTH_SCORE = 100` alıyor; "normalized" = yeniden kurulan puanın kendisi.
- Kanıt: `function_names.py:92-96` `base_score = (1.0 - generic_ratio) * 100.0 ... final_score = base_score * dict_similarity`; `scorer.py:196` `baseline_score = GROUND_TRUTH_SCORE if baseline.available else 0.0`.
- Etki: Bu puan bir yerde başarı ölçütü olarak anılırsa yanıltır: yanlış ad ve uydurma yorum puanı yükseltir.
- Güven: yüksek (kodu izledim)
- Onarım kapsamı: komutun çıktısına "yüzey ölçütü, doğruluk değil" notu ya da GT'li ölçümle (DWARF adları) değiştirmek. S.
- Nasıl sınanır: bütün adları rastgele İngilizce sözcüklerle değiştirilmiş bir ağaç, gerçek adlı ağaçla aynı puanı almamalı.

## TIP-11 — XTRIDE tip katmanı Ghidra'nın somut `long`/`ulong` bildirimini eziyor ve dizgi sabitindeki "2.5"i kayan nokta kanıtı sayıyor: `long lVar1` → `double lVar1`
- Önem: YÜKSEK
- Tür: hata (Ghidra'nın tipini daha kötüsüyle değiştiren kural)
- Yer: `karadul/reconstruction/xtride_typer.py:649` (`_FLOAT_LITERAL_RE`, satırın tamamı, dizgi örtülmeden), `:1102-` (`_infer_float_literals`), `:812-815` (eşik 0,50); uygulayan `karadul/pipeline/steps/_feedback_typing_extras.py:52-72` (desen `(?:undefined[1248]?|long|ulong)\s+<ad>`)
- Etkin mi: evet (`binary_reconstruction.enable_xtride_typing = True`, `karadul/config.py:468`; geri besleme döngüsünün tip fazı, dosyayı yerinde yazar `:72`)
- Ne: Uygulayıcı yalnız `undefined*` değil, Ghidra'nın veri akışıyla belirlediği somut `long` ve `ulong` bildirimlerini de değiştirilebilir sayıyor. XTRIDE'ın kayan nokta kuralı, TIP-06'daki aynı hatalı deseni taşıyor: `x = ...` satırında herhangi bir yerde `\d+\.\d+` görmesi yeterli; dizgi sabiti (sürüm metni, biçim dizgisi) ayıklanmıyor. Tek kanıt 0,65 güven veriyor, eşik 0,50 — tek bir dizgi bir tamsayının tipini `double`'a çeviriyor. Bu, Ghidra'nın `long` (doğru genişlik, tamsayı) bilgisini kaybettiriyor; `double` kayan nokta yazmacı anlamı taşıdığından okunan kodun anlamı da değişiyor.
- Kanıt:
  ```
  code: long lVar1; ... lVar1 = FUN_00002000(param_1,"version 2.5"); ... return lVar1 + uVar2;
  XTrideTyper().infer_types(code) ->
  lVar1 double 0.65 float_literal float literal 2.5
  ```
  `_feedback_typing_extras.py:56` deseni `long lVar1;` satırını eşler ve `double lVar1;` yazar.
- Etki: Analist sürüm/biçim dizgisi geçen her atamada tamsayı/işaretçi değişkeni `double` görür; TIP-06 ile birlikte aynı yanlışın iki ayrı katmandan gelmesi, bir katman onarılınca diğerinin hatayı sürdürmesi demek.
- Güven: kesin (çalıştırıp gösterdim; ürün çıktısında sıklığı ayrıca ölçülmedi)
- Onarım kapsamı: `xtride_typer.py` — desenleri dizgi/yorum örtülmüş metinde çalıştır; kayan nokta kuralını yalnız atamanın sağ tarafı çıplak sayı sabiti olduğunda uygula. `_feedback_typing_extras.py` — `long`/`ulong`'u (Ghidra somut tipi) değiştirilebilir listeden çıkar ya da yalnız aynı genişlikte ve daha bilgili tipe izin ver (`long` → `char *` gibi 8 baytlık işaretçi kanıtı varsa). S–M.
- Nasıl sınanır: yukarıdaki parça için `lVar1` tipi değişmemeli; `dVar1 = 2.5;` için `double` korunmalı.

## Küçükler
- Okunmayan ayar: `ComputationRecoveryConfig.cfg_iso_vf2_node_cap` (`karadul/config.py:723`) hiçbir yerde okunmuyor; gerçek sınır `KARADUL_VF2_NODE_CAP` ortam değişkeni (`computation/cfg_iso/vf2_matcher.py:46`). Yapılandırma dosyasından verilen değer etkisiz.
- Gizli başarım bombası: `vf2_match_with_timeout` her çağrıda `spawn` bağlamında yeni Python süreci açıyor (`vf2_matcher.py:253-262`). Bugün LSH aday üretmediği için hiç çalışmıyor; TIP-01 onarılırsa 14 000 fonksiyon × 10 aday × süreç başlatma maliyeti (yüzlerce ms) saatler sürer. Onarımla birlikte süreç havuzu ya da süreç içi zaman aşımı gerekir.
- `computation_struct_recovery`: zaman aşımı fonksiyon başına (`struct_solver_timeout` 60 sn, `computation_struct_recovery.py:221`); fonksiyon sayısıyla çarpılıyor, adımın toplam üst sınırı yok (bayrak kapalı).
- CFG-iso çapa denetiminde `string_refs` alt dizgi semantiği (`anchor_check.py:107-110`): kısa şablon dizgisi her uzun dizgide eşleşir; bugün sorgu `string_refs` boş olduğu için tetiklenmiyor.
- `_apply_per_func_replacements` gövde sonunu ayraç sayarak buluyor, dizgi/yorum içindeki `{`/`}`'yi ayıklamıyor (`c_type_recoverer.py:702-711`); gövdede `"{"` içeren dizgi kapsamı kaydırabilir (şüphe; ard koşul `_noncode_multiset` dizgi bozulmasını yakalar ama yanlış fonksiyona tip yazımını yakalamaz; sınanmadı).
- `engineering/struct_recovery.py:959-969`: yeniden yazım 0 olsa da her `.c` dosyası `struct_recovered/` ve `struct_recovered/originals/` altına iki kez yazılıyor (ikili başına 2×dosya sayısı gereksiz G/Ç).
- Ölü modüller: `karadul/reconstruction/inline_extractor.py` (`InlineExtractor`) ve `karadul/computation/struct_recovery/field_namer.py` yalnız paket `__init__`'inde dışa aktarılıyor; etkin çağıran yok.
- `cfg_iso_match.py:148`: fonksiyon başına hata `logger.debug` ile yutuluyor, sayaç yok; bütün fonksiyonlar hata verse istatistik "0 eşleşme" olarak "başarılı" görünür.
- `computation/fusion/model.py:90-100` `FusionWeights.load` eksik anahtarda `bias` için 0,0 kullanıyor (öntanım −3,5); kısmi ağırlık dosyası sessizce çok farklı bir model üretir.

## Bilinenlerin durumu
| Kalem | Durum | Kanıt |
|---|---|---|
| B-C3 CFG-iso 0/14 376 | duruyor; kök neden bulundu | TIP-01: sorgu histogramı `{"instr": N}`, şablonlar mnemonik; aynı topolojide LSH aday 0, benzerlik 0,0 |
| B-C3 füzyon 0/3 106 | duruyor; kök neden bulundu | TIP-02: tek kanıtlı adayın en yüksek olasılığı 0,182 (kabul 0,90); adaylar birleştirilmiyor; anahtarlar (ad ↔ adres) uyuşmuyor; `fused_matches` tüketicisi yalnız ölü `stages.py:4828` bloğu |
| MaxSMT ofset hatası (brifte doğrulanmış) | duruyor; kök neden bulundu | TIP-03: LOAD/STORE `input0` = alan kimliği 433; gerçek P-code'da 27 251 erişimin hepsi |
| "1 398 yapı parça ve bağsız" | duruyor; kök neden bulundu | TIP-07 (`c_type_recoverer`: ad tabanlı birleştirme + ölçeksiz ofset; 5 585 yapı, 3 kullanım) ve TIP-04 (mühendislik hattı Ghidra sistem yapılarını alıp 21 354 alan adını eziyor, 0 yeniden yazım) |
| İki yapı kurtarma hattı çakışması (soru 2) | çakışmıyor, ikisi de boşa | MaxSMT bayrak kapalı ve çıktısı bağlı değil (TIP-03); mühendislik hattının `types.h`'si `out/`'a girmiyor, `out/` `typed/`'dan geliyor (TIP-04) |
| B-C8 akış sadeleştirme kapalı | duruyor (bayrak `enable_flow_simplification = False`, `config.py:481`) | Onarılmış kodda her fonksiyon ard koşulla (denge, etiket, goto, çağrı, return, deyim kümesi, CFG denkliği) denetlenip ihlalde geri alınıyor (`c_flow_simplifier.py:1032-1103, 1380-1388`). Anlam değiştiren açık yol BULAMADIM; geçişleri tek tek okumadım. Kalan risk: `call_delta`'yı geçişler kendisi bildiriyor (`:1375`), yanlış bildirim çağrı denetimini zayıflatır (CFG denkliği yine de yakalamalı). |
| Sahte kripto etiketi (ab986da) | kısmen | Sabit katmanı onarılmış (`c_algorithm_id.py:1189-1290`: tam belirteç, ayırt edici sabit sayısı). Yapısal katman onarılmamış: TIP-09 (162 sahte "Galois field" 30 ikilide) |
| B-C1 `stages.py` ölü kod | duruyor (kulvarımdaki kısmı) | Füzyon kabul enjeksiyonu (`stages.py:4995-5025`) ve MaxSMT aday tüketimi yalnız `if not _use_step_registry:` bloğunda; `_use_step_registry` `:3100`'de zorla True |
| B-B8 `types.h` iki kez yazılıyor | kulvar dışı (çıktı biçimleyici) | bakmadım |

## Bakamadıklarım
- `reconstruction/recovery_layers/` (constraint_solver 2 079, formula_extractor 3 499, signature_fusion 1 533, cfg_fingerprint 1 189, callee_profile_propagator 705, engine 507 satır): motorun tamamı `computation_recovery.enabled = False` (`config.py:669`) arkasında ve etkileşimsiz koşuda zorla kapalı (`cli.py:751-752`; ölçüm komutu bayraksız). Okumadım; yalnız etkin olmadıklarını gösterdim. UI'dan açılabildiği için (`ui/server.py:1809`) ayrıca taranmalı.
- `computation/struct_recovery/solver.py`, `encoder.py`, `aliasing.py`, `candidate_synthesizer.py`: TIP-03'teki girdi hatası yüzünden çözücünün kendi doğruluğunu (hizalama, negatif ofset, örtüşme) denemedim.
- `c_comment_generator.py` satır içi yorum desenleri (`_LOGIC_COMPILED`, `_VULN_COMPILED`, `CONTROL_FLOW_PATTERNS`) ve `function_summary_patterns.match_function_summary` (`@brief` eşleşmesi): uydurma yorum yolu olabilir, okumadım.
- `c_type_recoverer_ext.py`, `type_recovery_consumer.py`, `_feedback_typing.py` (yinelemeler arası tip yeniden uygulaması), `trex_struct_recovery`.
- `quality/metrics/type_quality.py`, `code_structure.py`, `local_vars.py`, `param_names.py`, `dwarf_baseline.py` ayrıntısı.
- TIP-06/TIP-11'in ürün çıktısındaki YANLIŞ oranı ölçülmedi (yalnız değişen bildirim sayısı ve tek tek örnekler).
- `c_flow_simplifier.py` geçişleri (`_pass_*`) tek tek; etiket yeniden adlandırmanın başka simgelerle çakışması.
- Güven değerlerinin NaN/[0,1] dışı taşması (soru 6): füzyon sigmoid'i taşmaya karşı güvenli (`model.py:32-38`), yapısal güven `min(0.85, …)`, sabit güven `min(0.95, …)`, birleştirme `min(0.98, …)` ile sınırlı; NaN üreten yol görmedim ama sistematik tarama yapmadım. Sabit/1,0'a yapışan değerler: TIP-07 (0,80 sabit alan güveni), TIP-02 (kendisiyle kıyaslanan 1,0 `cfg_hash_similarity`).

## KULVAR BİTTİ
