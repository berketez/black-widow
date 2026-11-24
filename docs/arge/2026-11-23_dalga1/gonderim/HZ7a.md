# HZ7a — HZ-7a: düzenli ifade deseni önbelleği ve satır ön süzgeci (çıktıyı değiştirmez)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5 ve §6 dahil), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-9, A-19, A-34, A-35, A-36), `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-7" girişi ve "HZ-7a" (adımlar 1–7, kabul, ön kayıt: aşağıdaki hükümlerle uygula; satır numaraları eski, işlevleri `grep -n "def <ad>"` ile bul), `docs/arge/2026-11-19_mythos/hiz/BULGULAR.md` §3 (seri profil), `docs/arge/2026-11-19_mythos/ozkod/OK1.md` ve `docs/arge/2026-11-23_dalga1/BA2.md` (senden hemen önce `c_namer.py`'ye giren iki paket; yeniden oynatma düzeneği OK1'inki).

## Neden

Dünkü Ollama uçtan uca koşusunda (13 160 fonksiyon, yük altında) yeniden kurma 2 641 sn sürdü; en pahalı adım `c_naming` 812 sn ve 17 ad üretti. Ghidra'sız seri profilde yeniden kurmanın 953 sn'sinin 481 sn'si düzenli ifade derlemesi (3,68 M derleme): aynı desen her (ad, desen) çifti için yeniden derleniyor ve bütün satırlarda aranıyor. Bu paket derlemeyi önbelleğe alır ve aramayı adın geçtiği satırlara indirir. Çıktı değişmez.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Çıktı bayt bayt aynı:** aday listeleri (ad, güven, sıra), `naming_map.json`, `naming_provenance.json`, `reconstructed/src/` önce ↔ sonra eşit. Karar kurallarına, desen listelerine ve içeriklerine, aday güvenlerine dokunma.
2. **`config.py`'ye yazmazsın.** Alan var: `perf.desen_onbellegi_ust_sinir` (INERT'te, 200 000). Yama `docs/arge/2026-11-23_dalga1/yamalar/HZ7a__config.py.patch`: INERT satırını siler, yorumu düzeltir; ağacına uygulama.
3. **BA2'nin alanı:** BA2 `c_namer.py`'de üstel kalıp satırlarını değiştirdi ve tam takıma kalıp denetimi kapısı ekledi (`tests/test_kalip_denetimi.py`). Senin kurduğun dinamik desenler (şablon + `re.escape(ad)`) o kapının "dinamik şablon" denetiminden geçmeli; kapı kırmızıya düşerse deseni düzelt, istisna listesine ekleme.
4. **Ön süzgecin doğruluk koşulu testte:** `PARAM` her desende tam bir kez ve zorunlu konumdaysa satır ön süzgeci uygulanır; koşulu sağlamayan desen süzgeçsiz aranır. Koşul iki desen listesinin HER öğesi için testte denetlenir (liste değişirse test kırmızı olur). Ad, satırda yalnız başka bir tanımlayıcının parçası olarak geçiyorsa (alt dizgi) davranış eskisiyle aynı kalmalı: bunu örnekle test et.
5. **Ölçüm Ghidra'sız yeniden oynatmayla** (OK1'in düzeneği: `~/karadul_olcum/runs/dalga1-2026-11-23/OK1/ozet/kos1.sh`, `OK1/yeniden.py`; kopyala, uyarla, o köke yazma): eşitlik için S8'in 8 ikilisi (girdi `~/karadul_olcum/runs/urun-onarim-a62f15e/…` çalışma alanları; önce = main, sonra = dalın) + Ollama çalışma alanı (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_ba_kapali/ws`; salt okur; en çok iki yeniden oynatma: önce, sonra). Ollama yeniden oynatması tek başına TAHMİN 30–45 dk sürer: arka planda koş, beklerken belge yaz. Ghidra koşusu YOK.
6. **Süre hükmü yük altında:** "yük altında" etiketli, `uptime` künyeli, aynı koşulda art arda önce / sonra. Kesin oran boş makine ölçümünde (HZ-9). Eşitlik asıl kabuldür.
7. **Mutasyon süreyle değil eşitlikle öldürür:** desen anahtarına adı katmamak, ön süzgeci ters çevirmek, `re.error` yolunu düşürmek, api desenini her çağrıda yeniden kurmak → eşitlik / sayaç testi öldürmeli.

## Yazabileceğin dosyalar

`karadul/reconstruction/c_namer.py` — YALNIZ `_strategy_dataflow` ve `_strategy_local_var_naming` içindeki desen kurma / arama döngüleri, bu iki işlevin `_line_search` yardımcıları ve modül düzeyinde yeni `_ozel_desen`; `karadul/reconstruction/api_param_db.py` (`propagate_params`, `reverse_propagate_function_names` ve örnek başına desen saklama); yeni `tests/test_hz7a_desen_onbellegi.py`, `scripts/measurement/mutation_specs_hz7a.json` (≥ 6 mutant); `docs/arge/2026-11-19_mythos/hiz/on_kayit_hz7a.md`, `docs/arge/2026-11-19_mythos/hiz/HZ7a.md` (ilerleme dosyası); yama.

**Dokunma:** `c_namer.py`'nin öbür stratejileri (`_strategy_string_context` dahil), desen listeleri (`_PARAM_USAGE_PATTERNS`, `_LOCAL_VAR_USAGE_PATTERNS`) ve içerikleri, `_add_candidate`, `karadul/config.py`, `karadul/stages.py`, `karadul/pipeline/steps/`, `karadul/ghidra/`.

`c_namer.py` ve `api_param_db.py`'ye bakan eski mutasyon tanımlarını (`grep -l`) değişiklikten sonra yeniden koş; bayatlayanı düzelt ve yaz.

## Ön kayıt (`on_kayit_hz7a.md`; ölçümden önce ayrı commit; sayılar ana oturumun)

> H1 (eşitlik): S8'in 8 ikilisinde ve Ollama çalışma alanında `naming_map.json`, `naming_provenance.json` ve `reconstructed/src/` önce ↔ sonra bayt eşit (9 / 9).
> H2 (süre, Ollama yeniden oynatması, yük altında, art arda): `c_naming` adımı sonra / önce oranı ≤ 0,6.
> H3 (süre, S8'in en büyük iki ikilisi: sqlite3, mac/tmux): `c_naming` oranı ≤ 0,5.
> H4 (profil): seri profilde (plandaki `profil_yeniden.py` ya da eşdeğeri, bir ikili) `re._compile` kümülatif payı ≤ %5 (BULGULAR'da %50,5).
> H5: ön süzgeç koşulunu sağlamayan desen sayısı — yön bildirilmez, ilk ölçüm.

## Sıra

1. Ön kayıt → commit. 2. Kod + testler (plan adım 4: 20 küçük C gövdesi, eski davranış önbelleksiz yardımcıyla) + mutasyon. 3. S8 yeniden oynatması (H1'in 8'i, H3). 4. Ollama yeniden oynatması (H1'in 9.'su, H2). 5. Profil (H4). 6. Tam takım.

## Sert son

Gönderim iletisinde yazılı. Ollama'nın "sonra" kolu koşulamazsa "kalan" diye yaz.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: Ollama çalışma alanında `c_naming` kaç saniye → kaç saniye, çıktı bayt eşit mi (9 / 9). Sonra H1–H5, önbellek boyutu ve isabet sayaçları, test / mutant sayıları, eski tanımların durumu, commit listesi, yama, HZ-7b / HZ-7d için notlar, koşu kökünün yolu ve boyutu.
