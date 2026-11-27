# HZ7a — HZ-7a: düzenli ifade deseni önbelleği ve satır ön süzgeci (ilerleme)

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/HZ7a.md`; plan `hiz/PLAN.md` HZ-7a; ortak brif `ORTAK_D1.md` §7 (27 Kasım eki).
- Dal: `worktree-agent-a1190420e5bc0ba1f`; taban main `c59d3c0e` (`git merge --ff-only main`, 22:2x; ürün kodu `ed28e36b`). `karadul.__file__` worktree'yi gösteriyor.
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/HZ7a/` (özet `ozet/`).
- Sert son: 2026-11-28 00:45.
- Aynı anda çalışan paketler: GS1, PUV6c (dosya kümeleri ayrık). Bütün süreler **yük altında**.

## Durum

- 22:22 başladı (`uptime`: yük 4,90 / 4,95 / 6,48). Belgeler okundu: ORTAK_D1 (§5–§7), ORTAK_D0, ONARIM_BRIF, KARARLAR (A-7, A-9, A-19, A-34, A-35, A-36), PLAN HZ-7 / HZ-7a, BULGULAR §3, OK1, BA2.
- Takım tartışma dosyasına (`~/.claude/team-state/discussion.md`) yazılmadı: gönderim yalnız listelenen dosyalara yazma izni veriyor (BA2 ile aynı gerekçe).
- 22:3x ön kayıt `on_kayit_hz7a.md`, commit `1c4acca5` (koddan ve bütün ölçümlerden önce).
- 22:33 "önce" kolu arka planda başladı (Ollama ∥ S8 dizisi; ağaç `urun-ed28e36b`). İlk deneme 22:30'da `yeniden.py`'nin kendi hatasıyla (`ctx.stats` yok) düştü; düzeltilip sıfırdan başlatıldı (ilk denemenin çıktısı silindi, ölçüme girmedi).

## Kalem 1 — kod (`36cc1593`)

`karadul/reconstruction/c_namer.py`:
- Modül düzeyinde `_ozel_desen(kalip, ad, ust_sinir)` (yeni; `_build_param_alias`'tan sonra, işçi bölümünden önce). Anahtar **şablon metni + ad**. Plandaki imza `_ozel_desen(sira, kalip, ad)` idi; sıra yerine metin kullanıldı: iki listenin (`_PARAM_USAGE_PATTERNS`, `_LOCAL_VAR_USAGE_PATTERNS`) sıra numaraları çakışır, metin ise derlenen deseni tek başına belirler. Sözlük süreç başına; girdi sayısı `perf.desen_onbellegi_ust_sinir`'e varınca temizlenir (sayaç `temizleme`). Derlenemeyen desen `("derlenemedi", msg, pattern, pos)` olarak saklanır ve her istekte aynı iletiyle yeni bir `re.error` yükselir: yerel değişken stratejisinde bugünkü "atla + günlüğe yaz" yolu, veri akışında bugünkü "yükselt" yolu aynen işler. Sayaçlar `_OZEL_DESEN_SAYAC` (`isabet`, `derleme`, `hata`, `temizleme`).
- `_ozel_desen_suzgec_uygun(kalip)` + `_param_zorunlu_tek(metin)`: satır ön süzgecinin doğruluk koşulu. `PARAM` metinde tam bir kez; iki karakterlik işaretle (``) değiştirilip `re._parser` ile ayrıştırılır; işaretin iki karakteri art arda iki LITERAL olarak üst düzeyde ya da yalnız grup / atomik grup / en az bir kez yinelenen öğe içinden geçilerek bulunmalı. Seçenek, bakış, koşullu grup, `min = 0` yineleme, karakter sınıfı, büyük / küçük harf duyarsızlığı (genel ya da yerel bayrak) zorunlu sayılmaz. İki karakter: `[PARAM]` (ayrıştırıcı tek karakterlik sınıfı LITERAL'e indirir) ve `PARAM?` (niceleyici adın son karakterine uygulanır) tek karakterlik işaretle yanlışlıkla "uygun" çıkıyordu; ilk sınama koşusunda yakalandı, düzeltildi. Sonuç şablon metni başına bir kez.
- `_ozel_desen_ust_siniri(config)`: alanı okur; geçersizse (yok, `bool`, tamsayı değil) `PerfConfig`'in öntanımı (sayı ikinci kez yazılmadı).
- `_strategy_dataflow`: `_line_search`'e isteğe bağlı satır listesi; üç döngü (parametre, `local_`, otomatik değişken) tek yardımcıda (`_desen_ara`): ad başına bir kez `[ln for ln in body_lines if ad in ln]`, desen `_ozel_desen`'den, süzgeç yalnız uygun şablonda. Seçim kuralı (`conf > best`) ve sırası aynı.
- `_strategy_local_var_naming`: aynı düzen; `re.error` yolu aynı (`except re.error` → debug + `continue`). Layer 1.5 dönüş yakalama deseni `re.compile(r"\bPARAM\s*=\s*(\w+)\s*\(")` şablonundan `_ozel_desen` ile (eski `r"\b" + re.escape(v) + r"\s*=\s*(\w+)\s*\("` ile aynı metin); aranan satırlar adı içerenler (ilk eşleşen satır aynı, sıra korunur).

`karadul/reconstruction/api_param_db.py`: `call_re` (`propagate_params`), `call_start_re` ve `fun_re` (`reverse_propagate_function_names`) ilk kullanımda kurulup örnekte saklanır; `_desenleri_sifirla()` (`__init__`'in sonunda çağrılır; `_db` / `_callback_db`'yi değiştiren yöntem çağırmalı; bugün yok). Boş `all_known` durumunda eskisi gibi erken dönülür ve saklanmaz.

**H5 (ilk ölçüm):** `_PARAM_USAGE_PATTERNS` 35 öğe, koşulu sağlamayan **0**; `_LOCAL_VAR_USAGE_PATTERNS` 125 öğe, koşulu sağlamayan **5** (sıra 66, 68, 71, 92, 93: `PARAM` iki kez geçenler — `PARAM = PARAM + …`, `PARAM = PARAM * …`, `PARAM = PARAM + 1;`, `PARAM = *(…)PARAM;`, `PARAM = *(…)(PARAM + 0x…)`). Toplam **5 / 160**; bunlar süzgeçsiz aranır. (Planın "125 / 125'te `PARAM` bir kez" notu tutmuyor: 5'inde iki kez.) Dönüş yakalama şablonu koşulu sağlıyor.

**Dinamik şablon denetimi (hüküm 3; `kalip_denetimi.py tara`, iki dosya):** önce 236 sabit + 39 sabit olmayan (şablon 33, taranamayan 6: dört `pattern.pattern.replace('PARAM', …)` dahil); sonra 237 sabit + 35 sabit olmayan (şablon 32, taranamayan 3: `PARAM` yerleştirmesi tek yerde, `_ozel_desen` içinde). Üstel 0 / 0 (sabit ve şablon), kaçışsız yerleştirme 0 / 0. Dönüş yakalama deseni şablondan sabite geçti (taranıyor). İstisna listesine ekleme yok. Ham: koşu kökü `ozet/kalip_tara_{once,sonra}.json`.

## Kalem 2 — testler (`36cc1593`)

`tests/test_hz7a_desen_onbellegi.py`, **37 sınama**, hepsi yeşil (yeni kod); main `ed28e36b` koduna karşı **37 / 37 kırmızı** (yeni adlar yok; eşitlik özeti ise eski kodla ayrıca `eski_ozet.py` üzerinden aynı çıktı):
- 20 elle yazılmış Ghidra biçemli gövde (geliştirme setinden alınmadı: depo herkese açık; gerçek veri eşitliği S8 + Ollama yeniden oynatmasında). Veri akışı + yerel değişken stratejilerinin aday listesi (anahtar sırası, eski ad, yeni ad, güven, strateji, gerekçe): 76 aday. Özet (sha256) main `ed28e36b`'nin ürün koduyla üretildi (`PYTHONPATH=urun-ed28e36b python HZ7a/eski_ozet.py <test>`; tohum 0 ve 77 aynı) ve bu dalın koduyla aynı. Ayrıca aynı stratejiler önbelleksiz derleyici + süzgeçsiz aramayla (eski yol, testte `monkeypatch`) gövde gövde eşit; ikinci koşu (önbellek dolu) da eşit.
- Süzgeç koşulu iki listenin her öğesinde (liste içeriği özeti tutmazsa kırmızı: "koşulu yeniden doğrula"); H5 kümesi sabit; anlamsal denetim (süzgeçli şablonun eşleştiği her satır adı içerir; 20 gövdenin satırları × gövdelerdeki Ghidra adları); 20 yapısal örnek (`PARAM?`, `[PARAM]`, `(?i)`, bakış, seçenek …).
- Alt dizgi: `param_1` gövdede yalnız `param_10` içinde (`*param_10 = 0;` → `\*\s*param_1` eşleşir, eski davranış `ptr`), `uVar1` ayrıca `uVar12` / `puVar1` içinde: eski ↔ yeni eşit ve `ptr` adayı var.
- `re.error`: bozuk şablon yerel stratejide atlanır (sonuç bozuksuzla aynı, günlük satırı var), ikinci koşuda hata sayacı artmaz (önbellekten), ileti `re.compile`'ınkiyle aynı; veri akışında iki koşuda da yükselir (eski davranış).
- Sınır 7 iken sonuç aynı, sözlük ≤ 7, temizleme ≥ 10. Anahtar adı içerir; isabet / derleme sayaçları; ayar okuma ve geçersiz değer.
- `api_param_db`: üç çağrıda `propagate_params` sonucu eski yolla (testteki kopya) aynı ve `re.compile` 1 kez; `reverse_propagate_function_names` aynı sonuç ve 2 kez; `_desenleri_sifirla` sözleşmesi.

İlgili takım (`test_ad_gecerliligi`, `test_ba2_kalip_onarimi`, `test_bayrak_on_paketi`, `test_body_param_naming`, `test_c_namer_*`, `test_dynamic_namer`, `test_kalip_denetimi`, `test_local_var_domain_patterns`, `test_ok1_oz_ad_harf`, `test_on_ad_onarimi`, `test_p12{a,b,c,d}_*`, `test_p15a_etkisiz`, `test_param_naming_v172`, `test_regex_safety`, yeni test; 22:40, yük 17): **612 geçti / 15 atlandı / 3 kaldı / 2 hata**. Beklenen: `test_p15a_etkisiz::test_inert_registry_is_accurate` (`kayıtta ama okunuyor: perf.desen_onbellegi_ust_sinir → c_namer.py`; yama kapatır). Öbür dört (`test_kalip_denetimi`'nin iki sınaması + iki kurulum hatası, `RuntimeError`) o koşuda yük 17 iken çıktı; aynı dosya tek başına 8 / 8, yeni testle birlikte 45 / 45, ilk on dosyayla birlikte 396 / 15 atlandı / 0 kaldı (22:42, yük 9). Yük kaynaklı geçici sayıldı (kapının çocuk süreç bekçisi 2 sn ilerleme görmezse öldürüyor); tam takımda yeniden bakılacak. İletinin tam metni o koşuda kaydedilmedi.

## Kalem 3 — mutasyon ve yama (`c4fc91fd`)

- `scripts/measurement/mutation_specs_hz7a.json`: **15 / 15 öldü** (anahtara ad katmamak; ön süzgeci ters çevirmek ×2; `re.error` yolunu düşürmek ×3 — önbelleğe girmez, yakalanmaz, `None` döner; api desenini her çağrıda kurmak ×2; sıfırlamanın boşaltmaması; sınırın işlememesi; süzgeç koşulunun gevşetilmesi ×4 — çift `PARAM`, `IGNORECASE`, `min = 0`, işaret çifti; dönüş yakalama anahtarı). Süre sınaması yok; eşitlik / sayaç / yapı sınamaları öldürdü. Günlük koşu kökünde `hz7a_mutasyon.log`; sonra `git diff` temiz.
- Yama `docs/arge/2026-11-23_dalga1/yamalar/HZ7a__config.py.patch`: INERT satırını siler, alan yorumunu `# okuyan: reconstruction/c_namer.py _ozel_desen_ust_siniri (HZ-7a)` yapar, bölüm başlığından `HZ-7a`'yı çıkarır; öntanım 200 000 aynı. `git apply --check` geçti; ağaca uygulanmadı. Koşu kökündeki yamalı kopyada (`yamali/`: `karadul/` + yamalı `config.py` + üç test dosyası + `docker/measurement/karadul.yaml`) `test_p15a_etkisiz` + `test_bayrak_on_paketi` + `test_hz7a_desen_onbellegi` **192 geçti / 16 atlandı / 0 kaldı**.
