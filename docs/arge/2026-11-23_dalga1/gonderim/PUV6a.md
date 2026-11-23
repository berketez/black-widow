# PUV6a — P-ÜV6'nın ilk yarısı: Go ve ObjC üst veri adlarını ürün çıktısına bağlama

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-2, A-10, A-13, A-14, A-17, A-25, A-27, A-28), `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 ve "P-ÜV6", `docs/arge/2026-11-19_mythos/ustveri/P-UV1.md` ve `P-UV2.md` (okuyucuların raporu; P-ÜV6'ya bırakılan notlar), `docs/arge/2026-11-19_mythos/ustveri/olcum/HEDEF.md` (hedef seti, ölçüm tanımı, bugünkü ürünün "önce" sayısı), `docs/arge/2026-11-20_dalga0/BAYRAK.md` §3.1 (bağlama tablosu).

## Neden bu paket ilk

Hedef setinde bugünkü ürün: terminal-notifier'da ad bekleyen 40 fonksiyonun **0**'ına, Ollama diliminde 13 160 fonksiyonun **17**'sine ad veriyor. Aynı ikililerde ürün kodu (P-ÜV1 / P-ÜV2 okuyucuları, main'de) 10 600 Go + 151 ObjC ve 32 ObjC adını okuyor ama hiçbir yere yazmıyor: üretici adımlar Faz 1 listesinde yok, ad kanalı yok. Bu paket o bağı kurar.

## Kapsam (plandaki P-ÜV6'nın bölünmüş hâli; ana oturum kararı)

Plan P-ÜV6'yı P-ÜV1–5 ve 7 main'deyken tek paket olarak yazmıştı. Bugün main'de yalnız P-ÜV0, 1, 2 var. Bu paket **yalnız Go ve ObjC**'yi bağlar; ortak altyapıyı (etiket, `ozgun_ad`, ölçülmüş kesinlik tablosu, kanıt satırı yolu) sonraki kanalların aynı kalıpla eklenebileceği biçimde kurar.

**Bu pakette VAR:** plan kalem 1 (yalnız aşağıdaki dört bayrak), 2 (yalnız `go_metadata_recovery`, `objc_metadata_recovery`), 3 (kaynaklar `go_pclntab`, `objc_method`), 4 (`ozgun_ad`), 5 (etiket `üst veriden`; `ust_veri_dogrulama` alanı bugün her kayıtta `olculmedi`), 6 (ölçülmüş kesinlik tablosu, yalnız Go ve ObjC satırları), 7 (eski Go kanalıyla çift aday yok; `GoBinaryAnalyzer` bulgusu yalnız rapora), 8 (ölçüm; aşağıda).

**Bu pakette YOK (P-ÜV6b, sonraki paket):** Swift (`swift_type_accessor`), RTTI (`rtti` kanalının kanıt satırına çevrilmesi, `rtti_recovery` adımı), `enable_macho_entry_main` (P-ÜV5), `enable_go_metadata_integrity` ve `tutarsiz` / `ust_veri_supheli` damgaları (P-ÜV7 main'de değil), durum sabitlerinin `goruntu.py`'de tek tanıma taşınması. Bunlara dokunma; `_add_rtti`'yi değiştirme.

## Ana oturumun bağlayıcı hükümleri (plan metninin önüne geçer)

1. **Go, `pcsp_kapsama`:** `kisa` ya da `tasan` olan fonksiyon ad adayı olmaz (E türü bozmada ~170 yanlış ad buradan geliyordu; P-UV1.md). Sayaç: `pcsp_elendi`.
2. **ObjC, A-28:** Ghidra o adreste fonksiyonu adlandırmışsa ve Ghidra'nın adı üst verideki seçiciyle birebir aynıysa (Ghidra'nın yazım biçimini terminal-notifier çıktısında ölç, varsayma), tam ad (`-[Sınıf seçici]` / `+[Sınıf seçici]`) onun yerine yazılır. Ghidra'nın adı seçiciden farklı, jenerik olmayan bir adsa dokunulmaz (`ghidra_adli`). Bu, P13b'nin "aday yalnız adsız fonksiyona" kuralına tek istisnadır; yalnız `objc_method` kaynağı için.
3. **ObjC, ad yazılmayacak kayıtlar** (kanıt satırı olur, ad adayı olmaz; her biri ayrı sayaç): okuyucunun `ad_yazilabilir = False` dediği kayıt; `swift = true` kayıt (Swift sınıfının ObjC köprüsü: o adresin geliştirici adı ObjC değil); `imp_paylasimli` kayıt (aynı gövdeyi birden çok yöntem paylaşıyor: hangisi olduğu bilinemez). Bu üç kural iTerm2 GT'sine bakılmadan, şimdi konmuştur.
4. **Etiket:** yeni değer `üst veriden` (`LABEL_METADATA`), `NAME_LABELS`'a eklenir; üst veri adı `kesin` almaz. `scripts/measurement/alt_kanal.py` `GUVEN_ETIKETLERI` ile eşitlik testi kilitli kalır (ikisi birlikte güncellenir). Etiketi gösteren her yer (rapor, arayüz sunucusu, KaradulLM araçları) yeni değeri tanımalı: bilinmeyen etiket diye düşürmemeli, `kesin` gibi de göstermemeli.
5. **Güven:** `MEASURED_METADATA_PRECISION` tablosu `naming_labels.py`'de; değerler sınama ikililerindeki kanal düzeyi ölçümden: Go docker-compose 90 077 / 90 077, ObjC iTerm2 33 611 / 33 611 (kaynak P-UV1.md, P-UV2.md; Wilson alt sınırı betikle hesaplanır, elle yazılmaz). Eşik `AD_ESIGI` `naming_labels.py`'den içe aktarılır; kendi sabitini tanımlama (A-13, A-25). Bu iki kaynak `UNMEASURED_SOURCES`'ta olmaz.
6. **Bayraklar öntanımda kapalı kalır.** Öntanımda açma kararı (K-4) ayrı ölçümle, ana oturumda: A-14 en az 3 bağımsız program ister; bugün Go'da 2 (docker-cli, docker-compose), ObjC'de 2 (terminal-notifier, iTerm2) var. Bu paket kararı vermez; raporunda kanal başına "kaç programda ölçüldü" satırını yazar.
7. **Kanıt satırı yolu:** ad yazılmayan üst veri kaydı (madde 1 ve 3) kaybolmaz; köken kaydında / raporda "üst veri kanıtı" olarak görünür (alan adı ve yeri senin tasarımın; var olan kanıt düzenine uy: `provenance_evidence`). Sahte ad üretilmez.

## Yazabileceğin dosyalar

- `karadul/stages.py` — YALNIZ Faz 1 adım listesi (`PipelineRunner(steps=[…])`, ≈ 2501–2533): iki adım `binaryninja_analysis`'ten sonra, `type_recovery_consumer`'dan önce. Başka satıra dokunma (`_recover_main_from_entry` P-ÜV5'in).
- `karadul/pipeline/steps/__init__.py` (iki adımın kaydı), `karadul/pipeline/steps/_feedback_naming_candidates.py`, `karadul/pipeline/steps/_feedback_naming_merger.py`
- `karadul/core/naming_labels.py`
- Etiketi okuyan yerler: `karadul/reporting/report_data.py`, `karadul/reconstruction/tarif/baglama.py`, `karadul/lm/guard.py`, `karadul/lm/tools/__init__.py`, `ui/server.py` (yalnız etiket sözlüğü / süzgeci), `scripts/measurement/alt_kanal.py`, `scripts/measurement/alt_kanal_olc.py`, `scripts/measurement/urun_olc.py` (yalnız yeni etiket değeri gerekiyorsa). Tam listeyi `grep -rn "LABEL_CERTAIN\|NAME_LABELS\|GUVEN_ETIKETLERI\|doğrulanmadı" karadul scripts ui` ile çıkar; bu listede olmayan bir dosya gerekiyorsa yama bırak.
- Üretici adımlar (`karadul/pipeline/steps/go_metadata_recovery.py`, `objc_metadata_recovery.py`): yalnız Faz 1'e bağlanırken ortaya çıkan zorunlu düzeltme (ör. `requires` yapıtı Faz 1'de o noktada yoksa). Okuyuculara (`karadul/analyzers/ustveri/*.py`) DOKUNMA; eksik alan gerekiyorsa ilerleme dosyana yaz.
- Yeni: `tests/test_puv6a_baglama.py`, `scripts/measurement/mutation_specs_puv6a.json`, `scripts/measurement/ustveri_urun.py` (P-ÜV8 kalem 5–6: ürün düzeyi sayım; HEDEF.md kalem 4'ün tanımıyla aynı) + testi `tests/test_puv8_urun.py`
- Belgeler: `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV6a.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` (ilerleme dosyası)
- Yama: `docs/arge/2026-11-23_dalga1/yamalar/PUV6a__config.py.patch` (`enable_go_pclntab_naming`, `enable_objc_metadata_naming` INERT satırları ve `# ETKİSİZ` yorumları)

**Dokunma:** `karadul/config.py`, `karadul/reconstruction/c_namer.py`, `karadul/ghidra/headless.py` (P16e aynı anda yazıyor), `karadul/analyzers/ustveri/`, `karadul/analyzers/{go_binary,cpp_rtti,swift_binary}.py`, `tests/test_p15a_etkisiz.py` (yamayla yeşile döner).

## Ön kayıt (`on_kayit_PUV6a.md`; ölçümden önce commit; sayıları sen değiştirme)

> H1 (öntanım değişmez): bütün bayraklar kapalıyken S8'in 5 ikilisinde (debian cat, tree, sqlite3, zstd; mac/tmux) `naming_map.json` tabanla bayt bayt aynı; `ghidra_output` ve `.c` farkı yalnız bilinen çağıran sırası (sıra-normal karşılaştırmada 0).
> H2 (düz C etkilenmez): dört bayrak açıkken aynı 5 ikilide değişen ad 0; iki kanalın durumu `veri_yok`.
> H3 (terminal-notifier, soyulmuş kopya, ürün koşusu, bayraklar açık): üst veri kaynaklı ad ≥ 30 / 32 ürün çıktısında (`naming_map` ve `out/src`); GT'ye göre yanlış 0; ad bekleyen 40 fonksiyonda doğru ad 0 → ≥ 30.
> H4 (Ollama arm64, gösteri çalışma alanı üstünde Ghidra'sız yeniden oynatma): `go_pclntab` kanalında `tuttu` ≥ 9 540 (P-ÜV8 H4); `pcsp_elendi` sayısı raporlanır (ilk ölçüm).
> H5 (Ollama ObjC, A-28): 151 yöntemin ≥ 140'ına tam ad yazılır (HEDEF: 148'i Ghidra'da yalnız seçiciyle adlı).
> H6 (docker-cli, keşif, Ghidra'sız aday listesi ↔ GT): süzgeçlerden geçen Go adaylarının ≥ %99,9'u GT ile aynı (`ozgun_ad` üstünden).
> H7 (etiket): üst veri kaynaklı hiçbir ad `kesin` etiketi taşımaz; hepsinde `label = üst veriden`, `ozgun_ad` dolu, güven tablodan.
> H8 (SINAMA; kurallar dondurulduktan sonra BİR kez, Ghidra'sız aday listesi ↔ GT): iTerm2'de süzgeçlerden (hüküm 3) geçen ObjC adaylarında yanlış ≤ %1 ve doğru ≥ 33 000; docker-compose'da Go adaylarında yanlış ≤ %0,1.
> H9 (süre): bayraklar kapalıyken iki adımın koşu süresine etkisi ≤ 0,1 sn / ikili.
> Tutmayan hüküm silinmez; neden ayrıca yazılır.

## Yapılacaklar (sırayla; her kalem bitince commit)

1. Ön kayıt → commit. Taban sayıları yeniden üret: terminal-notifier 0 / 40 (HEDEF.md kalem 4'ün komutu; hazır kök varsa onu oku, yeniden koşma).
2. Kanal kodu: `_add_go_pclntab`, `_add_objc_methods`; `K4_CHANNEL_FLAGS`'a iki kaynak; `k4_inputs`'a iki yapıt (`go_functions`, `objc_methods` ve durumları); A-28 için `GhidraFunctionIndex`'e "adlı ama ad = seçici" yolu (var olan `key_for` davranışı öbür kanallar için değişmez).
3. Etiket, `ozgun_ad`, ölçülmüş kesinlik tablosu, kanıt satırı; etiketi okuyan yerler.
4. Faz 1 listesi + `__init__.py`; `config.py` yaması (yama geçici uygulanmış hâlde `tests/test_p15a_etkisiz.py` yeşil olmalı).
5. Birim testleri ≥ 16 (düzen: `tests/test_p13b_kanallar.py`; sahte yapıtlarla): kanal kapalı / açık; Ghidra adlı fonksiyona aday yok; A-28 yolu (ad = seçici → tam ad; ad ≠ seçici → dokunma); `kisa` / `tasan` elenir; `swift` / `imp_paylasimli` / `ad_yazilabilir = False` kanıt satırı olur; `ozgun_ad` korunur; etiket `üst veriden`; güven tablodan; iki Go kanalı aynı adrese iki aday üretmez; etiket sözlüğü eşitliği; adım sırası (üretici tüketiciden önce).
6. Mutasyon ≥ 10 (plandaki listeden Go / ObjC'ye düşenler + hüküm 1–3'ün her biri için birer mutant).
7. **Ölçüm, önce Ghidra'sız:** H4, H5 (gösteri çalışma alanı `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws`, salt okur: kanalı o çalışma alanının `ghidra_functions.json`'u ve ikilisiyle çağıran küçük sürücü `ustveri_urun.py` içinde), H6.
8. **Ölçüm, Ghidra'lı (kuyrukla; `~/karadul_olcum/ghidra_kuyruk.sh PUV6a <etiket> …`):** önce terminal-notifier (H3; küçük, birkaç dakika), sonra S8'in 5 ikilisi bayraklar kapalı (H1) ve açık (H2). Kendi dalının ürün ağacı: ORTAK_D0 §3.
9. Kuralları dondur (dondurma commit'ini ilerleme dosyasına yaz) → H8'i bir kez ölç.
10. Tam takım (yama uygulanmış hâlde), sonra yamayı geri al; `git status` temiz.

**Ollama'nın uçtan uca ürün koşusu senin işin değil** (2 saatten uzun; ana oturum dalın main'e girince koşar). Dönüş mesajına koşu komutunu ve bayrak yaml'ını yaz.

## Sert son: 11:45

O saatte dur; bitmeyen kalemleri "kalan" diye yaz, commit'le, dön. Öncelik sırası yukarıdaki sıradır: kod + test + mutasyon + Ghidra'sız ölçüm (1–7) önce biter.

## Dönüş mesajı

İlk satır gerçek uygulama sayıları (önce → sonra): terminal-notifier doğru ad x / 40; Ollama Go `tuttu`, ObjC tam ad; docker-cli aday kesinliği; iTerm2 / docker-compose sınama. Sonra ORTAK_D0 §7 biçimi: H1–H9 hükümleri, test ve mutant sayıları, commit listesi, yamalar, riskler, P-ÜV6b'ye bırakılanlar, Ollama koşu komutu.
