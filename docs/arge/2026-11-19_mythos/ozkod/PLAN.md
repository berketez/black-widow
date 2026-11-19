# ÖZ KOD hattı — plan (tur 1 sonrası, 2026-11-19)

Bu belge kendi başına uygulanabilir olacak biçimde yazıldı: uygulayan Opus ajanları bu turun oturumunu görmeyecek. Kanıt ve sayılar `BULGULAR.md`'de, ayrıntılı günlük `DEFTER.md`'de. Araştırma betikleri `scripts/arge/ozkod/`, çıktıları `~/karadul_olcum/runs/arge-2026-11-19/ozkod/`.

## 0. Bir bakışta

**Hat:** ÖZ KOD (soru kimlikleri A5, I1, A6, H2, B1-`oz_ad`).

**Hipotez (bu turdan sonra).** Programın kendi fonksiyonlarının adı iki yerden **hesaplanabilir**:
1. Fonksiyonun kendi adını taşıyan dizgi (`__func__`, assert) — dizgi adın kendisidir; dönüştürülmeden yazılmalıdır.
2. Fonksiyonu **kaydeden** yer — (dizgi, fonksiyon işaretçisi) çiftleri: komut / biçim / sınıf tabloları, kayıt çağrıları. Ad = önek + dizgi + sonek; ek aynı tablodaki adı bilinen fonksiyonlardan ("çapa") öğrenilir. Sonek sütuna bağlıdır, yani **rol** tablonun yuvasından gelir.

**Literatürün beklediği cevap (yasak):** dizgiden anahtar sözcük + fiil / nesne; dil modeli. Birincisi bu turda bir kez daha çürüdü: `oz_ad`'ın 40 yanlışı, kanıt dizgisi zaten ad iken onu sözcüklere bölüp yeniden kurmaktan geliyor.

**Aykırı öncül (sınandı, tuttu):** kanıt adlandırılan fonksiyonun içinde değil, onu kaydeden yerdedir.

**Ölçülen (geliştirme seti; keşif / sınama bölmeli):**

| Mekanizma | Keşif | Sınama | Ön kayıt |
|---|---|---|---|
| K1 kayıt çifti + sütun eki, çapa kâhin | 740 / 754 (%98,1) | 103 / 126 (%81,7) | ≥ %90: **tutmadı** |
| K1, bugünkü ön ad çapalarıyla | 95 / 97 | 0 / 1 | — |
| K1, çapa = ön adlar + G1 | 239 / 241 | 0 / 1 | — |
| `oz_ad` harf koruma | +3 doğru | +37 doğru | ölçüm sonrası tanım |
| R1 (`oz_ad` tekliği) + harf koruma | 78 / 80 | 28 / 31 | R1 tek başına **tutmadı** |
| G1 (tekil tanımlayıcı dizgi → ad) | 454 / 484 (%93,8) | 114 / 143 (%79,7) | ≥ %85: **tutmadı** |

**Bu yüzden sıra:** önce ölçülmüş ve riski düşük onarım (ÖK-1), sonra bağımsız veri (ÖK-V) ve kör ölçüm (ÖK-5); ürüne giren her yeni kanal bayrak arkasında, öntanımı kapalı (ÖK-2, ÖK-3, ÖK-4, ÖK-6).

**Durma ölçütü (hat için).** ÖK-5'te K1'in bağımsız nüfustaki norm kesinliğinin Wilson alt sınırı < %70 çıkarsa K1 ad kanalı olarak bırakılır, yalnız kanıt satırı olarak kalır. ÖK-3'te G1'in kapılı hâli bağımsız nüfusta < %85 kalırsa G1 bırakılır; ÖK-1 ve R1 kalır.

**Paket sırası ve önkoşullar:**

```
ÖK-1 (oz_ad harf koruma)            önkoşul: P12d bitmiş ya da aynı ajan sırayla yapar (aynı fonksiyon)
ÖK-4a (kayıt çifti çıkarıcısı, ürün; ad vermez)   önkoşul: yok           ┐ ÖK-1 ile paralel olabilir
ÖK-V (bağımsız nüfus: indirme + GT + koşu)        önkoşul: Berke onayı   ┘ (ayrık dosyalar)
ÖK-2 (R1 kapısı)                    önkoşul: ÖK-1, ÖK-4a
ÖK-5 (K1 / G1 kör ölçümü, araştırma betikleriyle) önkoşul: ÖK-V
ÖK-3 (G1 üretici)                   önkoşul: ÖK-2, ÖK-5'in G1 hükmü
ÖK-4b (K1 ad kanalı)                önkoşul: ÖK-4a, ÖK-5'in K1 hükmü
ÖK-6 (modül öneki kanıt satırı)     önkoşul: ÖK-5 (aynı nüfusta sayım)
ÖK-7 (açık ölçümler)                önkoşul: ÖK-V
```

Aynı anda en çok 3 paket. `karadul/reconstruction/c_namer.py`, `karadul/stages.py`, `karadul/config.py`, `karadul/core/naming_labels.py`, `karadul/reconstruction/tarif/baglama.py` ortak ve tehlikeli dosyalardır: bunlara dokunan paketler (ÖK-1, ÖK-2, ÖK-3, ÖK-4b, ÖK-6) **sıralı** koşar, paralel değil.

**Ortak kurallar (her paket için):**
- Depo kökünden `PYTHONDONTWRITEBYTECODE=1 python -m …` / `python scripts/…`. Kabuk zsh: komutu değişkende tutma.
- Kilitli setler (`targets/test_seti/`, `targets/dogrulama_seti/` ve koşu çıktıları) açılmaz, listelenmez.
- Ön kayıt metni ölçümden **önce** commit'lenir (aşağıda her pakette hazır metin var; `docs/arge/2026-11-19_mythos/ozkod/on_kayit_<paket>.md` olarak yazılır). Tutmayan beklenti silinmez.
- Sayılar betikten; Wilson %95 (`scripts/measurement/ks1_olc.py` `oran`).
- Ürün ölçümü: `scripts/measurement/urun_kos.py --agac <ürün ağacı> --kok <yeni kök> --paralel 3`, sonra `scripts/measurement/urun_olc.py olc --kok-debian <kök>/debian --kok-mac <kök>/mac --kol <ad> --json … --md …` ve `… karsilastir --taban <taban.json> --yeni <yeni.json>`. Aynı anda en çok 1 Ghidra koşusu; `PYTHONHASHSEED=0`; koşuya özel `KARADUL_CACHE_DIR`.
- Bayrağın ölçüm kolunda nasıl açıldığı: `enable_ks1_anchors` bayrağının ablasyon kollarında nasıl kapatıldığına bak (`grep -rn enable_ks1_anchors karadul scripts`); yeni bayraklar aynı yoldan açılır.
- Mutasyon: `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_<paket>.json`. Mutantın `find` metni dosyada tekil ve `replace` metni farklı uzunlukta olmalı; aynı worktree'de eşzamanlı mutasyon yok.
- Git: commit'i ana oturum atar; `Co-Authored-By` satırı yok.
- Sürüm numarası: ana oturum belirler (yalnız hata düzeltme → Z + 1; yeni özellik → Y + 1).

**Taşınacak araştırma betikleri (nereden → nereye):**

| Bu turun betiği (`scripts/arge/ozkod/`) | Ne | Hedef | Paket |
|---|---|---|---|
| `kayit_cifti.py`: `_argumanlar`, `cagri_ciftleri_metin`, `_FN_ARG`, `_DIZGI_ARG` | decompile edilmiş C'den çağrı yeri (dizgi, işaretçi) çiftleri | `karadul/reconstruction/tarif/kayit_cifti.py` (yeni) | ÖK-4a |
| `ek_kurali.py`: `adaylar`, `_ek_oyu`, `tahmin`; `kayit_cifti.py`: `ek_cikar`, `ek_uygula`, `ad_bicimli` | K1 aday grupları, ek oylaması, ad üretimi | `karadul/reconstruction/tarif/kayit_cifti.py` (yeni) | ÖK-4a (aday), ÖK-4b (ad) |
| `docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.py`: `elf_oku`, `macho_oku`, `Hedefci`, `bolum_turleri`, `tablolari_sec`, `kodda_alinan_adresler` (N4'ün betiği; bu tur içe aktardı) | veri sözcükleri: yer değişimi çözümü, tablo ve adım | `karadul/reconstruction/tarif/veri_sozcukleri.py` (yeni) | ÖK-4a |
| `oz_ad_ayrim.py`: `ozellikler` içindeki `n_fn`, `n_tanim`, `cakisma`, `kendi`, `kayitli`; `kural_tut` | R1 | `karadul/reconstruction/c_namer.py` (kapı) | ÖK-2 |
| `oz_ad_uretici.py`: `tanim_mi`, `g1` | G1 | `karadul/reconstruction/c_namer.py` ya da ön ad tohumu | ÖK-3 |
| `ozkod_veri.py` (ikili başına olgu önbelleği), `ek_kurali.py` (ölçüm kısmı), `ek_kurali_belirtec.py`, `ek_kurali_capa.py`, `oz_ad_harf.py`, `tavan.py` | ölçüm | `scripts/measurement/ozkod_olc.py` (tek betik, alt komutlu) | ÖK-5 |
| `tavan.py` içindeki sandviç sayımı | modül öneki | `karadul/reconstruction/tarif/modul_oneki.py` (yeni) | ÖK-6 |

Taşırken davranış değişmemeli: taşınan fonksiyonun çıktısı, araştırma betiğinin aynı girdideki çıktısıyla eşit olmalı (her pakette "eşdeğerlik sınaması" kalemi var).

---

## ÖK-1 — `oz_ad`: kanıt dizgisi tek bir tanımlayıcıysa adı dönüştürmeden yaz

**Amaç.** `string_context` klasik yolunda kanıt dizgisi alt çizgili tek bir C tanımlayıcısıysa ad, anahtar sözcüklerden yeniden kurulmak yerine dizginin kendisi olsun (harfler, rakamlar ve belirteç sayısı korunur).

**Kanıt.** `BULGULAR.md` §1.2: 196 `oz_ad` adının 93'ü doğru; kanıt harfleriyle 133'ü doğru olurdu (+40: zstd 37, coreutils 1, openssl 1, mac/tmux 1). Betik: `scripts/arge/ozkod/oz_ad_harf.py`.

**Önkoşul.** P12d (`_strategy_string_context` erken dönüşü; `docs/arge/2026-11-18_onarim/gonderim/OKU.md`) aynı fonksiyona dokunur. ÖK-1, P12d main'e girdikten sonra ya da aynı ajan tarafından P12d'nin hemen ardından yapılır. İkisi paralel koşmaz.

**Dokunacağı dosyalar.**
- `karadul/reconstruction/c_namer.py` (var): `_strategy_string_context` içindeki "Asama 2: Klasik keyword extraction" bölümü (a62f15e'de satır ≈ 3523–3570; `new_name = "_".join(best_keywords[:3])`).
- `karadul/reconstruction/tarif/alt_kanal.py` (var): `_is_own_name` yüklemi ve tanım sürümü.
- `scripts/measurement/alt_kanal.py` (var; ürün sınıflayıcısının dondurulmuş kopyası): aynı yüklem, aynı sürüm.
- `karadul/config.py` (var): yeni bayrak.
- `tests/test_ok1_oz_ad_harf.py` (yeni), `tests/test_alt_kanal.py` (var; yeni yüklem satırı), `scripts/measurement/mutation_specs_ok1.json` (yeni).

**Dokunmayacağı dosyalar.** `c_namer.py`'nin agresif aşaması ve erken dönüşü (P12d'nin alanı); `_extract_keywords_from_string`, `_sanitize_c_name` (başka çağıranları var); `karadul/stages.py`; `scripts/measurement/urun_olc.py`, `ks1_olc.py`.

**Adımlar.**
1. `karadul/config.py`: `enable_subchannel_silencing` satırının (≈ 608) altına `oz_ad_verbatim: bool = False` ekle (yorum: "ÖK-1: kanıt dizgisi tek tanımlayıcıysa ad dönüştürülmeden yazılır").
2. `c_namer.py` klasik aşama: `best_string` seçildikten sonra, `e = best_string.strip()` için koşul — `re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", e)` ∧ `"_" in e.strip("_")` ∧ en az bir küçük harf — tutuyorsa ve bayrak açıksa `new_name = e` (hiçbir dönüştürme yok; `_sanitize_c_name` çağrılmaz). Koşul tutmuyorsa bugünkü yol aynen. Güven formülü değişmez. Kanıt, `code_path="classic"`, `rule="keywords"` aynı kalır; kayda `verbatim: True` alanı eklenir.
3. Çakışma: aynı ad iki anahtara verilirse bugünkü çakışma eki (`_2`) mantığı aynen çalışır; değiştirme.
4. `alt_kanal._is_own_name` (iki kopyada da): bugün "`ad`, `e`'nin küçük harfli hâline eşit"; yeni tanım "`ad == e` **ya da** `ad == e.lower()`". Aksi hâlde harfi korunan ad `tanimlayici` alt kanalına düşer ve susar. Tanım sürümü 1 → 2 (`definition_version`); `tests/test_alt_kanal.py`'nin iki kopyanın eşitliğini denetleyen testi yeşil kalmalı.
5. `tests/test_ok1_oz_ad_harf.py`: (a) `"ZSTD_getCParamsFromCDict"` kanıtıyla ad aynen o; (b) `"ieee754_from_blob"` (rakamlı) aynen; (c) `"screen_write_scrollregion"` bayrak kapalı / açık aynı ad; (d) `"Failed to open database"` bugünkü ad (yol değişmedi); (e) tamamı büyük harf `"EXIT_FAILURE"` → koşul tutmaz, bugünkü yol; (f) bayrak kapalıyken (a) bugünkü küçük harfli ad; (g) alt kanal sınıflaması `oz_ad`.
6. Mutasyon tanımları (`mutation_specs_ok1.json`, en az 5): koşuldaki `"_" in` şartını kaldır; küçük harf şartını kaldır; `new_name = e` yerine `e.lower()`; `_is_own_name`'de `ad == e` kolunu sil; bayrak denetimini ters çevir. Hepsi `killed` olmalı.
7. Ölçüm: ürün ağacını kur (`~/karadul_olcum/urun-<commit>`), iki kol koş — bayrak kapalı (taban) ve açık — `urun_kos.py` + `urun_olc.py olc` + `karsilastir`. Ek sayım: `scripts/arge/ozkod/oz_ad_harf.py` taban kolda yeniden (beklenti sayılarının girdisi).
8. Belge: `docs/arge/2026-11-19_mythos/ozkod/OK1.md` (önce / sonra, hükümler).

**Kabul ölçütü.**
- `string_context/oz_ad` kanalında, bayrak kapalı kola göre: yanlıştan doğruya dönen ad **≥ 36** (beklenen 40); doğrudan yanlışa dönen **0**; kanalın ad sayısı değişmez (± 2).
- zstd biriminde yanlış ad **46 → ≤ 12** (beklenen 9).
- Öbür kanalların ad / doğru / yanlış sayıları aynı.
- Yeni yanlış ad (bayrak kapalı kolda adsız olup açık kolda yanlış adlı) **≤ 2**.

**Ön kayıt metni (ölçümden önce commit'lenecek).**
> ÖK-1 ön kaydı. Kollar: aynı commit, `oz_ad_verbatim` kapalı (taban) ve açık. Set: geliştirme seti 119 ikili; hüküm `urun_olc` (tam eşitlik). Beklenti, `scripts/arge/ozkod/oz_ad_harf.py`'nin a62f15e tabanındaki çıktısından: `oz_ad` kanalında yanlıştan doğruya dönen 40 ad (zstd 37, coreutils 1, openssl 1, mac/tmux 1; `redis-check-rdb` ≡ `redis-check-aof` olduğu için 119'luk sayımda en çok +1 fark). H1: dönen ad 36–44. H2: doğrudan yanlışa dönen 0. H3: zstd yanlış ad ≤ 12. H4: öbür kanallar aynı. H5: yeni yanlış ≤ 2. H6 (karar dışı): program düzeyi makro yanlış oranı düşer. Taban P12d'yi içeriyorsa `oz_ad` ad sayısı a62f15e'dekinden farklıdır; beklenti fark olarak okunur, mutlak sayı olarak değil. Tutmayan beklenti kayda geçer.

**Ürüne girişi.** Bayrak `oz_ad_verbatim`, öntanım kapalı. Ölçüm tutarsa öntanımı ana oturum açar (ayrı commit).

**Riskler.** (1) Küçük harfe çevirmenin bilerek yapılmış bir yan etkisi varsa (ad çakışması denetimi küçük harfe göre): adım 3'te denetle. (2) `tests/test_alt_kanal.py` ön kayıtlı sha256'ya bağlıysa tanım sürümü değişikliği o ön kaydı bayatlatır: sürüm 2 diye yeni satır aç, eskisini silme.

---

## ÖK-4a — kayıt çifti çıkarıcısı (ürün modülü; ad vermez, yalnız kanıt)

**Amaç.** İkilideki (dizgi, fonksiyon işaretçisi) çiftlerini ürün içinde çıkaran ve köken kaydına kanıt satırı olarak yazan modül; ad üretimi ÖK-4b'de.

**Kanıt.** `BULGULAR.md` §2.1–§2.2: coreutils dışı nüfusun %15,8'i bir kayıtta; dizgi ada "önek + dizgi + sonek" ile bağlanıyor.

**Dokunacağı dosyalar (hepsi yeni; var olan dosyaya dokunmaz).**
- `karadul/reconstruction/tarif/veri_sozcukleri.py`: ikilinin veri bölümlerindeki 8 baytlık sözcükler ve hedefleri.
- `karadul/reconstruction/tarif/kayit_cifti.py`: aday grupları ve çağrı yeri çiftleri.
- `tests/test_ok4a_veri_sozcukleri.py`, `tests/test_ok4a_kayit_cifti.py`, `scripts/measurement/mutation_specs_ok4a.json`.

**Dokunmayacağı dosyalar.** `karadul/stages.py`, `c_namer.py`, `baglama.py`, `naming_labels.py`, `config.py` (bağlama ÖK-4b'de); `docs/arge/2026-11-10_n4/` (kaynak olarak okunur, değişmez).

**Adımlar.**
1. Önce ara: ürün ağacında yer değişimi / işaretçi haritası okuyan bir modül var mı (`grep -rn "R_AARCH64_RELATIVE\|chained_fixups\|dyld_chained" karadul`). Varsa onu kullan, yenisini yazma; yoksa adım 2.
2. `veri_sozcukleri.py`: `docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.py`'den taşı — `dizgi_oku`, `dizgi_sinifi`, `Hedefci`, `bolum_turleri`, `elf_oku` (ELF: `R_AARCH64_RELATIVE` addend'i, `R_AARCH64_ABS64` simge + addend; kayma = Ghidra `image_base` − en küçük `PT_LOAD`), `macho_oku` (chained fixup, `DYLD_CHAINED_PTR_64_OFFSET`; lief), tablo bulma (`aday_tablolar`, `tablolari_sec`, `faz_sec` ve yardımcıları), `kodda_alinan_adresler`. x86-64 ELF için `R_X86_64_RELATIVE` (tür 8) ve `R_X86_64_64` (tür 1) ekle; desteklenmeyen biçimde boş sonuç + neden döndür (istisna yok).
3. `kayit_cifti.py` — aday çıkarımı, `scripts/arge/ozkod/ek_kurali.py` `adaylar` ile aynı tanım:
   - **T:** tablo (adım > 1) içindeki fonksiyon yuvası p ve −adım < δ < adım, δ ≠ 0 için p + δ yuvası ad biçimli dizgi gösteriyorsa grup `("T", bölüm, tablo no, sütun, δ)`. Faz varsayımı yok.
   - **N:** tablo dışı yuva; çapa nesnesi (yuvadan önceki son çapa ile sonraki ilk çapa arası, ≤ 64 sözcük; çapa = yer değişimi hedefi ya da kodda hesaplanan adres) içindeki ad biçimli dizgiler; grup `("N", nesnenin tür dizisi, yuva ofseti, dizgi ofseti)`.
   - **C:** çağrı yeri. Önce `karadul/reconstruction/tarif/kesin.py`'nin `CallSite` / `analyze_function` veri akışına bak: çağrı anında argüman yazmaçlarında dizgi adresi ve fonksiyon adresi sabiti birlikte görülüyorsa oradan üret (decompile metnine bağımlılık kalkar). Yetmezse `scripts/arge/ozkod/kayit_cifti.py` `cagri_ciftleri_metin`'i taşı (C metninden). Grup `("C", çağrılan, argüman sayısı, fonksiyon argümanı, dizgi argümanı)`.
   - "Ad biçimli" = N4 `dizgi_sinifi` ∈ {`tanimlayici`, `kisa_ad`} ve uzunluk ≥ 2.
4. Çıktı: `kayit_ciftleri(static_dir, ikili_yolu) -> dict[int, list[Aday]]` (fonksiyon adresi → aday listesi; `Aday`: grup, dizgi, yuva adresi ya da çağrı yeri adresi). Saf fonksiyon; dosya yazmaz.
5. Eşdeğerlik sınaması (zorunlu): geliştirme setinin şu dört ikilisinde modülün verdiği (fonksiyon, grup türü, dizgi) kümesi `scripts/arge/ozkod/ek_kurali.py` `adaylar` çıktısıyla aynı olmalı — `debian/tmux/tmux`, `mac/tmux/tmux`, `debian/openssl/openssl`, `debian/htop/htop`. (Araştırma tarafını `scripts/arge/ozkod/ozkod_veri.py` `hepsi(["debian/tmux"])` ile yükle.) C adayları veri akışından üretildiyse fark sayılır ve belgeye yazılır (eşitlik şartı T ve N için).
6. Birim testleri sentetik baytlarla: RELATIVE çözümü, ABS64 iç / dış simge, chained fixup çözümü, δ aralığı, çapa nesnesi sınırı (≤ 64), boş dizginin kanıt sayılmaması, C ayrıştırıcısında iç içe parantez ve dizgi içinde virgül.
7. Mutasyon (en az 8): kayma işareti, δ aralığının ucu, δ = 0 dışlaması, nesne uzunluk sınırı, ad biçimi süzgeci, ABS64 addend'i, fonksiyon argümanı deseni, dizgi argümanı deseni.
8. Belge `OK4a.md`: dört ikilide aday sayıları ve eşdeğerlik sonucu.

**Kabul ölçütü.** Eşdeğerlik: T ve N adaylarında simetrik fark 0 (dört ikili). Beklenen aday sayıları `scripts/arge/ozkod/kayit_cifti.py --taraf kesif|sinama` çıktısındaki "V kayıt dizgisi" ve "C çağrı çifti" sütunlarıyla tutarlı (nüfusta: debian/tmux V 366 / C 25; mac/tmux 447 / 26; openssl 56 / 1; debian/htop 77 / 0). Mutantların hepsi `killed`.

**Ön kayıt.** Bu paket ad vermez; ön kayıt gerekmez. Eşdeğerlik ölçütü yukarıda.

**Ürüne girişi.** Modül bu pakette hiçbir yerden çağrılmaz (ölü değil: ÖK-2 ve ÖK-4b çağırır). Bayrak yok.

**Riskler.** lief sürümü (0.17.6 ile yazıldı); x86-64 ve PIE olmayan ikililer bu sette yok (ölçülmedi, ÖK-7).

---

## ÖK-V — bağımsız sınama nüfusu (veri)

**Amaç.** K1, G1, R1 ve modül öneki için geliştirme setinden bağımsız, kayıt çifti yoğun bir nüfus kurmak.

**Önkoşul.** Berke'nin indirme onayı (ana oturum sorar). Liste ve boyutlar `BULGULAR.md` §6 (`scripts/arge/ozkod/aday_paket.py`): 24 paket, .deb + -dbgsym toplam 78,0 MiB (postgresql-17 hariç 43,8 MiB).

**Dokunacağı dosyalar.**
- `~/karadul_olcum/ozkod_nufus/` (yeni kök; Spotlight dışı): `indir/`, `x_<paket>/`, `runs/`.
- `scripts/measurement/ozkod_nufus_kur.py` (yeni): indirme listesi, sha256 sabitleme, ikili seçimi, bölme.
- `docs/arge/2026-11-19_mythos/ozkod/NUFUS.md` (yeni): liste, sha256, build-id, bölme.

**Dokunmayacağı dosyalar.** `targets/`, `~/karadul_olcum/n1_debian13/`, kilitli set dizinleri; ürün kodu.

**Adımlar.**
1. Aday listesini kilitle (ölçümden önce `NUFUS.md`'ye yaz): bash, nginx, irssi, hexchat, jq, gawk, tcl8.6 + libtcl8.6, lua-socket, lua-cjson, gedit, evince, mousepad, xfce4-terminal, geany, pidgin, xterm, mc, busybox, lighttpd, neomutt, python3.13-minimal + libpython3.13-stdlib; postgresql-17 isteğe bağlı (boyut). Kilitli test / doğrulama setindeki hiçbir program eklenmez (adlar `docs/arge/test_seti_kilidi.md`, `dogrulama_seti_kilidi.md`).
2. Debian 13 arm64 `.deb` ve `-dbgsym` paketlerini indir (snapshot.debian.org ya da deb.debian.org / debian-debug); her dosyanın sha256'sını `NUFUS.md`'ye yaz. python3.13 için hata ayıklama paketinin adını dizinden doğrula.
3. Her pakette ölçülecek ELF'leri seç (ana ikili; paylaşımlı kitaplık paketlerinde `.so`); build-id ↔ `.debug` eşleşmesini `scripts/measurement/function_f1.py` `extract_gt` ile kanıtla. C++ ikililer (`ks1_olc.cpp_ikili_mi`) ölçü dışı.
4. **Bölme (koşudan önce, sayılara bakmadan):** paket adının sha256'sının ilk baytı çift → "ayar", tek → "kör". Aynı kaynaktan iki paket (tcl8.6 / libtcl8.6; python3.13-*; lua-*) aynı tarafa: ilk paketin tarafı. `NUFUS.md`'ye yaz.
5. Taban ürün koşusu (bayraklar öntanımlı): ikili başına `python -m karadul analyze <ikili> --skip-dynamic --output-dir <d>/ws --output <d>/out`; sıralı (aynı anda 1 Ghidra), `PYTHONHASHSEED=0`, koşuya özel `KARADUL_CACHE_DIR`.
6. Olgu önbelleği: `scripts/arge/ozkod/ozkod_veri.py`'yi yeni kökle çalışacak biçimde `--kok` seçeneğiyle genişlet (ya da ÖK-5'in `ozkod_olc.py`'sini kullan); tutarlılık: nüfus > 0, GT eşleşmesi hatasız.
7. `NUFUS.md`: paket × (ELF sayısı, fonksiyon, nüfus, taraf). GT adı yazma.

**Kabul ölçütü.** En az 15 paket GT'li ve koşulmuş; iki tarafta da en az 5 paket; her ikilide `extract_gt` build-id eşleşmesi doğrulanmış.

**Ön kayıt.** Bölme kuralı adım 4'teki metinle, koşudan önce commit'lenir.

**Riskler.** Disk: her çalışma alanı yüzlerce MB olabilir (`diskutil info /System/Volumes/Data` ile önce / sonra ölç). GObject programlarında Vala üretimi kod (adlar mekanik) nüfusu yanıltabilir: `NUFUS.md`'de dil / üretilmiş kod notu düş.

---

## ÖK-5 — K1, G1, R1 ve öneğin bağımsız nüfusta kör ölçümü (araştırma betikleriyle; ürün değişmez)

**Amaç.** Bu turda dondurulan kuralları hiç değiştirmeden ÖK-V nüfusunun "kör" tarafında saymak; ürün kanalı kararlarını (ÖK-3, ÖK-4b, ÖK-6) buna bağlamak.

**Dokunacağı dosyalar.**
- `scripts/measurement/ozkod_olc.py` (yeni): `scripts/arge/ozkod/` betiklerinin kök parametreli birleşik hâli (alt komutlar: `kur`, `cift`, `k1`, `k1-capa`, `ozad`, `g1`, `tavan`).
- `tests/test_ozkod_olc.py` (yeni), `scripts/measurement/mutation_specs_ozkod_olc.json` (yeni).
- `docs/arge/2026-11-19_mythos/ozkod/on_kayit_OK5.md`, `OK5.md` (yeni).

**Dokunmayacağı dosyalar.** `scripts/arge/ozkod/*.py` (dondurulmuş; sha256'ları `DEFTER.md` §4, §7, §10'da), ürün kodu.

**Adımlar.**
1. `ozkod_olc.py`'yi yaz: kural fonksiyonlarını kopyalama, **içe aktar** (`sys.path`'e `scripts/arge/ozkod` ekle; `ek_kurali.adaylar`, `ek_kurali.tahmin`, `kayit_cifti.gt_esit`, `oz_ad_ayrim.kural_tut`, `oz_ad_uretici.g1`). Yalnız veri kökü ve birim listesi parametre olur.
2. Eşdeğerlik: geliştirme setinde `ozkod_olc.py k1` çıktısı `scripts/arge/ozkod/ek_kurali.py --taraf kesif|sinama` ile aynı sayıları vermeli (keşif 754 / 740, sınama 126 / 103).
3. Ön kaydı commit'le (aşağıdaki metin).
4. "Ayar" tarafında yalnız şu iki şey okunur ve dondurulur: (a) G1 için kapı adayı — ikilide KS-1 çapası sayısı ≥ 1 (`reconstructed/kesin_capalar.json`) ya da `__assert_fail` / `__assert_rtn` içe aktarımı var; (b) K1 için karakter düzeyinde ek (ÖK-7 A). K1'in kendisi (grup tanımı, `MIN_DESTEK` = 2, `MIN_ORAN` = 0,5) **değiştirilmez**.
5. "Kör" tarafta say: K1 çapa kâhin; K1 çapa = bugünkü ön adlar (kip A); K1 çapa = ön adlar + G1 (kip C); G1 düz ve kapılı; R1 + harf koruma (`oz_ad` adları varsa); modül öneki sandviç (aralık sınırsız ve ≤ 32).
6. Birim başına ve havuz; Wilson; karakter / norm / ayraçsız eşitlik ve belirteç kesinliği / duyarlılığı ayrı (`ek_kurali_belirtec.py` ile aynı tanımlar).
7. Yanlışların dökümü (ölçümden sonra): ad düzensizliği / gerçek yanlış ayrımı sayılmaz, yalnız liste (ÖLÇÜ hattına girdi).
8. `OK5.md`: hükümler ve ÖK-3 / ÖK-4b / ÖK-6 için karar satırı.

**Kabul ölçütü ve ön kayıt metni.**
> ÖK-5 ön kaydı. Nüfus: ÖK-V'nin "kör" tarafı. Kurallar: `scripts/arge/ozkod/ek_kurali.py` (sha256 7d02a6b5…), `oz_ad_ayrim.py` (ccc73f5c…), `oz_ad_uretici.py` (7ee4edfc…), değiştirilmeden. Geliştirme setinde ölçülen: K1 kâhin keşif %98,1, sınama %81,7; G1 keşif %93,8, sınama %79,7.
> - K1-a (kâhin çapa, norm eşitliği): havuz kesinliği ≥ %85 ve Wilson alt sınırı ≥ %80; ad sayısı ≥ 200; en az 5 pakette ≥ 10 ad. Beklentim %85–%95. **Tutarsa** ÖK-4b açılır. Wilson alt sınırı %70–%80 arasındaysa K1 yalnız "ek yüzey biçimi + tablo türü" kısıtlarıyla yeniden ön kayıtlanır; < %70 ise K1 ad kanalı olarak bırakılır (kanıt satırı kalır).
> - K1-b (erişim): nüfusun V ∪ C çiftli payı, paketlerin en az yarısında ≥ %5. Beklentim: kabuk, sunucu ve GTK programlarında var; kitaplıklarda değişken.
> - K1-c (çapa, kip A): ad sayısı küçük (beklenti: nüfusun < %2'si); kesinlik ≥ %90 (n ≥ 30 ise hükme girer).
> - G1-a (düz G1): kesinlik ≥ %85. Beklentim tutmaz (sınamada tutmadı).
> - G1-b (kapılı G1; kapı "ayar" tarafında dondurulur): kesinlik ≥ %90 ve Wilson alt sınırı ≥ %85; ad ≥ 50. **Tutarsa** ÖK-3 açılır.
> - Ö-a (sandviç, aralık ≤ 32): önek kesinliği ≥ %85. Geliştirme setinde 1 212 / 1 454 (%83,4). **Tutarsa** ÖK-6 açılır.
> - Tutmayan beklenti silinmez; eşikler ölçümden sonra değişmez.

**Ürüne girişi.** Yok (ölçüm paketi).

**Riskler.** Nüfusta GObject / Vala üretimi kod K1'i şişirebilir (mekanik adlar): paket başına ayrı satır ve "üretilmiş kod" notu.

---

## ÖK-2 — R1: `oz_ad` adına teklik kapısı (ad mı, kanıt satırı mı)

**Amaç.** `oz_ad` adayı R1'i sağlıyorsa ad olarak kalsın; sağlamıyorsa K-2 gereği susmasın, kanıt satırına insin.

**Kanıt.** `BULGULAR.md` §1.1–§1.2: R1 + harf koruma 106 / 111 (%95,5; %89,9–%98,1); R1 dışında kalan 85 adın 27'si doğru (harf korunmuş hâliyle). Ödenen bedel bu 27 addır.

**Önkoşul.** ÖK-1 (aynı fonksiyon), ÖK-4a (`kayitli` özelliği kayıt çiftinden gelir).

**Dokunacağı dosyalar.** `karadul/reconstruction/c_namer.py` (var: klasik aşamada aday eklenmeden önce kapı), `karadul/config.py` (bayrak), `tests/test_ok2_oz_ad_teklik.py` (yeni), `scripts/measurement/mutation_specs_ok2.json` (yeni).

**Dokunmayacağı dosyalar.** `alt_kanal.py` (R1 alt kanal tanımı değil, alt kanal içi kapıdır), `stages.py`, `baglama.py`.

**Adımlar.**
1. `config.py`: `oz_ad_uniqueness_gate: bool = False`.
2. `c_namer.py`: sınıf kurulurken bir kez hesapla — (a) dizgi metni → onu anan fonksiyon kümesi (`self._string_refs_by_func`'un tersi; **metne** göre, adrese göre değil); (b) fonksiyon → andığı tanımlayıcı biçimli (alt çizgili, küçük harfli) farklı dizgi sayısı; (c) ÖK-4a `kayit_ciftleri` → dizgi metni → kayıtlı olduğu fonksiyonlar.
3. Kapı (yalnız ÖK-1 koşulunu sağlayan adaylarda, yani kanıt tek tanımlayıcıyken): R1 = `n_fn == 1` ∧ `n_tanim <= 1` ∧ kanıt fonksiyonun kendi xref'inde (`evidence_origin == "string_ref"`) ∧ dizgi başka fonksiyonla kayıtlı değil. Çakışma şartı (aynı ad iki anahtara) `n_fn == 1` ile zaten sağlanır.
4. R1 tutmuyorsa aday eklenmez; köken kaydının `string_roles` bölümüne satır yazılır: `{"role": "tanimlayici_dizgi", "string": e, "n_functions": n_fn, "n_identifier_strings": n_tanim, "registered_elsewhere": bool}` (P12b'nin kebap satırlarıyla aynı yer: `c_namer._kebab_string_roles` örnek).
5. R1 tutuyorsa adaya `uniqueness: true` alanı; ad aynen.
6. Testler: tek anan + tek tanımlayıcı → ad; iki anan → satır; fonksiyon 3 tanımlayıcı anıyor → satır; dizgi başka fonksiyonla kayıtlı → satır; bayrak kapalı → bugünkü davranış; kanıt tanımlayıcı değil → kapı uygulanmaz.
7. Mutasyon (en az 5): `n_fn == 1` → `>= 1`; `n_tanim <= 1` → `<= 99`; kayıtlı şartını sil; satır yazımını sil; bayrağı ters çevir.
8. Ölçüm: üç kol — taban; ÖK-1 açık; ÖK-1 + ÖK-2 açık. `urun_olc karsilastir`.

**Kabul ölçütü.** ÖK-1 açık kola göre `oz_ad` kanalında: ad 196 → **105–117** (beklenen 111); kesinlik **≥ %92** (beklenen 106 / 111); kaybedilen doğru ad **≤ 30** (beklenen 27); `string_roles`'a inen satır sayısı = atılan ad sayısı.

**Ön kayıt metni.**
> ÖK-2 ön kaydı. Kollar: ÖK-1 açık (taban) ↔ ÖK-1 + `oz_ad_uniqueness_gate` açık. Geliştirme seti 119 ikili. Beklenti `scripts/arge/ozkod/oz_ad_harf.py` çıktısından (196 adlık sayım): R1'den geçen 111 ad, 106'sı doğru; atılan 85 adın 27'si doğruydu. H1: `oz_ad` ad sayısı 105–117. H2: `oz_ad` kesinliği ≥ %92. H3: kaybedilen doğru ≤ 30. H4: öbür kanallar aynı. H5: atılan her ad için `string_roles` satırı var. Not: R1 keşifte okundu; sınama tarafında tek başına ön kaydı tutmadı (yanlışların %44,4'ünü attı), çünkü oradaki yanlışlar harf kusuruydu (ÖK-1). Bu yüzden bu ölçüm geliştirme seti içi bir doğrulamadır; bağımsız sınama ÖK-5'tedir.

**Ürüne girişi.** Bayrak `oz_ad_uniqueness_gate`, öntanım kapalı. Açılması için ÖK-5'te R1'in bağımsız nüfusta kesinliği ≥ %90 görülmeli (nüfusta `oz_ad` adı yoksa G1-b hükmü kullanılır: aynı özellikler).

**Riskler.** 27 doğru adın kaybı. Bu bir kesinlik / kapsam takasıdır; karar ana oturumundur (bayrak bunun için). Kapsam küçültülmez kuralına uyum: kanal kapanmıyor, ölçülmüş kuralı olmayan adaylar kanıt satırına iniyor (K-2).

---

## ÖK-3 — G1: tekil tanımlayıcı dizgiden ad (üretici)

**Amaç.** `oz_ad`'ın bugün ulaşamadığı fonksiyonlara (KS-1 deseni olmayan, c_namer'ın görmediği) aynı kuralla ad vermek.

**Kanıt.** `BULGULAR.md` §1.3: keşif 454 / 484 (121 yeni doğru), sınama 114 / 143 (90 yeni doğru; zstd dışı 0 / 9). Düz G1 ön kaydı tutmadı.

**Önkoşul.** ÖK-2 (aynı özellikler ve aynı dosya); **ÖK-5'in G1-b hükmü "tuttu"**. Tutmadıysa bu paket açılmaz.

**Dokunacağı dosyalar.** `karadul/reconstruction/c_namer.py` (var; G1 adayı üreten yeni özel yöntem), `karadul/config.py` (bayrak), `karadul/reconstruction/tarif/alt_kanal.py` + `scripts/measurement/alt_kanal.py` (yeni alt kanal adı gerekirse; tanım sürümü), `tests/test_ok3_g1.py`, `scripts/measurement/mutation_specs_ok3.json`.

**Dokunmayacağı dosyalar.** `stages.py`, `baglama.py`, KS-1 (`tarif/kesin.py`): G1, KS-1'in ad verdiği anahtara ad vermez.

**Adımlar.**
1. `config.py`: `enable_unique_identifier_names: bool = False`.
2. c_namer'da `_strategy_string_context` başında (agresif aşamadan önce) G1 denetimi: fonksiyonun andığı dizgiler içinde `tanim_mi` (tek C tanımlayıcısı, alt çizgili, ≥ 1 küçük harf, uzunluk ≥ 4) olan **tam bir** farklı dizgi S; S'i ikilide yalnız bu fonksiyon anıyor; S başka fonksiyonla kayıtlı değil; **kapı** (ÖK-5 adım 4'te dondurulan: ikilide KS-1 çapası ≥ 1 ya da assert ailesi içe aktarımı) tutuyor → aday `new_name = S`, `strategy="string_context"`, `code_path="classic"`, `rule="unique_identifier"`, `evidence=S`.
3. Öncelik: ön adlar (`elle`, `main_giris`, `ks1`, `gnulib`, `elf_onyuk`) G1'i ezer; G1, klasik anahtar sözcük adayını ezer. Keşifte G1'in yanlış olup ürünün doğru olduğu 6 ad `main` girişleriydi.
4. Alt kanal: kayıt `oz_ad` sınıfına düşmeli (ÖK-1'in genişlettiği yüklem); düşmüyorsa yeni alt kanal `tekil_tanimlayici` (tanım sürümü + 1) ve N0b susturma listesine **girmez**.
5. Güven: sabit 0,85 yazma; ÖK-5'te ölçülen Wilson alt sınırını `naming_labels.MEASURED_PRE_NAME_PRECISION` benzeri bir tabloya `string_context/unique_identifier` satırı olarak koy (ölçüm kaynağı dizgisiyle).
6. Testler ve mutasyon (ÖK-2'deki özellik mutantları + kapı mutantı + öncelik mutantı).
7. Ölçüm: ÖK-1 + ÖK-2 açık kol ↔ + G1 açık kol, 119 ikili; ayrıca ÖK-V nüfusunun kör tarafında ürün koşusu.

**Kabul ölçütü.** Geliştirme setinde G1 açık kolda, ÖK-2 koluna göre: yeni doğru ad **≥ 170** (beklenen 121 + 90 = 211'in kapıdan geçen kısmı; kapı zstd dışı 9 adı atmalı), yeni yanlış **≤ 40** (keşif 10 + sınama 26'nın kapıdan geçen kısmı), öbür kanallarda kayıp 0. Bağımsız nüfusta: ÖK-5 G1-b eşiği ürün koşusunda da tutmalı.

**Ön kayıt metni.**
> ÖK-3 ön kaydı. Kollar: ÖK-1 + ÖK-2 açık ↔ + `enable_unique_identifier_names`. Geliştirme seti 119 ikili ve ÖK-V kör tarafı. Geliştirme setinde düz G1 (araştırma betiği): 627 ad, 568 doğru; bugün adsız doğru 211, bugün yanlış adlı olup düzelen 26, yeni yanlış 36. Kapılı G1 için: H1: yeni doğru ≥ 170. H2: yeni yanlış ≤ 40. H3: G1 adlarının kesinliği (ürün hükmü) ≥ %90. H4: ön ad kanallarında değişiklik 0. H5: bağımsız nüfusta kesinlik ≥ %90, Wilson alt sınırı ≥ %85. Kapının tanımı ÖK-5 adım 4'te donduruldu; burada değişmez.

**Ürüne girişi.** Bayrak `enable_unique_identifier_names`, öntanım kapalı; etiket "doğrulanmadı".

**Riskler.** Satır içine alınmış çağrılanın `__func__`'ı (zstd'deki 19 yeni yanlışın muhtemel kaynağı — **bakılmadı**; ÖK-7 D). Kapı zayıf kalırsa paket durur.

---

## ÖK-4b — K1: kayıt çifti + sütun eki ad kanalı (`kayit_eki`)

**Amaç.** Aynı tablo sütununda (ya da aynı kayıt çağrısında) adı bilinen en az iki fonksiyon varsa öbürlerinin adını ekle hesaplamak; çapa yoksa kanıt satırı yazmak.

**Kanıt.** `BULGULAR.md` §2.3: kâhin çapa keşif %98,1, sınama %81,7; bugünkü ön ad çapalarıyla 95 / 98 (Mac tmux); çapa = ön adlar + G1 ile 239 / 242.

**Önkoşul.** ÖK-4a; **ÖK-5'in K1-a hükmü "tuttu"**; karakter düzeyinde ek ölçümü (ÖK-7 A) yapılmış.

**Dokunacağı dosyalar.**
- `karadul/reconstruction/tarif/kayit_cifti.py` (ÖK-4a'nın dosyası; `ek_cikar`, `ek_uygula`, `ek_oyu`, `tahmin` eklenir).
- `karadul/stages.py` (var): `_seed_recovery_pre_names` (≈ satır 1751–1812; ön ad tohum zinciri).
- `karadul/reconstruction/tarif/baglama.py` (var): yeni tür `KIND_RECORD_AFFIX = "kayit_eki"`, `KIND_PRIORITY` sonuna.
- `karadul/core/naming_labels.py` (var): `MEASURED_PRE_NAME_PRECISION` satırı ve kaynak dizgisi.
- `karadul/config.py` (var): bayrak.
- `tests/test_ok4b_kayit_eki.py`, `scripts/measurement/mutation_specs_ok4b.json`, `tests/test_p12a_on_ad_guveni.py` (var; tablo satırı eklenince güncellenir).

**Dokunmayacağı dosyalar.** `c_namer.py` (K1 ön ad kanalıdır, c_namer adayı değil); `tarif/kesin.py`; `scripts/measurement/urun_olc.py` (kanal adı `on_ad:kayit_eki` kendiliğinden çıkar; çıkmıyorsa ana oturuma yaz, betiği değiştirme).

**Adımlar.**
1. `config.py`: `enable_record_affix_names: bool = False`.
2. `kayit_cifti.py`: ad üretimi `scripts/arge/ozkod/ek_kurali.py` ile aynı kural — grup başına ek oylaması **fonksiyon düzeyinde** (bir çapa bir eke en çok bir oy); kazanan ek ≥ 2 çapadan gelmeli, ikinciden kesin fazla olmalı, gruptaki çapa fonksiyonlarının ≥ yarısını açıklamalı; hedefin bütün aday gruplarından çıkan adlar tek ada iniyorsa ad, değilse çekimser. Ek, ÖK-7 A'da ölçülen yüzey biçimiyle uygulanır (çapanın adında dizginin geçtiği karakter aralığı; önek ve sonek çapanın harfleriyle).
3. Çapa kümesi (yalnız bunlar): `elle`, `main_giris`, `ks1` (etiketi "kesin" olan satırlar), `gnulib`, `elf_onyuk` ön adları ve Ghidra'nın jenerik olmayan adları. ÖK-3 açıksa G1 adları da çapa olur (ayrı sayılır). `oz_ad` (R1'siz), `faz1` ve c_namer'ın öbür adları çapa **olmaz**.
4. `stages.py` `_seed_recovery_pre_names`: `_recover_elf_boilerplate` ve `_apply_manual_overrides` çağrılarından **sonra** yeni adım — `kayit_ciftleri` + ad üretimi; yalnız **boş** anahtarlara yazar, hiçbir ön adı ezmez; `_bg.mark_changed(meta, before, extracted_names, _bg.KIND_RECORD_AFFIX)`. (Uyarı: `stages.py` monolitinin bu bölümü etkin koddur; `karadul/pipeline/steps/` altında eşi var mı diye `grep -rn "_recover_elf_boilerplate" karadul` ile denetle ve yalnız etkin olanı değiştir.)
5. Kanıt kaydı: ad verilen her anahtar için köken kaydına `{"table": yuva adresi ya da çağrı yeri, "column": sütun, "delta": δ, "string": dizgi, "affix": [önek, sonek], "anchors": [çapa anahtarları], "votes": n}`.
6. Çapasız çiftler: ad yazılmaz; köken kaydının `string_roles` bölümüne `{"role": "kayit_dizgisi", "string": dizgi, "table": …, "column": …}` satırı (K-2: kanıt satırı). Aynı fonksiyon birden çok kayıtta ise her biri ayrı satır.
7. Etiket: "doğrulanmadı". `MEASURED_PRE_NAME_PRECISION["on_ad:kayit_eki"]` = (doğru, ad, Wilson alt sınırı) — ÖK-5 kör ölçümünden (kip A / C hangisi açıksa).
8. Testler (sentetik tablo): iki çapa + üç hedef → üç ad; tek çapa → ad yok, satır var; yanlış δ grubunda rastlantısal iki oy ama çapaların yarısından az → ad yok; iki grup iki farklı ad → çekimser; dolu anahtar ezilmez; bayrak kapalı → hiçbir şey değişmez. Mutasyon (en az 8): `MIN_DESTEK`, `MIN_ORAN`, eşit oy şartı, çelişki şartı, boş anahtar şartı, çapa türü süzgeci, satır yazımı, bayrak.

**Kabul ölçütü.** Geliştirme seti, bayrak açık ↔ kapalı:
- kip A (G1 kapalı): `on_ad:kayit_eki` ad **90–105**, doğru **≥ 90** (araştırma betiği: 98 / 95); hepsi bugün adsız fonksiyonlarda; öbür kanallarda değişiklik 0; yeni yanlış ≤ 5.
- kip C (G1 açık): ad **225–260**, doğru **≥ 225** (araştırma betiği: 242 / 239).
- Çapasız çiftler için `string_roles` satırı: nüfusta V ∪ C çiftli 1 279 fonksiyonun ad almayanları (redis-check-rdb tekrarıyla 119'luk sayımda biraz fazla).
- Bağımsız nüfus (ÖK-V kör): ürün koşusunda `on_ad:kayit_eki` kesinliği ≥ %85 (n ≥ 30 ise).

**Ön kayıt metni.**
> ÖK-4b ön kaydı. Kollar: `enable_record_affix_names` kapalı ↔ açık (ve G1 açıkken ayrıca). Geliştirme seti 119 ikili; hüküm `urun_olc` (karakter eşitliği). Araştırma betiği `scripts/arge/ozkod/ek_kurali_capa.py` (norm eşitliği; a62f15e): kip A 98 ad / 95 doğru (97'si Mac tmux `window_copy_cmd_*` tablosu), kip C 242 / 239 (debian tmux 121 / 121, mac tmux 120 / 118). H1 (kip A): ad 90–105, doğru ≥ 90. H2 (kip C): ad 225–260, doğru ≥ 225. H3: yeni yanlış ≤ 5 (kip A), ≤ 8 (kip C). H4: var olan hiçbir ad değişmez (ezilen 0). H5: karakter eşitliği ile norm eşitliği farkı ≤ 3 ad (ek yüzey biçiminden öğreniliyor). H6: bağımsız nüfusta kesinlik ≥ %85. Sınama birimlerinde (htop, redis, sqlite3) bugün çapa olmadığı için ad beklenmez (araştırma betiği: 1 ad, 0 doğru).

**Ürüne girişi.** Bayrak `enable_record_affix_names`, öntanım kapalı. Ad haritasına ön ad olarak girer; analist arayüzünde kanıt (tablo, dizgi, çapalar) gösterilir.

**Riskler.** (1) Çapanın kendisi yanlışsa tablo dolusu yanlış ad üretilir: bu yüzden çapa yalnız ölçülmüş kesinliği yüksek türlerden ve en az iki çapa şartı. (2) Ad düzeni düzensiz programlarda (htop, sqlite3) tam eşitlik %65–%77'de kaldı; etiket bu yüzden "doğrulanmadı". (3) `stages.py` ortak dosya: tek ajan, sıralı.

---

## ÖK-6 — modül öneki kanıt satırı (ad değil)

**Amaç.** Adsız fonksiyona, adres sırasında iki yanındaki adlı fonksiyonların ortak önekini kanıt satırı olarak yazmak.

**Kanıt.** `BULGULAR.md` §5: iki adres komşusu uzlaşınca önek %96,4 doğru (kâhin); bugünkü adlarla sandviç 2 216 / 2 545 (%87,1); çağrı grafiği çoğunluğu %55,2.

**Önkoşul.** ÖK-5'in Ö-a hükmü "tuttu".

**Dokunacağı dosyalar.** `karadul/reconstruction/tarif/modul_oneki.py` (yeni), `karadul/reconstruction/c_namer.py` (var: köken kaydına `role_evidence` satırı; P12a'nın `_split_role_candidates` yazdığı yer), `karadul/config.py` (bayrak), `tests/test_ok6_modul_oneki.py`, `scripts/measurement/mutation_specs_ok6.json`.

**Dokunmayacağı dosyalar.** Ad haritasını değiştiren her yer: bu paket ad vermez.

**Adımlar.**
1. `config.py`: `enable_module_prefix_evidence: bool = False`.
2. `modul_oneki.py`: girdi — adres sıralı iç fonksiyon listesi (thunk ve dış hariç) ve o ana kadar verilmiş adlar (ön adlar + Ghidra adları; c_namer adayları değil). Önek = adın ilk belirteci (ad ≥ 2 belirteçliyse; belirteçleme `scripts/arge/ozkod/ozkod_veri.py` `belirtecler` ile aynı: harf / rakam dışı ayraç, camelCase sınırı).
3. Kural: adsız fonksiyonun önündeki ve arkasındaki en yakın adlı fonksiyonların öneki aynıysa ve aradaki fonksiyon sayısı ≤ 32 ise önek o.
4. c_namer: `role_evidence[anahtar]`'a `{"role": "modul_oneki", "prefix": p, "before": anahtar, "after": anahtar, "gap": n}`.
5. Eşdeğerlik: geliştirme setinde modülün verdiği (fonksiyon, önek) kümesi `scripts/arge/ozkod/tavan.py` sandviç (aralık ≤ 32) sayımıyla aynı büyüklükte (1 454 karar, 1 212 doğru; çapa kümesi farkı — `tavan.py` ürünün bütün adlarını çapa sayıyor — sayılıp yazılır).
6. Testler: iki yan aynı → satır; farklı → yok; aralık 33 → yok; tek belirteçli ad çapa olmaz.
7. Mutasyon: aralık sınırı, eşitlik şartı, tek belirteç şartı.

**Kabul ölçütü.** Geliştirme setinde satır yazılan fonksiyonlarda önek = GT öneki oranı ≥ %80 (beklenen ≈ %83; `tavan.py`: 1 212 / 1 454); ad haritası bayt düzeyinde aynı (bayrak açık / kapalı).

**Ön kayıt metni.**
> ÖK-6 ön kaydı. Ölçü: satır yazılan fonksiyonlarda önek = GT adının ilk belirteci. Geliştirme seti (yalnız sayım yapılmıştı; kural keşif / sınama bölmesiyle sınanmadı): aralık ≤ 32 → 1 212 / 1 454 (%83,4); birimler arası yayılım büyük (tmux %99, redis-tools %36). H1: geliştirme setinde ≥ %80. H2: bağımsız nüfusta (ÖK-5 Ö-a) ≥ %85 **beklemiyorum**; eşik %80, altında kalırsa satır yalnız "ön adlar" çapasıyla (c_namer adları hariç) yeniden sayılır ve paket durur. H3: ad haritası değişmez.

**Ürüne girişi.** Bayrak `enable_module_prefix_evidence`, öntanım kapalı; yalnız kanıt satırı. K1'in çekimser kaldığı çelişkilerde (iki farklı ad) önek ile seçim **ölçülmedi** (ÖK-7 E).

---

## ÖK-7 — açık ölçümler (bu turda veri ya da araç olmadığı için ölçülemeyenler)

Her biri ayrı küçük ölçüm paketidir; ürün koduna dokunmaz; `scripts/measurement/ozkod_olc.py`'ye alt komut olarak eklenir; çıktısı `docs/arge/2026-11-19_mythos/ozkod/OK7_<harf>.md`. Tahmini sonuç yazılmadı.

| # | Açık ölçüm | Neden ölçülemedi | Nasıl ölçülür | Hangi paketi bekletiyor |
|---|---|---|---|---|
| A | **Karakter düzeyinde ek.** Ek, çapanın yüzey biçiminden öğrenilince karakter eşitliği ne olur? (Sınamada norm 103 / 126, karakter 35 / 126.) | Kural snake_case yazıyor; yüzey biçimli sürüm yazılmadı. Geliştirme setinin iki tarafı da görüldü; yeni kural burada dürüstçe sınanamaz. | `ek_cikar`'ın karakter sürümü: çapa adında dizginin (ayraçları `_` / boş / camel dönüşümüyle) geçtiği aralığı bul; önek ve sonek çapanın harfleriyle. "Ayar" tarafında dönüşüm kümesini dondur, "kör" tarafta say. | ÖK-4b |
| B | **Rolü hangi çağrı veriyor?** Rol derinliği sayımı vekildi (uzaklık); rolün kaynağı etiketlenmedi. | Rol etiketi yok; ölçü ÖLÇÜ hattının işi. | ÖLÇÜ hattının fiil / rol etiket kümesi gelince: GT adının fiili ↔ derinlik d'deki ayırt edici içe aktarımın rol sınıfı uyumu, d = 0, 1, 2 ayrı. | I1'in ürün paketi (henüz yok) |
| C | **Koşut diziler** (ad dizisi + işlev dizisi, aynı indis; busybox türü). | Geliştirme setinde örnek görülmedi; K1 kayıt içi çifte bakıyor. | ÖK-V nüfusunda: aynı uzunlukta dizgi-işaretçi dizisi ve fonksiyon-işaretçi dizisi çiftlerini say; indis eşlemesinin GT adıyla ilişkisi. | — |
| D | **Satır içine alınmış çağrılanın `__func__`'ı.** G1'in zstd'deki 19 yeni yanlışı ve `oz_ad`'ın `n_fn` = 2 yanlışları bundan mı? | Dökülmedi (sınama tarafı; kural dondurulmuştu). | Yanlış G1 adlarında: ad başka bir GT fonksiyonunun adı mı; o fonksiyonun ikilide ayrı gövdesi var mı; assert'in satır numarası argümanı aynı fonksiyon içinde birden çok kaynak dosyaya mı işaret ediyor (dosya adı argümanı). | ÖK-3 |
| E | **K1 çelişkilerinde seçim.** Bir fonksiyon iki kayıtta iki farklı ada aday (tmux'ta aynı `exec`'i paylaşan komutlar: 22 + 16 çekimser). | Seçim kuralı yazılmadı. | Adaylardan modül öneki (ÖK-6) ya da adres sırasındaki kayıt sırası ile seçim; tam eşitlik. | ÖK-4b'nin sonraki sürümü |
| F | **Gevşek nesne anahtarı** (tür dizisi yerine uzunluk): sınamada 152 / 175, keşifte sınanmadı. | Keşifte örnek yoktu. | ÖK-V "ayar" tarafında oku, "kör"de say. | ÖK-4b (htop türü programlar) |
| G | **x86-64, PIE olmayan ikili, Windows PE.** | Sette yok. | ÖLÇÜ hattının tabakalı seti gelince `veri_sozcukleri` kapsamı ve K1 erişimi. | ÖK-4a'nın kapsam notu |
| H | **Belirteç seçimi ve sırası.** Tavan %52 / %13 (programın kendi kodu): belirteçler var, ad yok. | Bu, yasak cevabın bölgesi; kural kurmadım. | Yalnız kayıt çifti ve `__func__` dışındaki kaynaklar için ayrı araştırma turu; önce ÖLÇÜ'nün yakınlık ölçüsü. | — |
| I | **`urun_olc`'un proje normalleştirmesi** harf farkını görüyor mu? | Bakılmadı. | `urun_olcumu_onarim.json` `proje_normallestirmesi` satırı ↔ `oz_ad_harf.py`. | ÖK-1'in raporu |

---

## Gerekli veri ve araç

- Veri: ÖK-V listesi (78,0 MiB indirme; Berke onayı). Başka indirme yok.
- Araç: pyelftools 0.32, lief 0.17.6 (kurulu); Ghidra 12.1.2 (ürün koşuları için; aynı anda 1).
- Olgu tablosu: `~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` (kaynak sınıfı için kullanıldı; `cagri_ciftleri` alanı `desteklenmiyor` — bu hattın C metni çıkarıcısı OLGU'ya taşınabilir: `kayit_cifti.cagri_ciftleri_metin`).

## Riskler (hat düzeyi)

1. **Aşırı uyum.** K1 keşifte %98, sınamada %82. Geliştirme setinin iki tarafı da artık görüldü; bu sette yapılacak her yeni ayar aşırı uyumdur. Bu yüzden ÖK-5'ten önce K1 / G1 kuralına dokunulmaz.
2. **Çapa kıtlığı.** K1'in bugünkü getirisi tek tablo (Mac tmux). Getiri KS-1, G1, KİMLİK ve analist adlarına bağlı. KİMLİK hattı çapa üretirse K1'in getirisi yeniden sayılmalı (`ek_kurali_capa.py`'ye yeni kip).
3. **"Yakın ad" tanımsız.** K1'in sınama yanlışlarının çoğu ad düzensizliği; bunları başarı saymak B3 ölçüsü olmadan kabul edilmez. Tam eşitlikle raporlamaya devam.
4. **Ortak dosyalar.** `c_namer.py`, `stages.py`, `config.py`: paketler sıralı; her paket yalnız kendi bölgesine dokunur.
