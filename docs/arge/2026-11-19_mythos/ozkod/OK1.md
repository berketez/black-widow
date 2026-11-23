# OK1 — P12d (dalda bekleyen kod) + ÖK-1: `oz_ad` harf koruma (ilerleme)

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/OK1.md`; plan `ozkod/PLAN.md` ÖK-1; kararlar A-3, A-13, A-20, A-29.
- Taban: main `bf62e4a` (`git merge --ff-only main` ile; `karadul.__file__` worktree'yi gösterdi).
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/OK1/` (özet `ozet/`).
- Sert son: 21:30.

## Kalem 1 — P12d cherry-pick, testler, mutasyon

- `git cherry-pick 17a8a13 190ddb1 28657bd 3909043 459e74e c212db0` (taban `git merge-base main worktree-agent-a733cb2eb8bc2b9fd` = `2381dce`).
- Çakışma: dört belge commit'i (`17a8a13`, `3909043`, `459e74e`, `c212db0`) `P12d.md` / `P12d_on_kayit.md` / `yamalar/P12d__sonuc.md.patch` dosyalarına dokunuyor; bu dosyaların P12d dalındaki son hâli main'de `151433c` ile zaten var (iki dosya `git diff` ile birebir aynı). Çözüm: main'deki hâl (`--ours`) tutuldu; dört commit boş kaldığı için `--skip` edildi. İçerik kaybı yok.
- Kod commit'leri dalda: `4d3afca` (D1, `190ddb1`'in karşılığı), `45f7f85` (D2, `28657bd`'nin karşılığı). Çakışmasız uygulandı.
- Testler: `tests/test_p12d_erken_donus.py` + `tests/test_p12d_kanit_secimi.py` **18 geçti** / 0 kaldı.
- Mutasyon: `mutation_specs_p12d.json` **10 / 10 öldü** (günlük `p12d_mutasyon.log`); `git diff` temiz.

## Kalem 2 — ÖK-1 ön kaydı

`on_kayit_OK1.md`, commit `9ec2980f` (ÖK-1 kodundan ve bütün ölçümlerden önce; K0 / K1 tanı taraması ön kayıt commit'inden sonra başladı).

## Kalem 3 — ÖK-1 kodu, testler, mutasyon, yamalar

**Kod** (`08bad683`):
- `c_namer._strategy_string_context` klasik aşaması: ad kurulduktan sonra yeni doğrudan yardımcı `_oz_ad_verbatim_name(best_string)` çağrılır; None değilse ad o olur. Yardımcı: bayrak (`self._config.binary_reconstruction.oz_ad_verbatim`; işçiye `_init_heuristic_worker`'ın zaten taşıdığı `config` ile gider) ∧ `e = kanıt.strip()` tek tanımlayıcı (`[A-Za-z_][A-Za-z0-9_]*`) ∧ `"_" in e.strip("_")` ∧ en az bir küçük harf → `e`. `_sanitize_c_name` çağrılmaz; güven, kanıt, `code_path`, `rule` aynı. Çakışma eki mantığına dokunulmadı.
- `karadul/reconstruction/tarif/alt_kanal.py`: `_is_own_name` → `ad == e or ad == e.lower()`; `DEFINITION_VERSION` 1 → 2.
- **Gönderimden sapma 1 (gerekçeli):** `scripts/measurement/alt_kanal.py` DEĞİŞMEDİ. Dosya tanım sürümü 1'in donuk başvuru kopyası; sha256'sı (`d0e6f544…`) N0b ön kaydında (`docs/arge/2026-10-21_g10_n0b/alt_kanal_onkayit.md`), `kesinlik_tablosu.json` `onkosul`'unda ve `scripts/measurement/alt_kanal_olc.py` `ALT_KANAL_SHA256`'da kilitli. Değiştirilirse `tests/test_alt_kanal_olc.py` içe aktarmada (sha256 denetimi) ve `test_tarif_alt_kanal.py::test_basvuru_betigi_n0b_nin_olctugu_dosya` kırılır; N0b'nin donmuş ölçüm kaydı bayatlar. Plan riski 2'nin yolu izlendi: sürüm 1 kaydı silinmez, ürün sürüm 2 olur. Bu yüzden `tests/test_alt_kanal.py`'ye (donuk betiği sınar) satır eklenmedi; yüklem testleri `tests/test_ok1_oz_ad_harf.py`'de.
- **Bunun bedeli:** `tests/test_tarif_alt_kanal.py`'de sürüm eşitliğini isteyen iki satır kırmızı (`test_sabitler_basvuruyla_ayni[DEFINITION_VERSION-TANIM_SURUMU]`: `2 == 1`; `test_alt_kanal_listesi_ve_sirasi`: `U.DEFINITION_VERSION == 1`). Sınıflama eşitliği testlerinin hepsi yeşil (küçük harfli adlarda iki kopya aynı sınıflar). Yama: `docs/arge/2026-11-23_dalga1/yamalar/OK1__test_tarif_alt_kanal.py.patch` (eşitlik satırını çıkarır, "ürün 2, başvuru donuk 1" testini ekler); `git apply --check` geçti; yamalı kopya koşu kökünde ayrıca koşuldu: 58 geçti.
- **Gönderimden sapma 2:** kayda `verbatim: True` alanı eklenmedi (aday sınıfı `_NamingCandidate` ve köken yazıcısı izinli alanın dışında). Harf korunmuş ad kayıttan `evidence.strip() == ad` ile çıkarılır.
- `config.py` yaması: `docs/arge/2026-11-23_dalga1/yamalar/OK1__config.py.patch` (INERT satırını siler, alan yorumunu "okuyan: …" yapar; öntanım kapalı kalır). `git apply --check` geçti; ağaca uygulanmadı.

**Testler:** `tests/test_ok1_oz_ad_harf.py` 16 test, hepsi yeşil. P12d ağacında (ÖK-1 öncesi kod, koşu kökündeki kol ağacı) **6'sı kırmızı** (a, b, e2, f2, g, gerçek havuz [bayrak açık]); kalan 10'u davranış koruması (bayrak kapalı, koşulu tutmayan kanıt).

**Mutasyon:** `mutation_specs_ok1.json` **9 / 9 öldü** (`499cd614`; günlük koşu kökünde `ok1_mutasyon.log`); `git diff` temiz.

## Kalem 4 — Tanı taraması (Ghidra'sız, 119 / 119, dört kol)

Betik `tara.py` (koşu kökünde): ürünün yükleyicileri + `_strategy_string_context`, susturmadan sonra kalan `string_context` adayları. Karşılaştırma `tara_karsilastir.py`; özetler `ozet/tara_*.json` (ad yok, yalnız sayı ve ikili anahtarı).

| Karşılaştırma | Farklı ikili | Farklı fonksiyon | Ayrıntı |
|---|---:|---:|---|
| K0 → K1 (P12d) | 19 | 21 | 21 adsız → adlı (P12d raporunun 21'lik tanı listesiyle aynı sayı; 19 ikili P12d'nin H6 listesiyle aynı) |
| K1 → K2 (ÖK-1, bayrak açık) | 9 | 307 | 51 yalnız harf değişti; **256 adsız → adlı** (`tanimlayici` → `oz_ad` 253, `tek_sozcuk` → `oz_ad` 3) |
| K1 → K2k (bayrak kapalı) | **0** | 0 | H9 tanı düzeyinde **119 / 119 aynı** |
| K0 → K2 | 23 | 326 | — |

K1 → K2 ikili başına: zstd 117 (harf 47, yeni 70), mac/tmux 110 (yeni), debian/tmux 72 (yeni), openssl 3 (harf 2, yeni 1), cp 1 (harf), install 1 (harf), factor 1, sqlite3 1, pzstd 1 (yeni).

**H10 gerçekleşti (tanı düzeyinde):** bayrak açıkken 256 fonksiyon yeni ad alıyor; bunlar planın 40'lık sayımının dışında. Ürün hükmü (doğru / yanlış) yeniden oynatmadan.

**Şu an bekleniyor (20:17):** ürün yeniden oynatması — K0 ve K1: 19 ikili (3'er eşzamanlı, 20:11'de başladı); K2: 23 ikili (20:15); K1 ek: openssl, pzstd, sqlite3, factor (20:15). Yük ortalaması 33–38 (başka ajanlar). TAHMİN bitiş 20:50–21:10 (openssl en uzunu; P12d'de 33 dk). Tam takım da sürüyor (yamasız).

## Kalem 5 — Ürün yeniden oynatması ve ölçüm

**Yöntem:** `yeniden.py` (P12d'nin kopyası; yalnız `ReconstructionStage`), `kos1.sh` / `kol_sira.sh` (koşu kökünde), girdi `urun-onarim-a62f15e` çalışma alanları (SALT OKUR). Kol ağaçları koşu kökünde `git archive` ile: `agac_K0` (`bf62e4a`), `agac_K1` (`45f7f85`), `agac_K2` ve `agac_K2k` (`08bad683`; K2'de `karadul.yaml` ile `oz_ad_verbatim: true`). Ölçüm `olc_kol.py`: `urun_olc.py olc --eksik-izinli --siniflayici-agac <kol ağacı> --mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac`, ayrıca öğe kaydı (ad + GT adı; depo dışı, `ozet/kayit_<kol>.json`). Karşılaştırma `urun_olc.py karsilastir` + `analiz.py` (yalnız `BITTI` işaretli koşular). Yük ortalaması 27–38 (yük altında; süreler yalnız bilgi).

**oz_ad_harf.py yeniden** (a62f15e tabanı; çıktı koşu kökünde `ozet/oz_ad_harf_cikti/`, ARGE kökü değişmedi): 196 ad / bugün doğru 93 / kanıt harfleriyle doğru 133 / yanlıştan doğruya **40** (zstd 37, coreutils 1, openssl 1, mac/tmux 1). Planın sayısıyla aynı.

### H0 — K0 → K1 (P12d), 19 ikili (tanıda farklı çıkanların hepsi; 19 / 19 `basari True`)

| | K0 (`bf62e4a`) | K1 (+ P12d) |
|---|---|---|
| Havuz ad / doğru / yanlış (19 ikili) | 657 / 562 / 95 | 678 / 579 / 99 |
| `string_context/oz_ad` ad / doğru / yanlış | 164 / 84 / 80 | 185 / 101 / 84 |
| Öbür 7 kanal | — | **aynı** (7 / 7) |
| Kazanılan / kaybedilen doğru | — | **17 / 0** (hepsi `oz_ad`, coreutils) |
| Giderilen / yeni yanlış | — | **0 / 4** (debian/tmux `12296c`, zstd `1b80c0` ve `1f14b0`, mac/tmux `100004b58`: P12d raporundaki dört adresin aynısı) |

`karsilastir`: kaybedilen doğru 0 / 562 → `beklenen_aralikta`; `yanlis_yonu` `incele` (P12d'deki gibi; ad ekleyen değişiklik). **H0 tuttu** (sapma 0). Özet `ozet/fark_K0_K1.{json,md}`.

### K1 → K2 ve K0 → K2 (ÖK-1, bayrak açık), 23 ikili

- Yeniden oynatılan: K2 23 / 23 `basari True`; K1 için 19 + 4 ek (openssl, pzstd, sqlite3, factor; 4 / 4). K0'ın bu 4 ikilisi koşulmadı: tanıda K0 = K1 (aynı `string_context` çıktısı), K0 görünümünde K1'in bu 4 koşusu kullanıldı (`gorunum_K0`; etiket: "tanı düzeyinde aynı").
- `urun_olc` 22 ikiliyi ölçtü: `debian/zstd/pzstd` C++ (ölçüm aracı C++ ikiliyi dışarıda bırakır; ks1 kuralı).
- Altküme dışındaki 97 ikilide `string_context` çıktısı dört kolda aynı (tanı); onların `oz_ad` sayıları P12d tabanından (`olc_taban.json`, `2381dce`; altküme içi sayısı K0'ınkiyle birebir aynı: 178 / 88 / 90): 17 ad / 5 doğru / 12 yanlış. 119'luk satırlar bu türetmeyle yazıldı ve öyle etiketli.

**`string_context/oz_ad` (ad / doğru / yanlış; tam eşitlik):**

| | K0 | K1 (+ P12d) | K2 (+ ÖK-1) |
|---|---|---|---|
| Ölçülen altküme (22 ikili) | 178 / 88 / 90 | 199 / 105 / 94 | **351 / 236 / 115** |
| 119, türetilmiş (altküme dışı 17 / 5 / 12 eklendi) | 195 / 93 / 102 | 216 / 110 / 106 | 368 / 241 / 127 |
| Kanal kesinliği, tam (altküme; Wilson %95) | 88 / 178 (%49,4; %42,2–%56,7) | 105 / 199 (%52,8; %45,8–%59,6) | **236 / 351 (%67,2; %62,2–%71,9)** |
| Kanal kesinliği, tam + biçim (A-3; altküme) | 125 / 178 (%70,2; %63,1–%76,5) | 143 / 199 (%71,9; %65,2–%77,7) | **243 / 351 (%69,2; %64,2–%73,8)** |
| Kanal kesinliği, tam, 119 türetilmiş | — | 110 / 216 | 241 / 368 (%65,5; %60,5–%70,2); tam + biçim: altküme dışı 17 adın biçim hükmü yok, ölçülmedi |

**Havuz (22 ikili, `karsilastir`):** K1 730 / 621 / 109 → K2 882 / 752 / 130; kaybedilen doğru 0 / 621 (`beklenen_aralikta`); öbür 7 kanal ve "kesin" etiketli adlar (262 / 249) aynı; program düzeyi makro yanlış %33,4 → %22,9 (altküme, 6 birim). Birim yanlış oranı: zstd %84,2 → %27,0, openssl %11,5 → %7,7; **debian/tmux %10,8 → %16,3, mac/tmux %13,1 → %18,1, sqlite3 %58,3 → %61,5** (`yanlis_yonu` `incele`). Özetler `ozet/fark_K1g_K2.{json,md}`, `ozet/fark_K0g_K2.{json,md}`, `ozet/analiz.json`.

**K1 → K2 öğe geçişleri:**

| Geçiş | Sayı | Birim |
|---|---:|---|
| yanlış → doğru (harf korundu) | 33 | zstd 32, openssl 1 |
| yanlış → yanlış (ad değişti) | 16 | zstd 14, coreutils 2 (4'ü tam + biçim doğru) |
| doğru → yanlış | 0 | — |
| yanlış → adsız | 1 | openssl |
| adsız → doğru (yeni ad) | 98 | zstd 51, mac/tmux 25, debian/tmux 21, coreutils 1 |
| adsız → yanlış (yeni ad) | 55 | mac/tmux 20, zstd 18, debian/tmux 15, openssl 1, sqlite3 1 (2'si tam + biçim doğru) |

zstd birimi yanlış ad: **K0 46 → K1 48 → K2 34** (34 = harf korununca da yanlış kalan 14 + yeni yanlış 18 + `ks1:assert_ust` 2).

**H10 (yeni adlar):** tanıda 256 fonksiyon yeni aday aldı; üründe 153'ü ad oldu (98 doğru, 55 yanlış: **%64,1; Wilson %56,2–%71,2**). Tanı → ürün farkı (256 → 153) ayrıştırılmadı (ad geçerliliği süzgeci, ön ad önceliği, C++ pzstd ölçüm dışı; ölçülmedi). Bu yeni adların kesinliği A-13 eşiğinin (0,909) çok altında; A-29'da elenen G1'e (bağımsız nüfusta %69,2) yakın.

**Türetilmiş (ayrı kol koşulmadı):** yeni adlar çıkarılsa (yalnız harf koruma: verbatim, adayın anahtar sözcük adı zaten `e.lower()` iken) K2 `oz_ad` altkümede 198 / 138 / 60 (%69,7) olurdu, yeni yanlış 0. Etkileşim (çakışma eki, ad geçerliliği) yüzünden kesin değildir; ölçülmesi gerekir.

### Dört yeni yanlış (P12d; H8)

Adlar ve GT adları depo dışı: `ozet/dort_yeni_yanlis_ADLI_DEPO_DISI.json`.

| Adres | K1 | K2 | Fark türü |
|---|---|---|---|
| debian/tmux `12296c` | yanlış | yanlış (aynı ad) | gerçekten farklı işlev (GT başka bir işlev; mekanizmaya bakılmadı) |
| zstd `1b80c0` | yanlış | yanlış (harf korundu) | gerçekten farklı işlev (GT başka bir işlev) |
| zstd `1f14b0` | yanlış; tam + biçim **doğru** | **doğru** (tam) | yalnız biçim (A-3: K1'de "tam + biçim" doğru; ÖK-1 tam doğruya çevirdi) |
| mac/tmux `100004b58` | yanlış | yanlış (aynı ad) | gerçekten farklı işlev (debian/tmux ile aynı ad / GT çifti) |

H8: 4'ün **1'i** yalnız biçim farkı; 3'ü gerçekten farklı işlev. `urun_olc` biçim satırı (P-Ö1): K0 → K1'in 4 yeni yanlışından tam + biçim doğru olan 1 (`analiz.json` `yeni_yanlis_bicim_dogru`).

### H9 — bayrak kapalı

- Tanı: K1 ↔ K2k **119 / 119 aynı**.
- Ürün: K2k yeniden oynatması zstd, cp, install (3 / 3 `basari True`); `naming_map.json` K1 ile **3 / 3 aynı** (`harita_esit.py`). Kalan 20 ikilide ürün düzeyinde K2k koşulmadı (süre).

### Ön kayıt hükümleri

| # | Beklenti | Ölçülen | Hüküm |
|---|---|---|---|
| H0 | K0 → K1: +17 doğru, 0 yanlış geri, 4 yeni yanlış, öbür kanallar aynı (± 1) | +17, 0, 4 (aynı adresler), aynı | **tuttu** |
| H1 | K1 → K2 yanlıştan doğruya 36–44 | 33 (zstd 32, openssl 1; coreutils 0, mac/tmux 0) | **tutmadı** |
| H2 | doğrudan yanlışa 0 | 0 | **tuttu** |
| H3 | zstd yanlış ≤ 12 | 34 | **tutmadı** |
| H4 | öbür kanallar aynı | aynı (7 kanal + kesin etiket) | **tuttu** |
| H5 | yeni yanlış ≤ 2 | 55 | **tutmadı** (H10 genişlemesi) |
| H6 (karar dışı) | makro yanlış düşer | altkümede %33,4 → %22,9 | düştü (altküme; tmux birimlerinde arttı) |
| H7 | K0 → K2: `oz_ad` doğru ≥ +53; yeni yanlış ≤ 6; öbür kanallar aynı | +148; **58**; aynı | **tutmadı** (yeni yanlış) |
| H8 | bilgi | 1 / 4 yalnız biçim | — |
| H9 | K2k = K1 | tanı 119 / 119; ürün 3 / 3 | **tuttu** (ürün düzeyi altkümede) |
| H10 | bilgi | tanı 256 yeni aday; ürün 153 yeni ad, %64,1 doğru | gerçekleşti |

Kabul ölçütü (plan): "kanalın ad sayısı değişmez (± 2)" — 199 → 351: **tutmadı**; "yeni yanlış ≤ 2": tutmadı; "yanlıştan doğruya ≥ 36": tutmadı; "doğrudan yanlışa 0": tuttu; "öbür kanallar aynı": tuttu. **Bayrak öntanımda kapalı kalmalı** (ölçüm tutmadı; yama öntanımı değiştirmiyor).

**Hedef seti:** bu kanal C kodundaki öz-ad dizgileri içindir; hedef setinin Go / ObjC uygulamalarında (Ollama, docker-cli, terminal-notifier …) etkisi beklenmez. Hedef setinde ölçülmedi (Ghidra koşusu yok).
