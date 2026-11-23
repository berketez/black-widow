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
