# OK1 — P12d (dalda bekleyen) + ÖK-1: `oz_ad` kanalının iki ölçülmüş kusuru

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-3, A-13, A-20, A-29), `docs/arge/2026-11-19_mythos/ozkod/PLAN.md` §0 ve "ÖK-1" (adımlar 1–8, kabul, ön kayıt: aşağıdaki hükümlerle uygula), `docs/arge/2026-11-19_mythos/ozkod/BULGULAR.md` §1.2, `docs/arge/2026-11-18_onarim/gonderim/P12d.md` (P12d'nin iş emri) ve P12d'nin raporu: `git show worktree-agent-a733cb2eb8bc2b9fd:docs/arge/2026-11-18_onarim/P12d.md` (o dosya main'de yok; dalda).

## Neden

`string_context/oz_ad` kanalı geliştirme setinde ölçülmüş iki kusur taşıyor:
- **P12d (kod hazır, dalda):** klasik dizgi aşaması, susturulacak bir agresif adayın erken dönüşü ve eşit puanda yanlış kanıt seçimi yüzünden 19 doğru adı kaybediyor. Dal `worktree-agent-a733cb2eb8bc2b9fd` (6 commit): 17 doğru ad geri, 0 / 8 yanlış geri, **4 yeni yanlış**. A-20: tek başına main'e alınmaz; ÖK-1 ile aynı ajanda, sırayla alınır ve **birlikte** ölçülür.
- **ÖK-1:** kanıt dizgisi zaten tek bir C tanımlayıcısıyken ad anahtar sözcüklerden yeniden kurulup küçük harfe çevriliyor (`ZSTD_getCParamsFromCDict` → `zstd_getcparamsfromcdict`): 196 `oz_ad` adının 93'ü doğru; harf korunsa 133'ü doğru olurdu (+40: zstd 37).

Bu iki onarım aynı işleve (`c_namer._strategy_string_context`) dokunur.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Sıra:** önce P12d'nin altı commit'ini kendi dalına al (`git cherry-pick 17a8a13 190ddb1 28657bd 3909043 459e74e c212db0`; taban `git merge-base main worktree-agent-a733cb2eb8bc2b9fd`; çakışırsa çöz ve ne çözdüğünü yaz; P12d'nin testleri `tests/test_p12d_*.py` ve mutasyonu 10 / 10 senin dalında yeniden yeşil / ölü olmalı). Sonra ÖK-1.
2. **`config.py`'ye yazmazsın.** `oz_ad_verbatim` alanı BAYRAK paketiyle var (INERT'te, öntanım kapalı): plan adım 1 atlanır; yaman `docs/arge/2026-11-23_dalga1/yamalar/OK1__config.py.patch` INERT satırını siler, yorumu düzeltir. Öntanım kapalı kalır.
3. **Ölçüm Ghidra'sız yeniden oynatmayla** (plan adım 7'deki iki kollu 119 ürün koşusu yerine): `c_namer` Ghidra'dan sonra koştuğu için a62f15e koşusunun çalışma alanları üstünde yeniden oynatma geçerlidir. Yöntem ve araçlar P12d'nin kullandığıyla aynı (`docs/arge/2026-11-18_onarim/P12a.md`; P12d'nin verisi `~/karadul_olcum/runs/onarim-2026-11-19/P12d/`, salt okur). Üç kol, aynı 119 ikili: (K0) bugünkü main; (K1) main + P12d; (K2) main + P12d + ÖK-1, bayrak açık. Ek olarak (K2k) bayrak kapalı kolun K1 ile aynı olduğunu göster. Ghidra koşusu YOK.
4. **Dört yeni yanlışın dökümü:** P12d'nin getirdiği 4 yeni yanlış (debian/tmux 1, mac/tmux 1, zstd 2) K2'de ne oluyor? Her biri için: ad, GT adı, fark türü (yalnız biçim / gerçekten farklı işlev). Biçim farkıysa A-3'e göre "tam + biçim" düzeyinde doğrudur; `urun_olc`'un biçim satırıyla (P-Ö1, main'de) ayrıca raporla.
5. **`oz_ad` bağımsız nüfusta %79,8** (ÖK-5, A-29): bu paket kanalın ad mı kanıt satırı mı yazacağı kararını VERMEZ (o ÖK-2'nin yeniden tasarımı). Raporuna K2 sonrası kanal kesinliğini (doğru / ad verilen, Wilson alt sınırı; tam ve tam + biçim) yaz; ana oturum o sayıyla karar verecek.
6. `scripts/measurement/alt_kanal.py` ve `karadul/reconstruction/tarif/alt_kanal.py`'de PUV6a'nın (main'de) etiket değişikliği var: yalnız `_is_own_name` yüklemine ve tanım sürümüne dokun; iki kopyanın eşitlik testi yeşil kalmalı.

## Yazabileceğin dosyalar

`karadul/reconstruction/c_namer.py` (yalnız `_strategy_string_context` ve doğrudan yardımcıları); `karadul/reconstruction/tarif/alt_kanal.py` ve `scripts/measurement/alt_kanal.py` (yalnız `_is_own_name` + sürüm); `tests/test_alt_kanal.py` (yeni yüklem satırı); yeni `tests/test_ok1_oz_ad_harf.py`, `scripts/measurement/mutation_specs_ok1.json`; P12d'nin dosyaları (cherry-pick'le gelenler: `tests/test_p12d_*.py`, `scripts/measurement/mutation_specs_p12d.json`, `docs/arge/2026-11-18_onarim/{P12d,P12d_on_kayit}.md`, `docs/arge/2026-11-18_onarim/yamalar/P12d__sonuc.md.patch`); `docs/arge/2026-11-19_mythos/ozkod/on_kayit_OK1.md`, `docs/arge/2026-11-19_mythos/ozkod/OK1.md` (ilerleme dosyası); yama `docs/arge/2026-11-23_dalga1/yamalar/OK1__config.py.patch`.

**Dokunma:** `karadul/config.py`, `karadul/stages.py`, `karadul/pipeline/steps/`, `karadul/core/naming_labels.py`, `scripts/measurement/urun_olc.py`, `ks1_olc.py`; `c_namer.py`'nin öbür stratejileri; `_extract_keywords_from_string`, `_sanitize_c_name`.

## Ön kayıt (`on_kayit_OK1.md`; ölçümden önce commit)

Plandaki ÖK-1 ön kaydı (H1–H6) K1 → K2 farkı olarak aynen. Ek:
> H0 (P12d yeniden üretimi): K0 → K1'de doğru ad +17, yanlış geri 0, yeni yanlış 4, öbür kanallar aynı (P12d raporundaki sayılar; main o günden beri değiştiği için ± 1 sapma açıklanarak kabul).
> H7 (birleşik, K0 → K2): `oz_ad` kanalında doğru ad en az +53 (17 + 36); yeni yanlış ≤ 6; öbür kanallar aynı.
> H8 (dört yeni yanlış): K2'de bunların kaçı yalnız biçim farkıdır — yön bildirilmez, sayı ilk ölçüm.
> H9 (bayrak kapalı): K2k = K1 (ad haritası 119 / 119 aynı).

## Sıra

1. P12d cherry-pick + testleri + mutasyonu (10 / 10) → K0, K1 yeniden oynatma (H0).
2. ÖK-1 ön kaydı → commit.
3. ÖK-1 kodu (plan adım 2–4) + testler (adım 5) + mutasyon (adım 6, ≥ 5) + yama.
4. K2, K2k yeniden oynatma; `urun_olc karsilastir`; `scripts/arge/ozkod/oz_ad_harf.py` taban kolda.
5. Hüküm 4 ve 5'in tabloları.
6. İlgili takım (`c_namer`, ad birleştirici, alt kanal, P12a / P12b / P12c / P12d / P13a testleri), sonra tam takım (yama geçici uygulanmış), geri al.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır: geliştirme setinde `oz_ad` doğru ad K0 → K1 → K2 (sayı), yeni yanlış, zstd yanlış ad (46 → ?). (Bu kanal C kodu içindir; hedef setinin Go / ObjC uygulamalarında etkisi beklenmez — bunu açıkça yaz.) Sonra H0–H9, dört yeni yanlışın dökümü, K2 sonrası kanal kesinliği, test / mutant sayıları, commit listesi, yama, ÖK-2 için notlar.
