# Bilinen açık kusurlar (2026-11-12 itibarıyla; hafıza ve önceki belgelerden derlendi)

Bu liste taramadan ÖNCE yazıldı. Amaç: ajanlar bunları "yeni bulgu" diye yeniden keşfetmesin;
kulvarına düşen kalemin bugünkü durumunu (duruyor / kapanmış / kısmen) KODDAN doğrulasın.
Buradaki satır numaraları eskimiş olabilir; her biri yeniden bulunur.

## B-A. Ad doğruluğu (ölçülmüş; kaynak `docs/arge/2026-11-10_n1_adim3/urun_olcumu_sonuc_ek1.md`)
- B-A1. Yanlış ad oranı havuzda %29,7 (2 261 adın 672'si yanlış). Kaynak dağılımı: `kebap_ad` 239 (0 doğru),
  gnulib ön adları 222, `oz_ad` 112, `api_param_reverse` 84, `func_kalibi` 13, `assert_ust` 2.
- B-A2. Tam ad kapsamı %5,2. Mac htop'ta 0 ad.
- B-A3. Üç gnulib parmak izi (`version_etc`, `hard_locale`, `full_write`) LTO'lu Ubuntu'da doğru, LTO'suz Debian'da yanlış.
- B-A4. Yeni ad var olan fonksiyonla çakışıyor: 5 ikili (redis ×4 `_start`, Debian htop `full_write`); neden doğrulanmadı.
- B-A5. Yerel değişken adları: 37 ikili, 5 356 kusur kaydı (sağlamlık denetimi).
- B-A6. `c_namer` yerel ad sonekleri belirlenimci değildi (b7faeac ile bir kısmı düzeldi); bugünkü durum bilinmiyor.

## B-B. Çıktı ve rapor (kaynak `docs/arge/2026-11-10_cikti_saglamligi/yeni_urun_karsilastirma.md` §2, `2026-11-12_cikti_hatalari/sonuc.md`)
- B-B1. Başlıkta geçersiz C adı (5 ikili, 20); Mach-O'da `$` içeren ad süzgeçten geçmiyor.
- B-B2. pzstd çift tanım (5).
- B-B3. tmux'ta eski ad kodda kalıyor (2); eski ad yorumda kalıyor (117 ikili, 1 929).
- B-B4. Kırpık decompile kaydı (`decompiled_json_kirpik`: 21 ikili, 25 640); gövde 5 000 karakterde kırpılıyor, 500 kesmesi sessiz.
- B-B5. `readme_yapi_uyusmuyor` 119 (denetim mi ürün mü yanlış, bakılmadı).
- B-B6. `html_report.py` / `markdown_report.py` yazılmayan `static/signature_matches.json`'ı okuyor (IOC bölümü dolmuyor olabilir).
- B-B7. Raporda doğrulanmamış iddialar: "NSA-grade… 300+ rules", "Source Matching… names recovered".
- B-B8. C dalının yedek yolu `types.h`'yi iki kez yazıyor.
- B-B9. `bsim_yedege_dustu` 78 ikili; `ithal_sayaci_sifir` 119; `fonksiyon_anahtari_ghidrada_yok` 117 ikili / 234; `harita_uygulanmayan` 6 675.
- B-B10. `app_wrapper` gerekçesindeki "eşleşecek imza yok" çelişkisi.

## B-C. Boru hattı / ölü kod (kaynak `docs/arge/2026-11-11_yeniden_hesapla/fizibilite.md`)
- B-C1. `stages.py`'deki monolit metotlar emekli; etkin kod `karadul/pipeline/steps/`. `stages.py` ~3563–4820 adım kipinde ölü kod.
- B-C2. Okunmayan ayarlar: `max_decompile_timeout_per_func`, `DeepTraceConfig`.
- B-C3. CFG-iso 0/14 376 eşleşme; füzyon 0/3 106 kabul (adımlar koşuyor ama sonuç üretmiyor).
- B-C4. Ghidra projesi analiz sonunda siliniyor (`macho.py` ~937); saklansa tek fonksiyon 0,3 sn.
- B-C5. Mac htop'ta fonksiyonların %24,4'ünde "jumptable kurtarılamadı".
- B-C6. Manuel override'ın merge sonrası yeniden uygulanması ölü döngüde (MAJOR-1; 2026-09-25 kaydı; bugünkü durum bilinmiyor).
- B-C7. `data_flow.py`'de override edilmiş 3 ölü fonksiyon tanımı; `sigdb_builtin`'de tekrarlı anahtarlar.
- B-C8. Akış sadeleştirme onarıldı ama öntanımlı KAPALI.
- B-C9. Yerleşim bayrağı (`enable_address_placement`) kapalı; eşik 16 GCC 14 / AArch64'e özgü.

## B-D. Ghidra / ortam
- B-D1. Geliştirme CLI'ının Ghidra'sı ile paket/ölçüm Ghidra'sı farklı sürüm olabilir (12.0_DEV ↔ 12.1.2); tek sürüme bağlanmalı.
- B-D2. BSim adayları ortak depodan (`~/.cache/karadul/bsim/`); Mac tmux'ta %92'si aynı adlı programdan (sızıntı ya da döngü; doğrulanmadı).
- B-D3. FLIRT imza veritabanı seçici değil (redis 162 ad / 0 doğru); FLIRT bilerek kapalı.

## B-E. Arayüz / KaradulLM
- B-E1. KaradulLM (Aşama 1b) arayüze bağlı DEĞİL. K1/K2 kipleri kapalı ve gerçek modelde hiç denenmedi; K0 gerçek modelde 5/5 çekimser.
- B-E2. Jeton kestirimi gerçeği ~%8 düşük gösteriyor; 512'lik pay dar (497 kullanıldı).
- B-E3. `asama1b.md` §2: 22 tasarım sapması, 9'u karar bekliyor.
- B-E4. R1 açığı: kabul edilen ad `manual` / 1.0 olarak yazılırsa sonraki koşuda korunan ön ad olur, ölçüme sızar.
- B-E5. Yerel model sunucusunun anahtarı komut satırında görünüyor.
- B-E6. "Yeniden hesapla" düğmesi bugün süs olur (yeni kanıt üretmiyor).
- B-E7. Fonksiyon kartı önerisi (`2026-11-11_fonksiyon_karti/envanter.md` §5.1) uygulanmadı.

## B-F. Sürüm / dağıtım (kaynak `workspaces/2026-10-22_profesyonellik/denetim.md`)
- B-F1. Lisans çelişkisi; en düşük macOS (stub minos 27.2); GitHub'da sürüm yok; notarization yok.
- B-F2. Kurulu `.app` eski; `vendor/pycdc` pakete girmiyor.
- B-F3. Python kalanları: üçüncü parti modül üst sınırı; `dis` yedeğinde güvenilmeyen `marshal.loads`; static TOC little-endian hatası;
  manifest "zPYZ"; iki stdlib tanımı; decompyle3/uncompyle6 doğrulaması; cx_Freeze `__init__` çakışması; CLI decompile sayıları.
- B-F4. `context_namer` + `.mjs` hattı için test yok.
