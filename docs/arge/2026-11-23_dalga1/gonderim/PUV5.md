# PUV5 — P-ÜV5: Mach-O `main` (`LC_MAIN` girişi)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-27), `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` "P-ÜV5" (kalem 1–7, kabul, ön kayıt metni, sınama ve mutasyon: aynen uygula), `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` (senden hemen önce `stages.py`'ye ve ad bağlama dosyalarına giren paket).

## Neden

Mach-O çalıştırılabilirinde `LC_MAIN` girişi geliştiricinin `main`'idir (GT'li 8 / 8; Homebrew 1 169 / 1 169); ürün bugün `main`'i 0 / 8'de buluyor (`_recover_main_from_entry` yalnız ELF'in `__libc_start_main` kalıbını arıyor). `main` bulunmayınca ondan yayılan kanallar (`usage` geleneği, çağrı grafiği) da Mac'te çalışmıyor.

## Ana oturumun hükümleri

1. Bayrak `binary_reconstruction.enable_macho_entry_main` (BAYRAK ekledi; INERT'te, öntanım kapalı). Kod `getattr(…, "enable_macho_entry_main", False) is True` ile okur; INERT satırını silen ve `# ETKİSİZ` yorumunu düzelten yama: `docs/arge/2026-11-23_dalga1/yamalar/PUV5__config.py.patch`.
2. Go istisnası (plan kalem 3a) için ikilide `pclntab` var mı sorusunu ürünün Go okuyucusuyla cevapla (`karadul/analyzers/ustveri/go_pclntab.py`; içe aktar, değiştirme) — plan yazılırken o modül yoktu, artık main'de. Girişin `pclntab` adı `main.main` değilse (`_rt0_…`) ad yazma.
3. Etiket / künye: var olan `KIND_MAIN` (`main_giris`) ve `on_ad:main_giris` kanalı. `üst veriden` etiketini (PUV6a ekledi) KULLANMA: `main` adı üst veri metninden değil yükleyici alanından (`LC_MAIN`) gelir ve çalışma için zorunludur.
4. Ölçülmüş kesinlik satırının (`naming_labels.py` `MEASURED_PRE_NAME_PRECISION`) Mach-O ölçümüyle güncellenmesi bu pakette DEĞİL (P-ÜV6b); sayıyı raporuna yaz.

## Yazabileceğin dosyalar

`karadul/stages.py` — YALNIZ `_recover_main_from_entry` ve onun yeni yardımcıları (Faz 1 adım listesi PUV6a'nın, başka yöntemler değişmez); yeni `tests/test_puv5_macho_main.py`; yeni `scripts/measurement/mutation_specs_puv5.json`; `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV5.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV5.md` (ilerleme dosyası); yama `docs/arge/2026-11-23_dalga1/yamalar/PUV5__config.py.patch`.

**Dokunma:** `config.py`, `karadul/core/naming_labels.py`, `karadul/reconstruction/tarif/baglama.py`, `karadul/pipeline/steps/`, `karadul/analyzers/ustveri/`.

## Sıra

1. Ön kayıt (planın metni) → commit.
2. Kod + birim testleri (≥ 10; sahte `static` dizini ve sahte Ghidra fonksiyon listesiyle) + mutasyon (≥ 6).
3. **Gerçek veriyle yeniden oynatma (Ghidra'sız, öncelikli):** var olan çalışma alanları üstünde kuralı uygula ve say — Mac: `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/mac/tmux`, `~/karadul_olcum/runs/urun-onarim-a62f15e/mac/{htop,tmux}`, P-S3b kabul seti çalışma alanları (`~/karadul_olcum/runs/onarim-2026-11-18/P-S3b/`; düzeni oradaki `kos_mac.sh`'tan); ELF: geliştirme setinin 5 ikilisi (`~/karadul_olcum/runs/urun-onarim-a62f15e/debian/…`). H1 / H3 / H6'nın yeniden oynatma hükmü. Ayrıca hedef setinden terminal-notifier ve (varsa çalışma alanı) Ollama dilimi: giriş adresi Ghidra'da hangi adı taşıyor, kural ne yazardı.
4. **Ürün koşusu (kuyrukla):** kendi dalının ürün ağacıyla (ORTAK_D0 §3), bayrak açık, önce htop ve tmux; sonra kabul setinin kalanı; bayrak kapalı kol (H2) en son. Her biri `~/karadul_olcum/ghidra_kuyruk.sh PUV5 <ad> …`.
5. Tam takım (yamasız; ORTAK_D1 §2 `config.py` satırı: yama uygulanmaz, `git apply --check` ile denetlenir).

## Sert son

Gönderim iletisinde yazılı. O saatte koşulamayan ürün koşularını "kalan" diye yaz; yeniden oynatma ve birim kanıtıyla hüküm verilebilenleri ayrı yaz.

## Dönüş mesajı

İlk satır gerçek uygulama sayısı: Mach-O'da `main` x / 8 (önce 0 / 8), yanlış `main` sayısı; `usage` kanalından gelen yeni adlar (doğru / yanlış). Sonra H1–H6, test / mutant sayıları, commit listesi, yama, P-ÜV6b'ye notlar.
