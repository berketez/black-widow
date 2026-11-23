# Ön kayıt — P-ÜV5 (Mach-O `main`, `LC_MAIN` girişi), 2026-11-23

Bu metin koddan ve ölçümden ÖNCE commit'lenir. Tutmayan beklenti silinmez; eşik sonradan değişmez.
Paket metni `docs/arge/2026-11-23_dalga1/gonderim/PUV5.md`; plan `ustveri/PLAN.md` "P-ÜV5"; kararlar A-10, A-27,
A-34 (`config.py` yaması ajan ağacında uygulanmaz). Taban commit: `0b4d948` (main; `git merge --ff-only main`).

**Bu kayıttan önce görülenler (dürüstlük notu):**
- `scripts/arge/ustveri/macho_main.py` (kaynak) ve plandaki sayılar (GT'li 8 / 8, Homebrew 1 169 / 1 169, ürün 0 / 8).
- Sekiz Mac çalışma alanında (`urun-onarim-a62f15e/mac/{htop,tmux}`, `onarim-2026-11-18/P-S3b/B/macgnu/*`) Ghidra'nın
  girişteki adı ve `entry` sözcüğünün geçtiği yerler: sekizinde de girişte `entry` adlı fonksiyon var; htop'ta 4 baytlık
  thunk; `entry.c` dışında `entry` yalnız `// Callers:` yorum satırlarında geçiyor. GT dosyaları açılmadı.
- terminal-notifier (PUV6a `urun/acik2`) çalışma alanı: `entryoff 3424`, Ghidra'da `entry` (128 bayt, thunk değil).
- Ürün kodu: `_recover_gnulib_from_fingerprints` içindeki `_main_caller` (P-S3b kalem 2, `usage` geleneği) `main`'i
  çağıranın adresinden kurulan `FUN_<adres>` anahtarıyla arar. Mach-O'da girişin anahtarı Ghidra'nın adı `entry`'dir
  (kodda `FUN_<adres>` diye geçmez). **Ölçümden önceki öngörü:** bu yüzden H5'te `main` üstünden gelen yeni `usage`
  adı yamasız kodda 0 olur; kanalın `entry` anahtarını tanıması bu paketin yöntem sınırının dışında (yama ile).
- Ölçüm aracı `scripts/measurement/urun_olc.py` yalnız `FUN_<onaltılık>` anahtarlarını fonksiyon adı sayar; `entry`
  anahtarı `diger` sınıfına düşer. Bu yüzden H1 / H6 ürün düzeyinde bu paketin kendi sayım betiğiyle ölçülür
  (koşu kökünde; anahtar → adres `ghidra_functions.json`'dan, GT ve nüfus `ks1_olc.gt_mac` kuralıyla).

## 1. Hipotezler (plan + gönderim metni, aynen)

> H1: bayrak açıkken Mach-O 8 / 8'de giriş fonksiyonu `main` adını alır; GT'ye göre 8 / 8 doğru. H2: bayrak kapalıyken
> ad haritası 8 / 8'de tabanla aynı. H3: 5 ELF ikilisinde bayrak açıkken değişen ad 0. H4: iç bağlayıcılı Go ikilisinde
> (`gh`; yalnız kural birim testi ve giriş adı okuması, Ghidra koşusu yok) `main` yazılmaz. H5: `main` üstünden çalışan
> gelenek kanalının Mac'teki yeni adlarında yanlış 0; sayı ilk ölçüm. H6: nüfus etkisi: htop'ta `main` thunk olduğu
> için ad bekleyen nüfusa girmez; doğru ad kapsamı yalnız 7 ikilide 1'er artar. Tutmayan hüküm silinmez.

Kabul (plan): bayrak açıkken 8 / 8'de `main` giriş fonksiyonuna verilir ve GT'ye göre doğrudur; yanlış `main` 0.
Bayrak kapalıyken 8 ikilinin ad haritası tabanla bayt bayt aynı. Geliştirme setinin Debian kolundan 5 ikilide (cat,
expr, ls, tree, pzstd) bayrak açıkken ad haritası değişmez. `usage` kanalından gelen yeni adlar: yanlış 0.

## 2. Kural (gönderim hükümleri dahil; kod bundan yazılır)

1. Yalnız bayrak `binary_reconstruction.enable_macho_entry_main` gerçek `True` iken (`getattr(…) is True`).
2. ELF yolu değişmez: `__libc_start_main(FUN_…` kalıbı önce denenir; Mach-O kuralı yalnız kalıp bulunamadığında ve
   hedef Mach-O iken.
3. Hedef Mach-O `MH_EXECUTE` (`static/lief_analysis.json` `header.file_type` = `EXECUTE`); `static/load_commands.txt`'te
   tek bir `LC_MAIN` girişi (`entryoff`). Giriş adresi = Ghidra görüntü tabanı (`ghidra_combined_results.json`
   `program_info.image_base`) + `entryoff`.
4. Ghidra'nın fonksiyon listesinde (`ghidra_functions.json`) giriş adresinde fonksiyon var ve adı jenerik
   (`entry` ya da `FUN_…`; ürünün `kesin.is_generic_name` kuralı) → `extracted_names[<o ad>] = "main"`,
   `stats["main_recovered"]`, künye `KIND_MAIN` (`main_giris`; kanal `on_ad:main_giris`). `üst veriden` etiketi KULLANILMAZ.
5. İstisnalar (ad yazılmaz, neden `stats`'ta): (a) ikilide Go `pclntab` var (ürünün okuyucusu
   `karadul/analyzers/ustveri/go_pclntab.py`, içe aktarılır) ve girişin `pclntab` adı `main.main` değil (gönderim hüküm 2;
   `_rt0_…`, Go'nun `main` saplaması ve girişi kapsamayan tablo dahil); okuyucu `veri_yok` dışında bir durum verirse
   (`tutarsiz`, `desteklenmiyor`, `hata`) de yazılmaz; (b) `LC_MAIN` yok, `LC_UNIXTHREAD` var → yazılmaz; (c) girişte
   Ghidra jenerik olmayan bir ad taşıyor → dokunulmaz; (d) birden çok farklı `LC_MAIN` girişi ya da okunamayan alan →
   yazılmaz.
6. Thunk: girişteki fonksiyon thunk ise adı thunk'a yazılır, hedefine yazılmaz.

## 3. Ölçüm tanımları (ölçümden önce)

- **Ghidra'sız yeniden oynatma** (öncelikli; gönderim sıra 3): var olan çalışma alanlarının `static/` dizini üstünde
  ürün kodu (`ReconstructionStage._recover_main_from_entry` ve tohum sırası) bayrak açık / kapalı koşulur. Mac 8:
  `urun-onarim-a62f15e/mac/{htop,tmux}`, `dalga0-2026-11-20/s8_taban_b6aceb9/mac/tmux`, `onarim-2026-11-18/P-S3b/B/macgnu/
  {envsubst,gettext,gmktemp,gsort,idn2,xz}`; ELF 5: `urun-onarim-a62f15e/debian/…/{cat,expr,ls,tree,pzstd}`; hedef seti:
  terminal-notifier (PUV6a `urun/acik2`), Ollama (`gosteri-2026-11-19/ollama/ws`).
- **"GT'ye göre doğru `main`":** `main` adını alan anahtarın adresi (`ghidra_functions.json`, Ghidra adresi − görüntü
  tabanı farkı) GT'de `_main` adlı fonksiyonun adresiyle aynı. Başka adrese verilen her `main` yanlış sayılır.
- **H1** yeniden oynatmada (kural düzeyi) ve ürün koşusunda (`out/naming_map.json` `mappings`'te `entry` → `main`, `out/src`
  kodunda `main` tanımı, künye `main_giris`) ayrı ayrı yazılır.
- **H2** yeniden oynatmada: bayrak kapalıyken yeni kodun tohum sonucu (ad sözlüğü + künye + `stats`) main `0b4d948`'deki
  kodunkiyle aynı, 8 / 8 (+ 5 ELF). Ürün düzeyinde: bayrak kapalı kolun `out/naming_map.json`'ı aynı ürün kodunun tabanıyla
  (tmux: `s8_taban_b6aceb9` + A/A; öbürleri için bugünkü ürün ağacının koşusu) karşılaştırılır; süre yetmezse "kalan".
- **H3** yeniden oynatmada: 5 ELF'te bayrak açık ↔ kapalı tohum sonucu aynı.
- **H4**: birim testi (sahte Go okuyucu sonucu) + `gh`'nin `LC_MAIN` girişinin `pclntab` adı (ürün okuyucusuyla; ikili
  çalıştırılmaz, Ghidra yok).
- **H5**: yeniden oynatmada tohum sırasının tamamı (main → KS-1 → gnulib / `usage` → ELF önyük) bayrak açık; `usage`
  kararlarının `reason = usage_gelenegi` olanları sayılır, adresleri GT'ye göre doğru / yanlış. Yamalı `_main_caller`
  (koşu kökündeki kopya üstünde) ayrı satır, "yama önerisi" etiketiyle.
- **H6**: `ks1_olc.gt_mac` nüfus kuralıyla (thunk değil, Ghidra'da jenerik, program sınıfı, klon değil) girişin nüfusta
  olup olmadığı ve doğru ad kapsamına katkısı, ikili başına.
- Sınama ikilileri (docker-compose, iTerm2, llama-server) açılmaz.
