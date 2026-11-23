# PUV4 — P-ÜV4: C++ RTTI sembolsüz tarama ve üretici adım (IMZA-16)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-13, A-14, A-27), `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 ve "P-ÜV4" (yöntem, kalemler 1–7, kabul, sınama ve mutasyon: aynen uygula), `docs/arge/2026-11-19_mythos/ustveri/BULGULAR.md`'nin C++ bölümü, `docs/arge/2026-11-19_mythos/ustveri/P-UV2.md` (aynı kalıbın ObjC örneği).

Kod başvuruları: `karadul/analyzers/ustveri/goruntu.py` (arayüz — değiştirme), `karadul/analyzers/ustveri/objc.py` + `karadul/pipeline/steps/objc_metadata_recovery.py` (kalıp), `karadul/analyzers/cpp_rtti.py` (`batch_demangle` içe aktarılabilir; dosya değişmez), `karadul/pipeline/steps/_feedback_naming_candidates.py` `_add_rtti` (beklediği `rtti_classes` biçimi; dosyaya dokunma), araştırma betiği `scripts/arge/ustveri/cpp_rtti_tara.py` (çalışan başvuru; yeniden yazılır, kopyalanmaz).

## Neden

Soyulmuş C++ ikilisinde bugünkü `cpp_rtti.py` `_ZTI` / `_ZTV` sembolü istediği için 0 sınıf buluyor (Ollama arm64: vtable 0; araştırma taraması: 8 vtable, 68 işlev; llama-server: 1 994 typeinfo / 1 317 vtable / 7 053 işlev). Sınıf adları ve "bu işlev şu sınıfın N. sanal yuvası" bilgisi ikilide yazılı; bu paket onu okur.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Yuva adayı ad değildir** (plan H6; KARARLAR K-2): `Sınıf_vfunc_N` tam eşitlik ölçüsünde doğru ad olamaz. Bu paket `rtti_classes`'ı `_add_rtti`'nin beklediği biçimde üretir ama ad kanalını bağlamaz / değiştirmez; yuvaların kanıt satırına çevrilmesi P-ÜV6b'de. Raporunda sınıf adı kesinliğini ve "yuva → sınıf" bağının kesinliğini ayrı ayrı ver.
2. **Keşif / sınama ayrımı.** llama-server ve iTerm2 SINAMA ikilileridir. **Sayı eşitliği** (H1, H3: `$V/rtti/<ad>.json`; `$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri`) GT'ye bakmadığı için keşifte serbesttir. **Sembolle ad / vtable / yuva eşitliği** (H2 ve yuva kuralı) o iki ikilide yalnız tarayıcı dondurulduktan sonra BİR kez ölçülür. Keşif GT'si:
   - yerelde derlenen C++ örnekleri (senin yazdığın kaynak; `scripts/arge/ustveri/cpp_ornek/*.cpp`: taban, tekli kalıtım, çoklu ve sanal kalıtım, saf sanal, şablon sınıf, adsız ad alanı, iç içe sınıf, zayıf bağlı typeinfo için başlıkta tanımlı sınıf) — `/usr/bin/xcrun clang++ -O2` ve `-O0`, arm64 ve `-arch x86_64`; çıktı `~/karadul_olcum/runs/dalga1-2026-11-23/PUV4/ornek/` (sembollü + `/usr/bin/strip` ile soyulmuş); derleme çıktısı ÇALIŞTIRILMAZ, depoya girmez;
   - btop (kısmen soyulmuş), Ollama iki dilim (soyulmuş: yalnız sayı);
   - ELF: `pzstd` + dbgsym (`~/karadul_olcum/n1_debian13/`; geliştirme seti, serbest).
3. Bayrak `binary_reconstruction.enable_rtti_recovery` (var; INERT'te). Adım bayrağı `getattr(…, "enable_rtti_recovery", False) is True` ile okur; INERT satırını silen ve yorumu düzelten yama: `docs/arge/2026-11-23_dalga1/yamalar/PUV4__config.py.patch`. `rtti_max_vtable_entries` ayarını `config.py`'den oku (alan adını `grep` ile doğrula). Adım Faz 1 listesine ve `steps/__init__.py`'ye EKLENMEZ (P-ÜV6b).
4. Durum sabitleri: `goruntu.py`'dekileri içe aktar; orada olmayanları `objc.py`'deki gibi kendi modülünde tanımla.

## Yazabileceğin dosyalar (hepsi yeni)

`karadul/analyzers/ustveri/cpp_rtti_tara.py`; `karadul/pipeline/steps/rtti_recovery.py`; `tests/test_puv4_rtti.py`; `scripts/measurement/mutation_specs_puv4.json`; `scripts/arge/ustveri/cpp_ornek/` (kaynaklar + derleme / GT betiği); `scripts/arge/ustveri/puv4_olc.py`; `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV4.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV4.md` (ilerleme dosyası); yama `docs/arge/2026-11-23_dalga1/yamalar/PUV4__config.py.patch`.

**Dokunma:** var olan bütün dosyalar (`cpp_rtti.py`, `goruntu.py`, `stages.py`, `config.py`, `steps/__init__.py`, `_feedback_naming_*.py`, `scripts/measurement/ks1_olc.py` — `gt_elf` içe aktarılabilir). Ghidra koşusu YOK.

## Ön kayıt (`on_kayit_PUV4.md`; ölçümden önce commit)

Plandaki H1–H6 aynen, şu eklerle:
> H0 (keşif, yerel örnekler): sembollü kopyada her `_ZTI` sembolü için typeinfo bulunur, adı sembolle aynı; her `_ZTV` için vtable adresi sembolle aynı; yuva işlevlerinin sembolü sınıfın ya da tabanının adını taşır (saf sanal ve içe aktarım yuvası hariç). Soyulmuş kopyada çıktı sembollüyle aynı (fark 0). arm64 ve x86_64'te sınıf kümesi aynı.
> H2 (SINAMA, bir kez; tarayıcı dondurulduktan sonra): llama-server + iTerm2 + btop'ta typeinfo adı 2 028 / 2 028, vtable 1 328 / 1 328 sembolle aynı; yuva → sınıf bağı ≥ 7 098 / 7 119. Tutmazsa tarayıcı sınama sonucuna göre YENİDEN AYARLANMAZ; hangi sınıf türlerinde (şablon, sanal kalıtım, adsız ad alanı, öbür) kaç yanlış olduğu yazılır.

## Sıra

1. Ön kayıt → commit. 2. Yerel örnekler + GT betiği → commit. 3. Tarayıcı (typeinfo, vtable, zayıf bağ) + sentetik testler (≥ 14). 4. Devralınan yuva kuralı (kalem 4), ELF yolu (kalem 5). 5. Sağlamlık + bulanık girdi (kalem 6). 6. Üretici adım + yama. 7. Mutasyon (≥ 8). 8. Keşif ölçümü (H0, H1, H3, H4, H5). 9. Dondur (commit'i yaz) → H2'yi bir kez ölç. 10. Tam takım (yama geçici uygulanmış), geri al.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek uygulama sayıları: llama-server typeinfo / vtable / işlev (x / 1 994, x / 1 317, x / 7 053) ve sembolle eşitlik; Ollama 19 / 8 / 68; pzstd. Sonra H0–H6, test / mutant sayıları, dondurma commit'i, commit listesi, yama, P-ÜV6b'ye notlar (kanıt satırının alanları; belirsiz işlev sayısı).
