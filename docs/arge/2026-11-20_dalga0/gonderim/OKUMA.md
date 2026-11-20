# OKUMA — OKUMA-ENVANTERİ: ikilide ne varsa, ürün neyi okuyor (KARARLAR A-27)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md` (kurallar aynen geçerli), `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-11, A-17, A-27, A-28), `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 ve `ustveri/BULGULAR.md` (bugüne kadar ölçülen üst veri), `docs/arge/2026-11-19_mythos/ustveri/olcum/HEDEF.md` (hedef seti ve bugünkü ürün: terminal-notifier 0 / 40), `docs/arge/2026-11-19_mythos/kimlik/PLAN.md` PK-5 (ayrık hata ayıklama dosyası).

**Berke'nin kararı (A-27):** "Her şeyi okuyacak; yazılımda ne varsa her şeyi okumak zorunda." Bu paket "her şey"in eksiksiz, ölçülmüş listesini çıkarır; ürün kodu değişmez.

**Çıktı:** `docs/arge/2026-11-20_dalga0/OKUMA_ENVANTERI.md` (yeni; ilerleme dosyası da bu) ve araştırma betikleri `scripts/arge/okuma/*.py` (yeni); veri `~/karadul_olcum/runs/dalga0-2026-11-20/OKUMA/`.
**Dokunma:** ürün kodu (`karadul/`), testler, var olan betikler. Ghidra koşusu YOK (yalnız dosya baytları ve var olan koşu çıktıları, salt okur). Hedef ikililer çalıştırılmaz, yerinde değiştirilmez; `/usr/bin/{otool,nm,lipo,strings,dyld_info}`, `xcrun swift-demangle`, Python `lief`, `pyelftools`, `capstone` kullanılabilir (kurulu). Kapalı kaynak uygulama analiz edilmez; üçüncü taraf ad listesi depoya girmez (yalnız sayı).

## Yapılacaklar

1. **Kaynak listesi (biçim × kaynak).** Ad, tip ya da ilişki taşıyabilen her kaynak. Başlangıç listesi (eksiksiz değil, genişlet):
   - Mach-O: `LC_SYMTAB` / `LC_DYSYMTAB` (yerel, dışa aktarım), dışa aktarım ağacı (`LC_DYLD_EXPORTS_TRIE` / `LC_DYLD_INFO`), zincirli düzeltme içe aktarımları, `LC_FUNCTION_STARTS`, `LC_MAIN` / `LC_UNIXTHREAD`, `LC_LOAD_DYLIB` / `LC_ID_DYLIB` (kitaplık kimliği ve sürümü), `LC_UUID`, `LC_BUILD_VERSION`, `LC_CODE_SIGNATURE` (kimlik, entitlements), Info.plist, `__unwind_info`, `__eh_frame`, ObjC (sınıf, yöntem, protokol, kategori, özellik, ivar, `selrefs`, `classrefs`), Swift (tip tanımlayıcıları, alan tanımlayıcıları, protokol uyumları, yansıma dizgileri, `__swift5_*`), Go (`__gopclntab`, `__go_buildinfo`, `typelinks` / `itablinks`), C++ RTTI ve vtable'lar, DWARF / dSYM (varsa), dizgi bölümleri (`__cstring`, `__objc_methname`).
   - ELF: `.symtab`, `.dynsym` (sürümlü semboller), build-id + `.gnu_debuglink` (ayrık `.debug`), `.eh_frame` / `.eh_frame_hdr`, `.gopclntab`, `.note.*`, `.comment` (derleyici), DWARF (`.debug_*`), C++ RTTI, Rust kalıntıları (panic konumları, dosya yolları).
   - PE: dışa / içe / gecikmeli içe aktarımlar, hata ayıklama dizini (PDB yolu ve GUID), MSVC RTTI, .NET üst veri tabloları (tip ve yöntem adları), kaynaklar (sürüm bilgisi, manifest), TLS geri çağrıları.
   - Ürünün ayrı hatları: JS (source map), Java (sınıf dosyaları), .NET, Python (bytecode) — bu hatlar adları okuyor mu, sınıf düzeyinde.
2. **Her kaynak için tablo satırı:** (a) hangi biçim / dilde bulunur; (b) **ürün bugün okuyor mu** — modül:satır kanıtıyla; okuyorsa ad hattına bağlı mı (evet / kısmen / hayır; `grep` ve kod okuması), bağlı değilse neden; (c) **hedef setinde kaç ad / tip taşıyor**: terminal-notifier, docker-cli, docker-compose, iTerm2, llama-server (`~/karadul_olcum/ustveri_set/`, soyulmuş kopya `bin`), Ollama dilimi (`~/karadul_olcum/runs/gosteri-2026-11-19/ollama/girdi/Ollama`), btop, Rectangle, colima (`$V/hedef/`, `$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri`) ve geliştirme setinden 3 ELF (`~/karadul_olcum/n1_debian13/` cat, tmux, sqlite3) — sayım betikle, kaynağıyla; (d) sahtecilik riski (zorunlu alan mı, serbest metin mi; ÜST VERİ BULGULAR'daki sınıflama); (e) önerilen paket: var olan plan paketi (P-ÜV1 …, PK-5, …) ya da YENİ paket önerisi (kısa tanım + tahmini emek S / M / L).
3. **Öncelikli açık listesi:** taşıdığı ad sayısı × hedef setinde yaygınlık × düşük sahtecilik riskine göre sıralı; ilk 10'un her biri için tek satırlık uygulama yolu.

## Sıra ve sert son

Önce **genişlik**: bütün kaynaklar için (a), (b), (d) — sayı yoksa "ölçülmedi". Sonra (c) sayımları hedef setinin Mach-O'larından başlayarak, büyük kaynaktan küçüğe. **15:15'te dur:** belge o anki hâliyle commit'li olsun; ölçülemeyen hücre "ölçülmedi" yazar (uydurma sayı YOK). Son satır `## PAKET BİTTİ` (yetişmezse "kalan" listesi ve BİTTİ yazmadan dön). Ara commit'ler en az 30 dakikada bir.
