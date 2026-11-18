# Karadul onarımı — durum (2026-11-18'den itibaren)

İş emri: `docs/arge/2026-11-18_genel_tarama/RAPOR.md` (§5 plan). Ortak brif: `ONARIM_BRIF.md`.
Bu dosya yaşayan durum kaydıdır: hangi paket kimde, ne birleşti, hangi karar verildi. Oturum yarıda kalırsa buradan sürdürülür.

## Kurallar (bu oturum, Berke)
- Aynı anda en çok **5** Opus ajanı (Berke, 2026-11-18 onarım oturumu; tarama oturumundaki sınır 4'tü).
- Her ajan kendi git worktree'sinde (`.claude/worktrees/agent-*`, taban e9d2d08); dosya kümeleri ayrık. Ana oturum ajan commit'lerini doğrulayıp `main`'e alır (cherry-pick).
- Push her seferinde Berke'ye sorulur. Güvenlik bulgularını içeren rapor, güvenlik onarımları `main`'e girmeden push edilmez (K-7).

## Kararlar
| No | Karar | Kaynak |
|---|---|---|
| K-1 | **Beklet:** onarımı uzun sürecek katmanlar (bileşim şablonları, yapı kurtarma, hesaplama kolları) koşar, ama onarılıp masum ikili kapısından geçene kadar iddiaları rapora ve koda yazılmaz. Silme ya da kalıcı kapatma değil. | Berke, 2026-11-18 |
| K-2 | **Susturma yok, düzelt:** `kebap_ad` ve `api_param_reverse` ad üretmeye devam eder; hesaplamayla özgün ada yakın ve doğru ad üretecek biçimde onarılır (P12, ön kayıtlı ölçümle). Berke'nin sözü: "amacımız isim üretmek; düzelt, yakın ve doğru isim üretmek hesaplama ile". | Berke, 2026-11-18 |
| K-3 | Yön kabul: A türü (hiç çalışmayan kopyalar) silinir, B türü (bağlanmamış özellikler) bağlanır. Her silme kalemi paket başında "çağıran yok" kanıtıyla tek tek onaya sunulur. | Berke, 2026-11-18 (tarama oturumu) + "çöp kodları da sileceğiz" (onarım oturumu) |
| K-4 | K-3'ün B türünden çıkıyor: PDB / DWARF / Binary Ninja / TRex / Rust-Go / RTTI kanalları bağlanır; ad üretenler bayrak arkasında ve ölçülerek açılır. | K-3'ten |
| K-5 | **Uygulamaya gömülü:** yeniden kurulan imza veritabanı (yalnız tanımlanan/dışa aktarılan simgeler + ad başına kitaplık listesi) uygulama paketine gömülür. | Berke, 2026-11-18 |
| K-6 | Açık (güncelleme sorgusu; P17'den önce sorulacak). | — |
| K-7 | Rapor yerelde commit'lendi (5e49dd0); push güvenlik onarımlarından sonra. | öneri, uygulandı |
| K-8 | **Evet:** native olmayan hatlar için örnek seti. Liste onaylandı ve indirildi (11 dosya, ~199 MB): `~/karadul_olcum/dogrulama_native/` (`MANIFEST.json`: kaynak, boyut, sha256). JAR ×2, APK ×2 (F-Droid), .NET nupkg ×2, PyInstaller ×2 (yt-dlp Mach-O + PE), ASAR ×1 + Electron Fiddle 0.39.0, wheel ×1. Analiz girdisi; hiçbiri çalıştırılmaz. jadx / ilspycmd / dotnet kurulu değil. | Berke, 2026-11-18 |
| K-9 | Açık: `~/karadul_olcum/runs/genel-tarama-2026-11-18` (2,0 GB) P00 tabanı alınana kadar kalır; silme onaya bağlı. | — |

## Paketler
Plan dışı yeni paket: **P-GÜV** (hedef çalıştırma ve ağ güvenliği: GHIDRA-07, 11, 13, MEK-03). RAPOR'da P15 / P16 / P-S / P20'ye dağılmış güvenlik kalemleri, raporun yayımlanabilmesi için öne alındı. Bu kalemler o paketlerin kapsamından düşer.

| Paket | Konu | Durum | Not |
|---|---|---|---|
| P00 | Ölçüm zemini (masum ikili kapısı + sağlamlık denetimi) | çalışıyor (1. tur) | |
| P19 | Native olmayan hatlar: güvenlik ve tanıma | çalışıyor (1. tur) | |
| P-GÜV | Hedef çalıştırma ve ağ güvenliği | **main'de** (e8dfbda..ecf8175 + yama 86d0bf4) | 4/4 kalem; ajan: tam takım 8 271 geçti (4 kırmızı node_modules eksikliği, symlink'le geçti), mutant 34/34. Ana oturum: ilgili 175 test main'de geçti; uygulamanın gerçek `karadul.yaml`'ı katı bool ile yükleniyor. **P15'e kalan:** `--enable-network` / arayüz ağ düğmesi `allow_dts_fetch`'i açmıyor (artık `.d.ts` için iki bayrak gerekiyor; karar P15'te), `timeouts.frida_spawn_wait` ve `network.allow_source_match` okunmuyor. Bilinçli değişiklik: kaynak eşleme (Layer 1.5) artık `network.enabled` da istiyor. `TestFridaRealSpawn` gerçek süreç başlattığı için koşulmadı. |
| P01 | İkili istihbarat | **main'de** (bddd945..a60dbbf) | IMZA-01: geliştirme setinde toplam iddia 2 267 → 646; Bluetooth / OpenGL 119 → 0, Browser Engine 114 → 0; gerçek pozitif 34 beklentinin 33'ü korundu (endpointsecurityd kernel iddiası bilinçli düştü). Ajan: 14/14 mutant, tam takım 8 312 / 0. Ana oturum: BI testleri main'de 69 / 0. Bağımsız masum kapı (P00 aracı, main a60dbbf): bi yanlış (üst sınır) geliştirme 2 102 → 490, macos 701 → 242, pe 203 → 25; Bluetooth / OpenGL / kernel 0. **Kapı DÜŞTÜ:** zorunlu gerçek pozitif `antidebug_x86_64` → `guvenlik:Anti-Debugging` kayboldu (P01'in kendi pozitif setinde yoktu) → P01b kalem 0. **Devam P01b:** (1) conda `strings`/`nm` arm64e Mach-O'da çıkış 1 → `run_strings` her şeyi atıyor (ana oturum doğruladı: bluetoothd'de conda 41 889 satır basıp 1 dönüyor, `/usr/bin/strings` 42 153); (2) kalıntı alt sistem iddiaları (Version Control, Testing Framework, Terminal Emulator, Licensing); (3) `_VULNERABILITY_PATTERNS` iki kanıt kuralı dışında; (4) başarım 75 s → 228 s (196 ikili). P15'e: `hacker_cli.py:351-400` ölü (anahtarlar `architecture` altında). P07'ye: yeni `evidence_kinds` alanı. |
| P02 | Anti-debug + paketleyici | çalışıyor (1. tur) | |
| P03 | YARA + capa | çalışıyor (2. tur) | |
| P06 | Algoritma + güvenlik etiketleri | çalışıyor (2. tur) | |
| P09, P04a, P01b, P-S1, P08 | sıradakiler | bekliyor | P09 (K-1 bekletme) → P04a (P00'dan sonra) → P01b → P-S1 (P03'ten sonra) |
