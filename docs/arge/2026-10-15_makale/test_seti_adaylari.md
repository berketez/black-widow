# Karadul makalesi: test seti hazırlığı

Tarih: 2026-10-15 · Depo HEAD: `f893d72` · Seçim kararı: Berke

Bu belgede iki şey var:

1. Karadul'un bugüne kadar çalıştırıldığı ve sonucuna bakılan programların envanteri. Bunlar geliştirme setini oluşturur.
2. Geliştirme setinde olmayan 25 test seti adayı ve önerilen 15 programlık çekirdek liste.

Hiçbir aday üstünde Karadul çalıştırılmadı. İkili ya da kaynak kod indirilmedi, paket kurulmadı.

## 0. Yöntem ve kaynaklar

- **Envanter.** Şu yerler tarandı:
  - Depo: `tests/fixtures`, `tests/benchmark`, `scripts/`, `scripts/measurement/`, `docs/` (`arge`, `migrations`, `adr` dahil), `benchmarks/`, `workspaces/`, `docker/` ve kök dizindeki rapor dosyaları.
  - Hafıza notları ve `~/karadul_olcum/`.
  - Tarama sırasında bulunan ek yerler: `~/coreutils_gt/`, `~/karadul_meas/`, `~/karadul_coverage/`, `~/.cache/karadul/bsim/` (BSim dizini ve H2 veritabanı).
  - Bu oturumun scratchpad'i (`macho/`, `src/`).

  Hepsi yalnız okundu.
- **Homebrew.** `brew info --formula --json=v2` ile yalnız bilgi sorgulandı (2026-10-15).
- **Debian.** `api.ftp-master.debian.org/madison` üzerinden tek bir toplu sorgu yapıldı (`s=stable,stable-debug`, `a=arm64`). Debian 13 "trixie" şu an stable. Tablodaki bütün Debian sürümleri ve `-dbgsym` satırları bu sorgudan geliyor. packages.debian.org kullanılmadı.
- **Katalog yoklaması.** Her aday için 2-10 ayırt edici fonksiyon adı, Karadul'un 9,2 milyon girdilik LMDB `symbols` kataloğunda arandı (`LMDBSignatureDB(readonly=True).lookup_symbol`, `sigcov.py` ile aynı yöntem; LMDB'ye yazılmadı). Bu bir örneklemdir. "0/5" sonucu, programın ana iç fonksiyonlarının katalogda olmadığını gösterir; programın hiçbir adının katalogda olmadığını kanıtlamaz.
- **Boyutlar.** İkili indirilmediği için tahmindir (`≈`). Yalnız gpg ölçüldü: bu Mac'te kurulu, Homebrew şişesi 1.110.032 bayt.

## 1. Geliştirme seti envanteri

Kural, makale hedefi notundan geliyor: bir kez sonucuna bakılan program geliştirme setidir. Bu yüzden listede yalnız F1'i ölçülenler yok. Karadul'un üstünde koşturulup çıktısı incelenen her ikili var.

### 1.1 İsimlendirme ölçümü ve geliştirmesinde kullanılan C programları

| Program | Sürüm / platform | Ne için kullanıldı | Nerede geçiyor |
|---|---|---|---|
| GNU coreutils: cat, cut, wc, expr, comm | 9.4-3ubuntu6 (Ubuntu 24.04, LTO açık) ve 9.4-3 (Debian, LTO kapalı); Linux arm64 ELF | Fonksiyon-ismi F1 zemini (taban 2304560, aday f893d72); ARGE D1-D9 simülasyonu | `scripts/measurement/corpus.json`, `scripts/measurement/baseline_2304560.json`, `~/karadul_olcum/corpus/{ubuntu-9.4-3ubuntu6,debian-9.4-3}/`, `~/karadul_olcum/results/*.json`, `docs/arge/2026-09-25_lto_tani_ve_tasarim.md` |
| coreutils hold-out: head, tr, uniq, nl (Debian); head, tr (Ubuntu) | Aynı iki paket | ARGE kurallarının hold-out denemesi | `docs/arge/2026-09-25_lto_tani_ve_tasarim.md` §1 (çalışma dosyaları `/private/tmp/arge_lto/` altındaydı; kalıcı değil) |
| coreutils, 23 ikili: cat comm cp cut date du expr fmt fold head join ls mv nl od paste pr sort split stat tail tr wc | 9.4-3ubuntu6, arm64; `.stripped` + `.debug` + `.gt.txt` | Temmuz Mac-native F1 ölçümleri; gnulib parmak izi geliştirme (FIX-1/2/2b/4, disambiguation) | `~/coreutils_gt/`, `scripts/mac_f1_eval.py`, `scripts/mac_batch_measure.sh` (BINS: head cut tr expr wc date stat sort du mv cp), `~/karadul_meas/` (cat cut expr wc tr head sort stat date ls koşuları); hafıza `karadul-mac-native-olcum.md`, `karadul-denetim-2026-07-13.md` |
| coreutils-31 fixture: basename cat cmp cp cut date dirname echo env expr false head ls mkdir mv pwd readlink rm rmdir seq sleep sort stat tail tee test touch tr true uniq wc | Ubuntu 24.04 apt, aarch64 ELF (2026-05-10) | v1.15-A fixture; Mayıs benchmark'ı (cmp, test, echo, false); BSim lite dizini (cmp, echo, basename, cat, wc, cut, expr, comm, head, nl, tr); kapsam korpusu (cat, echo, basename) | `tests/fixtures/coreutils/{manifest.json,Dockerfile,binaries/stripped/}`, `BENCHMARK_2026_05_14.md`, `~/.cache/karadul/bsim/bsim_lite_index.json`, `~/karadul_coverage/corpus_manifest.jsonl` |
| coreutils `ls` (Docker duman testi) | Ubuntu 24.04 arm64 | Linux'taki ilk uçtan uca koşu (412 fonksiyon) | hafıza `karadul-docker-olcum-altyapisi.md` |
| tmux | 3.8, Homebrew, macOS arm64 (orijinal 1.185.984 B; strip'li kopya analiz edildi) | Mac gerçeklik ölçümü (isim bekleyen 1198 fonksiyon, P 0,07); tarif katmanının geliştirme hedefi; hafıza notuna göre BSim H2 DB'sinde kayıtlı (H2 dizgilerinde görülemedi) | scratchpad `macho/{orig,bin,runs}/tmux`, `macho/score_macho.py`, `src/tmux-dl/tmux-3.8.tar.gz`; hafıza `karadul-kullanilabilirlik-2026-10-14.md`, `karadul-makale-hedefi.md` |
| htop | 3.5.3, Homebrew, macOS arm64 (orijinal 268.064 B) | Mac gerçeklik ölçümü (53 isim, 0 doğru) | scratchpad `macho/{orig,bin,runs}/htop`; `~/.cache/karadul/bsim/karadul_bsim.mv.db` (exetable'da `htop`); hafıza `karadul-kullanilabilirlik-2026-10-14.md` |
| redis-server | Büyük olasılıkla Homebrew redis 8.10.2 (bu Mac'te kurulu). Sürüm doğrulanmadı | FLIRT bayt imzası FP ölçümü (162 isim, 0 doğru) | hafıza `karadul-flirt-bulgusu-2026-09-25.md`; `scripts/build_byte_signatures.py` başlık notu |
| libzstd | Büyük olasılıkla Homebrew zstd 1.5.7 (kurulu). Doğrulanmadı | FLIRT FP ölçümü (520/469). Ayrıca bayt imzalarının kaynağı | hafıza `karadul-flirt-bulgusu-2026-09-25.md`, `signatures_homebrew_bytes*.json` |
| jxl_from_tree (libjxl) | Büyük olasılıkla Homebrew jpeg-xl 0.12.0 (kurulu). Doğrulanmadı | FLIRT FP ölçümü (104/0) | hafıza `karadul-flirt-bulgusu-2026-09-25.md` |
| CalculiX ccx | 2.23, üçüncü taraf tap `costerwi/calculix` (Mac, ≈5 MB Mach-O); Ubuntu noble `calculix-ccx` + dbgsym (Linux arm64, GT 1033 fonksiyon) | İlk F1 denemesi (geçersiz çıktı); Docker ölçüm altyapısı; Fortran parametre DB'si | `workspaces/ccx_2/`, `docker/measurement/calculix/{ccx_stripped,ccx_debug}`, `docker/measurement/out/`; hafıza `karadul-olcum-bulgusu.md`, `karadul-docker-olcum-altyapisi.md`, `karadul-v135-durum.md` |
| varname_bench (hashbench): gnulib sha1, sha256, md5, crc + hashdriver | gnulib master `bb5bb43a`; Apple clang -O0 ve -O2, Mach-O arm64 | Değişken-adı F1 tabanı; çift döngü A/B ölçümü | `tests/fixtures/varname_bench/`, `scripts/varname_f1_eval.py`, scratchpad `varname/` |
| tree | 2.3.2 (Homebrew, Mach-O 111.256 B; içindeki dizgi "tree v2.3.2 … Steve Baker") | Haziran Mach-O denemeleri (strip'li iki kopya) | `workspaces/tree_real_macho/`, `workspaces/tree_strip2/` |
| sqlite3 CLI ve libsqlite3 | macOS sistem `/usr/bin/sqlite3` (universal, 4,69 MB); sistemden alınmış strip'li libsqlite3 dylib (1.270.336 B) | Nisan analizi; "sahte strip" bulgusu (F1=1,0 yapay çıkmıştı) | `workspaces/sqlite3/`, `benchmarks/stripped_baseline_2026_04_23.json`; hafıza `karadul-critical-findings-2026-04-23.md` |
| OpenSSL: openssl, libcrypto, libssl | Homebrew openssl@3 3.6.1 | Mart analizleri; Temmuz performans ölçümü (2319 fonksiyonlu ikili; hangi dosya olduğu doğrulanmadı) | `workspaces/openssl/`, `workspaces/openssl_normal/`; hafıza `karadul-2026-07-16-sprint.md` |
| macOS sistem araçları: `/usr/bin/true`, `/usr/bin/uname`, `/bin/echo`, `/bin/ls` | macOS (universal) | Kapsam ve sağlamlık denemeleri | `~/karadul_coverage/corpus_manifest.jsonl`, `workspaces/true/`, `workspaces/ls/`, `bsim_lite_index.json` (`uname_arm64`, `echo_arm64`) |

**Debian tarafındaki durum.** Bu programların Debian 13 derlemeleri hiç ölçülmedi. Yine de geliştirme setinde sayılırlar, çünkü kaynak kod aynı. Madison sorgusunun sonuçları:

| Program | Debian 13 sürümü | `-dbgsym` |
|---|---|---|
| tmux | 3.5a-3 | var |
| htop | 3.4.1-5 | var |
| tree | 2.2.1-1 | var |
| zstd | 1.5.7+dfsg-1 | var |
| sqlite3 | 3.46.1-7+deb13u2 | var |
| redis-server | 8.0.2 | yok |

### 1.2 C dışı programlar ve büyük kütüphaneler

Bu programlar test setine aday değil; liste eksiksiz olsun diye burada.

| Program | Platform / not | Nerede geçiyor |
|---|---|---|
| libz3 4.15.4 (C++) | Homebrew dylib; 26.611 fonksiyon | `workspaces/libz3.4.15.4.0/`, hafıza `karadul-v135-durum.md` |
| libfaiss (C++) | Homebrew dylib, 4,26 MB | `workspaces/libfaiss/` |
| libQuantLib.0 (C++) | 28 MB dylib, 918 sn | `workspaces/libQuantLib.0/`, hafıza `karadul-denetim-2026-07-13.md` |
| gh (Go), codex-cli (Rust) | Homebrew / Cask | `workspaces/gh/`, `scripts/batch-analyze.py` |
| Steam, Rectangle, Sublime Text, GlobalProtect, OpenRocket, LM Studio, Cursor 2.6.19, Claude masaüstü, Claude Code CLI | macOS uygulamaları (Obj-C, Swift, C++, JS) | `workspaces/*`, `workspaces/steam_analysis_*.json`, `workspaces/cursor_analysis_report.json`, `docs/vscode-dts-mapping-report.md` |
| Opera updateinstaller, crashreporter, crashinspector | macOS | BSim H2 DB (`karadul_bsim.mv.db`) |
| Discord, Codex.app, Element, Poe (Electron asar), Avast, Microsoft Excel | macOS. Hedef listelerinde geçiyor; koşulup koşulmadıkları doğrulanmadı | `scripts/batch-analyze.py`, `scripts/analyze-new-targets.py` |
| scapy (Python) | Anaconda | hafıza `karadul-v135-durum.md` |

### 1.3 Sentetik fixture'lar

Test setini etkilemezler.

- sample_macho: `tests/fixtures/sample_macho.c`, `tests/fixtures/golden/`
- hello: `tests/fixtures/diverse/hello.c` (arm64 ve x86_64)
- sample_elf: `tests/benchmark/fixtures/linux_elf_stripped/`
- richapp_O0 ve richapp_arm64: `workspaces/`
- Kapsam korpusu: prog.c, prog.cpp, prog.rs, Prog.swift, Prog.java (`~/karadul_coverage/src/`)
- BSim lite test adları: Helper, Multi, Engine, Tiny
- Testlerdeki PyInstaller, .NET, APK ve JVM örnekleri

### 1.4 Planda geçen, koşulduğuna kanıt bulunamayanlar

- **ffmpeg:** "M4 sonu: scapy, openssl, libz3, ffmpeg uçtan uca" (`karadul-v1100-plan.md`)
- **libxul, content_shell, libpng, libcrypto:** veri seti planı (`karadul-v1100-progress.md`, `karadul-v1120-roadmap.md`)
- **JavaScriptCore:** 30-40 MB hedef adayı (`BENCHMARK_2026_05_14.md`)

Bunların koşulduğuna dair kanıt bulunamadı. Yine de ffmpeg'i test setine almamak daha güvenli.

### 1.5 Dolaylı sızıntı: isim kataloğu nereden geldi

9,2 milyon girdilik katalog, export tablolarından hasat edildi. Kaynaklar:

- dyld önbelleği
- Homebrew `lib/` ve `Cellar/` altındaki `.dylib`, `.a` ve `.so` dosyaları (`scripts/gen_homebrew_sigs.py`, `scripts/mega-harvest-signatures.py`)
- `gen_homebrew_extra_sigs.py` ile bilerek kurulan paketler: boost, qt, opencv, ffmpeg, protobuf, grpc, vtk, cgal ve diğerleri
- Ubuntu `.so` dosyalarının `.dynsym` tabloları (`gen_ubuntu_sigs.py`)
- Anaconda, PyPI, Windows/Wine/MinGW, Rust ve GitHub FLIRT veritabanları

`.a` arşivleri statik olmayan bütün sembolleri taşır. Bu yüzden şu sonuç çıkıyor: bir adayın kodunun bir kısmı Homebrew'de ya da Ubuntu'da ayrı bir kütüphane olarak da dağıtılıyorsa, o kısmın adları büyük olasılıkla katalogdadır. §2.3'teki "Katalog" sütunu bunu örnekleyerek ölçüyor.

## 2. Test seti adayları

### 2.1 Seçim ölçütleri

Bu ölçütler sonuçlara bakmadan yazıldı ve kilit belgesine aynen taşınabilir.

1. **Dil.** Saf C. C++ programları ayrı tutulur (§2.5), çünkü ad karıştırma problemi değiştirir.
2. **Kaynak.** Kaynak kodu sürüm etiketli bir arşiv ya da etiket olarak erişilebilir olmalı.
3. **Gerçek isimler iki platformda.**
   - Linux: Debian 13 arm64 paketi ve aynı sürümün `-dbgsym` paketi. Bütün adaylarda madison ile doğrulandı.
   - macOS arm64: Homebrew şişesinin yerel sembolleri (tmux ve htop'ta kullanılan yöntem), yoksa etiketli kaynaktan `-g` ile derleme.
4. **Geliştirme setinde yok.** Karadul bu programlar üstünde hiç koşmadı (§1).
5. **Çeşitlilik.** Alan çeşitliliği olmalı. Boyut tabakaları: küçük <300 KB, orta 300 KB-2 MB, büyük >2 MB.
6. **İşaretler eleme sebebi değil.** Her aday için raporlanırlar. Çekirdek listede işaretli program en aza indirilir. İşaretli olanlar istenirse ayrı bir "stres" alt kümesi olur (§2.6).

### 2.2 Aday tablosu: kaynak ve gerçek isim bilgisi

Sürüm eşleşmesi Homebrew ile Debian 13 arasındadır: **aynı**, **yakın** (aynı küçük dal) ya da **farklı**. Lisans, Homebrew formülündeki SPDX ifadesidir. Homebrew kaynak URL'lerinin hepsi sürüm etiketli arşivlerdir.

| # | Program (ikili) | Alan | Boyut ≈ | Homebrew formülü · sürüm · kaynak | Debian 13 arm64 paketi · sürüm | `-dbgsym` | Sürüm eşleşmesi | Lisans |
|---|---|---|---|---|---|---|---|---|
| 1 | dash (`dash`) | kabuk | küçük, 0,1-0,2 MB | `dash-shell` 0.5.13.5 · `https://cdn.netbsd.org/pub/pkgsrc/distfiles/dash-0.5.13.5.tar.gz` | dash 0.5.12-12 | var | yakın | BSD-3-Clause |
| 2 | mawk | metin işleme | küçük, 0,15-0,25 MB | `mawk` 1.3.4-20260302 · `https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20260302.tgz` | mawk 1.3.4.20250131-1 | var | yakın | GPL-2.0-only |
| 3 | less | metin (sayfalayıcı) | küçük, ≈0,2 MB | `less` 710 · `https://www.greenwoodsoftware.com/less/less-710.tar.gz` | less 668-1 | var | farklı | GPL-3.0-or-later |
| 4 | unzip | sıkıştırma/arşiv | küçük, ≈0,2 MB | `unzip` 6.0 (keg-only) · `https://downloads.sourceforge.net/project/infozip/UnZip%206.x%20%28latest%29/UnZip%206.0/unzip60.tar.gz` | unzip 6.0-29+deb13u1 | var | aynı (Debian yamalı) | Info-ZIP |
| 5 | gifsicle | medya (GIF) | küçük, 0,2-0,3 MB | `gifsicle` 1.96 · `https://www.lcdf.org/gifsicle/gifsicle-1.96.tar.gz` | gifsicle 1.96-1 | var | aynı | GPL-2.0-only |
| 6 | dcraw | medya (RAW, sayısal) | küçük/orta, 0,3-0,4 MB | `dcraw` 9.28.0 · `https://dechifro.org/dcraw/archive/dcraw-9.28.0.tar.gz` | dcraw 9.28-8 | var | aynı | GPL-2.0-or-later |
| 7 | memcached | veritabanı (anahtar-değer önbellek) | küçük/orta, 0,2-0,5 MB | `memcached` 1.6.45 · `https://www.memcached.org/files/memcached-1.6.45.tar.gz` | memcached 1.6.38-1 | var | yakın | BSD-3-Clause |
| 8 | tcpdump | ağ | orta, 1-1,5 MB | `tcpdump` 4.99.7 · `https://www.tcpdump.org/release/tcpdump-4.99.7.tar.gz` | tcpdump 4.99.5-2 | var | yakın | BSD-3-Clause |
| 9 | OpenSSH (`ssh`) | kripto + ağ | orta, 0,8-1,2 MB | `openssh` 10.6p1 · `https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.6p1.tar.gz` | openssh-client 1:10.0p1-7+deb13u4 | var | farklı (aynı ana sürüm) | SSH-OpenSSH |
| 10 | GnuPG (`gpg`) | kripto | orta; Mac şişesi 1,11 MB (ölçüldü) | `gnupg` 2.5.24 · `https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.5.24.tar.bz2` | gpg 2.4.7-21+deb13u1+b5 | var (+b5 eşleşiyor) | farklı | GPL-3.0-or-later |
| 11 | rsync | sistem/ağ | orta, 0,5-0,7 MB | `rsync` 3.5.1 · `https://github.com/RsyncProject/rsync/releases/download/v3.5.1/rsync-3.5.1.tar.gz` | rsync 3.4.1+ds1-5+deb13u4 | var | farklı | GPL-3.0-or-later |
| 12 | lynx | ağ (metin tarayıcı) | orta/büyük, 1,5-2,5 MB | `lynx` 2.9.3 · `https://invisible-mirror.net/archives/lynx/tarballs/lynx2.9.3.tar.bz2` | lynx 2.9.2-1+b1 | var | yakın | GPL-2.0-only |
| 13 | vim | editör | büyük, 3-4 MB | `vim` 9.2.1150 · `https://github.com/vim/vim/archive/refs/tags/v9.2.1150.tar.gz` | vim ve vim-nox 2:9.1.1230-2 | var (ikisinde de) | farklı | Vim |
| 14 | git | sistem/geliştirme | büyük, 3-4 MB | `git` 2.56.0 · `https://mirrors.edge.kernel.org/pub/software/scm/git/git-2.56.0.tar.xz` | git 1:2.47.3-0+deb13u1 | var | farklı | GPL-2.0-only AND GPL-2.0-or-later AND LGPL-2.1-or-later AND BSD-3-Clause AND MIT |
| 15 | haproxy | ağ (yük dengeleyici) | büyük, 3-5 MB | `haproxy` 3.4.6 · `https://www.haproxy.org/download/3.4/src/haproxy-3.4.6.tar.gz` | haproxy 3.0.11-1+deb13u3 | var | farklı | GPL-2.0-or-later WITH openvpn-openssl-exception |
| 16 | pigz | sıkıştırma | küçük, 0,1-0,2 MB | `pigz` 2.8 · `https://zlib.net/pigz/pigz-2.8.tar.gz` | pigz 2.8-1+b1 | var | aynı | Zlib |
| 17 | the_silver_searcher (`ag`) | metin arama | küçük, ≈0,1 MB | `the_silver_searcher` 2.2.0 · `https://github.com/ggreer/the_silver_searcher/archive/refs/tags/2.2.0.tar.gz` | silversearcher-ag 2.2.0+git20200805-1.2 | var | aynı taban | Apache-2.0 |
| 18 | zsh | kabuk | orta, 0,8-1 MB + `.so` modülleri | `zsh` 5.9.2 · `https://downloads.sourceforge.net/project/zsh/zsh/5.9.2/zsh-5.9.2.tar.xz` | zsh 5.9-8+b24 | var (+b24 eşleşiyor) | yakın | MIT-Modern-Variant AND GPL-2.0-only AND GPL-2.0-or-later AND ISC |
| 19 | nasm | geliştirme (assembler) | orta, 1-1,5 MB | `nasm` 3.02 · `https://www.nasm.us/pub/nasm/releasebuilds/3.02/nasm-3.02.tar.xz` | nasm 2.16.03-1 | var | farklı | BSD-2-Clause |
| 20 | cmus | medya (ses çalar) | orta, 0,4-0,6 MB + eklentiler | `cmus` 2.12.0 · `https://github.com/cmus/cmus/archive/refs/tags/v2.12.0.tar.gz` | cmus 2.12.0-1 | var | aynı | GPL-2.0-or-later |
| 21 | dnsmasq | ağ (DNS/DHCP) | orta, 0,4-0,6 MB | `dnsmasq` 2.93 · `https://thekelleys.org.uk/dnsmasq/dnsmasq-2.93.tar.gz` | dnsmasq-base 2.91-1+deb13u2 | var | yakın | GPL-2.0-only OR GPL-3.0-only |
| 22 | wget | ağ | orta, ≈0,5 MB | `wget` 1.25.0 · `https://ftpmirror.gnu.org/wget/wget-1.25.0.tar.gz` | wget 1.25.0-2 | var | aynı | GPL-3.0-or-later |
| 23 | nano | editör | küçük/orta, ≈0,3 MB | `nano` 9.2 · `https://www.nano-editor.org/dist/v9/nano-9.2.tar.xz` | nano 8.4-1+deb13u1 | var | farklı | GPL-3.0-or-later |
| 24 | screen | sistem (terminal çoklayıcı) | orta, ≈0,5 MB | `screen` 5.0.2 · `https://ftpmirror.gnu.org/screen/screen-5.0.2.tar.gz` | screen 4.9.1-3 | var | farklı | GPL-3.0-or-later |
| 25 | lua | dil yorumlayıcısı | küçük, 0,2-0,3 MB | `lua` 5.5.1 · `https://www.lua.org/ftp/lua-5.5.1.tar.gz` | lua5.4 5.4.7-1+b2 | var | farklı (5.4 ile 5.5) | MIT |

### 2.3 Aday tablosu: işaretler ve gerekçe

Sütunların anlamı:

- **gnulib:** program gnulib kullanıyor; coreutils parmak izleriyle örtüşür.
- **Kütüphane ikizi:** programın içine gömülü kodun adları ayrı dağıtılan bir kütüphanede de var.
- **Yakın:** program geliştirme setine yakın.
- **Katalog:** yoklanan adlardan kaçının 9,2M katalogda bulunduğu. Katalogda kayıtlı kütüphane adı okla gösterildi. Paylaşımlı kütüphaneden ithal edilen API adları (ör. `gcry_md_open`) sayılmadı, çünkü bunlar ikilide zaten adıyla görünür.

| # | Program | gnulib | Kütüphane ikizi | Yakın | Katalog | Gerekçe / not |
|---|---|---|---|---|---|---|
| 1 | dash | yok | yok | yok | 0/5 (evaltree, parsecmd, expandarg, evalcommand, setvarsafe) | Tek ikili, bağımlılığı yok. Homebrew'de formül adı `dash-shell`. |
| 2 | mawk | yok | yok | yok | 0/4 | Thomas Dickey'nin awk'ı; kod tabanı GNU gawk'tan bağımsız. |
| 3 | less | yok | yok | yok | 0/5 | Homebrew'de pcre2'ye dinamik bağlı; regex kodu ikilinin içinde değil. |
| 4 | unzip | yok | yok | yok | 1/10 (yalnız jenerik `crc32` → DriverKit) | Info-ZIP'in kendi inflate kodu gömülü ama ayrı kütüphane olarak dağıtılmıyor; inflate_* adları katalogda yok. Debian revizyonu 29, paket yamalı. |
| 5 | gifsicle | yok | yok | yok | 0/4 | İç `Gif_*` kütüphanesi gömülü ama ayrıca dağıtılmıyor. |
| 6 | dcraw | yok | yok | yok | 0/4 | Tek dosyalık sayısal C (demozaik, renk). Karadul'un "hesaplamayla isim" iddiasını sınar. |
| 7 | memcached | yok | yok | hafif: redis'le aynı alan (bellek içi anahtar-değer), ortak kod yok | 1/5 (`conn_new` → openssl) | Veritabanı alanında işaretsiz kalan tek aday: sqlite ve redis geliştirme setinde, valkey de redis çatalı. Ad çakışması, yanlış kütüphane etiketi riskini de ölçer. |
| 8 | tcpdump | yok | yok | yok | 0/5 | libpcap dinamik bağlı. Yüzlerce `*_print` ayrıştırıcısı var; isimlendirme için zengin. |
| 9 | OpenSSH `ssh` | yok | kısmi: openbsd-compat'taki `bcrypt_pbkdf` katalogda | yok | 2/5 iç ad (`channel_new` → ssh, `bcrypt_pbkdf` → bcrypt); `arc4random_buf` libc'den ithal | Paket birçok ikili içeriyor; ölçülecek ikili `ssh` olarak sabitlenmeli. |
| 10 | GnuPG `gpg` | yok | yok (libgcrypt ve libassuan dinamik bağlı, gömülü değil) | yok | 0/3 | Mac şişesinde yerel semboller doğrulandı: `nm` 681 `t`, 1196 `T`. Sürüm farkı büyük (2.4 ile 2.5). |
| 11 | rsync | yok | yok (xxhash, popt, zstd dinamik bağlı) | yok | 0/4 iç ad | Debian'ın `+ds` paketi gömülü kütüphaneleri çıkarıyor. |
| 12 | lynx | yok | yok (libwww'den gelen `HT*` kodu gömülü ama katalogda yok) | yok | 0/5 | Büyük tabakanın sınırında. |
| 13 | vim | yok | yok | yok | 0/5 | Homebrew vim lua, python ve ruby ile derleniyor. Debian'da buna en yakın eş `vim-nox` (`vim.nox`). |
| 14 | git | yok | yok (xdiff gömülü, katalogda yok) | yok | 0/5 | Tek ikilide çok sayıda builtin var. Homebrew'ün derleme bağımlılıklarında rust yok (2026-10-15). |
| 15 | haproxy | yok | yok (ebtree gömülü, katalogda yok) | yok | 0/5 | Büyük; bağımlılığı az. |
| 16 | pigz | yok | **kısmi: gömülü zopfli** (`ZopfliCompress`, `ZopfliDeflate`, `ZopfliInitOptions` → zopfli) | yok | 3/5 (yalnız zopfli adları) | Bu işaret yüzünden çekirdekte yerini unzip aldı. |
| 17 | ag | yok | yok | yok | 0/5 | pcre2 dinamik bağlı. |
| 18 | zsh | yok | yok | yok | 0/5 | Çekirdek ikilinin yanında ayrı `.so` modülleri var (zle vb.). Ölçüm biriminin önceden tanımlanması gerekir. |
| 19 | nasm | yok | yok | yok | 1/4 (`parse_line` → libedit, tesadüfi çakışma) | Sürüm farkı 2.16 ile 3.02. |
| 20 | cmus | yok | yok | hafif: ncurses TUI | 0/5 | Giriş ve çıkış eklentileri ayrı `.so` dosyaları. |
| 21 | dnsmasq | yok | yok | yok | 0/2 | Linux'ta netlink, macOS'ta BSD yolu kullanıyor; iki platformda fonksiyon kümesi farklı. |
| 22 | wget | **var** | yok | gnulib üzerinden coreutils'e yakın | 0/3 | Stres adayı. Ana sayılara karışmamalı. Gnulib modül örtüşmesinin derecesi doğrulanmadı. |
| 23 | nano | **var** | yok | yok | 0/2 | wget ile aynı durum. |
| 24 | screen | yok (doğrulanmadı) | yok | **var: tmux benzeri** | 1/2 (`ProcessInput` → user32, çakışma) | Görevde örnek verilen yakın program. |
| 25 | lua | yok | **var: liblua** (`luaV_execute`, `lua_pushnumber`, `luaL_newstate` katalogda) | yok | 3/3 | Debian'da `lua5.4` liblua5.4'e dinamik bağlı olabilir; o durumda ikili incedir (doğrulanmadı). Stres adayı. |

### 2.4 Değerlendirilip tabloya alınmayanlar

**a) İşaret nedeniyle elenenler.** Debian `-dbgsym` aksi yazılmadıkça var.

| Program | Homebrew / Debian 13 sürümü | Elenme nedeni |
|---|---|---|
| jq | 1.8.2 / 1.7.1-6+deb13u3 | Katalog 2/2 (`jv_parse`, `jq_compile` → jq). İkili büyük olasılıkla libjq'ya dinamik bağlı, yani kod ve dışa açık adlar kütüphanede (doğrulanmadı). |
| xz | 5.8.4 / xz-utils 5.8.1-1+deb13u1 | Katalog 2/2 (liblzma). Bu Mac'teki şişede `xz` ikilisinde yalnız 1 global ve 131 yerel sembol var; kod liblzma'da. |
| mupdf (`mutool`) | 1.28.5 / mupdf-tools 1.25.1+ds1-6+deb13u1 | Katalog 2/2 (`fz_open_document`, `pdf_load_object` → PyMuPDF). |
| curl | 8.22.0 (keg-only) / 8.14.1-2+deb13u5 | libcurl API'si katalogda; bu beklenen bir durum, çünkü API ithal ediliyor. Araç kodu (`tool_write_cb`, `getparameter`) katalogda yok. Aday olabilir; ama libcurl'den ikiliye derlenen `curlx_*` yardımcıları ikiz riski taşır (doğrulanmadı). |
| bash | 5.3 / 5.2.37-2+b10 | `rl_insert` katalogda (editline). Homebrew bash readline'a dinamik bağlı; Debian'da readline gömülü olabilir (doğrulanmadı). Bu iki platform arasında asimetri yaratır. |
| grep | 3.12 / 3.11-4+b1 | gnulib: coreutils ile aynı modül ailesi. En güçlü gnulib örtüşmesi. |
| gawk | 5.4.1 / 1:5.2.1-2+b2 | gnulib modüllerini kısmen içeriyor (dfa, regex); doğrulanmadı. |
| valkey | 9.1.2 / valkey-server 8.1.1+dfsg1-3+deb13u2 | redis çatalı. Debian stable-debug'da `valkey-server-dbgsym` **yok**. |
| neovim | 0.12.6 / 0.10.4-8 | vim'in çatalı; vim ile birlikte alınmamalı. Tek başına büyük bir yedek olabilir. |
| mg | 7.3 (ibara portu) / 20240709-1+b1 | İki platformda aynı programın farklı portları. |

**b) Temiz yedek havuz.** Hepsinde Debian `-dbgsym` var ve katalog yoklaması 0/2. Sürümler Homebrew / Debian 13 sırasıyla:

| Program | Homebrew | Debian 13 | Not |
|---|---|---|---|
| socat | 1.8.1.3 | 1.8.0.3-1+deb13u1 | |
| stunnel | 5.82 | stunnel4 3:5.74-2 | |
| openvpn | 2.7.8 | 2.6.14-1+deb13u3 | |
| nginx | 1.31.6 | 1.26.3-3+deb13u7 | |
| lighttpd | 1.4.85 | 1.4.79-2 | |
| privoxy | 4.2.0 | 4.0.0-2 | |
| masscan | 1.3.2 | 2:1.3.2+ds1-2 | |
| mutt | 2.4.3 | 2.2.13-1+deb13u1 | |
| irssi | 1.4.5 | 1.4.5-1+b5 | |
| w3m | 0.5.6 | 0.5.3+git20230121-2.1 | |
| tig | 2.6.1 | 2.5.8-1+b2 | |
| mc | 4.8.33 | 3:4.8.33-1+deb13u1 | |
| pv | 1.12.0 | 1.9.31-1 | |
| jhead | 3.08 | 1:3.08-3 | |
| mtr | 0.96 | 0.95-1.1+b2 | ncurses canlı tablo; arayüz olarak htop'a yakın |
| wireguard-tools | 1.0.20260223 | 1.0.20210914-3 | 4,5 yıllık sürüm farkı |
| universal-ctags | 6.2.1 | 5.9.20210829.0-2 | Büyük sürüm farkı |
| gnuplot | 6.0.5 | gnuplot-nox 6.0.2+dfsg1-1 | Bilimsel alan için yedek. Homebrew derlemesi Qt terminali yüzünden C++ kod içerebilir (doğrulanmadı); Debian `-nox` saf C. |

### 2.5 C++ adayları

Bunlar için Homebrew ve Debian bilgisi doğrulanmadı: nmap, mosh, aria2, btop, qpdf, poppler-utils, 7-Zip, exiv2, ninja, groff.

C++'ta ad karıştırma çözülünce isimle birlikte parametre tipleri de gelir. Bu yüzden C++ alt kümesi seçilirse iki şey ayrıca tanımlanmalı:

- Gerçek isim kuralı: tam demangled ad mı, yalnız temel ad mı sayılacak.
- Puanlama kuralı.

Bu programlar C sayılarıyla aynı tabloda raporlanmamalı.

### 2.6 Önerilen 15 programlık çekirdek liste

| # | Program (ölçülecek ikili) | Alan | Boyut ≈ | Sürüm eşleşmesi | İşaret |
|---|---|---|---|---|---|
| 1 | dash (`dash`) | kabuk | küçük | yakın | yok |
| 2 | mawk (`mawk`) | metin işleme | küçük | yakın | yok |
| 3 | less (`less`) | metin / sistem | küçük | farklı | yok |
| 4 | unzip (`unzip`) | sıkıştırma/arşiv | küçük | aynı | jenerik `crc32` çakışması |
| 5 | gifsicle (`gifsicle`) | medya | küçük | aynı | yok |
| 6 | dcraw (`dcraw`) | medya / sayısal | küçük-orta | aynı | yok |
| 7 | memcached (`memcached`) | veritabanı | küçük-orta | yakın | hafif alan yakınlığı (redis); `conn_new` çakışması |
| 8 | tcpdump (`tcpdump`) | ağ | orta | yakın | yok |
| 9 | OpenSSH (`ssh`) | kripto + ağ | orta | farklı | kısmi: `bcrypt_pbkdf`; `channel_new` çakışması |
| 10 | GnuPG (`gpg`) | kripto | orta | farklı | yok |
| 11 | rsync (`rsync`) | sistem/ağ | orta | farklı | yok |
| 12 | lynx (`lynx`) | ağ / metin tarayıcı | orta-büyük | yakın | yok |
| 13 | vim (Debian'da `vim.nox`) | editör | büyük | farklı | yok |
| 14 | git (`git`) | sistem/geliştirme | büyük | farklı | yok |
| 15 | haproxy (`haproxy`) | ağ | büyük | farklı | yok |

**Dağılım.**

- **Alan:** dokuz alanın hepsi temsil ediliyor.
  - Ağ: tcpdump, lynx, haproxy
  - Kripto: ssh, gpg
  - Sıkıştırma: unzip
  - Veritabanı: memcached
  - Editör: vim
  - Kabuk: dash
  - Metin işleme: mawk, less
  - Medya: gifsicle, dcraw
  - Sistem: rsync, git
- **Boyut:** küçük 5, küçük-orta 2, orta 4, orta-büyük 1, büyük 3.
- **İşaret:** gnulib 0, güçlü kütüphane ikizi 0, ad çakışması ya da kısmi ikiz 3.

**Stres alt kümesi (isteğe bağlı).** Programlar: wget (gnulib), lua (kütüphane ikizi), pigz (gömülü zopfli), screen (tmux'a yakın). Bu küme ayrı kilitlenir ve ana sayılara karıştırılmaz. Hakemin "katalog ve gnulib etkisi ne kadar?" sorusunu doğrudan yanıtlar.

**Kilitleme notları.**

1. **Debian'ı birebir sabitle.** Paket ve `-dbgsym` sürümleri binNMU ekiyle birlikte sabitlenmeli. Stable-debug'da birden çok yeniden derleme duruyor:
   - gpg-dbgsym: +b1…+b5
   - zsh-dbgsym: +b14…+b24
   - bash-dbgsym: +b5…+b10

   İkiliyle aynı eki taşıyan dbgsym alınmalı. Her paket için sha256 ve BuildID `scripts/measurement/corpus.json` biçiminde kaydedilmeli. Kalıcılık için snapshot.debian.org URL'leri kullanılmalı.
2. **Homebrew'i sabitle.** Homebrew sürümleri ilerler; tablodakiler 2026-10-15 tarihli. Kilitleme günü şişe sha256'sı kaydedilmeli ya da etiketli kaynaktan `-g` ile derlenmeli.
   - Şişede yerel sembol varsa tmux/htop yöntemi kullanılır: gerçek isimler orijinal ikilinin `nm` çıktısından alınır, analiz strip'li kopyada yapılır. Bu yalnız gpg'de doğrulandı.
   - Mach-O export trie'sinden görünen adlar puanlamadan çıkarılmalı. Bu, Debian tarafındaki `.dynsym` kuralının karşılığı.
3. **Sürüm farkı.** Homebrew çoğu zaman daha yeni. İki platformda aynı kaynak isteniyorsa Debian sürümünün etiketi Mac'te `-g` ile derlenir.
4. **LTO.** Geliştirme setinde LTO'nun sonucu büyük ölçüde değiştirdiği görüldü (Ubuntu F1 0,48, Debian 0,12). Debian paketleri genellikle LTO'suz derleniyor; Ubuntu'da `dpkg-buildflags` ile LTO varsayılan olarak açık. Bu her paket için ayrı doğrulanmadı. Ubuntu derlemeleri de eklenecekse ayrı bir koşul olarak raporlanmalı.
5. **Seçim yanlılığı.** Bu çekirdeği elle ben önerdim. Hakem itirazına karşı daha savunulabilir bir yol var: 25'lik havuzdan alan×boyut tabakalı kura çekilir ve kuranın tohumu belgeye yazılır.
6. **LLM ezber riski.** Makale LLM kıyası içerecek. vim, git ve OpenSSH gibi çok bilinen programlarda LLM tabanı ezberle şişebilir; expr.c dersinde bu görüldü. gifsicle, dcraw, mawk ve memcached gibi daha az bilinen programlar bu riski dengeler. İki grup ayrı raporlanabilir.

### 2.7 Sınırlamalar

- Boyutlar tahmin; yalnız gpg ölçüldü.
- Katalog yoklaması örnekleme: program başına 2-10 ad sorgulandı.
- wget ve nano'nun gnulib kullandığı bilgisi kaynaktan doğrulanmadı.
- Şunlar da doğrulanmadı: Debian bash'te readline'ın gömülü olup olmadığı, Debian `lua5.4` ikilisinin liblua'ya bağlı olup olmadığı, Homebrew gnuplot'taki C++ payı.
- Homebrew şişelerinde yerel sembol bulunduğu yalnız gpg'de doğrulandı. Geliştirme setindeki tmux ve htop da aynı durumdaydı.
- Madison sorgusu 2026-10-15'te yapıldı. Point release'lerle (`+deb13uN`) sürümler değişebilir.
