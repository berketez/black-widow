# Doğrulama seti ön kaydının kanıtları

- **Ait olduğu belge:** `docs/arge/dogrulama_seti_onkayit.md` (plan v2 G5).
- **Ait olduğu betik:** `scripts/measurement/dogrulama_seti_kura.py`.
- **Tarih:** 2026-10-19.
- **Kapsam:** Hiçbir ikili indirilmedi, hiçbir paket kurulmadı. Bütün ağ sorguları salt okumaydı.
- **Depo dışında kalanlar:** Ham dizin dosyaları çok megabaytlık olduğu için depoya konmadı (Packages, Contents, Homebrew API önbelleği). Aynı dosyalar aşağıdaki adreslerden yeniden alınabilir; sha256'ları bu belgede.

## Dosyalar

| Dosya | İçerik |
|---|---|
| `pool_data.json` | Havuzdaki 68 adayın kanıt kaydı. Anahtar, betikteki `VALIDATION_POOL` adıdır |
| `isaretli_data.json` | İşaretli listedeki 13 programın kanıt kaydı. Anahtar, betikteki `FLAGGED` adıdır |

`tests/test_dogrulama_seti_kura.py`, bu iki dosyanın betikle tutarlı olduğunu denetler: ad kümesi, alan, aile, vekil ve tabaka.

**Alanlar:**

| Alan | Anlamı |
|---|---|
| `alan`, `aile` | Ön kayıt §4.2'deki alan ve aile etiketi (yalnız havuz) |
| `isaret` | Havuzda: işaretler listesi. İşaretli listede: neden işaretlendiği |
| `not` | Havuzdaki adayın notu |
| `vekil_kib` | Debian `-dbgsym` paketinin `Installed-Size` değeri (KiB) |
| `elf` | dbgsym paketinin `Build-Ids` alanındaki BuildID sayısı, yani paketteki ELF sayısı |
| `tabaka` | `vekil_kib`'den ön kayıt §4.1'deki eşiklerle hesaplanan tabaka |
| `brew`, `brew_surum`, `rebuild` | Homebrew formülü, sürüm (`_revizyon` dahil), şişe rebuild numarası |
| `sise_sha256` | `arm64_tahoe` şişesinin sha256'sı (API'deki değer; GHCR dizinindeki özetle eşleşti) |
| `brew_kurulu_boyut` | GHCR dizinindeki `sh.brew.bottle.installed_size` (bayt) |
| `deb`, `deb_surum` | Ölçülecek ikiliyi taşıyan Debian paketi ve sürümü |
| `dbgsym`, `dbgsym_surum` | Aynı sürümün `-dbgsym` paketi (her kayıtta `dbgsym_surum = deb_surum`) |
| `kaynak` | Debian kaynak paketi |
| `mac_ikili`, `deb_ikili` | Ölçülecek ikili. Debian yolu `Contents-arm64`'te denetlendi; Mac yolu 2. aşamada denetlenir |
| `eslesme` | Homebrew ile Debian upstream sürümü: aynı / yakın (ilk iki bileşen eşit) / farklı |

## Kaynaklar, adresler, tarihler

### Homebrew

- **Komut:** `brew info --json=v2 <formül...>`, `HOMEBREW_NO_AUTO_UPDATE=1` ile, yerel API önbelleğinden.
- **Homebrew sürümü:** 7.0.9-135-gaac1fb8.
- **Önbellek dosyası:** `~/Library/Caches/Homebrew/api/internal/packages.arm64_tahoe.jws.json`.
  - 15 717 617 B;
  - sha256 `53794de6056a4927502e23549bafaf0d40a482e649f279c04ecd22073bdb3dec`;
  - `generated_at` 2026-10-17 11:40:38 UTC;
  - dosya zamanı 2026-10-17 15:03 (yerel saat).
  - Sorgulardan sonra dosya değişmedi.

### GHCR şişe dizinleri

- **Ne alındı:** yalnız JSON dizini; şişe indirilmedi.
- **Adres:** `https://ghcr.io/v2/homebrew/core/<formül>/manifests/<sürüm>[_<revizyon>][-<rebuild>]`.
  - Formül adındaki `@`, yolda `/` olur (ör. `php/8.4`).
  - Başlıklar: `Authorization: Bearer QQ==` (Homebrew'un anonim belirteci) ve `Accept: application/vnd.oci.image.index.v1+json`.
- **Okunan alanlar:** `org.opencontainers.image.ref.name`, `sh.brew.bottle.digest`, `sh.brew.bottle.installed_size`, `sh.brew.tab` içindeki `linkage_files`.
- **Tarih:** 2026-10-19, 09:20-09:58 UTC.
- **Sonuç:** 68 havuz ve 13 işaretli formülün `arm64_tahoe` özeti API'deki sha256 ile eşleşti.

### Debian (deb.debian.org)

**Sorgu:** 2026-10-19, 08:47:53 UTC (Contents: 09:13 UTC). Sürüm 13.7, InRelease tarihi `Sat, 12 Sep 2026 07:55:41 UTC`.

| Dosya | Adres | Boyut (B) | sha256 |
|---|---|---|---|
| trixie InRelease | `https://deb.debian.org/debian/dists/trixie/InRelease` | 140 421 | `0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675` |
| trixie-debug InRelease | `https://deb.debian.org/debian-debug/dists/trixie-debug/InRelease` | 45 194 | `2fa356a75cf39ddf11f1ee0e2c7fcefe39852c30540da7e2236cde40120a8a57` |
| Packages (main, arm64) | `https://deb.debian.org/debian/dists/trixie/main/binary-arm64/Packages.xz` | 9 614 192 | `be16b37b2f740f066ea93d35d56f04f94d63693e5a3eb421b052bf86fae75bcd` |
| Packages (debug, arm64) | `https://deb.debian.org/debian-debug/dists/trixie-debug/main/binary-arm64/Packages.xz` | 3 689 184 | `ff6185861c668d9038f36fd826a14fd13a05d039d74b2ef9b59fd63ad38a1560` |
| Contents (main, arm64) | `https://deb.debian.org/debian/dists/trixie/main/Contents-arm64.gz` | 12 639 045 | `276dbed691664effd4be91435f7e0d1552f0ab645c0aa0397de9ba5900e13b74` |

- Packages ve Contents dosyalarının sha256'sı InRelease'teki değerle aynı.
- InRelease'in GPG imzası doğrulanmadı.
- 13.8 ara sürümünden sonra aynı durum `snapshot.debian.org` üzerinden alınabilir.

### sources.debian.org

- **Ne alındı:** yalnız dizin listeleri; dosya içeriği okunmadı.
- **Adres:** `https://sources.debian.org/api/src/<kaynak>/<sürüm>/<dizin>/`.
- **Tarih:** 2026-10-19, 09:09-09:50 UTC.
- **Ne için:**
  - gnulib işaretleri: `m4/` ya da `gl/m4/` altında `gnulib-comp.m4`, `lib/gnulib.mk`, `bootstrap.conf`;
  - dil (dosya uzantıları);
  - çatal kanıtları:
    - yasm: `modules/preprocs/nasm/`;
    - zip: `crypt.c`, `ttyio.c`, `crc32.c`;
    - dropbear: `src/atomicio.c`, `libtomcrypt/`;
    - hatari: `src/cpu/gencpu.c`;
    - minimap2 ve bwa: klib dosyaları.

### Karadul imza kataloğu (yerel, salt okunur)

- **Yöntem:** `~/.karadul/signatures.lmdb`, `LMDBSignatureDB(readonly=True).lookup_symbol`. Ad ve `_` önekli biçimleri denendi; yöntem `docs/arge/2026-10-15_makale/test_seti_adaylari.md` §0 ile aynı.
- **Yoklanan adlar:** gömülü kütüphanelerin herkese açık API adları ile unbound ve nsd'nin bilinen iç adları.
- **Sonuçlar:** ön kayıt §9'da.

### Geliştirme seti (yerel)

Bu Mac'te kurulu Homebrew keglerinde `nm -U` ile t/T sayıları ve dosya boyutları alındı. Programlar: tmux, htop, tree, zstd, sqlite, openssl@3, redis, coreutils.

## Test seti meta verisi (ana oturum kararıyla kabul, 2026-10-19)

Tabaka eşikleri için test setinin 15 ana programının yalnız Debian Packages meta verisi okundu. İkili, kaynak ve Karadul çıktısı okunmadı. Sürümler `test_seti_kilidi.md` §4.1 ile aynı.

| Program | dbgsym paketi ve sürümü | Vekil (KiB) | ELF |
|---|---|---|---|
| dash | `dash-dbgsym` 0.5.12-12 | 309 | 1 |
| mawk | `mawk-dbgsym` 1.3.4.20250131-1 | 370 | 1 |
| unzip | `unzip-dbgsym` 6.0-29+deb13u1 | 569 | 3 |
| dcraw | `dcraw-dbgsym` 9.28-8 | 669 | 6 |
| gifsicle | `gifsicle-dbgsym` 1.96-1 | 797 | 3 |
| dnsmasq | `dnsmasq-base-dbgsym` 2.91-1+deb13u2 | 1061 | 1 |
| rsync | `rsync-dbgsym` 3.4.1+ds1-5+deb13u4 | 1111 | 1 |
| nasm | `nasm-dbgsym` 2.16.03-1 | 1180 | 2 |
| memcached | `memcached-dbgsym` 1.6.38-1 | 1789 | 1 |
| zsh | `zsh-dbgsym` 5.9-8+b24 | 3062 | 39 |
| gpg | `gpg-dbgsym` 2.4.7-21+deb13u1+b5 | 3312 | 2 |
| vim | `vim-nox-dbgsym` 2:9.1.1230-2 | 8971 | 1 |
| ssh | `openssh-client-dbgsym` 1:10.0p1-7+deb13u4 | 9096 | 10 |
| haproxy | `haproxy-dbgsym` 3.0.11-1+deb13u3 | 11299 | 2 |
| git | `git-dbgsym` 1:2.47.3-0+deb13u1 | 70029 | 10 |

Testlerden biri, bu 15 adın test setinin yayımlı kurasıyla aynı olduğunu `test_seti_kura.draw()` ile yeniden üreterek denetler. Bu, kilit belgesinde zaten yayımlı olan listedir; doğrulama kurası değildir.
