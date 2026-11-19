# Tabaka A / B verisi (P-Ö7 adım 1–3)

Plan: `olcu/PLAN.md` P-Ö7 ve §4. İndirme onayı: `KARARLAR.md` A-4. Bu belge yalnız indirme, doğrulama ve sabitlemenin kaydıdır; ürün koşusu (adım 4–7) ve ön kayıt sonraki oturumun işi. P-Ö8 ve P-Ö9 bu pakette yok.

- **Betik:** `scripts/arge/olcu/tabaka_indir.py` (sınaması `scripts/arge/olcu/test_tabaka_indir.py`: 21 / 21 geçti; mutant "kilit süzgeci boş liste döner" → süzgeç sınamaları kırmızı, 2 failed, sınamanın içinde koşuyor).
- **Komutlar** (depo kökünden):
  - `PYTHONDONTWRITEBYTECODE=1 python -I scripts/arge/olcu/tabaka_indir.py dizin --indir-kok ~/karadul_olcum/downloads/n2_tabaka --json ~/karadul_olcum/downloads/n2_tabaka/secim.json`
  - `PYTHONDONTWRITEBYTECODE=1 python -I scripts/arge/olcu/tabaka_indir.py indir --secim ~/karadul_olcum/downloads/n2_tabaka/secim.json --indir-kok ~/karadul_olcum/downloads/n2_tabaka --veri-kok ~/karadul_olcum/n2_tabaka --json ~/karadul_olcum/n2_tabaka/tabaka_veri.json`
  - `PYTHONDONTWRITEBYTECODE=1 python -I scripts/arge/olcu/tabaka_indir.py kiyas --veri ~/karadul_olcum/n2_tabaka/tabaka_veri.json --veri-kok ~/karadul_olcum/n2_tabaka`
  - `PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider scripts/arge/olcu/test_tabaka_indir.py -q`
- **Yerler:** indirilenler `~/karadul_olcum/downloads/n2_tabaka/<dağıtım>/` (dizinler `…/indeks/<dağıtım>/`); açılanlar `~/karadul_olcum/n2_tabaka/a/x_<paket>/`, `~/karadul_olcum/n2_tabaka/b/{debian12_arm64,ubuntu2404_arm64}/x_<paket>/` (her `.deb` / `.ddeb` ayrı yeni dizine). Kayıt dosyaları: `secim.json` (sha256 `5b1366ba2a2f418d…`), `tabaka_veri.json` (sha256 `2bc7f4395e6bb7a9…`).
- **Güvenlik:** kaynak yalnız `deb.debian.org` (`debian`, `debian-debug`, `debian-security`, `debian-security-debug`), `ports.ubuntu.com`, `ddebs.ubuntu.com`; snapshot.debian.org gerekmedi. İndirilen hiçbir dosya çalıştırılmadı; paketler Python içinde (`ar` + `tar`, yol kaçışı denetimli) açıldı; okuyan betikler `python -I` ile depo kökünden koştu.
- **Zaman:** dizinler 2026-11-19T08:38:06Z; paket indirme / doğrulama kaydı 2026-11-19T08:51:40Z (`tabaka_veri.json` `tarih_utc`).

## 1. Dizinler ve imza

Her dizinin `InRelease`'i indirildi ve imzası yerel `gpgv` ile dağıtımın kendi anahtar halkası paketine karşı doğrulandı; `Packages.xz`'in sha256'sı imzalı içerikle karşılaştırıldı. Anahtar halkası paketleri aynı arşivden HTTPS ile alındı ve sha256'ları dizinle eşleşti:

| dağıtım | anahtar halkası paketi | sürüm | sha256 |
|---|---|---|---|
| Debian 13 (amd64) | `debian-archive-keyring` | 2025.1 | `9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac` |
| Debian 12 (arm64) | `debian-archive-keyring` | 2023.3+deb12u2 | `f699e2f88dca05212f2a452b58475f2993cb6993dfbafb1d0205a3291eb8b4b8` |
| Ubuntu 24.04 (arm64) | `ubuntu-keyring` | 2023.11.28.1 | `36de43b15853ccae0028e9a767613770c704833f82586f28eb262f0311adb8a8` |
| Ubuntu 24.04 (arm64) | `ubuntu-dbgsym-keyring` | 2023.11.28.1 | `777b6a23443c60e54ccd3c5ee960a975450a8c4a0255affe0b7121df938a0cb1` |

**ddebs.ubuntu.com HTTPS sunmuyor** (HTTPS isteği 301 ile HTTP'ye dönüyor, 2026-11-19). Bu yüzden hata ayıklama paketlerinin bütünlüğü HTTP üzerinden şu zincire dayanıyor: `ubuntu-dbgsym-keyring` (HTTPS, ports dizini) → ddebs `InRelease` imzası (gpgv, anahtar `F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622`) → `Packages.xz` sha256 → `.ddeb` sha256. Zincirin her halkası tuttu.

| dizin | bileşen | mimari | Packages.xz sha256 | bayt | imza | imzalayan anahtar(lar) | imzalı sha256 tutuyor |
|---|---|---|---|---:|---|---|---|
| https://deb.debian.org/debian/dists/trixie | main | amd64 | `7778d3e3f303b7ddb8ce0fe7c8d57473a076c6bf2e8f241f75421d2396352498` | 9678380 | evet | 41587F7DB8C774BCCF131416762F67A0B2C39DE4, 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian/dists/trixie-updates | main | amd64 | `eea860c5dea11680e64299adb2736c2367c4235763a66f2b70ca61ce1b51978a` | 1108 | evet | 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-security/dists/trixie-security | main | amd64 | `f2f5a7ecda0ea72c669c0a1af315168253bf9a48fb57d627c7f2389b2c157e03` | 325232 | evet | 89C87ACEA5DD6B8E6A7068808E9F831205B4BA95, B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8 | evet |
| https://deb.debian.org/debian-debug/dists/trixie-debug | main | amd64 | `25acab545b35cfefca5380d5aa30cc8050a63388490d7a929d7e932c8a1b295e` | 3772552 | evet | 41587F7DB8C774BCCF131416762F67A0B2C39DE4, 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-debug/dists/trixie-proposed-updates-debug | main | amd64 | `5b8e465f5f27cb1af569da5481b240bf539a33ab5f109786f98ede4b9b3a5376` | 166124 | evet | 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-security-debug/dists/trixie-security-debug | main | amd64 | `83ede6172229034fcfb9965bc076a3c38b7ce0857f1ef6cc1e22f8cf00bfb351` | 233460 | evet | 89C87ACEA5DD6B8E6A7068808E9F831205B4BA95, B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8 | evet |
| https://deb.debian.org/debian/dists/bookworm | main | arm64 | `2ddb1737692e8c45c53e8d57c0ce4cd21c78c5703b830c3226b1423566a06c00` | 8689464 | evet | 4CB50190207B4758A3F73A796ED0E7B82643E131, 4D64FEC119C2029067D6E791F8D2585B8783D481, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian/dists/bookworm-updates | main | arm64 | `5dfd52317071685ad6e58c4ef0720128b7db68624079f83be02bdf55f07ac070` | 6936 | evet | 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-security/dists/bookworm-security | main | arm64 | `d04563689a3e0290ab2a8b488ec7b9c473f92f80d6a1fe78d23c40c4a5760dce` | 374852 | evet | B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8, ED541312A33F1128F10B1C6C54404762BBB6E853 | evet |
| https://deb.debian.org/debian-debug/dists/bookworm-debug | main | arm64 | `5b8080c4d04116f1c9162794d8ef1d11c023ba3b7b0b78d0150973ae99024672` | 3517248 | evet | 4CB50190207B4758A3F73A796ED0E7B82643E131, 4D64FEC119C2029067D6E791F8D2585B8783D481, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-debug/dists/bookworm-proposed-updates-debug | main | arm64 | `0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275` | 32 | evet | 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-security-debug/dists/bookworm-security-debug | main | arm64 | `a7f55d6e69607e4411cb8cfcabadc75994e475fb9a53d92a612401ff95f12ecb` | 283448 | evet | B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8, ED541312A33F1128F10B1C6C54404762BBB6E853 | evet |
| https://ports.ubuntu.com/ubuntu-ports/dists/noble | main | arm64 | `4a1901e6124fb0a111f5dffc8f5c14474f449e2ecfa71f2eaf0b29917edb53f9` | 1376632 | evet | F6ECB3762474EDA9D21B7022871920D1991BC93C | evet |
| https://ports.ubuntu.com/ubuntu-ports/dists/noble-updates | main | arm64 | `c2672a6a2cd0355bd9e274052bbfc2685c05cdc764df0cc27df8bda5ebf7335e` | 1516604 | evet | F6ECB3762474EDA9D21B7022871920D1991BC93C | evet |
| https://ports.ubuntu.com/ubuntu-ports/dists/noble-security | main | arm64 | `47b607403f6479170c603dcbf0bfdd2ea7008558284be7cd852de66120277e71` | 1266768 | evet | F6ECB3762474EDA9D21B7022871920D1991BC93C | evet |
| http://ddebs.ubuntu.com/dists/noble | main | arm64 | `e8473ebe263eb8d5f65020c69c5e1877c28c7cc9a5619ab53fd9baf418ba36da` | 547912 | evet | F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622 | evet |
| http://ddebs.ubuntu.com/dists/noble-updates | main | arm64 | `7bbad9775e9a6ea2577ae0994ba433f7afa3c683fd8ff3f48fb167bc17dd8a04` | 455612 | evet | F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622 | evet |
| https://ports.ubuntu.com/ubuntu-ports/dists/noble | universe | arm64 | `6df230cf5cfebcbd59e4e2713b8eed07dc0aaed66fb471ebf046cb70ccb07275` | 15313828 | evet | F6ECB3762474EDA9D21B7022871920D1991BC93C | evet |
| https://ports.ubuntu.com/ubuntu-ports/dists/noble-updates | universe | arm64 | `c2e887b3a0c44f44a6a553959cba078a38f35be719affcba686a57f3fea76a3d` | 1773852 | evet | F6ECB3762474EDA9D21B7022871920D1991BC93C | evet |
| https://ports.ubuntu.com/ubuntu-ports/dists/noble-security | universe | arm64 | `814727acde8b6bb09d6655ce5a66b69917e79b5c519815e98fb82d8f9b541a77` | 1321268 | evet | F6ECB3762474EDA9D21B7022871920D1991BC93C | evet |
| http://ddebs.ubuntu.com/dists/noble | universe | arm64 | `312b73f1b7f4dad47f857c952dd704138027b50583fd1ef37943e59123848ecc` | 4936812 | evet | F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622 | evet |
| http://ddebs.ubuntu.com/dists/noble-updates | universe | arm64 | `03a4debd2e3506015147b405e67acbebac0e415d7508ac04c14882e7fbd93eba` | 460448 | evet | F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622 | evet |

(ddebs'te `noble-security` dizini yok: 404, 2026-11-19; güvenlik güncellemelerinin hata ayıklama paketleri `noble-updates`'te.)

## 2. Kilitli ad denetimi

`tabaka_indir.kilitli_adlar` kilit belgelerinden 136 ad okudu (`test_seti_kilidi.md` sha256 `ec1dbd3622387cb4…`, `dogrulama_seti_kilidi.md` sha256 `d8474d6a56db6139…`; okunan yerler: ana küme tabloları, Homebrew / Debian paket sütunları, stres tabloları, korumalı ve sonraki yedek listeleri, kurada dışarıda kalanlar). 8 paket adı ve 8 `-dbgsym` adıyla **kesişim boş**; `-` parçası yakınlığı da boş (`secim.json` `kilit_kesisimi`, `kilit_yakinligi`).

## 3. Sürüm seçimi

- **Tabaka A** (Debian 13 amd64): kural PLAN adım 2 — kaynak sürümü geliştirme setindeki arm64 sürümüyle aynı (künye `~/karadul_olcum/downloads/debian13/manifest.json`; `~/karadul_olcum/n1_debian13/kosu_kunyesi.json` sürüm taşımıyor). Sekizinin sekizi de bugünkü `trixie` dizininde bulundu; snapshot.debian.org'a gerek kalmadı. Not: PLAN §4'teki amd64 boyutları packages.debian.org'dan okunmuştu ve openssl / redis-tools için `~deb13u3` / `+deb13u3` sürümünü gösteriyordu; kural gereği `~deb13u2` / `+deb13u2` alındı (openssl 1 507 300 bayt, PLAN'da 1 508 068; redis-tools 1 245 324, PLAN'da 1 247 524).
- **Tabaka B** (Debian 12 arm64, Ubuntu 24.04 arm64): aynı sürümde hata ayıklama paketi bulunan en yüksek sürüm (dpkg sırası).
- Geliştirme seti sürümleri (künyeden): `{'tmux': '3.5a-3', 'htop': '3.4.1-5', 'zstd': '1.5.7+dfsg-1', 'sqlite3': '3.46.1-7+deb13u2', 'openssl': '3.5.7-1~deb13u2', 'redis-tools': '5:8.0.2-3+deb13u2', 'coreutils': '9.7-3', 'tree': '2.2.1-1'}`

Komut: `python3 -I -c` ile `secim.json`'dan döküm (sütunlar `paketler[].dizin_surumleri`, `hata_surumleri`, `ikili_surum`, `ikili_dizin`, `hata_dizin`). Tabaka A satırlarında "dizindeki ikili sürümler" yalnız kaynak sürüm koşuluna uyanlardır.

| tabaka | dağıtım | paket | kaynak sürüm koşulu | dizindeki ikili sürümler | dizindeki dbgsym sürümleri | seçilen | ikili dizini | dbgsym dizini |
|---|---|---|---|---|---|---|---|---|
| A | debian13_amd64 | tmux | 3.5a-3 | 3.5a-3 | 3.5a-3 | 3.5a-3 | trixie_main | trixie-debug_main |
| A | debian13_amd64 | htop | 3.4.1-5 | 3.4.1-5 | 3.4.1-5 | 3.4.1-5 | trixie_main | trixie-debug_main |
| A | debian13_amd64 | zstd | 1.5.7+dfsg-1 | 1.5.7+dfsg-1 | 1.5.7+dfsg-1 | 1.5.7+dfsg-1 | trixie_main | trixie-debug_main |
| A | debian13_amd64 | sqlite3 | 3.46.1-7+deb13u2 | 3.46.1-7+deb13u2 | 3.46.1-7+deb13u2 | 3.46.1-7+deb13u2 | trixie_main | trixie-debug_main |
| A | debian13_amd64 | openssl | 3.5.7-1~deb13u2 | 3.5.7-1~deb13u2 | 3.5.7-1~deb13u2, 3.5.7-1~deb13u3, 3.5.9-1~deb13u1 | 3.5.7-1~deb13u2 | trixie_main | trixie-debug_main |
| A | debian13_amd64 | redis-tools | 8.0.2-3+deb13u2 | 5:8.0.2-3+deb13u2 | 5:8.0.2-3+deb13u2, 5:8.0.2-3+deb13u3 | 5:8.0.2-3+deb13u2 | trixie_main | trixie-debug_main |
| A | debian13_amd64 | coreutils | 9.7-3 | 9.7-3 | 9.7-3 | 9.7-3 | trixie_main | trixie-debug_main |
| A | debian13_amd64 | tree | 2.2.1-1 | 2.2.1-1 | 2.2.1-1 | 2.2.1-1 | trixie_main | trixie-debug_main |
| B | debian12_arm64 | tmux | — | 3.3a-3 | 3.3a-3 | 3.3a-3 | bookworm_main | bookworm-debug_main |
| B | debian12_arm64 | htop | — | 3.2.2-2 | 3.2.2-2 | 3.2.2-2 | bookworm_main | bookworm-debug_main |
| B | debian12_arm64 | zstd | — | 1.5.4+dfsg2-5 | 1.5.4+dfsg2-5 | 1.5.4+dfsg2-5 | bookworm_main | bookworm-debug_main |
| B | debian12_arm64 | sqlite3 | — | 3.40.1-2+deb12u2 | 3.40.1-2+deb12u2 | 3.40.1-2+deb12u2 | bookworm_main | bookworm-debug_main |
| B | debian12_arm64 | openssl | — | 3.0.17-1~deb12u2, 3.0.20-1~deb12u2, 3.0.22-1~deb12u2 | 3.0.20-1~deb12u2, 3.0.22-1~deb12u2 | 3.0.22-1~deb12u2 | bookworm-security_main | bookworm-security-debug_main |
| B | debian12_arm64 | redis-tools | — | 5:7.0.15-1~deb12u10, 5:7.0.15-1~deb12u7 | 5:7.0.15-1~deb12u10, 5:7.0.15-1~deb12u7 | 5:7.0.15-1~deb12u10 | bookworm-security_main | bookworm-security-debug_main |
| B | debian12_arm64 | coreutils | — | 9.1-1 | 9.1-1 | 9.1-1 | bookworm_main | bookworm-debug_main |
| B | debian12_arm64 | tree | — | 2.1.0-1 | 2.1.0-1 | 2.1.0-1 | bookworm_main | bookworm-debug_main |
| B | ubuntu2404_arm64 | tmux | — | 3.4-1build1, 3.4-1ubuntu0.2 | 3.4-1build1, 3.4-1ubuntu0.2 | 3.4-1ubuntu0.2 | noble-updates_main | ddebs_noble-updates_main |
| B | ubuntu2404_arm64 | htop | — | 3.3.0-4build1 | 3.3.0-4build1 | 3.3.0-4build1 | noble_main | ddebs_noble_main |
| B | ubuntu2404_arm64 | zstd | — | 1.5.5+dfsg2-2build1, 1.5.5+dfsg2-2build1.1 | 1.5.5+dfsg2-2build1, 1.5.5+dfsg2-2build1.1 | 1.5.5+dfsg2-2build1.1 | noble-updates_main | ddebs_noble-updates_main |
| B | ubuntu2404_arm64 | sqlite3 | — | 3.45.1-1ubuntu2, 3.45.1-1ubuntu2.8, 3.45.1-1ubuntu2.9 | 3.45.1-1ubuntu2, 3.45.1-1ubuntu2.9 | 3.45.1-1ubuntu2.9 | noble-updates_main | ddebs_noble-updates_main |
| B | ubuntu2404_arm64 | openssl | — | 3.0.13-0ubuntu3, 3.0.13-0ubuntu3.16 | 3.0.13-0ubuntu3, 3.0.13-0ubuntu3.16 | 3.0.13-0ubuntu3.16 | noble-updates_main | ddebs_noble-updates_main |
| B | ubuntu2404_arm64 | redis-tools | — | 5:7.0.15-1build2, 5:7.0.15-1ubuntu0.24.04.5 | 5:7.0.15-1build2, 5:7.0.15-1ubuntu0.24.04.5 | 5:7.0.15-1ubuntu0.24.04.5 | noble-updates_universe | ddebs_noble-updates_universe |
| B | ubuntu2404_arm64 | coreutils | — | 9.4-3ubuntu6, 9.4-3ubuntu6.3 | 9.4-3ubuntu6, 9.4-3ubuntu6.3 | 9.4-3ubuntu6.3 | noble-updates_main | ddebs_noble-updates_main |
| B | ubuntu2404_arm64 | tree | — | 2.1.1-2ubuntu3, 2.1.1-2ubuntu3.24.04.2 | 2.1.1-2ubuntu3, 2.1.1-2ubuntu3.24.04.2 | 2.1.1-2ubuntu3.24.04.2 | noble-updates_universe | ddebs_noble-updates_universe |

## 4. Paketler: sha256, BuildID, boyut

"sha256 = dizin": dosyanın sha256'sı ve boyutu imzalı dizindeki `SHA256` / `Size` ile aynı. "ELF": açılan ikili paketteki düzenli ELF dosyaları. "BuildID eşleşen": GNU BuildID notu (yalnız sahibi `GNU` olan not) hata ayıklama paketindeki `usr/lib/debug/.build-id/xx/yyyy.debug` ile aynı ve `scripts/measurement/function_f1.py` `extract_gt` hatasız geçen ELF'ler. "extract_gt FUNC": eşleşen ELF'lerin GT fonksiyon sayısı toplamı (`counts.functions`).

| tabaka | dağıtım | paket | sürüm (.deb / dbgsym) | kaynak | .deb bayt | dbgsym bayt | .deb sha256 | dbgsym sha256 | sha256 = dizin | ELF | BuildID eşleşen | extract_gt FUNC (toplam) | durum |
|---|---|---|---|---|---:|---:|---|---|---|---:|---:|---:|---|
| A | debian13_amd64 | tmux | 3.5a-3 / 3.5a-3 | dizin | 490296 | 1160244 | `e6b6aa51780044e2c4a0e618c33f832b70ec80caa30303e6c254a0c851b5af78` | `630a599a444a2de4a3b88a63ec19282f53d7c8f75e5ab5235c7b4d8308589f56` | evet / evet | 1 | 1 | 1928 | tamam |
| A | debian13_amd64 | htop | 3.4.1-5 / 3.4.1-5 | dizin | 171412 | 399516 | `42725cc15e215e9286bf169fe734fbf47826dae209f319f6d0370cb950112fbf` | `a79bf55380d415f5057ff05c6bc8b6efd42a85359d23400f9d03d48947d8560b` | evet / evet | 1 | 1 | 618 | tamam |
| A | debian13_amd64 | zstd | 1.5.7+dfsg-1 / 1.5.7+dfsg-1 | dizin | 756244 | 5048268 | `6da09b6aad171ef9b50d6a2bb4c62f756b3561aac5e05b452b80516223e5e0f5` | `94351b44bdf76b5f3080c307c3081d5cbec28bc8c093fb89798db07f3f92f023` | evet / evet | 2 | 2 | 2450 | tamam |
| A | debian13_amd64 | sqlite3 | 3.46.1-7+deb13u2 / 3.46.1-7+deb13u2 | dizin | 384144 | 393280 | `877b00bd5ab6a3792fdffebd4aeebe0b8178df3c21f0e06f6a3c5186f7a799d9` | `b3a0793564cceb9ef6c1c020c41d0d118368cc6955d75c73743643e72674cfb3` | evet / evet | 1 | 1 | 431 | tamam |
| A | debian13_amd64 | openssl | 3.5.7-1~deb13u2 / 3.5.7-1~deb13u2 | dizin | 1507300 | 750356 | `4ff006f431d8c2e69fa736885a3b6e779f2448535f69dbde821d9f0ff87ad8ea` | `521b54a85176e72e9412617c2a231a243347586794197d9cf576d4648cdcb7e0` | evet / evet | 1 | 1 | 610 | tamam |
| A | debian13_amd64 | redis-tools | 5:8.0.2-3+deb13u2 / 5:8.0.2-3+deb13u2 | dizin | 1245324 | 4532716 | `9d7cbe20963c8bfc00af3e8a3a33451bb815f7501b12e55583f9e942a767859b` | `d0f46011a2058b635dc1a0ec118d216994d960763381333a439d87443490604a` | evet / evet | 4 | 4 | 11392 | tamam |
| A | debian13_amd64 | coreutils | 9.7-3 / 9.7-3 | dizin | 3023556 | 7248364 | `1299ab6f9389a288eb2f5f3dd222c26cc777b9a2d5ecb6ee4cbd340cebcdada2` | `f2c5b7841c16f64ed9be08eb9bc9d2c3cb88817f362408d080f18fc6a8a7f08e` | evet / evet | 106 | 106 | 16013 | tamam |
| A | debian13_amd64 | tree | 2.2.1-1 / 2.2.1-1 | dizin | 59392 | 82808 | `123f5e15790fee551c52f56bb930e3eadd77f74af0819c8bec243e26521e98f5` | `b1fced329e44d8ad0353a0e80edff3ef7a3859e52b5701b3c8a4c3af1083f93b` | evet / evet | 1 | 1 | 118 | tamam |
| B | debian12_arm64 | tmux | 3.3a-3 / 3.3a-3 | dizin | 419156 | 1027120 | `bbf91233312841253fb0c79c28d28d08680d23056674b4499aac14bd4831ac28` | `c5dd7eb52032f1c6d9a81922fed5375cbc8fd168369addc5a5864971d55b129f` | evet / evet | 1 | 1 | 1793 | tamam |
| B | debian12_arm64 | htop | 3.2.2-2 / 3.2.2-2 | dizin | 144044 | 337936 | `3cd8f5612c694a1748fbf661f71d83ca3d8b6d71e629dd492f3ef6ab641c3b0a` | `6b6a8d216d5c3b748378394582c93d91a0ccb1ca782cf42743d8d484810a435f` | evet / evet | 1 | 1 | 542 | tamam |
| B | debian12_arm64 | zstd | 1.5.4+dfsg2-5 / 1.5.4+dfsg2-5 | dizin | 584044 | 4225628 | `97a58383b0ad55cc8183e59cbb112f2eb55c3dc1e90de816fa5cfb983d5c2ff0` | `8f57f6a9a00082169fc00b14816703bb836e31a0e9a63312f8284d2ca31b74db` | evet / evet | 2 | 2 | 1929 | tamam |
| B | debian12_arm64 | sqlite3 | 3.40.1-2+deb12u2 / 3.40.1-2+deb12u2 | dizin | 341568 | 359564 | `1f14747c3e019164bc6ed4c1aba47d9705fd7ec990594669b073cd8e3ddc737d` | `5173dcd29898bea065031f8929d4cabcce3aba873cc7bb8ba971553c87ce3a56` | evet / evet | 1 | 1 | 372 | tamam |
| B | debian12_arm64 | openssl | 3.0.22-1~deb12u2 / 3.0.22-1~deb12u2 | dizin | 1409768 | 684916 | `416af916dd59f08e996ec887acf3d267039169ef40ee4d38b44829b5ec3e92a4` | `d82f0e5c188e34b1587fb44a354ea635f1cda1141826b9c309b8a608dbdb9694` | evet / evet | 1 | 1 | 533 | tamam |
| B | debian12_arm64 | redis-tools | 5:7.0.15-1~deb12u10 / 5:7.0.15-1~deb12u10 | dizin | 899140 | 2754076 | `417bf100f26845212c4d644bd39fd28b1510c2bb4a7caab28a24165ccc97e9a9` | `517f6b7c70b0d6c75be57e9c6a238b60e88472f83fbde43185b118102d578d08` | evet / evet | 4 | 4 | 8966 | tamam |
| B | debian12_arm64 | coreutils | 9.1-1 / 9.1-1 | dizin | 2815252 | 7200844 | `ec8f090a14c684879dce251254d8d9ed0876d4480f750d5807ef04e5435e1c4d` | `06b8391e953100003187516f01497dc2263c7518e8cf662e8764cb9a6fc4db55` | evet / evet | 106 | 106 | 13470 | tamam |
| B | debian12_arm64 | tree | 2.1.0-1 / 2.1.0-1 | dizin | 50920 | 78828 | `f83d01326a0071cea2d0bdea2d465add7c50e9d68c247cbe8f22f1dc7eb0eb2f` | `89b57da2df5713db269486a10ac3a0a0bb58245a6a094cf29bb60a660a0ec1b1` | evet / evet | 1 | 1 | 115 | tamam |
| B | ubuntu2404_arm64 | tmux | 3.4-1ubuntu0.2 / 3.4-1ubuntu0.2 | dizin | 465230 | 1365444 | `0245fe5e11f7f9243fb841508071be46c35fe4012fef0f65254abfc6e4fe0034` | `7dff3cc4e904af207b15970c4ffa4b979932d366842755eedd3602026a8f9333` | evet / evet | 1 | 1 | 1290 | tamam |
| B | ubuntu2404_arm64 | htop | 3.3.0-4build1 / 3.3.0-4build1 | dizin | 170728 | 496848 | `98db74e9b9f36d3775b5b65c96c093a03c61571bccdc8e058d36d8f12811c1e0` | `aa24205111b8cac14f2b9ec4209a024a2b9620ba48b32970246b00659fb428a1` | evet / evet | 1 | 1 | 601 | tamam |
| B | ubuntu2404_arm64 | zstd | 1.5.5+dfsg2-2build1.1 / 1.5.5+dfsg2-2build1.1 | dizin | 574636 | 3591736 | `0a57c275f85a4bc5bae0bb0e8d82eda1614623366d4e50caddcca6ba475c5cc8` | `e5eeeebcf62ce33f9b6a652688d84ab89e9b1d2be5f2a027afbca4d810712f2b` | evet / evet | 2 | 2 | 965 | tamam |
| B | ubuntu2404_arm64 | sqlite3 | 3.45.1-1ubuntu2.9 / 3.45.1-1ubuntu2.9 | dizin | 139586 | 372714 | `d4d15cc2109732bce3e16216eb4e4c5106cff4424e9fe477586dadd7d0bdf3f2` | `eb99cc318ae7d58396c52d4d8b9af80c73cac3e4fb0c289db30af5985fb9df05` | evet / evet | 1 | 1 | 379 | tamam |
| B | ubuntu2404_arm64 | openssl | 3.0.13-0ubuntu3.16 / 3.0.13-0ubuntu3.16 | dizin | 985334 | 687738 | `07fa666e2dfe758e5c4e19ccc695a19e8a56fb512fa55bd7de89219a1e65d372` | `c258c308414af463adcad0841cbd7aa8f7ebd3fcbdf8b5734ea56642f3474259` | evet / evet | 1 | 1 | 534 | tamam |
| B | ubuntu2404_arm64 | redis-tools | 5:7.0.15-1ubuntu0.24.04.5 / 5:7.0.15-1ubuntu0.24.04.5 | dizin | 1170186 | 3591658 | `c74a99662a91d85e6acd01c5352c276384ac5075d316a687f45a721168fecbca` | `9fe10633ccb4db5193604008a3fd9736c53f6ae8ababdd65bfda91c4700ba8b3` | evet / evet | 4 | 4 | 8871 | tamam |
| B | ubuntu2404_arm64 | coreutils | 9.4-3ubuntu6.3 / 9.4-3ubuntu6.3 | dizin | 1363982 | 5696106 | `1a0b163febf032934ecc3c7a71769c90a9b68cdbdd8c3afa7f3ef985b4c962da` | `0f49e32d79d4faaa0911463238f3499a625fd86e08b72ca83a6be62a067b0634` | evet / evet | 106 | 106 | 4556 | tamam |
| B | ubuntu2404_arm64 | tree | 2.1.1-2ubuntu3.24.04.2 / 2.1.1-2ubuntu3.24.04.2 | dizin | 46224 | 82980 | `db73aefa02220d220343a66005f956cb7beec74d1b3f72bdcbe6e29ee0b90743` | `80237cdd4babfb4696773e1fc1a06e324bf0c77bb2d55b92f957e0cec68c65a7` | evet / evet | 1 | 1 | 93 | tamam |

İndirilen ve sha256'sı tutan: .deb 19217466 bayt, dbgsym 52169688 bayt, toplam 71387154 bayt (68.08 MiB).

Toplam: 24 paket (3 tabaka hücresi × 8), 48 dosya; 48'inin sha256'sı tuttu; 351 ELF'in 351'inde BuildID eşleşmesi ve `extract_gt` geçti. İndirilemeyen ya da bulunamayan paket yok.

## 5. Geliştirme setiyle karşılaştırma ve derleyici

ELF adları her pakette geliştirme setinin birim dizinleriyle (`~/karadul_olcum/n1_debian13/<paket>/<ikili>/`) aynı; makine beklenen mimari; derleyici izi her paketin ilk üç ELF'inin `.debug` dosyasındaki `.comment` satırı. `function_f1.read_elf_info`'nun BuildID'si `tabaka_indir.elf_bilgisi`'ninkinden farklı olan ELF sayısı (SystemTap notu sapması, `ozkod/NUFUS.md` §8 not 3) da burada.

| tabaka | dağıtım | paket | ELF | geliştirme setindeki ELF | ad farkı (eksik / fazla) | makine | derleyici (`.comment`) | `function_f1` BuildID sapması |
|---|---|---|---:|---:|---|---|---|---:|
| A | debian13_amd64 | tmux | 1 | 1 | 0 / 0 | EM_X86_64 | GCC: (Debian 14.2.0-16) 14.2.0 | 0 |
| A | debian13_amd64 | htop | 1 | 1 | 0 / 0 | EM_X86_64 | GCC: (Debian 14.2.0-19) 14.2.0 | 0 |
| A | debian13_amd64 | zstd | 2 | 2 | 0 / 0 | EM_X86_64 | GCC: (Debian 14.2.0-18) 14.2.0 | 0 |
| A | debian13_amd64 | sqlite3 | 1 | 1 | 0 / 0 | EM_X86_64 | GCC: (Debian 14.2.0-19) 14.2.0 | 0 |
| A | debian13_amd64 | openssl | 1 | 1 | 0 / 0 | EM_X86_64 | GCC: (Debian 14.2.0-19) 14.2.0 | 0 |
| A | debian13_amd64 | redis-tools | 4 | 4 | 0 / 0 | EM_X86_64 | GCC: (Debian 14.2.0-19) 14.2.0 | 0 |
| A | debian13_amd64 | coreutils | 106 | 106 | 0 / 0 | EM_X86_64 | GCC: (Debian 14.2.0-19) 14.2.0 | 0 |
| A | debian13_amd64 | tree | 1 | 1 | 0 / 0 | EM_X86_64 | GCC: (Debian 14.2.0-8) 14.2.0 | 0 |
| B | debian12_arm64 | tmux | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Debian 12.2.0-7) 12.2.0 | 0 |
| B | debian12_arm64 | htop | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Debian 12.2.0-14) 12.2.0 | 0 |
| B | debian12_arm64 | zstd | 2 | 2 | 0 / 0 | EM_AARCH64 | GCC: (Debian 12.2.0-14) 12.2.0 | 0 |
| B | debian12_arm64 | sqlite3 | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Debian 12.2.0-14+deb12u1) 12.2.0 | 0 |
| B | debian12_arm64 | openssl | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Debian 12.2.0-14+deb12u1) 12.2.0 | 0 |
| B | debian12_arm64 | redis-tools | 4 | 4 | 0 / 0 | EM_AARCH64 | GCC: (Debian 12.2.0-14+deb12u1) 12.2.0 | 0 |
| B | debian12_arm64 | coreutils | 106 | 106 | 0 / 0 | EM_AARCH64 | GCC: (Debian 12.2.0-2) 12.2.0 | 0 |
| B | debian12_arm64 | tree | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Debian 12.2.0-11) 12.2.0 | 0 |
| B | ubuntu2404_arm64 | tmux | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 | 0 |
| B | ubuntu2404_arm64 | htop | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Ubuntu 13.2.0-23ubuntu3) 13.2.0 | 0 |
| B | ubuntu2404_arm64 | zstd | 2 | 2 | 0 / 0 | EM_AARCH64 | GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0 | 0 |
| B | ubuntu2404_arm64 | sqlite3 | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 | 0 |
| B | ubuntu2404_arm64 | openssl | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 | 0 |
| B | ubuntu2404_arm64 | redis-tools | 4 | 4 | 0 / 0 | EM_AARCH64 | GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 | 0 |
| B | ubuntu2404_arm64 | coreutils | 106 | 106 | 0 / 0 | EM_AARCH64 | GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 | 0 |
| B | ubuntu2404_arm64 | tree | 1 | 1 | 0 / 0 | EM_AARCH64 | GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0 | 0 |

Toplam ELF: 351; ad farkı olan paket: 0; BuildID sapması: 0

Okuma: tabaka A'nın tek değişen etkeni mimari (GCC 14.2, Debian 13), tabaka B'nin derleyici sürümü (Debian 12: GCC 12.2; Ubuntu 24.04: GCC 13.2 / 13.3) — PLAN §4'ün tabaka tanımıyla uyumlu. Program sürümleri tabaka B'de geliştirme setinden farklı (ör. coreutils 9.1 / 9.4 ↔ 9.7); B'nin etkeni "derleyici sürümü + o dağıtımdaki program sürümü" diye okunmalı, saf derleyici etkisi değil.

## 6. Boyut ve disk

- Bu pakette indirilen (ÖZ KOD ÖK-V dahil, `scripts/measurement/ozkod_nufus_kur.py`): tabaka paketleri 71 387 154 bayt; tabaka dizin dosyaları (`InRelease` + `Packages.xz`) 57 960 831 bayt; tabaka anahtar halkası paketleri 373 468 bayt (`downloads/n2_tabaka` altındaki `.deb` toplamı 71 760 622 − 71 387 154); ÖK-V paketleri 135 365 004 bayt + anahtar halkası 179 244 bayt; ÖK-V dizinleri 14 383 295 bayt. **Toplam 279 648 996 bayt (266,7 MiB)** — 2 GiB sınırının altında (komut: `find … \( -name '*.deb' -o -name '*.ddeb' -o -name InRelease -o -name Packages.xz \) | stat` toplamı).
- Disk (`diskutil info /System/Volumes/Data | grep "Volume Used"`; ortak makine, başka oturumlar da yazıyor):
  - önce (2026-11-19 11:21:41 +03): `710.4 GB (710430367744 Bytes)`
  - sonra (2026-11-19 11:52:18 +03): `716.1 GB (716129710080 Bytes)`
  - Bu paketin dizinleri (`du -sk`): `~/karadul_olcum/n2_tabaka` 154 364 KiB, `~/karadul_olcum/downloads/n2_tabaka` 127 632 KiB, `~/karadul_olcum/ozkod_nufus` 456 556 KiB. Farkın geri kalanı bu paketin dışından.

## 7. Sonraki adım (P-Ö7 adım 4–7, sonraki oturum)

Ön kaydı (PLAN P-Ö7 "Kabul ölçütü ve ön kayıt metni") `P-O7_on_kayit.md` olarak commit'le; sonra ürün koşusu, tabaka başına ayrı kök, sıralı (aynı anda 1 Ghidra), koşuya özel `KARADUL_CACHE_DIR`, `PYTHONHASHSEED=0`. ELF yolları `tabaka_veri.json` `paketler[].buildid.satirlar[].yol` (açılan dizine göre), GT `.debug` yolları `debug_yol`. `urun_olc` için kök düzeni `debian/<birim>/<ikili>` olacak biçimde düzenlenmeli (`urun_kos.py`'ye "tabaka" seçeneği PLAN'ın önerisi).
