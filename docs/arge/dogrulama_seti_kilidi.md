# Doğrulama seti kilidi

- **Tarih:** 2026-10-19
- **Kura betiği:** `scripts/measurement/dogrulama_seti_kura.py`. Sonuç görülmeden, ön kayıt belgesiyle birlikte commit `be19227` ile sabitlendi.
- **Ön kayıt:** `docs/arge/dogrulama_seti_onkayit.md` (aynı commit). Kanıt kayıtları: `docs/arge/dogrulama_seti_kanit/`.
- **Tohum:** SHA-256(`karadul-dogrulama-seti-kura-2026-10-19`) değerinin ilk 16 hex basamağı = `6938462450958974163`
- **Stres alt tohumu:** SHA-256(`karadul-dogrulama-seti-kura-2026-10-19/stres`) değerinin ilk 16 hex basamağı = `1099394289718775035`
- **Kura:** 2026-10-19 10:08:45 UTC. Betiğin commit denetimi geçti: betik ve ön kayıt belgesi git'te izleniyor, değişiklik yok.
- **Künye** (kura çıktısından):
  - betik sha256 `ffaa0373973adf3b750c25c8d418baa2e36ee2cb8aaf6f99b51f58b479ddade7`;
  - test seti betiği sha256 `ee9970380f9d17c6c24af3f33baaa35d0ff28a161446be1d02a732cceef81492`;
  - havuz sha256 `89bd7fadc48fada0777fa71468b1b5aa268a45e831264b39d90ba048680e7497`;
  - git HEAD `be192278c2e1a8b959ad31c268fcec2a65c0445f`;
  - Python 3.12.7.
- **Kura çıktısı:** `targets/dogrulama_seti/kura/kura_ilk.json` (depo dışında). Aynı komut aynı sonucu verir.
- **Plan:** `docs/arge/2026-10-17_plan_v2.md` §3 madde 2, §7. Kapılar bu sette ölçülür.

## Kurallar

1. **Bu programlar yalnız kapı günlerinde Karadul ile analiz edilir; kural geliştirmede kaynaklarına ve çıktılarına bakılmaz.**
   - Kapı günleri: G13, G20, G28-G30.
   - Kural, eşik ya da sözlük bu programlara göre ayarlanmaz.
2. **Kapsam:** §1'deki 10 program, §1'deki korumalı yedekler ve işaretli listenin 13 programı. İşaretli listede §2'deki stres alt kümesi ile yedekleri var.
3. **Stres alt kümesi** kapı günlerinde ölçülür ve ayrı raporlanır. Kapı ölçütüne girmez.
4. **Yasak kullanımlar:** bu programlar şu işlerde kullanılmaz:
   - LLM pilotu (G6);
   - KaradulLM eğitim verisi;
   - imza ya da sözlük kurulumu;
   - "görülmemiş dilim".
5. **Liste sonradan değiştirilmez.**
   - Bir program koşulamazsa (K1, K2, K4, K5, K6; ön kayıt §4.4) yerine ön kayıt §4.5'teki kuralla `--kosulamayan ad:NEDEN` çıktısındaki program gelir. Değişiklik ve gerekçesi bu belgeye eklenir (§4.4).
   - K3'te program değişmez: Mac ikilisi aynı formülden, sembolleri korunarak kaynaktan derlenir (ön kayıt §4.4).
   - Derleme 30 dakikada başarıyla bitmezse neden K6 olur.
6. **Sabitleme analizden önce:** ikililer indirilince sha256 ve BuildID/UUID bu belgeye yazılır (§4). Bu adım ilk analizden önce yapıldı.
7. **Bakış kaydı:** her kapı gününde doğrulama setine her bakış kayda geçer (tarih, kapı, commit, ne görüldüğü).
8. **Sembol adı yazılmaz:** bu belgede ve raporlarda sembol adı yer almaz. Sabitlemede `nm` yalnız sayım için çalıştırıldı.

## 1. Ana küme (10 program)

| # | Program (ölçülecek ikili) | Alan | Aile | Tabaka (vekil KiB) | Homebrew (API 2026-10-17) | Debian 13 arm64 | Sürüm eşleşmesi | Not |
|---|---|---|---|---|---|---|---|---|
| 1 | mosquitto (`mosquitto`; Debian `mosquitto`) | ağ altyapısı | Eclipse Mosquitto | küçük (949) | `mosquitto` 2.1.2_2 | `mosquitto` 2.0.21-1 | farklı | — |
| 2 | newlisp (`newlisp`; Debian `newlisp`) | dil yorumlayıcısı | newlisp | küçük (428) | `newlisp` 10.7.5 | `newlisp` 10.7.5-2+b4 | aynı | Mac şişesi soyulmuş (K3): Mac ikilisi kaynaktan derlenecek |
| 3 | pspg (`pspg`; Debian `pspg`) | metin ve belge | pspg | küçük (724) | `pspg` 5.8.16 | `pspg` 5.8.9-1 | yakın | — |
| 4 | kalign (`kalign`; Debian `kalign`) | bilim | kalign | küçük (504) | `kalign` 3.5.1, rebuild 1 | `kalign` 1:3.4.0-1+b3 | farklı | — |
| 5 | timidity (`timidity`; Debian `timidity`) | medya | TiMidity++ | orta (2728) | `timidity` 2.15.0_3 | `timidity` 2.14.0-8.3+b1 | farklı | — |
| 6 | nagios (`nagios`; Debian `nagios4`) | sistem yönetimi | Nagios | orta (1552) | `nagios` 4.5.14 | `nagios4-core` 4.4.6-4.1+deb13u1 | farklı | Mac şişesi soyulmuş (K3): Mac ikilisi kaynaktan derlenecek |
| 7 | joe (`joe`; Debian `joe`) | editör | joe | orta (1226) | `joe` 4.8 | `joe` 4.6-2 | farklı | — |
| 8 | gnugo (`gnugo`; Debian `gnugo`) | oyun | GNU Go | orta (1359) | `gnu-go` 3.8_1 | `gnugo` 3.8-13+b1 | aynı | — |
| 9 | alpine (`alpine`; Debian `alpine`) | iletişim | Alpine (UW Pine) | büyük (13799) | `alpine` 2.26, rebuild 2 | `alpine` 2.26+dfsg-3 | aynı | — |
| 10 | gnome-builder (`gnome-builder`; Debian `gnome-builder`) | geliştirme araçları | GNOME Builder | büyük (15033) | `gnome-builder` 50.0, rebuild 1 | `gnome-builder` 48.0-2+b1 | farklı | — |

**Kura notları:**

- Alan kısıtı hiç gevşetilmedi.
- Komşu tabakaya geçilmedi.
- Eksik yer yok.
- 10 program 10 ayrı alandan ve 10 ayrı aileden.

**Yedek sırası.** Her tabakanın karışık sırasında seçilmeyenler, sırasıyla. İlk *kota* kadarı korumalı yedektir (4/4/2):

- **küçük:** korumalı: zmap, abcm2ps, bogofilter, byacc. Sonrası: jove, frotz, sslh, tcsh, mtools, hydra, dosfstools, remind, calcurse, multitail, mle, iodine, bmake, minimap2, enscript, flex, ne, dnsperf, distcc, ngircd, rmlint, vnstat, bitlbee, minicom, lowdown, sc-im, squashfs-tools, isync, bwa, fetchmail.
- **orta:** korumalı: tin, fig2dev, profanity, mpv. Sonrası: chrony, splint, weechat, nethack, nsd, zabbix, angband, vifm, mksh, exim, links, cscope, testdisk, monit, freeciv.
- **büyük:** korumalı: php, pari. Sonrası: tor, qemu-img, ipv6calc.

Değişimde aile ve alan kısıtı uygulanır (ön kayıt §4.5). Bu yüzden her zaman sıradaki ilk program gelmeyebilir.

## 2. Doğrulama stres alt kümesi (5 program)

| # | Program (ölçülecek ikili) | İşaret | Vekil KiB | Homebrew (API 2026-10-17) | Debian 13 arm64 |
|---|---|---|---|---|---|
| 1 | datamash (`datamash`; Debian `datamash`) | gnulib (m4/gnulib-comp.m4, lib/gnulib.mk) | 490 | `datamash` 1.9 | `datamash` 1.9-1 |
| 2 | bison (`bison`; Debian `bison`) | gnulib (m4/gnulib-comp.m4, lib/gnulib.mk) | 812 | `bison` 3.8.2 | `bison` 2:3.8.2+dfsg-1+b2 |
| 3 | tar (`gtar`; Debian `tar`) | gnulib (m4/gnulib-comp.m4) | 1224 | `gnu-tar` 1.35_1 | `tar` 1.35+dfsg-3.1 |
| 4 | sed (`gsed`; Debian `sed`) | gnulib (m4/gnulib-comp.m4, lib/gnulib.mk, bootstrap.conf) | 310 | `gnu-sed` 4.10 | `sed` 4.9-2+deb13u1 |
| 5 | diffutils (`diff`; Debian `diff`) | gnulib (m4/gnulib-comp.m4, lib/gnulib.mk) | 815 | `diffutils` 3.12 | `diffutils` 1:3.10-4 |

**Stres yedek sırası:** findutils, unbound, inetutils-telnet, m4, patch, hatari, make, cpio.

**Not:** Çıkan 5 programın hepsi gnulib işaretli. Kütüphane ikizi (unbound) ve üretilmiş kod (hatari) yedekte kaldı. Bu yüzden stres koşusu yalnız gnulib etkisini ölçer. Kura ön kayda göre çekildi; sonuç değiştirilmez.

## 3. Ölçüm tanımları

Tanımlar `test_seti_kilidi.md` §3 ile aynı; yalnız Mac'teki gerçek isim kaynağı için K3 kuralı eklendi.

- **Payda:** isim bekleyen fonksiyonlar, yani Ghidra'nın kendisinin adlandıramadıkları.
  - Thunk ve stub'lar hariç.
  - `.cold` ve `OUTLINED_FUNCTION` parçaları ayrı sınıf.
- **Mac:**
  - Gerçek isimler Homebrew şişesindeki ikilinin `nm` çıktısından alınır.
  - K3 olan programlarda gerçek isimler, aynı formülden kaynaktan derlenen ikiliden alınır (ön kayıt §4.4).
  - Analiz, ikilinin `/usr/bin/strip` ile soyulmuş kopyası üzerinde yapılır. Export trie'nin boşaldığı `xcrun dyld_info -exports` ile doğrulanır.
- **Linux:**
  - Gerçek isimler aynı sürümün `-dbgsym` paketinden alınır.
  - Analiz, dağıtılan soyulmuş ikili üzerinde yapılır.
- **Kapılar:** plan §7'ye göre program sınıfı başına makro ortalama, risk-kapsam biçiminde ölçülür.
  - Program sınıfı tanımı plan belgesinde G13'ten önce yazılacak (ön kayıt §11).
  - Stres alt kümesi ayrı raporlanır.

## 4. İkili sabitleme (2026-10-19)

İndirilen dosyalar `targets/dogrulama_seti/<program>/` altında; depo ve Spotlight dışında. İndirme 80,8 MB (80 774 973 B); açılmış dosyalarla diskte 271 MB. Program başına kayıt: `targets/dogrulama_seti/<program>/sabitleme.json`.

**Doğrulamalar:**

- Homebrew şişelerinin sha256'sı API önbelleğindeki değerle eşleşti: 15/15.
- Debian paketlerinin ve dbgsym'lerin sha256'sı Packages dizini (13.7) ile eşleşti: 30/30.
- dbgsym BuildID'leri 15/15 eşleşti. İki denetim yapıldı: `.debug` dosyasının notu ve Packages'taki `Build-Ids` alanı.
- Dağıtılan Debian ikililerinin hiçbirinde `.symtab` yok.
- Yalıtım:
  - Hiçbir ikili çalıştırılmadı; Karadul ya da Ghidra ile açılmadı; kaynaklara bakılmadı.
  - Yalnız sayılar, sha256, UUID/BuildID ve kütüphane yolları kaydedildi.
  - Sembol adı okunmadı, yazılmadı.
- Ağ yalnız ghcr.io (ve yönlendirdiği GitHub paket sunucusu) ile deb.debian.org'du. Sistem Homebrew'u değişmedi; kurulum yapılmadı.

### 4.1 Ana küme (10 program × 2 platform)

| Program | Platform | Paket/şişe (sürüm) | sha256 (ölçülecek ikili) | BuildID / UUID | Tarih | Sembol / dbgsym |
|---|---|---|---|---|---|---|
| mosquitto (`mosquitto`) | macOS arm64 (`arm64_tahoe`) | `mosquitto` 2.1.2_2 | `2468da650b1069bad4bac2a4704ddaaa01f91cbfdd4d477ce8a20df960caf12e` | `AAC64D50-1734-310C-828E-F9A247DC8525` | 2026-10-19 | nm -U 710 (t=577, T=82) |
| mosquitto (`mosquitto`) | Debian 13 arm64 | `mosquitto` 2.0.21-1 | `8b627b97168005342af18801db46cc8f76346d1cf5c7511b91a660b6a7356391` | `ddc3c436c03000cf910911b3babc4e1213d7db77` | 2026-10-19 | `mosquitto-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 422 (yerel 73, global 349); dağıtılan ikilide `.symtab` yok |
| newlisp (`newlisp`) | macOS arm64 (`arm64_tahoe`) | `newlisp` 10.7.5 | `dd0cd5e981ed20780a17dd9a48fa6e2425ab57ad89f0bd6e7914d47ce7e47513` | `75905649-3F0C-3AD9-910E-587E9BD6A6CF` | 2026-10-19 | bağlantı: `bin/newlisp` → `bin/newlisp-10.7.5`; **SEMBOLSÜZ (K3)**: nm -U 1 satır (t=0, T=1) |
| newlisp (`newlisp`) | Debian 13 arm64 | `newlisp` 10.7.5-2+b4 | `875d761d2103f3f7605b9f7dea0258ddd81be70b44af8f37d13b0174a76e69ec` | `ebe8360d9ab755dc2649213aefa254c5a619ff16` | 2026-10-19 | `newlisp-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 850 (yerel 42, global 808); dağıtılan ikilide `.symtab` yok |
| pspg (`pspg`) | macOS arm64 (`arm64_tahoe`) | `pspg` 5.8.16 | `e5681573d19d67ed4b40a6550f2710347ccb682efd884cca81346e14d59876ea` | `DC2685BA-8F82-3131-B040-C97E16D3F7A2` | 2026-10-19 | nm -U 408 (t=90, T=156) |
| pspg (`pspg`) | Debian 13 arm64 | `pspg` 5.8.9-1 | `d68a73ff962b8e05d7a56af771f89f7f50700741b302aa19afcfd597d53d95cf` | `f5806420e6691674c533d1150684e0d112c78c38` | 2026-10-19 | `pspg-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 244 (yerel 82, global 162); dağıtılan ikilide `.symtab` yok |
| kalign (`kalign`) | macOS arm64 (`arm64_tahoe`) | `kalign` 3.5.1, rebuild 1 | `ccec20454844615f11437cf36fa62ad0c8a91cd1c61283b86eb0e0a3494f1415` | `1323FC43-C05B-3A14-AF0E-4F86CCFED390` | 2026-10-19 | nm -U 293 (t=78, T=211) |
| kalign (`kalign`) | Debian 13 arm64 | `kalign` 1:3.4.0-1+b3 | `1480e3251e42421f8f753199eea9b37e3bf3a2b5d9321bfad312e6c278683082` | `b03e3a7f80dbc5a1e04b4a952ffbab380920ff15` | 2026-10-19 | `kalign-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 229 (yerel 45, global 184); dağıtılan ikilide `.symtab` yok |
| timidity (`timidity`) | macOS arm64 (`arm64_tahoe`) | `timidity` 2.15.0_3 | `bc5ca01fb5056f4cc536981d4b9d8344686e5260e9c687768cd97a8440e351ee` | `52FA3E2D-408D-3C49-8959-03EFA63C11C6` | 2026-10-19 | nm -U 2003 (t=647, T=541) |
| timidity (`timidity`) | Debian 13 arm64 | `timidity` 2.14.0-8.3+b1 | `7d3b751da482fe511a9325c2adc4f0ea266903ab04750533b7dcaf6296942b4f` | `5e3474753e5a9322faa1e6b189d30e0c89ade1e8` | 2026-10-19 | `timidity-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 1457 (yerel 769, global 688); dağıtılan ikilide `.symtab` yok |
| nagios (`nagios`) | macOS arm64 (`arm64_tahoe`) | `nagios` 4.5.14 | `92b54007346a45e26c9122b05ff5ec65da2322c6008a8a82f799aed3b5ca73e4` | `38A81700-94C4-3008-8734-EB0417E7356A` | 2026-10-19 | **SEMBOLSÜZ (K3)**: nm -U 1 satır (t=0, T=1) |
| nagios (`nagios4`) | Debian 13 arm64 | `nagios4-core` 4.4.6-4.1+deb13u1 | `f9b9974fecf27692e138ea79d453063d6cc8ac4ebb1702f88aaf97a89c8ab2f9` | `5f7dd8e5fcc91d090ede31d8aa63d02761d4e866` | 2026-10-19 | `nagios4-core-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 969 (yerel 113, global 856); dağıtılan ikilide `.symtab` yok |
| joe (`joe`) | macOS arm64 (`arm64_tahoe`) | `joe` 4.8 | `18af53afb47d881a2da0f1fa75a325a2e0a4c99d5be7c631c602d1c88b24409d` | `6F3C1022-ED70-31C5-B608-9B1A0A73D1C2` | 2026-10-19 | nm -U 1636 (t=339, T=834) |
| joe (`joe`) | Debian 13 arm64 | `joe` 4.6-2 | `9d95f26543e58f5e98269fcb621c85b1cc3cf6e1e15056c1bc607c351f5caa20` | `89cb9a2278b2360f3dee6388423deac77c2b6897` | 2026-10-19 | `joe-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 1143 (yerel 319, global 824); dağıtılan ikilide `.symtab` yok |
| gnugo (`gnugo`) | macOS arm64 (`arm64_tahoe`) | `gnu-go` 3.8_1 | `b78c5469507fe5a8465594a1f6b4df48866bdb04a19f97b69fe0dfdb75f34312` | `678A3D41-E532-38A8-9EFD-0438B9CE7DA0` | 2026-10-19 | nm -U 6829 (t=2109, T=643) |
| gnugo (`gnugo`) | Debian 13 arm64 | `gnugo` 3.8-13+b1 | `dfa0a4033f5d1b33fd44d802ce4093b0b112863103592d618c01b993dc589dc0` | `f597a25162d365b90adace9e5a9a719cef4ab0a2` | 2026-10-19 | `gnugo-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 2736 (yerel 2091, global 645); dağıtılan ikilide `.symtab` yok |
| alpine (`alpine`) | macOS arm64 (`arm64_tahoe`) | `alpine` 2.26, rebuild 2 | `b804706905d061edc1d123fe207c2c5d7ad851b0437a388175557053257f396c` | `45ECF5C3-FC13-3FB3-89EF-C25627A2B7FE` | 2026-10-19 | nm -U 6925 (t=85, T=4290) |
| alpine (`alpine`) | Debian 13 arm64 | `alpine` 2.26+dfsg-3 | `38805d00ec568154a54d9847eab03bda023b2f366b619acceb9b90b345a37fd4` | `29ac3d416366c7920b879eee0bd9a8c1f8eb795a` | 2026-10-19 | `alpine-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 4470 (yerel 180, global 4290); dağıtılan ikilide `.symtab` yok |
| gnome-builder (`gnome-builder`) | macOS arm64 (`arm64_tahoe`) | `gnome-builder` 50.0, rebuild 1 | `a6ec6f0de7f88937a289896a54c4d3b0c2f11a0e718e61e8871f24aca93af05f` | `E2E696E6-4349-3C20-A923-E60242C6AC64` | 2026-10-19 | nm -U 21675 (t=15614, T=2858) |
| gnome-builder (`gnome-builder`) | Debian 13 arm64 | `gnome-builder` 48.0-2+b1 | `04894ff3e455247a82dfea0867e733fe72b01c0a2658d7b97d0fa6ddbbd6bf7a` | `171b6a7ae78a593d9b09675be05a7a543ee68bf3` | 2026-10-19 | `gnome-builder-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 13300 (yerel 10417, global 2883); dağıtılan ikilide `.symtab` yok |

### 4.2 Stres alt kümesi (5 program × 2 platform)

| Program | Platform | Paket/şişe (sürüm) | sha256 (ölçülecek ikili) | BuildID / UUID | Tarih | Sembol / dbgsym |
|---|---|---|---|---|---|---|
| datamash (`datamash`) | macOS arm64 (`arm64_tahoe`) | `datamash` 1.9 | `694dd560df1e52bef70c847227ae15b27126664a1995446b20da270c70c3c5ba` | `5A657322-66A9-3E2B-8867-CB832792C9B7` | 2026-10-19 | nm -U 538 (t=188, T=252) |
| datamash (`datamash`) | Debian 13 arm64 | `datamash` 1.9-1 | `761cf0d80a278be15196300063a3b9c2cfb982cf2d246f1c2448cdfbba9aed64` | `74a3848d69781df23a2f7d9cd3e82476bb55b285` | 2026-10-19 | `datamash-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 272 (yerel 63, global 209); dağıtılan ikilide `.symtab` yok |
| bison (`bison`) | macOS arm64 (`arm64_tahoe`) | `bison` 3.8.2 | `980fa0b3554e44f6e4ceb755a37cee9ae9435e6a59d130a3819f0a9413eae25a` | `C2A55B78-DDAF-317B-B9C6-0E92C4862E9D` | 2026-10-19 | nm -U 1674 (t=604, T=654) |
| bison (`bison`) | Debian 13 arm64 | `bison` 2:3.8.2+dfsg-1+b2 | `1b69eccf2120221423eec30dc039ea71ec81d230af3b5992596054d248b01bbb` | `610ebef92ad592619de9c2475749d0de26f75a77` | 2026-10-19 | `bison-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 1111 (yerel 488, global 623); dağıtılan ikilide `.symtab` yok |
| tar (`gtar`) | macOS arm64 (`arm64_tahoe`) | `gnu-tar` 1.35_1 | `5646999cee2444b3e07c1602b7f3427b0c05fe19aca6f59009abdf806a6fe6ea` | `0B21B06F-E7D2-37CB-8B8E-1266F08B1689` | 2026-10-19 | nm -U 1510 (t=554, T=552) |
| tar (`tar`) | Debian 13 arm64 | `tar` 1.35+dfsg-3.1 | `3063698897279d7eec9cc81da6c191d1e148b96044f0362d023e4a8285f21df0` | `6539521b82d53a88767aa228bc330f325e4b3ebb` | 2026-10-19 | `tar-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 872 (yerel 341, global 531); dağıtılan ikilide `.symtab` yok |
| sed (`gsed`) | macOS arm64 (`arm64_tahoe`) | `gnu-sed` 4.10 | `130563b48d1c66445de3d00fe83e352e0447a9f946f042c0164cf8c621e1532b` | `C57E9D38-BD0D-3272-BFD5-6D033040B7C0` | 2026-10-19 | nm -U 575 (t=313, T=170) |
| sed (`sed`) | Debian 13 arm64 | `sed` 4.9-2+deb13u1 | `c93b193abfbafa655db11516179c62b7cd9e9ab17389d5ebbae1ecbc40f04179` | `32a2ded6881c43449e1aa1fcfe85d889a8ca32af` | 2026-10-19 | `sed-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 220 (yerel 84, global 136); dağıtılan ikilide `.symtab` yok |
| diffutils (`diff`) | macOS arm64 (`arm64_tahoe`) | `diffutils` 3.12 | `1a6176bc00fc8f529eecf223a9aec75a44d89a30cf6e514e57d2ecd9d59cca6f` | `B0C97FA2-4CEB-37F7-90A4-9A9DC1A0FA8D` | 2026-10-19 | nm -U 593 (t=246, T=211) |
| diffutils (`diff`) | Debian 13 arm64 | `diffutils` 1:3.10-4 | `58d1941ab7a019ac168c51f5cadab65f78b8d8d3fe5dbe2d144b87cf8b1b4c00` | `57fa6cd094e5d7305e52fe716c66c42bbf3bd026` | 2026-10-19 | `diffutils-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 273 (yerel 86, global 187); dağıtılan ikilide `.symtab` yok |

### 4.3 Sabitlemede çıkan sorunlar

1. **K3: nagios ve newlisp.**
   - Mac şişelerinde ikili tamamen soyulmuş: `nm -U` 1 satır.
   - Ön kayıt §4.4 gereği program değişmez; Mac ikilisi kaynaktan derlenecek. Bu ayrı bir iş; Berke'nin bağımlılık onayı gerekebilir.
   - Debian tarafı sağlam: nagios `.symtab` FUNC 969, newlisp 850.
   - Derleme 30 dakikada başarıyla bitmezse K6 ile değişim yapılır.
   - Stres alt kümesinde K3 yok.
2. **K1, K2, K4, K5:** hiçbir programda yok. Değişim yapılmadı.
3. **K4 denetimi.**
   - mosquitto'nun Mac ikilisinde `@loader_path/../lib` rpath'i var, ama bağlı kütüphaneler arasında formülün kendi kütüphanesi yok.
   - gnome-builder'ın rpath'i kendi keg'indeki `lib/gnome-builder` dizinini gösteriyor; bağlı kütüphaneler arasında yine formülün kendi kütüphanesi yok.
   - Öteki 13 programda kendi keg'e bağ yok.
4. **Küçük notlar (sorun değil):**
   - newlisp (Mac): `bin/newlisp`, `bin/newlisp-10.7.5`'e sembolik bağ. Tablodaki sha256 gerçek dosyanın.
   - nagios (Debian): ikili `/usr/sbin/nagios4`.
   - Mac'te tar `bin/gtar`, sed `bin/gsed`, diffutils `bin/diff`.
   - Minimum macOS 26.0 (15 programın hepsinde). SDK 26.0-26.5.

### 4.4 Değişimler

Yok (2026-10-19). Kura sonucu ile sabitlenen küme aynı.

### 4.5 Kaynaktan derlenen Mac ikilileri (2026-10-19)

K3 olan iki programın (§4.3 madde 1) Mac ikilisi ön kayıt §4.4'e göre kaynaktan derlenir. Yöntem `test_seti_kilidi.md` §4.5'tekinin aynısı. İkisi de derlendi. nagios, `gd` bağımlılığı Berke'nin onayıyla kurulduktan sonra derlendi (bkz. "Açık sorunlar" madde 1). İkisinde de K3 koşulu kalktı; K6 yok.

- **Konum:** `targets/dogrulama_seti/mac_kaynaktan/<program>/` (depo ve Spotlight dışında). Alt dizinler: `indirilen/` (kaynak ve şişedeki formül), `src/`, `prefix/`, `gt/<ikili>` ve `gt/<ikili>.dSYM`, `analiz/<ikili>`, `log/`.
- **Betikler:** `targets/dogrulama_seti/mac_kaynaktan/betikler/`. Test setindeki betiklerin kopyası:
  - `ortam.sh`: kök dizin değişti. nagios için sandbox profiline yalnız kendi derleme ağacımızda `file-write-setugid` ve `file-write-mode` izni eklendi (bkz. "Yöntem — nagios").
  - `dogrula.sh`, `bayrak_ozeti.py`, `bolum_ozeti.py`, `bolum_kiyas.py`: değişmedi;
  - `newlisp.sh`, `nagios.sh`: yeni.
- **Ölçümde kullanım:** Gerçek isimler `gt/<ikili>`'nin `nm` çıktısından (ya da dSYM'den) alınır. Analiz girdisi `analiz/<ikili>`'dir; aynı dosyanın `/usr/bin/strip` ile soyulmuş kopyası.

| Program | Formül sürümü, yama | Derleme bayrakları | sha256 (analiz girdisi) | sha256 (GT) | UUID | nm -U t/T (GT) | dSYM UUID eşleşmesi | Export trie boş mu | Minimum macOS |
|---|---|---|---|---|---|---|---|---|---|
| newlisp (`newlisp`) | `newlisp` 10.7.5 (şişe rebuild 0); yama yok | `-w -Os -g -DNEWCONFIG -c` (formülün `CFLAGS`'ı); bağlama `-lm -Wl,-headerpad_max_install_names`; readline ve ffi kapalı (configure-alt, şişedeki gibi); `STRIP=true` | `6f7d33c013d26cd912717fe7ac7383da8645dc6837e70184265edabc4660f4a1` | `02f019ae1b4b1d4623f87f7c8bc598c1613008c03f2fa9621de695ac66032581` | `46C0622D-643A-34F2-9B30-58A19B317BF7` | t=25, T=794 (nm -U 1014 satır) | evet | evet (yalnız `__mh_execute_header`) | 26.0 (SDK 26.5) |
| nagios (`nagios`) | `nagios` 4.5.14 (şişe rebuild 0); yama yok | `-w -Os -g` ve configure tanımları; bağlama `-lssl -lcrypto` (openssl@4), `-Wl,-headerpad_max_install_names`; `install-unstripped` (`install -s` kapalı) | `cefd2b434ef1c17950c5655ea573c9761ee0e7dbc46e8fbc3ecf3a2f9dc43925` | `a3a379f411e5af77be33d96bac88e91a4d20c92ed51ae60eca5b0559324a33b0` | `7B35CE2D-A94D-3033-ACCC-234D65136F4A` | t=128, T=864 (nm -U 1322 satır) | evet | evet (yalnız `__mh_execute_header`) | 26.0 (SDK 26.5) |

**Yöntem — newlisp**
- **Formül:** Şişenin içindeki `.brew/newlisp.rb` kullanıldı. homebrew-core `bf7ada6` ile derleme adımları aynı. Fark: adresler `https`'e geçmiş, bottle bloğu, test yazımı ve yeni bir `mirror` (Debian orig).
  - API'deki güncel sürüm 10.7.5, rebuild 0. arm64_tahoe sha256'sı sabitlenen şişeninki (`cd0b1afe…`).
  - Şişe tab'ı: Homebrew 4.6.10, CLT 26.0 (Xcode 26.0), macOS 26; çalışma bağımlılığı readline 8.3.1.
- **Kaynak:** Formüldeki adres (`www.newlisp.org`) 2026-10-19'da DNS'te çözülmedi.
  - Aynı dosya iki bağımsız yerden alındı: MacPorts distfiles ve Debian'ın `newlisp_10.7.5.orig.tar.gz`'si.
  - İkisi bayt bayt aynı; sha256 formülle eşleşti (`dc2d0ff6…`).
  - Güncel formül de Debian orig'i mirror olarak gösteriyor. Kayıt: `indirilen/KAYNAK.txt`.
- **Derleyici ve ortam:** test seti §4.5 ile aynı.
  - Superenv kabukları, `env -i`, `HOMEBREW_CCCFG=fD` (`-g`).
  - Bağımlılık yolu yalnız `opt/readline` (keg-only).
  - `LC_ALL=en_US.UTF-8`, `TZ=UTC0`, `ZERO_AR_DATE=1`, `SOURCE_DATE_EPOCH=1557679457` (şişe tab'ı), SDK `MacOSX26.sdk`, `make -j6`.
  - `sandbox-exec` ile `/opt/homebrew` altına yazma engelli; `Cellar/` altında iz yok.
- **Formül adımları:**
  - `ENV.append_to_cflags "-DNEWCONFIG -c"`: ortamda `CFLAGS`, `CXXFLAGS`, `OBJCFLAGS`, `OBJCXXFLAGS`.
  - `./configure-alt --prefix=/opt/homebrew/Cellar/newlisp/10.7.5 --mandir=…/share/man`.
  - `make`.
  - `make check`: ATLANDI, çünkü derlenen ikiliyi çalıştırıyor; ikiliyi etkilemez.
  - `make install DESTDIR=…/prefix`. `makefile_install` DESTDIR'i destekliyor; komutlar hata yutan `-` ile çalıştığı için kurulan dosya ayrıca denetlendi.
- **configure-alt sonuçları** (yalnız özet satırları okundu): MAC_OSX, LP64, 64 bit `time_t`, readline kapalı, ffi kapalı.
  - readline denemesi dört bağlama biçiminde de başarısız; şişede de readline bağlı değil.
  - Bağlı kütüphane yalnız libSystem; şişeyle aynı.
- **Strip'in kapatılması:** `make STRIP=true`. configure-alt'ın ürettiği `makefile_build`, bağlamadan sonra `$(STRIP) $(TARG)` çalıştırıyor; şişenin tamamen soyulmuş olmasının sebebi bu. Kurulum `install -m 755` ile, `-s` yok.
- **Derleme günlüğü** (`bayrak_ozeti.py`, `-D` değerleri maskeli): 15 derleme çağrısının hepsinde `-Os -g -w` var. `-O1`/`-O2`/`-O3`, `-Wl,-x`, `-Wl,-S` ve `-s` hiçbirinde yok.
- **Süre:** derleme (configure-alt + make + kurulum + dSYM + soyma) 4 sn. Ön kayıttaki 30 dakika sınırının çok altında.

**Yöntem — nagios**
- **Formül:** Şişenin içindeki `.brew/nagios.rb` kullanıldı.
  - homebrew-core `cc475e638cb4`'teki ("nagios: update 4.5.14 bottle.", 2026-08-05) formülle bottle bloğu dışında aynı. O commit'teki arm64_tahoe sha256'sı sabitlenen şişeninki (`ba4c8b09…`).
  - O dönemki formül `depends_on xcode: :build` içeriyordu. homebrew-core bu şartı 2026-08-11'de kaldırdı (`4a038c5d4952`). Bugünkü formül (`bf7ada6`) derleme adımlarında aynı.
  - Şişe tab'ı: Homebrew 6.0.15, Xcode 26.6 / CLT 26.6, macOS 26.
- **Kaynak:** `brew fetch --build-from-source` ile indirildi; sha256 formülle eşleşti (`dce59f30…`).
- **Ortam:** newlisp ile aynı (`HOMEBREW_CCCFG=fD`, `SOURCE_DATE_EPOCH=1785941675`, SDK `MacOSX26.sdk`, `make -j6`).
  - Bağımlılık listesi, şişe tab'ındaki 20 çalışma bağımlılığı (tab sırasıyla). Hiçbiri keg-only değil; yollar `opt/<bağımlılık>` dizinlerinden.
- **Sandbox düzeltmesi:**
  - İlk deneme kurulumda durdu (53 sn): `install-basic` adımındaki `chmod g+s`, `sandbox-exec` altında reddedildi. sandbox-exec, `(allow default)` olsa da setuid/setgid bitine izin vermiyor.
  - Homebrew'un kendi derleme sandbox'ı yazılabilir yollarda `file-write-setugid` ve `file-write-mode`'a açıkça izin veriyor (`Library/Homebrew/sandbox.rb`). Aynı izin yalnız kendi derleme ağacımız için `ortam.sh`'ye eklendi. `/opt/homebrew` yasağı aynen duruyor.
  - İkinci deneme temiz kaynakla baştan çalıştı ve başarılı oldu. İlk denemenin dizinleri `nagios/deneme1/`'de.
- **Formül adımları:**
  - `./configure` `std_configure_args` ve formülün argümanlarıyla: `--sbindir`, `--sysconfdir=/opt/homebrew/etc/nagios`, `--localstatedir=/opt/homebrew/var/lib/nagios`, `--datadir`, `--libexecdir=/opt/homebrew/sbin`, URL'ler, `--with-httpd-conf`, `--with-ssl=/opt/homebrew/opt/openssl@4`, `--disable-libtool`, `--with-command-group=_www`.
  - Kullanıcı ve grup: `--with-nagios-user` ile `--with-command-user` `id -un`'dan, `--with-nagios-group` `id -gn`'den geliyor; grup değeri formüldeki gibi tırnaklı. configure bunları ikiliye varsayılan değer olarak gömüyor (sapma 4).
  - `make all`.
  - `make install` yerine `make install-unstripped`: nagios'un kendi hedefi; aynı adımlar, yalnız `base/`'deki `install -s` yok.
  - `make install-config` ve `make install-webconf`: yalnız dosya kopyalıyor.
  - Hiçbir adım nagios'u çalıştırmıyor. Hizmet adımları (`install-init`, `install-daemoninit`) formülde yok.
  - Yetkisiz kullanıcının `install -g _www` sahiplik değişikliği uyarı verip geçiyor; CI'da da aynı.
- **configure özeti** (yalnız özet satırları okundu): Event Broker evet, IOBroker poll, kullanıcı/grup yukarıdaki gibi.
  - pkg-config bulundu (superenv kabuğu). SSL için önce pkg-config deneniyor (sapma 8).
  - CGI'lar için gd bulundu.
- **Strip'in kapatılması:** `install-unstripped`. Bağlamada `-s` ya da `-Wl,-x` yok.
- **Derleme günlüğü** (`bayrak_ozeti.py`, configure denemeleri hariç): 55 derleme çağrısının hepsinde `-Os -g -w` var. `-O1`/`-O2`/`-O3`, `-Wl,-x`, `-Wl,-S` ve `-s` hiçbirinde yok.
- **Süre:** iki deneme toplamı 109 sn. Duvar saati 14:00:41 – 14:04:16, yani yaklaşık 3,5 dakika; 30 dakika sınırının çok altında.

**Doğrulamalar (yalnız sayılar; iki değer varsa bizim / şişe)**

| Ölçüt | newlisp | nagios |
|---|---|---|
| Mimari | arm64 / arm64 | arm64 / arm64 |
| nm -U (GT / şişe) | 1014 (t=25, T=794) / 1 (t=0, T=1) | 1322 (t=128, T=864) / 1 (t=0, T=1) |
| nm -U (analiz kopyası) | 1 (yalnız `__mh_execute_header`) | 1 (yalnız `__mh_execute_header`) |
| nm -u (dışarıdan alınan semboller) | 161 / 161 | 182 / 182 |
| Fonksiyon başlangıcı (`dyld_info -function_starts`) | 817 / 811 | 990 / 990 |
| `__TEXT,__text` (bayt) | 223 064 / 224 124 | 356 396 / 356 408 |
| Bağlı kütüphaneler | aynı: yalnız libSystem | aynı: libssl.4 ve libcrypto.4 (openssl@4), libSystem |
| LC_RPATH | yok / yok | yok / yok |
| LC_BUILD_VERSION minos / SDK / ld | 26.0 / 26.5 / 27037.1 — şişe: 26.0 / 26.0 / 1221.4 | 26.0 / 26.5 / 27037.1 — şişe: 26.0 / 26.5 / 1267.0 |
| dSYM: derleme birimi, `DW_TAG_subprogram` | 15, 1620 | 42, 2370 |
| dSYM DWARF sha256 | `f075ca091916fd096ec33168fd111b66d5b4c4b61ac95c1c9ef9afe34a3335d3` | `d59014db14d6cd53333da88723383f53ebf20923c53c3a337b2b2a2b2000990a` |
| Export trie (GT → analiz) | 948 → 1 | 1115 → 1 |
| Kod imzası (GT ve analiz) | geçerli (ad-hoc, linker-signed) | geçerli (ad-hoc, linker-signed) |
| Ön kayıt §4.4 K3 koşulu (GT'de yerel sembol) | sağlandı: t=25 > 0 (Debian `.symtab` yerel FUNC 42) | sağlandı: t=128 > 0 (Debian `.symtab` yerel FUNC 113) |

- **Şişe kipinde kıyas derlemesi (newlisp):** `.tekrar/newlisp-sisekipi/` altında `HOMEBREW_CCCFG=f` ile yapıldı; şişenin bayraklarının birebir aynısı.
  - Sonuç GT kipiyle bütün bölümlerde bayt bayt aynı; fonksiyon adres listesi de aynı. Yani `D` kipinin newlisp'e hiçbir etkisi yok.
  - UUID şişeninkinden farklı (`2FB2E4EF-5C82-35F7-BA4C-A7F3179AB2BB`, şişede `75905649-…`), çünkü şişe başka CLT ile derlenmiş (sapma 2). Test setindeki ssh'te olduğu gibi şişenin kendisini analiz girdisi yapma seçeneği burada yok.
  - Kıyas dosyaları: GT sha256 `5c0a0c555f4398742ff8a40e57b4a2b07a21e422ed393135882d920a08be365f`, soyulmuş kopya `bdfad97fea65baf4b126364955899fb3521888c9d125ddb25b7b3c7220070b13`. Ölçümde kullanılmaz.
- **Şişe kipinde kıyas derlemesi (nagios):** `.tekrar/nagios-sisekipi/` altında, aynı yöntemle.
  - GT kipiyle bütün bölümlerde bayt bayt aynı; fonksiyon adres listesi de aynı. `D` kipinin nagios'a etkisi yok.
  - Şişeye göre fonksiyon sayısı aynı (990), ama adres listesi farklı. `__text` 12 bayt küçük, `__cstring` 1 bayt büyük, `__unwind_info` 8 bayt büyük.
  - UUID farklı (`F29A208E-4478-311B-A5E9-303607129CDE`, şişede `38A81700-…`). Sebep: araç zinciri (Xcode 26.6 ↔ CLT 27.0), bağımlılıklar ve gömülü kullanıcı adı (sapmalar 2–4).
  - Adresler örtüşmediği için şişenin kendisini analiz girdisi yapma seçeneği burada da yok.
  - Kıyas dosyaları: GT sha256 `a3cb33889b0542d2815811b51c08ece811cf37b2f47c4ba8b96e72b287f3761f`, soyulmuş kopya `94c7b4cf537531af9582a6adda67210727a4b1ed470b0f29783c3c9d2a792e85`. Ölçümde kullanılmaz.

**Şişeden sapmalar — newlisp**
1. **Amaçlananlar:** `-g` (debug map ve dSYM) ve `makefile_build`'deki `strip` adımının kapatılması.
2. **Derleyici:** CLT 27.0 (Apple clang 21.0.0, ld 27037.1); şişe CLT 26.0 ile derlenmiş.
   - Fonksiyon başlangıcı 817 / 811, `__text` 1060 bayt (%0,47) küçük, `__TEXT,__const` 232 bayt büyük, `__unwind_info` 16 bayt büyük.
   - `__cstring` ve dışarıdan alınan semboller (161) şişeyle aynı. Yapılandırma aynı, fark kod üretiminde.
3. **SDK:** 26.5 (şişe 26.0). Minimum macOS aynı (26.0).
4. **readline:** bugün 8.3.6, şişe döneminde 8.3.1. İkisinde de configure-alt readline'ı kapatıyor ve ikili readline'a bağlanmıyor; etkisi yok.
5. **`make check` atlandı:** ikiliyi etkilemez.
6. **Kaynağın alındığı yer:** formüldeki adres yerine MacPorts ve Debian kopyası; sha256 aynı, yani dosya aynı.
7. **Yol eşlemesi (`D` kipi):** `-ffile-prefix-map` ve `-Wl,-oso_prefix` yok. Kıyas derlemesine göre newlisp'te ölçülebilir etkisi yok. GT'nin debug map'i mutlak derleme yollarını içeriyor; analiz kopyasında debug map yok.
8. **Yalıtım (kural 1 ve 8) kaydı:**
   - .c/.h dosyalarına ve ikili içeriğine bakılmadı. `nm` yalnız sayım için çalıştı; `-D` değerleri maskeli basıldı.
   - Strip, kurulum ve readline mekanizmasını bulmak için `configure-alt` ile `Makefile`'ın ilgili satırları okundu. Bu satırlarda configure-alt'ın kendi deneme programlarından birkaç satır vardı (readline kütüphanesinin API adları; newlisp'in kendi fonksiyonları değil).
   - Derlenen newlisp çalıştırılmadı.

**Şişeden sapmalar — nagios**
1. **Amaçlananlar:** `-g` (debug map ve dSYM) ve `install -s`'nin kapatılması (`install-unstripped`).
2. **Araç zinciri:** Şişe, formülün o dönemki `depends_on xcode: :build` şartıyla Xcode 26.6 / CLT 26.6 araçlarıyla (ld 1267.0) derlenmiş. Bu makinede Xcode yok; CLT 27.0 (Apple clang 21.0.0, ld 27037.1) kullanıldı. homebrew-core bu şartı 2026-08-11'de kaldırdı.
   - SDK ikisinde de 26.5, minimum macOS 26.0.
   - Etkisi: fonksiyon sayısı aynı (990), `__text` 12 bayt küçük, `__unwind_info` 8 bayt büyük, fonksiyon adresleri kayıyor.
3. **Bağımlılık sürümleri** (şişe tab'ı ↔ 2026-10-19 kurulu):

    | Bağımlılık | Şişe derlemesinde | 2026-10-19 kurulu |
    |---|---|---|
    | openssl@4 (nagios'un bağlandığı tek Homebrew kütüphanesi) | 4.0.1, şişe rebuild 1 | 4.0.3 |
    | gd | 2.3.3_6, rebuild 0 | 2.3.3_6, rebuild 0 (bugün kuruldu) |
    | libavif | 1.4.2 | 1.4.2 (bugün kuruldu) |
    | libpng | 1.6.58 | 1.6.59 |
    | freetype | 2.14.3 | 2.15.0 (yeni bağımlılık brotli ile) |
    | fontconfig | 2.18.2 | 2.18.3 |
    | aom / libvmaf | 3.14.1 / 3.2.0 | 3.15.2 / 3.2.1 |
    | xz | 5.8.3 | 5.8.4 |
    | ca-certificates | 2026-07-16 | 2026-09-25 |
    | jpeg-turbo, dav1d, giflib, webp, libtiff, lz4, zstd, json-c, libunistring, gettext | 3.2.0, 1.5.4, 6.1.3, 1.6.0, 4.7.2, 1.10.0, 1.5.7_1, 0.19, 1.4.2, 1.0 | aynı sürümler |

    - `bin/nagios` yalnız openssl@4'e bağlanıyor; öteki bağımlılıklar CGI'lar içindir ve ölçülen ikiliye girmiyor.
    - Bağlı kütüphane kümesi ve dışarıdan alınan semboller (182) şişeyle aynı.
4. **Gömülü kullanıcı ve makine bilgisi:** formül `--with-nagios-user`, `--with-command-user` ve `--with-nagios-group` değerlerini derleyen makinenin `id -un` / `id -gn` çıktısından alıyor; configure bunları ikiliye gömüyor.
   - Bizde derleyen kullanıcının adı var, şişede CI kullanıcısınınki. CI kullanıcısının adı bilinmiyor; şişe içeriğine bakılmadı.
   - `__cstring`'deki +1 baytlık fark buradan gelebilir; doğrulanmadı.
5. **Kurulum hedefi:** `install` yerine `install-unstripped`; fark yalnız `install -s`.
6. **Sandbox izni:** `file-write-setugid` izni yalnız kurulum dosyalarının kipini etkiliyor (`chmod g+s`); ikiliyi etkilemez.
7. **Yol eşlemesi (`D` kipi):** kıyas derlemesine göre nagios'ta ölçülebilir etkisi yok.
8. **pkg-config:**
   - Bu makinede pkgconf kurulu; superenv kabuğu üzerinden çalışıyor. nagios'un configure'u SSL için önce pkg-config'i deniyor.
   - Şişe derlemesinde pkgconf'un kurulu olup olmadığı bilinmiyor; formülün bağımlılığı değil.
   - İki yol da openssl@4'e bağlıyor; bağlı kütüphaneler ve dışarıdan alınan semboller şişeyle aynı.
9. **Yalıtım (kural 1 ve 8) kaydı:**
   - .c/.h dosyalarına, ikili içeriğine ve şişedeki yapılandırma dosyalarına bakılmadı.
   - Strip, kurulum, kullanıcı/grup, pkg-config ve SSL mekanizması için `Makefile.in`, `base/Makefile.in` ve `configure`'un ilgili satırları okundu.
   - configure çıktısında gd kütüphanesinin iki API adı görüldü; nagios'un kendi fonksiyonları değil. Bu belgeye yazılmadı.
   - `nm` yalnız sayım için çalıştı. Derlenen nagios ve CGI'lar çalıştırılmadı.

**Açık sorunlar (karar ana oturumun)**
1. **KAPANDI — nagios'un `gd` bağımlılığı (2026-10-19):** ana oturum, Berke'nin onayıyla, `HOMEBREW_NO_INSTALL_UPGRADE=1` ile gd 2.3.3_6 ve libavif 1.4.2'yi kurdu; mevcut hiçbir paket yükseltilmedi. Sonra nagios derlendi (tablo). Onay bekleme süresi ön kayıt §4.4'e göre 30 dakikaya sayılmadı.
2. **Silinebilecek dizinler (onay gerekiyor):** yalnız kıyas ya da kayıt içindir.
   - `.tekrar/newlisp-sisekipi/` (yaklaşık 9 MB);
   - `.tekrar/nagios-sisekipi/` (32 MB);
   - `nagios/deneme1/` (41 MB, kurulumda duran ilk deneme).
