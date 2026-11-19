# ÖK-V — bağımsız sınama nüfusu (NUFUS)

Plan: `ozkod/PLAN.md` "ÖK-V". İndirme onayı: `KARARLAR.md` A-4. Betik: `scripts/measurement/ozkod_nufus_kur.py` (indirme, imza / sha256 doğrulaması ve açma işlevleri `scripts/arge/olcu/tabaka_indir.py`'den). Veri kökü: `~/karadul_olcum/ozkod_nufus/` (Spotlight dışı): `indir/` (indirilen dosyalar, `indir/indeks/` dizinler), `x_<paket>/` (her `.deb` ayrı dizine açıldı), `nufus.json` (ELF dökümü ve sayılar).

**Körlük.** "Kör" taraftaki paketlerin sembol adları, dizgileri ve kaynak kodu okunmadı ve hiçbir yere yazılmadı. Bu belgede iki tarafta da yalnız sha256, BuildID, boyut, ELF sayısı ve sembol SAYISI var; hiçbir GT adı geçmez. Betik "kör" paketlerin ELF yollarını ekrana basmaz (yol yalnız `nufus.json`'da, adım 5'teki koşu için durur).

Bu belgenin §1–§3'ü **hiçbir paket indirilmeden önce** yazıldı (2026-11-19 08:33 UTC; betiklerin o anki sha256'ları: `ozkod_nufus_kur.py` `3914877393b86ffe…`, `tabaka_indir.py` `6432473d5934e674…`, `aday_paket.py` `7f9e6ffa96d83f90…`). §4 ve sonrası indirmeden sonra eklendi.

## 1. Aday listesi (kilitli)

ÖK-V adım 1'in 24 paketi. Liste tek kaynaktan okunur: `scripts/arge/ozkod/aday_paket.py` `ADAYLAR` (ÖZ KOD hattı, `BULGULAR.md` §6). Sıra o betiğin sırasıdır. postgresql-17 PLAN'da isteğe bağlıydı; A-4 24 paketi (78,0 MiB) onayladığı için listede.

bash, nginx, irssi, hexchat, jq, gawk, tcl8.6, libtcl8.6, python3.13-minimal, libpython3.13-stdlib, lua-socket, lua-cjson, postgresql-17, gedit, evince, mousepad, xfce4-terminal, geany, pidgin, xterm, mc, busybox, lighttpd, neomutt.

- Kaynak: Debian 13 (trixie) arm64; ikili paket `deb.debian.org/debian` (trixie, trixie-updates) ya da `deb.debian.org/debian-security` (trixie-security), hata ayıklama paketi `deb.debian.org/debian-debug` (trixie-debug, trixie-proposed-updates-debug) ya da `deb.debian.org/debian-security-debug`.
- Sürüm kuralı: aynı sürümde `-dbgsym` eşi bulunan en yüksek ikili sürüm (dpkg sırası). Eşi yoksa paket "dbgsym yok" diye yazılır; aynı kaynağın hata dizinindeki öbür paketler bilgi olarak dökülür (python3.13 için hata ayıklama paketinin adı böyle doğrulanır, PLAN adım 2).
- Kilitli setler: test ve doğrulama seti kilit belgelerinden (`docs/arge/test_seti_kilidi.md`, `dogrulama_seti_kilidi.md`) yalnız program / paket adları betikle okunur (`tabaka_indir.kilitli_adlar`); paket adları, hata ayıklama paketi adları ve kaynak paket adlarıyla kesişimi boş olmalı. Sonuç §4'te.

## 2. Bölme kuralı (ön kayıt; indirmeden ve koşudan önce, sayılara bakmadan)

> **ÖK-V bölme kuralı.** Her paket için `sha256(paket adının UTF-8 baytları)` hesaplanır (satır sonu yok). İlk bayt çiftse paket **"ayar"**, tekse **"kör"** tarafındadır. Aynı kaynaktan gelen paketler aynı tarafa düşer: grubun ilk paketinin (listedeki sıraya göre) tarafına. Gruplar PLAN adım 4'te açıkça sayılanlardır: {tcl8.6, libtcl8.6}, {python3.13-minimal, libpython3.13-stdlib}, {lua-socket, lua-cjson}. Dizin okununca `Source` alanı denetlenir; bu üç grubun dışında aynı kaynağı paylaşan paket çıkarsa betik bunu "tanımsız kaynak grubu" diye bildirir ve aynı kural (ilk paketin tarafı) uygulanır. "Ayar" tarafında ÖK-5 adım 4'teki iki şey okunur ve dondurulur; "kör" tarafta yalnız sayılır. Bölme sonradan değiştirilmez.

Hesap (`PYTHONDONTWRITEBYTECODE=1 python -I scripts/measurement/ozkod_nufus_kur.py bolme`):

| # | paket | sha256(ad) ilk bayt | ham taraf | grup ilki | taraf |
|---:|---|---:|---|---|---|
| 1 | bash | 55 | kör | bash | **kör** |
| 2 | nginx | 91 | kör | nginx | **kör** |
| 3 | irssi | 81 | kör | irssi | **kör** |
| 4 | hexchat | 180 | ayar | hexchat | **ayar** |
| 5 | jq | 200 | ayar | jq | **ayar** |
| 6 | gawk | 188 | ayar | gawk | **ayar** |
| 7 | tcl8.6 | 13 | kör | tcl8.6 | **kör** |
| 8 | libtcl8.6 | 190 | ayar | tcl8.6 | **kör** |
| 9 | python3.13-minimal | 227 | kör | python3.13-minimal | **kör** |
| 10 | libpython3.13-stdlib | 185 | kör | python3.13-minimal | **kör** |
| 11 | lua-socket | 237 | kör | lua-socket | **kör** |
| 12 | lua-cjson | 104 | ayar | lua-socket | **kör** |
| 13 | postgresql-17 | 158 | ayar | postgresql-17 | **ayar** |
| 14 | gedit | 104 | ayar | gedit | **ayar** |
| 15 | evince | 6 | ayar | evince | **ayar** |
| 16 | mousepad | 93 | kör | mousepad | **kör** |
| 17 | xfce4-terminal | 99 | kör | xfce4-terminal | **kör** |
| 18 | geany | 105 | kör | geany | **kör** |
| 19 | pidgin | 240 | ayar | pidgin | **ayar** |
| 20 | xterm | 223 | kör | xterm | **kör** |
| 21 | mc | 107 | kör | mc | **kör** |
| 22 | busybox | 157 | kör | busybox | **kör** |
| 23 | lighttpd | 170 | ayar | lighttpd | **ayar** |
| 24 | neomutt | 142 | ayar | neomutt | **ayar** |

Ayar: 9 paket; kör: 15 paket.

Not: grup kuralı iki paketi ham taraflarından çevirdi (libtcl8.6 ve lua-cjson "ayar" → "kör"). Bu, kuralın kendisidir; sonuca bakılarak yapılmış bir seçim değildir.

## 3. Ölçülecek ELF'in seçim kuralı (ön kayıt; paketler açılmadan önce)

PLAN adım 3: "ana ikili; paylaşımlı kitaplık paketlerinde `.so`". Mekanik karşılığı (`ozkod_nufus_kur.elf_sec`):

1. **Kitaplık paketi** (adı `lib` ya da `lua-` ile başlayan: libtcl8.6, libpython3.13-stdlib, lua-socket, lua-cjson): paketteki bütün ELF paylaşımlı nesneler (`ET_DYN`).
2. **Program paketi** (öbür 20 paket): paketteki **en büyük** (bayt) ELF dosyası (sembolik bağlar sayılmaz). Programın kodu kimi pakette yürütülebilir dosyada, kimi pakette programın kendi özel kitaplığında durur; "en büyük ELF" kuralı ikisini aynı biçimde yakalar ve yol adına bakmayı gerektirmez.
3. **C++ ikili ölçü dışı** (PLAN adım 3): seçilen ELF'in `.dynsym` içe aktarımlarından biri `ks1_olc.CPP_ISARETLERI` öneklerinden birini taşıyorsa (`ks1_olc.cpp_ikili_mi`'nin GT'siz, ELF üstündeki karşılığı: `ozkod_nufus_kur.cpp_mi`) ELF ölçü dışıdır. Yerine başka ELF seçilmez.
4. **GT:** seçilen ELF'in BuildID'si hata ayıklama paketindeki `usr/lib/debug/.build-id/xx/yyyy.debug` ile eşleşmeli ve `scripts/measurement/function_f1.py` `extract_gt` (BuildID eşitliği + soyulmuşluk denetimi) hatasız geçmeli. Geçmeyen ELF "GT yok" diye yazılır; yerine başka ELF seçilmez.
5. Paketteki öbür ELF'ler sayılır (ELF sayısı, BuildID eşleşen sayısı) ama ölçülmez; sonraki bir oturum nüfusu genişletmek isterse dökümü `nufus.json`'da hazırdır.

---

*Aşağısı indirmeden sonra eklendi (dizinler 2026-11-19T08:36:40Z; paket indirme / doğrulama kaydı `nufus.json` 2026-11-19T08:47:12Z).*

## 4. Dizinler, imza ve kilit denetimi

Komut: `PYTHONDONTWRITEBYTECODE=1 python -I scripts/measurement/ozkod_nufus_kur.py dizin --kok ~/karadul_olcum/ozkod_nufus` → `~/karadul_olcum/ozkod_nufus/indir/secim.json` (sha256 `6afc061c277baca6…`, 2026-11-19T08:36:40Z).

Doğrulama zinciri: her dizinin `InRelease`'i indirildi; imzası `gpgv` (Homebrew, yerel) ile `debian-archive-keyring` 2025.1 paketindeki anahtar halkalarına karşı doğrulandı (paket `deb.debian.org`'dan HTTPS ile alındı, sha256 `9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac` trixie dizinindeki değerle eşleşti); `Packages.xz`'in sha256'sı imzalı içerikle karşılaştırıldı.

| dizin | bileşen | mimari | Packages.xz sha256 | bayt | imza | imzalayan anahtar(lar) | imzalı sha256 tutuyor |
|---|---|---|---|---:|---|---|---|
| https://deb.debian.org/debian/dists/trixie | main | arm64 | `be16b37b2f740f066ea93d35d56f04f94d63693e5a3eb421b052bf86fae75bcd` | 9614192 | evet | 41587F7DB8C774BCCF131416762F67A0B2C39DE4, 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian/dists/trixie-updates | main | arm64 | `eea860c5dea11680e64299adb2736c2367c4235763a66f2b70ca61ce1b51978a` | 1108 | evet | 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-security/dists/trixie-security | main | arm64 | `2c6af03db540ce3d5e6a720b9c70f826c567a6ef335b7c3b63db0ac3a0492290` | 326192 | evet | 89C87ACEA5DD6B8E6A7068808E9F831205B4BA95, B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8 | evet |
| https://deb.debian.org/debian-debug/dists/trixie-debug | main | arm64 | `ff6185861c668d9038f36fd826a14fd13a05d039d74b2ef9b59fd63ad38a1560` | 3689184 | evet | 41587F7DB8C774BCCF131416762F67A0B2C39DE4, 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-debug/dists/trixie-proposed-updates-debug | main | arm64 | `f094cf95f72c1bcad216cbea73bacd53ab8bcce978bf2b7ed98ee36ad82174a4` | 152552 | evet | 4CB50190207B4758A3F73A796ED0E7B82643E131, B8E5F13176D2A7A75220028078DBA3BC47EF2265 | evet |
| https://deb.debian.org/debian-security-debug/dists/trixie-security-debug | main | arm64 | `ea87f3998bbdd9ad3805548cdef58b379e9f61614d85e923d01cebd54d5e96fa` | 231724 | evet | 89C87ACEA5DD6B8E6A7068808E9F831205B4BA95, B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8 | evet |

- **Kilit süzgeci** (`tabaka_indir.kilitli_adlar` + `kilit_suzgeci`): kilit belgelerinden 136 ad okundu (`test_seti_kilidi.md` sha256 `ec1dbd3622387cb4…`, `dogrulama_seti_kilidi.md` sha256 `d8474d6a56db6139…`). 24 paket adı + hata ayıklama paketi adları + kaynak paket adlarıyla **kesişim boş**.
- **Yakınlık (bilgi, dışlama değil):** `lua-socket`, `lua-cjson` (ve `-dbgsym`'leri) adlarının `-` ile ayrılmış bir parçası test setinin stres alt kümesindeki `lua` ile aynı. Bu paketler Lua yorumlayıcısı değil, ayrı kaynak paketlerinden (`luasocket`, `lua-cjson`) C modülleridir; kilitli program listede yok. Ana oturumun bilgisi için yazıldı.
- **Kaynak grubu denetimi:** `Source` alanına göre §2'deki üç grubun dışında aynı kaynağı paylaşan paket yok ("tanımsız kaynak grubu: []"). Bölme değişmedi.
- **Sürümler:** 22 paket için aynı sürümde `-dbgsym` eşi bulundu: 19'u `trixie` + `trixie-debug`, 3'ü (nginx, jq, postgresql-17) `trixie-security` + `trixie-proposed-updates-debug`. Ekim'deki dizine göre değişenler (BULGULAR §6 ile kıyas): nginx `1.26.3-3+deb13u10` (Ekim: `+deb13u7`), jq `1.7.1-6+deb13u4` (`+deb13u3`), postgresql-17 `17.12-0+deb13u1` (`17.11-0+deb13u1`).

## 5. python3.13: hata ayıklama paketi (PLAN adım 2'nin doğrulaması)

- Hata ayıklama arşivinde (`trixie-debug`, `trixie-proposed-updates-debug`, `trixie-security-debug`) `python3.13` kaynağından **hiç paket yok**; `python3.13-minimal-dbgsym` ve `libpython3.13-stdlib-dbgsym` yok.
- Ana arşivde aynı kaynaktan ve aynı sürümde (`3.13.5-2+deb13u5`) `Build-Ids` alanı dolu tek paket `python3.13-dbg` (53 360 552 bayt; dizindeki `Build-Ids` alanında 52 BuildID). `libpython3.13-dbg`'nin `Build-Ids` alanı boş.
- **Usul eklemesi (betiğe paketler indirilmeden önce, dizin okunduktan sonra eklendi; bu satırlar indirmeden sonra yazıldı):** §1'deki "aynı sürümde `-dbgsym`" kuralı bu iki pakette sonuç vermediği için betik şu yolu izledi: ikili paket indirilip açıldı, ELF'lerinin BuildID'leri hesaplandı; `Build-Ids` alanı bu BuildID'lerle kesişen ana arşiv paketi (yalnız `python3.13-dbg`) indirildi. Bu, A-4'te Berke'ye söylenen 78,0 MiB'a 50,9 MiB ekledi (toplam ÖK-V indirmesi 129,1 MiB; 2 GiB sınırının altında).
- Sonuç §7'de: python3.13-minimal'in 1 ELF'i ve libpython3.13-stdlib'in 45 ELF'inin 45'i `python3.13-dbg`'deki `.debug` dosyalarıyla BuildID düzeyinde eşleşti.

## 6. İndirilen dosyalar ve sha256

Komut: `PYTHONDONTWRITEBYTECODE=1 python -I scripts/measurement/ozkod_nufus_kur.py kur --kok ~/karadul_olcum/ozkod_nufus` (çıktı `~/karadul_olcum/ozkod_nufus/nufus.json`; tablolar `… rapor --kok ~/karadul_olcum/ozkod_nufus` ile yeniden üretilir). "= dizin": dosyanın sha256'sı ve boyutu imzalı dizindeki `SHA256` / `Size` ile aynı.

| paket | taraf | dosya | sürüm | bayt | sha256 (dosya) | = dizin |
|---|---|---|---|---:|---|---|
| bash | kör | `bash_5.2.37-2+b10_arm64.deb` | 5.2.37-2+b10 | 1456340 | `9e2d2b3646b250f53be79b6128d9cff5e99cc5ff4a8c84e58efab59ad9bb0ddc` | evet |
| bash | kör | `bash-dbgsym_5.2.37-2+b10_arm64.deb` | 5.2.37-2+b10 | 1469424 | `3a0eca30da6fd1d4a656affc2f84676955754e524ba30b1302c285d02664fd65` | evet |
| nginx | kör | `nginx_1.26.3-3+deb13u10_arm64.deb` | 1.26.3-3+deb13u10 | 572680 | `3c437f0c988bd93a5222d4ecd52e4de2c0af1a2fcba2453a619a73908dbcf04e` | evet |
| nginx | kör | `nginx-dbgsym_1.26.3-3+deb13u10_arm64.deb` | 1.26.3-3+deb13u10 | 1313480 | `190ab1689d678c868188773763f1bac1cc1d65e7b41838ae8a4d1ef3195fef07` | evet |
| irssi | kör | `irssi_1.4.5-1+b5_arm64.deb` | 1.4.5-1+b5 | 1152952 | `937e1e902ae52350086c4e62893a2965e3ba3e48bbfaac1641513798259031fa` | evet |
| irssi | kör | `irssi-dbgsym_1.4.5-1+b5_arm64.deb` | 1.4.5-1+b5 | 1713516 | `ba2f83b6a9c428e3787ccb5b8c8c562ddf4a8fd63b9381adabdb27c258e42957` | evet |
| hexchat | ayar | `hexchat_2.16.2-1+b6_arm64.deb` | 2.16.2-1+b6 | 308804 | `1cb8fd2c33822deaa01114c85b45d8d4e9979d5c1d9a5742d4343991fa1f8d5d` | evet |
| hexchat | ayar | `hexchat-dbgsym_2.16.2-1+b6_arm64.deb` | 2.16.2-1+b6 | 896724 | `ca00d754a067731ca1e007a51e38267292279180296116866a6694401819853b` | evet |
| jq | ayar | `jq_1.7.1-6+deb13u4_arm64.deb` | 1.7.1-6+deb13u4 | 78424 | `5d77ae282441d3ef0560141d55b4ac562d2cba7a873eb9ad7572ccfe69471ebf` | evet |
| jq | ayar | `jq-dbgsym_1.7.1-6+deb13u4_arm64.deb` | 1.7.1-6+deb13u4 | 19416 | `0e5bfbb519ebfaa6e09b05e1da5970fd162cf20f4e7540bb1d0273f5a0c28c87` | evet |
| gawk | ayar | `gawk_5.2.1-2+b2_arm64.deb` | 1:5.2.1-2+b2 | 643936 | `0c040f686b0dd34387c0aa69848dd9f29741043821a843b480c38a1cf5956142` | evet |
| gawk | ayar | `gawk-dbgsym_5.2.1-2+b2_arm64.deb` | 1:5.2.1-2+b2 | 1163284 | `7ea02d1ddb35e8df08ba49216904fa64b10ed9bbca18d8dc19b25d9197730d6b` | evet |
| tcl8.6 | kör | `tcl8.6_8.6.16+dfsg-1_arm64.deb` | 8.6.16+dfsg-1 | 120708 | `1cd867d99819b5464af416967558a54358f71770fabafcc737baab854caa4e44` | evet |
| tcl8.6 | kör | `tcl8.6-dbgsym_8.6.16+dfsg-1_arm64.deb` | 8.6.16+dfsg-1 | 4320 | `bfce68a8affacf899a182e28a75d4d538c267ee7e7557bc223f155c32f2df8ee` | evet |
| libtcl8.6 | kör | `libtcl8.6_8.6.16+dfsg-1_arm64.deb` | 8.6.16+dfsg-1 | 983536 | `7a9f7eda696d505657a6cf54550fe50d4684bd79dc888d6b72f486f8066a14f5` | evet |
| libtcl8.6 | kör | `libtcl8.6-dbgsym_8.6.16+dfsg-1_arm64.deb` | 8.6.16+dfsg-1 | 1906256 | `960c9ed2d597960183417031f79146be91121ebd131bd20c14e6ef4337ff4ec2` | evet |
| python3.13-minimal | kör | `python3.13-minimal_3.13.5-2+deb13u5_arm64.deb` | 3.13.5-2+deb13u5 | 2008016 | `95237a3ad99bf9366308e16f7c79449c9371c4cff9c883772fb7c254652467eb` | evet |
| python3.13-minimal | kör | `python3.13-dbg_3.13.5-2+deb13u5_arm64.deb` | 3.13.5-2+deb13u5 | 53360552 | `7cedf3d17796da6cf0c0116b24927a1b3a69bcf5cd461ae09fc6a9eb23a9805b` | evet |
| libpython3.13-stdlib | kör | `libpython3.13-stdlib_3.13.5-2+deb13u5_arm64.deb` | 3.13.5-2+deb13u5 | 1894712 | `d1178d24e4d143cc6c577d9dc0f26dd982efccc2e600d25ce86361f168a22be0` | evet |
| lua-socket | kör | `lua-socket_3.1.0-1+b2_arm64.deb` | 3.1.0-1+b2 | 80724 | `4c0a95acc43dd6bd547c2e12bd90fc235b24792d793f56338af670ed28f4560a` | evet |
| lua-socket | kör | `lua-socket-dbgsym_3.1.0-1+b2_arm64.deb` | 3.1.0-1+b2 | 535612 | `6aad4d2ec01664a18fe80a1ceea6b286737db95d37d8c2a69b4ba3bb4dd7d2e8` | evet |
| lua-cjson | kör | `lua-cjson_2.1.0+dfsg-2.2+b2_arm64.deb` | 2.1.0+dfsg-2.2+b2 | 19792 | `8ba92decf07bd8e34a69d9295cdec9f79e5ad6c7fd88825cdb06965201986794` | evet |
| lua-cjson | kör | `lua-cjson-dbgsym_2.1.0+dfsg-2.2+b2_arm64.deb` | 2.1.0+dfsg-2.2+b2 | 106204 | `3a0999804f04d6c2e3308825a8eced22e2e3c8e7dbb889bcaa1e8cfbfa5abaa6` | evet |
| postgresql-17 | ayar | `postgresql-17_17.12-0+deb13u1_arm64.deb` | 17.12-0+deb13u1 | 16298464 | `7d89ed7e3b0a746697db80257d8e5cbf1e7efe421f60b46400eaaa50712e3399` | evet |
| postgresql-17 | ayar | `postgresql-17-dbgsym_17.12-0+deb13u1_arm64.deb` | 17.12-0+deb13u1 | 19724632 | `577faca225f36dd9586556d1e3d0e9b0b771deb52425a0630de0d7b9c2070f07` | evet |
| gedit | ayar | `gedit_48.1-4_arm64.deb` | 48.1-4 | 283008 | `6572ba8974abe229f1558566d758d59df6bc501bd64ad65f35786722bf7fe590` | evet |
| gedit | ayar | `gedit-dbgsym_48.1-4_arm64.deb` | 48.1-4 | 813136 | `ad9567d9708604d86fce7ae41d859d697c2ed6a76ae0d9ac6a375e9a10b99042` | evet |
| evince | ayar | `evince_48.1-3+deb13u1_arm64.deb` | 48.1-3+deb13u1 | 274688 | `6f05371aab066ccc63891ad2cb03c2afc3ee197ed5f41af1aec7d9da167ecdfd` | evet |
| evince | ayar | `evince-dbgsym_48.1-3+deb13u1_arm64.deb` | 48.1-3+deb13u1 | 598160 | `d64961dca633e94990f83452cbe07dfc5b703ca4c82bc0b27bf2002d16a09ee2` | evet |
| mousepad | kör | `mousepad_0.6.3-1_arm64.deb` | 0.6.3-1 | 315008 | `a00b9abfe94f201c713601950ef66cafff3fa3110de0d7944373c313185803e0` | evet |
| mousepad | kör | `mousepad-dbgsym_0.6.3-1_arm64.deb` | 0.6.3-1 | 43516 | `14c67e13af775558d95423ed818cbe285cec066900906240b4f2d99f818a6795` | evet |
| xfce4-terminal | kör | `xfce4-terminal_1.1.4-1_arm64.deb` | 1.1.4-1 | 409272 | `b0fe0388a71231b5ce591a963939c095b34e2c52ce02e01e5973726e88412ef8` | evet |
| xfce4-terminal | kör | `xfce4-terminal-dbgsym_1.1.4-1_arm64.deb` | 1.1.4-1 | 286352 | `37ae684d3d4e2b706875c50dd42fb12b37e96131ea7de4a67408cf40d4a06743` | evet |
| geany | kör | `geany_2.0-2_arm64.deb` | 2.0-2 | 1908884 | `7ba36a226eea7ec60a156b60357146fcd90a5e8fb8db23dac5d3db46ffaaa8c1` | evet |
| geany | kör | `geany-dbgsym_2.0-2_arm64.deb` | 2.0-2 | 9548492 | `0dbe64716e3594de3fc25758294377962c83599a1a23d51ec69ff6fb0c09c149` | evet |
| pidgin | ayar | `pidgin_2.14.14-1_arm64.deb` | 2.14.14-1 | 522476 | `df6eaedaeed4e80ae1bb704e381e904489de80b761bc124b983db5fa31096aff` | evet |
| pidgin | ayar | `pidgin-dbgsym_2.14.14-1_arm64.deb` | 2.14.14-1 | 1558012 | `4aedff8c58cacc264586d2d1dd51645400b1de59cc4b2bdcf9c7ca9b53468504` | evet |
| xterm | kör | `xterm_398-1_arm64.deb` | 398-1 | 858228 | `ea328eb319bda3e1be85042aba65c9be8fda1108400f13714794a280caef7802` | evet |
| xterm | kör | `xterm-dbgsym_398-1_arm64.deb` | 398-1 | 842852 | `d8c6ae672460fa810bb7df09a03df893a19031f648dc07219749b91052aecc69` | evet |
| mc | kör | `mc_4.8.33-1+deb13u1_arm64.deb` | 3:4.8.33-1+deb13u1 | 516544 | `3b3e6d73b7305ef77e4ebc5a13277ce36704dc5d7a43d04034710d71429722ac` | evet |
| mc | kör | `mc-dbgsym_4.8.33-1+deb13u1_arm64.deb` | 3:4.8.33-1+deb13u1 | 1537668 | `e1aa250ef634bc6a11ac3153bc0c112a391491aea9f02e493c14aed647ea8371` | evet |
| busybox | kör | `busybox_1.37.0-6+b9_arm64.deb` | 1:1.37.0-6+b9 | 453884 | `38bc174119c9f1f07073d1dc28464b672eb0a1402fdee3022198e3138420e3a0` | evet |
| busybox | kör | `busybox-dbgsym_1.37.0-6+b9_arm64.deb` | 1:1.37.0-6+b9 | 1477872 | `e8d27929d97eb0a0d8513aaaab2ce4c4499325f2ca24ba4cde55e6abced64e29` | evet |
| lighttpd | ayar | `lighttpd_1.4.79-2_arm64.deb` | 1.4.79-2 | 350144 | `52b3dd58f9bf55154d00d8f54a914bdcb88113ba62323f2ed325f5ae20000379` | evet |
| lighttpd | ayar | `lighttpd-dbgsym_1.4.79-2_arm64.deb` | 1.4.79-2 | 893112 | `f53f4484271e39987aea0992c34cf3049ba7c311e92b3850468bd16acb73b49a` | evet |
| neomutt | ayar | `neomutt_20250510+dfsg-2_arm64.deb` | 20250510+dfsg-2 | 1885364 | `407abe00534ea5477d48531791bf6c896150a2ded4fc4070567a1d5c23710466` | evet |
| neomutt | ayar | `neomutt-dbgsym_20250510+dfsg-2_arm64.deb` | 20250510+dfsg-2 | 2155824 | `49ab5986d40d0a5e28f6a389aaca900e777c3c540a34c8c3a3a633eac193063c` | evet |

sha256'sı dizinle tutan dosyaların toplamı: 135365004 bayt (129.09 MiB). Ayrıca `debian-archive-keyring_2025.1_all.deb` (anahtar halkası; §4) ve dizin dosyaları (`InRelease` + `Packages.xz`, 6 dizin, 14 383 295 bayt) indirildi.

## 7. ELF, BuildID ve sembol sayıları

- "paketteki ELF": açılan ikili paketteki düzenli ELF dosyaları (sembolik bağlar hariç). "BuildID ↔ .debug eşleşen": GNU BuildID notu (yalnız sahibi `GNU` olan not) hata ayıklama paketindeki `usr/lib/debug/.build-id/xx/yyyy.debug` dosyasının BuildID'siyle aynı olanlar.
- "seçilen ELF": §3 kuralı. "GT FUNC" ve "puanlanan": seçilen (C++ olmayan) ELF'lerde `function_f1.extract_gt`'nin `counts.functions` ve `counts.scored` toplamı (yalnız sayı; ad okunmadı / yazılmadı).

| paket | taraf | paketteki ELF | BuildID ↔ .debug eşleşen | seçilen ELF | C++ (ölçü dışı) | ölçülecek | GT FUNC (seçilen, toplam) | puanlanan (crt / ihraç dışı) | seçilenlerin BuildID'si | durum |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| bash | kör | 2 | 2 | 1 | 0 | 1 | 2269 | 592 | `bea6a154d9a9158114ee0a2a439045596615df14` | tamam |
| nginx | kör | 1 | 1 | 1 | 0 | 1 | 1906 | 1149 | `bb7d044cf2edf50d4e0e3a3d74cc7780c3134a0f` | tamam |
| irssi | kör | 8 | 8 | 1 | 0 | 1 | 2572 | 1416 | `d2045a7f109544823584e3ed4058fb0985cdfd03` | tamam |
| hexchat | ayar | 1 | 1 | 1 | 0 | 1 | 1618 | 962 | `6b1fe40d2d5073d86756938614cfea9bea1e7871` | tamam |
| jq | ayar | 1 | 1 | 1 | 0 | 1 | 15 | 7 | `93a13a689f8050ef71e6a8c5fa0e3cc6869ba5ea` | tamam |
| gawk | ayar | 15 | 15 | 1 | 0 | 1 | 868 | 839 | `eba3f43c96b2367410b5ce277044178374cf5411` | tamam |
| tcl8.6 | kör | 1 | 1 | 1 | 0 | 1 | 10 | 2 | `702b5e3a81014ee6d04abf19058e3f46fbd353c9` | tamam |
| libtcl8.6 | kör | 1 | 1 | 1 | 0 | 1 | 2853 | 1962 | `85e9478f0e81c8eb281979763bfbb01659b05e43` | tamam |
| python3.13-minimal | kör | 1 | 1 | 1 | 0 | 1 | 7731 | 6224 | `9e7f76dabfdf1c3b469670d23239b2f4cb2743d1` | tamam |
| libpython3.13-stdlib | kör | 45 | 45 | 45 | 0 | 45 | 3331 | 2837 | 45 BuildID; sıralı listenin sha256'sı `49eb76cddab62e2e…` (nufus.json) | tamam |
| lua-socket | kör | 16 | 16 | 16 | 0 | 16 | 1980 | 1336 | 16 BuildID; sıralı listenin sha256'sı `109809475c61196c…` (nufus.json) | tamam |
| lua-cjson | kör | 4 | 4 | 4 | 0 | 4 | 184 | 100 | 4 BuildID; sıralı listenin sha256'sı `931fd6582ad6744f…` (nufus.json) | tamam |
| postgresql-17 | ayar | 96 | 96 | 1 | 0 | 1 | 14826 | 4707 | `7ec6760ecbf3e10286773d2ef241df31700eba53` | tamam |
| gedit | ayar | 10 | 10 | 1 | 0 | 1 | 1034 | 690 | `dd66d993451a07fdbd0f48a20c2dbc8e2d357a45` | tamam |
| evince | ayar | 4 | 4 | 1 | 0 | 1 | 963 | 701 | `441f8fade27de69a1a7790d93f34e9cf2fae8b14` | tamam |
| mousepad | kör | 3 | 3 | 1 | 0 | 1 | 9 | 0 | `829b5a10219a7bcba8e3cd13dbde9d68148a60db` | tamam |
| xfce4-terminal | kör | 1 | 1 | 1 | 0 | 1 | 382 | 374 | `433232c2be15dbb00bf26dd88844066b1c832953` | tamam |
| geany | kör | 8 | 8 | 1 | 1 | 0 | 0 | 0 | `3326e908d8744cf669707926e5c8757d1f8dced1` | ölçülecek ELF yok |
| pidgin | ayar | 23 | 23 | 1 | 0 | 1 | 1781 | 1304 | `df1b6f1f2c36858094cc3ca09a930d5d69e7fd9e` | tamam |
| xterm | kör | 2 | 2 | 1 | 0 | 1 | 1054 | 1045 | `cbb9ec6a3ef619d21af1d7ae941144b277f0bb7c` | tamam |
| mc | kör | 2 | 2 | 1 | 0 | 1 | 2308 | 2299 | `69ecfa9e9c8ce9244d283b6f01080fab31edd32a` | tamam |
| busybox | kör | 1 | 1 | 1 | 0 | 1 | 2360 | 2352 | `c0672c0365c9a37ef275d8abe5a305128e7c2c04` | tamam |
| lighttpd | ayar | 18 | 18 | 1 | 0 | 1 | 745 | 298 | `1f993f2167e0cbd7df61a32c9d0cef17a5cf2097` | tamam |
| neomutt | ayar | 2 | 2 | 1 | 0 | 1 | 3480 | 3472 | `5c4a9908df70b124f1b7f38406286abd5f094d4a` | tamam |

Taraf özeti (aynı betik):

| taraf | paket | ölçülecek ELF'i olan paket | ölçülecek ELF | GT FUNC | puanlanan |
|---|---:|---:|---:|---:|---:|
| ayar | 9 | 9 | 9 | 25330 | 12980 |
| kör | 15 | 14 | 76 | 28949 | 21688 |

`nufus.json` sha256: 65513ae4a8627e0d671497dee1495531a9158b66b3345e06c4abd24e249ea5b5

## 8. Kabul ölçütü, notlar, disk

**PLAN kabul ölçütü** ("en az 15 paket GT'li ve koşulmuş; iki tarafta da en az 5 paket; her ikilide `extract_gt` build-id eşleşmesi"):
- GT'li (ölçülecek ELF'i olan) paket: 23 / 24 (ayar 9 / 9, kör 14 / 15). **Koşulmuş: 0** — ürün koşusu (adım 5) bu paketin işi değildi; sonraki oturum. Ölçütün "koşulmuş" yarısı açık.
- Bütün indirilen paket dosyalarının sha256'sı ve boyutu imzalı dizinle tuttu (47 / 47 benzersiz dosya; `python3.13-dbg` iki paketin ortak hata ayıklama paketi, bir kez indirildi). Bütün paketlerde paketteki her ELF'in BuildID'si bir `.debug` ile eşleşti (§7 "paketteki ELF" = "eşleşen", 24 / 24 paket).

**Notlar (sayı yukarıdaki tablolardan):**
1. **geany (kör):** seçilen ELF C++ (içe aktarımda C++ işareti); kurala göre ölçü dışı, yerine başka ELF seçilmedi. Kör tarafta 14 paket kalıyor.
2. **Katkısı küçük paketler:** mousepad (kör) seçilen ELF'te 9 FUNC, puanlanan 0; tcl8.6 (kör) 10 FUNC, puanlanan 2; jq (ayar) 15 FUNC, puanlanan 7. jq'de ikilinin `DT_NEEDED` listesinde `libjq.so.1` var (ayar tarafı; `libjq1` paketi listede yok): programın kodu ayrı kitaplık paketinde. Kör paketlerde bu tür bir bakış yapılmadı. Liste ve kural değişmedi; ÖK-5 bu paketleri birim olarak sayarken nüfusun küçüklüğünü göz önüne almalı.
3. **`function_f1.read_elf_info` hatası (ölçüm altyapısı için not, bu pakette düzeltilmedi; dosya salt okur):** pyelftools, SystemTap notlarını (`.note.stapsdt`, sahibi `stapsdt`, tür numarası 3) da `NT_GNU_BUILD_ID` diye etiketliyor; `read_elf_info` notun sahibine bakmadığı için bu ELF'lerde BuildID olarak son stapsdt notunun baytlarını alıyor. Seçilen 86 ELF'ten 2'sinde (postgresql-17 / ayar, python3.13-minimal / kör) `extract_gt`'nin kendi BuildID karşılaştırması bu yüzden gerçek BuildID'yi değil stapsdt baytlarını karşılaştırdı. Bu iki ELF'te gerçek GNU BuildID eşleşmesi `tabaka_indir.elf_bilgisi` (yalnız `GNU` sahipli not) ile ayrıca kanıtlandı (§7). Önerilen onarım: `read_elf_info`'da `note["n_name"] == "GNU"` koşulu. Tabaka A / B'nin 351 ELF'inde bu sapma yok (`olcu/TABAKA_VERI.md`).
4. **Körlük denetimi:** betik kör paketlerde yalnız BuildID / sha256 / sayı bastı; C++ denetimi yalnız evet / hayır döndürdü. Bu oturumda kör paketlerin ELF yolu, sembol adı, dizgisi ya da kaynağı ekrana gelmedi.
5. **Betik değişiklikleri (§1–§3 yazıldıktan sonra):** python hata ayıklama paketi için `Build-Ids` kesişimi (§5), SystemTap notu filtresi (not 3), çoklu hata ayıklama kökü, rapor özeti. Bölme kuralı (§2) ve ELF seçim kuralı (§3) değişmedi. Son sha256'lar: `scripts/measurement/ozkod_nufus_kur.py` `75da71c7475a6058…`, `scripts/arge/olcu/tabaka_indir.py` `ac6153bef82fe336…` (`nufus.json` üretildikten sonra tabaka_indir.py'ye yalnız `kiyas` alt komutu eklendi; indirme / doğrulama kodu değişmedi).

**Disk** (`diskutil info /System/Volumes/Data | grep "Volume Used"`; ortak makine, başka oturumlar da yazıyor):
- önce (2026-11-19 11:21:41 +03): `710.4 GB (710430367744 Bytes)`
- sonra (2026-11-19 11:52:18 +03): `716.1 GB (716129710080 Bytes)`
- Bu paketin dizinleri (`du -sk`): `~/karadul_olcum/ozkod_nufus` 456 556 KiB, `~/karadul_olcum/n2_tabaka` 154 364 KiB, `~/karadul_olcum/downloads/n2_tabaka` 127 632 KiB (toplam 738 552 KiB). Aradaki farkın geri kalanı bu paketin dışından.

**Sonraki adım (ÖK-V adım 5–6, sonraki oturum):** ürün koşusu `nufus.json`'daki seçilen ve `olculur` ELF'lerle (ELF yolu ve `x_<paket>` dizini orada); `--kok` seçeneğiyle olgu önbelleği. Ön kayıt (ÖK-5) ve bu belgenin commit'i koşudan önce.
