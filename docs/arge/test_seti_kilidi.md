# Makale test seti kilidi

- **Tarih:** 2026-10-15
- **Kura betiği:** `scripts/measurement/test_seti_kura.py`. Sonuç görülmeden önce, commit `337c4d5` ile sabitlendi.
- **Tohum:** SHA-256(`karadul-test-seti-kura-2026-10-15`) değerinin ilk 16 hex basamağı = `1357717698366421230`
- **Aday havuzu ve işaretler:** `docs/arge/2026-10-15_makale/test_seti_adaylari.md`
- **Plan:** `docs/arge/2026-10-15_isimlendirme_plani.md`. Test seti Hafta 7'de (G31) açılır.

## Kurallar
1. Bu programlar G31'den önce Karadul ile analiz edilmez.
2. Geliştirme sırasında bu programların kaynak koduna ve çıktılarına bakılmaz.
3. Kural, eşik ya da sözlük ayarı bu programlara göre yapılmaz.
4. Listeyi sonradan değiştirmek yasaktır. Bir program teknik olarak koşulamazsa (ör. paket kalkarsa), yerine aynı tabakadaki dışarıda kalanlardan, bu belgede yazılı sırayla gelen ilk program alınır. Değişiklik ve gerekçesi bu belgeye eklenir.
5. İkililer indirilince sha256 ve BuildID bu belgeye yazılır (bkz. §4). Bu adım ilk analizden önce yapılır.

## 1. Ana küme (15 program)

| # | Program (ölçülecek ikili) | Alan | Boyut tabakası | Homebrew (2026-10-15) | Debian 13 arm64 | Not |
|---|---|---|---|---|---|---|
| 1 | unzip (`unzip`) | sıkıştırma | küçük | `unzip` 6.0 | unzip 6.0-29+deb13u1 | zorunlu (tek temsilci) |
| 2 | memcached (`memcached`) | veritabanı | küçük | `memcached` 1.6.45 | memcached 1.6.38-1 | zorunlu (tek temsilci) |
| 3 | dash (`dash`) | kabuk | küçük | `dash-shell` 0.5.13.5 | dash 0.5.12-12 | |
| 4 | dcraw (`dcraw`) | medya | küçük | `dcraw` 9.28.0 | dcraw 9.28-8 | |
| 5 | gifsicle (`gifsicle`) | medya | küçük | `gifsicle` 1.96 | gifsicle 1.96-1 | |
| 6 | mawk (`mawk`) | metin işleme | küçük | `mawk` 1.3.4-20260302 | mawk 1.3.4.20250131-1 | |
| 7 | dnsmasq (`dnsmasq`) | ağ | orta | `dnsmasq` 2.93 | dnsmasq-base 2.91-1+deb13u2 | Linux ve macOS'ta fonksiyon kümesi farklı |
| 8 | GnuPG (`gpg`) | kripto | orta | `gnupg` 2.5.24 | gpg 2.4.7-21+deb13u1+b5 | dbgsym +b5 eşleşmeli |
| 9 | nasm (`nasm`) | geliştirme | orta | `nasm` 3.02 | nasm 2.16.03-1 | |
| 10 | rsync (`rsync`) | sistem | orta | `rsync` 3.5.1 | rsync 3.4.1+ds1-5+deb13u4 | |
| 11 | OpenSSH (`ssh`) | kripto + ağ | orta | `openssh` 10.6p1 | openssh-client 1:10.0p1-7+deb13u4 | yalnız `ssh` ikilisi |
| 12 | zsh (`zsh`) | kabuk | orta | `zsh` 5.9.2 | zsh 5.9-8+b24 | yalnız ana ikili, `.so` modülleri hariç; dbgsym +b24 |
| 13 | vim (`vim`; Debian'da `vim.nox`) | editör | büyük | `vim` 9.2.1150 | vim-nox 2:9.1.1230-2 | zorunlu (tek temsilci) |
| 14 | git (`git`) | sistem | büyük | `git` 2.56.0 | git 1:2.47.3-0+deb13u1 | |
| 15 | haproxy (`haproxy`) | ağ | büyük | `haproxy` 3.4.6 | haproxy 3.0.11-1+deb13u3 | |

**Kurada dışarıda kalanlar** (yedek sırası, tabaka içinde alfabetik):
- küçük: `ag`, `less`
- orta: `cmus`, `tcpdump`
- büyük: `lynx`

## 2. Stres alt kümesi (ayrı raporlanır, ana sayılara karışmaz)

| Program | Neden ayrı |
|---|---|
| wget | gnulib kullanıyor; coreutils parmak izleriyle örtüşür |
| nano | gnulib kullanıyor |
| screen | tmux'a çok benziyor (geliştirme setine yakın) |
| lua | liblua kütüphane ikizi |
| pigz | içine gömülü zopfli kodu |

## 3. Ölçüm tanımları
- **Payda:** İsim bekleyen fonksiyonlar, yani Ghidra'nın kendisinin adlandıramadıkları. Thunk ve stub'lar hariç. `.cold` ve `OUTLINED_FUNCTION` parçaları ayrı sınıf. Aynı adrese düşen birden çok gerçek isim (bağlayıcının özdeş kod katlaması) bir isim kümesi sayılır.
- **Mac:**
  - Gerçek isimler Homebrew şişesindeki ikilinin `nm` çıktısından alınır.
  - Analiz, ikilinin `/usr/bin/strip` ile soyulmuş kopyası üzerinde yapılır.
  - Export trie'nin boşaldığı `xcrun dyld_info -exports` ile doğrulanır.
- **Linux:**
  - Gerçek isimler aynı `+bN` ekini taşıyan `-dbgsym` paketinden alınır.
  - Analiz, dağıtılan strip edilmiş ikili üzerinde yapılır.
- **Metrikler:**
  - Tam isim.
  - Yakın isim: `tam` + `dogru_tarif`, ölçüt `docs/arge/etiket_rehberi.md`.
  - Yanlış isim oranı.
  - Kapsam.
  - Literatürle kıyas için token düzeyi P/R/F1.
- **Değerlendirme:** Ajan ön etiket koyar. Örneklem iki insan değerlendiriciyle etiketlenir ve uyum (Cohen kappa) raporlanır.
- **Kıyas:** Ghidra'nın tek başına verdiği isimler, IDA (Free), mevcut Karadul. Literatür kıyası için SymGen veri setinin coreutils dışı alt örneklemi kullanılır; isim imza DB'si açık ve kapalı iki koşu yapılır.
- **Ezber riski:** Çok bilinen programlar (vim, git, ssh) az bilinenlerden ayrı raporlanır.

## 4. İkili sabitleme (2026-10-15)

İndirilen dosyalar `targets/test_seti/` altında (636 MB, depoda dışlanmış). Doğrulamalar:
- Homebrew şişelerinin sha256'sı Homebrew JSON'u ile eşleşti.
- Debian paketlerinin ve dbgsym'lerin sha256'sı Debian Packages dizini ile eşleşti.
- dbgsym BuildID'leri 21/21 eşleşti.

### 4.1 Ana küme (15 program × 2 platform)

| Program | Platform | Paket/şişe (sürüm) | sha256 (ölçülecek ikili) | BuildID / UUID | Tarih | Sembol / dbgsym |
|---|---|---|---|---|---|---|
| unzip (`unzip`) | macOS arm64 (`arm64_tahoe`) | `unzip` 6.0_8, rebuild 1 | `8a2cbfb8ee59cf90ba69ae385b9a949ad20c8285514719433ec6e00f86e2b0de` | `DED0E222-24A8-33E3-9F27-50E7242D3729` | 2026-10-15 | **SEMBOLSÜZ** — nm -U 1 satır (t=0, T=1) |
| unzip (`unzip`) | Debian 13 arm64 | `unzip` 6.0-29+deb13u1 | `c0c8914d75002c9da92a2f923c019dcdecbafe9853f6fe642493d55174ae5b2d` | `607ed613e82d17242455df4ab3b4dcc30ff47512` | 2026-10-15 | `unzip-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 114 (yerel 24, global 90); dağıtılan ikilide `.symtab` yok |
| memcached (`memcached`) | macOS arm64 (`arm64_tahoe`) | `memcached` 1.6.45_1 | `f6a49327089e66164580cbcfa3a3a57fdd92590fb5da08d2560d9b6afe72cb5d` | `0D6E5F4D-44C6-33C2-A865-964ADDD6B84D` | 2026-10-15 | nm -U 724 (t=263, T=323) |
| memcached (`memcached`) | Debian 13 arm64 | `memcached` 1.6.38-1 | `d2b9d5b63277d3ba8d46270437f62aa2faa559822a99dfee3625cce6ef393088` | `ab6e14f92b84b7bc301c3a29875b76c035df8f15` | 2026-10-15 | `memcached-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 1442 (yerel 849, global 593); dağıtılan ikilide `.symtab` yok |
| dash (`dash`) | macOS arm64 (`arm64_tahoe`) | `dash-shell` 0.5.13.5 | `29ad19b56c370e094602eecc1d5de033b88800a970be2005f00a233b84254f62` | `4123FC21-5430-36B1-A718-F0205793D91A` | 2026-10-15 | nm -U 441 (t=108, T=187) |
| dash (`dash`) | Debian 13 arm64 | `dash` 0.5.12-12 | `367967c823a0c391e5049b15a67c6a0a629c88b9b6dcdca75ef13ac9d65334b1` | `93916dee0ae0f4d1bd2ac634e97d750fc88dc1d0` | 2026-10-15 | `dash-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 258 (yerel 87, global 171); dağıtılan ikilide `.symtab` yok |
| dcraw (`dcraw`) | macOS arm64 (`arm64_tahoe`) | `dcraw` 9.28.0_3 | `80d7ead3dc772b4dd7ff3d1268b3f32de2ac277d107ad8f44ec5583cd775b585` | `52EFD0EF-BF7D-3C11-B4AD-FA38F2844FB9` | 2026-10-15 | nm -U 373 (t=2, T=177) |
| dcraw (`dcraw`) | Debian 13 arm64 | `dcraw` 9.28-8 | `8610752025128e35549c467a9941cb2ccf8a711bb3f4328fceba802d11045c09` | `e71ef061767faf32bb65f9d1214366ca1b206dc5` | 2026-10-15 | `dcraw-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 195 (yerel 15, global 180); dağıtılan ikilide `.symtab` yok |
| gifsicle (`gifsicle`) | macOS arm64 (`arm64_tahoe`) | `gifsicle` 1.96 | `2eee1c6380a98a772ececdd53a767accad7e1962fb3b066f72cda4fe28ce413f` | `E47C1ABE-773A-3793-8054-4F7878C91DB6` | 2026-10-15 | nm -U 450 (t=165, T=176) |
| gifsicle (`gifsicle`) | Debian 13 arm64 | `gifsicle` 1.96-1 | `de28c8a49f6fd41da7995fc2793e86f8a750556f959543686bc95fd04721675b` | `237ee6406e9a82535f983bd9a83c15fa965ddc7f` | 2026-10-15 | `gifsicle-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 299 (yerel 121, global 178); dağıtılan ikilide `.symtab` yok |
| mawk (`mawk`) | macOS arm64 (`arm64_tahoe`) | `mawk` 1.3.4-20260302 | `57c041748deb296e45994fad21d43fc2d78ece11ee3134dda81fa6b362e62f52` | `20A30921-E83F-32E4-AB1A-1FED845FA708` | 2026-10-15 | nm -U 415 (t=61, T=184) |
| mawk (`mawk`) | Debian 13 arm64 | `mawk` 1.3.4.20250131-1 | `f1fdae58b46515eb6631dd55b99be603f2b133376cd694e78927a121c7648353` | `07249648e1e0ef71e8e218b7af819b9d6880395d` | 2026-10-15 | `mawk-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 240 (yerel 55, global 185); dağıtılan ikilide `.symtab` yok |
| dnsmasq (`dnsmasq`) | macOS arm64 (`arm64_tahoe`) | `dnsmasq` 2.93 | `554aee6600e2cf8861396a856008672f6683a5069294a57f565e6132f81a363c` | `85454D17-763E-3B6D-929C-FAFF2F540FC7` | 2026-10-15 | nm -U 556 (t=163, T=293) |
| dnsmasq (`dnsmasq`) | Debian 13 arm64 | `dnsmasq-base` 2.91-1+deb13u2 | `8a307feb5fa212ffa5f0d93cbb7015dedc82be296328957fb5c67d3c4539741b` | `6d7b0eef2e2116f118bcd8cd0f6968b2af1fd0bd` | 2026-10-15 | `dnsmasq-base-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 507 (yerel 186, global 321); dağıtılan ikilide `.symtab` yok |
| gnupg (`gpg`) | macOS arm64 (`arm64_tahoe`) | `gnupg` 2.5.24 | `459c18c3f2e1e198e33efe53f88a1786b1e835de579ce35b4c7f134326d45bd0` | `B1D3B9DE-8394-3BFA-9080-5A87F7BDC3DA` | 2026-10-15 | nm -U 2196 (t=681, T=1196) |
| gnupg (`gpg`) | Debian 13 arm64 | `gpg` 2.4.7-21+deb13u1+b5 | `8abfa53f25b7e338fcef742ac0f900bd87dbdcd9c0d0cb2c7c89accdd1299192` | `429a62eeee986663f80486719e8316e841a46501` | 2026-10-15 | `gpg-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 1633 (yerel 495, global 1138); dağıtılan ikilide `.symtab` yok |
| nasm (`nasm`) | macOS arm64 (`arm64_tahoe`) | `nasm` 3.02 | `4a35962ae78b3051bf568da70e3de7ecb8e99cb7925741eefb08d7f17cd1822b` | `2144EF31-5F03-3103-BF95-1162AABFCC79` | 2026-10-15 | nm -U 4130 (t=952, T=1) |
| nasm (`nasm`) | Debian 13 arm64 | `nasm` 2.16.03-1 | `693949b575c35f949012318cd6fe2baaf3b5742dfed6a1f246e8bdbb026897a0` | `4487c63fe2c29d025e5a0859ac34721e3cbb94d8` | 2026-10-15 | `nasm-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 558 (yerel 542, global 16); dağıtılan ikilide `.symtab` yok |
| rsync (`rsync`) | macOS arm64 (`arm64_tahoe`) | `rsync` 3.5.1, rebuild 1 | `b42e8bc83729eb3bf5cfac2dc38f7bfb9755a87bb0c271c7222b217c359a35c3` | `2F8B1A69-ED1F-33C7-9D88-17703F20AE8A` | 2026-10-15 | nm -U 1432 (t=228, T=536) |
| rsync (`rsync`) | Debian 13 arm64 | `rsync` 3.4.1+ds1-5+deb13u4 | `3852336282ee66a98c52966a8bebbf3508980a3ec47e7150f40330ada999980e` | `9ebe2bd91f59ad01a7960f099bf9d6e3ff499465` | 2026-10-15 | `rsync-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 644 (yerel 161, global 483); dağıtılan ikilide `.symtab` yok |
| openssh (`ssh`) | macOS arm64 (`arm64_tahoe`) | `openssh` 10.6p1_1 | `1aaf14aa6ffe225efec4c51e65ad22e858fd59e65c6707b8768d26f0307c64a7` | `526841B8-52EA-38DC-9C75-2938207732B0` | 2026-10-15 | **SEMBOLSÜZ** — nm -U 1 satır (t=0, T=1) |
| openssh (`ssh`) | Debian 13 arm64 | `openssh-client` 1:10.0p1-7+deb13u4 | `de352e4ace7028d9816fd0ee9d22936bc1b5622c400d5b0b7df660df3426b068` | `7fb005d83b99adff228c749fc9a3744c49859ebe` | 2026-10-15 | `openssh-client-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 1279 (yerel 402, global 877); dağıtılan ikilide `.symtab` yok |
| zsh (`zsh`) | macOS arm64 (`arm64_tahoe`) | `zsh` 5.9.2 | `7c25b61739dfda3ee157365fe61c3b5a0b0166bf54fd12183af17bcc819ef673` | `2414DF78-3B55-32D5-9677-C50F1FB1FCB7` | 2026-10-15 | **Yerel sembol yok** — nm -U 1045 (t=0, T=758) |
| zsh (`zsh`) | Debian 13 arm64 | `zsh` 5.9-8+b24 | `e0087edbed176638f1cca619a8907397baa64b70f9bd4c38b81643d8fd309a21` | `c74c9a9fe68a1f4b4730636f958b0780413fe276` | 2026-10-15 | `zsh-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 1073 (yerel 316, global 757); dağıtılan ikilide `.symtab` yok |
| vim (`vim`) | macOS arm64 (`arm64_tahoe`) | `vim` 9.2.1150 | `aadb445fa5896c806277df3af2356c5c687bc7c4000305328e97169ff87dc9f8` | `1821A35C-9C31-388C-A365-6899CCE76ED1` | 2026-10-15 | **SEMBOLSÜZ** — nm -U 1 satır (t=0, T=1) |
| vim (`vim.nox`) | Debian 13 arm64 | `vim-nox` 2:9.1.1230-2 | `96f7196061e6d599256feef9da03158840a5386281d49db4744aec3851e2ed6d` | `a20141c9496ebb297a2935e8d87070bb2b186d2f` | 2026-10-15 | `vim-nox-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 6595 (yerel 2212, global 4383); dağıtılan ikilide `.symtab` yok |
| git (`git`) | macOS arm64 (`arm64_tahoe`) | `git` 2.56.0_1 | `a6f94822a13b583487a95280bfa18104e2fcfa91fbda59d313eed1689dfe46f2` | `876BD517-FCE2-391B-BAA7-1DE56C5BAAA0` | 2026-10-15 | nm -U 10387 (t=4890, T=3300) |
| git (`git`) | Debian 13 arm64 | `git` 1:2.47.3-0+deb13u1 | `a0e562e4bd3c4c79379e91d8c07a10104b2cefe8fac966dc6bd4874a57a807f3` | `9392bfd1f041e8b8b0b3238543bea65a8a923494` | 2026-10-15 | `git-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 6510 (yerel 3502, global 3008); dağıtılan ikilide `.symtab` yok |
| haproxy (`haproxy`) | macOS arm64 (`arm64_tahoe`) | `haproxy` 3.4.6 | `13d67674707f275bacf59a58f4112617280c5dbce574a50a2d67fc24a4071798` | `A988D0E3-AAB0-33D6-8FC6-A298F8D26F0E` | 2026-10-15 | nm -U 16590 (t=9777, T=2760) |
| haproxy (`haproxy`) | Debian 13 arm64 | `haproxy` 3.0.11-1+deb13u3 | `befe122f1e78163f8b35bad129c162870f0958d3b4e83235eac67b8c4199abfb` | `9df30439911a0e032c27158605490a6e0063a9dd` | 2026-10-15 | `haproxy-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 4990 (yerel 2716, global 2274); dağıtılan ikilide `.symtab` yok |

### 4.2 Stres alt kümesi (5 program × 2 platform, lua için ek kütüphane satırları)

| Program | Platform | Paket/şişe (sürüm) | sha256 (ölçülecek ikili) | BuildID / UUID | Tarih | Sembol / dbgsym |
|---|---|---|---|---|---|---|
| wget (`wget`) | macOS arm64 (`arm64_tahoe`) | `wget` 1.25.0_2 | `69f852d1e3ea985c1a50f2ad0b0e140ebfda4237f055ea50dabfe4a00fc6acfc` | `5A5FD6D8-8269-3084-84F5-081BDD4B8762` | 2026-10-15 | nm -U 1010 (t=327, T=459) |
| wget (`wget`) | Debian 13 arm64 | `wget` 1.25.0-2 | `e3ebab2a49f8039f3479e0a4cf285bec5fd75600ba47ea7c298feb04d70f3063` | `de599bc13773a5ee91f8f997859437b431697551` | 2026-10-15 | `wget-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 621 (yerel 206, global 415); dağıtılan ikilide `.symtab` yok |
| nano (`nano`) | macOS arm64 (`arm64_tahoe`) | `nano` 9.2 | `15083fc9fe4a5e83485dc07e4769d4da16141ffc464856930e7f38af6684e722` | `3B1280A6-A40F-32F0-94C3-F2DB88B292CC` | 2026-10-15 | nm -U 1000 (t=213, T=549) |
| nano (`nano`) | Debian 13 arm64 | `nano` 8.4-1+deb13u1 | `1353f379f3f922f8a2992a3770c2c4e8a86e5aaeb1c382f1a11136bf14195b61` | `b4db8cdaeec1981da1cb155106bcf4171b6e004d` | 2026-10-15 | `nano-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 487 (yerel 13, global 474); dağıtılan ikilide `.symtab` yok |
| screen (`screen`) | macOS arm64 (`arm64_tahoe`) | `screen` 5.0.2 | `bfcd94e08da0e02d1cf810dfe7a60f25213d3e9fcfa874d693c1ab5810044951` | `0172C99E-F80A-331F-848B-D792E99F3787` | 2026-10-15 | nm -U 1009 (t=384, T=373) |
| screen (`screen`) | Debian 13 arm64 | `screen` 4.9.1-3 | `29a3a1603e2e65618927ca67e6bcb20d60635f80608e565d47b1c77fa564086b` | `08a51095aca72d2785a3ee1775b1e8d7c9ff3965` | 2026-10-15 | `screen-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 614 (yerel 244, global 370); dağıtılan ikilide `.symtab` yok |
| lua (`lua`) | macOS arm64 (`arm64_tahoe`) | `lua` 5.5.1 | `50ddcd568ab099619e6c5a2e45bebad7cdfaef44af2e8af67cbed3336e105da9` | `AA635D48-96FC-30E3-AB6B-3DDD1B525005` | 2026-10-15 | nm -U 20 (t=14, T=2) |
| lua (`lua5.4`) | Debian 13 arm64 | `lua5.4` 5.4.7-1+b2 | `55f81694b150cc72af255d771a0e1c37843fb07cca57f82554f58ca1a981e62a` | `1036fdde6f5ea76cfd5174d393292ef910041151` | 2026-10-15 | `lua5.4-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 733 (yerel 579, global 154); dağıtılan ikilide `.symtab` yok |
| lua — ek (`liblua.5.5.1.dylib`) | macOS arm64 (`arm64_tahoe`) | `lua` 5.5.1 (aynı şişe) | `81746a3ef0cddf332a869204465afba5555c6810b7ef73316060ecc5250e588b` | `4A3F734E-A86D-39D7-B5F6-F1739A056284` | 2026-10-15 | nm -U 858 (t=649, T=156) |
| lua — ek (`liblua5.4.so.0.0.0`) | Debian 13 arm64 | `liblua5.4-0` 5.4.7-1+b2 | `779e258a2f1874543f5e048f62d662dbee084a71a4d4e6ebbcf766e796327695` | `7a85af6dcee219c20bc0772e7eedb116248350ec` | 2026-10-15 | `liblua5.4-0-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 721 (yerel 567, global 154); dağıtılan ikilide `.symtab` yok |
| pigz (`pigz`) | macOS arm64 (`arm64_tahoe`) | `pigz` 2.8_1, rebuild 1 | `a05b6a8ff40a84f8c1fa4052e38a70a682e30f142f5fc7486356134572733a80` | `5E3EDB40-0088-3C5A-9FAD-4A4B18E45FA6` | 2026-10-15 | nm -U 267 (t=163, T=60) |
| pigz (`pigz`) | Debian 13 arm64 | `pigz` 2.8-1+b1 | `3e92528e773e2f79b159694d3b2f459efa3844da04441053be906a9b1b2c6bc8` | `32ca0c5f3018d6cd8de6cad10e378667cbf9b1b7` | 2026-10-15 | `pigz-dbgsym` aynı sürüm; BuildID eşleşti (.debug notu: evet, Packages `Build-Ids`: evet); .debug `.symtab` FUNC 137 (yerel 75, global 62); dağıtılan ikilide `.symtab` yok |

### 4.3 Sabitlemede çıkan sorunlar (karar bekleyenler)

1. **Sembolsüz Mac şişeleri: unzip, openssh (`ssh`), vim.**
   - `nm -U` yalnız 1 satır veriyor (`__mh_execute_header`). `otool -l` sonucu: nlocalsym=1, nextdefsym=1. LC_SYMTAB'daki öteki kayıtlar (toplam 87 / 432 / 359) tanımsız, yani dışarıdan alınan semboller.
   - Sonuç: kilit belgesi §3'teki Mac yöntemi bu üç programda **uygulanamaz**. O yöntem gerçek isimleri şişedeki ikilinin `nm` çıktısından alıyor.
   - Üçünden ikisi "zorunlu (tek temsilci)": unzip ve vim.
   - Debian tarafı üçünde de sağlam. dbgsym FUNC sayıları: unzip 114, ssh 1279, vim.nox 6595.
   - Seçenekler:
     - Bu üç programın Mac ölçümünü düşürmek.
     - Aynı formülü sembolleri koruyarak yerelde derlemek. Bu durumda dosya kimliği değişir ve yeniden sabitleme gerekir.
     - §1 kural 4'ü uygulamak.
   - Hiçbirini ben yapmadım; karar ana oturumun.
2. **zsh (Mac) şişesinde yerel sembol yok.**
   - nlocalsym=0. Yalnız 1045 global tanım var (T=758).
   - Sonuç: `static` fonksiyonların gerçek adı şişeden alınamaz. Mac paydası global fonksiyonlarla sınırlı kalır.
   - Şişede bir de `bin/zsh-5.9.2` var. UUID'si ve sembol sayıları `bin/zsh` ile aynı ama dosya farklı:
     - `bin/zsh-5.9.2`: sha256 `e64b38f3ff9ad95ac2875e1e1ab3ad0fbc2f62f8d942edf9fa3fb65911eb30a8`, 654016 bayt.
     - `bin/zsh`: 668352 bayt.
   - Ölçülecek dosya olarak `bin/zsh` sabitlendi.
3. **lua: platformlar farklı derlenmiş, sürümler de farklı.**
   - **Mac:** `bin/lua` 53 KB'lık ince bir sürücü (nm -U 20; t=14, T=2). Asıl kod `lib/liblua.5.5.dylib`'de; bu, `otool -L` çıktısında görüldü. Kütüphane ek satır olarak sabitlendi: `liblua.5.5.1.dylib`, nm -U 858 (t=649, T=156).
   - **Debian:** `lua5.4` kütüphaneye bağlı değil. NEEDED listesinde liblua yok, dosya 330 KB, `.debug` FUNC sayısı 733. `liblua5.4-0` ve onun dbgsym paketi de ek olarak sabitlendi.
   - **Sürüm:** Homebrew'da 5.5.1, Debian'da 5.4.7. trixie'de lua5.5 yok.
   - Mac'te hangi dosyanın ölçüleceğine (dylib mi, lua ile dylib birlikte mi) ana oturum karar verecek.
4. **Stres kümesinde sürüm farkları.**
   - screen: Homebrew 5.0.2, Debian 4.9.1-3. Ana sürüm farklı.
   - nano: Homebrew 9.2, Debian 8.4-1+deb13u1.
   - §2'de Debian sürümleri yazılı değildi, bu yüzden madison stable'dan seçildi. Seçilen sürümler: wget 1.25.0-2, nano 8.4-1+deb13u1, screen 4.9.1-3, lua5.4 5.4.7-1+b2, pigz 2.8-1+b1. Kilit belgesine eklenmeleri gerekiyor.
5. **rsync'in Debian sürümü yakında değişecek.**
   - `trixie-proposed-updates`'te `3.5.0+ds1-0+deb13u1` bekliyor; 13.8 ara sürümüyle stable'a geçecek.
   - Sabitlenen `3.4.1+ds1-5+deb13u4` o zaman bir süre sonra deb.debian.org havuzundan kalkabilir.
   - Yerel kopya ve sha256 elimizde. Gerekirse aynı dosya snapshot.debian.org'dan alınabilir.
6. **Homebrew meta verisinin tarihi.**
   - `brew info` yerel API önbelleğinden okundu (2026-10-12 14:47). Kilit belgesindeki "Homebrew (2026-10-15)" sürümleri bununla aynı.
   - Önbellek güncellenmedi, çünkü auto-update kapalıydı.
   - Formüller sonradan güncellenirse yeni şişe farklı bir sürüm ya da rebuild numarası alır. Sabitlenen dosyalar sha256 ile kayıtlı.
7. **Küçük notlar (sorun değil):**
   - nasm (Mac): T=1, t=952. Fonksiyonların hepsi yerel sembol olarak duruyor, isimler mevcut.
   - git (Debian): `/usr/lib/git-core/git` aynı içerikte ikinci bir kopya.
   - git (Mac): `libexec/git-core/git`, `bin/git`'e sembolik bağ. Ölçülecek dosya her iki platformda da `bin/git`.
   - screen (Mac): `bin/screen`, `screen-5.0.2`'ye sembolik bağ. Tablodaki sha256 gerçek dosyanın.
   - Her .deb için `*_ar/` klasöründe ara dosyalar duruyor: `control.tar.xz`, `data.tar.xz`, `debian-binary`. Silinmedi.
   - Debian dbgsym sürümleri binNMU ekiyle birebir: gpg `+b5`, zsh `+b24`, lua5.4 `+b2`, pigz `+b1`.

### 4.4 Kararlar (2026-10-17)

1. **Sembolsüz Mac ikilileri (unzip, ssh, vim) ve yerel sembolü olmayan zsh** (Berke kararı). Bu dört programın Mac kopyası kaynaktan, sembolleri koruyarak yeniden derlenir. Liste değişmez; değişen, Mac'te gerçek isimlerin alındığı ikilidir. Yöntem:
   - Kaynak, §4.1'deki şişeyle aynı Homebrew formül sürümünden alınır. Derleme seçenekleri formülle aynıdır; tek fark, kurulumda strip yapılmaması.
   - Derleme yalıtılmış bir önekte yapılır; sistemdeki Homebrew kurulumu değişmez.
   - Gerçek isimler bu derlemenin `nm` çıktısından alınır. Analiz girdisi, aynı dosyanın `/usr/bin/strip` ile soyulmuş kopyasıdır. Export trie'nin boşaldığı `xcrun dyld_info -exports` ile doğrulanır.
   - Derleme sırasında kaynak koda ve derleme çıktısına bakılmaz; yalnız derlemenin başarısı denetlenir (kural 2). Bu ikililer G31'den önce Karadul ile analiz edilmez (kural 1).
   - Yeni dosyaların sha256 ve UUID değerleri ilk analizden önce bu belgeye eklenir (kural 5). §4.1'deki şişe satırları kayıt olarak kalır; Mac ölçümünde kullanılmaz.
2. **lua (Mac)** (ana oturum kararı). Ölçülecek dosya `liblua.5.5.1.dylib`'dir, çünkü kod orada. 53 KB'lık `bin/lua` sürücüsü ayrı satırda raporlanır. Mac'te 5.5.1, Debian'da 5.4.7 var; program başına platformlar arası kıyas yapılmaz.
3. **Stres kümesinin Debian sürümleri** §4.2'de yazılı; §4.3 madde 4 kapandı.

### 4.5 Kaynaktan derlenen Mac ikilileri (2026-10-19)

§4.4 madde 1'in uygulaması. Dört programdan ikisi derlendi: unzip ve zsh. openssh ile vim'in bağımlılıkları bu makinede kurulu değil. Görev kuralı gereği kurulmadılar, bu iki program derlenmedi (bkz. "Açık sorunlar").

- **Konum:** `targets/test_seti/mac_kaynaktan/<program>/` (depo ve Spotlight dışında). Alt dizinler: `indirilen/` (kaynak, yama, şişedeki formül), `src/`, `prefix/`, `gt/<ikili>` ve `gt/<ikili>.dSYM`, `analiz/<ikili>`, `log/`.
- **Betikler:** `targets/test_seti/mac_kaynaktan/betikler/`: `ortam.sh` (superenv ortamı), `unzip.sh`, `zsh.sh`, `openssh.sh`, `vim.sh`, `dogrula.sh`, `bayrak_ozeti.py`, `bolum_ozeti.py`. Çalıştırıldıkları hâliyle depodaki kopyası: `scripts/measurement/test_seti_mac_derleme/` (betikler `targets/` altındaki mutlak yollarla çalışır).
- **Ölçümde kullanım:** Gerçek isimler `gt/<ikili>`'nin `nm` çıktısından (ya da dSYM'den) alınır. Analiz girdisi `analiz/<ikili>`'dir; aynı dosyanın `/usr/bin/strip` ile soyulmuş kopyası.

| Program | Formül sürümü, yama | Derleme bayrakları | sha256 (analiz girdisi) | sha256 (GT) | UUID | nm -U t/T (GT) | dSYM UUID eşleşmesi | Export trie boş mu | Minimum macOS |
|---|---|---|---|---|---|---|---|---|---|
| unzip (`unzip`) | `unzip` 6.0_8 (şişe rebuild 1); 29 Ubuntu yaması (`unzip_6.0-28ubuntu4.1`), 29/29 temiz uygulandı | `-w -Os -g -DBSD -DUNIX` ve formülün 5 `LOC` makrosu; bağlama `-liconv -lbz2 -Wl,-headerpad_max_install_names`; `strip` adımı kapalı | `84999ab7fa915ce4a17da1ddbaca57eaf4da04dd55ed08bdef556fa9f4b67773` | `3445a9133e429c122dafd328eed13e5f4986db81fa5516479ed9ad8f3034109e` | `9B2A146E-BA69-3939-8DEA-66ABAB3E2B22` | t=20, T=87 (nm -U 541 satır) | evet | evet (yalnız `__mh_execute_header`) | 26.0 (SDK 26.5) |
| zsh (`zsh`) | `zsh` 5.9.2; yama yok (formüldeki `inreplace`, 2 Makefile) | `-w -Os -g -std=gnu23`; bağlama `-rdynamic -lpcre2-8 -liconv -ldl -lncursesw -lm -lc -Wl,-headerpad_max_install_names`; `-Wl,-x` yok | `6e14bd7aa782841e534c1025943283a21193ceb94da302dc8d0c93feb4807500` | `d9e50a0bcdf85b3ffaf12a89db7e95b19b7f113840b0f0716fdf371e6b9c2d72` | `8CB23E3B-1C51-3E0E-945D-306B3A28B220` | t=335, T=758 (nm -U 1641 satır) | evet | evet (yalnız `__mh_execute_header`) | 26.0 (SDK 26.5) |
| openssh (`ssh`) | `openssh` 10.6p1_1; yama yok | derlenmedi (ldns, libfido2, libcbor kurulu değil) | — | — | — | — | — | — | — |
| vim (`vim`) | `vim` 9.2.1150; yama yok | derlenmedi (lua, ruby kurulu değil) | — | — | — | — | — | — | — |

**Yöntem**
- **Formül:** Şişenin içindeki `.brew/<formül>.rb` kullanıldı, yani şişeyi üreten formül.
  - unzip, zsh ve openssh: homebrew-core `bf7ada6` ile derleme adımları aynı. Fark yalnız bottle bloğu ve meta veri.
  - vim: Homebrew 9.2.1200'e geçmiş. 9.2.1150 formülü homebrew-core `8bebb800c2da`'da ("vim: update 9.2.1150 bottle.", 2026-09-30) şişedekiyle aynı. O commit'teki arm64_tahoe sha256'sı sabitlenen şişeninkiyle aynı.
- **Kaynaklar:** `brew fetch --build-from-source` ile indirildi. vim eski sürüm olduğu için formüldeki adresten `curl` ile alındı. Hepsinin sha256'sı formülle eşleşti.
- **Derleyici sarmalayıcısı:** Homebrew'un kendi superenv kabukları kullanıldı (`shims/super/cc`, `shims/mac/super/bin/make` ve `xcrun`). Ortam `env -i` ile sıfırlandı, superenv'in koyduğu değişkenler elle verildi. Kabuk en sonda Apple clang'ı (`/usr/bin/clang`, 21.0.0) çağırıyor.
  - Gerekçe: superenv `make` altında bayrakları yeniden yazıyor. Derleme sisteminin `-O…` ve `-g…` bayraklarını ve uyarı bayraklarının çoğunu (`-W…`; `-Wl,`, `-Wno-…` gibileri kalır) siliyor, yerine `-w -Os` koyuyor; arm64 şişelerinde `HOMEBREW_OPTFLAGS` boş. Yani şişeler `-O2` ile değil `-Os` ile derlenmiş. Bu `CFLAGS` ile taklit edilemez; örneğin unzip'in `macosx` hedefi `-O3`'ü alt make'e kendisi veriyor.
  - `-g` için `HOMEBREW_CCCFG`'ye `D` eklendi (Homebrew'un `--debug-symbols` kipi). Bu kip `-ffile-prefix-map` ve `-Wl,-oso_prefix` eklemiyor. İkisi yalnız gömülü yol dizgilerini ve debug map'i etkiler. Derleme göreli yollarla yapıldığından analiz kopyasında fark yaratmaz.
  - Derleme günlüğünden sayıldı (`bayrak_ozeti.py`, configure denemeleri hariç): unzip'in 35, zsh'nin 86 derleme çağrısının hepsinde `-Os -g -w` var. `-O1`/`-O2`/`-O3`, `-Wl,-x`, `-Wl,-S` ve `-s` hiçbirinde yok.
- **Ortam:**
  - PATH: superenv kabukları, bağımlılıkların `opt/bin`'i ve `/usr/bin:/bin:/usr/sbin:/sbin`. Bu superenv'in kendi PATH'i. `/opt/homebrew/bin` bilerek konmadı, çünkü orada bağımlılık olmayan formüllerin araçları da var. Conda yolu yok.
  - `LC_ALL=en_US.UTF-8`, `TZ=UTC0`, `ZERO_AR_DATE=1`, `am_cv_func_iconv_works=yes`, `make -j6`.
  - `SOURCE_DATE_EPOCH`: şişe tab'ındaki `source_modified_time` (unzip 1240192822, zsh 1783881774).
  - SDK: `MacOSX26.sdk` (26.5), Homebrew'un bu makinede seçeceği SDK. Minimum macOS 26.0, şişelerle aynı.
  - Başlık ve kütüphane yolları: yalnız bağımlılıkların `opt/` dizinleri (bkz. sapma 5).
- **Koruma:** Derleme ve kurulum `sandbox-exec` altında çalıştı; `/opt/homebrew` altına yazma çekirdek düzeyinde engellendi. Sistem Homebrew'u değişmedi, `Cellar/` altında iz yok.
- **Strip'in kapatılması:**
  - unzip: `STRIP=true`. `macosx` hedefi derlemeden sonra `$(STRIP) $(UNZIPS)` çalıştırıyor. Bağlamada `-s` zaten yok (`LF2=""`); kurulum `cp` ile.
  - zsh: `LDFLAGS` tanımlı ama boş verildi. configure, `LDFLAGS` tanımsızsa darwin'de `LDFLAGS=-Wl,-x` koyuyor. Şişedeki nlocalsym=0'ın sebebi bu (§4.3 madde 2). Kurulumdaki `STRIPFLAGS` zaten boş.
- **Kurulum:** zsh, ikiliye gömülü yollar şişeyle aynı olsun diye `--prefix=/opt/homebrew/Cellar/zsh/5.9.2` ile yapılandırıldı ve `make install DESTDIR=…/prefix` ile kendi önekimize kuruldu. unzip'te önek ikiliye gömülmüyor; doğrudan `prefix/`'e kuruldu.
- **dSYM ve analiz kopyası:** dSYM `/usr/bin/dsymutil` ile üretildi, uyarı yok. Analiz kopyası `/usr/bin/strip` ile (mutlak yol) soyuldu.

**Doğrulamalar (yalnız sayılar; iki değer varsa bizim / şişe)**

| Ölçüt | unzip | zsh |
|---|---|---|
| Mimari | arm64 / arm64 | arm64 / arm64 |
| nm -U (GT / şişe) | 541 (t=20, T=87) / 1 (t=0, T=1) | 1641 (t=335, T=758) / 1045 (t=0, T=758) |
| nm -U (analiz kopyası) | 1 (yalnız `__mh_execute_header`) | 1 (yalnız `__mh_execute_header`) |
| nm -u (dışarıdan alınan semboller) | 85 / 85 | 193 / 193 |
| Fonksiyon başlangıcı (`dyld_info -function_starts`) | 106 / 105 | 1090 / 1090 |
| `__TEXT,__text` (bayt) | 90 020 / 92 956 | 478 396 / 477 936 |
| Bağlı kütüphaneler | aynı: libiconv, libbz2, libSystem | aynı: ncursesw 6, pcre2-8, libiconv, libSystem |
| LC_BUILD_VERSION minos / SDK / ld | 26.0 / 26.5 / 27037.1 — şişe: 26.0 / 26.0 / 1221.4 | 26.0 / 26.5 / 27037.1 — şişe: 26.0 / 26.4 / 1266.8 |
| dSYM: derleme birimi, `DW_TAG_subprogram` | 16, 404 | 32, 3128 |
| dSYM DWARF sha256 | `40633ecb6b0e39eebc7647c2338d6b2d4c20b318931bee799f2104a0bebc8621` | `e78af5e7c85d6c18e175eacc6f5f33b75f648fc4158276bc29243f593869d031` |
| Export trie (GT → analiz) | 113 → 1 | 1045 → 1 |
| Kod imzası (GT ve analiz) | geçerli (ad-hoc, linker-signed) | geçerli (ad-hoc, linker-signed) |

- **Yeniden derleme denemesi:** Aynı betikler `.tekrar/<program>/` altında ikinci kez çalıştırıldı. İki derlemenin analiz kopyalarında bütün bölümler bayt bayt aynı çıktı (`bolum_ozeti.py`). Farklı olan yalnız LC_UUID; bu yüzden dosya sha256'sı ve imza da farklı. Sebep: ld, UUID'yi debug map'teki mutlak `.o` yollarını da katarak hesaplıyor. Aynı dizinde bit bit aynılık denenmedi.

**Şişeden sapmalar**
1. **Amaçlananlar:** `-g` (debug map ve dSYM) ve strip'in kapatılması (unzip'te `strip` adımı, zsh'de `-Wl,-x`).
2. **Derleyici:** CLT 27.0 (Apple clang 21.0.0, ld 27037.1). Şişeler unzip'te CLT 26.0, zsh'de CLT 26.4 ile derlenmiş. Gözlenen fark: unzip'te fonksiyon başlangıcı 106 / 105 ve `__text` %3,2 küçük; zsh'de fonksiyon sayısı aynı, `__text` %0,1 büyük. Derleyici ve SDK sürümü dışında bilinen bir sebep yok. openssh ve vim şişeleri bu makinedekiyle aynı CLT ile (27.0.0.0.1788430756) derlenmiş.
3. **SDK:** 26.5 (şişeler: unzip 26.0, zsh 26.4). Minimum macOS aynı (26.0).
4. **pcre2:** 10.49; zsh şişesi 10.47_1 ile derlenmiş. Ana ikili pcre2'ye yalnız bağlanıyor; pcre kodu `pcre.bundle` modülünde ve modüller ölçüm dışı. ncurses 6.6, şişedekiyle aynı.
5. **Başlık ve kütüphane yolları:** Superenv `/opt/homebrew/include` ve `/opt/homebrew/lib`'i veriyor. Şişelerin derlendiği CI makinesinde orada yalnız bağımlılıklar var; bu makinede `/opt/homebrew/include` 859 girdi içeriyor. Bu yüzden yalnız bağımlılıkların `opt/` dizinleri verildi.
6. **Atlanan belge adımları:** zsh'de `make install.info` (texinfo kurulu değil) ve htmldoc kaynağı. İkiliyi etkilemez.
7. **Yol eşlemesi:** `-ffile-prefix-map` ve `-Wl,-oso_prefix` yok (bkz. Yöntem). GT'nin debug map'i mutlak derleme yollarını içeriyor; analiz kopyasında debug map yok.
8. **Dosya kopyaları:** Şişede `bin/zsh` ile `bin/zsh-5.9.2`'nin boyutları farklıydı (§4.3 madde 2). Bizim kurulumda ikisi aynı dosya (sabit bağ).
9. **Yalıtım (kural 2) kaydı:** .c/.h dosyalarına ve ikililerin içeriğine bakılmadı. Strip mekanizmasını bulmak için yalnız Makefile ve configure'un ilgili satırları okundu. Bir kez, unzip derleme günlüğünün son 3 satırı (bağlama komutları; yalnız nesne dosyası adları, bazıları genel kavram adı) ajan oturumuna düştü; belgeye girmedi.

**Açık sorunlar (karar ana oturumun)**
1. **openssh (`ssh`):** ldns, libfido2 ve libcbor kurulu değil; görev kuralı gereği kurulmadı.
   - `ssh` ikilisi ldns'e bağlanıyor. configure, `--with-security-key-builtin` için libfido2'yi arıyor.
   - Şişe ldns 1.9.2_1, libfido2 1.17.0_1 ve libcbor 0.14.0 ile derlenmiş. Homebrew'daki güncel sürümler bunlarla aynı, ama ldns artık python@3.15'e bağlı (şişe döneminde python@3.14).
   - Kaynak indirildi, sha256 eşleşti. `betikler/openssh.sh` hazır; bağımlılık denetiminde duruyor, ötesi denenmedi.
2. **vim:** lua ve ruby kurulu değil. İkisi de build bağımlılığı. Formül `--enable-luainterp=dynamic` ve `--enable-rubyinterp=dynamic` veriyor; bunlar olmadan configure bu arayüzleri derlemez ve fonksiyon kümesi şişeden ayrılır. Kaynak (9.2.1150) indirildi, sha256 eşleşti. `betikler/vim.sh` hazır; denenmedi.
3. **Seçenekler:**
   - (a) Berke'nin onayıyla `brew install ldns libfido2 lua ruby`. Sistem değişir; ruby libyaml'ı, ldns python@3.15'i de getirir.
   - (b) Bu formüllerin şişelerini `brew fetch` ile indirip yalıtılmış bir öneke açmak. Sistem değişmez, ama bağlanan kütüphanelerin kurulum adlarını şişedekiyle aynı tutmak ek iş ister.
   - (c) Bu iki program için §4.3 madde 1'deki öteki seçeneklere dönmek.
4. **vim şişesi güncel değil:** Sabitlenen şişe (9.2.1150, rebuild 0) artık homebrew-core'daki güncel şişe değil. 2026-10-14'te python@3.15 geçişiyle rebuild 1 çıktı (`67e7f9f31a30`), 2026-10-15'te de 9.2.1200 geldi. Kaynaktan derleme, sabitlenen şişenin formülünü (python@3.14) izler.
5. **`.tekrar/`** (64 MB) yalnız yeniden derleme denemesi için; silinebilir.
