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

## 4. İkili sabitleme (indirme sonrası doldurulacak)

| Program | Platform | Paket/şişe | sha256 | BuildID / UUID | Tarih |
|---|---|---|---|---|---|
| — | — | — | — | — | — |
