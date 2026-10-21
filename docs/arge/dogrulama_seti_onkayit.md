# Doğrulama seti ön kaydı (plan v2 G5)

- **Tarih:** 2026-10-19
- **Durum:** 1. aşama, ön kayıt. **Kura çekilmedi.** Ana oturumun 2026-10-19 kararları işlendi: K3'te kaynaktan derleme (§4.4), doğrulama stres alt kümesi (§7), kanıt dizini. Bu belge ve kura betiği commit edildikten sonra kura çekilir (2. aşama, §12).
- **Kura betiği:** `scripts/measurement/dogrulama_seti_kura.py` (testleri `tests/test_dogrulama_seti_kura.py`). Betik, kendisi ve bu belge git'te izlenmiyorsa ya da commit edilmemiş değişiklik taşıyorsa kura çekmez.
- **Tohum:** SHA-256(`karadul-dogrulama-seti-kura-2026-10-19`) değerinin ilk 16 hex basamağı = `604a5ed66ccbbcd3` = `6938462450958974163`
- **Stres alt tohumu:** SHA-256(`karadul-dogrulama-seti-kura-2026-10-19/stres`) değerinin ilk 16 hex basamağı = `0f41d5481ac7ccfb` = `1099394289718775035` (§7)
- **Kanıt:** `docs/arge/dogrulama_seti_kanit/`: `pool_data.json` (68 aday), `isaretli_data.json` (13 program), `README.md` (adresler, tarihler, sha256'lar)
- **Ön kayıt commit'i:** bu belgenin ve betiğin ilk commit'i. Kura çıktısının künyesinde `git HEAD`, betiğin, test seti betiğinin ve havuzun sha256'sı yazılır.
- **Dayanak:** plan v2 (`2026-10-17_plan_v2.md`) §3 madde 2, §5 G5, §7; `test_seti_kilidi.md`; `2026-10-15_makale/test_seti_adaylari.md`.

## 1. Amaç

Plan v2 üç ayrı veri kümesi kullanır:

- **Geliştirme seti:** kurallar burada yazılır (§8).
- **Doğrulama seti:** kapılar (G13, G20, G30) burada ölçülür (plan §7). Eşik seçimi de burada yapılır.
- **Test seti:** G31'e kadar kilitli (`test_seti_kilidi.md`).

Doğrulama sonucu test setini temsil etmelidir. Bu yüzden doğrulama seti test setiyle şu noktalarda aynı yapıdadır:

- dil: C;
- platformlar ve gerçek isim kaynağı: Mac'te Homebrew şişesinin `nm` çıktısı (şişede yerel sembol yoksa aynı formülden kaynaktan derlenen ikilininki, §4.4), Debian 13 arm64'te aynı sürümün `-dbgsym` paketi;
- boyut oranı: test seti 6/6/3, doğrulama seti 4/4/2 (10 program);
- çeşitlilik: farklı yazılım aileleri ve alanlar.

Doğrulama seti test setiyle, yedekleriyle, stres kümesiyle, aday listesiyle ve geliştirme setiyle kesişmez. Bunların çatalları ve ikizleri de dışarıdadır (§6).

## 2. Kullanım kuralları

1. Doğrulama programları (seçilen 10 program ve korumalı yedekler, §4.5) ile doğrulama stres alt kümesi (§7) Karadul ile yalnız kapı günlerinde analiz edilir: G13, G20, G28-G30. Başka gün analiz edilmez.
   - İşaretli listenin 13 programının hepsi aynı korumayı görür; stres yedekleri de geliştirmede kullanılmaz.
2. Kural, eşik ya da sözlük geliştirilirken bu programların kaynak koduna, ikili içeriğine ve Karadul çıktılarına bakılmaz.
   - 2. aşamadaki ikili sabitlemede yalnız sha256, UUID/BuildID, dosya boyutu, sembol sayıları ve `otool -L` bağımlılıkları kaydedilir. İsim listeleri okunmaz.
   - K3'te kaynaktan derlemede (§4.4) kaynak koduna ve derleme çıktısına bakılmaz. Yalnız formül ve derleme günlüğünün bayrak özeti okunur; doğrulama sayılarla yapılır.
3. Kapı günlerinde sonuç tablo düzeyinde okunur: program sınıfı başına makro ortalama ve risk-kapsam.
   - Fonksiyon düzeyindeki çıktı yalnız kör etiket protokolüyle etiketlenir (`etiket_rehberi.md`, plan §3 madde 5).
   - Etiketleyici, kural yazan oturumdan ayrı çalışır. Etiket paketleri kural geliştirmede kullanılmaz.
4. Kapı tutmazsa düzeltme geliştirme setinde yapılır. Doğrulama seti yalnız bir sonraki kapı gününde yeniden ölçülür.
   - Her bakış **bakış kaydına** yazılır: tarih, kapı, commit, ne görüldüğü. Makalede doğrulama setine kaç kez bakıldığı raporlanır.
5. Doğrulama programları şu işlerde kullanılmaz: LLM pilotu (G6), KaradulLM eğitim verisi, imza ya da sözlük kurulumu, "görülmemiş dilim".
6. Ön kayıttan sonra havuz, tabakalar, alan ve aile etiketleri, tohum ve algoritma değişmez. Tek istisna §4.5'teki değişim kuralıdır. Her değişim bu belgeye tarih ve gerekçeyle eklenir.

## 3. Uygunluk ölçütleri

Bir program havuza ancak hepsini sağlarsa girer. U1-U6'yı sağlamayan dışlanır (§6). Yalnız U7-U10'u sağlamayan işaretli listeye gider (§7).

| # | Ölçüt | Nasıl denetlendi |
|---|---|---|
| U1 | Dil C | Debian ikili paketi `libstdc++6`'ya bağlı değil; Homebrew'de `rust`, `go`, `zig` derleme bağımlılığı yok; Debian kaynak dizininde C dosyaları var. Başka dilden üretilmiş C (ör. Vala) sayılmaz |
| U2 | Homebrew | `homebrew/core` formülü var, `arm64_tahoe` şişesi var, formül kullanımdan kaldırılmamış (deprecated/disabled değil) |
| U3 | Debian | Debian 13.7 (trixie) `main` arm64 paketi ve **aynı sürümün** `-dbgsym` paketi var; ölçülecek ikili `Contents-arm64`'te o pakette |
| U4 | Boyut aralığı | Vekil ölçü (§4.1) test setinin en küçük ve en büyük değeri arasında: 309 ≤ vekil ≤ 70029 KiB |
| U5 | ELF sayısı | Ölçülecek ikilinin Debian paketinde en fazla 4 ELF dosyası var (dbgsym `Build-Ids` alanı). Vekil paket toplamıdır; daha çok ELF'te ölçülecek ikiliyi temsil etmez |
| U6 | Dışlama | §6'daki listelerde değil, onların çatalı ya da ikizi değil |
| U7 | gnulib yok | Debian kaynağında şu dosyaların hiçbiri yok: `gnulib-comp.m4` (`m4/` ya da `gl/m4/` altında), `lib/gnulib.mk`, `bootstrap.conf`. Yalnız gettext'in getirdiği `00gnulib.m4` ve `gnulib-common.m4` gnulib sayılmaz |
| U8 | Güçlü kütüphane ikizi yok | Programın iç adları Karadul'un 9,2M girdilik kataloğunda değil (yoklama, §9). İkili kodunu aynı kaynaktan bir paylaşımlı kütüphaneden almıyor (Debian `Depends`) |
| U9 | Üretilmiş kod baskın değil | Fonksiyonların büyük kısmı derlemede bir üreteçle üretilmiyor |
| U10 | Geliştirme setine işlevce yakın değil | `screen` emsali: test setinde tmux'a benzediği için stres kümesine alınmıştı |

## 4. Yöntem

### 4.1 Boyut vekili ve tabakalar

- **Vekil ölçü:** ölçülecek ikilinin Debian paketine ait `-dbgsym` paketinin `Installed-Size` değeri (KiB).
- **Neden bu ölçü:**
  - 1. aşamada ikili indirilmedi.
  - Ana paketin `Installed-Size` değeri belgeleri, çevirileri ve veri dosyalarını da sayıyor. Örnek: prodigal 12 MB görünüyor, dbgsym'i 117 KiB.
  - dbgsym paketi yalnız ELF dosyalarının hata ayıklama bilgisini taşır.
- **Eşikler test setinden türetildi.** Test setinin 15 ana programının aynı ölçüdeki değerleri, kilit belgesi §4.1'deki sürümlerle (2026-10-19'da birebir aynı olduğu denetlendi):

| dash | mawk | unzip | dcraw | gifsicle | dnsmasq | rsync | nasm | memcached | zsh | gpg | vim | ssh | haproxy | git |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 309 | 370 | 569 | 669 | 797 | 1061 | 1111 | 1180 | 1789 | 3062 | 3312 | 8971 | 9096 | 11299 | 70029 |

- **Sınırlar:**
  - Küçük/orta sınırı, 6. ve 7. değerin ortası: T1 = (1061 + 1111) / 2 = **1086 KiB**.
  - Orta/büyük sınırı, 12. ve 13. değerin ortası: T2 = (8971 + 9096) / 2 = **9033,5 KiB**.
- **Tabakalar:** küçük < 1086 ≤ orta ≤ 9033,5 < büyük.
- **Sonuç:** test seti bu ölçüde 6/6/3 bölünür. Doğrulama kotası aynı orandır: 10 × (6, 6, 3) / 15 = (4, 4, 2).
- **Dürüstlük notu:** Vekil, test setinin dağılımını korur, tek tek programların kilit belgesindeki tahmini etiketlerini değil. Vekille dört program tabaka değiştirir:
  - memcached küçükten ortaya geçer;
  - dnsmasq ortadan küçüğe geçer;
  - vim büyükten ortaya geçer;
  - ssh ortadan büyüğe geçer.
- **Bilinen sapmalar:**
  - Çok ELF'li paketlerde vekil şişer: test setinde ssh (10 ELF), havuzda tor ve ipv6calc (4 ELF).
  - Aynı programın birden çok derlemesi de vekili şişirir: mksh, sslh.
  - 2. aşamada gerçek ikili boyutları ölçülür ve kayda geçer. **Tabaka değişmez.**
  - Ayrıntı ve tam liste §10'da. Ana oturum kararı (2026-10-19): vekil ve akış korunur.
- **Test seti meta verisinin kullanımı** (ana oturum kararıyla kabul, 2026-10-19):
  - Eşikler için test setinin 15 programının yalnız Debian Packages meta verisi okundu: dbgsym boyutu ve sürüm. İkili, kaynak ve Karadul çıktısı okunmadı.
  - Değerler, paket adları ve ELF sayıları `dogrulama_seti_kanit/README.md`'de.
  - Testlerden biri, bu 15 adın test setinin yayımlı kurasıyla aynı olduğunu `test_seti_kura.draw()` ile yeniden üreterek denetler. Bu, kilit belgesinde zaten yayımlı listedir; doğrulama kurası değildir.

### 4.2 Alan ve aile

**Alan sözlüğü (17).** Her program birincil amacına göre etiketlendi:

| Alan | Tanım |
|---|---|
| ağ altyapısı | ağ hizmeti, tünel, ölçüm, tarama, trafik sayımı |
| iletişim | insanlar arası ileti: e-posta, sohbet, haber grubu |
| güvenlik | saldırı ve gizlilik araçları |
| sistem yönetimi | izleme, zaman eşitleme, günlük izleme |
| dosya sistemi | dosya sistemi oluşturma, onarma, kurtarma |
| dosya yönetimi | dosya yöneticisi, kopya bulma |
| editör | metin düzenleyici |
| kabuk | komut kabuğu |
| geliştirme araçları | yapı aracı, ayrıştırıcı üreteci, kod gezgini, statik çözümleyici |
| dil yorumlayıcısı | genel amaçlı dil yorumlayıcısı |
| metin ve belge | biçim dönüştürme, sayfalama |
| medya | ses, görüntü, nota, çizim |
| bilim | biyoinformatik, sayısal matematik |
| oyun | oyun ve oyun yorumlayıcısı |
| kişisel bilgi ve ofis | takvim, hatırlatıcı, elektronik tablo |
| seri iletişim | seri port terminali |
| web tarayıcı | metin tabanlı web tarayıcı |

**Aile** kod soyudur: ortak kaynak, çatal ya da gömülü ortak kod. Havuzda paylaşılan tek aile `klib (Heng Li)`: minimap2 ve bwa. İkisinin kaynağında da klib dosyaları var (`khash.h`, `kseq.h`, `ksort.h`, `kvec.h`, `kthread.c`; dosya adı düzeyinde doğrulandı). Öteki ailelerin her biri tek üyeli.

**Kısıtlar:**

- Aynı aileden en fazla bir program seçilir. Bu kısıt hiç gevşemez.
- Aynı alandan en fazla bir program seçilir. Bu kısıt yalnız bir yer başka türlü doldurulamıyorsa gevşer. Gevşeme kura çıktısına yazılır.
- Alan sözlüğü ve bu iki kısıt ana oturumca kabul edildi (2026-10-19).

**Kabuk ailesi kararı (gerekçeli).**

- **Dışarıda:** test setindeki dash ve zsh ile kod soyu ortak olanlar.
  - ash türevleri: busybox ash, NetBSD ve FreeBSD sh.
  - zsh çatalları.
- **Havuzda:** tcsh (csh soyu) ve mksh (pdksh soyu). İkisi de dash ve zsh ile kod paylaşmıyor. "Test setiyle aynı alan" işaretini taşıyorlar.
- **Gerekçe:**
  - Sızıntı ortak kodla olur. Ortak kod taşıyan program doğrulamaya girerse, kapı günü ona bakmak test programının kodunun çıktısına bakmak olur. Bu, kilit belgesinin 2. kuralını dolaylı olarak çiğner.
  - Bağımsız bir uygulama ise test setindeki bir alanı temsil eder; doğrulamanın amacı da budur.
  - Alan kısıtı nedeniyle doğrulama setine en fazla bir kabuk çıkar.
- **Aynı ilke öteki alanlarda da uygulandı.** "Aynı alan" ya da "aynı işlev" işaretiyle havuzda kalanlar:
  - editörler: ne, mle, jove, joe (vim ile);
  - links (yedekteki lynx ile);
  - pspg (yedekteki less ile);
  - nsd (dnsmasq ile, DNS).
- **Geliştirme setine yakınlık ayrı kurala bağlı (U10).** Geliştirme setindeki bir programa benzeyen program doğrulamaya girerse, orada yazılan kurallar ona kolay geçer ve kapı sonucu şişer. Bu yüzden geliştirme setinin işlevce eşleri dışarıda (§6.3).

### 4.3 Kura algoritması

1. Havuz tabakalara ayrılır (§4.1). Her tabakanın üyeleri alfabetik sıralanır.
2. Üreteç `random.Random(tohum)` kurulur. Tabakaların sıraları küçük, orta, büyük düzeninde `shuffle` ile karıştırılır. Üreteç başka bir şey için kullanılmaz; stres alt kümesi ayrı alt tohumla çekilir (§7).
3. Seçim kıt tabakadan başlar: büyük, orta, küçük. Her tabakada karışık sıra baştan taranır; aile ve alan kısıtını sağlayan ilk programlar kota dolana kadar alınır.
4. Kota dolmazsa aynı tarama alan kısıtı gevşetilerek tekrarlanır. Aile kısıtı gevşemez.
5. Yine dolmazsa eksik yer, komşu tabakanın kalan sırasından aynı kurallarla doldurulur:
   - büyük için orta, sonra küçük;
   - orta için küçük, sonra büyük;
   - küçük için orta, sonra büyük.
6. Her tabakanın **yedek sırası**, karışık sırada seçilmeyen programlardır.

Betik Python 3.12.7 ile yazıldı ve test edildi. Kura çıktısının künyesine Python sürümü yazılır. Yeniden üretim aynı Python sürümüyle yapılmalıdır.

### 4.4 Mac gerçek isim kaynağı (K3) ve koşulamama ölçütleri

**K3: Mac şişesinde yerel sembol yoksa program değiştirilmez, kaynaktan derlenir.**

- **Karar:** ana oturum, 2026-10-19.
- **Gerekçe:** test setinde aynı durumda Berke'nin kararıyla kaynaktan derlendi (`test_seti_kilidi.md` §4.4-4.5); yöntem iki kümede simetrik olmalı. Değişim, şişesi soyulmuş programları sistematik olarak dışarıda bırakırdı. Soyulma rastgele değildir (ör. kendi Makefile'ıyla kuran projeler).
- **K3 koşulu** (ikisinden biri):
  - ölçülecek ikilinin `nm -U` çıktısı en fazla 1 satır (tamamen soyulmuş; test setinde unzip, ssh, vim);
  - çıktıda hiç küçük harf `t` satırı yok ve Debian `.debug` dosyasının `.symtab`'ında yerel FUNC sayısı sıfırdan büyük (yerel semboller soyulmuş; test setinde zsh).
- **Yöntem.** Şablon: `scripts/measurement/test_seti_mac_derleme/`. Ayrıntı: `test_seti_kilidi.md` §4.5.
  - **Formül:** şişeyle aynı formül sürümü. Şişenin içindeki `.brew/<formül>.rb` kullanılır, yani şişeyi üreten formül. Sürüm Ek A'dakiyle aynı olmalı.
  - **Kaynak:** formüldeki adresten (`brew fetch --build-from-source` ya da `curl`). sha256 formülle eşleşmeli.
  - **Derleyici:** Homebrew'un superenv kabukları (`shims/super/cc`, `shims/mac/super/bin/make` ve `xcrun`). Ortam `env -i` ile sıfırlanır (`ortam.sh`). `HOMEBREW_CCCFG`'ye `D` eklenir, yani `-g` açık. Optimizasyon şişeyle aynı: `-Os`.
  - **Strip kapalı:** formülün ya da derleme sisteminin soyma adımları etkisiz bırakılır (`-s`, `-Wl,-x`, `install -s`, `$(STRIP)`).
  - **Koruma:** derleme `sandbox-exec` altında çalışır; `/opt/homebrew` altına yazılmaz. Kurulum `DESTDIR` ile kendi önekimize yapılır.
  - **Çıktılar:**
    - `gt/<ikili>`: sembollü ikili, gerçek isim kaynağı;
    - `gt/<ikili>.dSYM`: `dsymutil` çıktısı;
    - `analiz/<ikili>`: aynı dosyanın `/usr/bin/strip` ile soyulmuş kopyası, analiz girdisi.
    - Konum depo ve Spotlight dışında olmalı (öneri: `targets/dogrulama_seti/mac_kaynaktan/<program>/`).
  - **Doğrulama:** `dogrula.sh` ile yalnız sayılar, sha256, UUID ve kütüphane yolları basılır; hiçbir isim basılmaz.
    - GT'de yerel sembol bulunmalı.
    - Analiz kopyasında export trie boşalmalı (yalnız `__mh_execute_header`).
  - **Bağımlılık:** derleme bağımlılığı kurulu değilse kurulum Berke'nin onayına bağlıdır. Onay bekleme süresi aşağıdaki 30 dakikaya sayılmaz.
- **Süre sınırı:** bütün denemeler dahil derleme 30 dakikalık duvar saatinde başarıyla bitmezse program koşulamaz sayılır: **K6**.
  - Derleme şu adımları kapsar: yapılandırma, derleme, kurulum, dSYM ve soyma.
  - Çıkan GT ikilisinde K3 koşulu sürüyorsa da sonuç K6'dır.

**Koşulamama ölçütleri.** Aşağıdakilerden biri olursa program koşulamaz sayılır ve §4.5 uygulanır.

| # | Ölçüt |
|---|---|
| K1 | Homebrew şişesi Ek A'daki sha256 ile indirilemiyor |
| K2 | Debian paketi ya da aynı sürümün dbgsym'i deb.debian.org'da da snapshot.debian.org'da da yok; ya da ikilinin BuildID'si dbgsym'deki `.debug` ile eşleşmiyor |
| K4 | Mac ikilisi (şişedeki ya da kaynaktan derlenen) kodunu aynı formülün kendi dinamik kütüphanesinden alıyor (`otool -L` çıktısında formülün kendi keg'indeki bir dylib var). Şişesinde kendi kütüphanesi olan mosquitto, lowdown, mpv, profanity, freeciv ve pari'de özellikle bakılır |
| K5 | Ölçülecek ikili şişede ya da pakette yok |
| K6 | K3 nedeniyle başlayan kaynaktan derleme 30 dakikada başarıyla bitmedi ya da derlenen ikilide yine yerel sembol yok |

K3 bir koşulamama nedeni değildir. Betik `--kosulamayan ad:K3` girdisini reddeder ve kura çekmez.

### 4.5 Değişim kuralı

Test seti kilit belgesindeki 4. kuralın karşılığıdır. Yalnız K1, K2, K4, K5 ve K6 nedenleriyle uygulanır.

1. **Yedekten doldurma.** Koşulamayan programın yerine aynı tabakanın yedek sırasından şu program gelir: sırada, kümede kalan programlarla aile ve alan çakışması olmayan ilk program.
   - Böyle bir program yoksa alan kısıtı gevşer.
   - O da yoksa komşu tabakanın yedek sırasına geçilir (§4.3 madde 5).
   - Kümenin geri kalanı değişmez.
2. **Uygulama.** Kural betikte mekaniktir:
   - komut: `python scripts/measurement/dogrulama_seti_kura.py --kosulamayan ad:NEDEN,ad:NEDEN` (ör. `--kosulamayan mpv:K4,tor:K6`);
   - nedeni yazılmamış, bilinmeyen ya da K3 olan girdi reddedilir ve kura çekilmez;
   - sonuç, koşulamayanlar kümesinin işlevidir; sırası önemli değildir; çıktıdaki her değişimde neden yazılır;
   - yedek de koşulamazsa listeye eklenip betik yeniden çalıştırılır;
   - stres alt kümesindeki bir program aynı komutla, stres yedek sırasından değiştirilir (§7).
3. **Korumalı yedekler.** Her tabakada yedek sırasının ilk *kota* kadar programı (4/4/2) korumalı yedektir. Bunlar doğrulama programı gibi korunur (§2) ve geliştirme setine verilmez.
4. **Kayıt.** Her değişim bu belgeye eklenir: tarih, çıkan, giren, hangi ölçüt.

### 4.6 Doğrulama seti boyutu

Hedef 10 programdır. Bir tabakanın yedekleri tükenirse ve komşu tabakadan da doldurulamazsa yer boş kalır. Kümenin 8'in altına düşmesi ana oturumun kararını gerektirir; plan 8-10 program istiyor.

## 5. Havuz (68 aday)

**Dağılım:**

- Tabaka: küçük 38, orta 23, büyük 7.
- Ayrı alan sayısı: küçük 16, orta 11, büyük 7.
- Bütün adaylarda dbgsym, ikiliyle aynı sürümde var.
- Homebrew şişelerinin `arm64_tahoe` özeti GHCR dizinindeki özetle eşleşti (68/68).

**"Sürüm eşleşmesi" sütununun anlamı** (Homebrew ile Debian upstream sürümü arasında):

- aynı: bütün sayısal bileşenler eşit;
- yakın: ilk iki bileşen eşit;
- farklı: geri kalan her durum.

| # | Program | Ölçülecek ikili (Mac / Debian) | Alan | Aile | Tabaka (vekil KiB · ELF) | Homebrew | Debian 13 arm64 | Sürüm eşleşmesi | İşaret / not |
|---|---|---|---|---|---|---|---|---|---|
| 1 | abcm2ps | `abcm2ps` / `abcm2ps` | medya | abcm2ps | küçük (816 · 1) | `abcm2ps` 8.14.18 | `abcm2ps` 8.14.17-2 | yakın | — |
| 2 | bitlbee | `bitlbee` / `bitlbee` | iletişim | bitlbee | küçük (1082 · 1) | `bitlbee` 3.6 (rebuild 2) | `bitlbee` 3.6-1.5 | aynı | — |
| 3 | bmake | `bmake` / `bmake` | geliştirme araçları | NetBSD make | küçük (487 · 1) | `bmake` 20260912 | `bmake` 20200710-17 | farklı | — |
| 4 | bogofilter | `bogofilter` / `bogofilter-sqlite` | iletişim | bogofilter | küçük (710 · 4) | `bogofilter` 1.2.5 (rebuild 1) | `bogofilter-sqlite` 1.2.5-1+b4 | aynı | Homebrew macOS sqlite'ını kullanıyor; Debian'da aynı arka uçlu bogofilter-sqlite seçildi |
| 5 | bwa | `bwa` / `bwa` | bilim | klib (Heng Li) | küçük (461 · 1) | `bwa` 0.7.19 (rebuild 1) | `bwa` 0.7.18-1 | yakın | minimap2 ile aynı aile; kurada en fazla biri |
| 6 | byacc | `byacc` / `byacc` | geliştirme araçları | byacc | küçük (330 · 1) | `byacc` 20260126 | `byacc` 1:2.0.20241231-1 | farklı | bakımcı T. Dickey (test setindeki mawk ve yedekteki lynx de onun bakımında); ortak kod yok |
| 7 | calcurse | `calcurse` / `calcurse` | kişisel bilgi ve ofis | calcurse | küçük (744 · 1) | `calcurse` 4.8.2 | `calcurse` 4.8.1-1.3 | yakın | — |
| 8 | distcc | `distcc` / `distcc` | geliştirme araçları | distcc | küçük (876 · 4) | `distcc` 3.4_3 (rebuild 2) | `distcc` 3.4+really3.4-12 | aynı | — |
| 9 | dnsperf | `dnsperf` / `dnsperf` | ağ altyapısı | dnsperf | küçük (454 · 2) | `dnsperf` 2.16.0_1 | `dnsperf` 2.14.0-5 | farklı | — |
| 10 | dosfstools | `fsck.fat` / `fsck.fat` | dosya sistemi | dosfstools | küçük (400 · 3) | `dosfstools` 4.2 | `dosfstools` 4.2-1.2 | aynı | — |
| 11 | enscript | `enscript` / `enscript` | metin ve belge | GNU enscript | küçük (737 · 3) | `enscript` 1.6.6_1 | `enscript` 1.6.5.90-3.1+b2 | yakın | GNU projesi; gnulib işareti yok |
| 12 | fetchmail | `fetchmail` / `fetchmail` | iletişim | fetchmail | küçük (624 · 1) | `fetchmail` 6.6.9 | `fetchmail` 6.4.39-1+b2 | farklı | m4/ altında yalnız gettext'in getirdiği 00gnulib.m4 ve gnulib-common.m4 var; gnulib-comp.m4 yok |
| 13 | flex | `flex` / `flex` | geliştirme araçları | flex | küçük (602 · 1) | `flex` 2.6.4_2 | `flex` 2.6.4-8.2+b4 | aynı | libfl'nin iki genel adı (yylex, yywrap) katalogda; flex'in kendi kodu değil |
| 14 | frotz | `frotz` / `frotz` | oyun | frotz | küçük (579 · 2) | `frotz` 2.55 (rebuild 1) | `frotz` 2.55+dfsg-2 | aynı | — |
| 15 | hydra | `hydra` / `hydra` | güvenlik | THC-Hydra | küçük (530 · 2) | `hydra` 9.7_1 | `hydra` 9.5-3 | farklı | — |
| 16 | iodine | `iodine` / `iodine` | ağ altyapısı | iodine | küçük (315 · 2) | `iodine` 0.8.0 (rebuild 1) | `iodine` 0.7.0-11 | farklı | — |
| 17 | isync | `mbsync` / `mbsync` | iletişim | isync | küçük (565 · 2) | `isync` 1.5.1_1 | `isync` 1.5.1-1 | aynı | — |
| 18 | jove | `jove` / `jove` | editör | jove | küçük (623 · 2) | `jove` 4.17.5.5 | `jove` 4.17.5.4-1 | yakın | test setiyle aynı alan (vim) |
| 19 | kalign | `kalign` / `kalign` | bilim | kalign | küçük (504 · 2) | `kalign` 3.5.1 (rebuild 1) | `kalign` 1:3.4.0-1+b3 | farklı | — |
| 20 | lowdown | `lowdown` / `lowdown` | metin ve belge | lowdown | küçük (505 · 1) | `lowdown` 3.2.1 | `lowdown` 2.0.2-2 | farklı | aynı kaynaktan kütüphane (liblowdown; Mac şişesinde liblowdown.5.dylib); katalogda 0/4 |
| 21 | minicom | `minicom` / `minicom` | seri iletişim | minicom | küçük (489 · 3) | `minicom` 2.11.1 | `minicom` 2.10-1 | farklı | — |
| 22 | minimap2 | `minimap2` / `minimap2` | bilim | klib (Heng Li) | küçük (460 · 1) | `minimap2` 2.31 | `minimap2` 2.27+dfsg-1+b4 | farklı | bwa ile aynı aile; kurada en fazla biri |
| 23 | mle | `mle` / `mle` | editör | mle | küçük (339 · 1) | `mle` 1.8.1 (rebuild 1) | `mle` 1.7.2-1+b1 | farklı | test setiyle aynı alan (vim); gömülü termbox2 adları katalogda 0/3 |
| 24 | mosquitto | `mosquitto` / `mosquitto` | ağ altyapısı | Eclipse Mosquitto | küçük (949 · 4) | `mosquitto` 2.1.2_2 | `mosquitto` 2.0.21-1 | farklı | aynı kaynaktan kütüphane (libmosquitto; Mac şişesinde libmosquitto.2.1.2.dylib); katalogda 0/4 |
| 25 | mtools | `mtools` / `mtools` | dosya sistemi | GNU mtools | küçük (567 · 2) | `mtools` 4.0.49 | `mtools` 4.0.48-1 | yakın | GNU projesi; gnulib işareti yok |
| 26 | multitail | `multitail` / `multitail` | sistem yönetimi | multitail | küçük (597 · 1) | `multitail` 7.1.6 | `multitail` 7.1.5-2 | yakın | — |
| 27 | ne | `ne` / `ne` | editör | ne | küçük (484 · 1) | `ne` 3.3.4 | `ne` 3.3.3-1 | yakın | test setiyle aynı alan (vim) |
| 28 | newlisp | `newlisp` / `newlisp` | dil yorumlayıcısı | newlisp | küçük (428 · 1) | `newlisp` 10.7.5 | `newlisp` 10.7.5-2+b4 | aynı | — |
| 29 | ngircd | `ngircd` / `ngircd` | iletişim | ngIRCd | küçük (309 · 1) | `ngircd` 28 (rebuild 1) | `ngircd` 27-2+b1 | farklı | vekil ölçü alt sınıra eşit (309 KiB) |
| 30 | pspg | `pspg` / `pspg` | metin ve belge | pspg | küçük (724 · 1) | `pspg` 5.8.16 | `pspg` 5.8.9-1 | yakın | test yedeğiyle aynı işlev (less) |
| 31 | remind | `remind` / `remind` | kişisel bilgi ve ofis | remind | küçük (869 · 1) | `remind` 06.03.06 | `remind` 05.03.07-1+deb13u1 | farklı | — |
| 32 | rmlint | `rmlint` / `rmlint` | dosya yönetimi | rmlint | küçük (964 · 1) | `rmlint` 2.10.3 | `rmlint` 2.10.2-0.2 | yakın | — |
| 33 | sc-im | `sc-im` / `sc-im` | kişisel bilgi ve ofis | sc-im | küçük (463 · 1) | `sc-im` 0.8.5_4 | `sc-im` 0.8.4+ds-1+b1 | yakın | — |
| 34 | squashfs-tools | `mksquashfs` / `mksquashfs` | dosya sistemi | squashfs-tools | küçük (559 · 2) | `squashfs` 4.7.5 | `squashfs-tools` 1:4.6.1-1+b1 | farklı | — |
| 35 | sslh | `sslh` / `sslh` | ağ altyapısı | sslh | küçük (962 · 4) | `sslh` 2.3.1 | `sslh` 2.1.4-1+b1 | farklı | Debian paketinde aynı programın üç derlemesi var (sslh, sslh-ev, sslh-select); vekil şişik |
| 36 | tcsh | `tcsh` / `tcsh` | kabuk | csh/tcsh | küçük (501 · 1) | `tcsh` 6.24.16 | `tcsh` 6.24.13-2+b1 | yakın | test setiyle aynı alan (dash, zsh) |
| 37 | vnstat | `vnstat` / `vnstat` | ağ altyapısı | vnstat | küçük (562 · 2) | `vnstat` 2.13 (rebuild 1) | `vnstat` 2.13-1 | aynı | — |
| 38 | zmap | `zmap` / `zmap` | ağ altyapısı | zmap | küçük (387 · 3) | `zmap` 4.4.0 (rebuild 1) | `zmap` 2.1.1-2.1+b2 | farklı | — |
| 39 | angband | `angband` / `angband` | oyun | Angband | orta (4228 · 1) | `angband` 4.2.6 | `angband` 1:4.2.5+dfsg1-3 | yakın | — |
| 40 | chrony | `chronyd` / `chronyd` | sistem yönetimi | chrony | orta (1094 · 2) | `chrony` 4.9 | `chrony` 4.6.1-3+deb13u2 | farklı | — |
| 41 | cscope | `cscope` / `cscope` | geliştirme araçları | cscope | orta (1301 · 1) | `cscope` 15.9 | `cscope` 15.9-2+b2 | aynı | — |
| 42 | exim | `exim` / `exim4` | iletişim | Exim | orta (3021 · 1) | `exim` 4.100.1 (rebuild 1) | `exim4-daemon-light` 4.98.2-1+deb13u4 | farklı | — |
| 43 | fig2dev | `fig2dev` / `fig2dev` | medya | fig2dev | orta (1380 · 4) | `fig2dev` 3.2.9a (rebuild 1) | `fig2dev` 1:3.2.9a-4 | aynı | — |
| 44 | freeciv | `freeciv-server` / `freeciv-server` | oyun | Freeciv | orta (7650 · 1) | `freeciv` 3.2.6 | `freeciv-server` 3.1.4+ds-2+deb13u1 | farklı | Mac şişesinde kendi kütüphanesi (libfreeciv.dylib) |
| 45 | gnugo | `gnugo` / `gnugo` | oyun | GNU Go | orta (1359 · 1) | `gnu-go` 3.8_1 | `gnugo` 3.8-13+b1 | aynı | GNU projesi; gnulib işareti yok |
| 46 | joe | `joe` / `joe` | editör | joe | orta (1226 · 1) | `joe` 4.8 | `joe` 4.6-2 | farklı | test setiyle aynı alan (vim) |
| 47 | links | `links` / `links` | web tarayıcı | Links (Patočka) | orta (2829 · 1) | `links` 2.30_1 | `links` 2.29-2+b3 | farklı | test yedeğiyle aynı işlev (lynx) |
| 48 | mksh | `mksh` / `mksh` | kabuk | pdksh/mksh | orta (1317 · 3) | `mksh` 59c | `mksh` 59c-41+b2 | aynı | test setiyle aynı alan (dash, zsh); Debian paketinde aynı kaynaktan üç derleme (mksh, lksh, mksh-static); vekil şişik |
| 49 | monit | `monit` / `monit` | sistem yönetimi | monit | orta (1789 · 1) | `monit` 6.0.0_1 | `monit` 1:5.34.3-1 | farklı | — |
| 50 | mpv | `mpv` / `mpv` | medya | mpv | orta (5644 · 1) | `mpv` 0.41.0_10 | `mpv` 0.40.0-3+deb13u1 | farklı | aynı kaynaktan kütüphane (libmpv; Mac şişesinde libmpv.2.dylib); katalogda 0/4 |
| 51 | nagios | `nagios` / `nagios4` | sistem yönetimi | Nagios | orta (1552 · 2) | `nagios` 4.5.14 | `nagios4-core` 4.4.6-4.1+deb13u1 | farklı | — |
| 52 | nethack | `nethack` / `nethack-console` | oyun | NetHack | orta (5279 · 1) | `nethack` 5.0.0_1 | `nethack-console` 3.6.7-1+b4 | farklı | Debian'da gerçek ikili usr/lib/games/nethack/ altında |
| 53 | nsd | `nsd` / `nsd` | ağ altyapısı | NLnet Labs | orta (6663 · 4) | `nsd` 4.15.3 | `nsd` 4.12.0-1 | farklı | kısmi ikiz: unbound ile ortak kod (rbtree_create katalogda, lib=unbound; 1/4); test setiyle aynı alan (dnsmasq: DNS) |
| 54 | profanity | `profanity` / `profanity` | iletişim | profanity | orta (3016 · 2) | `profanity` 0.19.0 | `profanity` 0.15.0-1 | farklı | Mac şişesinde kendi kütüphanesi (libprofanity.0.dylib) |
| 55 | splint | `splint` / `splint` | geliştirme araçları | splint | orta (3862 · 1) | `splint` 3.1.2 (rebuild 1) | `splint` 1:3.1.2+dfsg-5+b2 | aynı | — |
| 56 | testdisk | `testdisk` / `testdisk` | dosya sistemi | CGSecurity | orta (2449 · 3) | `testdisk` 7.2 (rebuild 1) | `testdisk` 7.2-0.1 | aynı | — |
| 57 | timidity | `timidity` / `timidity` | medya | TiMidity++ | orta (2728 · 1) | `timidity` 2.15.0_3 | `timidity` 2.14.0-8.3+b1 | farklı | — |
| 58 | tin | `tin` / `tin` | iletişim | tin | orta (1985 · 1) | `tin` 2.6.6 | `tin` 1:2.6.5~20250409-1 | yakın | — |
| 59 | vifm | `vifm` / `vifm` | dosya yönetimi | vifm | orta (3997 · 1) | `vifm` 0.14.4 | `vifm` 0.14-3 | yakın | — |
| 60 | weechat | `weechat` / `weechat` | iletişim | weechat | orta (2594 · 1) | `weechat` 4.10.1_1 (rebuild 1) | `weechat-curses` 4.6.3-1 | farklı | IRC kodu ayrı eklentide (irc.so); ölçülen ikili çekirdek |
| 61 | zabbix | `zabbix_agentd` / `zabbix_agentd` | sistem yönetimi | Zabbix | orta (1708 · 1) | `zabbix` 7.4.15 | `zabbix-agent` 1:7.0.22+dfsg-1~deb13u1 | farklı | — |
| 62 | alpine | `alpine` / `alpine` | iletişim | Alpine (UW Pine) | büyük (13799 · 4) | `alpine` 2.26 (rebuild 2) | `alpine` 2.26+dfsg-3 | aynı | gömülü UW c-client; katalogda 0/10 |
| 63 | gnome-builder | `gnome-builder` / `gnome-builder` | geliştirme araçları | GNOME Builder | büyük (15033 · 4) | `gnome-builder` 50.0 (rebuild 1) | `gnome-builder` 48.0-2+b1 | farklı | GTK4 tümleşik geliştirme ortamı; büyük tabaka taramasında bulundu; katalogda iç adlar 0/4 |
| 64 | ipv6calc | `ipv6calc` / `ipv6calc` | ağ altyapısı | ipv6calc | büyük (19715 · 4) | `ipv6calc` 4.4.1 | `ipv6calc` 4.1.0-0.2 | farklı | pakette 4 ELF ortak statik kütüphaneyi taşıyor, vekil şişik; büyük veri tabloları olabilir (şişenin kurulu boyutu 14,9 MB; doğrulanmadı) |
| 65 | pari | `gp` / `gp-2.17` | bilim | PARI/GP | büyük (27007 · 1) | `pari` 2.19.0 | `pari-gp` 2.17.2-1 | farklı | Mac şişesinde kendi kütüphanesi (libpari-gmp-tls.dylib) |
| 66 | php | `php` / `php8.4` | dil yorumlayıcısı | PHP | büyük (14422 · 1) | `php@8.4` 8.4.26_1 | `php8.4-cli` 8.4.24-1~deb13u1 | yakın | aynı kaynaktan kütüphane (Debian libphp8.4-embed, Mac şişesinde Apache modülü libphp.so); katalogda 0/12; üretilmiş Zend VM işleyicileri; Debian'da bazı eklentiler ayrı .so (php8.4-common) |
| 67 | qemu-img | `qemu-img` / `qemu-img` | dosya sistemi | QEMU | büyük (24463 · 4) | `qemu` 11.1.2 | `qemu-utils` 1:10.0.13+ds-0+deb13u1 | farklı | üretilmiş QAPI kodu payı var; disk imajı aracı; pakette 4 ELF ortak blok katmanını taşıyor, vekil şişik; QEMU'nun sistem öykünücüleri dışarıda (§6.4); katalogda 0/3 |
| 68 | tor | `tor` / `tor` | güvenlik | Tor | büyük (10606 · 4) | `tor` 0.4.9.14_1 | `tor` 0.4.9.11-0+deb13u1 | yakın | kısmi ikiz: gömülü kripto kodu (curve25519_donna, crypto_scalarmult_curve25519 katalogda; 2/4) |

**Alanlara göre dağılım:**

| Alan | Küçük | Orta | Büyük |
|---|---|---|---|
| ağ altyapısı | dnsperf, iodine, mosquitto, sslh, vnstat, zmap | nsd | ipv6calc |
| iletişim | bitlbee, bogofilter, fetchmail, isync, ngircd | exim, profanity, tin, weechat | alpine |
| güvenlik | hydra | — | tor |
| sistem yönetimi | multitail | chrony, monit, nagios, zabbix | — |
| dosya sistemi | dosfstools, mtools, squashfs-tools | testdisk | qemu-img |
| dosya yönetimi | rmlint | vifm | — |
| editör | jove, mle, ne | joe | — |
| kabuk | tcsh | mksh | — |
| geliştirme araçları | bmake, byacc, distcc, flex | cscope, splint | gnome-builder |
| dil yorumlayıcısı | newlisp | — | php |
| metin ve belge | enscript, lowdown, pspg | — | — |
| medya | abcm2ps | fig2dev, mpv, timidity | — |
| bilim | bwa, kalign, minimap2 | — | pari |
| oyun | frotz | angband, freeciv, gnugo, nethack | — |
| kişisel bilgi ve ofis | calcurse, remind, sc-im | — | — |
| seri iletişim | minicom | — | — |
| web tarayıcı | — | links | — |

**Havuzun nasıl kurulduğu.**

- Havuz elle derlendi. Test setinin aday havuzu da öyle kurulmuştu.
- 200'den fazla program incelendi. Ölçütler (§3) her birine aynı sırayla uygulandı; ölçütleri sağlayanların hepsi havuza alındı.
- Büyük tabaka için ayrıca sistematik bir tarama yapıldı: Debian ∩ Homebrew, vekil 9033,5-70029 KiB, en fazla 4 ELF, `libstdc++` bağımlılığı yok. Taramadan çıkan C programları tor, alpine, unbound, hatari, pari, ipv6calc, gnome-builder, qemu-utils (`qemu-img`) ve QEMU'nun sistem öykünücüleri. php ad farkı (`php8.4`) yüzünden taramada görünmedi, elle eklendi. QEMU sistem öykünücülerinin neden dışarıda olduğu §6.4'te.
- Seçim yanlılığı havuz düzeyinde kalır. Havuz içinde seçim kurayla yapılır.

## 6. Dışlananlar

### 6.1 Liste gereği (betikte `EXCLUDED`)

- **Test seti:**
  - 15 ana program;
  - 5 yedek: ag, less, cmus, tcpdump, lynx;
  - 5 stres programı: wget, nano, screen, lua, pigz.
  - Bu 25 ad betikte `test_seti_kura.py`'den okunur.
  - Takma adları da listede: gnupg, openssh, the_silver_searcher, dnsmasq-base, vim-nox, dash-shell.
- **`test_seti_adaylari.md` adayları:** §2.2'dekiler yukarıdakilerle aynı. Ek olarak:
  - §2.4a: jq, xz, mupdf, curl, bash, grep, gawk, valkey, neovim, mg;
  - §2.4b: socat, stunnel, openvpn, nginx, lighttpd, privoxy, masscan, mutt, irssi, w3m, tig, mc, pv, jhead, mtr, wireguard-tools, universal-ctags, gnuplot;
  - §2.5: nmap, mosh, aria2, btop, qpdf, poppler-utils, 7-zip, exiv2, ninja, groff.
- **Geliştirme seti envanteri (§1):**
  - coreutils, tmux, htop, redis, zstd (libzstd), jpeg-xl (jxl_from_tree), CalculiX (ccx), varname_bench, tree, sqlite3 (libsqlite3), OpenSSL (libcrypto, libssl);
  - macOS sistem araçları (true, uname, echo, ls);
  - libz3, libfaiss, libQuantLib, gh, codex, scapy;
  - §1.4'tekiler: ffmpeg, libxul, content_shell, libpng, JavaScriptCore.

### 6.2 Çatal, ikiz ya da kod soyu ortağı (betikte `LINEAGE`)

| Program | Neden |
|---|---|
| xxd | Debian'da kaynak paketi `vim` (doğrulandı) |
| macvim | vim çatalı |
| keydb, redict | redis çatalları (valkey zaten aday listesinde) |
| zip | Info-ZIP projesi, unzip'in kardeşi; kaynakta ortak dosyalar var (`crypt.c`, `ttyio.c`, `crc32.c`; dosya adı düzeyinde doğrulandı) |
| dropbear | SSH uygulaması; kaynakta OpenSSH'tan alınmış dosya (`atomicio.c`), gömülü libtomcrypt ve libtommath (Debian sistem kütüphanesine bağlıyor) |
| yasm | NASM önişlemcisini içeriyor (`modules/preprocs/nasm/nasm-pp.c`, doğrulandı) |
| tmate | tmux çatalı |
| busybox, ash | ash soyu (dash da ash'tan); coreutils işlevleri |
| cgit | git'i gömüyor (Debian sürüm dizgisinde `+git2.46.0`) |
| fossil | SQLite'ı gömüyor (Debian'da `libsqlite3` bağımlılığı yok, Homebrew'de `sqlite` bağımlılığı yok); SQLite'ın yazarının projesi |
| sqlcipher | SQLite çatalı |
| libressl | OpenSSL çatalı |
| lz4, xxhash | zstd'nin yazarının projeleri; xxhash zstd'nin içine gömülü. Debian'da ikisi de ince ikili (`liblz4-1`, `libxxhash0` bağımlılığı) |
| zopfli | pigz'in içine gömülü (stres kümesi) |
| luajit | Lua C API'sinin adlarını dışa açıyor (lua stres kümesinde, liblua ikizi) |
| neomutt | mutt çatalı (mutt aday listesinde) |
| wget2 | wget ile aynı proje |
| tcpslice | tcpdump grubunun projesi |
| pinentry | GnuPG projesi |
| libraw, ufraw | dcraw kodundan türedi |
| p7zip | 7-Zip çatalı |
| xpdf | poppler'ın atası (poppler aday listesinde) |

### 6.3 Geliştirme setine işlevce yakın (betikte `NEAR_DEV`)

dtach, abduco, dvtm (tmux işlevi), toybox (coreutils işlevi), nvtop, iftop, bmon (htop türü canlı tablo). Bunların her biri ayrıca U2-U5'ten en az birine de takılıyor; listede, karar kayda geçsin diye duruyorlar.

### 6.4 Ölçütle elenenler (incelenen adaylar)

| Neden | Programlar |
|---|---|
| U1 dil | gnuchess (kaynak `.cc`), moria, aircrack-ng, ngspice, stockfish, bastet (`libstdc++6` bağımlılığı), zile (Vala'dan üretilmiş C), zsync (Homebrew 0.8.0 Go ile yeniden yazılmış, Debian 0.6.2 C), ncdu (Homebrew 2.9.2 Zig, Debian 1.22 C). Büyük tabaka taramasında çıkan C dışı ya da karma programlar: etcd, gh, kubectl, caddy, syncthing, rclone, hugo, miller, senpai (Go); rustc, fish, helix, mdbook, sccache, prs (Rust); suricata (C + Rust); coccinelle, dune, haxe, hevea, camlp5 (OCaml); dub, sambamba (D); racket; plink2, xmrig (C++); nwchem (Fortran); papers (C + Rust), elan, python3-maturin, gpg-sq (Rust), podman-toolbox (Go), mono-utils (C#), texlive-binaries (WEB'den üretilmiş C) |
| U2 Homebrew | formül yok: dte, antiword, picosat, fasttree, elinks, arj, rc, lbzip2, sharutils, simh. Kullanımdan kalkmış: gocr, nvi, nvtop. Homebrew `zabbix` formülü yalnız ajanı kuruyor; zabbix sunucu ve vekil paketlerinin Mac karşılığı yok |
| U3 Debian | trixie arm64'te paket yok: samurai, darkhttpd, abduco, apcalc, yash, gforth, vice, simh, librsync-tools, calculix-ccx, dante-server, atari800, xroar, qemacs, brogue, gprolog, bcrypt, crafty. Aynı sürüm dbgsym yok: lrzsz, minisign, ngrep, arj, sl, tcc, john, ksh (ksh93u+m), toybox, slrn, vsftpd, mono-runtime-sgen, snake4, wordgrinder |
| U4 boyut, < 309 KiB | jo, entr, fzy, pwgen, sipcalc, fping, arping, p0f, darkstat, tinyproxy, httping, beanstalkd, dfc, logrotate, ncompress, lzop, cabextract, figlet, moon-buggy, abook, nnn, jp2a, pngcheck, jpegoptim, cava, foremost, pdfcrack, fcrackzip, prodigal, seqtk, tty-clock, cmatrix, ttyrec, ii, autossh, sshpass, original-awk, ed, rc, dialog, progress, most, whois, nuttcp, msmtp, xmlstarlet, units, bc, avra, xa65, acme, cproto, diffstat, unpaper, opus-tools, mpc, lame, dfu-util, hexedit, bvi, rlwrap, picocom, ccrypt, fdupes, jdupes, sslsplit, ssldump, sslscan, optipng, outguess, tnftp, lsyncd, unrtf, catdoc, potrace, nsxiv, duc, scalpel, wiggle, chrpath, jpeginfo, xmp, phalanx, indent, gdbm, cflow, gzip, wdiff, time, patchutils, feh, peg, lp-solve, gap-core, ninvaders, nudoku, greed, robotfindskitten |
| U4 boyut, > 70029 KiB | qemu-system-arm (85178), hashcat (76748). QEMU'nun sistem öykünücüsü için ölçülecek ikili ev sahibi mimarininkidir (`qemu-system-aarch64`, paket `qemu-system-arm`). Öteki hedef paketleri (ppc, riscv, x86, sparc, s390x) aralıkta, ama aynı kodun başka hedefe derlemeleri; birini seçmek keyfi olurdu, üretilmiş kod payları da yüksek (qapi, decodetree). QEMU ailesinden havuzda yalnız `qemu-img` var |
| U5 ELF > 4 | hmmer (20), gputils (7), cc65 (12), samtools (7), bcftools (40), mandoc (5), coturn (6), vorbis-tools (6), mcabber (5), global (9), rsyslog (39), varnish (18), slapd (41), collectd-core (147), apache2-bin (119), postgresql-client-17 (22), emacs-nox (151), erlang-base (13), ncftp (6), pure-ftpd (11), proftpd-core (46), crossfire-server (6), ispell (6) |
| U8 ince ikili (Debian `Depends`) | lsof (`liblsof0`; ayrıca lehçe kodu platforma göre tamamen farklı), autogen (`libopts25`), gnucobol3 (`libcob4t64`), clamav (`libclamav12`) |

## 7. İşaretli liste ve doğrulama stres alt kümesi

Aşağıdakiler U1-U6'yı sağlıyor, U7-U9'dan birini sağlamıyor. Ana kuraya girmezler; içlerinden bir stres alt kümesi ayrı kurayla seçilir (test setindeki stres mantığı). Kanıt kaydı: `dogrulama_seti_kanit/isaretli_data.json`.

| Program | Homebrew | Debian 13 arm64 (+ aynı sürüm dbgsym) | Vekil KiB · ELF |
|---|---|---|---|
| sed | `gnu-sed` 4.10 | `sed` 4.9-2+deb13u1 | 310 · 1 |
| tar | `gnu-tar` 1.35_1 | `tar` 1.35+dfsg-3.1 | 1224 · 2 |
| findutils | `findutils` 4.11.0 | `findutils` 4.10.0-3 | 459 · 2 |
| diffutils | `diffutils` 3.12 | `diffutils` 1:3.10-4 | 815 · 4 |
| patch | `gpatch` 2.8 | `patch` 2.8-2 | 395 · 1 |
| m4 | `m4` 1.4.21 | `m4` 1.4.19-8 | 716 · 1 |
| make | `make` 4.4.1 (rebuild 1) | `make` 4.4.1-2 | 568 · 1 |
| bison | `bison` 3.8.2 | `bison` 2:3.8.2+dfsg-1+b2 | 812 · 1 |
| cpio | `cpio` 2.15 | `cpio` 2.15+dfsg-2 | 388 · 2 |
| datamash | `datamash` 1.9 | `datamash` 1.9-1 | 490 · 2 |
| inetutils-telnet | `inetutils` 2.8 | `inetutils-telnet` 2:2.6-3+deb13u3 | 460 · 1 |
| unbound | `unbound` 1.26.1_1 | `unbound` 1.22.0-2+deb13u3 | 10524 · 3 |
| hatari | `hatari` 2.6.1 (rebuild 2) | `hatari` 2.5.0+dfsg-1+b1 | 35882 · 3 |

**Kanıtlar:**

- **gnulib:** 11 GNU programında Debian kaynağında `gnulib-comp.m4` var. Dosyanın yeri betikteki `FLAGGED` sözlüğünde.
- **Gnulib işareti olmayan GNU programları:** mtools, enscript ve GNU Go'da işaret bulunmadı; bu üçü havuzda.
- **unbound:** yoklanan yedi iç ad katalogda var (`lib=unbound`): `sldns_str2wire_dname`, `regional_alloc`, `rbtree_insert`, `lruhash_insert`, `outside_network_create`, `comm_base_create`, `ub_ctx_create`. Homebrew şişesinde `libunbound.8.dylib` var.
- **hatari:** kaynak ağacında `src/cpu/gencpu.c`, `build68k.c` ve `table68k` var. 68k komut yorumlayıcısı derlemede üretiliyor (UAE soyu). Ek olarak gömülü SoftFloat var. SoftFloat adları katalogda yok (0/5).

**Doğrulama stres alt kümesi** (ana oturum kararı, 2026-10-19):

- **Boyut:** 13 işaretli programdan 5'i kurayla seçilir.
- **Alt tohum:** ana tohum metnine `/stres` eklenerek türetilir. SHA-256(`karadul-dogrulama-seti-kura-2026-10-19/stres`) değerinin ilk 16 hex basamağı = `0f41d5481ac7ccfb` = `1099394289718775035`.
- **Yöntem:**
  - Liste alfabetik sıralanır ve `random.Random(alt tohum).shuffle` ile karıştırılır.
  - İlk 5 program stres alt kümesidir; kalan 8 program sırasıyla stres yedeğidir.
  - Ana kuranın üretecine dokunulmaz; iki kura birbirinden bağımsızdır.
  - Tabaka, alan ve aile kısıtı uygulanmaz (basit rastgele örneklem).
- **Ölçüm:** kapı günlerinde ölçülür ve ayrı raporlanır. Kapı ölçütüne hiç girmez.
- **Mac gerçek isim kaynağı ve değişim:** K3'te aynı kaynaktan derleme yöntemi uygulanır (§4.4). K1, K2, K4, K5 ya da K6'da yerine stres yedek sırasındaki ilk koşulabilir program gelir (`--kosulamayan ad:NEDEN`).
- **Koruma:** 13 programın hepsi doğrulama programları gibi korunur (§2).

## 8. Geliştirme seti

### 8.1 Liste: `test_seti_adaylari.md` §1'den, iki platformda gerçek isim kaynağı olanlar (8 program)

Mac sayıları bu Mac'te kurulu kegden 2026-10-19'da `nm -U` ile alındı. Geliştirme seti olduğu için bu ölçüm serbesttir. Kurulu sürümler, API önbelleğindeki güncel formül sürümleriyle aynı.

| # | Program | Mac (Homebrew; ölçülen ikili; `nm -U` t / T) | Debian 13 arm64 + dbgsym | Not |
|---|---|---|---|---|
| 1 | tmux | 3.8; `tmux`; 1210 / 1374 | `tmux` 3.5a-3 | 2026-10-14 Mac gerçeklik ölçümünde kullanıldı |
| 2 | htop | 3.5.3; `htop`; 221 / 385 | `htop` 3.4.1-5 | 2026-10-14 Mac gerçeklik ölçümünde kullanıldı |
| 3 | tree | 2.3.2; `tree`; 0 / 119 | `tree` 2.2.1-1 | Mac'te yalnız global adlar var (yerel sembol yok) |
| 4 | zstd | 1.5.7_1; `zstd` 68 / 151, `libzstd.1.5.7.dylib` 275 / 594 | `zstd` 1.5.7+dfsg-1 | Debian paketinde C++ `pzstd` de var |
| 5 | sqlite3 | 3.54.0; `sqlite3` 2978 / 417 | `sqlite3` 3.46.1-7+deb13u2 | Mac CLI SQLite'ı içeriyor, Debian CLI `libsqlite3-0`'a dinamik bağlı: platform asimetrisi |
| 6 | openssl | openssl@3 3.5.9; `openssl` 405 / 304 | `openssl` 3.5.7-1~deb13u2 | |
| 7 | redis | 8.10.2_1; `redis-server` 3411 / 371 | `redis-tools` 5:8.0.2-3+deb13u2 | Debian'da sunucu kodu `redis-tools` paketinde; `redis-server` paketinde yalnız bağlantı var (2. aşamada doğrulanacak). Az miktar C++ içeriyor (`libstdc++6` bağımlılığı) |
| 8 | coreutils | 9.12 (g önekli); `gcat` 33 / 107, `gls` 205 / 219 | `coreutils` 9.7-3 | gnulib; Debian'da 106 ELF |

**§1'den dışarıda kalanlar:**

- CalculiX: Fortran ağırlıklı; trixie arm64'te `calculix-ccx` yok.
- jxl_from_tree: C++.
- varname_bench: sentetik; Debian karşılığı yok.
- macOS sistem araçları: Mac'te gerçek isim yok.
- §1.2'deki C++, Go ve Rust programları ile uygulamalar.
- §1.4'tekiler: koşulduklarına kanıt yok.

**Karar (ana oturum, 2026-10-19):** 8 program kabul edildi. Zayıflıklar sınırlama ve 2. aşama notu olarak kalır (§10):

- tree: Mac'te yalnız global adlar var;
- sqlite3: platform asimetrisi;
- redis: Debian'daki sunucu ikilisinin `redis-tools` içinde olduğu 2. aşamada doğrulanacak.

§8.2'deki kural yalnız geliştirme seti ileride 8'in altına inerse kullanılır.

### 8.2 Tamamlama kuralı (önceden yazılı)

Geliştirme seti 8'in altına inerse eksik sayı kadar program, 2. aşamada son doğrulama kümesi belli olduktan sonra şu kuralla alınır. Komut: `--gelistirme N`.

1. Seçilen 10 program ve korumalı yedekler (her tabakada yedek sırasının ilk 4/4/2 programı) verilmez.
2. Son doğrulama kümesiyle aynı aileden ya da aynı alandan program verilmez. Neden: geliştirme setine yakın program doğrulamayı şişirir (U10'un aynası).
3. Kalanlar tabakalar arasında küçük, orta, büyük sırasıyla dönüşümlü alınır. Her tabakada yedek sırası izlenir.
4. Alınan program Mac'te K3 ya da K4'ten, Debian'da K2'den geçmezse atlanır ve sıradaki alınır.
5. Geliştirmeye aktarılan programın ailesi ve alanı, sonraki değişimlerde kullanılmış sayılır. Komut: `--aktarilan`.

## 9. Kanıt kaynakları ve tarihler

Bütün ağ sorguları yalnız okumaydı. Hiçbir ikili indirilmedi, hiçbir paket kurulmadı.

**Yöntem olarak kullanılan salt okuma kaynakları** (ana oturum onayı, 2026-10-19):

- `brew info` (yerel API önbelleği);
- GHCR şişe dizin JSON'u;
- Debian Packages ve Contents dizinleri;
- sources.debian.org dizin listeleri;
- Karadul imza kataloğunda salt okunur yoklama;
- geliştirme setinde yerel `nm -U` sayımı.

Adresler, sorgu tarihleri ve indirilen dizin dosyalarının sha256'ları `dogrulama_seti_kanit/README.md`'de. Aday başına kanıt kayıtları `pool_data.json` ve `isaretli_data.json`'da.

| Kaynak | Ne alındı | Tarih |
|---|---|---|
| Homebrew API önbelleği | `brew info --json=v2`, `HOMEBREW_NO_AUTO_UPDATE=1`, Homebrew 7.0.9-135-gaac1fb8. Önbellek: `~/Library/Caches/Homebrew/api/internal/packages.arm64_tahoe.jws.json`. Sorgulardan sonra dosya değişmedi | `generated_at` 2026-10-17 11:40:38 UTC; dosya 2026-10-17 15:03 (yerel saat) |
| GHCR şişe dizinleri | Yalnız dizin JSON'u, şişe değil: `sh.brew.bottle.digest`, `installed_size`, `sh.brew.tab` içindeki `linkage_files`. 68 şişenin özeti API'deki sha256 ile eşleşti | 2026-10-19, yaklaşık 09:15-09:30 UTC |
| deb.debian.org | `dists/trixie/InRelease` (13.7, Date: Sat, 12 Sep 2026 07:55:41 UTC); `dists/trixie-debug/InRelease` (aynı tarih) | indirme 2026-10-19 08:47 UTC |
| | `main/binary-arm64/Packages.xz` sha256 `be16b37b2f740f066ea93d35d56f04f94d63693e5a3eb421b052bf86fae75bcd` (9 614 192 B) | |
| | debug `main/binary-arm64/Packages.xz` sha256 `ff6185861c668d9038f36fd826a14fd13a05d039d74b2ef9b59fd63ad38a1560` (3 689 184 B) | |
| | `main/Contents-arm64.gz` sha256 `276dbed691664effd4be91435f7e0d1552f0ab645c0aa0397de9ba5900e13b74` (12 639 045 B); indirme 09:13 UTC | |
| | Üç dosyanın özeti InRelease'teki değerle aynı. InRelease'in GPG imzası doğrulanmadı | |
| sources.debian.org API | Yalnız dizin listeleri (dosya içeriği okunmadı). gnulib işaretleri; dil için dosya uzantıları; çatal kanıtları (yasm, zip, dropbear, hatari) | 2026-10-19 |
| Karadul imza kataloğu | `~/.karadul/signatures.lmdb`, `LMDBSignatureDB(readonly=True).lookup_symbol`. Yöntem `test_seti_adaylari.md` §0 ile aynı: ad ve `_` önekli biçimleri. Yoklanan adlar gömülü kütüphanelerin herkese açık API adları ve unbound/nsd'nin bilinen iç adlarıydı | 2026-10-19 |

**Yoklama sonuçları:**

- 0 isabet:
  - alpine'deki c-client: 0/10;
  - libmosquitto: 0/4;
  - libmpv: 0/4;
  - PHP'nin Zend, libmagic, lexbor ve timelib adları: 0/12;
  - liblowdown: 0/4;
  - termbox2 (mle): 0/3;
  - PARI: 0/5;
  - ipv6calc: 0/2;
  - hatari'deki SoftFloat: 0/5;
  - minimap2, bwa, kalign ve newlisp'in kütüphane API'leri;
  - gnome-builder'ın `libide` iç adları: 0/4;
  - QEMU'nun ortak adları (`visit_type_int`, `qmp_query_status`, `qemu_mutex_lock_impl`): 0/3.
- İsabet olanlar:
  - unbound 7/7;
  - nsd 1/4 (`rbtree_create`, `lib=unbound`);
  - tor 2/4 (`curve25519_donna`, `crypto_scalarmult_curve25519`);
  - flex 2/2 (`yylex`, `yywrap`; genel adlar).
- "0" sonucu yalnız yoklanan adların katalogda olmadığını gösterir; programın hiçbir adının katalogda olmadığını kanıtlamaz.

## 10. Sınırlamalar

- **Havuz elle derlendi** (§5). Bulunamayan uygun programlar olabilir.
- **Boyut vekili** (ana oturum kararıyla korunur, akış değişmez):
  - Vekil ikili boyutu değil, dbgsym paketinin boyutudur.
  - Test setinin dört programı bu ölçüde kilit belgesindeki tahmini tabakasından kayıyor:
    - memcached küçükten ortaya;
    - dnsmasq ortadan küçüğe;
    - vim büyükten ortaya;
    - ssh ortadan büyüğe.
  - Vekil, test setinin 6/6/3 dağılımını korur; tek tek etiketleri değil.
  - Çok ELF'li paketlerde vekil paketteki bütün ELF'lerin toplamıdır, ölçülecek ikiliden büyüktür:
    - test setinde: ssh (10 ELF), git (10), zsh (39);
    - havuzda 4 ELF'liler: tor, alpine, gnome-builder, ipv6calc, qemu-img, nsd, mosquitto, distcc, fig2dev, bogofilter;
    - havuzda 3 ELF'liler: minicom, dosfstools, testdisk, zmap.
  - Aynı programın birden çok derlemesi vekili ayrıca şişirir: mksh (mksh, lksh, mksh-static), sslh (sslh, sslh-ev, sslh-select).
  - 2. aşamada gerçek ikili boyutları ölçülür ve kayda geçer; tabaka değişmez.
- **Mac'te yerel sembol bilgisi kura öncesi bilinmiyor.**
  - Test setinin 20 programından 4'ünde şişede sorun çıkmıştı.
  - K3'te program değişmez, Mac ikilisi kaynaktan derlenir (§4.4).
  - Derleme superenv'in `D` kipiyle (`-g`) yapılır. Test setinde şişe kipindeki derlemeye göre birkaç baytlık fark ölçüldü; fonksiyon sayısı aynıydı (`test_seti_kilidi.md` §4.5).
  - Derleme 30 dakikada bitmezse K6 ile değişim yapılır. Bu, seyrek de olsa bir seçim etkisi bırakır; değişenler §13'te raporlanır.
- **Sürüm farkları.** Homebrew çoğu zaman daha yeni.
  - Büyük farklar: nethack 3.6.7 / 5.0.0, zmap 2.1.1 / 4.4.0, bmake 2020 / 2026, lowdown 2.0.2 / 3.2.1, remind 05 / 06, monit 5 / 6, profanity 0.15 / 0.19.
  - Test setinde de böyleydi (gpg, nasm). Program başına platformlar arası kıyas yapılmaz.
- **Platform asimetrisi:**
  - PHP: Debian'da bazı eklentiler ayrı `.so`.
  - weechat: IRC eklentisi ayrı `.so`; ölçülen ikili çekirdek.
  - nethack: Debian'da gerçek ikili `usr/lib/games/nethack/` altında.
- **"Kütüphane ikizi" denetimi örneklemdir.** 2. aşamada seçilen programların gerçek isim listelerinin katalogda bulunma oranı mekanik olarak ölçülüp rapora yazılmalıdır. Bu oran programı kümeden çıkarmaz.
- **Geliştirme setinin zayıflıkları** (§8.1): tree'de Mac'te yalnız global adlar var; sqlite3'te platform asimetrisi var; redis'in Debian sunucu ikilisi henüz doğrulanmadı.
- **Ham dizin dosyaları depoda değil.** Packages, Contents ve Homebrew API önbelleği çok megabaytlık. Adresleri ve sha256'ları `dogrulama_seti_kanit/README.md`'de; aday başına kayıtlar depoda.

## 11. Açık maddeler

1. **Program sınıfı tanımı.** Plan §7 kapıları program sınıfı başına ölçüyor ("htop türü ve tmux türü ayrı").
   - Tanım bu belgenin işi değil. Plan belgesinde G13'ten önce, doğrulama sonuçlarına bakmadan, mekanik bir ölçütle yazılacak (ana oturum kararı, 2026-10-19).
   - Doğrulama ve stres programlarının sınıfı o tanımla, ilk kapı ölçümünden önce atanır.

## 12. 2. aşamada yapılacaklar

1. **Kura.** Bu belge ve betik commit edildikten sonra: `python scripts/measurement/dogrulama_seti_kura.py > <kura>.json`. Çıktı; ana kümeyi, yedek sıralarını, stres alt kümesini, künyeyi ve alanları içerir.
2. **Sabitleme.** Seçilen 10 programı ve 5 stres programını sabitle:
   - **Mac:**
     - Ek A'daki (stres için `isaretli_data.json`'daki) sha256 ile şişe;
     - ölçülecek ikilinin sha256'sı ve UUID'si;
     - `nm -U` t/T sayıları ve `otool -L`;
     - `/usr/bin/strip` ile soyulmuş kopya;
     - `xcrun dyld_info -exports` denetimi.
   - **Debian:**
     - paket ve dbgsym'in sha256'sı (Packages ile);
     - BuildID eşleşmesi;
     - `.debug` `.symtab` FUNC sayıları (yerel/global).
   - **Her iki platformda** ikili boyutu.
3. **K3.** K3'e takılanları kaynaktan derle (§4.4); süre sınırı 30 dakika. Sonucu `test_seti_kilidi.md` §4.5'teki tablo biçiminde kaydet.
4. **Değişim.** K1, K2, K4, K5 ya da K6'ya takılanları `--kosulamayan ad:NEDEN` ile yeniden üret. Gelen yedekler için 2. ve 3. adımları tekrarla.
5. **Kayıt.** Sonucu bu belgeye "§13 Kura sonucu ve sabitleme" olarak ekle. Ek A'nın karşılığı `test_seti_kilidi.md` §4 biçimindedir.
6. **Bakış kaydı.** Bakış kaydını başlat.

## 13. Kura sonucu ve sabitleme (2026-10-19)

- **Kura:** 2026-10-19 10:08:45 UTC'de çekildi. Commit `be19227`'deki betik ve bu belge kullanıldı; betiğin commit denetimi geçti. Künye, yedek sıraları ve sabitleme tabloları: `docs/arge/dogrulama_seti_kilidi.md`.
- **Ana küme (10):**
  - küçük: mosquitto, newlisp, pspg, kalign;
  - orta: timidity, nagios, joe, gnugo;
  - büyük: alpine, gnome-builder.
  - 10 ayrı alan, 10 ayrı aile. Alan kısıtı gevşetilmedi, komşu tabakaya geçilmedi.
- **Stres alt kümesi (5/13):** datamash, bison, tar, sed, diffutils; hepsi gnulib.
  - Stres yedek sırası: findutils, unbound, inetutils-telnet, m4, patch, hatari, make, cpio.
- **Sabitleme:** 15 programın Homebrew şişesi, Debian paketi ve aynı sürüm dbgsym'i indirildi (80,8 MB). Doğrulamalar:
  - şişe sha256: 15/15;
  - paket ve dbgsym sha256: 30/30;
  - dbgsym BuildID: 15/15.
- **K3 (Mac şişesinde ikili tamamen soyulmuş):** nagios, newlisp. Program değişmez; Mac ikilileri kaynaktan derlenecek (§4.4). Bu ayrı bir iş.
- **K1, K2, K4, K5, K6:** yok. Değişim yapılmadı.

## 14. Değişiklik kaydı

**2026-10-21: kapı günleri değişti** (plan v2.2, `docs/arge/2026-10-21_plan_v2_2.md` §6; Berke'nin kararı).
- §2 madde 1'deki kapı günleri (G13, G20, G28-G30) plan v2.2'de şöyle: Kapı 1 G15, K1 G19, K2 G23, Kapı 2 G29, Faz 2 sonu G37-G39.
- Etiketleme günleri (G14 ve G28) ait oldukları kapının bakışına sayılır.
- Bakış sayısı üçten beşe çıktı. Her bakış bakış kaydına yazılır; makalede sayısı raporlanır.
- §2 madde 2-6 aynen geçerli. Kapı tutmazsa düzeltme geliştirme setinde yapılır. Tip kapılarında (K1, K2) doğrulamada tek okuma vardır; doğrulamaya bakarak kural ayarı yapılmaz.
- Gerekçe: plan v2.1'den beri tip ve yapı izinin kendi kapıları var (Berke, 2026-10-21). Onuncu Adam bu değişikliğin ön kayda tarihli bir girişle yazılmasını istedi (`2026-10-21_v2_1/onuncu_adam.md` İ11).

## Ek A. Şişe özetleri ve Debian ikili yolları

| Program | Homebrew şişesi `arm64_tahoe` sha256 | Mac kurulu boyut (B) | Debian dbgsym paketi | Debian ikili yolu |
|---|---|---|---|---|
| abcm2ps | `ad72e488f58816b605a868a4b62886e7da304c35c0147cc5d56d0903a8d950fd` | 484187 | `abcm2ps-dbgsym` 8.14.17-2 | `/usr/bin/abcm2ps` |
| bitlbee | `31ddec7ca433f3bcf5dc5f86206c99464e9586065bf0fbb54b327051ff751dff` | 643788 | `bitlbee-dbgsym` 3.6-1.5 | `/usr/sbin/bitlbee` |
| bmake | `93f2a6f6db6d6fa92fa29472294bcf2d8bb358eae85bce25a3c7d80fc3c14956` | 852325 | `bmake-dbgsym` 20200710-17 | `/usr/bin/bmake` |
| bogofilter | `52568286a8cb6ce65a146f26233362ec1df94e8d028d6c6d41dd889a31ab3e6c` | 1012882 | `bogofilter-sqlite-dbgsym` 1.2.5-1+b4 | `/usr/bin/bogofilter-sqlite` |
| bwa | `cd17b7367cbda46d49bba96116e29ec1ffae87d4595bb599180608d3d2bd8f36` | 566992 | `bwa-dbgsym` 0.7.18-1 | `/usr/bin/bwa` |
| byacc | `7b744045116e9ce0829c9c99ed2df820a8b35a56e92be4e8f714446e3bd5301d` | 429021 | `byacc-dbgsym` 1:2.0.20241231-1 | `/usr/bin/byacc` |
| calcurse | `36702d8f775d240b6968de8c9920deb70f8a1c4174efb8807a65b137a17abe6d` | 944567 | `calcurse-dbgsym` 4.8.1-1.3 | `/usr/bin/calcurse` |
| distcc | `9f900b2ebc2e4c934e04e2c943997a3cad07ac5b7551c7106f22f62291939de5` | 2012700 | `distcc-dbgsym` 3.4+really3.4-12 | `/usr/bin/distcc` |
| dnsperf | `c195ad0dff7969dec034ab5e086b07fa80853c718223321dd3560c074d65a0f2` | 432632 | `dnsperf-dbgsym` 2.14.0-5 | `/usr/bin/dnsperf` |
| dosfstools | `d54a1407f985fc34279f07ead09aa53ae0cbe1a24b8a7328d4cbcb8fb24d9c49` | 839086 | `dosfstools-dbgsym` 4.2-1.2 | `/usr/sbin/fsck.fat` |
| enscript | `8ec384c474020c7910824f10690c55502ceaa686c444c4989dd3785268dac77a` | 2049438 | `enscript-dbgsym` 1.6.5.90-3.1+b2 | `/usr/bin/enscript` |
| fetchmail | `c5fb4e5a482ba203a4ff910696d66399f4d63f871e56f4ead0baa39f3c05dec9` | 780236 | `fetchmail-dbgsym` 6.4.39-1+b2 | `/usr/bin/fetchmail` |
| flex | `62ca8b8763bc2c97fe3ec02a4f55e410a6bf80ab26c291b0914313a82d004afe` | 1627953 | `flex-dbgsym` 2.6.4-8.2+b4 | `/usr/bin/flex` |
| frotz | `13e6781a5e0e185bb4bb73634f55d01ae38a55127b20f0f6eb0e88ff13bef27a` | 651448 | `frotz-dbgsym` 2.55+dfsg-2 | `/usr/games/frotz` |
| hydra | `2d199dbae3ac05667fc94351a2a07a16bd49b9cba698aa2d4e9ded70139db1dd` | 1756672 | `hydra-dbgsym` 9.5-3 | `/usr/bin/hydra` |
| iodine | `a8e87d64fdc26c599c69d781412172b9393917733d1994e3687f4c435d32fa0c` | 285509 | `iodine-dbgsym` 0.7.0-11 | `/usr/sbin/iodine` |
| isync | `b4c6e597e2d119bc81bf052a2c25ae0a648692e987d144e0e4752bd806e91f7b` | 391671 | `isync-dbgsym` 1.5.1-1 | `/usr/bin/mbsync` |
| jove | `ee1248e197df0c81afc0548004d8ae314d911b63470761a839421d4b3a4b4ba5` | 1365474 | `jove-dbgsym` 4.17.5.4-1 | `/usr/bin/jove` |
| kalign | `11bcedd722af4c6c3703fbac5785f7e8c6b6fbe24d618fc4d56f54c088a8a0c0` | 456438 | `kalign-dbgsym` 1:3.4.0-1+b3 | `/usr/bin/kalign` |
| lowdown | `1db06afacaaec6d74c6eab22e02640d6baf377ce2174aa58cd24dbe2610b0c73` | 2593848 | `lowdown-dbgsym` 2.0.2-2 | `/usr/bin/lowdown` |
| minicom | `a7ccffde0108b847384bfd1b59b65de15b2fa0038243b4b89929469f9d8e3a31` | 462405 | `minicom-dbgsym` 2.10-1 | `/usr/bin/minicom` |
| minimap2 | `a0621571925138e90e219a9aaac5595a5b332a6ac9bba3357f360bcb579b89f0` | 367566 | `minimap2-dbgsym` 2.27+dfsg-1+b4 | `/usr/bin/minimap2` |
| mle | `d1fca3abdacc62e424b44f3c6b1fd986636ed1db3b4665ab66c26127e36bfd5e` | 339259 | `mle-dbgsym` 1.7.2-1+b1 | `/usr/bin/mle` |
| mosquitto | `1db18231340891829a844c975058895c639fec4a802e19e426f0e67c2523bcc1` | 2548235 | `mosquitto-dbgsym` 2.0.21-1 | `/usr/sbin/mosquitto` |
| mtools | `4d7abe94bc09a3ff5ecb64d9a6c0dc37799b5ddd51c993d2480b2cee0567bef8` | 596226 | `mtools-dbgsym` 4.0.48-1 | `/usr/bin/mtools` |
| multitail | `a6200a07329926c2cb274a6a61b0c5ad0d48ebe0a3445446f686395b418f873d` | 344915 | `multitail-dbgsym` 7.1.5-2 | `/usr/bin/multitail` |
| ne | `8d3fb098e03124349321ca8162f9b615f1d6ae439be8f5687a6cf791a3960dd6` | 1946988 | `ne-dbgsym` 3.3.3-1 | `/usr/bin/ne` |
| newlisp | `cd0b1afe583ffbacd299097ba50acf21f8343d26301612afad78ce5ce18f56a6` | 1856932 | `newlisp-dbgsym` 10.7.5-2+b4 | `/usr/bin/newlisp` |
| ngircd | `87bc6a006ee2a63d03860f388378b53405cd2bddcfaa702e960f7d7af502eb1e` | 898703 | `ngircd-dbgsym` 27-2+b1 | `/usr/sbin/ngircd` |
| pspg | `8dd9ef474eaf5c99b2119f4a49fbdefd42fc8cfed43d87d37cf6913fdc3707e0` | 360456 | `pspg-dbgsym` 5.8.9-1 | `/usr/bin/pspg` |
| remind | `7e31dbd119d74b26f6160ad07af51b3bc09b1ac53dc098916cf7d20cfec4f544` | 1985689 | `remind-dbgsym` 05.03.07-1+deb13u1 | `/usr/bin/remind` |
| rmlint | `0d90cd13c8a94f6fc34bbdbf82ae92ce390a501cb7719eed1c3e5ba7e5a17311` | 433787 | `rmlint-dbgsym` 2.10.2-0.2 | `/usr/bin/rmlint` |
| sc-im | `1cc0a6f1c2ceaed2882bdfc320acff02e3aeca823226cffad9f9b53e5184d206` | 541906 | `sc-im-dbgsym` 0.8.4+ds-1+b1 | `/usr/bin/sc-im` |
| squashfs-tools | `4457ab0b11eff5278270c2bcf8de450879d4e8d9d3b6b3c2aac3d3aef822e5db` | 773703 | `squashfs-tools-dbgsym` 1:4.6.1-1+b1 | `/usr/bin/mksquashfs` |
| sslh | `5aa0861161f4e13c703825e23a3c885010d68a0f494c1af257929654dc3af9b6` | 208786 | `sslh-dbgsym` 2.1.4-1+b1 | `/usr/sbin/sslh` |
| tcsh | `0df869ae003eeca37ff2acec0a8a9f604c1ffebda8b279facc0e3be826240dce` | 1034594 | `tcsh-dbgsym` 6.24.13-2+b1 | `/usr/bin/tcsh` |
| vnstat | `af145bbd1da554febe818a33724a04fd13316d589279f3e7c7dd44178556f1ae` | 569190 | `vnstat-dbgsym` 2.13-1 | `/usr/bin/vnstat` |
| zmap | `a78dfb358782c21ebc754ce63d0d54b80d274b7f73b2f5f3fe9c8fcd04972c3d` | 563760 | `zmap-dbgsym` 2.1.1-2.1+b2 | `/usr/sbin/zmap` |
| angband | `d4aef25f1be9724500e460e68ca2da76fd2294d56e4467bb4f85b156e5193934` | 26296145 | `angband-dbgsym` 1:4.2.5+dfsg1-3 | `/usr/games/angband` |
| chrony | `a1df029e9d933dd0dcce82a8b260475751ff01eeb68767b8362735a7c88c923d` | 828477 | `chrony-dbgsym` 4.6.1-3+deb13u2 | `/usr/sbin/chronyd` |
| cscope | `a0a30f47c29cb9473180bfe1c3670ceff999e1cd694babbe88d90e012cca0827` | 768951 | `cscope-dbgsym` 15.9-2+b2 | `/usr/bin/cscope` |
| exim | `ea7f0786ea3c915aa0237344bea3cc87717ee4539fc9989ee61754371eb376ff` | 2264188 | `exim4-daemon-light-dbgsym` 4.98.2-1+deb13u4 | `/usr/sbin/exim4` |
| fig2dev | `24dd6f6aa035586bd4c43d727b1329b822da452a0f64005a9defa12f2fa0faed` | 834079 | `fig2dev-dbgsym` 1:3.2.9a-4 | `/usr/bin/fig2dev` |
| freeciv | `7be9340d5ebbffcb1f17c4c36e68ccefc04938878d7d817d39af0a3515f0fff7` | 76672938 | `freeciv-server-dbgsym` 3.1.4+ds-2+deb13u1 | `/usr/games/freeciv-server` |
| gnugo | `65707404eb0034b25296dc8c9dfc0dd3ec1016b4ef97744500b702317c50b89c` | 7896036 | `gnugo-dbgsym` 3.8-13+b1 | `/usr/bin/gnugo` |
| joe | `78fb6ee8e904471bb40ca0dfd1f285478219978a7f8315b819c6e982ab593ef4` | 2386896 | `joe-dbgsym` 4.6-2 | `/usr/bin/joe` |
| links | `033baf6900816d9cfa21fd82ee9607a7b8863cc58586febdded445fa5144d776` | 1767455 | `links-dbgsym` 2.29-2+b3 | `/usr/bin/links` |
| mksh | `99d5701b22abd93460ac4d8dff1779534e5a74ccb010f96091a70bc7499ec464` | 527922 | `mksh-dbgsym` 59c-41+b2 | `/usr/bin/mksh` |
| monit | `477331b19fc0b1cf7f425b2634ed2a214246b4dbf5c4a303096580af03e90f1e` | 1041420 | `monit-dbgsym` 1:5.34.3-1 | `/usr/bin/monit` |
| mpv | `7d498f6e80a4f6b4071c5f2862e1a228edac45961d52c713831e0cef8e1cf6ba` | 11479720 | `mpv-dbgsym` 0.40.0-3+deb13u1 | `/usr/bin/mpv` |
| nagios | `ba4c8b095224835ee6c835b58b2f609110e7a5df460d42ebcb686141d5063f47` | 7312876 | `nagios4-core-dbgsym` 4.4.6-4.1+deb13u1 | `/usr/sbin/nagios4` |
| nethack | `4ed420ea146cea8d1db4e8db8b21471a5058ece3e714696f754765365264f115` | 7090055 | `nethack-console-dbgsym` 3.6.7-1+b4 | `/usr/lib/games/nethack/nethack-console` |
| nsd | `5766f00bfe5307e987cb1d613039bcbbf950880e385a9bf3080e91254cea3c66` | 1691951 | `nsd-dbgsym` 4.12.0-1 | `/usr/sbin/nsd` |
| profanity | `1cb182a6a25209e7c7e5c5aa0f22698ae5d4d38c8b298f7eace2808dfdad37b9` | 1894024 | `profanity-dbgsym` 0.15.0-1 | `/usr/bin/profanity` |
| splint | `3d26b806b15af6dde29829bdca6d9c0cc44ac7ef96d5522dee1cbd3f24a9924e` | 2545571 | `splint-dbgsym` 1:3.1.2+dfsg-5+b2 | `/usr/bin/splint` |
| testdisk | `e329a6e62f3a3a45d211f502f2d9286e1f33740bae6b63777166f18b2051138c` | 2022558 | `testdisk-dbgsym` 7.2-0.1 | `/usr/bin/testdisk` |
| timidity | `d1870a696de648a1ed46e25d590b6f6a3bfa73091044c8623fbf77901e71c7a9` | 34322896 | `timidity-dbgsym` 2.14.0-8.3+b1 | `/usr/bin/timidity` |
| tin | `1e53cebb5c99bc1f13b9b9590fc9ccfd7e33b8bbcd46ab6c807fc36295d84a77` | 3595733 | `tin-dbgsym` 1:2.6.5~20250409-1 | `/usr/bin/tin` |
| vifm | `f97fa172bca7120403ab18f6feb214e0b050c5fa1206bc3909672056901fd0e8` | 3979154 | `vifm-dbgsym` 0.14-3 | `/usr/bin/vifm` |
| weechat | `56343f6691b8a0b873fcb9751315bf491a849517261e1de2dbd48b6459320d6b` | 10244336 | `weechat-curses-dbgsym` 4.6.3-1 | `/usr/bin/weechat` |
| zabbix | `a0cf6a58b0cb475e85fdcc733c77c6e560ba31cd2562a33829957f5ee804ad83` | 3320401 | `zabbix-agent-dbgsym` 1:7.0.22+dfsg-1~deb13u1 | `/usr/sbin/zabbix_agentd` |
| alpine | `62301d0e5eb9290a24fb3ab3d9117f9dccc45160fbdee0ee7a176e9d02a21f2e` | 9842268 | `alpine-dbgsym` 2.26+dfsg-3 | `/usr/bin/alpine` |
| gnome-builder | `82adf89ed4bc89f83e846a4c12a47f3f99bf21ed637b6cc73686dea62a860b42` | 18324531 | `gnome-builder-dbgsym` 48.0-2+b1 | `/usr/bin/gnome-builder` |
| ipv6calc | `f694cc121eabb42e7190973671e9e909012f607a873525712ac71c1d854af0ca` | 14882132 | `ipv6calc-dbgsym` 4.1.0-0.2 | `/usr/bin/ipv6calc` |
| pari | `95d6c9c4f0cb47a1f2fbf4e912fbc933ede9d1db7b8b5ceca17960c34dc56b25` | 14604240 | `pari-gp-dbgsym` 2.17.2-1 | `/usr/bin/gp-2.17` |
| php | `e6e07d3573f3be869d3e9b5b2d7ba3a00fc2128a9cdd0687b6a5120d9907af3c` | 107684390 | `php8.4-cli-dbgsym` 8.4.24-1~deb13u1 | `/usr/bin/php8.4` |
| qemu-img | `3651058eea3d9dce6a8c8745b763d55b5571da0de31a60eb501464f10af00195` | 729030677 | `qemu-utils-dbgsym` 1:10.0.13+ds-0+deb13u1 | `/usr/bin/qemu-img` |
| tor | `62e8888704102c7de35f1393214a4c3c5e773cd6c183110ac71b76fe3482bda5` | 32369640 | `tor-dbgsym` 0.4.9.11-0+deb13u1 | `/usr/bin/tor` |