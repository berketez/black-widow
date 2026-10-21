# G10 / N0b: `string_context` alt kanalları — ön kayıt

- **Tarih:** 2026-10-21.
- **Durum:** Ön kayıt. G4 etiketlerine bakılmadan yazıldı. Ana oturum bu belgeyi inceleyip commit'lemeden etiketlere bakılmaz (adım 2).
- **Susturma kuralı:** "yalnız zayıflar" (§5). Ana oturumun kararıdır (2026-10-21; Berke kararı ana oturuma bıraktı). Etiketlere bakılmadan, ilk taslaktaki katı kuralın yerine geçti.
- **Plan:** v2.2 §0 karar 2; §3 N0 (c)-(d) ve N1; §8 "alt kanal tanımı tutmazsa" riski.
- **Dayanak:**
  - İsim kökeni kaydı, commit 9a36142 (`naming_provenance.json`, şema 1).
  - Taban v2 koşusu `taban-v2-62ad154` (Ghidra 12.1.2).
- **Bu adımda yapılmayan:** kesinlik ya da doğruluk hesabı, eşik seçimi, ürün değişikliği. Yalnız tanım ve kapsam var.

**Dosyalar:**

| Dosya | İçerik | sha256 (ilk 16) |
|---|---|---|
| `scripts/measurement/alt_kanal.py` | sınıflayıcı, halef, Wilson, karar kuralı ve güven etiketi; `uret`, `sinifla`, `kapsam`, `tanimlar` | `d0e6f54431d77f26` |
| `kayitlar_htop.jsonl`, `kayitlar_tmux.jsonl` | genel fonksiyon adı başına bir satır: kanıt, alt kanal, halef, taban eşleşmesi. **Atamalar burada dondu** | `8a3bb6eec444926f`, `81c642aae2b84d49` |
| `kapsam.json` | etiketsiz kapsam tabloları | `da2a16e12ecbda52` |
| `uretim_htop.json`, `uretim_tmux.json` | yeniden üretim künyesi: girdilerin sha256'sı, `pre_names`, strateji sayıları | `0fa2492631f9145e`, `be5a430d42fbc12c` |
| `ters_eslesme_htop.json`, `ters_eslesme_tmux.json` | taban adı olup köken kaydı olmayanlar | `06ddb655e1d9e575`, `9c1b6293c17dd34b` |
| `tests/test_alt_kanal.py`, `scripts/measurement/mutation_specs_alt_kanal.json` | 45 test, 6 mutant | — |

Betiğin tam sha256'sı: `d0e6f54431d77f2663f84afa6d5091e216b04b6bdf3d781005cd0c0a65c273eb`.

Kural değişikliğinden sonra bütün çıktılar bu betikle yeniden üretildi. Kayıt ve ters eşleşme dosyaları önceki sürümle bayt bayt aynı çıktı. Değişen yalnız künye alanları: betiğin sha256'sı, `git_head`, `kirli_dosyalar`, süre.

## 1. Girdi: köken kaydının yeniden üretimi

Commit'li kodla, Ghidra koşmadan, taban v2'nin Ghidra çıktısı üzerinde yalnız c_namer koşuldu:

```bash
R=workspaces/olcum_mac/runs/taban-v2-62ad154
PYTHONHASHSEED=0 python scripts/measurement/alt_kanal.py uret \
    --calisma $R/htop/ws/workspaces/htop/20261019_090424 --program htop -o <dizin>/htop
PYTHONHASHSEED=0 python scripts/measurement/alt_kanal.py uret \
    --calisma $R/tmux/ws/workspaces/tmux/20261019_090738 --program tmux -o <dizin>/tmux
python scripts/measurement/alt_kanal.py sinifla <dizin>/tmux/naming_provenance.json --program tmux \
    --macho-score $R/tmux/macho_score.json --naming-map $R/tmux/out/naming_map.json \
    -o docs/arge/2026-10-21_g10_n0b/kayitlar_tmux.jsonl \
    --ters-json docs/arge/2026-10-21_g10_n0b/ters_eslesme_tmux.json      # htop için aynısı
python scripts/measurement/alt_kanal.py kapsam docs/arge/2026-10-21_g10_n0b/kayitlar_htop.jsonl \
    docs/arge/2026-10-21_g10_n0b/kayitlar_tmux.jsonl --json docs/arge/2026-10-21_g10_n0b/kapsam.json
```

**Girdiler boru hattındaki gibi seçildi:**
- JSON'lar `deobfuscated/`'tan alındı (`ghidra_metadata._resolve_json_paths`); `static/`'tekilerle bayt bayt aynılar. `ghidra_xrefs.json` `static/`'ten.
- C dosyaları `deobfuscated/decompiled`'dan alındı. `static/ghidra_output/decompiled`'dan yalnız dosya sonundaki boş satırla ayrılıyorlar.
- `pre_names` boru hattının belirlenimci tohumlarıyla kuruldu (`ReconstructionStage`: main, gnulib parmak izi, ELF önyükü). Sonuç:
  - tmux'ta tek ad: `FUN_100027cac → close_stdout` (gnulib). Taban v2'de de `binary_extract` 1'dir.
  - htop'ta boş.
  - Analist geçersiz kılma deposu boştu.
- c_namer kurucusunun öntanımlı eşiği 0,15'tir (boru hattıyla aynı); ürün eşiği 0,7'dir (`binary_reconstruction.min_naming_confidence`, NameMerger).
- `ProcessPoolExecutor` yerine seri yürütücü kullanıldı, `PYTHONHASHSEED=0`.

**Sonuç (ürün eşiğini geçen genel fonksiyon adları):**

| Program | `string_context` | `api_param_reverse` | `binary_extract` | Klasik/`keywords` | Agresif | `string_ref` / `body_literal` |
|---|---|---|---|---|---|---|
| htop | 101 | 0 | 0 | 101 | 0 | 91 / 10 |
| tmux | 862 | 12 | 1 | 862 | 0 | 782 / 80 |

- tmux'taki 862, taban v2 raporundaki 863'ten bir eksik:
  - Raporun `naming_by_strategy`'si boru hattının ikinci yinelemesinin sayımıdır (`timing_c_naming_iter1` var; her yineleme sayımı ezer).
  - Aradaki net fark, `naming_map.json`'daki tek fazla adla uyumlu: `FUN_1000118c4 → fatal` (aşağıda). İlk yinelemenin çıktısında (`reconstructed/src`) fonksiyon hâlâ `FUN_1000118c4` adıyla geçiyor; ikincisinde (`src_iter1`) bu ad yok, `fatal(` çağrıları var.
  - `close_stdout` anahtarının `string_context` adayı (`write_file`) hem boru hattında hem bu koşuda tohumla `pre_named` olarak eleniyor. Ana oturumun daha önceki `pre_names`'siz koşusundaki 863 bu adaydan geliyordu.
- Klasik kayıtların hepsinde ad ve güven, dondurulmuş kopyayla kanıttan yeniden kuruluyor; tutarsız kayıt 0.

**Nihai adlarla eşleşme (köken kaydı ↔ taban v2):**

| | htop | tmux |
|---|---|---|
| `macho_score.json` `pred` dolu satır | 101 | 871 |
| … aynı ad | 95 | 781 |
| … yalnız çakışma eki farklı (`small` ↔ `small_2`) | 6 | 90 |
| … farklı ad ya da kaydı yok | 0 | 0 |
| Kaydı olup `macho_score`'da satırı olmayan | 0 | 4 |
| `naming_map.json` `FUN_…` (`c_namer`) | 101 | 876 |
| … aynı / yalnız ek farklı / kaydı yok | 97 / 4 / 0 | 786 / 89 / 1 |

- **Puanlanan bütün adlar (htop 101, tmux 871) köken kaydıyla taban adda eşleşiyor.** Rubrik çakışma eklerini yok sayar (kural 2). G4'ün 482 öğesi bu satırlardan çekildiği için adım 2'de beklenen eşlenme oranı %100'dür; adım 2 bunu öğe öğe denetler.
- Ek farkları yalnız sırayla ilgili. Taban v2'nin süreç havuzunda adaylar başka sırayla geldiği için ekler başka fonksiyonlara düşmüş. ÖL-7 (1acba60) aynı commit'le iki koşu arasında da aynı türden farkı ölçtü (yalnız çakışma ekleri).
- Kaydı olmayan tek taban adı tmux'ta `FUN_1000118c4 → fatal`. Boru hattının ikinci yinelemesinde (`src_iter1`) verilmiş görünüyor; `macho_score`'da `pred` boş, yani puanlanmıyor.
- **Kararlılık:** `PYTHONHASHSEED=1` ile ikinci koşuda kazanan ad, kanıt, güven ve strateji aynı çıktı. Yalnız üçüncü sıradaki `callee_based` rakibi değişiyor (htop 1, tmux 31 kayıt). Alt kanal ve halef sütunlarının hepsi aynı kaldı.

## 2. Alt kanal tanımları (sürüm 1)

**Gösterim:**
- `e`: kanıt dizgisinin baştaki ve sondaki boşlukları atılmış hâli.
- `ad`: önerilen ad, yani çakışma eki eklenmeden önceki ad (`proposed_name`, yoksa `new_name`).
- `k`: klasik yolun kanıttan çıkardığı anahtar sözcük sayısı (1-4). Klasik güven min(0,9; 0,7 + 0,05·k)'dir; ad ilk üç anahtar sözcükten kurulur.

**Kural:** Kanallar ayrıktır ve öncelik sırası aşağıdaki gibidir. Bir kanal, kendi yüklemi ile kendisinden önceki bütün yüklemlerin olumsuzlamasıdır. `diger` her kaydı tutar; bu yüzden her kayıt tam olarak bir alt kanala düşer.

| Sıra | Alt kanal | Yüklem | Dayanağı |
|---|---|---|---|
| 1 | `agresif` | kod yolu `aggressive` | Ayrı kod yolu ve kurallar (`STRING_CONTEXT_RULES`). Taban v2'de hiç kazanmıyor |
| 2 | `kod_parcasi` | kanıt `body_literal` ve ham satır sonu ya da Ghidra'nın kendiliğinden verdiği bir ad (`GHIDRA_OTO_AD_RE`) taşıyor | Gövde taraması `"([^"]{3,80})"` iki literalin arasındaki kodu yakalıyor (tırnak çifti bozulunca). Ghidra'nın C çıktısında dizgi literali tek satırdır |
| 3 | `bicim_parcasi` | adı kuran ilk üç anahtar sözcükten biri bir printf dönüşüm belirtecinin (`%%` hariç) içine taşıyor | Anahtar sözcük deseni `[a-zA-Z]{3,}` belirtecin harflerini alıyor: `%lld` → `lld`, `%siB` → `sib` |
| 4 | `oz_ad` | `e` tek C tanımlayıcısı; alt çizgi ve küçük harf var; `ad` = `e`'nin küçük harfli hâli | Kendi adını yazan tanımlayıcı biçimi (KS-1'e komşu, §6). Dizginin bu fonksiyonun adı olduğu doğrulanmaz |
| 5 | `tek_sozcuk` | `k = 1` | Ad tek sözcük; klasik güvenin en alt basamağı (0,75) |
| 6 | `tanimlayici` | `e` alt çizgili tek C tanımlayıcısı (4'e girmeyen) | Tanımlayıcı dizgi ama ad dizginin kendisi değil: durak sözcük, 3 harften kısa parça ya da rakam düşmüş, 3'ten çok parça kırpılmış; ya da tanımlayıcının tamamı büyük harf (sabit, ortam değişkeni) |
| 7 | `kebap_ad` | `e` küçük harfli, tireli tek belirteç (`^[a-z][a-z0-9]*(-[a-z0-9]+)+$`) | Seçenek, kanca, komut ya da bildirim adı biçimi (`monitor-activity`) |
| 8 | `hata_iletisi` | `HATA_RE` kanıtta geçiyor | Hata ya da kullanım iletisi |
| 9 | `bicim_dizgisi` | printf belirteci (`%%` hariç) ya da şablon yer tutucusu (`#{`, `#[`, `${`, `{{`) | Biçim dizgisi; `%s: …` günlük öneki de burada |
| 10 | `duz_metin` | `e` boşlukla ayrılmış birden çok parça; C işleci (`->`, `==`, `!=`, `<=`, `>=`, `&&`, `\|\|`) yok | Düz ileti ya da arayüz etiketi |
| 11 | `diger` | her kayıt | Noktalı anahtarlar (`kern.osrelease`), virgüllü listeler, yollar, boşluksuz ya da işleçli ifadeler |

**Sabit desenler (betikteki hâliyle; değişirse sürüm değişir):**
- `HATA_RE` (büyük/küçük harf duyarsız, sözcük sınırlı): `errors?`, `fail(s|ed|ure)?`, `fatal`, `invalid`, `illegal`, `bad`, `wrong`, `unknown`, `unsupported`, `unexpected`, `unrecogni[sz]ed`, `cannot`, `can'?t`, `could not`, `couldn'?t`, `unable`, `not able`, `missing`, `no such`, `not found`, `not allowed`, `denied`, `refused`, `too (many|few|long|big|large|small)`, `overflow`, `out of`, `usage`, `must`, `expected`.
- printf belirteci: `%[n$][-+#0']*[genişlik|*][.kesinlik|*][hh|h|ll|l|L|q|j|z|t][diouxXeEfFgGaAcspnmCS@]`; `%%` ayrıca eşlenir ve sayılmaz. Boşluk bayrağı alınmaz: düz metindeki `50% done` belirteç sayılmaz.
- `GHIDRA_OTO_AD_RE`: `FUN_`, `DAT_`, `PTR_`, `LAB_`, `SUB_`, `UNK_`, `thunk_FUN_` + onaltılık; `param_N`; `local_<onaltılık>`; `[a-z]{1,3}VarN`; `a…Stack_<onaltılık>`; `extraout_…`, `unaff_…`; `undefinedN` (rakamlı).

**Tanımların kullanmadığı bilgiler:**
- gerçek ad, `macho_score.json`'ın `gt`, `status`, `lenient` ve `sinif` alanları, `nm` çıktısı, kaynak ağaçları;
- G4 etiketleri, anahtarları ve amaç cümleleri.

Tanımlar yalnız kod yolundan (`code_path`, `evidence_origin`) ve kanıt dizgisinin biçiminden kuruldu.

**Dondurulmuş kopyalar:**
- c_namer'ın üç parçası betikte kopya olarak durur: klasik anahtar sözcük çıkarımı, ad temizleme ve genel adlardaki yapısal süzgeç (`call_graph`, `callee_based`, `api_call`).
- Böylece motor değişse de sınıflama değişmez.
- Testler kopyaların motorla aynı davrandığını denetler; c_namer'ın kendi `_strategy_string_context`'i de bunlara dahil. Motor değişirse test kırmızıya döner.

**Atamalar dondu:**
- Her kaydın alt kanalı `kayitlar_*.jsonl`'a yazıldı.
- `test_depodaki_atamalar_yeniden_uretilir`, bu dosyalardaki her `string_context` satırını bugünkü sınıflayıcıyla yeniden sınıflar: alt kanal, `k`, tutarlılık ve tutan yüklemler aynı çıkmalı.

**Ayrı kanal yapılmayan önerilen yönler:** Görev tanımında öneri olarak geçiyorlardı. Kayıt sayıları etiketsiz sayıldı. G4'te beklenen n'leri en çok ≈ 15 (`%s:` öneki; öbürleri 3-8) olduğu için ayrı kanal yapılmadılar:

| Biçim | Kayıt | Düştüğü kanallar |
|---|---|---|
| `%s: …` günlük öneki | 34 | `bicim_dizgisi` 25, `bicim_parcasi` 5, `tek_sozcuk` 2, `hata_iletisi` 2 |
| `tanımlayıcı: …` öneki | 13 | `hata_iletisi` 4, `bicim_dizgisi` 4, `duz_metin` 3, `tek_sozcuk` 2 |
| C işleçli ifade (assert ifadesi dahil) | 51 | `kod_parcasi` 34, `tek_sozcuk` 9, `bicim_dizgisi` 4, `diger` 3, `bicim_parcasi` 1 |
| yol ya da URL | 4 | `diger` 4 |

**İkincil öznitelikler (karar dışı):** Her kayıtta `kanit_kaynagi` (`string_ref` / `body_literal`) ve `k` ayrıca durur. Adım 2'de yalnız betimsel kırılım olarak raporlanır (§4); alt kanal değildir.

## 3. Kapsam (etiketsiz)

Ürün eşiğini geçen `string_context` adları. Bu bir doğruluk ölçüsü değil, kapsam ölçüsüdür.
- **0,15 ve 0,7 sütunları:** taban v2'de bütün adlar klasik yoldan ve güvenleri ≥ 0,75 olduğu için bu iki eşikteki sayılar aynıdır. 0,15 sütunu ayrıca yazılmadı (`kapsam.json`'da var).
- **Nihai:** taban v2'de `pred`'i dolu, yani puanlanan satır.
- **E[n]:** G4 örnekleminde beklenen öğe sayısı ≈ 385 · tmux_nihai/871 + 97 · htop_nihai/101. Yaklaşıktır: tmux örneklem çerçevesi yalnız `program` sınıfıdır (857 satır), burada bütün adlı satırlar (871) payda alındı.

| Sıra | Alt kanal | htop 0,7 | tmux 0,7 | htop nihai | tmux nihai | Pay (nihai) | E[n] |
|---|---|---|---|---|---|---|---|
| 1 | `agresif` | 0 | 0 | 0 | 0 | %0,0 | 0 |
| 2 | `kod_parcasi` | 10 | 75 | 10 | 72 | %8,6 | 41 |
| 3 | `bicim_parcasi` | 6 | 18 | 6 | 18 | %2,5 | 14 |
| 4 | `oz_ad` | 0 | 126 | 0 | 126 | %13,1 | 56 |
| 5 | `tek_sozcuk` | 35 | 95 | 35 | 95 | %13,6 | 76 |
| 6 | `tanimlayici` | 0 | 114 | 0 | 114 | %11,9 | 50 |
| 7 | `kebap_ad` | 0 | 148 | 0 | 147 | %15,3 | 65 |
| 8 | `hata_iletisi` | 12 | 102 | 12 | 102 | %11,9 | 57 |
| 9 | `bicim_dizgisi` | 8 | 139 | 8 | 139 | %15,3 | 69 |
| 10 | `duz_metin` | 23 | 34 | 23 | 34 | %5,9 | 37 |
| 11 | `diger` | 7 | 11 | 7 | 11 | %1,9 | 12 |
| | **toplam** | 101 | 862 | 101 | 858 | | ≈ 476 |

- htop'ta tanımlayıcı biçimli kanallar (`oz_ad`, `tanimlayici`, `kebap_ad`) boş. Kanal dağılımı programa güçlü biçimde bağlı: htop'ta arayüz etiketleri ve tek sözcükler ağır basıyor.
- `k` dağılımı: `oz_ad` 2-3; `tanimlayici` en çok 4 (63/114); `kod_parcasi` 2-4. `body_literal` kayıtlarının 85'i `kod_parcasi`'nda; 5'i gerçek literal.

**Halef: alt kanal tek başına susturulursa ne olur.** Ürün eşiği 0,7 ile, birleşik:

| Alt kanal | n | `FUN_` kalır | yerine `api_param_reverse` | yerine agresif `string_context` |
|---|---|---|---|---|
| `kod_parcasi` | 85 | 84 | 1 | 0 |
| `bicim_parcasi` | 24 | 23 | 1 | 0 |
| `oz_ad` | 126 | 126 | 0 | 0 |
| `tek_sozcuk` | 130 | 130 | 0 | 0 |
| `tanimlayici` | 114 | 112 | 2 | 0 |
| `kebap_ad` | 148 | 147 | 1 | 0 |
| `hata_iletisi` | 114 | 111 | 3 | 0 |
| `bicim_dizgisi` | 147 | 139 | 7 | 1 |
| `duz_metin` | 57 | 55 | 2 | 0 |
| `diger` | 18 | 18 | 0 | 0 |

- `FUN_` kalmanın nedenleri ve tam dağılım `kapsam.json`'da (`halef_urun`, `ilk_rakip`). Üç neden var:
  - en iyi rakip yapısal süzgeçte (`call_graph`, `api_call`): c_namer anahtarı adsız bırakır;
  - rakip 0,7'nin altında: c_namer ad verir, NameMerger düşürür;
  - rakip yok.
- c_namer düzeyinde (0,15) 79 kayıtta agresif bir `string_context` adayı ad alır. Bunların 78'i 0,55-0,65 güvenlidir ve NameMerger'dan geçmez; 1'i (htop, 0,70) geçer.
- Susturma bugünkü verilerde neredeyse yalnız ad silmek demek: 963 adın 945'i `FUN_` kalır, 17'sinin yerine `api_param_reverse` geçer, 1'inin yerine agresif bir `string_context` adayı geçer.
- NameMerger'ın öbür kaynakları (`signature_db`, BinDiff, refdiff) bu tabloda görünmez. Bu kaynaklar susturulan anahtara ad verebilir.

## 4. Adım 2'de G4 etiketleriyle hesaplanacak ölçüler

**Öğeler:**
- G4'ün 482 ana öğesi: L1 `tmux_385_kor` (385) ve L3 `htop_kor` (97). Yemler hariç.
- L2 (`tmux_200_gt`) gerçek adı gördüğü için kullanılmaz.

**Eşleme:**
- Öğe, anahtardaki adresle `kayitlar_<program>.jsonl` satırına bağlanır.
- Eşleme denetimi: öğenin adayı ile kaydın adı taban adda (çakışma eki atılmış) aynı olmalı.
- Plan N0'ın ölçüsü raporlanır: 482 öğenin kökenle eşlenme oranı. Eşlenmeyenler adresleriyle listelenir.
- `string_context` dışı öğeler (`api_param_reverse`, `binary_extract`) ayrı satırda sayılır; bu adımda onlar için karar yoktur.

**Etiketler:**
- Rubrik sürüm 2'nin dört etiketi kullanılır.
- `tam` anahtardaki otomatik tam eşleşmeden gelir (protokol §3.3).
- Yakın = `tam` + `dogru_tarif`.
- Yanlış = `yanlis`. Rubrik sürüm 2'de yanlış fiil bu etiketin içindedir.

**Her alt kanal için** (program başına ve iki program birleşik):
- n;
- `tam`, yakın, `yalniz_alan` ve `yanlis` sayıları, oranları ve Wilson %95 aralıkları (z = 1,96);
- yanlış olmayan oran (1 − yanlış);
- `karar(n, yanlis)`: karar, üründe kalıp kalmadığı ve güven etiketi (§5).

Bu belgede "kesinlik" yakın oranı demektir. Karar ölçüsü ise yanlış oranıdır.

**Karar, iki programın birleşik (ağırlıksız) sayılarıyla** verilir; ürün bir kanalı programdan bağımsız susturur. Program başına satırlar yalnız raporlanır. Sınıf başına ayrı hedef yoktur (v2.2 §0 karar 4).

**Tek kanal okuması:** Bütün `string_context` aynı kuralla bir kez daha okunur ve raporlanır (§5'teki §8 riski).

**Betimsel kırılımlar** (karar dışı, birleşik `string_context` için): `kanit_kaynagi`; `k` (1-4).

**Duyarlılık** (karar dışı; ana kararı değiştirmez, ayrışma raporlanır):
1. `capraz_atif > 0` öğeler dışarıda (protokol §3.3).
2. tmux kısmı için L3'ün `tmux_200_kor` etiketleriyle aynı tablo (başka değerlendirici; 88 öğesi L1 ile ortak).

**Kod:**
- Adım 2'nin kodu `alt_kanal.py`'yi değiştirmez; onu içe aktarır.
- Koşuda betiğin sha256'sının `d0e6f54431d77f26…` olduğunu denetler.
- `sinifla`, `karar`, `urunde_kalir`, `guven_etiketi`, `hepsini_kapatir` ve `wilson` işlevlerini buradan kullanır.

## 5. Susturma kuralı: "yalnız zayıflar"

Ana oturumun kararıdır (2026-10-21; Berke kararı ana oturuma bıraktı). Bu belgenin ilk taslağındaki katı kural, bölümün sonunda "değerlendirilen ve seçilmeyen seçenek" olarak duruyor.

**Ölçüt:** Alt kanalın yanlış oranı (yanlış fiil dahil). Eşik %10'dur, plan v2 §7 G13 ve v2.2 Kapı 1'in hedefi. Wilson %95 aralığı `[L, U]` ile:

| Karar | Koşul | Üründe (N1'den sonra) | Güven etiketi |
|---|---|---|---|
| `dogrulandi` | U ≤ %10 | ad vermeyi sürdürür | "doğrulandı" |
| `belirsiz` | L ≤ %10 < U | ad vermeyi sürdürür; N2'nin taze örnekleminde yeniden ölçülür | "doğrulanmadı" |
| `zayif` | L > %10 | N1'de KS-1 ile birlikte susturulur | — |
| `olculemedi` | n = 0 | susturulur | — |

Kural betikte `karar()`, `urunde_kalir()`, `guven_etiketi()` ve `hepsini_kapatir()` olarak yazılı ve testlidir. Etiketin adla birlikte çıktıya kadar taşınması plan v2.1 3.1'in işidir (`name_provenance` → `output_formatter`).

**`belirsiz` ile `olculemedi` arasındaki fark:**
- `belirsiz` kanalın etiketli öğeleri var. Veri kanalın hedeften kötü olduğunu göstermiyor (L ≤ %10), iyi olduğunu da göstermiyor (U > %10). Ad verilir, ama bu durumu söyleyen "doğrulanmadı" etiketiyle.
- `olculemedi` kanal hakkında hiç kanıt yok (n = 0). Ölçülmemiş kanal ad vermez. Geliştirme setinde bu durumdaki tek kanal agresif kod yoludur.

**Susturmanın anlamı:**
- Kanalın adayları c_namer'da yarıştan çıkarılır; ad doğrudan silinmez.
- Yerine §3'teki halef geçer. Halefin kendi kanalı da susturulmuşsa o da geçemez.
- Susturma N1'de KS-1 ile aynı anda açılır (v2.2 §0 karar 2).

**N2 ile ilişki:**
- `belirsiz` kanallar N2'nin taze örnekleminde yeniden ölçülür. Örneklem geliştirme setinden, G4'te etiketlenmemiş öğelerden çekilir.
- Bu, G4 verisiyle yeniden açma değildir; N2 zaten planlı taze ölçümdür.
- N2'nin ölçüleri ve kararı ayrı bir ön kayıtta yazılır. Bu belge onları yazmaz.
- G4 verisiyle hiçbir kanalın kararı sonradan değiştirilmez. `belirsiz`, G4'e bakılarak `dogrulandi`'ya yükseltilmez. `zayif` ve `olculemedi` ancak taze veriyle ve yeni bir ön kayıtla yeniden açılabilir.

**n küçükse:**
- Sıfır yanlışla bile U ≤ %10 için en az 35 öğe gerekir (0 olayda U = z²/(n + z²)). n < 35 olan bir kanal "doğrulandı" etiketi alamaz.
- Küçük n'li kanal ancak yanlışları açıkça çoksa `zayif` olur ve susar. Değilse `belirsiz` kalır ve "doğrulanmadı" etiketiyle ad vermeyi sürdürür.
- G4'te beklenen n'ler 12-76 arasında (§3):

| n | "doğrulandı" için en çok yanlış | susturma (`zayif`) için en az yanlış |
|---|---|---|
| 14 | — | 4 (%28,6) |
| 35 | 0 | 7 (%20,0) |
| 41 | 0 | 8 (%19,5) |
| 50 | 0 | 10 (%20,0) |
| 56 | 1 (%1,8) | 11 (%19,6) |
| 65 | 1 (%1,5) | 12 (%18,5) |
| 76 | 2 (%2,6) | 13 (%17,1) |
| 100 | 4 (%4,0) | 16 (%16,0) |

**Plan §8 riskinin önceden yazılan kararı** ("alt kanal tanımı tutmazsa susturma ya hepsini kapatır ya hiçbirini"):
- Karar alt kanal kuralıyla verilir. Bütün alt kanallar `zayif` ya da `olculemedi` çıkarsa `string_context` üründe tümüyle susar ("hepsini kapatır"; `hepsini_kapatir()`).
- Tek kanal okuması (§4) aynı kuralla raporlanır ama kararı değiştirmez.
- Beklenen durum, bütün `string_context`'in tek kanal olarak `zayif` çıkmasıdır (taban v2'nin program düzeyindeki yanlış oranları, §7 madde 9). Bu durumda `zayif` ya da `olculemedi` çıkmayan alt kanallar ad vermeyi yine sürdürür. Alt kanalların amacı tam da bu ayrımı yapmaktır.

**Gerekçe:**
1. Plan v2.2 §2: "Ara katmanlar adayları güven ve kökenleriyle taşır; eşik son çıktıda uygulanır." Belirsiz bir kanalın adı silinmez, güveniyle taşınır.
2. Plan v2.2 §3 N1: "Yalnız N0'da ön kayıtla yazılmış ölçüte göre zayıf kalan alt kanallar susturulur." Susturma, verinin hedeften kötü olduğunu gösterdiği (L > %10) kanala uygulanır.
3. Berke'nin 2026-10-15 kararı: "Her isim güven etiketiyle gelir, eleme en sonda."
4. Katı kural bütün `string_context`'i susturabilir (aşağıda). O zaman ürün adsız kalır ve çıktısı çıplak Ghidra'dan ayırt edilemez ("Ghidra yeter" riski).
5. Eşik verilerden seçilmedi: %10 Kapı 1'in hedefidir.

**Hata türleri** (binom hesabı, kural `karar()` ile):
- İyi bir kanalın yanlışlıkla susturulması: gerçek yanlış oranı tam %10 olan bir kanal n = 37-76'da %2,1-3,8, n = 14'te %4,4 olasılıkla `zayif` çıkar. Gerçek oran %5 ise bu olasılık %0,5'in altındadır.
- Kötü bir kanalın kalması: gerçekte %20 yanlışlı bir kanal `belirsiz` kalıp "doğrulanmadı" etiketiyle ad vermeyi sürdürebilir. Olasılığı n = 14'te %70, n = 37'de %53, n = 56'da %42, n = 76'da %22.
- Bu ikinci riski "doğrulanmadı" etiketi görünür kılar, N2'nin taze ölçümü sınar.
- Çoklu karşılaştırma düzeltmesi yapılmaz.

**Agresif kod yolu (`olculemedi`):**
- Geliştirme setinde hiç kazanmadığı için susturulur. Geliştirme setinde etkisi sıfırdır.
- Doğrulama setinde (Debian, ELF) ya da başka programlarda `Class::Method`, `func()` gibi kurallar ad verebilir. Bu adlar da susturulmuş olur.
- Hakkında hiç kanıt olmadığı için bu bilinçli bir seçimdir; ölçülmemiş kanal ad vermez.

**Değerlendirilen ve seçilmeyen seçenek: katı kural** (bu belgenin ilk taslağı):
- Yalnız `dogrulandi` kalır; `belirsiz` de susar.
- Dayanağı: plan v2.2 §2'deki "her katman emin olmadığı sonucu ad olarak yazmaz" cümlesi.
- Bedeli:
  - Beklenen n'lerde (12-76) "doğrulandı" için en çok 0-2 yanlış olabilir.
  - Gerçekte %5 yanlışlı iyi bir kanal n = 37-76'da yalnız %15-26 olasılıkla doğrulanır; geri kalan durumlarda susardı.
  - Hiçbir alt kanal doğrulanmazsa `string_context` tümüyle susar, ürün adsız kalırdı.
- Seçilmeme nedeni yukarıdaki gerekçeler (1-4).

## 6. KS-1 ile ilişki

- **`oz_ad` KS-1'in kendisi değil, biçim komşusudur.**
  - KS-1 (N1, v2.1 3.2) kesin çapaları kendi tanımıyla kuracak: kendi adını yazan dizgi, `__func__` kalıbı, assert dizgileri, export ve kesin kaynaklar.
  - `oz_ad` yalnız "dizgi tek tanımlayıcı ve ad ona eşit" biçimidir. Dizginin o fonksiyona ait olduğunu (ör. `__func__` olarak geçtiğini) denetlemez.
  - Bu yüzden tmux biçim değişkeni adlarını da (ör. `window_index`) içerir.
- **Otomatik geçiş yoktur.**
  - N1'de KS-1'in adlandırdığı fonksiyonlar KS-1'in kökeniyle (yeni strateji ya da kanal) ad alır ve `string_context`'ten çıkar.
  - KS-1'in almadığı fonksiyonlarda `oz_ad` adayı bu ön kaydın kararına uyar.
  - `tanimlayici` kanalı (kırpılmış tanımlayıcılar, büyük olasılıkla `__func__` dizgileri) için de durum aynıdır: KS-1 bunları tam tanımlayıcıyla adlandırabilir.
- **KS-1'in ölçütü bu kurallar dışında kalır.**
  - KS-1'in çapa kesinliği (≥ %95, geliştirme seti) KS-1'in kendi tanımıyla ve kendi ön kaydıyla ölçülür.
  - `oz_ad` satırı KS-1'in geliştirme verisi olabilir, ama onun kapısı olamaz.
  - Sayısal sınır: yakın oranı için Wilson alt sınırı ≥ %95 en az 73 öğe ister, hepsi yakın olmak koşuluyla. G4'te `oz_ad` için beklenen n ≈ 56; hepsi yakın olsa bile alt sınır 56/(56 + 3,84) ≈ %93,6 kalır.
  - Sonuç: G4 tek başına `oz_ad` biçimini %95 çapa olarak gösteremez. KS-1 için ek etiket gerekir.
- **Yayılım (N6):** Yalnız KS-1'in kesin çapalarını kullanır. Bu ön kayıtta üründe kalan bir alt kanal, etiketi "doğrulandı" da olsa "doğrulanmadı" da olsa, yayılım çapası sayılmaz; yalnız kendi adını verir.

## 7. Bilinen sınırlar

1. **Biçim tanımı, sahiplik değil.** `oz_ad` ve `tanimlayici` dizginin kime ait olduğuna bakmaz. Bir dizginin kaç fonksiyonca kullanıldığı ve `__func__` çağrı kalıbı gibi ikiliden hesaplanabilen sinyaller kullanılmadı. Gerekçe: her yüklem yalnız köken kaydının alanlarından hesaplanabilsin (kayıt kendi başına yeterli olsun) ve sahiplik işi, yani KS-1, burada öne alınmasın.
2. **Sabit sözcük listesi.** `HATA_RE` İngilizce ve elle yazıldı. Hata gibi okunan ama listede olmayan iletiler `duz_metin`'e düşer (ör. `no current session`, `queue not empty`). Liste etiketlerden önce donduruldu; sonradan genişletilmez.
3. **printf deseni sezgisel.** Desen, dizginin gerçekten printf biçimi olup olmadığını bilmez. Örnek yanlış pozitif: tmux bildirimi `%layout-change` → `%la`, `bicim_parcasi`'na düşen 1 kayıt.
4. **Küçük ve bağımlı örneklem.**
   - Beklenen n'ler 12-76.
   - Wilson bağımsızlık varsayar. Aynı programdan ve aynı dosyadan gelen öğeler bağımsız değildir; gerçek belirsizlik daha geniştir (protokol §9).
   - Aralıklar gerçekte daha geniş olduğu için kural iki yönde de iyimserdir: susturma (`zayif`, L > %10) da "doğrulandı" etiketi (U ≤ %10) de olması gerekenden kolay verilir.
   - Küçük n'de kötü bir kanal `belirsiz` kalıp ad vermeyi sürdürebilir (§5, hata türleri).
5. **İki program, tek platform.**
   - tmux ve htop Mac'te (clang `-Os`, Mach-O) geliştirme setidir.
   - htop'ta tanımlayıcı kanalları boş, tmux'ta dolu. Doğrulama setinde (Debian, gcc `-O2`, ELF) kanal payları farklı olabilir.
   - `agresif` yalnız orada görülebilir.
6. **Karar yalnız yanlış oranına bakar.** Yakın kapsam karar ölçüsü değildir. Kapı 1'in kapsam koşulu N2 ve Kapı 1'de ölçülür.
7. **Halef tablosu ilk üç rakiple sınırlı.**
   - Kayda geçmeyen rakip "bilinmiyor" sayılır; bugünkü verilerde böyle kayıt yok.
   - NameMerger'ın öbür kaynakları tabloda görünmez.
8. **Yeniden üretim farkları.**
   - Seri yürütücü yüzünden çakışma ekleri taban v2'den farklı dağılıyor (htop 6, tmux 90 satır; taban ad aynı).
   - tmux'ta bir taban adı (`fatal`) köken kaydında yok; puanlanmıyor.
   - `PYTHONHASHSEED` yalnız üçüncü rakibi değiştiriyor.
   - `kayitlar_*.jsonl` bayt bayt yeniden üretilir. `kapsam.json` ve `uretim_*.json`'da künye alanları (`git_head`, `kirli_dosyalar`, süre) koşudan koşuya değişir.
   - Betik koşu sırasında commit'lenmemişti (`kirli_dosyalar`). Sürüm sha256'yla tanımlanır.
9. **Tanımları yazanın bilgisi** (§8 ile birlikte okunmalı).
   - Tanımları bir LLM ajanı (Claude Opus 5.5) yazdı.
   - Etiketsiz olarak bütün kanıt dizgilerini ve önerilen adları gördü.
   - Program düzeyindeki toplu yanlış oranlarını biliyordu (plan v2.1 §1: tmux %45,5, htop %81,4).
   - tmux ve htop kaynaklarını eğitiminden tanıyor olabilir. Bu yüzden örtük bir ayar tümüyle dışlanamaz.
   - Önlemler:
     - tanımlar kod yolu ve dizgi biçimiyle sınırlı;
     - sıra ve desenler yazılı;
     - kayıt başına atamalar etiketlerden önce depoya konuyor;
     - adım 2'nin kodu ayrı ve sha256 denetimli.

## 8. Bütünlük kaydı: neye bakıldı, neye bakılmadı

**Bakılmadı:**
- `docs/arge/2026-10-19_g4_etiketleme/veri/` altındaki dosyaların içerikleri;
- G4 `sonuc.json` ve `sonuc.md`;
- `macho_score.json`'ın `gt`, `status`, `lenient` ve `sinif` değerleri. Betik satırı okurken yalnız `addr` ve `pred`'e erişir; keşifte bu dört alanın yalnız adları görüldü, değerleri basılmadı;
- `nm` çıktısı ve kaynak ağaçları.

**Bakıldı:**
- plan v2.2 ve v2.1'in ilgili bölümleri;
- G4 `onkayit.md` (etiketsiz ön kayıt);
- `etiket_rehberi.md`, `etiket_protokolu_v2.md` (§3.3, §4, §9-10);
- c_namer, `stages.py`, `config.py` ve boru hattı adımları;
- taban v2'nin `naming_map.json`, `report.json` ve `macho_score.json` (`addr`, `pred`) dosyaları;
- bütün `string_context` kanıt dizgileri ve önerilen adlar.

**Kazara görülen:** `git ls-files` çıktısında `veri/` altındaki altı dosyanın adı göründü (`amac_L1_tmux385.jsonl`, `amac_L2_tmux200gt.jsonl`, `amac_L3_htop.jsonl`, `amac_L3_tmux200.jsonl`, `anahtar_htop_kor.json`, `anahtar_tmux_200_gt.json`). İçerikleri açılmadı.

**Tanım geçmişi** (hepsi etiketsiz):
- Kanal sayısını sınırlamak için kayıt sayıları kullanıldı (§2, ayrı kanal yapılmayan yönler).
- Taslaktan son sürüme yalnız iki yüklem değişti:
  - `oz_ad`'a büyük harf dışlaması eklendi (`TERM_PROGRAM_VERSION`);
  - `GHIDRA_OTO_AD_RE`'den rakamsız `undefined` ve `in_…` çıkarıldı. İngilizce sözcüğe uymasın diye yapıldı; taban v2'de hiçbir atamayı değiştirmedi.

**Kural geçmişi** (etiketlere bakılmadan):
- İlk taslakta susturma kuralı katıydı: yalnız `dogrulandi` kalıyordu.
- Ana oturum taslağı inceledi ve kararı verdi (2026-10-21; Berke kararı ana oturuma bıraktı): "yalnız zayıflar". `belirsiz` kalır ve "doğrulanmadı" etiketi taşır; `zayif` ve `olculemedi` susar.
- Değişiklik `karar()` ile ilgili işlevlere ve testlere dokundu. Alt kanal tanımları ve atamalar değişmedi; kayıt dosyaları bayt bayt aynı çıktı.
- Mutasyon kümesinin değişimi:
  - İki mutant eklendi: "belirsiz susturulur" (katı kural) ve "ölçülemeyen kanal ad verir".
  - Sınırı 4-6'da tutmak için iki sınıflayıcı mutantı spec'ten çıkarıldı: "`bicim_parcasi` yalnız ilk sözcüğe bakar" ve "`%%` belirteç sayılır".
  - Çıkarılan ikisi ayrıca sınandı: hem kendi birim testleri hem `test_depodaki_atamalar_yeniden_uretilir` onları öldürüyor.
