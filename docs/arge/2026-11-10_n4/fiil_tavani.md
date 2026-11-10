# N4 fiil tavanı: geliştirme setinde ad bekleyenlerin gerçek adlarındaki fiiller

- **Tarih:** 2026-11-10.
- **Bu sonuç yalnız şu karara girdidir:** "N4 bu kapsamla (üç aile, sözlük v0) hedefe ulaşabilir mi?" Sözlük v0, kural aileleri ve korumalar bu ölçüme bakılarak **değiştirilmez**; ölçüm onları ayarlamak için yapılmadı.
- **Dayanak:** `onuncu_adam.md` §7 madde 3 (üçüncü ön ölçüm); `fiil_onkayit_taslak.md` §2.2, §3.1, §3.3, §4.2, §6.8; `on_sayim.py` / `on_sayim.json` (bu dizin).
- **Sıra:** Aşağıdaki "Tanımlar" bölümü GT açılmadan önce yazıldı ve kaydedildi; ölçüm ondan sonra yapıldı. Bölümün sha256'sı ve yazılma anı §S.1'de.
- **Çıktıda olmayan:** fonksiyon adı, GT adı, `FUN_` anahtarı, adres, sözlükte olmayan fiil sözcüğü. Yalnız sayılar ve sözlük v0'ın sınıf adları vardır.

<!-- TANIMLAR-BAS -->
## Tanımlar (GT açılmadan önce yazıldı)

### T1. Veri ve nüfus

- **Veri:** yalnız geliştirme seti. Mac: `workspaces/olcum_mac/runs/ol7-a-9a36142` (tmux, htop). Debian: `~/karadul_olcum/n1_debian13` (8 program, 117 ELF). Ön sayımla aynı koşular. Kilitli veri (`dogrulama_seti*`, `test_seti*`, `targets/`) açılmaz.
- **Birim:** (platform, program); 10 birim.
- **Nüfus:** ön sayımdaki `isim_bekleyen` ile aynı: thunk ve dış olmayan, adı `^FUN_<onaltılık>$` olan Ghidra fonksiyonu. Tanım `on_sayim.elf_say` içindedir; bu ölçüm o fonksiyonu çağırır ve fonksiyon başına ara verisini (sınıf, çağrı kümeleri, disassembly özeti) oradan alır. Yeniden yazılmaz.
- **Yapısal sınıf (K / I / Y):** `on_sayim.py`'deki tanım: K en az bir kütüphane fonksiyonu çağırıyor (derleyici eki ve CRT hariç); I yalnız iç fonksiyon çağırıyor; Y yaprak.
- **GT:** `scripts/measurement/ks1_olc.py`'nin `gt_mac` ve `gt_elf` fonksiyonlarıyla okunur (adres → GT adları, Ghidra adres uzayında). Başka yoldan okunmaz. C++ ikili (`ks1_olc.cpp_ikili_mi`; geliştirme setinde pzstd) için GT okunmaz; o ELF'in fonksiyonları `cpp_disarida` durumunda sayılır (KS-1 ve taslak S25 ile aynı işaret).
- **KS-1 nüfusuyla fark:** KS-1'in GT'li nüfusu (`GtBirimi.nufus`: program sınıfı, klon değil, CRT ve export değil) bu vekil nüfusun alt kümesi olmayabilir. Vekil nüfustaki fonksiyonların kaçının KS-1 nüfusunda olduğu ayrıca sayılır.

### T2. GT adından fiil

1. Adres GT'de yoksa durum `gt_yok`.
2. GT'deki her takma ad için: platform öneki atılır (`ks1_olc.platform_adi`: Mach-O'da baştaki tek `_`); derleyici eki soyulur (`ks1_olc.klon_tabani`: `.cold`, `.part`, `.isra`, `.constprop` …). Tabanı boş kalan ad (makine dışlayıcısı parçası) atılır.
3. Hiç ad kalmadıysa durum `parca`.
4. Kalan tabanlar sıralanır, `_` ile birleştirilir ve `on_sayim.fiil_durumu`'na verilir. Yani kural ön sayımdaki ve taslak §6.3'teki başvuru kuralının aynısıdır: ad alt çizgiden ve küçük/büyük harf geçişinden belirteçlere bölünür; belirteçlerin sözlük v0 sınıfları toplanır; önek atlanmaz, belirtecin addaki konumuna bakılmaz. Birden çok takma adda sınıfların birleşimi alınır.
5. Durumlar: `tek_sinif` (genel sınıf dışında tam bir sınıf), `cok_sinif` (birden çok), `yalniz_genel` (yalnız `handle` sınıfı), `fiilsiz` (sözlük belirteci yok).
6. "Sözlükte fiil var" = `tek_sinif` + `cok_sinif`. Başvuru fiili yalnız `tek_sinif` adlarda tanımlıdır (taslak §6.3).
7. Ayrıca sayılır: bütün takma adları derleyici ekli olan fonksiyonlar (`klon_ekli`), birden çok takma adı olanlar (`cok_adli`).

### T3. Üretilecek sayılar

Hepsi birim başına; ayrıca havuz (10 birimin toplamı), Mac ikilisi (mac/tmux + mac/htop) ve program düzeyi makro (aynı programın platform birimleri önce ortalanır, sonra 8 program eşit ağırlıkla; KS-1'in kuralı). Payda aksi yazılmadıkça birimin nüfusudur. Çok ELF'li birimlerde sayım örnek düzeyindedir (aynı ad birden çok ELF'te birden çok kez sayılır); ek olarak tekil görünüm verilir: birim içinde aynı (birleşik) GT adı bir kez sayılır, aile isabeti örneklerden herhangi birinde varsa var sayılır. Tekil görünümde GT adı olmayan fonksiyonlar (`gt_yok`, `parca`, `cpp_disarida`) yer almaz.

1. **Fiil durumu:** T2'deki yedi durumun sayısı.
2. **Sözlük sınıfı başına pay:** `tek_sinif` adların 30 sınıfa dağılımı. Yan sayı: `cok_sinif` adlar da sayılırsa sınıf başına üye sayısı (bir ad birden çok sınıfta).
3. **K / I / Y × fiil durumu.**
4. **Aile tavanı** (T4).
5. **Sözlük dışı fiil** (T5).
6. **Ad biçimi** (T6).

### T4. Aile tavanı

"Aile kusursuz çalışsa doğru fiil verdiği fonksiyon" üst sınırı = ailenin **erişebildiği** (GT'siz, `static/` çıktısından hesaplanan ön koşul) ve GT başvuru fiili ailenin o fonksiyona verebildiği sınıf olan (`tek_sinif`) nüfus fonksiyonları. Erişim tanımları kuralların kendisi değil, kuralların gerek koşullarının cömert vekilleridir; gerçek kurallar (veri akışı bağı, ana yol, korumalar) bundan az fonksiyona ad verir.

| Aile | Verebildiği sınıflar | Erişim (ön koşul) | İsabet |
|---|---|---|---|
| **F-API** | `open`, `close`, `read`, `write`, `print`, `parse`, `encode`, `find`, `sort`, `lock`, `unlock`, `start`, `stop`, `wait` (taslak §4.2) | Ayırt edici bir kütüphane fonksiyonu çağırıyor (ön sayımdaki `K_ayirt_edici`: hata/ileti ve bellek/dizgi aileleri dışında en az bir kütüphane çağrısı). İki düzey: **fk2** = iç çağrı sayısı ≤ 3 (taslak S13; ilk sürümün sınırı); **geniş** = iç çağrı sınırı yok | Başvuru sınıfı 14 sınıftan biri. API → fiil tablosu yazılmadığı için çağrılan API'nin o fiili verip veremeyeceğine bakılmaz (cömert) |
| **F-ETKİ, ilk sürüm** | `create`, `destroy` | `create`: bir ayırıcı çağırıyor; `destroy`: bir bırakıcı çağırıyor. Üç düzey: **doğrudan** = kütüphane ayırıcısı (`malloc`, `calloc`, `realloc`, `reallocarray`, `strdup`, `strndup`) ya da bırakıcısı (`free`); **sarmalayıcı dahil** = doğrudan ya da çağırdığı iç fonksiyonlardan biri sarmalayıcı vekili (aşağıda); **çağrı yapan** = yaprak değil (K ya da I; kuralın en zayıf gerek koşulu, taslak `:306-307`) | Başvuru sınıfı, ön koşulu sağlanan fiille aynı (`create` ↔ ayırıcı, `destroy` ↔ bırakıcı) |
| **F-ETKİ, ölçüm adayları** (ilk sürümde yok) | `init`, `get`, `set`, `is`, `copy`, `compare` | Taslak §4.2'deki koşulların sayılabilen kısmı: `get`, `set`: yaprak; `is`: yığın dışına saklama komutu yok (ön sayımdaki `yazar` işareti; disassembly yoksa erişilir sayılır); `init`: kütüphane ayırıcısını doğrudan çağırmıyor; `copy`, `compare`: koşulsuz | Başvuru sınıfı, koşulu sağlanan fiille aynı |
| **F-ROL** | Rol adının ilk belirtecinin sınıfı (`rules.py:213-248`): `qsort`, `bsearch` → `compare`; `atexit` → `fini`. Öbür roller genel sınıftadır (`sigaction`, `signal`, `event_once`, `event_set`, `bufferevent_new` → `handle`) ya da fiilsizdir (`pthread_create`); FK8 gereği fiil vermez | Fonksiyonun adresi, kayıt API'lerinden birini çağıran bir iç fonksiyonun gövdesinde kuruluyor (`macho_f1.scan_code_refs`'in `address_taken` kuralı: `adrp` + 16 komut içinde `add`, ya da `adr`). Argüman konumu denetlenmez (cömert) | Başvuru sınıfı, kaydeden API'nin rol sınıfıyla aynı (`compare` ya da `fini`). Yan sayılar: erişilen fonksiyon sayısı; bunlardan GT durumu `yalniz_genel` olanlar; erişim aranmadan başvuru sınıfı `compare` ya da `fini` olan bütün fonksiyonlar |

- **Sarmalayıcı vekili** (FK1'in cömert, GT'siz vekili; ayırıcı ve bırakıcı için ayrı ayrı): (a) *temel:* iç fonksiyon; kütüphane çağrılarından hata/ileti ailesi ve errno erişimi çıkarıldığında kalan küme boş değil ve tümü ayırıcı (ya da tümü bırakıcı) ailesinde; iç çağrı sayısı ≤ 1; komut sayısı ≤ 32. (b) *iletici:* toplam çağrı hedefi (kütüphane ∪ iç) tek, o hedef bir sarmalayıcı vekili, komut sayısı ≤ 32; en çok 4 adım. Sayılar (≤ 1, ≤ 32, 4) bu ölçüme özgü seçimlerdir; ölçülmüş değerler değildir.
- **Birleşik tavan** (bir fonksiyon bir kez sayılır):
  - **ilk sürüm, dar:** F-ROL ∪ F-API fk2 ∪ F-ETKİ ilk sürüm (sarmalayıcı dahil). Taslağın ilk sürümüne en yakın üst sınır.
  - **ilk sürüm, geniş:** F-ROL ∪ F-API geniş ∪ F-ETKİ ilk sürüm (çağrı yapan).
  - **adaylar dahil, geniş:** yukarıdaki ∪ F-ETKİ ölçüm adayları.
  - **erişimsiz sınır:** başvuru sınıfı üç ailenin ilk sürümde verebildiği 18 sınıftan (14 + `create`, `destroy` + `compare`, `fini`) biri olan bütün fonksiyonlar; ve adaylarla 23 sınıf. Erişim koşulu aranmaz; "sözlük ve fiil kümesi" sınırıdır.
- **Duyarlılık:** aynı tavanlar, `cok_sinif` adlarda sınıflardan biri ailenin verebildiği sınıfsa isabet sayılarak ikinci kez verilir. Asıl sayı `tek_sinif` tanımlıdır.
- Bir aile tavanı o ailenin **doğru adlandırdığı** fonksiyon sayısı değildir: nesne, ad biçimi (B4), rubrik ve korumaların elediği fonksiyonlar hesaba girmez. Tavan yalnız "en çok bu kadar" der.

### T5. Sözlük dışı fiil

- Bu makinede sözcük türü bilgisi taşıyan bir sözlük yok (WordNet kurulu değil; `/usr/share/dict/web2` çekimli biçimleri tutarsız içeriyor). Ağ ve başka model yasak. Bu yüzden sözlük dışı fiil, GT açılmadan önce yazılmış **kapalı bir ölçme listesiyle** sayılır: `~/karadul_olcum/runs/n4-fiil-tavani-2026-11-10/ek_fiil_listesi.txt` (depo dışı; sha256'sı çıktıya yazılır). Liste ürün sözlüğü değildir, hiçbir programın ad listesinden alınmadı ve GT görüldükten sonra değişmez. İki kesimi var: `acik` (tanımlayıcıda çoğunlukla fiil) ve `belirsiz` (ad olarak da sık geçen). Sözlük v0 belirteçleriyle kesişmez (betik denetler).
- Sayım yalnız durumu `fiilsiz` ya da `yalniz_genel` olan adlarda yapılır. Üretilen: en az bir `acik` belirteci taşıyan fonksiyon sayısı; `acik` ya da `belirsiz` taşıyan fonksiyon sayısı; görülen farklı liste belirteci sayısı (kesim başına); en sık 10 belirtecin fonksiyon sayıları, yalnız sıra numarasıyla. Belirteçlerin kendisi hiçbir çıktıya yazılmaz.
- **Sınırı:** kapalı liste alt kestirimdir (listede olmayan fiil sayılmaz); `belirsiz` kesimi üst yöne şişirir (ad olarak kullanılan belirteç fiil sayılır). Gerçek pay elle denetimdeki `fiilsiz` örneklerinden ayrıca kestirilir (T7).

### T6. Ad biçimi

`tek_sinif` adlarda (birden çok takma ad varsa sözlük fiili taşıyan, sıralamada ilk taban ad), yalnız rakamdan oluşan belirteçler atıldıktan sonra, sözlük fiili belirtecinin (genel sınıf hariç; birden çoksa ilki) konumu:
- `yalniz_fiil`: ad tek belirteç;
- `fiil_nesne`: fiil ilk belirteç;
- `nesne_fiil`: fiil son belirteç (öneki olan `modül_nesne_fiil` de buraya düşer);
- `onek_fiil_nesne`: fiil ortada (önünde ve arkasında belirteç var).

Modül öneki vekili (GT adı olan bütün fonksiyonlarda): adın (sıralamada ilk taban adın) ilk belirteci sözlük belirteci değil ve aynı birimin nüfusunda en az 5 farklı GT adının ilk belirteci. Sayı (5) bu ölçüme özgü seçimdir.

### T7. Doğrulama ve önceden yazılan okuma

- Nüfus ve K/I/Y sayıları birim başına `on_sayim.json` ile aynı olmalı; her ELF'te fonksiyon başına yeniden toplanan sayılar (`isim_bekleyen`, `sinif_K/I/Y`, `K_ayirt_edici`, `K_ayirt_edici_ic_cagri_*`) `on_sayim.elf_say`'in döndürdüğü sayımla aynı olmalı. Tutmazsa betik durur.
- Çıktı iki farklı `PYTHONHASHSEED` ile bayt bayt aynı olmalı.
- **Elle denetim (uçbirimde; dosyaya yazılmaz):** tohumu sabit (20261110) 40 fonksiyon: 16 `tek_sinif`, 14 `fiilsiz`, 5 `cok_sinif`, 5 `yalniz_genel`; her tabakanın yarısı Mac birimlerinden, yarısı Debian birimlerinden. Sorular: (a) `tek_sinif`: sözlük belirteci adda gerçekten fiil olarak mı duruyor ve sınıfı doğru mu; (b) `fiilsiz`: adda açık bir fiil var mı (varsa sözlük boşluğu; `acik` listede mi); (c) `cok_sinif`: sınıflardan biri açıkça asıl fiil mi; (d) `yalniz_genel`: adda başka bir fiil var mı. Yanlış sınıflama oranı = (a)'da "fiil değil ya da sınıf yanlış" + (b)'de "açık fiil var" + (d)'de "başka fiil var" sayılarının toplamı / 35 (çok sınıflılar ayrı raporlanır). Değerlendiren tek modeldir; insan denetimi değildir.
- **Önceden yazılan okuma** (Onuncu Adam §7 madde 3'ün önerdiği eşik; karar Berke'nin): Mac htop'ta başvuru sınıfı `create` ya da `destroy` olan fonksiyonların nüfustaki payı %8'in altındaysa F-ETKİ'nin ilk sürümü htop türünde Kapı 1 sonucunu değiştiremez. Karşılaştırılacak öbür sayılar: Onuncu Adam'ın K ∪ Y tavanı (Mac tmux %52,8, Mac htop %55,6) ve gerçekçi katkı tahmini (Mac tmux ≈ %3-11, Mac htop ≈ %5-11).
- Bu ölçümün söyleyemeyeceği: yakın kapsam (rubrik), yanlış fiil oranı, kanıt tavanı (Kapı 1'in paydası). Fiil tavanı yalnız N4'ün fiil kökenli kapsamına üst sınır verir.
<!-- TANIMLAR-SON -->

## Sonuçlar (GT açıldıktan sonra yazıldı)

İşaretler: **[hesap]** bu belgedeki ya da anılan kaynaktaki sayılardan aritmetik; **[elle]** uçbirimde elle bakış; **[ek]** ön kayıtta olmayan, GT görüldükten sonra eklenen bakış.

### S.1 Bütünlük kaydı

| Ne | Değer |
|---|---|
| "Tanımlar" bölümünün sha256'sı | `08ed09098900b94a…`; `fiil_tavani.json` → `kunye.tanimlar_sha256` aynı değeri taşır |
| Tanımların kaydı | `~/karadul_olcum/runs/n4-fiil-tavani-2026-11-10/tanimlar_on_kayit.txt`: ilk kayıt 17:19:29 (`3d17c6e3…`), ikinci kayıt 17:20:44 (T6'daki önek tanımı netleştirildi; GT hâlâ kapalıydı). İlk GT okuması 17:24-17:25 (`deneme1.json`, 17:25:36). Commit olmadığı için kanıt yalnız dosya zaman damgalarıdır |
| Sözlük dışı fiil ölçme listesi | sha256 `857c2a3ad718980c…`; `acik` 185, `belirsiz` 63 belirteç; 17:18:04'te yazıldı, sonra değişmedi |
| `fiil_tavani.py` / `fiil_tavani.json` (sha256, ilk 16) | `494b73d67a07eaf3` / `81e733bbd75ef9d2` |
| `on_sayim.py` / `on_sayim.json` (sha256, ilk 16) | `ad6c0e6ec4934954` / `b0bfc0665b2cefb1` (taslağın yazdığı değerler; değişmedi) |
| Git | `fa99144` (izole çalışma ağacı; commit yok) |

Yeniden üretim:
`python3 -B docs/arge/2026-11-10_n4/fiil_tavani.py --mac-kosu workspaces/olcum_mac/runs/ol7-a-9a36142 --mac-veri workspaces/olcum_mac --debian-kosu ~/karadul_olcum/n1_debian13 --ek-fiil-listesi ~/karadul_olcum/runs/n4-fiil-tavani-2026-11-10/ek_fiil_listesi.txt --cikti docs/arge/2026-11-10_n4/fiil_tavani.json`

Denetimler:
- **Nüfus:** 10 birimde nüfus ve K/I/Y `on_sayim.json` ile aynı (Mac tmux 2 587 = 951 / 1 220 / 416; Mac htop 597 = 230 / 265 / 102; toplam 23 963). 119 ELF'in her birinde fonksiyon başına yeniden toplanan 8 sayaç `on_sayim.elf_say`'in döndürdüğüyle aynı.
- **Belirlenimcilik:** `PYTHONHASHSEED` 0 ve 12345 ile JSON ve tablolar bayt bayt aynı; 1 ile tablolar aynı.
- **Test:** `tests/test_n4_fiil_tavani.py`, 36 test, sentetik veri. Yalıtılmış kopyada (`PYTHONDONTWRITEBYTECODE=1`, her mutant farklı uzunlukta) 28 elle mutantın 28'i öldü; kayıt `…/mutant_sonuc.txt`.
- **GT görüldükten sonra betikte değişen:** boş kayıt kümesinde sayaç anahtarı hatası (sentetik testte çıktı) ve bir belge satırı. Sayılar değişmedi: ilk GT koşusunun (`deneme1`) tabloları ve JSON'u (betik sha256'sı dışında) son koşuyla aynı. Sözlük, aile kümeleri, eşikler ve ölçme listesi değişmedi.

### S.2 Özet

Payda birimin nüfusu. "Dar" ve "geniş" T4'teki birleşik tavanlardır; hepsi başvuru = tek sınıflı ad tanımıyla.

| | Nüfus | GT adı tek sınıflı | F-API fk2 / geniş | F-ETKİ ilk sürüm: sarmalayıcı dahil / çağrı yapan | F-ROL | **Birleşik, ilk sürüm: dar / geniş** | Adaylar dahil, geniş | Erişimsiz: 18 / 23 sınıf |
|---|---|---|---|---|---|---|---|---|
| `mac/tmux` | 2 587 | 1 612 (%62,3) | %3,0 / %5,3 | %3,7 / %5,6 | 3 (%0,1) | **175 (%6,8) / 286 (%11,1)** | 566 (%21,9) | %31,3 / %50,5 |
| `mac/htop` | 597 | 423 (%70,9) | %3,7 / %5,2 | %13,9 / %15,4 | 0 | **105 (%17,6) / 123 (%20,6)** | 200 (%33,5) | %37,4 / %62,8 |
| Mac ikilisi | 3 184 | 2 035 (%63,9) | %3,1 / %5,3 | %5,6 / %7,4 | 3 (%0,1) | **280 (%8,8) / 409 (%12,8)** | 766 (%24,1) | %32,4 / %52,8 |
| Havuz, örnek düzeyi | 23 963 | 8 620 (%36,0) | %4,8 / %6,1 | %2,9 / %5,2 | 22 (%0,1) | **1 848 (%7,7) / 2 725 (%11,4)** | 4 261 (%17,8) | %19,2 / %30,1 |
| Havuz, tekil GT adı | 9 698 | 5 572 (%57,5) | %5,7 / %8,3 | %4,1 / %6,4 | 19 (%0,2) | **966 (%10,0) / 1 444 (%14,9)** | 2 371 (%24,4) | %31,3 / %48,4 |
| Program makrosu, örnek | — | %45,3 | %7,0 / %8,9 | %3,3 / %5,8 | %0,1 | **%10,4 / %14,8** | %22,0 | %26,3 / %39,1 |
| Program makrosu, tekil | — | %51,4 | %7,9 / %10,4 | %3,6 / %6,3 | %0,2 | **%11,7 / %16,9** | %24,9 | %30,3 / %44,6 |

- Duyarlılık (çok sınıflı adlarda sınıflardan biri yeterse): Mac tmux %8,6 / %14,1; Mac htop %19,6 / %23,5; havuz (örnek) %8,6 / %12,7.
- Havuzun örnek düzeyi coreutils'e bağlıdır: nüfusun %56,3'ü (13 485) oradan gelir ve 106 ELF'te aynı yardımcı kütüphane fonksiyonları yinelenir (tekil ad 1 205). Programlar arası okuma için makro ya da tekil görünüm kullanılmalıdır.
- `debian/zstd` biriminde nüfusun %43,6'sı (832) C++ ikilisindedir (pzstd); GT okunmadı, payda içinde kaldı.

**GT adlarının fiil durumu** (Mac tmux / Mac htop): tek sınıf %62,3 / %70,9; çok sınıf %13,0 / %7,4; yalnız genel %2,2 / %3,7; fiilsiz %21,4 / %18,1; GT'de yok 27 / 0; parça 1 / 0.

**Sınıf payları** (tek sınıflı adlar; nüfusa oran; tam tablo S.7'de):
- Mac tmux'ta ilk beş: `print` %11,9, `set` %5,8, `get` %5,5, `copy` %4,9, `add` %4,3. `print` ve `copy` büyük ölçüde modül adı çakışmasıdır (S.4, S.5).
- Mac htop'ta ilk beş: `set` %14,2, `print` %9,0, `create` %8,4, `destroy` %7,5, `get` %4,9.
- Hiçbir ailenin (adaylar dahil) veremediği altı sınıf (`reset`, `add`, `remove`, `run`, `compute`, `resize`): Mac tmux 305 (%11,8), Mac htop 48 (%8,0) **[hesap]**.

**K / I / Y:** tek sınıflı ad oranı sınıflar arasında yakın: Mac tmux K %65,3, I %63,3, Y %52,6; Mac htop K %67,0, I %74,7, Y %69,6. Tek sınıflı adların Mac tmux'ta 772'si (%47,9), Mac htop'ta 198'i (%46,8) I sınıfındadır **[hesap]**; bu fonksiyonlara ilk sürümde yalnız sarmalayıcı üzerinden `create` / `destroy` erişir.

**F-ETKİ ilk sürüm:**
- Mac htop: GT `create` 50 (%8,4), `destroy` 45 (%7,5). Ayırıcıyı doğrudan çağıranlarda `create` isabeti 0, sarmalayıcı dahil 40, çağrı yapanlarda 48. `destroy`: 38 / 43 / 44.
- Mac tmux: GT `create` 50 (%1,9), `destroy` 97 (%3,7). `create`: 3 / 18 / 48; `destroy`: 72 / 77 / 97.
- Kütüphane ayırıcısını doğrudan çağıran isim bekleyen Mac tmux'ta 21, Mac htop'ta 14; sarmalayıcı vekiliyle 351 ve 100. Yani `create` Mac'te tümüyle sarmalayıcı tanımaya bağlıdır.

**F-ROL:** adresi bir kayıt yerinde kurulan isim bekleyen Mac tmux'ta 67, Mac htop'ta 2, havuzda 242. Bunların rolü çoğunlukla genel sınıftadır (havuzda 197'si); `compare` rolü 46, `fini` rolü 0. İsabet havuzda 22, Mac tmux'ta 3, Mac htop'ta 0. Geliştirme setinde `atexit` adlı import'u çağıran iç fonksiyon yok (ön sayımın çağrı çözümüyle); nedeni doğrulanmadı.

**Sözlük dışı fiil (kapalı liste):** durumu fiilsiz ya da yalnız genel olan adlar Mac tmux'ta 611 (%23,6), Mac htop'ta 130 (%21,8). `acik` belirteci taşıyan: 96 (%3,7) ve 30 (%5,0); `belirsiz` de sayılırsa 157 (%6,1) ve 39 (%6,5). Görülen farklı `acik` belirteç: 40 ve 14; havuzda 185'in 93'ü. En sık 10'un fonksiyon sayıları Mac tmux'ta 24, 6, 4, 4, 4, 4, 4, 4, 3, 3; Mac htop'ta 9, 3, 3, 3, 2, 2, 2, 1, 1, 1. Liste, elle denetimdeki fiilli 8 `fiilsiz` adın hiçbirini yakalamadı (S.4); bu sayılar zayıf bir alt kestirimdir.

**Ad biçimi** (tek sınıflı adlar): Mac tmux'ta fiil başta %19,7, sonda %27,9, ortada %52,4; Mac htop'ta %4,0 / %45,6 / %50,1. Modül öneki vekili GT adı olanların Mac tmux'ta %81,2'sinde, Mac htop'ta %78,9'unda tutuyor. Taslağın öneksiz `fiil_nesne` kalıbı (§3.3) Mac birimlerinde tek sınıflı adların %16,4'üdür; fiil belirtecinin konumu elle denetlenmedi (modül çakışması bu sayıları da etkiler).

### S.3 Okuma

**Önceden yazılan eşik (T7).** Mac htop'ta başvuru sınıfı `create` ya da `destroy` olan pay 95 / 597 = %15,9 **[hesap]**; %8 eşiğinin üstünde. "F-ETKİ'nin ilk sürümü htop türünde Kapı 1'i değiştiremez" okuması bu ölçütle **çıkmıyor**. Mac tmux'ta aynı pay 147 / 2 587 = %5,7.

**Onuncu Adam'la karşılaştırma:**

| | Mac tmux | Mac htop |
|---|---|---|
| Onuncu Adam: N4'ün mutlak tavanı K ∪ Y (`onuncu_adam.md` §1.1) | %52,8 | %55,6 |
| Ölçülen: GT adı tek sınıflı (sözlük v0'ın bütünü; erişim aranmadan) | %62,3 | %70,9 |
| Ölçülen: üç ailenin ilk sürümde verebildiği 18 sınıf, erişim aranmadan | %31,3 | %37,4 |
| Ölçülen: ilk sürüm birleşik tavan, dar / geniş | %6,8 / %11,1 | %17,6 / %20,6 |
| Ölçülen: adaylar dahil, geniş | %21,9 | %33,5 |
| Onuncu Adam: gerçekçi katkı tahmini, kötümser-iyimser (§1.3) | ≈ %3-11 | ≈ %5-11 |

- K ∪ Y tavanı yapısal bir üst sınırdı; fiil tavanı onun çok altında. İlk sürümün cömert tavanı bile Mac tmux'ta K ∪ Y'nin yaklaşık beşte biri, Mac htop'ta üçte biri kadardır **[hesap]**.
- **Mac tmux:** Onuncu Adam'ın iyimser senaryosu (≈ %11) ilk sürümün geniş tavanına (%11,1) eşittir. O senaryonun tutması için tavandaki her fonksiyonun ad alması ve yakın sayılması gerekir. Dar tavan %6,8'dir; gerçekçi katkı bunun altında kalır. Ölçüm, tahmin aralığının alt yarısını destekliyor.
- **Mac htop:** tavan (%17,6 / %20,6) tahmin aralığının (≈ %5-11) üstünde. Farkın kaynağı F-ETKİ'dir: dar tavanın 83'ü (%13,9) `create` / `destroy`, yalnız 22'si (%3,7) F-API. Bu adlar ilk sürümde genel nesnelidir (B4). Tavan, B4 adları yakın sayılırsa ve sarmalayıcı tanıma çalışırsa erişilebilir; ikisi de ölçülmedi.
- Onuncu Adam'ın tahmini "yakın kapsam", buradaki sayı "GT adındaki fiille aynı sınıf" tavanıdır; iki ölçü aynı şey değildir (S.6 madde 1).

**Taslağın hedefi (Kapı 1) için:**
- Kapı 1: yanlış ≤ %10 iken yakın kapsam ≥ kanıt tavanının %50'si. Kanıt tavanı burada ölçülmedi.
- Fiil kökenli kapsamın üst sınırı (dar / geniş): Mac tmux %6,8 / %11,1; Mac htop %17,6 / %20,6. KS-1'in kesin satırıyla (Mac tmux %5,9, Mac htop 0; `ks1_olcum.md:43`) toplanırsa, çakışma yok sayılarak: Mac tmux ≤ %12,7 / %17,0; Mac htop ≤ %17,6 / %20,6 **[hesap]**.
- Bu, her isabetin ad alıp yakın sayıldığı durumdur. O durumda bile Kapı 1 ancak kanıt tavanı Mac tmux'ta ≤ %25-34, Mac htop'ta ≤ %35-41 ise tutar **[hesap: 2 × kapsam]**. İsabetlerin yarısı yakın çıkarsa sınırlar Mac tmux'ta ≤ %19-23, Mac htop'ta ≤ %18-21 olur **[hesap]**.
- **%75 hedefi** fiille ulaşılamaz: sözlük v0'ın bütün sınıfları sayılsa ve her fonksiyona erişilse bile tek sınıflı ad payı %62,3 / %70,9; üç ailenin sınıflarıyla %31,3 / %37,4.
- htop türünde sonuç iki karara bağlıdır: B4 adlarının yakın sayılması (S7, H-N4-5) ve `create` kuralının sarmalayıcı üzerinden çalışması (FK1). tmux türünde üç ailenin ilk sürümü tek başına taşımıyor; tavanın en büyük parçası ölçüm adaylarında (`get`, `set`, `is`, `init`) ve hiçbir ailenin vermediği sınıflarda (`add`, `remove`, `reset`, `resize`, `run`) kalıyor.

### S.4 Elle denetim [elle]

Tohumu sabit 40 fonksiyon uçbirimde okundu; adlar dosyaya yazılmadı. Değerlendiren tek modeldir.

| Tabaka | n | Bulgu | Oran (Wilson %95) |
|---|---|---|---|
| `tek_sinif` | 16 | 1 adda sözlük belirteci fiil değil, modül adının parçası. Öbür 15'te belirteç fiil ve sınıfı uygun (birinde fonksiyon derleyici çalışma zamanına ait; nüfus vekilinin kusuru) | 1/16 = %6,3 (%1,1-28,3) |
| `fiilsiz` | 14 | 8 adda açık bir fiil var. 7'sinde fiil başka sözcüğe bitişik yazılmış (4'ü aynı ayırıcı sarmalayıcı ailesi, Debian coreutils'te yineleniyor); 1'inde ayrı belirteç ama sözlükte yok. Ölçme listesi 8'in hiçbirini yakalamadı; listenin iki eşleşmesi de ad kullanımıydı | 8/14 = %57,1 (%32,6-78,6) |
| `yalniz_genel` | 5 | Başka fiil yok | 0/5 |
| `cok_sinif` | 5 | 5'inde de sınıflardan biri açıkça asıl fiil (öbürü modül adı, sonek ya da ad) | 5/5 |

- **Yanlış sınıflama oranı** (T7'deki tanım): (1 + 8 + 0) / 35 = **%25,7** (%14,2-42,1).
- İki hata ters yönde çalışır: modül adı çakışması tek sınıflı payı ve tavanı şişirir; bitişik yazılmış fiiller `fiilsiz` payını şişirir, tavanı düşürür. Örnek küçüktür; yönleri ve kabaca büyüklükleri S.5'te mekanik olarak bakıldı.
- Sonuç başvuru tanımının (taslak §6.3, M1) kendisi için de geçerlidir: aynı kural M1'de export adlarına uygulanacak.

### S.5 Ön kayıtta olmayan ek bakışlar [ek]

GT görüldükten sonra, elle denetimin gösterdiği iki hata türünün tavanlara etkisini görmek için yapıldı. Betik depo dışında: `~/karadul_olcum/runs/n4-fiil-tavani-2026-11-10/ek_bakis.py`. Karar dayanağı değildir; yön ve büyüklük içindir.

1. **Modül adı çakışması (yalnız Mac tmux).** Tek sınıflı adlarda (önceki belirteç, fiil belirteci) çiftlerine bakıldı. Beş çift modül önekinin parçası çıktı ve 471 adı kapsıyor: 246, 106, 51, 48, 20 (tek sınıflı 1 612 adın %29,2'si) **[elle; hesap]**. Dördü F-API sınıflarına (`print`, `write`, `read`, `find`), biri `copy`'ye düşüyor. Mac htop'ta en sık çiftler gerçek fiildi. Bu beş önek atlanıp ad yeniden sınıflanınca:

| Mac tmux | Tek sınıflı | F-API fk2 / geniş | Birleşik dar / geniş | Adaylar dahil | Erişimsiz 18 / 23 |
|---|---|---|---|---|---|
| Ön kayıtlı tanım | %62,3 | %3,0 / %5,3 | %6,8 / %11,1 | %21,9 | %31,3 / %50,5 |
| Modül öneki atlanarak | %51,8 | %2,2 / %4,1 | %6,3 / %10,4 | %18,1 | %21,5 / %38,7 |
| Modül öneki atlanarak ve bitişik fiil sayılarak (madde 2) | %58,2 | %2,3 / %4,2 | %6,5 / %11,0 | %18,9 | %24,9 / %42,9 |

2. **Bitişik yazılmış fiil (bütün birimler).** Durumu fiilsiz ya da yalnız genel olan adlarda, bir belirtecin başında ya da sonunda en az 4 harfli bir sözlük belirteci gömülüyse ve bunlar tam bir sınıf veriyorsa ad tek sınıflı sayıldı. Kaba bir üst kestirimdir (eylemi yapanı anlatan adlar ve sıfatlar da yakalanır). Tek sınıfa geçen: Mac tmux 110, Mac htop 17, coreutils 2 725 (örnek düzeyi).

| Birleşik dar / geniş | Ön kayıtlı tanım | Bitişik fiil de sayılarak |
|---|---|---|
| Mac tmux | %6,8 / %11,1 | %7,0 / %11,5 |
| Mac htop | %17,6 / %20,6 | %19,1 / %22,3 |
| Havuz, örnek düzeyi | %7,7 / %11,4 | %16,9 / %21,3 |
| Havuz, tekil | %10,0 / %14,9 | %11,3 / %16,7 |
| Program makrosu, tekil | %11,7 / %16,9 | %14,8 / %20,5 |

- **Okuma:** Mac birimlerinin ilk sürüm tavanı iki düzeltmeye karşı dayanıklı: Mac tmux %6,3-7,0 / %10,4-11,5; Mac htop %17,6-19,1 / %20,6-22,3. Erişimsiz sınırlar ve "adaylar dahil" tavanı Mac tmux'ta modül çakışmasıyla 4-12 puan şişmiş. Havuzun örnek düzeyi sayısı bitişik fiil kuralına çok duyarlı (coreutils'te yinelenen ayırıcı sarmalayıcıları); o sayı tek başına okunmamalı.

### S.6 Sınırlar ve doğrulanamayanlar

1. **Fiil tavanı yakın kapsam tavanı değildir.** Rubrik adı fonksiyonun amaç cümlesine göre değerlendirir, GT adına göre değil. GT adında sözlük fiili olmayan (ya da fiili yanlış okunan) bir fonksiyona verilen fiilli ad yakın sayılabilir; GT fiiliyle aynı sınıftaki ad da nesne ya da asıl iş yüzünden yakın sayılmayabilir. Tavan, M1'in ölçtüğü "aynı sınıf" uyumunun üst sınırıdır.
2. **Başvuru kuralı gürültülü:** elle denetimde yanlış sınıflama %25,7 (n = 35). Modül adı çakışmasının büyüklüğü yalnız Mac tmux'ta elle bakıldı; öbür birimlerde ölçülmedi.
3. **Erişim tanımları vekildir.** Sarmalayıcı vekilinin (≤ 32 komut, ≤ 1 iç çağrı, 4 adım) FK1'in gerçek tanımıyla örtüşmesi ölçülmedi. F-ROL'de argüman konumuna bakılmadı; kayıt API'leri `rules.py`'deki dokuz adla sınırlı. F-API'de çağrılan API'nin o fiili verip veremeyeceğine bakılmadı. Erişim tanımları cömert yazıldı, ama başvuru kuralındaki gürültü yüzünden sonuç kesin bir üst sınır olarak okunmamalı.
4. **Nüfus vekildir.** `FUN_` adlı fonksiyonların KS-1 nüfusunda olan payı Mac tmux'ta %98,3, Mac htop'ta %100, redis-tools'ta %69,1 (derleyici klonları), zstd'de %47,9 (C++ ikili). Debian birimlerinde derleyici çalışma zamanı fonksiyonları da nüfustadır.
5. **Sözlük dışı fiil ölçülemedi.** Sözcük türü kaynağı yoktu; kapalı liste elle denetimde hiçbir fiili yakalamadı. "Farklı fiil sayısı" ve sıklık dağılımı listeyle sınırlıdır.
6. **Elle denetim** tek modelle, 40 örnekle yapıldı. Model bu programları eğitim verisinden tanıyor olabilir; ölçme listesi ve tanımlar yazılırken bu bilgi bilerek kullanılmadı, ama etkisi dışlanamaz.
7. **Kanıt tavanı, yakın oranı, yanlış fiil oranı** bu ölçümde yok. Kapı 1 okuması koşulludur.
8. **`fini` rolünün erişimi 0** çıktı; `atexit`'in ELF'te neden import olarak görünmediği doğrulanmadı.
9. Tekil görünümde aile isabeti örneklerden herhangi birinde varsa var sayıldı (cömert); yapısal sınıf kırılımı yalnız örnek düzeyinde verildi.

### S.7 Tablolar (betik çıktısı)

`fiil_tavani.py --md-tablolar` çıktısıdır; elle değiştirilmedi. Bütün sayılar `fiil_tavani.json`'da.

#### Fiil durumu (örnek düzeyi)

| Birim | Nüfus | Tek sınıf | Çok sınıf | Yalnız genel | Fiilsiz | Parça | GT'de yok | C++ (okunmadı) |
|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 13 485 | 3 003 (%22,3) | 671 (%5,0) | 49 (%0,4) | 9 656 (%71,6) | 0 (%0,0) | 106 (%0,8) | 0 (%0,0) |
| `debian/htop` | 239 | 162 (%67,8) | 18 (%7,5) | 17 (%7,1) | 41 (%17,2) | 0 (%0,0) | 1 (%0,4) | 0 (%0,0) |
| `debian/openssl` | 588 | 275 (%46,8) | 30 (%5,1) | 56 (%9,5) | 226 (%38,4) | 0 (%0,0) | 1 (%0,2) | 0 (%0,0) |
| `debian/redis-tools` | 2 103 | 961 (%45,7) | 99 (%4,7) | 51 (%2,4) | 978 (%46,5) | 0 (%0,0) | 14 (%0,7) | 0 (%0,0) |
| `debian/sqlite3` | 425 | 212 (%49,9) | 15 (%3,5) | 10 (%2,4) | 187 (%44,0) | 0 (%0,0) | 1 (%0,2) | 0 (%0,0) |
| `debian/tmux` | 1 916 | 1 193 (%62,3) | 232 (%12,1) | 38 (%2,0) | 452 (%23,6) | 0 (%0,0) | 1 (%0,1) | 0 (%0,0) |
| `debian/tree` | 115 | 31 (%27,0) | 0 (%0,0) | 1 (%0,9) | 82 (%71,3) | 0 (%0,0) | 1 (%0,9) | 0 (%0,0) |
| `debian/zstd` | 1 908 | 748 (%39,2) | 115 (%6,0) | 1 (%0,1) | 211 (%11,1) | 0 (%0,0) | 1 (%0,1) | 832 (%43,6) |
| `mac/htop` | 597 | 423 (%70,9) | 44 (%7,4) | 22 (%3,7) | 108 (%18,1) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `mac/tmux` | 2 587 | 1 612 (%62,3) | 336 (%13,0) | 58 (%2,2) | 553 (%21,4) | 1 (%0,0) | 27 (%1,0) | 0 (%0,0) |
| **Mac ikilisi** | 3 184 | 2 035 (%63,9) | 380 (%11,9) | 80 (%2,5) | 661 (%20,8) | 1 (%0,0) | 27 (%0,8) | 0 (%0,0) |
| **havuz** | 23 963 | 8 620 (%36,0) | 1 560 (%6,5) | 303 (%1,3) | 12 494 (%52,1) | 1 (%0,0) | 153 (%0,6) | 832 (%3,5) |
| **program makrosu** | — | %45,3 | %5,5 | %2,9 | %40,4 | %0,0 | %0,4 | %5,5 |

#### Aile tavanı (örnek düzeyi; başvuru = tek sınıflı ad)

| Birim | Nüfus | F-API fk2 | F-API geniş | F-ETKİ doğrudan | F-ETKİ sarmalayıcı dahil | F-ETKİ çağrı yapan | F-ROL | Birleşik: ilk sürüm, dar | Birleşik: ilk sürüm, geniş | Birleşik: adaylar dahil, geniş | Erişimsiz: 18 sınıf | Erişimsiz: 23 sınıf |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 13 485 | 637 (%4,7) | 728 (%5,4) | 164 (%1,2) | 289 (%2,1) | 590 (%4,4) | 7 (%0,1) | 933 (%6,9) | 1 325 (%9,8) | 1 954 (%14,5) | 1 587 (%11,8) | 2 492 (%18,5) |
| `debian/htop` | 239 | 8 (%3,3) | 19 (%7,9) | 14 (%5,9) | 16 (%6,7) | 22 (%9,2) | 0 (%0,0) | 24 (%10,0) | 41 (%17,2) | 59 (%24,7) | 98 (%41,0) | 151 (%63,2) |
| `debian/openssl` | 588 | 96 (%16,3) | 106 (%18,0) | 0 (%0,0) | 0 (%0,0) | 25 (%4,3) | 1 (%0,2) | 97 (%16,5) | 132 (%22,4) | 194 (%33,0) | 169 (%28,7) | 258 (%43,9) |
| `debian/redis-tools` | 2 103 | 75 (%3,6) | 122 (%5,8) | 44 (%2,1) | 49 (%2,3) | 136 (%6,5) | 5 (%0,2) | 129 (%6,1) | 263 (%12,5) | 371 (%17,6) | 510 (%24,3) | 815 (%38,8) |
| `debian/sqlite3` | 425 | 57 (%13,4) | 64 (%15,1) | 1 (%0,2) | 1 (%0,2) | 18 (%4,2) | 0 (%0,0) | 58 (%13,6) | 82 (%19,3) | 125 (%29,4) | 126 (%29,6) | 176 (%41,4) |
| `debian/tmux` | 1 916 | 63 (%3,3) | 100 (%5,2) | 51 (%2,7) | 82 (%4,3) | 104 (%5,4) | 5 (%0,3) | 150 (%7,8) | 209 (%10,9) | 407 (%21,2) | 606 (%31,6) | 942 (%49,2) |
| `debian/tree` | 115 | 7 (%6,1) | 8 (%7,0) | 1 (%0,9) | 5 (%4,3) | 5 (%4,3) | 0 (%0,0) | 12 (%10,4) | 13 (%11,3) | 13 (%11,3) | 25 (%21,7) | 25 (%21,7) |
| `debian/zstd` | 1 908 | 101 (%5,3) | 150 (%7,9) | 60 (%3,1) | 63 (%3,3) | 100 (%5,2) | 1 (%0,1) | 165 (%8,6) | 251 (%13,2) | 372 (%19,5) | 455 (%23,8) | 681 (%35,7) |
| `mac/htop` | 597 | 22 (%3,7) | 31 (%5,2) | 38 (%6,4) | 83 (%13,9) | 92 (%15,4) | 0 (%0,0) | 105 (%17,6) | 123 (%20,6) | 200 (%33,5) | 223 (%37,4) | 375 (%62,8) |
| `mac/tmux` | 2 587 | 77 (%3,0) | 138 (%5,3) | 75 (%2,9) | 95 (%3,7) | 145 (%5,6) | 3 (%0,1) | 175 (%6,8) | 286 (%11,1) | 566 (%21,9) | 810 (%31,3) | 1 307 (%50,5) |
| **Mac ikilisi** | 3 184 | 99 (%3,1) | 169 (%5,3) | 113 (%3,5) | 178 (%5,6) | 237 (%7,4) | 3 (%0,1) | 280 (%8,8) | 409 (%12,8) | 766 (%24,1) | 1 033 (%32,4) | 1 682 (%52,8) |
| **havuz** | 23 963 | 1 143 (%4,8) | 1 466 (%6,1) | 448 (%1,9) | 683 (%2,9) | 1 237 (%5,2) | 22 (%0,1) | 1 848 (%7,7) | 2 725 (%11,4) | 4 261 (%17,8) | 4 609 (%19,2) | 7 222 (%30,1) |
| **program makrosu** | — | %7,0 | %8,9 | %2,1 | %3,3 | %5,8 | %0,1 | %10,4 | %14,8 | %22,0 | %26,3 | %39,1 |

#### Aile tavanı (örnek düzeyi; duyarlılık: çok sınıflı adlar da)

| Birim | Nüfus | F-API fk2 | F-API geniş | F-ETKİ doğrudan | F-ETKİ sarmalayıcı dahil | F-ETKİ çağrı yapan | F-ROL | Birleşik: ilk sürüm, dar | Birleşik: ilk sürüm, geniş | Birleşik: adaylar dahil, geniş | Erişimsiz: 18 sınıf | Erişimsiz: 23 sınıf |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 13 485 | 657 (%4,9) | 752 (%5,6) | 198 (%1,5) | 325 (%2,4) | 633 (%4,7) | 7 (%0,1) | 989 (%7,3) | 1 390 (%10,3) | 2 375 (%17,6) | 1 955 (%14,5) | 3 053 (%22,6) |
| `debian/htop` | 239 | 8 (%3,3) | 20 (%8,4) | 15 (%6,3) | 17 (%7,1) | 24 (%10,0) | 0 (%0,0) | 25 (%10,5) | 44 (%18,4) | 70 (%29,3) | 112 (%46,9) | 169 (%70,7) |
| `debian/openssl` | 588 | 103 (%17,5) | 113 (%19,2) | 0 (%0,0) | 0 (%0,0) | 33 (%5,6) | 1 (%0,2) | 104 (%17,7) | 145 (%24,7) | 223 (%37,9) | 195 (%33,2) | 288 (%49,0) |
| `debian/redis-tools` | 2 103 | 86 (%4,1) | 133 (%6,3) | 46 (%2,2) | 51 (%2,4) | 148 (%7,0) | 5 (%0,2) | 142 (%6,8) | 286 (%13,6) | 398 (%18,9) | 594 (%28,2) | 908 (%43,2) |
| `debian/sqlite3` | 425 | 66 (%15,5) | 73 (%17,2) | 2 (%0,5) | 2 (%0,5) | 22 (%5,2) | 0 (%0,0) | 67 (%15,8) | 92 (%21,6) | 136 (%32,0) | 139 (%32,7) | 189 (%44,5) |
| `debian/tmux` | 1 916 | 74 (%3,9) | 132 (%6,9) | 61 (%3,2) | 103 (%5,4) | 130 (%6,8) | 5 (%0,3) | 181 (%9,4) | 264 (%13,8) | 544 (%28,4) | 800 (%41,8) | 1 169 (%61,0) |
| `debian/tree` | 115 | 7 (%6,1) | 8 (%7,0) | 1 (%0,9) | 5 (%4,3) | 5 (%4,3) | 0 (%0,0) | 12 (%10,4) | 13 (%11,3) | 13 (%11,3) | 25 (%21,7) | 25 (%21,7) |
| `debian/zstd` | 1 908 | 129 (%6,8) | 201 (%10,5) | 64 (%3,4) | 67 (%3,5) | 106 (%5,6) | 1 (%0,1) | 194 (%10,2) | 304 (%15,9) | 447 (%23,4) | 563 (%29,5) | 796 (%41,7) |
| `mac/htop` | 597 | 26 (%4,4) | 37 (%6,2) | 41 (%6,9) | 91 (%15,2) | 106 (%17,8) | 0 (%0,0) | 117 (%19,6) | 140 (%23,5) | 231 (%38,7) | 258 (%43,2) | 419 (%70,2) |
| `mac/tmux` | 2 587 | 104 (%4,0) | 188 (%7,3) | 87 (%3,4) | 112 (%4,3) | 174 (%6,7) | 8 (%0,3) | 222 (%8,6) | 365 (%14,1) | 762 (%29,5) | 1 083 (%41,9) | 1 638 (%63,3) |
| **Mac ikilisi** | 3 184 | 130 (%4,1) | 225 (%7,1) | 128 (%4,0) | 203 (%6,4) | 280 (%8,8) | 8 (%0,3) | 339 (%10,6) | 505 (%15,9) | 993 (%31,2) | 1 341 (%42,1) | 2 057 (%64,6) |
| **havuz** | 23 963 | 1 260 (%5,3) | 1 657 (%6,9) | 515 (%2,1) | 773 (%3,2) | 1 381 (%5,8) | 27 (%0,1) | 2 053 (%8,6) | 3 043 (%12,7) | 5 199 (%21,7) | 5 724 (%23,9) | 8 654 (%36,1) |
| **program makrosu** | — | %7,8 | %10,0 | %2,3 | %3,6 | %6,6 | %0,1 | %11,5 | %16,5 | %25,5 | %30,8 | %44,4 |

#### Fiil durumu (tekil GT adı)

| Birim | Nüfus | Tek sınıf | Çok sınıf | Yalnız genel | Fiilsiz | Parça | GT'de yok | C++ (okunmadı) |
|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 1 205 | 463 (%38,4) | 62 (%5,1) | 21 (%1,7) | 659 (%54,7) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/htop` | 238 | 162 (%68,1) | 18 (%7,6) | 17 (%7,1) | 41 (%17,2) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/openssl` | 582 | 275 (%47,3) | 30 (%5,2) | 53 (%9,1) | 224 (%38,5) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/redis-tools` | 1 045 | 484 (%46,3) | 50 (%4,8) | 23 (%2,2) | 488 (%46,7) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/sqlite3` | 421 | 209 (%49,6) | 15 (%3,6) | 10 (%2,4) | 187 (%44,4) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/tmux` | 1 905 | 1 186 (%62,3) | 232 (%12,2) | 38 (%2,0) | 449 (%23,6) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/tree` | 113 | 31 (%27,4) | 0 (%0,0) | 1 (%0,9) | 81 (%71,7) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/zstd` | 1 048 | 732 (%69,8) | 114 (%10,9) | 1 (%0,1) | 201 (%19,2) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `mac/htop` | 597 | 423 (%70,9) | 44 (%7,4) | 22 (%3,7) | 108 (%18,1) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `mac/tmux` | 2 544 | 1 607 (%63,2) | 326 (%12,8) | 58 (%2,3) | 553 (%21,7) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| **Mac ikilisi** | 3 141 | 2 030 (%64,6) | 370 (%11,8) | 80 (%2,5) | 661 (%21,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| **havuz** | 9 698 | 5 572 (%57,5) | 891 (%9,2) | 244 (%2,5) | 2 991 (%30,8) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| **program makrosu** | — | %51,4 | %6,2 | %3,0 | %39,4 | %0,0 | %0,0 | %0,0 |

#### Aile tavanı (tekil GT adı; başvuru = tek sınıflı ad)

| Birim | Nüfus | F-API fk2 | F-API geniş | F-ETKİ doğrudan | F-ETKİ sarmalayıcı dahil | F-ETKİ çağrı yapan | F-ROL | Birleşik: ilk sürüm, dar | Birleşik: ilk sürüm, geniş | Birleşik: adaylar dahil, geniş | Erişimsiz: 18 sınıf | Erişimsiz: 23 sınıf |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 1 205 | 87 (%7,2) | 129 (%10,7) | 19 (%1,6) | 32 (%2,7) | 56 (%4,6) | 6 (%0,5) | 125 (%10,4) | 191 (%15,9) | 266 (%22,1) | 294 (%24,4) | 394 (%32,7) |
| `debian/htop` | 238 | 8 (%3,4) | 19 (%8,0) | 14 (%5,9) | 16 (%6,7) | 22 (%9,2) | 0 (%0,0) | 24 (%10,1) | 41 (%17,2) | 59 (%24,8) | 98 (%41,2) | 151 (%63,4) |
| `debian/openssl` | 582 | 96 (%16,5) | 106 (%18,2) | 0 (%0,0) | 0 (%0,0) | 25 (%4,3) | 1 (%0,2) | 97 (%16,7) | 132 (%22,7) | 194 (%33,3) | 169 (%29,0) | 258 (%44,3) |
| `debian/redis-tools` | 1 045 | 36 (%3,4) | 63 (%6,0) | 12 (%1,1) | 16 (%1,5) | 61 (%5,8) | 3 (%0,3) | 55 (%5,3) | 127 (%12,2) | 181 (%17,3) | 249 (%23,8) | 409 (%39,1) |
| `debian/sqlite3` | 421 | 57 (%13,5) | 64 (%15,2) | 1 (%0,2) | 1 (%0,2) | 17 (%4,0) | 0 (%0,0) | 58 (%13,8) | 81 (%19,2) | 124 (%29,5) | 123 (%29,2) | 173 (%41,1) |
| `debian/tmux` | 1 905 | 63 (%3,3) | 100 (%5,2) | 51 (%2,7) | 82 (%4,3) | 101 (%5,3) | 5 (%0,3) | 150 (%7,9) | 206 (%10,8) | 404 (%21,2) | 601 (%31,5) | 937 (%49,2) |
| `debian/tree` | 113 | 7 (%6,2) | 8 (%7,1) | 1 (%0,9) | 5 (%4,4) | 5 (%4,4) | 0 (%0,0) | 12 (%10,6) | 13 (%11,5) | 13 (%11,5) | 25 (%22,1) | 25 (%22,1) |
| `debian/zstd` | 1 048 | 101 (%9,6) | 150 (%14,3) | 60 (%5,7) | 63 (%6,0) | 97 (%9,3) | 1 (%0,1) | 165 (%15,7) | 248 (%23,7) | 368 (%35,1) | 449 (%42,8) | 672 (%64,1) |
| `mac/htop` | 597 | 22 (%3,7) | 31 (%5,2) | 38 (%6,4) | 83 (%13,9) | 92 (%15,4) | 0 (%0,0) | 105 (%17,6) | 123 (%20,6) | 200 (%33,5) | 223 (%37,4) | 375 (%62,8) |
| `mac/tmux` | 2 544 | 77 (%3,0) | 138 (%5,4) | 75 (%2,9) | 95 (%3,7) | 141 (%5,5) | 3 (%0,1) | 175 (%6,9) | 282 (%11,1) | 562 (%22,1) | 805 (%31,6) | 1 302 (%51,2) |
| **Mac ikilisi** | 3 141 | 99 (%3,2) | 169 (%5,4) | 113 (%3,6) | 178 (%5,7) | 233 (%7,4) | 3 (%0,1) | 280 (%8,9) | 405 (%12,9) | 762 (%24,3) | 1 028 (%32,7) | 1 677 (%53,4) |
| **havuz** | 9 698 | 554 (%5,7) | 808 (%8,3) | 271 (%2,8) | 393 (%4,1) | 617 (%6,4) | 19 (%0,2) | 966 (%10,0) | 1 444 (%14,9) | 2 371 (%24,4) | 3 036 (%31,3) | 4 696 (%48,4) |
| **program makrosu** | — | %7,9 | %10,4 | %2,3 | %3,6 | %6,3 | %0,2 | %11,7 | %16,9 | %24,9 | %30,3 | %44,6 |

#### Aile tavanı (tekil GT adı; duyarlılık: çok sınıflı adlar da)

| Birim | Nüfus | F-API fk2 | F-API geniş | F-ETKİ doğrudan | F-ETKİ sarmalayıcı dahil | F-ETKİ çağrı yapan | F-ROL | Birleşik: ilk sürüm, dar | Birleşik: ilk sürüm, geniş | Birleşik: adaylar dahil, geniş | Erişimsiz: 18 sınıf | Erişimsiz: 23 sınıf |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 1 205 | 97 (%8,0) | 143 (%11,9) | 26 (%2,2) | 41 (%3,4) | 70 (%5,8) | 6 (%0,5) | 144 (%12,0) | 217 (%18,0) | 313 (%26,0) | 339 (%28,1) | 451 (%37,4) |
| `debian/htop` | 238 | 8 (%3,4) | 20 (%8,4) | 15 (%6,3) | 17 (%7,1) | 24 (%10,1) | 0 (%0,0) | 25 (%10,5) | 44 (%18,5) | 70 (%29,4) | 112 (%47,1) | 169 (%71,0) |
| `debian/openssl` | 582 | 103 (%17,7) | 113 (%19,4) | 0 (%0,0) | 0 (%0,0) | 33 (%5,7) | 1 (%0,2) | 104 (%17,9) | 145 (%24,9) | 223 (%38,3) | 195 (%33,5) | 288 (%49,5) |
| `debian/redis-tools` | 1 045 | 43 (%4,1) | 70 (%6,7) | 13 (%1,2) | 17 (%1,6) | 66 (%6,3) | 3 (%0,3) | 63 (%6,0) | 139 (%13,3) | 195 (%18,7) | 291 (%27,8) | 456 (%43,6) |
| `debian/sqlite3` | 421 | 66 (%15,7) | 73 (%17,3) | 2 (%0,5) | 2 (%0,5) | 21 (%5,0) | 0 (%0,0) | 67 (%15,9) | 91 (%21,6) | 135 (%32,1) | 136 (%32,3) | 186 (%44,2) |
| `debian/tmux` | 1 905 | 74 (%3,9) | 132 (%6,9) | 61 (%3,2) | 103 (%5,4) | 127 (%6,7) | 5 (%0,3) | 181 (%9,5) | 261 (%13,7) | 541 (%28,4) | 795 (%41,7) | 1 164 (%61,1) |
| `debian/tree` | 113 | 7 (%6,2) | 8 (%7,1) | 1 (%0,9) | 5 (%4,4) | 5 (%4,4) | 0 (%0,0) | 12 (%10,6) | 13 (%11,5) | 13 (%11,5) | 25 (%22,1) | 25 (%22,1) |
| `debian/zstd` | 1 048 | 129 (%12,3) | 201 (%19,2) | 64 (%6,1) | 67 (%6,4) | 103 (%9,8) | 1 (%0,1) | 194 (%18,5) | 301 (%28,7) | 443 (%42,3) | 556 (%53,1) | 786 (%75,0) |
| `mac/htop` | 597 | 26 (%4,4) | 37 (%6,2) | 41 (%6,9) | 91 (%15,2) | 106 (%17,8) | 0 (%0,0) | 117 (%19,6) | 140 (%23,5) | 231 (%38,7) | 258 (%43,2) | 419 (%70,2) |
| `mac/tmux` | 2 544 | 104 (%4,1) | 188 (%7,4) | 87 (%3,4) | 112 (%4,4) | 170 (%6,7) | 8 (%0,3) | 222 (%8,7) | 361 (%14,2) | 748 (%29,4) | 1 078 (%42,4) | 1 623 (%63,8) |
| **Mac ikilisi** | 3 141 | 130 (%4,1) | 225 (%7,2) | 128 (%4,1) | 203 (%6,5) | 276 (%8,8) | 8 (%0,3) | 339 (%10,8) | 501 (%16,0) | 979 (%31,2) | 1 336 (%42,5) | 2 042 (%65,0) |
| **havuz** | 9 698 | 657 (%6,8) | 985 (%10,2) | 310 (%3,2) | 455 (%4,7) | 725 (%7,5) | 24 (%0,2) | 1 129 (%11,6) | 1 712 (%17,7) | 2 912 (%30,0) | 3 785 (%39,0) | 5 567 (%57,4) |
| **program makrosu** | — | %9,0 | %12,0 | %2,6 | %4,1 | %7,2 | %0,2 | %13,1 | %19,1 | %29,0 | %35,5 | %50,6 |

#### F-ETKİ ayrıntısı (örnek düzeyi; başvuru = tek sınıflı ad)

| Birim | GT `create` | … doğrudan | … sarmalayıcı dahil | … çağrı yapan | GT `destroy` | … doğrudan | … sarmalayıcı dahil | … çağrı yapan | Adaylar (6 fiil) |
|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 416 (%3,1) | 13 (%0,1) | 138 (%1,0) | 416 (%3,1) | 174 (%1,3) | 151 (%1,1) | 151 (%1,1) | 174 (%1,3) | 636 (%4,7) |
| `debian/htop` | 6 (%2,5) | 0 (%0,0) | 1 (%0,4) | 6 (%2,5) | 16 (%6,7) | 14 (%5,9) | 15 (%6,3) | 16 (%6,7) | 18 (%7,5) |
| `debian/openssl` | 16 (%2,7) | 0 (%0,0) | 0 (%0,0) | 16 (%2,7) | 9 (%1,5) | 0 (%0,0) | 0 (%0,0) | 9 (%1,5) | 63 (%10,7) |
| `debian/redis-tools` | 78 (%3,7) | 30 (%1,4) | 32 (%1,5) | 78 (%3,7) | 58 (%2,8) | 14 (%0,7) | 17 (%0,8) | 58 (%2,8) | 113 (%5,4) |
| `debian/sqlite3` | 11 (%2,6) | 0 (%0,0) | 0 (%0,0) | 11 (%2,6) | 8 (%1,9) | 1 (%0,2) | 1 (%0,2) | 7 (%1,6) | 43 (%10,1) |
| `debian/tmux` | 38 (%2,0) | 0 (%0,0) | 27 (%1,4) | 36 (%1,9) | 68 (%3,5) | 51 (%2,7) | 55 (%2,9) | 68 (%3,5) | 203 (%10,6) |
| `debian/tree` | 4 (%3,5) | 0 (%0,0) | 4 (%3,5) | 4 (%3,5) | 1 (%0,9) | 1 (%0,9) | 1 (%0,9) | 1 (%0,9) | 0 (%0,0) |
| `debian/zstd` | 77 (%4,0) | 35 (%1,8) | 38 (%2,0) | 67 (%3,5) | 36 (%1,9) | 25 (%1,3) | 25 (%1,3) | 33 (%1,7) | 122 (%6,4) |
| `mac/htop` | 50 (%8,4) | 0 (%0,0) | 40 (%6,7) | 48 (%8,0) | 45 (%7,5) | 38 (%6,4) | 43 (%7,2) | 44 (%7,4) | 77 (%12,9) |
| `mac/tmux` | 50 (%1,9) | 3 (%0,1) | 18 (%0,7) | 48 (%1,9) | 97 (%3,7) | 72 (%2,8) | 77 (%3,0) | 97 (%3,7) | 283 (%10,9) |
| **Mac ikilisi** | 100 (%3,1) | 3 (%0,1) | 58 (%1,8) | 96 (%3,0) | 142 (%4,5) | 110 (%3,5) | 120 (%3,8) | 141 (%4,4) | 360 (%11,3) |
| **havuz** | 746 (%3,1) | 81 (%0,3) | 298 (%1,2) | 730 (%3,0) | 512 (%2,1) | 367 (%1,5) | 385 (%1,6) | 507 (%2,1) | 1 558 (%6,5) |

#### Erişim: ön koşulu sağlayan fonksiyonlar (GT'siz; örnek düzeyi)

| Birim | Nüfus | F-API fk2 | F-API geniş | Ayırıcı: doğrudan | Ayırıcı: sarmalayıcı dahil | Bırakıcı: doğrudan | Bırakıcı: sarmalayıcı dahil | Çağrı yapan | F-ROL (adresi kayıt yerinde kurulan) |
|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 13 485 | 3 354 (%24,9) | 3 760 (%27,9) | 1 910 (%14,2) | 3 004 (%22,3) | 817 (%6,1) | 835 (%6,2) | 11 285 (%83,7) | 35 (%0,3) |
| `debian/htop` | 239 | 32 (%13,4) | 62 (%25,9) | 0 (%0,0) | 20 (%8,4) | 37 (%15,5) | 47 (%19,7) | 210 (%87,9) | 2 (%0,8) |
| `debian/openssl` | 588 | 407 (%69,2) | 488 (%83,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) | 535 (%91,0) | 49 (%8,3) |
| `debian/redis-tools` | 2 103 | 301 (%14,3) | 448 (%21,3) | 53 (%2,5) | 59 (%2,8) | 40 (%1,9) | 99 (%4,7) | 1 842 (%87,6) | 22 (%1,0) |
| `debian/sqlite3` | 425 | 241 (%56,7) | 268 (%63,1) | 8 (%1,9) | 8 (%1,9) | 9 (%2,1) | 9 (%2,1) | 327 (%76,9) | 5 (%1,2) |
| `debian/tmux` | 1 916 | 177 (%9,2) | 318 (%16,6) | 15 (%0,8) | 386 (%20,1) | 393 (%20,5) | 408 (%21,3) | 1 616 (%84,3) | 57 (%3,0) |
| `debian/tree` | 115 | 32 (%27,8) | 42 (%36,5) | 8 (%7,0) | 22 (%19,1) | 15 (%13,0) | 16 (%13,9) | 98 (%85,2) | 0 (%0,0) |
| `debian/zstd` | 1 908 | 369 (%19,3) | 498 (%26,1) | 129 (%6,8) | 140 (%7,3) | 108 (%5,7) | 139 (%7,3) | 1 424 (%74,6) | 3 (%0,2) |
| `mac/htop` | 597 | 82 (%13,7) | 114 (%19,1) | 14 (%2,3) | 100 (%16,8) | 84 (%14,1) | 115 (%19,3) | 495 (%82,9) | 2 (%0,3) |
| `mac/tmux` | 2 587 | 229 (%8,9) | 405 (%15,7) | 21 (%0,8) | 351 (%13,6) | 493 (%19,1) | 534 (%20,6) | 2 171 (%83,9) | 67 (%2,6) |
| **Mac ikilisi** | 3 184 | 311 (%9,8) | 519 (%16,3) | 35 (%1,1) | 451 (%14,2) | 577 (%18,1) | 649 (%20,4) | 2 666 (%83,7) | 69 (%2,2) |
| **havuz** | 23 963 | 5 224 (%21,8) | 6 403 (%26,7) | 2 158 (%9,0) | 4 090 (%17,1) | 1 996 (%8,3) | 2 202 (%9,2) | 20 003 (%83,5) | 242 (%1,0) |

#### F-ROL ayrıntısı (örnek düzeyi)

| Birim | Erişilen | … rolü `compare` | … rolü `fini` | … rolü genel | … rolü fiilsiz | Erişilenlerde GT tek sınıf | … GT yalnız genel | … GT fiilsiz | İsabet | Erişimsiz: GT `compare` ya da `fini` |
|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 35 | 9 | 0 | 29 | 1 | 18 | 3 | 13 | 7 | 112 |
| `debian/htop` | 2 | 1 | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 6 |
| `debian/openssl` | 49 | 7 | 0 | 42 | 0 | 14 | 0 | 35 | 1 | 27 |
| `debian/redis-tools` | 22 | 11 | 0 | 10 | 1 | 16 | 5 | 1 | 5 | 30 |
| `debian/sqlite3` | 5 | 0 | 0 | 5 | 0 | 2 | 1 | 2 | 0 | 10 |
| `debian/tmux` | 57 | 7 | 0 | 50 | 0 | 33 | 16 | 8 | 5 | 14 |
| `debian/tree` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/zstd` | 3 | 2 | 0 | 0 | 1 | 1 | 0 | 1 | 1 | 10 |
| `mac/htop` | 2 | 0 | 0 | 2 | 0 | 0 | 2 | 0 | 0 | 19 |
| `mac/tmux` | 67 | 9 | 0 | 58 | 0 | 36 | 16 | 10 | 3 | 16 |
| **Mac ikilisi** | 69 | 9 | 0 | 60 | 0 | 36 | 18 | 10 | 3 | 35 |
| **havuz** | 242 | 46 | 0 | 197 | 3 | 121 | 44 | 70 | 22 | 244 |

#### K / I / Y × fiil durumu (örnek düzeyi; payda sınıfın nüfusu)

| Birim | Sınıf | Nüfus | Tek sınıf | Çok sınıf | Yalnız genel | Fiilsiz | Parça | GT'de yok | C++ |
|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | K | 8 092 | 1 877 (%23,2) | 243 (%3,0) | 31 (%0,4) | 5 941 (%73,4) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/coreutils` | I | 3 193 | 286 (%9,0) | 37 (%1,2) | 2 (%0,1) | 2 868 (%89,8) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/coreutils` | Y | 2 200 | 840 (%38,2) | 391 (%17,8) | 16 (%0,7) | 847 (%38,5) | 0 (%0,0) | 106 (%4,8) | 0 (%0,0) |
| `debian/htop` | K | 103 | 69 (%67,0) | 3 (%2,9) | 12 (%11,7) | 19 (%18,4) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/htop` | I | 107 | 77 (%72,0) | 12 (%11,2) | 5 (%4,7) | 13 (%12,1) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/htop` | Y | 29 | 16 (%55,2) | 3 (%10,3) | 0 (%0,0) | 9 (%31,0) | 0 (%0,0) | 1 (%3,4) | 0 (%0,0) |
| `debian/openssl` | K | 505 | 244 (%48,3) | 27 (%5,3) | 53 (%10,5) | 181 (%35,8) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/openssl` | I | 30 | 10 (%33,3) | 1 (%3,3) | 1 (%3,3) | 18 (%60,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/openssl` | Y | 53 | 21 (%39,6) | 2 (%3,8) | 2 (%3,8) | 27 (%50,9) | 0 (%0,0) | 1 (%1,9) | 0 (%0,0) |
| `debian/redis-tools` | K | 727 | 460 (%63,3) | 23 (%3,2) | 31 (%4,3) | 211 (%29,0) | 0 (%0,0) | 2 (%0,3) | 0 (%0,0) |
| `debian/redis-tools` | I | 1 115 | 394 (%35,3) | 68 (%6,1) | 14 (%1,3) | 635 (%57,0) | 0 (%0,0) | 4 (%0,4) | 0 (%0,0) |
| `debian/redis-tools` | Y | 261 | 107 (%41,0) | 8 (%3,1) | 6 (%2,3) | 132 (%50,6) | 0 (%0,0) | 8 (%3,1) | 0 (%0,0) |
| `debian/sqlite3` | K | 297 | 161 (%54,2) | 13 (%4,4) | 5 (%1,7) | 118 (%39,7) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/sqlite3` | I | 30 | 19 (%63,3) | 0 (%0,0) | 5 (%16,7) | 6 (%20,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/sqlite3` | Y | 98 | 32 (%32,7) | 2 (%2,0) | 0 (%0,0) | 63 (%64,3) | 0 (%0,0) | 1 (%1,0) | 0 (%0,0) |
| `debian/tmux` | K | 766 | 486 (%63,4) | 100 (%13,1) | 19 (%2,5) | 161 (%21,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/tmux` | I | 850 | 549 (%64,6) | 113 (%13,3) | 15 (%1,8) | 173 (%20,4) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/tmux` | Y | 300 | 158 (%52,7) | 19 (%6,3) | 4 (%1,3) | 118 (%39,3) | 0 (%0,0) | 1 (%0,3) | 0 (%0,0) |
| `debian/tree` | K | 93 | 25 (%26,9) | 0 (%0,0) | 1 (%1,1) | 67 (%72,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/tree` | I | 5 | 2 (%40,0) | 0 (%0,0) | 0 (%0,0) | 3 (%60,0) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `debian/tree` | Y | 17 | 4 (%23,5) | 0 (%0,0) | 0 (%0,0) | 12 (%70,6) | 0 (%0,0) | 1 (%5,9) | 0 (%0,0) |
| `debian/zstd` | K | 934 | 485 (%51,9) | 75 (%8,0) | 1 (%0,1) | 142 (%15,2) | 0 (%0,0) | 0 (%0,0) | 231 (%24,7) |
| `debian/zstd` | I | 490 | 141 (%28,8) | 19 (%3,9) | 0 (%0,0) | 22 (%4,5) | 0 (%0,0) | 0 (%0,0) | 308 (%62,9) |
| `debian/zstd` | Y | 484 | 122 (%25,2) | 21 (%4,3) | 0 (%0,0) | 47 (%9,7) | 0 (%0,0) | 1 (%0,2) | 293 (%60,5) |
| `mac/htop` | K | 230 | 154 (%67,0) | 13 (%5,7) | 14 (%6,1) | 49 (%21,3) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `mac/htop` | I | 265 | 198 (%74,7) | 24 (%9,1) | 7 (%2,6) | 36 (%13,6) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `mac/htop` | Y | 102 | 71 (%69,6) | 7 (%6,9) | 1 (%1,0) | 23 (%22,5) | 0 (%0,0) | 0 (%0,0) | 0 (%0,0) |
| `mac/tmux` | K | 951 | 621 (%65,3) | 145 (%15,2) | 18 (%1,9) | 158 (%16,6) | 0 (%0,0) | 9 (%0,9) | 0 (%0,0) |
| `mac/tmux` | I | 1 220 | 772 (%63,3) | 155 (%12,7) | 35 (%2,9) | 240 (%19,7) | 0 (%0,0) | 18 (%1,5) | 0 (%0,0) |
| `mac/tmux` | Y | 416 | 219 (%52,6) | 36 (%8,7) | 5 (%1,2) | 155 (%37,3) | 1 (%0,2) | 0 (%0,0) | 0 (%0,0) |
| **Mac ikilisi** | K | 1 181 | 775 (%65,6) | 158 (%13,4) | 32 (%2,7) | 207 (%17,5) | 0 (%0,0) | 9 (%0,8) | 0 (%0,0) |
| **Mac ikilisi** | I | 1 485 | 970 (%65,3) | 179 (%12,1) | 42 (%2,8) | 276 (%18,6) | 0 (%0,0) | 18 (%1,2) | 0 (%0,0) |
| **Mac ikilisi** | Y | 518 | 290 (%56,0) | 43 (%8,3) | 6 (%1,2) | 178 (%34,4) | 1 (%0,2) | 0 (%0,0) | 0 (%0,0) |
| **havuz** | K | 12 698 | 4 582 (%36,1) | 642 (%5,1) | 185 (%1,5) | 7 047 (%55,5) | 0 (%0,0) | 11 (%0,1) | 231 (%1,8) |
| **havuz** | I | 7 305 | 2 448 (%33,5) | 429 (%5,9) | 84 (%1,1) | 4 014 (%54,9) | 0 (%0,0) | 22 (%0,3) | 308 (%4,2) |
| **havuz** | Y | 3 960 | 1 590 (%40,2) | 489 (%12,3) | 34 (%0,9) | 1 433 (%36,2) | 1 (%0,0) | 120 (%3,0) | 293 (%7,4) |

#### Sözlük sınıfı başına pay (tek sınıflı adlar; sayı ve nüfusa oranı)

| Sınıf | Aile | `mac/tmux` | `mac/htop` | havuz (örnek) | havuz (tekil) | makro (örnek) | makro (tekil) |
|---|---|---|---|---|---|---|---|
| `get` | F-ETKİ aday | 141 (%5,5) | 29 (%4,9) | 583 (%2,4) | 425 (%4,4) | %2,9 | %3,4 |
| `set` | F-ETKİ aday | 149 (%5,8) | 85 (%14,2) | 1 178 (%4,9) | 554 (%5,7) | %4,9 | %5,0 |
| `is` | F-ETKİ aday | 59 (%2,3) | 9 (%1,5) | 327 (%1,4) | 231 (%2,4) | %1,8 | %2,2 |
| `create` | F-ETKİ ilk | 50 (%1,9) | 50 (%8,4) | 746 (%3,1) | 316 (%3,3) | %3,4 | %3,7 |
| `destroy` | F-ETKİ ilk | 97 (%3,7) | 45 (%7,5) | 512 (%2,1) | 322 (%3,3) | %2,6 | %2,8 |
| `init` | F-ETKİ aday | 20 (%0,8) | 22 (%3,7) | 235 (%1,0) | 185 (%1,9) | %2,2 | %2,6 |
| `fini` | F-ROL | 0 (%0,0) | 6 (%1,0) | 54 (%0,2) | 34 (%0,4) | %0,5 | %0,5 |
| `reset` | — | 50 (%1,9) | 6 (%1,0) | 266 (%1,1) | 138 (%1,4) | %0,8 | %0,9 |
| `add` | — | 112 (%4,3) | 24 (%4,0) | 474 (%2,0) | 322 (%3,3) | %2,5 | %2,7 |
| `remove` | — | 53 (%2,0) | 5 (%0,8) | 129 (%0,5) | 113 (%1,2) | %0,6 | %0,7 |
| `find` | F-API | 76 (%2,9) | 7 (%1,2) | 268 (%1,1) | 246 (%2,5) | %1,4 | %1,9 |
| `compare` | F-ETKİ aday / F-ROL | 16 (%0,6) | 13 (%2,2) | 190 (%0,8) | 118 (%1,2) | %1,2 | %1,4 |
| `copy` | F-ETKİ aday | 128 (%4,9) | 7 (%1,2) | 290 (%1,2) | 265 (%2,7) | %0,9 | %1,1 |
| `open` | F-API | 7 (%0,3) | 0 (%0,0) | 134 (%0,6) | 65 (%0,7) | %1,1 | %1,1 |
| `close` | F-API | 7 (%0,3) | 0 (%0,0) | 286 (%1,2) | 53 (%0,5) | %1,5 | %1,4 |
| `read` | F-API | 74 (%2,9) | 8 (%1,3) | 354 (%1,5) | 280 (%2,9) | %2,7 | %3,1 |
| `write` | F-API | 84 (%3,2) | 13 (%2,2) | 453 (%1,9) | 269 (%2,8) | %2,2 | %2,3 |
| `print` | F-API | 309 (%11,9) | 54 (%9,0) | 947 (%4,0) | 801 (%8,3) | %5,6 | %6,2 |
| `parse` | F-API | 28 (%1,1) | 7 (%1,2) | 317 (%1,3) | 242 (%2,5) | %1,7 | %2,6 |
| `encode` | F-API | 2 (%0,1) | 0 (%0,0) | 116 (%0,5) | 103 (%1,1) | %1,0 | %1,5 |
| `lock` | F-API | 4 (%0,2) | 0 (%0,0) | 14 (%0,1) | 13 (%0,1) | %0,2 | %0,2 |
| `unlock` | F-API | 0 (%0,0) | 0 (%0,0) | 3 (%0,0) | 3 (%0,0) | %0,1 | %0,1 |
| `start` | F-API | 21 (%0,8) | 6 (%1,0) | 77 (%0,3) | 58 (%0,6) | %0,3 | %0,4 |
| `stop` | F-API | 23 (%0,9) | 6 (%1,0) | 65 (%0,3) | 62 (%0,6) | %0,4 | %0,4 |
| `run` | — | 42 (%1,6) | 4 (%0,7) | 107 (%0,4) | 103 (%1,1) | %0,6 | %0,6 |
| `compute` | — | 9 (%0,3) | 3 (%0,5) | 288 (%1,2) | 102 (%1,1) | %1,0 | %1,2 |
| `sort` | F-API | 8 (%0,3) | 8 (%1,3) | 52 (%0,2) | 35 (%0,4) | %0,4 | %0,4 |
| `wait` | F-API | 4 (%0,2) | 0 (%0,0) | 21 (%0,1) | 16 (%0,2) | %0,2 | %0,2 |
| `resize` | — | 39 (%1,5) | 6 (%1,0) | 134 (%0,6) | 98 (%1,0) | %0,6 | %0,6 |

#### Sözlük dışı fiil: kapalı ölçme listesiyle (örnek düzeyi)

| Birim | Nüfus | Fiilsiz + yalnız genel | `acik` taşıyan | `acik` ya da `belirsiz` taşıyan | Farklı `acik` belirteç | Farklı belirteç (iki kesim) | En sık 10 (`acik`): fonksiyon sayıları |
|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 13 485 | 9 705 (%72,0) | 696 (%5,2) | 1 001 (%7,4) | 30 | 43 | 534, 29, 22, 21, 16, 13, 7, 7, 6, 6 |
| `debian/htop` | 239 | 58 (%24,3) | 14 (%5,9) | 20 (%8,4) | 6 | 13 | 7, 4, 1, 1, 1, 1 |
| `debian/openssl` | 588 | 282 (%48,0) | 33 (%5,6) | 63 (%10,7) | 12 | 19 | 17, 3, 2, 2, 2, 1, 1, 1, 1, 1 |
| `debian/redis-tools` | 2 103 | 1 029 (%48,9) | 76 (%3,6) | 148 (%7,0) | 27 | 40 | 8, 6, 4, 4, 4, 4, 4, 4, 4, 3 |
| `debian/sqlite3` | 425 | 197 (%46,4) | 21 (%4,9) | 38 (%8,9) | 13 | 23 | 7, 2, 2, 2, 1, 1, 1, 1, 1, 1 |
| `debian/tmux` | 1 916 | 490 (%25,6) | 98 (%5,1) | 131 (%6,8) | 36 | 52 | 23, 18, 6, 4, 3, 3, 3, 3, 3, 3 |
| `debian/tree` | 115 | 83 (%72,2) | 4 (%3,5) | 5 (%4,3) | 2 | 3 | 3, 1 |
| `debian/zstd` | 1 908 | 212 (%11,1) | 61 (%3,2) | 78 (%4,1) | 23 | 32 | 17, 6, 4, 3, 3, 3, 3, 2, 2, 2 |
| `mac/htop` | 597 | 130 (%21,8) | 30 (%5,0) | 39 (%6,5) | 14 | 22 | 9, 3, 3, 3, 2, 2, 2, 1, 1, 1 |
| `mac/tmux` | 2 587 | 611 (%23,6) | 96 (%3,7) | 157 (%6,1) | 40 | 58 | 24, 6, 4, 4, 4, 4, 4, 4, 3, 3 |
| **Mac ikilisi** | 3 184 | 741 (%23,3) | 126 (%4,0) | 196 (%6,2) | 45 | 66 | 25, 9, 7, 6, 5, 4, 4, 4, 4, 4 |
| **havuz** | 23 963 | 12 797 (%53,4) | 1 129 (%4,7) | 1 680 (%7,0) | 93 | 132 | 536, 44, 40, 29, 27, 24, 23, 18, 17, 17 |

#### Ad biçimi (örnek düzeyi; payda tek sınıflı adlar) ve modül öneki vekili (payda GT adı olanlar)

| Birim | Tek sınıflı ad | `yalniz_fiil` | `fiil_nesne` | `nesne_fiil` | `onek_fiil_nesne` | GT adı olan | Önekli (vekil) | Tek sınıflılarda önekli |
|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 3 003 | 14 (%0,5) | 2 031 (%67,6) | 678 (%22,6) | 280 (%9,3) | 13 379 | 4 623 (%34,6) | 673 (%22,4) |
| `debian/htop` | 162 | 1 (%0,6) | 9 (%5,6) | 67 (%41,4) | 85 (%52,5) | 238 | 114 (%47,9) | 74 (%45,7) |
| `debian/openssl` | 275 | 1 (%0,4) | 146 (%53,1) | 66 (%24,0) | 62 (%22,5) | 587 | 189 (%32,2) | 62 (%22,5) |
| `debian/redis-tools` | 961 | 10 (%1,0) | 287 (%29,9) | 344 (%35,8) | 320 (%33,3) | 2 089 | 1 226 (%58,7) | 527 (%54,8) |
| `debian/sqlite3` | 212 | 0 (%0,0) | 33 (%15,6) | 115 (%54,2) | 64 (%30,2) | 424 | 305 (%71,9) | 157 (%74,1) |
| `debian/tmux` | 1 193 | 0 (%0,0) | 235 (%19,7) | 350 (%29,3) | 608 (%51,0) | 1 915 | 1 567 (%81,8) | 953 (%79,9) |
| `debian/tree` | 31 | 1 (%3,2) | 18 (%58,1) | 12 (%38,7) | 0 (%0,0) | 114 | 37 (%32,5) | 10 (%32,3) |
| `debian/zstd` | 748 | 0 (%0,0) | 12 (%1,6) | 77 (%10,3) | 659 (%88,1) | 1 075 | 1 021 (%95,0) | 723 (%96,7) |
| `mac/htop` | 423 | 1 (%0,2) | 17 (%4,0) | 193 (%45,6) | 212 (%50,1) | 597 | 471 (%78,9) | 330 (%78,0) |
| `mac/tmux` | 1 612 | 0 (%0,0) | 317 (%19,7) | 450 (%27,9) | 845 (%52,4) | 2 559 | 2 078 (%81,2) | 1 285 (%79,7) |
| **Mac ikilisi** | 2 035 | 1 (%0,0) | 334 (%16,4) | 643 (%31,6) | 1 057 (%51,9) | 3 156 | 2 549 (%80,8) | 1 615 (%79,4) |
| **havuz** | 8 620 | 28 (%0,3) | 3 105 (%36,0) | 2 352 (%27,3) | 3 135 (%36,4) | 22 977 | 11 631 (%50,6) | 4 794 (%55,6) |

#### Sözlük dışı fiil: kapalı ölçme listesiyle (tekil GT adı)

| Birim | Nüfus | Fiilsiz + yalnız genel | `acik` taşıyan | `acik` ya da `belirsiz` taşıyan | Farklı `acik` belirteç | Farklı belirteç (iki kesim) | En sık 10 (`acik`): fonksiyon sayıları |
|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 1 205 | 680 (%56,4) | 57 (%4,7) | 90 (%7,5) | 30 | 43 | 8, 7, 6, 5, 2, 2, 2, 2, 2, 2 |
| `debian/htop` | 238 | 58 (%24,4) | 14 (%5,9) | 20 (%8,4) | 6 | 13 | 7, 4, 1, 1, 1, 1 |
| `debian/openssl` | 582 | 277 (%47,6) | 31 (%5,3) | 61 (%10,5) | 12 | 19 | 15, 3, 2, 2, 2, 1, 1, 1, 1, 1 |
| `debian/redis-tools` | 1 045 | 511 (%48,9) | 40 (%3,8) | 77 (%7,4) | 27 | 40 | 3, 3, 2, 2, 2, 2, 2, 2, 2, 2 |
| `debian/sqlite3` | 421 | 197 (%46,8) | 21 (%5,0) | 38 (%9,0) | 13 | 23 | 7, 2, 2, 2, 1, 1, 1, 1, 1, 1 |
| `debian/tmux` | 1 905 | 487 (%25,6) | 97 (%5,1) | 130 (%6,8) | 36 | 52 | 23, 18, 6, 4, 3, 3, 3, 3, 3, 3 |
| `debian/tree` | 113 | 82 (%72,6) | 4 (%3,5) | 5 (%4,4) | 2 | 3 | 3, 1 |
| `debian/zstd` | 1 048 | 202 (%19,3) | 60 (%5,7) | 77 (%7,3) | 23 | 32 | 17, 6, 4, 3, 3, 3, 3, 2, 2, 2 |
| `mac/htop` | 597 | 130 (%21,8) | 30 (%5,0) | 39 (%6,5) | 14 | 22 | 9, 3, 3, 3, 2, 2, 2, 1, 1, 1 |
| `mac/tmux` | 2 544 | 611 (%24,0) | 96 (%3,8) | 157 (%6,2) | 40 | 58 | 24, 6, 4, 4, 4, 4, 4, 4, 3, 3 |
| **Mac ikilisi** | 3 141 | 741 (%23,6) | 126 (%4,0) | 196 (%6,2) | 45 | 66 | 25, 9, 7, 6, 5, 4, 4, 4, 4, 4 |
| **havuz** | 9 698 | 3 235 (%33,4) | 450 (%4,6) | 694 (%7,2) | 93 | 132 | 44, 25, 19, 17, 17, 17, 17, 15, 12, 12 |

#### Ad biçimi (tekil GT adı; payda tek sınıflı adlar) ve modül öneki vekili (payda GT adı olanlar)

| Birim | Tek sınıflı ad | `yalniz_fiil` | `fiil_nesne` | `nesne_fiil` | `onek_fiil_nesne` | GT adı olan | Önekli (vekil) | Tek sınıflılarda önekli |
|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 463 | 8 (%1,7) | 268 (%57,9) | 122 (%26,3) | 65 (%14,0) | 1 205 | 333 (%27,6) | 109 (%23,5) |
| `debian/htop` | 162 | 1 (%0,6) | 9 (%5,6) | 67 (%41,4) | 85 (%52,5) | 238 | 114 (%47,9) | 74 (%45,7) |
| `debian/openssl` | 275 | 1 (%0,4) | 146 (%53,1) | 66 (%24,0) | 62 (%22,5) | 582 | 186 (%32,0) | 62 (%22,5) |
| `debian/redis-tools` | 484 | 5 (%1,0) | 152 (%31,4) | 158 (%32,6) | 169 (%34,9) | 1 045 | 606 (%58,0) | 259 (%53,5) |
| `debian/sqlite3` | 209 | 0 (%0,0) | 33 (%15,8) | 112 (%53,6) | 64 (%30,6) | 421 | 302 (%71,7) | 154 (%73,7) |
| `debian/tmux` | 1 186 | 0 (%0,0) | 234 (%19,7) | 349 (%29,4) | 603 (%50,8) | 1 905 | 1 559 (%81,8) | 947 (%79,8) |
| `debian/tree` | 31 | 1 (%3,2) | 18 (%58,1) | 12 (%38,7) | 0 (%0,0) | 113 | 37 (%32,7) | 10 (%32,3) |
| `debian/zstd` | 732 | 0 (%0,0) | 12 (%1,6) | 73 (%10,0) | 647 (%88,4) | 1 048 | 994 (%94,8) | 707 (%96,6) |
| `mac/htop` | 423 | 1 (%0,2) | 17 (%4,0) | 193 (%45,6) | 212 (%50,1) | 597 | 471 (%78,9) | 330 (%78,0) |
| `mac/tmux` | 1 607 | 0 (%0,0) | 317 (%19,7) | 448 (%27,9) | 842 (%52,4) | 2 544 | 2 063 (%81,1) | 1 280 (%79,7) |
| **Mac ikilisi** | 2 030 | 1 (%0,0) | 334 (%16,5) | 641 (%31,6) | 1 054 (%51,9) | 3 141 | 2 534 (%80,7) | 1 610 (%79,3) |
| **havuz** | 5 572 | 17 (%0,3) | 1 206 (%21,6) | 1 600 (%28,7) | 2 749 (%49,3) | 9 698 | 6 665 (%68,7) | 3 932 (%70,6) |

#### Yan sayılar (örnek düzeyi)

| Birim | Nüfus | KS-1 nüfusunda | Birden çok takma adlı | Klon ekli: tek sınıf | Klon ekli: çok sınıf | Klon ekli: fiilsiz | Klon ekli: parça |
|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 13 485 | 12 716 (%94,3) | 29 | 62 | 2 | 176 | 0 |
| `debian/htop` | 239 | 222 (%92,9) | 0 | 7 | 0 | 5 | 0 |
| `debian/openssl` | 588 | 563 (%95,7) | 0 | 10 | 0 | 7 | 0 |
| `debian/redis-tools` | 2 103 | 1 454 (%69,1) | 6 | 368 | 58 | 182 | 0 |
| `debian/sqlite3` | 425 | 389 (%91,5) | 2 | 19 | 2 | 9 | 0 |
| `debian/tmux` | 1 916 | 1 851 (%96,6) | 0 | 44 | 8 | 9 | 0 |
| `debian/tree` | 115 | 110 (%95,7) | 0 | 0 | 0 | 1 | 0 |
| `debian/zstd` | 1 908 | 913 (%47,9) | 1 | 126 | 2 | 31 | 0 |
| `mac/htop` | 597 | 597 (%100,0) | 0 | 0 | 0 | 0 | 0 |
| `mac/tmux` | 2 587 | 2 544 (%98,3) | 8 | 5 | 10 | 0 | 1 |
| **Mac ikilisi** | 3 184 | 3 141 (%98,6) | 8 | 5 | 10 | 0 | 1 |
| **havuz** | 23 963 | 21 359 (%89,1) | 46 | 641 | 82 | 420 | 1 |
