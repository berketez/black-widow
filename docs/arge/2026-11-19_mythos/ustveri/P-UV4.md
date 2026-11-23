# P-ÜV4 — C++ RTTI sembolsüz tarama + `rtti_recovery` (ilerleme)

Paket metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV4.md`. Ortak brifler: `ORTAK_D1.md`, `ORTAK_D0.md`, `ONARIM_BRIF.md`.
Plan: `ustveri/PLAN.md` "P-ÜV4". Kararlar: A-10, A-13, A-14, A-27, A-32, A-34.

- Başlangıç: 2026-11-23 09:06. Taban commit `bcbc183` (main; `git merge --ff-only main`).
- `karadul.__file__` worktree yolunu gösteriyor (doğrulandı).
- Koşu dizini: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV4/` (ölçüm özetleri `ozet/`).
- Sert son 11:45.
- **Ön kayıt:** `on_kayit_PUV4.md`, commit `fab4abe` (koddan ve ölçümden önce).
- **Tarayıcı dondurma commit'i: `ce3ea34`** (tarayıcı kodunun son değiştiği commit `ee37ccb`; `ce3ea34` yalnız ölçüm betiğini
  ekledi). Sınama ikililerinin (llama-server, iTerm2) hiçbir çıktısına — GT'siz sayım dahil — bu commit'ten önce
  bakılmadı; H1'in o iki satırı da H2 ile birlikte dondurmadan sonra koşuldu.

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| Ön kayıt | yazıldı | `fab4abe` |
| Yerel örnekler + derleme / GT betiği | bitti (4 derleme × sembollü / soyulmuş) | `bbb72a5` |
| 1–3 tarayıcı (typeinfo, vtable, zayıf bağ, ad çözme, `rtti_classes`) | bitti | `bfbb25a`, `ee37ccb` |
| 4 devralınan yuva kuralı (en taban sınıf / `belirsiz`) | bitti | `bfbb25a` |
| 5 ELF yolu | bitti; pzstd'de H5 tuttu | `bfbb25a` |
| 6 sağlamlık + bulanık girdi | bitti; H4 tuttu | `bfbb25a`, `ee37ccb` |
| 7 üretici adım `rtti_recovery` | bitti | `bfbb25a` |
| Yamalar (`config.py`, `test_p15b`) | bırakıldı, `git apply --check` temiz | `2a81657` |
| Mutasyon | 16 / 16 öldü | `be20612` |
| Ölçüm betiği | `scripts/arge/ustveri/puv4_olc.py` | `ce3ea34` |
| Keşif ölçümü (H0, H1 keşif satırları, H3, H4, H5, H6) | bitti (aşağıda) | — |
| Dondurma + H1 sınama satırları + H2 (bir kez) | sırada | — |
| Tam takım (yamasız) | sırada | — |

## Tasarım (koddan)

- `karadul/analyzers/ustveri/cpp_rtti_tara.py`: `tara(goruntu, azami_yuva=…, sure_siniri=…) -> RttiSonuc`. İstisna atmaz.
  Durum sözlüğü ortak dördü (`goruntu.py`'den) + yerel `DURUM_KAPALI` (objc.py ile aynı ad; tek tanım P-ÜV6b).
- typeinfo: ilk sözcüğü `_ZTVN10__cxxabiv1{17__class,20__si_class,21__vmi_class}_type_infoE` adına bağ (Mach-O'daki fazla
  `_` soyulur). Ad göstericisi: zayıf bağsa adı aynı ikilide tanımlı sembolün adresine çevrilir (**64 bit ekli içe
  aktarımda ek "tekil değil" bitini taşır**: arm64 örneklerde ilk denemede 2 typeinfo bu yüzden kaçıyordu; ek eklendikten
  sonra maskeleniyor); en üst 8 bit maskelenir, bit 63 `tekil_olmayan` olarak kaydedilir. GCC'nin `*` yerel ad işareti
  soyulur, `yerel_ad` kaydedilir. `si` / `vmi` tabanları (yerel typeinfo adresi ya da dış bağ adı; vmi bayrağı: sanal /
  açık / ofset).
- vtable: typeinfo nesnesinin içinde olmayan, yerel bir typeinfo'ya gösteren sözcük; önündeki sözcük düzeltme yeri değil
  (bağ değil; `gosterici()` değeri ham sözcükten farklı değil) ve `-2^20 … 0` aralığında. Yuvalar: kod bölümüne gösteren
  ardışık göstericiler; dış bağ (işlev) = içe aktarım yuvası (`None`, sıra ilerler); `_ZTI/_ZTV/_ZTS/_ZTT/_ZTC` bağında,
  typeinfo başında, kod dışı değerde durur; `rtti_max_vtable_entries` (config öntanımı 64) aşılırsa kesilir ve sayılır.
- Adres kaynağı: zincirli düzeltmeli Mach-O'da düzeltme yerleri (başvurunun yaptığı gibi); öbür biçimlerde kod dışı
  yüklenen bölümlerin bütün sözcükleri.
- **Yuva → sınıf** (kalem 4): işlevin göründüğü sınıflar arasında öbürlerinin hepsinin geçişli tabanı olan tek sınıf
  varsa ona (`en_taban_sinif`), tek sınıfta görünüyorsa ona (`tek_sinif`); yoksa `belirsiz` (aday yok).
- `rtti_classes()` (`_add_rtti` biçimi): her typeinfo için `{"name", "mangled", "methods", "bases", "vtable", "typeinfo"}`;
  `methods` = sınıfın ilk birincil vtable'ının yuvaları; işlev bu sınıfa bağlı değilse (içe aktarım, devralınan, belirsiz)
  0 — böylece bir işlev ad kanalına en çok bir kez girer.
- `karadul/pipeline/steps/rtti_recovery.py`: bayrak `getattr(…, "enable_rtti_recovery", False) is True`; yuva sınırı
  `rtti_max_vtable_entries` (geçersizse config öntanımı); `produces = rtti_classes, rtti_status (durum, neden),
  rtti_classes_path`; çıktı `static/rtti_classes.json` (`karadul.rtti_classes.v1`: özet, sınıflar, typeinfo'lar,
  vtable'lar, işlev bağları). Faz 1 listesine ve `steps/__init__.py`'ye EKLENMEDİ (P-ÜV6b).
- **Başvurudan bilerek ayrılık:** başvuru betiği bir vtable'ın hemen ardından typeinfo nesnesi gelince o nesnenin ilk
  sözcüğünü (cxxabiv1 bağı) içe aktarım yuvası sayıyordu (`ice_aktarim_yuvasi` btop'ta 54, burada 22; `yuva` 187 / 155).
  H1'in üç sayısı bundan etkilenmiyor (aşağıda aynı).
- Süre sınırı (10 sn) yalnız taramaya uygulanır; görüntü hazırlığı (sembol tablosu, düzeltme zinciri) dışında (`ee37ccb`).

## Testler ve mutasyon

- `tests/test_puv4_rtti.py`: **44 test** (typeinfo 6, vtable 8, yuva → sınıf 4, ELF 1, sağlamlık 9, adım 16 — parametreler
  dahil). Sentetik görüntü: `Taban` (class, "tekil değil" biti), `Tekli : Taban` (si), `Ikinci` (class; ilk yuva
  `__cxa_pure_virtual`), `Coklu : Tekli, Ikinci` (vmi; birincil + ikincil vtable), `Zayif : Taban` (ad ve bir yuva zayıf
  bağ); iki tuzak (tepeye uzaklığı düzeltme yeri / pozitif); belirsiz işlev (Taban ve Ikinci'de). Bulanık test 60 deneme.
- Mutasyon `scripts/measurement/mutation_specs_puv4.json`: **16 / 16 öldü** (planın 8'i + 8 ek). İlk koşuda "typeinfo içi
  başvuru vtable sayılır" mutantı yaşadı: yuva yürüyüşündeki iç sözcük denetimi dış döngünün denetimini örtüyordu;
  yürüyüş artık yalnız typeinfo başında duruyor (sayılar değişmedi), sonra 16 / 16 (`be20612`, `ee37ccb` sonrası yinelendi).

## Keşif ölçümü (dondurmadan önce; yük altında, load 9–18)

Komutlar: `python scripts/arge/ustveri/puv4_olc.py {ornek --kok …/PUV4/ornek | say btop Ollama.arm64 Ollama.x86_64 | h3 |
h4 | h5 | h6}`; çıktılar `…/PUV4/ozet/{ornek,say_btop_Ollama.arm64_Ollama.x86_64,h3,h4,h5,h6}.json`.

### H0 — yerel örnekler (17 sınıf; `cpp_ornek/`, clang 21, 4 derleme)

| Derleme | typeinfo adı = `_ZTI` | kaçan `_ZTI` | vtable = `_ZTV` (birincil, sembol adresinde) | `_ZTV` adresinde birincil yok | yuva (a) başvuru kuralı | thunk | yuva (b) ürün bağı | belirsiz (sembollü) | soyulmuş = sembollü | H6 tam eşit |
|---|---|---|---|---|---|---|---|---|---|---|
| arm64 -O0 | 17 / 17 | 0 | 14 / 14 | 3 | 53 / 53 | 12 | 53 / 53 | 0 | evet | 0 / 53 |
| arm64 -O2 | 17 / 17 | 0 | 14 / 14 | 3 | 32 / 32 | 6 | 31 / 31 | 1 | evet | 0 / 31 |
| x86_64 -O0 | 17 / 17 | 0 | 14 / 14 | 3 | 53 / 53 | 12 | 53 / 53 | 0 | evet | 0 / 53 |
| x86_64 -O2 | 17 / 17 | 0 | 14 / 14 | 3 | 32 / 32 | 6 | 31 / 31 | 1 | evet | 0 / 31 |

- Sınıf kümesi arm64 = x86_64 (-O0 ve -O2). Soyulmuş kopyada tam çıktı (typeinfo, vtable, işlev bağları, `rtti_classes`)
  sembollüyle aynı (4 / 4).
- `_ZTV` adresinde birincil kaydı olmayan 3 sembol: `VSol`, `VSag`, `Elmas` (**sanal kalıtım**; ön kayıtta öngörülen
  durum). Üçünde de kayıt sembolden 8 bayt sonra (sanal taban ofseti sözcüğü), sınıf adı aynı. Yani "vtable adresi
  sembolle aynı" maddesi sanal tabanlı sınıfta **tutmadı** (14 / 17); kayıt adresi vtable grubunun başı değil tepeye
  uzaklık sözcüğü. P-ÜV6b'ye not: kanıt satırında grup başı gerekiyorsa sanal taban ofsetleri geri sayılmalı.
- arm64 -O2'de 3 belirsiz işlev (11, 11 ve 3 ilgisiz sınıfın vtable'ında aynı adres: derleyicinin ortak yıkıcı gövdesi);
  biri sembollü. Aday verilmedi.
- Zayıf bağ: arm64'te 2 typeinfo adı + 2 yuva, x86_64'te 4 + 2 ada göre bağlı; hepsi yerel adrese çevrildi.
- **H0 hükmü:** typeinfo maddesi tuttu (17 / 17 × 4), soyulmuş = sembollü tuttu, sınıf kümesi tuttu, yuva maddesi tuttu
  (thunk'lar ve belirsiz dışarıda); vtable maddesi sanal kalıtımlı 3 sınıfta tutmadı (kayıt 8 bayt sonra).

### H1 — keşif satırları (üç sayı ↔ `$V/rtti/<ad>.json`)

| Hedef | typeinfo | vtable | işlev | başvuru | aynı | tarama süresi |
|---|---|---|---|---|---|---|
| btop | 42 | 36 | 84 | 42 / 36 / 84 | evet | 0,015 sn |
| Ollama arm64 | 19 | 8 | 68 | 19 / 8 / 68 | evet | 0,072 sn |
| Ollama x86_64 | 19 | 8 | 68 | 19 / 8 / 68 | evet | 0,074 sn |

btop'ta 9 belirsiz işlev (ürün bağı 75 işlev); Ollama'da 0.

### H3 — Ollama iki dilim + zayıf bağ mutantı

- İki dilim 19 / 8 / 68 (aynı). x86_64'te 15 typeinfo adı zayıf bağla geliyor.
- Mutant (zayıf bağ adı yerel adrese çevrilmez; süreç içinde `RttiTarayici._yerel` boş sözlük döndürerek — ürün dosyası
  değiştirilmedi; ön kayıttaki "geçici tek satır" ile eşdeğer): x86_64'te **4 typeinfo** (15 ad çözülemeyen bağ). **H3 tuttu.**

### H4 — bulanık girdi (200 deneme × 200 rastgele bayt, tohumlu)

| İkili | bölüm | istisna | süre aşımı | durumlar | en uzun deneme |
|---|---|---|---|---|---|
| btop | `__DATA_CONST,__const` (6 688 B) | 0 | 0 | çalıştı 151, veri yok 49 | 0,005 sn |
| pzstd (ek) | `.data.rel.ro` (960 B) | 0 | 0 | çalıştı 200 | 0,02 sn |

**H4 tuttu.** (btop'ta bozulan zincir sözcükleri zinciri erken bitirdiği için 49 denemede typeinfo bulunamadı: `veri_yok`.)

### H5 — ELF pzstd (Debian 13 arm64, GCC / libstdc++) ↔ dbgsym `.symtab`

- 13 typeinfo (class 9, si 4; GCC yerel ad 4), 3 vtable, 13 işlev, belirsiz 0.
- typeinfo adı 13 / 13 (kaçan `_ZTI` 0), vtable 3 / 3, yuva (a) 13 / 13, (b) 13 / 13. **H5 tuttu** (vtable ≥ 1, ad
  eşitliği %100 ≥ %99). n küçük (Wilson alt 0,772): ELF yolu tek ikilide ölçüldü.

### H6 — `Sınıf_vfunc_N` tam eşitliği

Yerel örnekler 0 / 53, 0 / 31 (her derleme); btop 75 aday, 2'si sembollü, tam eşit 0. **H6 tuttu** (beklenen sınır:
yuvadan yöntem adı çıkmaz → kanıt satırı).
