# Karadul çıktı sağlamlığı denetimi

- **Tarih:** 2026-11-10. **Yazan:** Tester ajanı. Ürün koduna dokunulmadı; kusurlar düzeltilmedi, raporlandı.
- **Konu:** çıktının bütünlüğü ve tutarlılığı. Adların doğruluğu bu raporun konusu değil; GT'ye bakılmadı.
- **Betik:** `docs/arge/2026-11-10_cikti_saglamligi/denetle.py` (yalnız okur). **Ham sonuç:** `sonuc.json` (126 koşu). Bu rapordaki her sayı ya `sonuc.json`'dan ya da aşağıda adı geçen komuttan gelir.

## 1. Özet hüküm

**Hat çalışıyor ama son C çıktısı güvenilir değil.** 119 ikilinin 119'unda koşu bitti, rapor "success" dedi, çıktı ağacı var ve dolu; bugünkü ağaçla yapılan 3 yeniden koşu da hatasız bitti. Buna karşın kullanıcının okuduğu son C metni, Ghidra'nın ham çıktısından **daha az** güvenilir:

- Ghidra'nın ham decompile'ı 66 983 fonksiyonun hepsinde biçimsel olarak sağlam (bozuk gövde 0). Karadul'un akış sadeleştirme adımı, `goto` içeren 7 405 fonksiyonun **4 661'ini (%63)** bozuyor: 2 351'inde ayraç ya da parantez dengesi bozuk; 2 310'unda denge yerinde ama koşul ve dönüş mantığı değişmiş (ihtiyatlı sayım). 117/119 ikilide var. Küçük programlarda fonksiyonların %3,7'si, büyüklerde %14,2'si.
- 35/119 ikilide 52 fonksiyon son çıktıdan sessizce düşüyor; rapor yine "SUCCESS" diyor ve düşen dosyayı yazılmış sayıyor.
- Tek C++ ikilisinde (pzstd) son çıktı, bütün ara aşamaların düz dökümü: günlük "12 837 kaynak" diyor, diskte 1 330 dosya var, 106 fonksiyon iki kez tanımlı.
- Analiz, ikilideki bir sürüm dizgisi yüzünden ağdan kaynak indirmeyi deniyor (2/119); "ağ varsayılan kapalı" anahtarı bu yolda hiç okunmuyor.

**Nerede güvenilir, nerede değil:**

| Katman | Durum | Kanıt |
|---|---|---|
| Koşunun bitmesi, aşama başarısı | Güvenilir | 119/119 bitti; aşama hatası 0; 18 sayı karşılaştırmasının 12'si 119/119 tutuyor |
| Ham Ghidra çıktısı (`static/ghidra_output/decompiled`) | Güvenilir, belirlenimli | Bozuk gövde 0/66 983; aynı girdinin 8 koşu çiftinde fonksiyon metni birebir aynı |
| Fonksiyon adlarının belirlenimliği | Güvenilir | Aynı kodla 3 çiftte tanım adı 9 299/9 299 aynı |
| Adlandırma ve tip aşamalarının kodu (akış sadeleştirmeden önce) | Sağlam | `struct_recovered`'a kadar bozuk gövde 0; ilk bozulma 2 350/2 351 fonksiyonda `semantic_named` |
| Son C metni (`out/src`) | **Güvenilmez** | `goto` içeren fonksiyonların %63'ü bozuk; 6 721 fonksiyonda belge yorumu C'yi bozuyor |
| `out/naming_map.json` | **Güvenilmez** | 28 308 "kurtarılan ad"ın 9 823'ü özdeş, 6 466'sı kodda uygulanmamış |
| Rapor sayaçları | Kısmen | Tur sayacı 119/119 yanlış; dosya sayısı 31/119 fazla; ithal sayacı 119/119 sıfır |
| Dosya yerleşimi (`subsystem_group_N`) | Belirlenimsiz | Aynı kodla htop'ta fonksiyonların 270/790'ı aynı yolda |
| Etiketler (kripto, YARA, "OpenGL") | Güvenilmez (bilinen) | Kripto: 8 666 fonksiyon; bugünkü kodda büyük ölçüde düzeldi (kusur 18) |

## 2. Kapsam ve kod durumu

- **119 ikili** = 117 Debian 13 arm64 ELF (`~/karadul_olcum/n1_debian13`, a10fde3) + 2 Mach-O (`workspaces/olcum_mac/runs/ol7-c-b7faeac/{tmux,htop}`). Toplam 66 983 fonksiyon; ELF başına 34–5 697.
- Ayrıca denetlenenler: `ol7-a-9a36142` ve `ol7-d-b7faeac` (4 koşu) ve bugünkü 3 yeniden koşu. Toplam 126 koşu dizini.
- **`ol7-a` neden 119'da değil:** görevin yazıldığı commit'te (a22d833) `git diff --stat a10fde3 a22d833 -- karadul/` ve `b7faeac a22d833` yalnız hatta bağlı olmayan `tarif/kesin.py`'yi gösteriyor; `9a36142 a22d833` ise `c_namer.py`'yi de (b7faeac, belirlenimcilik düzeltmesi). Yani `ol7-a` o günkü ürünün çıktısı değildi; `ol7-c` ve `ol7-d` öyleydi. Üç etiketin kusur sayıları aynı (ör. tmux: bozuk gövde 175, iç içe yorum 426).
- **"Saklı koşular bugünkü ürünün çıktısıdır" iddiası artık tam doğru değil.** Görev yazıldıktan sonra ana oturum ürün koduna commit attı. Rapor anında HEAD 0dcf0fa (14:49); a10fde3'ten beri değişen ürün dosyaları: `c_algorithm_id.py` (ab986da, kripto), `core/output_formatter.py` + `core/naming_labels.py` (ce1caf6, güven), `c_namer.py`, `config.py`, `cli.py`, `hacker_cli.py`, `analyzers/signature_db.py`, `__init__.py`, `tarif/*`. Aşağıdaki kök neden dosyalarının **hiçbiri** değişmedi (`git diff --stat a10fde3 HEAD -- <dosya>` boş): `c_flow_simplifier.py`, `c_project_builder.py`, `c_comment_generator.py`, `engineering/semantic_namer.py`, `c_type_recoverer.py`, `ghidra/headless.py`, `reference_populator.py`, `reference_differ.py`, `_feedback_naming_refdiff.py`, `stages.py`, `finalize.py`. Yani kripto etiketi ve güven 1,0 dışındaki bulgular bugünkü HEAD için de geçerli.
- **Yöntem:** fonksiyonlar adresle eşlendi (`// Address:` başlığı); her fonksiyon bir kez sayıldı. Gövde durumu C'nin sözcük kurallarıyla (yorum, dizgi, ayraç) bulundu; derleyici kullanılmadı. Akış bulguları için 3 fonksiyon elle okundu (htop `FUN_00130620`, tree `FUN_001061a0`, `[` `FUN_001021c0`); ikisi ürünün sınıfıyla bellekte yeniden üretildi.
- **Boyut tabakası** `ks1_sinif.json`'dan, program birimi düzeyinde: küçük (108 ikili), orta (6), büyük (5).

## 3. Kalem başına tablolar (program × boyut tabakası)

Hücrelerde "a / b" biçimi: etkilenen ikili sayısı / etkilenen öğe sayısı.

### Kalem 1 — tamamlanma ve rapor dürüstlüğü

| Program (tabaka) | İkili | Bitti | Rapor "success" | Aşama hatası | Tur sayacı yanlış | Günlükteki dosya sayısı yanlış | İthal sayacı 0 | Diğer sayı uyuşmazlığı |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| debian/coreutils (küçük) | 106 | 106 | 106 | 0 | 106 | 0 | 106 | decompile 5, proje dosyası 24 |
| debian/sqlite3 (küçük) | 1 | 1 | 1 | 0 | 1 | 0 | 1 | – |
| debian/tree (küçük) | 1 | 1 | 1 | 0 | 1 | 0 | 1 | – |
| debian/htop (orta) | 1 | 1 | 1 | 0 | 1 | 0 | 1 | – |
| debian/openssl (orta) | 1 | 1 | 1 | 0 | 1 | 0 | 1 | proje dosyası 1 |
| debian/tmux (orta) | 1 | 1 | 1 | 0 | 1 | 0 | 1 | proje dosyası 1 |
| debian/zstd (orta) | 2 | 2 | 2 | 0 | 2 | 1 | 2 | – |
| mac/htop (orta) | 1 | 1 | 1 | 0 | 1 | 0 | 1 | – |
| debian/redis-tools (büyük) | 4 | 4 | 4 | 0 | 4 | 0 | 4 | proje dosyası 4 |
| mac/tmux (büyük) | 1 | 1 | 1 | 0 | 1 | 0 | 1 | proje dosyası 1 |
| **Toplam** | **119** | **119** | **119** | **0** | **119** | **1** | **119** | **decompile 5, proje dosyası 31** |

- 119/119'da tutan sayılar: fonksiyon sayısı (rapor ↔ `ghidra_functions.json` ↔ günlük ↔ `out/report.json`), deobfuscate girdi ve çıktı dosyası, açıklamalı dosya, imza eşleşmesi, dizgi, çağrı grafı kenar ve düğümü, algoritma sayısı, ad haritası toplamı, yeniden adlandırılan değişken sayısı (son tur haritasıyla).
- Tutmayanlar: tur sayacı 0/119 (rapor 0 diyor; 117 ikilide 2, 2 ikilide 3 tur koşmuş), `project_files` 88/119, decompile sayısı 114/119, günlükteki dosya sayısı 118/119.
- `convergence_reason` 119/119'da "unknown". `total_imports` 119/119'da 0; Ghidra aynı ikililerde toplam 33 547 thunk listeliyor.

### Kalem 2 — boş ya da eksik çıktı

| Program (tabaka) | İkili | Kaynaklı `out/` | `.c` dosyası | Eksik fonksiyon | Sıfır baytlı dosya | `out/src` ≠ `project/` | Çift tanımlı adres | Başlıksız `_partN.c` | README'deki yapı diskte yok |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| debian/coreutils (küçük) | 106 | 106 | 36 507 | 28 / 29 | 0 | 0 | 0 | 4 / 4 | 106 |
| debian/sqlite3 (küçük) | 1 | 1 | 1 146 | 0 | 0 | 0 | 0 | 1 / 2 | 1 |
| debian/tree (küçük) | 1 | 1 | 250 | 0 | 0 | 0 | 0 | 0 | 1 |
| debian/htop (orta) | 1 | 1 | 1 147 | 0 | 0 | 0 | 0 | 0 | 1 |
| debian/openssl (orta) | 1 | 1 | 5 673 | 1 / 1 | 0 | 0 | 0 | 1 / 6 | 1 |
| debian/tmux (orta) | 1 | 1 | 2 588 | 1 / 1 | 0 | 0 | 0 | 1 / 1 | 1 |
| debian/zstd (orta) | 2 | 2 | 2 698 | 0 | 0 | 1 | 1 / 106 | 2 / 7 | 2 |
| mac/htop (orta) | 1 | 1 | 787 | 0 | 0 | 0 | 0 | 0 | 1 |
| debian/redis-tools (büyük) | 4 | 4 | 13 377 | 4 / 20 | 0 | 0 | 0 | 2 / 4 | 4 |
| mac/tmux (büyük) | 1 | 1 | 2 811 | 1 / 1 | 0 | 0 | 0 | 0 | 1 |
| **Toplam** | **119** | **119** | **66 984** | **35 / 52** | **0** | **1** | **1 / 106** | **11 / 24** | **119** |

- "Başarılı ama 0 kaynak dosyası" durumu bu veride yok: en küçük çıktı 34 `.c` (libstdbuf.so). Zorunlu dosyalar (`report.json`, `report.html`, `naming_map.json`, `dependency_graph.json`, `README.md`, `src/`) 119/119'da var.
- Kesik gövde bu tabloda değil, Kalem 4'te: 988 fonksiyonun gövdesi kapanmıyor.

### Kalem 3 — iç tutarlılık (ad haritası ↔ çıktı)

| Program (tabaka) | İkili | Fonksiyon | Adı değişen fonk. | Haritada var, kodda yok | Özdeş eşleme | Yetim anahtar | Yaratılan çift ad (grup) | Anahtar sözcük ad | Harita ≠ kod (fonk. adı) | Yerel ad uygulanmamış (fonk.) | Son tur haritası ≠ çıktı (fonk.) | `@address` yanlış (fonk.) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| debian/coreutils (küçük) | 106 | 36 573 | 2 442 | 106 / 5 240 | 106 / 5 708 | 106 / 211 | 10 / 14 | 0 | 1 / 4 | 106 / 2 040 | 27 / 146 | 106 / 14 005 |
| debian/sqlite3 (küçük) | 1 | 1 144 | 149 | 1 / 49 | 1 / 226 | 1 / 2 | 1 / 4 | 0 | 0 | 1 / 22 | 0 | 1 / 466 |
| debian/tree (küçük) | 1 | 250 | 48 | 1 / 30 | 1 / 49 | 1 / 2 | 0 | 0 | 0 | 1 / 25 | 1 / 23 | 1 / 63 |
| debian/htop (orta) | 1 | 1 148 | 71 | 1 / 74 | 1 / 158 | 1 / 3 | 0 | 0 | 0 | 1 / 53 | 1 / 106 | 1 / 336 |
| debian/openssl (orta) | 1 | 5 672 | 370 | 1 / 48 | 1 / 1 687 | 1 / 2 | 1 / 1 | 1 / 1 | 1 / 1 | 1 / 227 | 1 / 351 | 1 / 3 279 |
| debian/tmux (orta) | 1 | 2 588 | 634 | 1 / 80 | 1 / 196 | 1 / 2 | 1 / 5 | 1 / 2 | 1 / 3 | 0 | 1 / 570 | 1 / 421 |
| debian/zstd (orta) | 2 | 2 600 | 644 | 2 / 82 | 2 / 159 | 2 / 4 | 0 | 0 | 0 | 1 / 1 | 1 / 234 | 2 / 225 |
| mac/htop (orta) | 1 | 790 | 101 | 1 / 185 | 1 / 1 | 0 | 0 | 0 | 0 | 0 | 1 / 137 | 1 / 2 |
| debian/redis-tools (büyük) | 4 | 13 397 | 887 | 4 / 454 | 4 / 1 638 | 4 / 8 | 4 / 11 | 2 / 4 | 3 / 3 | 4 / 101 | 4 / 6 478 | 4 / 1 748 |
| mac/tmux (büyük) | 1 | 2 821 | 875 | 1 / 224 | 1 / 1 | 0 | 0 | 1 / 2 | 1 / 4 | 1 / 1 | 1 / 2 012 | 1 / 1 |
| **Toplam** | **119** | **66 983** | **6 221** | **119 / 6 466** | **119 / 9 823** | **117 / 234** | **17 / 35** | **5 / 9** | **7 / 15** | **116 / 2 470** | **38 / 10 057** | **119 / 20 546** |

Görevdeki dört soruya cevap:

- **Haritadaki her ad çıktıda geçiyor mu?** Hayır. c_namer'ın 6 461 fonksiyon adından 6 206'sı uygulanmış; `signature_db` kaynaklı 6 459 eşleme haritada var ama kodda yok (ör. `__libc_start_main → libc_start_main`). Veri adlarında (9 211 `DAT_`) eski ad kodda kalmamış.
- **Aynı ad iki fonksiyona verilmiş mi?** Evet, 17 ikilide 35 grup: c_namer bir iç fonksiyona ikilide zaten var olan ithal adını veriyor (ör. coreutils/cat `FUN_00103480 → write`).
- **Geçerli C tanımlayıcısı olmayan ad var mı?** Evet, 5 ikilide 9 fonksiyon C anahtar sözcüğüyle adlandırılmış: `break`, `char`, `default`, `continue`, `long`. Ör. `tmux/tmux/out/src/src/subsystem_group_0/FUN_00141080.c:20` → `void continue(long buf_188,uint *buf_189)`.
- **Çıktıda haritada olmayan fonksiyon adı var mı?** Hayır (0/119). Tek istisna: openssl'de haritanın `undefined` dediği fonksiyon kodda `uint64_t` adını taşıyor (kusur 9).

### Kalem 4 — C'nin biçimsel sağlamlığı (ham Ghidra ↔ son çıktı)

| Program (tabaka) | İkili | Fonksiyon | Ham Ghidra'da bozuk | Ham kodda `goto` içeren | Son çıktıda ayraç/parantez bozuk | Akış anlamı değişen (ihtiyatlı) | Birleşik (ihtiyatlı) | `goto` içerenlere oranı | Birleşik (üst sınır) | İç içe yorum | Dizgi sabiti değişen | Bozuk kodlama |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| debian/coreutils (küçük) | 106 | 36 573 | 0 | 2 124 | 105 / 605 | 105 / 1 179 | 105 / 1 291 | %61 | 1 424 | 105 / 3 325 | 0 | 0 |
| debian/sqlite3 (küçük) | 1 | 1 144 | 0 | 118 | 1 / 47 | 1 / 86 | 1 / 92 | %78 | 99 | 1 / 42 | 1 | 0 |
| debian/tree (küçük) | 1 | 250 | 0 | 26 | 1 / 8 | 1 / 14 | 1 / 16 | %62 | 17 | 1 / 18 | 0 | 0 |
| debian/htop (orta) | 1 | 1 148 | 0 | 116 | 1 / 37 | 1 / 70 | 1 / 79 | %68 | 86 | 1 / 127 | 0 | 0 |
| debian/openssl (orta) | 1 | 5 672 | 0 | 236 | 1 / 84 | 1 / 174 | 1 / 183 | %78 | 196 | 1 / 76 | 5 | 0 |
| debian/tmux (orta) | 1 | 2 588 | 0 | 558 | 1 / 211 | 1 / 338 | 1 / 372 | %67 | 412 | 1 / 311 | 0 | 0 |
| debian/zstd (orta) | 2 | 2 600 | 0 | 680 | 1 / 144 | 1 / 232 | 1 / 264 | %39 | 289 | 1 / 247 | 1 | 0 |
| mac/htop (orta) | 1 | 790 | 0 | 81 | 1 / 18 | 1 / 55 | 1 / 57 | %70 | 60 | 1 / 136 | 0 | 0 |
| debian/redis-tools (büyük) | 4 | 13 397 | 0 | 2 921 | 4 / 1 022 | 4 / 1 729 | 4 / 1 911 | %65 | 2 128 | 4 / 2 013 | 0 | 0 |
| mac/tmux (büyük) | 1 | 2 821 | 0 | 545 | 1 / 175 | 1 / 366 | 1 / 396 | %73 | 437 | 1 / 426 | 0 | 0 |
| **Toplam** | **119** | **66 983** | **0** | **7 405** | **117 / 2 351** | **117 / 4 243** | **117 / 4 661** | **%63** | **5 148** | **117 / 6 721** | **7** | **0** |

- **Bozuk gövde 2 351:** 988 kapanmıyor, 1 220 erken kapanıyor (kapanıştan sonra kod kalıyor), 143'ünde yalnız parantez dengesiz. İlk bozulduğu aşama: 2 350'sinde `semantic_named` (akış sadeleştirme bu dizinde yerinde çalışıyor), 1'inde son çıktı.
- **"Akış anlamı değişen"** iki işaretten biriyle sayıldı: (a) `if (k) goto L;` yerine ayraçsız çok deyimli blok konmuş (son metinde 3 485 etikette görülüyor); (b) etikete düşerek de ulaşılıyordu ama etiket bloğu silinmiş. İhtiyatlı sayımda (b) yalnız etiketten hemen önce düz deyim ya da `{` varsa sayıldı (4 512 etiket); `}` ile biten durumlar da sayılırsa 6 988 etiket ve 5 148 fonksiyon.
- pzstd ve libstdbuf.so'da akış bozulması 0. pzstd'de neden: son çıktı akış sadeleştirmeden önceki ara dizinden geliyor (kusur 3).
- **Satır kaybı:** kod satırı toplamı ham 1 906 404 → son 1 855 172; satırı azalan 2 576 fonksiyon var. Akış sadeleştirme `goto` ve etiket satırlarını kaldırdığı için azalma tek başına kayıp sayılmadı. Daha sıkı ölçüt: sözdizimi sağlam olup çağrı ya da deyim sayısı azalan fonksiyon 0. Fonksiyon sayısı düzeyinde kayıp: 52 (Kalem 2).
- **İç içe yorum:** 6 721 fonksiyonda belge bloğu erken kapanıyor; 6 508'inde bloğun kalan `@…` satırları da kod sayılıyor (kusur 5).
- Boş gövdeye dönüşen fonksiyon 0. Bozuk UTF-8 ya da NUL baytı 0 (bütün aşamalarda).

### Kalem 5 — sessiz hatalar

| Program (tabaka) | İkili | Günlük satırı (ortanca) | BSim yedeğe düştü | Ağdan indirme denemesi | "başarısız" satırı | Traceback | Ghidra uyarısı (ham) | Ghidra uyarısı (son) | Gizlenen kritik uyarı | Kripto etiketli fonk. |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| debian/coreutils (küçük) | 106 | 38 | 74 | 0 | 74 | 0 | 45 894 | 0 | 106 / 1 163 | 105 / 2 859 |
| debian/sqlite3 (küçük) | 1 | 40 | 1 | 1 | 3 | 0 | 1 066 | 0 | 1 / 135 | 1 / 89 |
| debian/tree (küçük) | 1 | 37 | 0 | 0 | 0 | 0 | 326 | 0 | 1 / 11 | 1 / 21 |
| debian/htop (orta) | 1 | 38 | 1 | 0 | 1 | 0 | 1 085 | 0 | 1 / 41 | 1 / 199 |
| debian/openssl (orta) | 1 | 40 | 1 | 1 | 3 | 0 | 6 316 | 0 | 1 / 58 | 1 / 91 |
| debian/tmux (orta) | 1 | 37 | 0 | 0 | 0 | 0 | 2 165 | 0 | 1 / 67 | 1 / 421 |
| debian/zstd (orta) | 2 | 38 | 2 | 0 | 2 | 0 | 5 180 | 0 | 2 / 98 | 1 / 137 |
| mac/htop (orta) | 1 | 38 | 0 | 0 | 0 | 0 | 626 | 0 | 1 / 391 | 1 / 139 |
| debian/redis-tools (büyük) | 4 | 38 | 3 | 0 | 3 | 0 | 14 457 | 0 | 4 / 625 | 4 / 4 248 |
| mac/tmux (büyük) | 1 | 38 | 0 | 0 | 0 | 0 | 1 067 | 0 | 1 / 503 | 1 / 462 |
| **Toplam** | **119** | **38** | **82** | **2** | **86** | **0** | **78 182** | **0** | **119 / 3 092** | **117 / 8 666** |

- **Günlük neredeyse boş.** 37–40 satır; yalnız özet tablosu. Aşama bazında ileti yok. Bütün veride üç tür ileti var:
  - `BSim native ingest basarisiz … Database already in use by another process`: 82 ikili (hepsi Debian, paralel 3 koşu; en küçüğü 245 fonksiyon). Boyuta değil eşzamanlılığa bağlı.
  - `ReferencePopulator: … tum URL'ler basarisiz` + `Auto-populate basarisiz`: 2 ikili (sqlite3, openssl). Boyuta değil ikilideki sürüm dizgisine bağlı.
  - Yalnız büyüklerde çıkan ileti yok.
- Rapordaki aşama `errors` listeleri 119/119'da boş. Uyarı, traceback, "skip" satırı 0. Zaman aşımı kalıbına uyan 2 satır `timeout` adlı ikilinin kendi adı.
- **Ghidra'nın 78 182 uyarı yorumunun hepsi son çıktıdan silinmiş.** En sık türler: `Unknown calling convention` 22 136, `Subroutine does not return` 21 219, `Bad instruction - Truncating control flow here` 11 213, `Globals starting with '_' overlap…` 9 232. Decompile'ın eksik ya da kuşkulu olduğunu söyleyenler: `Removing unreachable block` 879 (119 ikili), `Could not recover jumptable` 876 (118), `Treating indirect jump as call` 876 (118), `Type propagation algorithm not settling` 304 (118), `Restarted to delay deadcode elimination` 108, `Heritage AFTER dead removal` 40.

### Kalem 6 — ölçek

| Program (tabaka) | İkili | Fonksiyon | Toplam süre (s) | s / fonksiyon (ortanca) | Statik aşama payı % (ortanca) | Çıktı KB / fonksiyon (ortanca) | `decompiled.json` kırpık |
|---|---:|---:|---:|---:|---:|---:|---:|
| debian/coreutils (küçük) | 106 | 34–815 | 13–124 | 0,16 | 78 | 2,5 | 9 / 1 480 |
| debian/sqlite3 (küçük) | 1 | 1 144 | 209 | 0,18 | 69 | 3,7 | 1 / 644 |
| debian/tree (küçük) | 1 | 250 | 58 | 0,23 | 73 | 3,9 | 0 |
| debian/htop (orta) | 1 | 1 148 | 212 | 0,18 | 80 | 3,5 | 1 / 648 |
| debian/openssl (orta) | 1 | 5 672 | 531 | 0,09 | 66 | 2,3 | 1 / 5 172 |
| debian/tmux (orta) | 1 | 2 588 | 728 | 0,28 | 76 | 4,8 | 1 / 2 088 |
| debian/zstd (orta) | 2 | 1 156–1 444 | 370–594 | 0,37 | 71 | 10,1 | 2 / 1 600 |
| mac/htop (orta) | 1 | 790 | 193 | 0,24 | 81 | 3,8 | 1 / 290 |
| debian/redis-tools (büyük) | 4 | 892–5 697 | 166–2 292 | 0,30 | 73 | 4,8 | 4 / 11 397 |
| mac/tmux (büyük) | 1 | 2 821 | 941 | 0,33 | 77 | 5,0 | 1 / 2 321 |
| **Toplam** | **119** | **34–5 697** | **13–2 292** | **0,16** | **77** | **2,6** | **21 / 25 640** |

- **Doğrusala yakın.** 117 Debian koşusunda log-log eğim (süre ∝ fonksiyon^eğim): toplam 1,10 (R² 0,93), statik 1,07, reconstruct 1,18, çıktı boyutu 1,21. Ham C baytına göre eğimler 1'in altında (toplam 0,80). Aynı fonksiyon sayısında süre kod hacmine bağlı: openssl 5 672 fonksiyon 531 s, redis-check-aof 5 697 fonksiyon 2 292 s (ham C 7,7 MB ve 21,1 MB).
- **Doğrusal üstü tek adım: `engineering_analysis`.** Eğim 2,70 (R² 0,93). 500'den küçük ikililerde toplam sürenin %0,2'si (ortanca), 2 000'den büyüklerde %10,3'ü; redis-check-aof'ta 330 s. Sonraki en dik adımlar: `deep_tracing` 1,53, `inline_detection` 1,43, `semantic_naming` 1,33.
- **Zaman aşımına yaklaşan yok.** En uzun statik aşama 1 569 s; Ghidra sınırı 7 200 s (%22). En uzun tur 122 s; tur sınırı 600 s (%20).
- **`decompiled.json` 500 kayıtla kırpılıyor.** 500'den çok fonksiyonu olan 21 ikilinin 21'inde; toplam 25 640 fonksiyon kaydı yok (kusur 16).
- Süreler: Debian paralel 3, Mac tek iş; iki küme birbiriyle kıyaslanmamalı. 119 koşunun toplamı 4,04 saat. Disk: çalışma alanları 4,24 GB, `out/` 0,25 GB.

### Kalem 7 — belirlenimcilik ve bugünkü ağaç

| Çift | Kod | Fonksiyon | Ham Ghidra aynı | Tanım adı aynı | Metin aynı | Yorumsuz kod aynı | Aynı yolda | Ad haritası |
|---|---|---:|---:|---:|---:|---:|---:|---|
| mac tmux: ol7-c ↔ ol7-d | aynı (b7faeac) | 2 820 | 2 821 / 2 821 | 2 820 | 2 818 | 2 818 | 2 650 | aynı |
| mac htop: ol7-c ↔ ol7-d | aynı (b7faeac) | 790 | 790 / 790 | 790 | 786 | 788 | 270 | aynı |
| redis-check-aof ↔ redis-check-rdb (aynı sha256) | aynı (a10fde3) | 5 689 | 5 697 / 5 697 | 5 689 | 5 686 | 5 686 | 4 910 | aynı |
| mac tmux: ol7-a ↔ ol7-c | farklı (c_namer) | 2 820 | 2 821 / 2 821 | 2 739 | 322 | 359 | 2 693 | 89 ad farklı |
| mac htop: ol7-a ↔ ol7-c | farklı (c_namer) | 790 | 790 / 790 | 788 | 155 | 157 | 255 | 2 ad farklı |
| tree: saklı ↔ bugün | farklı (ab986da) | 250 | 250 / 250 | 250 | 229 | 250 | 130 | aynı |
| true: saklı ↔ bugün | farklı (ab986da + ce1caf6) | 239 | 239 / 239 | 239 | 213 | 226 | 155 | adlar aynı; 44 girişte güven alanı farklı |
| redis-benchmark: saklı ↔ bugün | farklı (ab986da + ce1caf6) | 890 | 892 / 892 | 890 | 648 | 788 | 677 | adlar aynı; 181 girişte güven alanı farklı |

Ayrıntı §5'te.

## 4. Kusurlar (önem sırasıyla)

Önem: **engel** = çıktıya bu yönüyle güvenilemez; **uyarı** = yanlış ya da yanıltıcı ama sınırlı; **not** = kozmetik ya da bilgi.

| # | Kusur | Kaç ikilide | Önem |
|---:|---|---:|---|
| 1 | Akış sadeleştirme kodu bozuyor | 117/119 (4 661 fonksiyon) | engel |
| 2 | Fonksiyonlar son çıktıdan sessizce düşüyor | 35/119 (52 fonksiyon) | engel |
| 3 | C++ hedefte son çıktı ara aşamaların düz dökümü | 1/119 (tek C++ ikilisi) | engel |
| 4 | Analiz ağdan kaynak indirip derlemeyi deniyor; ağ anahtarı okunmuyor | 2/119 denedi, 0 başardı | engel (güvenlik) |
| 5 | Belge yorumu iç içe yorumla C'yi bozuyor | 117/119 (6 721 fonksiyon) | uyarı |
| 6 | `naming_map.json` kodda olmayan adları listeliyor | 119/119 (6 466 + 9 823 özdeş) | uyarı |
| 7 | Son tur haritası ve kökeni çıktıyla uyuşmuyor | 38/119 (10 057 fonksiyon) | uyarı |
| 8 | Anahtar sözcük adlar ve ithal adıyla çakışan adlar | 5/119 ve 17/119 | uyarı |
| 9 | Tip değişimi dizgi sabitlerini ve bir fonksiyon adını değiştiriyor | 1/119 doğrulandı (5 fonksiyon) | uyarı |
| 10 | Yerel ad haritada var, kodda yok | 116/119 (2 470 fonksiyon) | uyarı |
| 11 | Belge yorumundaki `@address` başka fonksiyonun | 119/119 (20 546 fonksiyon) | uyarı |
| 12 | Ghidra uyarılarının hepsi siliniyor | 119/119 (78 182 uyarı) | uyarı |
| 13 | Rapor sayaçları yanlış | 119/119 (tur, ithal), 31/119 (dosya), 5/119 (decompile) | uyarı |
| 14 | Dosya yerleşimi ve birkaç yerel tip koşudan koşuya değişiyor | 3/3 aynı kod çifti | uyarı (bilinen) |
| 15 | BSim eşzamanlı koşuda yedeğe düşüyor; her koşu ortak veritabanını değiştiriyor | 82/119 | uyarı |
| 16 | `decompiled.json` 500 kayıtla kırpık; `engineering_analysis` doğrusal üstü | 21/119; eğim 2,70 | uyarı (ölçek) |
| 17 | Her ada güven 1,0 | 119/119 (15 679 giriş) | uyarı (bilinen; HEAD'de düzeldi) |
| 18 | Kripto ve diğer etiketler | 117/119 (8 666 fonksiyon) | uyarı (bilinen; HEAD'de büyük ölçüde düzeldi) |
| 19 | Büyük fonksiyon `_partN.c` dosyalarına bölünüyor | 11/119 (24 dosya) | not |
| 20 | README'deki dizin yapısı diskte yok; yorumlarda eski `FUN_` adları | 119/119 | not |

### 1. Akış sadeleştirme kodu bozuyor — engel

- **Ölçüm:** 117/119 ikili. Ham kodda `goto` içeren 7 405 fonksiyonun 4 661'i (ihtiyatlı; üst sınır 5 148). Ayraç/parantez bozuk 2 351; ayraçsız koşula blok gömülen 3 485 etiket; düşerek ulaşılan etiketi silinen 4 512 etiket (ihtiyatlı).
- **Örnek 1 (denge korunuyor, anlam değişiyor):** `~/karadul_olcum/n1_debian13/tree/tree/out/src/src/subsystem_group_4/FUN_001061a0.c`. Ham: `if (__s2[sVar2] != '\0') goto LAB_00106214;`. Son: `if (__s2[n] != '\0')` satırından sonra ayraçsız üç deyim; `return result_31;` koşulsuz hâle gelmiş, arkasındaki hata iletisi ölü kod. Öbür kolda etiket bloğu silinmiş, yerinde tek `;` kalmış; o yol artık dönmüyor.
- **Örnek 2 (denge bozuluyor):** `~/karadul_olcum/n1_debian13/htop/htop/out/src/src/subsystem_network/FUN_00130620.c` sonu: `_guard);\n  }\n  return;\n}`. Silinen bloğun kuyruğu yerinde kalmış.
- **Örnek 3:** `~/karadul_olcum/n1_debian13/coreutils/[/out/src/src/subsystem_group_0/FUN_001021c0.c:61-66`. `[` programının ana fonksiyonu; etiket bloğu `}`'ı aşıp sonraki koda taşmış.
- **Etki:** okuyan kişi ikilinin yapmadığı bir akışı görür. Bozulanlar `goto` içeren, yani en karmaşık fonksiyonlar. 2 351'i ayrıştırıcıdan da geçmez.
- **Kök neden (doğrulandı, bellekte yeniden üretildi):** `karadul/reconstruction/c_flow_simplifier.py`
  - `:421-437` `_extract_label_block`: bloğu satır satır, ilk `return`/`break`/`goto` satırına kadar alır; ayraç derinliğine bakmaz; boş satırları atar.
  - `:355` goto'nun yerine blok ayraçsız konur (`if (k) goto L;` tek deyimdi).
  - `:362-369` etiket ve blok silinir; etikete düşerek ulaşılıp ulaşılmadığı denetlenmez. Silinecek uzunluk `len(block)` ile hesaplanır; boş satırlar atıldığı için kısa kalır. Boş satırı çoğu kez silinen Ghidra uyarı yorumu bırakır (kusur 12).
  - `:938-977` çok hedefli etiketlerde aynı kalıp.
  - `:166-167` dosya başına hata `logger.debug` ile yutulur.
- **Doğrulama komutu:** `CFlowSimplifier()._simplify_content(...)`, `reconstructed/struct_recovered/FUN_001061a0.c` (tree) ve `FUN_00130620.c` (htop) metinleriyle; ikisinde de saklı çıktıdaki bozulma aynen çıktı.

### 2. Fonksiyonlar son çıktıdan sessizce düşüyor — engel

- **Ölçüm:** 35/119 ikili, 52 fonksiyon. `_exit` 28 ikilide; redis'te programın kendi fonksiyonları da var (`_dictExpand`, `_sdsnewlen`, `_sdsMakeRoomFor`, `__redisAppendCommand`, `_quicklistBookmarkDelete`). 31 ikilide rapor `project_files`'ı diskten 1–8 fazla sayıyor. README 35'inde de "SUCCESS".
- **Örnek:** `~/karadul_olcum/n1_debian13/coreutils/base32`: `reconstructed/annotated/_exit.c` (adres 00101b50) var; `reconstructed/project` ve `out/` altında bu adres yok, `exit.c` var. Rapor 331 dosya diyor, diskte 330.
- **Etki:** çıktıyı okuyan kişi fonksiyonun eksik olduğunu hiçbir yerden öğrenemez.
- **Kök neden a (disk kanıtıyla doğrulandı):** `karadul/reconstruction/c_project_builder.py:409` dosya adından baştaki `_` karakterlerini siler (`safe.strip('_.')`); `_exit` ile `exit` aynı dizinde aynı dosyaya yazılır. `:559-560` üzerine yazar ve ikisini de sayar.
- **Kök neden b (kod okumasıyla; yarış yeniden üretilmedi):** `karadul/ghidra/headless.py:1127-1129`. Dosya adı "varsa adres eki koy" denetimiyle seçiliyor; decompile 9 iş parçacığıyla koşuyor. Aynı adlı iki fonksiyon aynı anda denetimi geçince biri ötekinin üstüne yazıyor. 5/119 ikilide (comm, fmt, runcon, stat, tac) ham dizinde 1 dosya eksik; rapor yine tam sayıyı veriyor. Örnek: `coreutils/fmt`: `memcmp` 00101df8 hiçbir aşamada yok. Yarış olduğu için koşudan koşuya değişebilir.

### 3. C++ hedefte son çıktı ara aşamaların düz dökümü — engel

- **Ölçüm:** 1/119 (zstd/pzstd; `language: cpp` olan tek ikili). Günlük "12 842 dosya yazıldı (12 837 kaynak)" diyor; diskte 1 335 dosya var. 106 adres iki dosyada tanımlı. `out/src` ile `reconstructed/project` farklı; alt sistem dizinleri ve yorum katmanı çıktıda yok.
- **Örnek:** `~/karadul_olcum/n1_debian13/zstd/pzstd/out/src/DT_FINI.c` ve `_DT_FINI.c` (ikisi de adres 001972fc).
- **Etki:** C++ ikilisinde kullanıcı en olgun çıktıyı değil, üst üste yazılmış ara dosyaları görür; rapordaki sayı on kat şişik.
- **Kök neden (kod okuması + disk):** `karadul/core/output_formatter.py:147-154` (satır numaraları HEAD 0dcf0fa'ya göre; ce1caf6'dan önce 9 satır yukarıdaydı). Dil "c" değilse genel dala düşüyor; `:242` yalnız "unknown" değerini eliyor, "cpp" geçiyor. `:493-497` `reconstructed/` altındaki bütün kaynakları tek dizine, aynı adlıları üst üste kopyalıyor ve her kopyayı sayıyor. Dosyadaki yorum (`:233-241`) aynı hatayı "unknown" için anlatıyor.

### 4. Analiz ağdan kaynak indirip derlemeyi deniyor — engel (güvenlik)

- **Ölçüm:** 2/119 ikilide deneme izi (sqlite3, openssl); 0 başarı. sqlite3'te `timing_reference_differ_iter0` 5,2 s (diğerlerinde 0,3–0,6 s). `~/.cache/karadul/sources/{sqlite3/3.8.12,openssl/3.5.7}` koşu saatinde açılmış, boş.
- **Örnek:** `~/karadul_olcum/n1_debian13/sqlite3/sqlite3/kosu.log:14-15`.
- **Etki:** indirme tutarsa araç inen kaynağı derliyor (`./Configure`, `make -j4`) ve sonucu ad kaynağı yapıyor. Tetikleyen şey, incelenen ikilinin içindeki bir sürüm dizgisi. Çıktı ağ durumuna bağlı hâle geliyor.
- **Kök neden (kod okumasıyla):** `karadul/pipeline/steps/_feedback_naming_refdiff.py:110-112` `ReferenceDiffer(…, auto_populate=True)`; `karadul/reconstruction/reference_differ.py:903` `ReferencePopulator(skip_ghidra=False)`; `karadul/reconstruction/reference_populator.py:448-507` indirme, `:136-150` derleme adımları. `config.py:327` `allow_reference_download` hiçbir yerde okunmuyor (`grep -rn allow_reference_download karadul` yalnız tanımı bulur).
- **Doğrulanmadı:** isteklerin ağa gerçekten çıkıp çıkmadığı. Bu yüzden kalem 7'de sqlite3 yeniden koşulmadı.

### 5. Belge yorumu iç içe yorumla C'yi bozuyor — uyarı

- **Ölçüm:** 117/119 ikili, 6 721 fonksiyon (%10,0). 6 508'inde bloğun kalan `@…` satırları da koda sızıyor; kalanında yalnız kapanış ` */` kod sayılıyor.
- **Örnek:** `~/karadul_olcum/n1_debian13/htop/htop/out/src/src/subsystem_group_6/Process_rowChangePriorityBy.c:16`: ` * @param int count /* was: param_2 */`. C'de yorumlar iç içe geçmez; blok burada kapanır, sonraki `@calls` ve `@algorithm` satırları kod sayılır.
- **Etki:** dosya geçerli C değil; çıktıyla birlikte yazılan `.clangd` ve `compile_commands.json` bu dosyalarda işe yaramaz.
- **Kök neden (kod okuması + disk):** `karadul/reconstruction/engineering/semantic_namer.py:3107` imzaya `/* was: … */` ekliyor; `karadul/reconstruction/c_comment_generator.py:1386-1389` parametre metnini olduğu gibi `/** … */` bloğuna kopyalıyor.

### 6. `naming_map.json` kodda olmayan adları listeliyor — uyarı

- **Ölçüm:** 119/119. README'lerdeki "Names Recovered" toplamı 28 308. Bunun 9 823'ü özdeş eşleme (`strlen → strlen`), 6 466'sı kodda uygulanmamış (6 459 `signature_db`, 7 c_namer). Çıktıda adı gerçekten değişen fonksiyon 6 221.
- **Örnek:** `~/karadul_olcum/n1_debian13/htop/htop/out/naming_map.json`: `Settings_write → update_record` (signature_db, 0,79, kütüphane "sqlite3"); kodda tanım `Settings_write`.
- **Etki:** harita, çıktıda olmayan yeniden adlandırmaları bildiriyor; başlıktaki sayı şişik.
- **Kök neden (kod okumasıyla):** `karadul/core/output_formatter.py:533-544`: imza eşleşmeleri, koda uygulanıp uygulanmadığına bakılmadan haritaya giriyor.

### 7. Son tur haritası ve kökeni çıktıyla uyuşmuyor — uyarı

- **Ölçüm:** kod ilk turun adlarını taşıyor. Son turun `naming_map.json` ve `naming_provenance.json` dosyaları (raporun `artifacts.named_sources` alanı bunları gösteriyor) 38/119 ikilide 10 057 fonksiyonda 21 886 yerel adı farklı veriyor. İlk tur haritasıyla aynı karşılaştırmada fark 110 fonksiyon (parametreler; `param_naming_map.json`'da). Fonksiyon adı düzeyinde 7 ikilide 21 ad turlar arasında değişiyor; 15'inde `out/naming_map.json` koddan farklı.
- **Örnek:** `~/karadul_olcum/n1_debian13/tmux/tmux`: `out/naming_map.json` `FUN_00164a80 → screen_reflow` diyor; kodda çağrılar hâlâ `FUN_00164a80("saving history to %s", …)` (`out/src/src/subsystem_file_io/FUN_001896a0.c:38`).
- **Etki:** köken kaydını son turdan okuyan her ölçüm ya da arayüz, çıktıda olmayan adı anlatır. Güvenli kaynak `reconstructed/src/` (ilk tur).
- **Kök neden:** `karadul/core/output_formatter.py:625-640` "son iterasyon kazanır". İkinci turun adlarının koda neden ulaşmadığı **doğrulanmadı**; gözlem: `typed_iter1` içeriği `typed` ile aynı (htop 1 148/1 148 dosya).

### 8. Anahtar sözcük adlar ve ithal adıyla çakışan adlar — uyarı

- **Ölçüm:** C anahtar sözcüğü: 5 ikili, 9 fonksiyon (redis-check-aof ve -rdb aynı ikili). İkilideki ithal adıyla çakışma: 17 ikili, 35 grup (`write`, `read`, `open`, `fflush`, `fdatasync`, `sigprocmask`…).
- **Örnek:** `~/karadul_olcum/n1_debian13/redis-tools/redis-check-aof/out/src/src/subsystem_group_0/FUN_00304970.c:19` → `void break(uint64_t param_1)`. Köken: `string_context`, güven 0,75, kanıt dizgisi `"break"`.
- **Etki:** `continue(status_208,lVar8);` gibi satırlar C değil. `write` adlı iki ayrı fonksiyon olunca çağrının hangisine gittiği okunamaz.
- **Kök neden:** c_namer'da anahtar sözcük ve var olan fonksiyon adı süzgeci yok; satır **doğrulanmadı**.

### 9. Tip değişimi dizgi sabitlerini ve bir fonksiyon adını değiştiriyor — uyarı

- **Ölçüm:** openssl'de 5 fonksiyonda dizgi içindeki "undefined" sözcüğü "uint64_t" olmuş; 1 fonksiyonun adı `uint64_t`. sqlite3 ve zstd'de birer fonksiyonda da dizgi farkı var; ikisi bozuk gövdeli, nedeni ayrıca doğrulanmadı.
- **Örnek:** `~/karadul_olcum/n1_debian13/openssl/openssl/out/src/src/subsystem_crypto/FUN_001653a0.c:533` → `BIO_printf(global_8150,"iv uint64_t\n");`. Ham: `"iv undefined\n"`. `FUN_0016dc6c.c:21` → `int uint64_t(long count …)`.
- **Etki:** ikilinin gerçek dizgisi çıktıda değiştirilmiş; dizgi, tersine mühendislikte birincil kanıttır.
- **Kök neden (kod okuması + aşama aşama disk):** `karadul/reconstruction/c_type_recoverer.py:336-347`: `undefined*` sözcükleri tek bir `\b…\b` düzenli ifadesiyle bütün dosya metninde değiştiriliyor; dizgi, yorum ve tanımlayıcı ayrımı yok.

### 10. Yerel ad haritada var, kodda yok — uyarı

- **Ölçüm:** 116/119 ikili, 2 470 fonksiyon, 2 473 eşleme (128 954 yerel eşlemenin %1,9'u). Mac'te 1.
- **Örnek:** `~/karadul_olcum/n1_debian13/tree/tree`: harita `strlen: sVar1 → len`; `out/src/src/…/strlen.c` içinde hâlâ `sVar1`.
- **Etki:** "Variables renamed" sayacı bu kadar şişik.
- **Kök neden (doğrulanmadı):** eşleme fonksiyon adıyla anahtarlı; ELF'te aynı adlı iki fonksiyon var (thunk ve dış sembol), dosyaları `ad.c` ve `ad_<adres>.c`. Görünüşe göre değişiklik yanlış dosyaya uygulanıyor.

### 11. Belge yorumundaki `@address` başka fonksiyonun — uyarı

- **Ölçüm:** 119/119 ikili, 20 546 fonksiyon (%31); ELF'lerde yoğun, Mac'te 3.
- **Örnek:** `~/karadul_olcum/n1_debian13/tree/tree/out/src/src/subsystem_group_1/memcpy.c`: başlık `Address: 00103ce0`, belge `@address 00135000`, `@size 1 bytes`.
- **Etki:** aynı dosyada iki farklı adres ve boyut; `@called_by` listesi de öbür fonksiyonun.
- **Kök neden (kod okumasıyla):** `karadul/reconstruction/c_comment_generator.py:1345-1348`: üst veri fonksiyon adıyla aranıyor; aynı adlı ikinci fonksiyonun kaydı geliyor.

### 12. Ghidra uyarılarının hepsi siliniyor — uyarı

- **Ölçüm:** 119/119; ham 78 182 uyarı, son çıktıda 0. Uyarı taşıyan 41 106 fonksiyon.
- **Örnek:** `~/karadul_olcum/n1_debian13/tree/tree`: ham dizinde `Could not recover jumptable … Too many branches` 2, `Type propagation algorithm not settling` 1; `out/` altında hiçbiri yok.
- **Etki:** decompiler'ın "bu fonksiyon eksik çözüldü" dediği yerler kullanıcıya ulaşmıyor.
- **Kök neden (kod okumasıyla):** `karadul/deobfuscators/binary_deobfuscator.py:73-74`: `/* WARNING: … */` kalıbı "Ghidra artığı" sayılıp siliniyor (rapordaki `ghidra_artifacts_cleaned`).

### 13. Rapor sayaçları yanlış — uyarı

- **Ölçüm ve kök neden:**
  - `pipeline_iterations_run` 119/119'da 0, `pipeline_iteration_details` boş. `karadul/stages.py:4766-4767`: eski döngü step-registry kipinde 0 tur koşuyor (`:3513`) ve adımın yazdığı değeri eziyor (`pipeline/steps/feedback_loop.py:216`).
  - `convergence_reason` 119/119'da "unknown". `karadul/pipeline/steps/finalize.py:62`; değerin neden gelmediği **doğrulanmadı**.
  - `total_imports` 119/119'da 0 (`karadul/reporting/json_report.py:150`, `imports_found` alanı); `symbols.json` da 0. Neden boş kaldığı **doğrulanmadı**.
  - `project_files` 31/119'da fazla (kusur 2). Decompile sayısı 5/119'da fazla (kusur 2b). Günlükteki dosya sayısı 1/119'da on kat fazla (kusur 3).
- **Etki:** tur sayısı ve yakınsama nedeni rapordan okunamıyor; "kaç dosya yazıldı" sayısı kayıp dosyayı gizliyor.

### 14. Yerleşim ve birkaç yerel tip koşudan koşuya değişiyor — uyarı (bilinen)

- **Ölçüm (aynı kod, aynı girdi):** aynı yolda kalan fonksiyon: htop 270/790, tmux 2 650/2 820, redis-check 4 910/5 689. Fonksiyon adları ve `out/naming_map.json` üç çiftte de birebir aynı. Yorumsuz kodu farklı fonksiyon: 2, 2 ve 3; elle bakılan 4'ünde fark bir yerel değişkenin bildirilen tipi (ör. `void * uVar8` ↔ `int32_t uVar8`).
- **Etki:** iki koşunun çıktısı dosya yoluyla karşılaştırılamaz; adresle karşılaştırılmalı.
- **Kök neden, yerleşim (doğrulandı):** `karadul/reconstruction/c_project_builder.py:513-517`: komşu etiketleri bir `set` üzerinden sayılıyor, eşitlikte `most_common(1)` ilk geleni seçiyor; `set` sırası `PYTHONHASHSEED`'e bağlı. tree'nin çağrı grafıyla `PYTHONHASHSEED=1,2,3` üç farklı sonuç verdi; aynı tohum aynı sonucu verdi.
- **Kök neden, tip:** **doğrulanmadı**.

### 15. BSim eşzamanlı koşuda yedeğe düşüyor; ortak veritabanı değişiyor — uyarı

- **Ölçüm:** 82/117 Debian koşusu (paralel 3) "lite" kipine düştü; Mac'te (tek iş) 0. Aynı ikilinin iki koşusunda `bsim_shadow_functions` 4 710 ↔ 224. BSim "shadow" kipinde; adlara etkisi görülmedi (adlar aynı).
- **Yan etki:** her analiz `~/.cache/karadul/bsim/karadul_bsim.mv.db` dosyasına yazıyor. Kalem 7'deki 3 koşunun penceresinde (14:12–14:16) dosya 10,06 MB → 13,69 MB oldu; son yazma 14:16:31, redis-benchmark koşusunun bitişi 14:16:32.
- **Etki:** `bsim_shadow.json` içeriği, o makinede daha önce hangi ikililerin analiz edildiğine ve eşzamanlı koşu olup olmadığına bağlı.
- **Kök neden:** `karadul/ghidra/bsim.py`; satır **doğrulanmadı**.

### 16. `decompiled.json` kırpık; `engineering_analysis` doğrusal üstü — uyarı (ölçek)

- **Ölçüm:** 21/119 ikili (500'den çok fonksiyonu olanların hepsi); 25 640 kayıt eksik. `engineering_analysis` eğimi 2,70.
- **Etki:** tip kurtarma, Ghidra'nın değişken tiplerini yalnız ilk 500 fonksiyon için okuyor; bu 21 ikilide fonksiyonların %3–91'i (fonksiyon sayısına göre) bu bilgiden yoksun. Sonuca etkisi **ölçülmedi**. Eğim 2,70 ile 20 000 fonksiyonluk bir ikilide bu adım tek başına saatler sürer (dış değerleme; ölçülmedi).
- **Kök neden (kod okumasıyla):** `karadul/ghidra/headless.py:1055` `results[:500]`; okuyan `karadul/reconstruction/c_type_recoverer.py:1398-1404`. `engineering_analysis` için satır **doğrulanmadı**.

### 17. Her ada güven 1,0 — uyarı (bilinen; ölçüldü)

- **Saklı koşular:** `out/naming_map.json`'daki 15 679 c_namer girişinin 15 679'u 1,0. Köken kaydında 15 674'ü 1,0'dan düşük; 9 211'i 0,7 eşiğinin altında (hepsi `DAT_` veri adı, 0,30). Fonksiyon adları (6 461) 0,75–0,95.
- **Bugün:** ce1caf6 ile düzeldi. O kodla koşan 2 yeniden koşuda 1,0 yazılan giriş 0/44 ve 0/181.

### 18. Kripto ve diğer etiketler — uyarı (bilinen; ölçüldü)

- **Saklı koşular:** 12 172 `ALGORITHM:` etiketi, 8 666 fonksiyon, 117/119 ikili. Keccak/SHA-3 8 031, Poly1305 2 941, AES 610, GOST 236.
- **Bugün (ab986da):** tree 26 → 0, true 16 → 0, redis-benchmark 287 → 17 etiket.
- **Değişmeyenler (bugünkü 3 koşuda da aynı):** `intelligence_report.json`'da "OpenGL" 119/119 ikilide, "HTTPS" 112, "SHA-256" 107, "IPsec" 46. YARA: `AntiDebug_Timing` 23, `MPRESS_Packed` 13, `Delphi_Compiler` 2, `ASPack_Packed` 1. `anti_debug_top_technique` 14 arm64 ikilide `RDTSC_Timing` (RDTSC bir x86 komutu). Doğruluk yargılanmadı; aynı etiketin içeriğe bakmadan her ikilide çıkması tutarlılık bulgusudur.

### 19. Büyük fonksiyon `_partN.c` dosyalarına bölünüyor — not

- 11/119 ikili, 24 başlıksız dosya. 500 satırı aşan dosya (disassembly dökümü dahil) satır sayısına göre kesiliyor: `c_project_builder.py:581-613`. Kesim çoğunlukla disassembly yorumlarına denk geliyor. Kod gövdesinin ortasından bölünen 1 fonksiyon bulundu: `~/karadul_olcum/n1_debian13/zstd/zstd/out/src/src/subsystem_memory/FUN_001063c0_part1.c` (3 parça).

### 20. README yapısı ve yorumlardaki eski adlar — not

- README `src/main.c`, `src/modules/`, `src/types/` diyor; gerçek yapı `src/src/subsystem_*/` (119/119).
- Adı değişen 6 221 fonksiyonun 5 209'unun eski `FUN_` adı yorumlarda (`@called_by`, `@calls`) duruyor; aynı dosyanın `// Callers:` başlığı yeni adı kullanıyor.
- 117 ikilide haritada fonksiyon karşılığı olmayan 234 anahtar var (ör. `FUN_00105dc0 → start`; Ghidra'daki ad `entry`).

## 5. Kalem 7 — bugün çalışıyor mu

**Üç koşu, hepsi çıkış kodu 0.** Komut künyedekiyle aynı; ana ağaçtan `/opt/anaconda3/bin/python -m karadul analyze <elf> --skip-dynamic --output-dir <d>/ws --output <d>/out`.

| İkili | Süre (bugün / saklı) | En yüksek RSS | Kod | Çıktı |
|---|---:|---:|---|---|
| tree (250 fonk.) | 59,5 s / 61 s | 1,07 GB | 6eeff82 (a10fde3 + ab986da) | 281 dosya; saklı 284 |
| coreutils/true (239) | 42,6 s / 40 s | 1,07 GB | 6eeff82 + commit'lenmemiş `output_formatter.py`, `naming_labels.py` | 272 dosya; saklı 271 |
| redis-benchmark (892) | 167,3 s / 168 s | 1,21 GB | aynı | 937 dosya; saklı 939 |

- **Ağaç koşu sırasında değişti.** tree koşusu temiz ağaçla başladı; bitişinde `output_formatter.py` değişmiş, `naming_labels.py` eklenmişti (ana oturum, sonradan ce1caf6). tree çıktısı eski biçimlendiriciyi, diğer ikisi yenisini taşıyor (güven alanından belli). O anki dosya içeriğinin ce1caf6 ile aynı olduğu **doğrulanmadı**. Ana ağaçtan koşmanın bedeli bu; koşular bir commit'e bağlanamıyor.
- **Saklı çıktıyla fark:**
  - Ham Ghidra metni üçünde de birebir aynı (250/250, 239/239, 892/892).
  - Fonksiyon tanım adları üçünde de aynı (250/250, 239/239, 890/890). `naming_map.json` adları aynı.
  - Yorumlar atılınca kod: tree 250/250 aynı; true 226/239; redis-benchmark 788/890. Çakışma sonekleri (`result_12` ↔ `result_11`) de atılınca 239/239 ve 886/890. Kalan 4 fonksiyonun 3'üne elle bakıldı: parametre adı algoritma etiketine bağlıymış (`ciphertext` → `index_array`).
  - Farkın kaynağı: ab986da kripto etiketlerini kaldırdı; etiket satırları gidince yorum konumları 3 satır kaydı, bir yerel ad eksildi ve sonekler bir kaydı. Bunlar kod değişikliğinin sonucu; belirlenimsizlik değil.
  - Dosya yolu aynı kalan fonksiyon: 130/250, 155/239, 677/890 (kusur 14).
- **Bugünkü ağaçta duran kusurlar (saklı koşuyla aynı sayılar):** tree'de bozuk gövde 8, akışı değişen 14, iç içe yorum 18; true'da 1, 2, 22; redis-benchmark'ta 40, 66, 94 ve 2 eksik fonksiyon. Kök neden dosyaları değişmedi.
- **Temiz belirlenimcilik ölçümü** yeniden koşulardan değil, aynı kodla yapılmış üç saklı çiftten geliyor (Kalem 7 tablosunun ilk üç satırı): adlar %100 aynı; kod 9 292/9 299 fonksiyonda aynı; fark yerleşimde ve 7 fonksiyonda bir yerel tipte.
- **Öneriden sapma:** üçüncü ikili sqlite3 değil, redis-benchmark. Neden: sqlite3 koşusu kusur 4'teki indirme yolunu tetikliyor; tutarsa indirilen kaynağı derliyor. Boyut benzer (892 ↔ 1 144 fonksiyon).

## 6. Bilinen beş sorunun sayımı

| Bilinen sorun | Saklı 119 koşuda | Bugün |
|---|---|---|
| Her ada güven 1,0 | 15 679 / 15 679 c_namer girişi | ce1caf6 ile düzeldi (2 koşuda 0) |
| Kripto etiketleri | 12 172 etiket, 8 666 fonksiyon, 117 ikili | ab986da: 3 koşuda 329 → 17 |
| İkinci turda boş çıktıya "success" | 0/119 (en küçük çıktı 34 `.c`) | 0/3. İlgili bulgu: ikinci turun adları koda ulaşmıyor (kusur 7) |
| `subsystem_group_N` yerleşimi | Aynı kodla %34–94 aynı yol | Sürüyor; kök neden doğrulandı (kusur 14) |
| Geniş `except Exception` | Çıktıdan ölçülemez. Görünen yüz: günlük 37–40 satır, traceback 0, aşama hatası 0 | `grep -rn 'except Exception' karadul` = 588 (b0c972c'de sayıldı) |

## 7. Denetlenemeyenler

- **Adların doğruluğu:** kapsam dışı; GT'ye bakılmadı.
- **Derlenebilirlik:** derleyici çalıştırılmadı. Denetim sözcükseldir (yorum, dizgi, ayraç, parantez); tip ve bildirim hataları görülmez.
- **Akış anlamının tam kanıtı:** "akışı değişen" sayımı ham C metninden; denetim akış grafı kurulmadı. İhtiyatlı ve üst sınır birlikte verildi; 3 fonksiyon elle okundu.
- **Yutulan hatalar:** günlükte iz yok; kaç hatanın `except` içinde kaybolduğu çıktıdan sayılamaz.
- **Bellek:** saklı koşularda kayıt yok. Yalnız bugünkü 3 küçük koşuda ölçüldü (1,07–1,21 GB). Büyük ikililerde bellek sınırına yakınlık ölçülmedi.
- **3 MB'tan büyük ikili, x86-64, PE, yönetilen biçimler:** veri yok. C++ tek ikiliyle temsil ediliyor.
- **Ağ isteklerinin gerçekten çıkıp çıkmadığı** (kusur 4) ve **decompile yarışının** yeniden üretimi (kusur 2b).
- **`decompiled.json` kırpmasının tip kurtarmaya etkisi** (kusur 16).
- **`report.html` ve arayüz:** içerik denetlenmedi; yalnız dosyanın varlığına bakıldı.
- **Temiz commit'e bağlı yeniden koşu:** ana ağaç koşu sırasında değiştiği için yapılamadı (§5).
- **`kosu.log` dışındaki günlükler:** yok; `logging` çıktısı dosyaya alınmamış.

## 8. Yeniden üretim

```
python docs/arge/2026-11-10_cikti_saglamligi/denetle.py            # 126 koşu, 3 işçi, ~2 dk
python docs/arge/2026-11-10_cikti_saglamligi/denetle.py --yalniz debian/tree --json /tmp/x.json
```

- Yollar ve eşikler betiğin başında adlandırılmış sabit (`DEBIAN_KOK`, `MAC_ANA_ETIKET`, `GUVEN_ESIGI`, `TUR_ZAMAN_ASIMI_S`…).
- `sonuc.json`: `kosular[]` (ikili başına `k1`–`k6`, `kusur`, `ornek`), `ozet` (kusur × program, ölçek eğimleri, uyarı türleri), `ciftler[]` (kalem 7), `depo_durumu`.
- Diskte bırakılanlar: bu dizindeki 3 dosya; `~/karadul_olcum/runs/saglamlik-2026-11-10/{tree,true,redis-benchmark}` (122 MB; her birinde `kunye.json`, `zaman.txt`, `kosu.log`). Aracın kendi yan etkisi: `~/.cache/karadul/bsim/karadul_bsim.mv.db` +3,6 MB.
