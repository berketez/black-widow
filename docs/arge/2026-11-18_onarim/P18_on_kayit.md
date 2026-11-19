# P18 ön kayıt — Kalem 3: Ghidra `undefinedN` tiplerinin öntanımı

Yazıldı: 2026-11-19, değişiklikten ve yamalı ölçümden ÖNCE. Ağaç `2c7a1de` (P18 Kalem 2a; tip kodu `main` = `39aca9c` ile aynı).

## Soru
`c_type_recoverer._UNDEFINED_DEFAULTS` bağlam kanıtı olmayan her `undefinedN`'i bir tamsayı tipine çeviriyor (`undefined1/2/4/8/undefined` → `uint8_t / uint16_t / int32_t / uint64_t / uint64_t`). P09'un ölçümü (D, 23 ikili): DWARF hizalı parametrelerde Karadul'un değiştirdiği 8 115 tipin 4 450'si Ghidra'dan kötü, 1 568'i iyi; kötüleşenlerin hemen hepsi bu öntanımdan (`undefined8` → `uint64_t`, DWARF'ta işaretçi). Ghidra'nın `undefinedN`'i "N bayt, türü bilinmiyor" der ve yanlış değildir; `uint64_t` bir tamsayı iddiasıdır.

## Seçenekler
- **A (bugünkü):** öntanım tamsayı tipine çevirir.
- **B:** öntanım yok; kanıtsız `undefinedN` Ghidra'nın adıyla kalır. `include/types.h`'deki `typedef`'ler yalnız ayrıştırıcı / IDE okusun diye kalır (tür iddiası değil); `undefined` Ghidra'da 1 bayttır → `typedef uint8_t undefined;` (bugün `void*`, yanlış boyut).
- **C:** belirsizliği koruyan ayrı ad (ör. `unk64_t`). Bilgi içeriği B ile aynı; analistin tanıdığı Ghidra adı yerine yeni bir ad uydurur. B bir şeyi bozmadıkça (ayrıştırma, sonraki adımlar) C seçilmez.

## Ölçüm
`scripts/measurement/p09_olc.py kos` (Ghidra'sız yeniden oynatma; XTRIDE dahil), birleşik koşu `~/karadul_olcum/runs/urun-onarim-a62f15e`, DWARF hizalaması olan 22 ikili (`t0b-1acba60/hizalama`; P09'un D kümesi). İki etiket aynı girdiyle: `A` = bu ağaç, `B` = bu ağaç + `yamalar/P18__c_type_recoverer.py.patch` (`_UNDEFINED_DEFAULTS` boş). Kök: `~/karadul_olcum/runs/onarim-2026-11-19/P18/k3/`.

## Öngörüler (sayılar ölçümden önce)
- **H1:** B'de DWARF `kotulesen` A'nınkinin en çok %5'i (öntanım kaynaklı kötüleşmelerin hepsi düşer; kalan çıkarım katmanlarından).
- **H2:** B'de DWARF `iyilesen` düşer (öntanımın doğru tahminleri de kaybolur); düşüş A'daki öntanım kaynaklı iyileşmeyle sınırlı.
- **H3:** Çıkarım değişimleri (`degisim.sayac.cikarim`, `double_yeni`, `genislik_bozan`, `somut_ezilen`) A ile B'de aynı ±%2 (öntanım çıkarım katmanlarını beslemiyor). Tutmazsa B'nin yan etkisi ayrıca okunur (XTRIDE `undefinedN`'i "boş" sayıp daha çok tip yazabilir).
- **H4:** `ontanim` sınıfı B'de 0.

## Karar kuralı
A'da öntanımın DWARF'la sınanabilen değişimlerinde yanlış / (yanlış + doğru) ≥ 0,5 ise öntanım analisti doğrudan çok yanıltıyordur → **B** (H1 ve H3 tutarsa). Oran < 0,5 ise A kalır, ölçüm kayda geçer. H3 tutmazsa karar, yan etkinin okunmasından sonra verilir ve gerekçesi yazılır.

Uygulama: `c_type_recoverer.py` bu paketin dosyası değil → yama (`yamalar/P18__c_type_recoverer.py.patch`). Bu paketin dosyalarında karara uyum: `c_project_builder` `types.h` (`undefined` boyutu + açıklama), `output_formatter._clean_c_source` (yedek yol) aynı kararı izler.
