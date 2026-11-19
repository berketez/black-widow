# Paket: OLGU — fonksiyon başına olgu tablosu ve kapsam bütçesi (A1)

Opus ölçüm paketi. Önce `ORTAK_BRIF.md` (bu paket hat değil; "yasak cevap / aykırı öncül" bölümleri sana uygulanmaz, öbür bütün kurallar uygulanır).

## Amaç

Taban ürün koşusunun (a62f15e, 119 ikili) **bütün** fonksiyonları için fonksiyon başına tek satırlık bir olgu tablosu. Üç araştırma hattı (KİMLİK, ÖZ KOD, ÖLÇÜ) bu tabloyu Ghidra'ya dokunmadan sorgulayacak. İlk çıktısı liste A1'in kapsam bütçesidir.

## Dosyaların

- Betik: `scripts/arge/olgu/olgu_tablosu.py` (+ gerekirse aynı dizinde yardımcı modül)
- Sınama: `scripts/arge/olgu/test_olgu_tablosu.py` (pytest; `tests/` altına yazma)
- Çıktı: `~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` (+ birim başına parçalar istersen)
- Belgeler: `docs/arge/2026-11-19_mythos/olgu/SEMA.md`, `BUTCE.md`, `DEFTER.md`
- Başka hiçbir dosyaya dokunma. Git'te durumu değiştiren komut yok.

## Kalemler

1. **Girdiyi tanı.** `~/karadul_olcum/runs/urun-onarim-a62f15e/<platform>/<birim>/<ikili>/{out,ws}` altındaki dosyalar (fonksiyon listesi, çağrı grafiği, `ghidra_strings.json` ve `xrefs`, P-code dökümü, ad haritası ve köken kaydı) ve GT (`scripts/measurement/ks1_olc.py`: `gt_elf`, `gt_mac`, `GtBirimi`; `urun_olc.py`). Ölçüm betiklerinin fonksiyonlarını içe aktararak kullan, kopyalama.
2. **Çekirdek alanlar** (satır = ikili + adres): birim, ikili, platform, adres, boyut (bayt ve varsa komut sayısı), thunk mı, GT adı / adları, nüfusta mı (`GtBirimi.nufus`), Ghidra'nın verdiği ad, ürünün verdiği ad + kanal + alt kanal + hüküm (doğru / yanlış; `urun_olc` ile aynı tanım).
3. **Tutarlılık kapısı (zorunlu).** Tablodan yeniden hesaplanan toplamlar taban ölçümüyle birebir tutmalı: nüfus 21 371; ad verilen 1 800; doğru 1 681; yanlış 119; nüfusta doğru 1 212; birim başına sayılar `sonuc.md` §2 tablosuyla aynı. Tutmuyorsa nedenini bul; tutmadan sonraki kaleme geçme.
4. **Kaynak sınıfı (ELF, dbgsym'den).** Fonksiyonun derleme birimi yolu (DW_AT_name, comp_dir), `DW_AT_external`, bildirildiği dosya. Buradan sınıf: gnulib (`lib/` ve benzeri; kalıpları veriden çıkar ve `SEMA.md`'ye yaz), programa gömülü üçüncü taraf dizini (`deps/`, `contrib/`, `third_party/` …), programın kendi kodu, derleyici / çalışma zamanı. Mac'te DWARF yoksa alan `bilinmiyor`; uydurma.
5. **Kanıt alanları.** Fonksiyonun doğrudan andığı dizgiler (metin; uzun olanı kırp ve kırptığını işaretle); çağırdığı fonksiyonlar (adres; içe aktarım ise adı; ürün adı varsa o); çağıranlar (adres); yaprak mı.
6. **Kayıt çiftleri.** (a) Veri bölümünde fonksiyonun adresinin durduğu her yer için: yer adresi ve aynı kaydın komşu yuvalarındaki (± 4 işaretçi genişliği) dizgi işaretçilerinin gösterdiği dizgiler. (b) Çağrı yerinde birlikte geçen dizgi sabiti ve fonksiyon işaretçisi argümanı (P-code dökümünden çıkarılabiliyorsa; çıkarılamıyorsa alanı `desteklenmiyor` yaz ve nedenini deftere not et). Koşu çıktısında yoksa ikiliden (`~/karadul_olcum/n1_debian13/`, Mach-O) doğrudan oku; ELF yeniden konumlandırma kayıtlarını (RELATIVE) hesaba kat.
7. **Kapsam bütçesi (`BUTCE.md`).** Kaynak sınıfı × (nüfus, bugün doğru, bugün yanlış, kanal kırılımı). Ek kırılımlar: boyut dilimi, yaprak / değil, doğrudan dizgisi var / yok, kayıt çifti var / yok, birim. GT adı yazma; yalnız sayılar.
8. **Sınama.** Küçük sentetik girdiyle birim testleri (şema, hüküm, kayıt çifti çıkarımı, RELATIVE yeniden konumlandırma); tutarlılık kapısı betikte `--dogrula` olarak koşulabilir olsun.

## Kurallar

- Ghidra koşma; var olan çıktıları ve ikili dosyaları oku.
- Sayılar betikten; `BUTCE.md`'deki her tablo betiğin çıktısı.
- `SEMA.md`: her alanın tanımı, kaynağı (hangi dosya, hangi fonksiyon), bilinen eksikler.
- Kalem 3 ve 7 bitince `DEFTER.md`'ye `## ARA TESLİM: çekirdek + bütçe hazır` yaz (öbür hatlar beklemeden kullanmaya başlar); sonra 5–6'yı tamamla.
- Son mesaj: özet + yollar + `## PAKET BİTTİ`.
