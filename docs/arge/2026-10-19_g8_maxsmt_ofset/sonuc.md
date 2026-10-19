# G8: MaxSMT ofset çıkarımının doğrulanması

- **Tarih:** 2026-10-19
- **Plan:** v2 §5 G8 ("MaxSMT ofset hatasının doğrulanması"), §2 madde 4. Düzeltme G19'da.
- **Girdi:** tmux 3.8, taban v2 koşusu (`taban-v2-62ad154`, Ghidra 12.1.2), `pcode.jsonl` sha256 `c18f887a43b6e1ea…` (tamamı `sonuc_tmux.json`'da).
- **Betik:** `maxsmt_ofset.py`. Ürünün kendi kodunu çağırır: `PcodeAnalyzer.analyze_streaming` ve `computation_struct_recovery._extract_accesses_per_function`. Yeni bir çıkarım yazmaz; ürünün çıkardığını sayar.

## Şüphe

`karadul/pipeline/steps/computation_struct_recovery.py` (`_extract_accesses_per_function`), LOAD/STORE işleminin girdileri arasında 0-4095 aralığındaki **ilk sabiti** alanın ofseti sayıyor. Oysa p-code'da LOAD ve STORE'un 0. girdisi adres uzayının kimliğini taşıyan bir sabittir. Gerçek alan ofseti, 1. girdiyi (adresi) üreten `INT_ADD`/`PTRSUB` işlemindedir (Onuncu Adam İ2).

## Sonuç: şüphe doğrulandı

| Sayı | Değer |
|---|---|
| Fonksiyon | 2821 |
| LOAD/STORE işlemi | 30 839 |
| Ürünün çıkardığı bellek erişimi (LOAD/STORE + PTRADD) | 39 555 |
| LOAD/STORE'un 0. girdisindeki sabit | **hepsinde 433** (`ram` uzayının kimliği) |
| Ofseti 0. girdiden alınan LOAD/STORE | **30 839 / 30 839** |
| Ofset = 433 olan erişim | 30 840 (çıkarılan erişimlerin %78,0'ı) |
| Farklı ofset sayısı | 261 |

Sonraki en sık ofsetler 1, 2, 4, 6, 3 (1717, 1036, 706, 539, 524). Bunlar PTRADD'dan geliyor. PTRADD'ın girdileri taban, indis ve öğe boyutudur; bu sayılar da alan ofseti değil, indis ya da öğe boyutu olabilir. Bu deneyde ayrıştırılmadı.

## Yorum

- MaxSMT yapı çözücüsüne giden LOAD/STORE erişimlerinin hepsi aynı sahte ofsette (0x1b1) görünüyor. Çözücünün bu girdiyle doğru bir yapı yerleşimi kurması mümkün değil.
- Ürüne bugünkü etkisi: adım isteğe bağlı (`enable_computation_struct_recovery`) ve adayları tüketen yol ölü (kod haritası §Faz 2). Yani bugün kullanıcı çıktısını bozmuyor. Ama Faz 1'deki tip ve yapı izi (G14-G17) bu çıkarıma dayanırsa bütünüyle yanlış veriyle başlar.
- G19 düzeltmesi: ofset, LOAD/STORE'un 1. girdisini üreten işlemden (taban + sabit) alınmalı; var_name de yüklenen değerden değil taban işaretçiden. Düzeltmenin testi bu tabloyu kullanabilir: düzeltmeden sonra 433 ofset kalmamalı.
