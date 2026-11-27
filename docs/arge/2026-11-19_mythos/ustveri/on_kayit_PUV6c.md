# P-ÜV6c ön kaydı (Go tutarlılık damgası, okuyucu düzeltmeleri, yanıltıcı "kısmi")

Yazıldığı an: 2026-11-27 22:35, ölçümden ÖNCE (kod henüz yazılmadı). Sayılar ve eşikler ana oturumun
(`docs/arge/2026-11-23_dalga1/gonderim/PUV6c.md` "Ön kayıt"); bu belge onları aynen kaydeder ve yöntemi
adıyla yazar. Tutmayan beklenti silinmez; eşik sonradan değişmez.

**Tek değişiklik (ana oturumun 27 Kasım eki, `ORTAK_D1.md` §7):** H1'in S8 tabanı
`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_ed28e36b` (gönderim metnindeki `s8_taban_534e252b`, HZ2'nin
`bsim_detail.scan_mode` alanı yüzünden bayat). Sayılar değişmedi. Kökte `BITTI` yokken tabanla kıyas yapılmaz.

## Beklentiler (aynen)

> H1 (bayrak kapalı): S8'in 2 ikilisinde (cat, mac/tmux; taban `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/s8_taban_ed28e36b`)
> çıktı tabanla aynı; Ollama'nın Ghidra'sız yeniden oynatmasında (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_kabul/ws`;
> salt okur) Go ad adayları 10 475 ve hepsinde `olculmedi`.
>
> H2 (bayrak açık, Ollama, Ghidra'sız yeniden oynatma): `cift_kaynak` 3 907, `tek_kaynak` 6 568 ± 130, `tutarsiz` 0
> (PUV7'nin okuyucu düzeyi sayımı: 10 600 adın 3 907'si çift, 6 693'ü tek; ad kanalına giren 10 475); yazılan ad 10 475;
> ikili kararı `temiz`; rapora uyarı 0.
>
> H3 (okuyucu düzeltmesi): Ollama ve docker-cli'de `ozgun_ad` kümesi düzeltmeden önce ↔ sonra aynı (fark 0); `paket`
> alanı değişen fonksiyon sayısı Ollama 4, docker-cli 264 (PUV7'nin sayımı; ± 0 değilse nedenini yaz).
>
> H4 (bozuk üst veri; PUV7'nin bozma düzeneği `scripts/measurement/ustveri_bozma.py`, A türü, `gh`, Ghidra'sız kanal
> sınaması): ikinci kaynaklı 66 fonksiyon `tutarsiz` damgası alır ve adı YAZILMAZ; ikinci kaynaksız 134 fonksiyonun bozuk
> adı yazılır (beklenen sınır; kayda geçer); ikili kararı `uyari`, rapora uyarı 1.
>
> H5 (yanıltıcı hata): Ollama'nın yeniden oynatmasında statik aşamanın hata listesinde "evrensel ikilide go dilimi"
> iletisi 1 → 0 (bilgi satırına iner); yeni okuyucu kapalı kolda 1 kalır. (Statik aşamayı Ghidra'sız yeniden
> oynatamıyorsan birim / bütünleşme testiyle göster ve "ürün koşusunda ölçülmedi" yaz.)
>
> H6: üst veri kaynaklı hiçbir ad `kesin` etiketi taşımaz (damga ne olursa olsun).

## Yöntem (ölçümden önce sabitlenir)

- **Ghidra'sız yeniden oynatma (H1'in Ollama yarısı, H2, H5):** girdi `ANA/ollama_kabul/ws/workspaces/Ollama/20261124_101017`
  (salt okunur): `static/ghidra_functions.json`, `raw/Ollama_arm64` (ürünün ince dilimi), `raw/target_info.json`.
  Akış ürün kodunun kendisi: `go_metadata_recovery` adımının okuma + damga yolu (bayrak kapalı / açık) →
  `_feedback_naming_candidates.add_k4_channels` (Go ad kanalı açık) → `_feedback_naming_merger.validate_merged_names` →
  `metadata_decision` (köken alanları; `ust_veri_dogrulama` sayımı buradan) → `reporting.report_data._naming_labels`
  (rapora uyarı sayımı; yeniden oynatmanın sahte `reconstruct` sonucu yalnız bu sayaçları taşır). Statik aşamanın
  iletisi için `stages._note_universal_special_slices` gerçek `target_info.json`'dan kurulan hedefle çağrılır,
  ardından adım aynı bağlamda koşar (H5). Betik koşu kökünde (`PUV6c/betik/`), commit'lenmez; yalnız sayılar
  `PUV6c/ozet/` altında.
- **H1'in S8 yarısı:** ürün koşusu (`urun_kos.py`, kendi dalımın ürün ağacı, bayraklar öntanım = kapalı), cat ve mac/tmux;
  karşılaştırma `scripts/arge/hiz/s8_esitlik.py` (P-ÜV6b'nin H1'i gibi `naming_map` + `decompiled/*.c` + `out/src`;
  `compile_commands.json`'daki mutlak yol farkı ayrıca yazılır). Ghidra kuyruğu dolu kalır ya da zaman yetmezse
  "koşulmadı" yazılır; birim testi bayrak kapalı kolun bayt eşitliğini ayrıca kilitler.
- **H3:** aynı ikilide okuyucunun eski kuralı (`paket_adi`, `runtime.funcpkgpath`) ↔ yeni kural; `ozgun_ad` = `ad`
  alanı (adres, ad) kümeleri karşılaştırılır; `paket` farkı sayılır. Girdiler: Ollama `raw/Ollama_arm64` (yukarıdaki
  çalışma alanı), docker-cli `~/karadul_olcum/ustveri_set/docker-cli/bin` (keşif ikilisi; sınama ikilileri açılmaz).
- **H4:** `ustveri_bozma.py`'nin A türü (tohum 20261119, 200 fonksiyon) aynı örneklemle bellekte; bozuk görüntü ürünün
  okuma + damga yoluna verilir; ad kanalına Ghidra dizini olarak "her fonksiyon adsız" sahte dizin (Ghidra'sız kanal
  sınaması; PUV6a'nın H6'sı gibi). Sayılan: bozulan 200'ün ikinci kaynaklı / kaynaksız kırılımı, kanalın aday ↔ kanıt
  satırı kararı, ikili kararı, rapor uyarısı.
- **H6:** H2 / H4 akışlarında köken kaydının `label` alanı; ek olarak birim testi + mutant.
- Süreler "yük altında" etiketli ve `uptime` künyeli yazılır (üç ajan birlikte çalışıyor).
