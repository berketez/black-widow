# P05 — ön kayıt (anlamsal parametre adlandırıcısı: MUH-01, MUH-02, MUH-11)

Bu belge `karadul/` kodu değişmeden ÖNCE yazıldı ve commit'lendi. Taban sayıları ölçüm betiğinin değişmemiş kodla (07a3fc3) ürettiği değerlerdir ve `P05.md`'ye yazılır; "sonra" sayıları her kalemden sonra aynı betikle, aynı girdilerle alınır. Bir beklenti tutmazsa "tutmadı" yazılır; eşik ya da hüküm kuralı sonradan değiştirilmez.

**Önceden görülen (gizli değil):** kayıtlı çıktı sayımı (`p05_olc.py say`, `urun-yeni2-f30ac9a` ve `genel-tarama-2026-11-18`) ve ön denemede dört ikilinin (cat, tee, tree, htop) taban yeniden oynatması. htop'ta taban kodun 234 adından DWARF'a göre 2'si tam, 21'i yakın, 196'sı yanlış çıktı. Yani bu kanal bugün çoğunlukla yanlış ad veriyor; aşağıdaki beklentiler bunu bilerek yazıldı.

## 1. Araç ve girdiler
- Betik: `scripts/measurement/p05_olc.py` (tanımlar betiğin başında).
  - `say`: kayıtlı ürün çıktısında `out/src` imzalarındaki `<ad> /* was: param_N */` adları ve `reconstructed/param_naming_map.json` adları.
  - `kos`: kayıtlı koşunun çalışma dizinindeki girdilerle (`reconstructed/struct_recovered/*.c`, `ghidra_functions.json`, `ghidra_call_graph.json`, `algorithms.json` + `engineering_algorithms.json`, `signature_matches.json`) ölçülen ağacın `SemanticParameterNamer.rename`'ini koşar. Ghidra koşmaz.
- **Yeniden oynatma doğrulaması (koşul):** değişmemiş kodla yeniden oynatılan `param_naming_map.json`'ın `functions → renames` kısmı kayıtlıyla aynı olmalı (`dogrulama: ayni`). 119 ikilinin hepsinde aynı değilse aynı olmayanlar ölçümden ayrı raporlanır.
- **Set Y:** `~/karadul_olcum/runs/urun-yeni2-f30ac9a` (119 ikili; 1.22.1; `semantic_namer.py` ve `semantic_naming.py` f30ac9a ile 07a3fc3 arasında değişmedi).
- **Set D (DWARF):** Y'nin T0b hizalama belgesi olan 22 ikilisi (`~/karadul_olcum/runs/t0b-1acba60/hizalama`; belgenin `ghidra_ikili_sha256`'sı `urun_kos.isleri_topla` sha256'sıyla aynı olmalı, değilse o ikilide hüküm yok).
- **Set G (kayıtlı HEAD):** `~/karadul_olcum/runs/genel-tarama-2026-11-18` (14 ikili, 1.23.1); yalnız `say`.
- **Uçtan uca örnek:** en çok 14 ikili, `urun_kos.py --paralel 1` ile (P05 kodu); `urun_olc.py olc/karsilastir` taban kolu `urun-yeni2-f30ac9a` (aynı anahtarlar).
- Çıktı: `~/karadul_olcum/runs/onarim-2026-11-18/P05/`.

## 2. Ölçüler
- **Kusurlu ad** (`ad_sinifi`): `gecersiz`, `anahtar`, `tip` (ürünün `name_validity.lexical_reject_reason(local=True)` kuralları), `ghidra_oto` (Ghidra'nın kendi ad biçimi: `DAT_`, `PTR_`, `FUN_`, `local_`, `uVarN` …), `govde_cakismasi` (yalnız `kos`: yeni ad fonksiyonun girdi kodunda başka bir tanımlayıcı olarak zaten geçiyor).
- **Matris / vektör adı** (`matris_vektor`): `(M|K|A)_matrix`, `(v|u|phi)_vector`, `_N` ekli biçimleri dahil.
- **DWARF hükmü** (D): `tam`, `yakin`, `yanlis` (kural betiğin başında; `tam`: normalize ad eşitliği; `yakin`: ortak belirteç ya da en az 3 harflik önek). Hükümsüz: `gt_yok`, `imza_uyusmadi`. "Doğru ad" = `tam` + `yakin`.
- **Kaynak başına** (`kaynak_hukum`): `sig_db_params`, `signature_based`, `algorithm_template`, `call_graph_propagation`, `struct_context`, `call_context`, `type_heuristic`.

## 3. Onarımın ilkesi (ölçümden önce sabit)
- Koda yazılan her parametre adı TEK kapıdan geçer, sıra: (1) ürün eşiği, (2) ad geçerliliği (`name_validity.lexical_reject_reason(local=True)`; yerel ad kuralı), (3) Ghidra'nın kendi ad biçimi reddedilir, (4) çakışma: ad fonksiyonun kodunda (dizgi/yorum örtülü) zaten geçiyorsa ya da aynı fonksiyonda başka parametreye verildiyse `name_validity.unique_name` ile `_2`, `_3` … eki (c_namer'ın yerel ad kuralı), (5) köken kaydı.
- Bir parametrenin en iyi adayı kapıdan geçemezse sıradaki aday denenir; hiçbiri geçemezse parametre adsız kalır (Ghidra adı).
- **Eşik:** yerel ad için ürünün eşiği `config.min_confidence.c_namer_apply` (0,15; c_namer'ın yerel adlara uyguladığı değerle aynı). Genel ad eşiği (0,7) yerel adlara uygulanmaz: c_namer de uygulamıyor. Bugünkü adayların hepsi ≥ 0,40 olduğu için **bu eşiğin ad düşürmesi beklenmez**; adlandırıcının güvenleri ölçülmemiş sabitlerdir. Eşiği kanal başına ölçülen kesinlikle değiştirmek bu paketin işi değildir (aynı veriyle eşik seçmek aşırı uyum olur); ölçülen kesinlik `P05.md`'ye öneri olarak yazılır.
- **Yayılım (MUH-01):** çağıranın argümanı ayraç dengeli ayrıştırılır; yalnız düz tanımlayıcı (`^[A-Za-z_]\w*$`) olan ve çağıranda değişken olarak bildirilmiş (parametre ya da yerel bildirim) argüman ad verir. Sabit, dizgi, cast, adres alma, ifade, küresel ad vermez.
- **Döngü derinliği (MUH-02):** derinlik yalnız `for` / `while` / `do` gövdeleri sayılarak hesaplanır; parametre adı tam sözcük olarak aranır. `double *` şablonları (matris, vektör, skaler başvuru) parametrenin tipi `double *` / `float *` değilse ancak parametre üstünde kayan noktalı erişim (`(double *)` / `(float *)` cast'i) görülürse uygulanır.
- Kanal susturulmaz (K-2): bayrak kapatılmaz, kaynak silinmez.

## 4. Beklentiler
**Kalem 1 — tek ad kapısı + yayılım (MUH-11, MUH-01).**
- Y'de yeniden oynatmada kusurlu ad (`gecersiz` + `anahtar` + `tip` + `ghidra_oto` + `govde_cakismasi`) = 0, 119 ikilinin hepsinde. Tutmadı: herhangi bir ikilide > 0.
- Kabul edilen her ad için köken kaydı var: köken kaydındaki kabul edilen ad sayısı = `total_renamed` (her ikili). Tutmadı: bir ikilide eşit değil.
- `param_naming_map.json`'da her adın `source`, `confidence`, `reason` alanı var.
- D'de `yanlis` sayısı düşer. Tutmadı: düşmezse.
- D'de doğru ad (`tam` + `yakin`) kaybı: kaybedilen her ad `karsilastir` çıktısında tek tek listelenir. Doğru ad toplamı tabanın %10'undan fazla düşerse "K-2 kaybı" olarak ana oturuma bildirilir; onarım geri çekilmez, eşik gevşetilmez.

**Kalem 2 — döngü derinliği (MUH-02).**
- Y'de coreutils (106 ikili) `matris_vektor` = 0. Tutmadı: > 0.
- Y'nin geri kalanında kalan her `matris_vektor` adı tek tek okunur; her birinde kayan noktalı erişim kanıtı bulunmalı. Tutmadı: kanıtsız bir tane bile.
- Birim testi: üç katlı döngüde `*(double *)(param + …)` erişimli `double *` matris çarpımında `M_matrix` adı korunur; `if` içinde kullanılan `ulong` parametre `M_matrix` / `v_vector` almaz.
- D'de doğru ad değişimi Kalem 1 kuralıyla raporlanır.

**Uçtan uca (ürün koşusu, P05 kodu, ≤ 14 ikili).**
- Fonksiyon adları değişmez: `urun_olc.py karsilastir` (taban `urun-yeni2-f30ac9a`) yanlış ve doğru fonksiyon adı sayıları aynı. Bu paket fonksiyon adına dokunmuyor; fark çıkarsa kaynağı (P05 mi, aradaki başka değişiklik mi) yazılır.
- `out/src` imzalarındaki `/* was: param_N */` adlarında kusurlu ad = 0; `naming_provenance.json`'da parametre adı bölümü var ve kayıt sayısı `param_naming_map.json`'daki ad sayısına eşit.

## 5. Kapsam dışı (bilerek)
- `CALLER_NAME_HINTS`'in iki yönlü alt dizgi eşleşmesi (MUH "Küçükler"; bugün zararsız gözlendi): yalnız kapıdan geçer, kural değişmez.
- `api_param_db.propagate_params` (strateji 5'in kaynağı; AD-02 / P12) ve `c_namer.py` (P12).
- Kanal başına eşik ayarı (yukarıda gerekçesi).
- `masum_kapi_esik.json`'a yazılmaz.
