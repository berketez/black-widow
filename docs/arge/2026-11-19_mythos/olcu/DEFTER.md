# ÖLÇÜ hattı — defter (tur 1, 2026-11-19)

Sıra: en yeni kayıt en altta. Her sayı bir betiğin çıktısıdır; betik ve komut yanında.
Hat dizini `docs/arge/2026-11-19_mythos/olcu/`, betikler `scripts/arge/olcu/`, veri `~/karadul_olcum/runs/arge-2026-11-19/olcu/`.

## 0. Okunanlar

- `ORTAK_BRIF.md`, `HAT_OLCU.md`, `YON.md`, soru listesi §1–§2, B1–B5, G1–G4, §4–§6, `2026-11-19_birlesik_olcum/sonuc.md`.
- `etiket_rehberi.md` (rubrik sürüm 2), `2026-10-19_g4_etiketleme/{onkayit,sonuc}.md`.
- `test_seti_kilidi.md` ve `dogrulama_seti_kilidi.md`: yalnız program listeleri ve kurallar (kilitli program adlarını tanımak için). `targets/` altına girilmedi, listelenmedi.
- `yontem_taramasi.md` §2.2, §2.3, §3.1, §5.

## 1. Etiket envanteri (kalem 1) — ölçüme bakmadan yazıldı

**İlk ve en önemli bulgu: depoda tek bir insan etiketi yok.** Var olan bütün hükümler Claude Opus ajanlarının (vekil değerlendirici) hükümleridir. Hat metni "insan hükmüyle uyum" diyor; bu turda ölçülebilen şey "vekil (model) hükmüyle uyum"dur ve belgelerde hep böyle adlandırılacak. Kanıt:

- G4 (`docs/arge/2026-10-19_g4_etiketleme/sonuc.md` başlık ve §8): "üç Claude Opus 5.5 ajanı (L1, L2, L3), vekil değerlendirici. İnsan değerlendirme G32'de."
- P15c (`~/karadul_olcum/runs/onarim-2026-11-18/P15c/etiket_gelistirme.json` `yontem` alanı): "etiketci P15c ajani, tek etiketci, kor DEGIL".
- 15 Ekim sürüm 1 dosyalarında insan için ayrılmış `etiket` alanı 201 / 201 satırda boş (tmux 100, htop 101); dolu olan alanlar `etiket_claude` (15 + 15) ve ayrı ajan dosyası (`etiket_ajan_*`). Sayım: bu defterin §1 altındaki komut.

Set aidiyeti doğrulaması (ortak brif §2.3): aşağıdaki kümelerin hepsi geliştirme seti programlarıdır (tmux, htop, coreutils, zstd, openssl, sqlite3, redis-tools, tree). Kilitli programların (test: unzip, memcached, dash, dcraw, gifsicle, mawk, dnsmasq, gpg, nasm, rsync, ssh, zsh, vim, git, haproxy + stres + yedekler; doğrulama: mosquitto, newlisp, pspg, kalign, timidity, nagios, joe, gnugo, alpine, gnome-builder + stres + yedekler) hiçbiri bu etiket dosyalarının künyelerinde geçmiyor. Kilitli sete ait etiket kümesine rastlanmadı.

| Küme | Kaynak dosya | Program / platform | Ürün sürümü ve kanal | Rubrik | Etiketçi | Kör mü | Üçlü sayısı |
|---|---|---|---|---|---|---|---|
| G4-L1-tmux | `docs/arge/2026-10-19_g4_etiketleme/veri/{anahtar_tmux_385_kor.json, etiket_L1_tmux385.jsonl}` | tmux 3.8, Mac | `taban-v2-62ad154` (eski ürün; adların çoğu dizgiden) | v2 | L1 (Opus ajanı) | kör | 385 (+39 yem) |
| G4-L3-tmux | `…/{anahtar_tmux_200_kor.json, etiket_L3_tmux200.jsonl}` | tmux, Mac | aynı | v2 | L3 | kör | 200 (+20 yem); 88'i L1 ile ortak |
| G4-L2-tmux-gt | `…/{anahtar_tmux_200_gt.json, etiket_L2_tmux200gt.jsonl}` | tmux, Mac | aynı | v2 | L2 | GT adı görünür | 200 (+20 yem); L3 ile aynı öğeler |
| G4-L3-htop | `…/{anahtar_htop_kor.json, etiket_L3_htop.jsonl}` | htop 3.5.3, Mac | aynı | v2 | L3 | kör | 97 (+10 yem) |
| P15c | `~/karadul_olcum/runs/onarim-2026-11-18/P15c/{etiket_gelistirme.json, ozellik_gelistirme_T.json}` | 12 ikili: zstd 55, openssl 49, sqlite3 41, redis-cli 21, mac/tmux 18, debian/tmux 12, mac/htop 10, debian/htop 8, pzstd 7, ls 6, tree 5, sort 4 | imza VT `call_pattern` / `string_ref` (adsız fonksiyona rol adı) | v2 | P15c ajanı | GT adı görünür | 236 kayıt, 220 tekil (ad, GT) çifti |
| V1-ajan | `workspaces/2026-10-15_oturum_scratchpad/tarif/{etiket_tmux.jsonl, etiket_ajan_tmux.jsonl, etiket_htop.jsonl, etiket_ajan_htop.jsonl}` | tmux, htop, Mac | 15 Ekim ürünü | **v1** (yanlış fiil `yalniz_alan`) | ajan (+ ana oturum 15'er satır) | kör (`kor_*.jsonl`) | 100 + 101 |

Sayım komutları (bu oturumda koşuldu; çıktılar yukarıdaki tabloda):
- `python3 -c "…"` ile `ozellik_gelistirme_T.json`: 236 kayıt; etiket dağılımı yanlis 168, yalniz_alan 44, dogru_tarif 24; 220 tekil çift.
- V1: `etiket` alanı dolu 0 / 100 ve 0 / 101; `etiket_claude` dolu 15 ve 15; ajan dağılımı tmux yanlis 41, yalniz_alan 30, dogru_tarif 16, tam 13; htop yanlis 65, yalniz_alan 32, dogru_tarif 4.
- Bu sayımlar `scripts/arge/olcu/etiket_topla.py` ile yeniden üretilir (aşağıda).

Etiket dosyalarının sha256'sı (bu oturumda `shasum -a 256`): L1 `8e4207db…`, L3-tmux `1c67207a…`, L3-htop `2bd5cff5…`, L2 `4de0fec0…` (dördü `donma.log` ile aynı); P15c `974bb953…` (P15c.md ile aynı); P15c özellik `ff70e360…`; V1 ajan tmux `ae41caa3…`, htop `2fe8f609…`.

Kullanılmayanlar: `v0/etiket_ajan_v{0,1}_*.jsonl` (tarif prototipinin aday adları; ürün çıktısı değil); N0b ayrı etiket üretmedi (G4-L1'i kullandı); P12b ayrı etiket üretmedi (G4-L1'in 76 kebap öğesi).

**Yapısal sınır (döngüsellik):** yasak cevap "dil modeli hakem"dir. Elimizdeki tek hüküm kaynağı dil modeli olduğu için, bu turda bir ölçünün "hükümle uyumu" aslında "model hakemle uyum"dur. Bu, ölçüyü doğrulamaz; yalnız aday ölçüleri sıralar ve insan etiketleme paketinin boyutunu belirlemeye yarar. İnsan doğrulaması PLAN'daki etiket paketine bağlıdır.

## 2. Bölme kararı (sayılara bakmadan; ortak brif §2.4)

Bu satırlar hiçbir ölçü–etiket ilişkisi hesaplanmadan yazıldı. O ana kadar gördüğüm çiftler: dosya biçimine bakarken ekrana düşen ilk birkaç satır (G4-L1'in ilk 3 öğesi, V1'in ilk 2'şer öğesi, P15c'nin ilk 3 çifti ve 2 kaydı). Sözlük bu çiftlere göre yazılmadı.

- **AYAR:** G4-L1-tmux (385, kör). Ölçü seçimi, eşik ve ağırlık yalnız burada.
- **SINAMA-A (başka program, başka değerlendirici, kör):** G4-L3-htop (97).
- **SINAMA-B (başka programlar, başka kanal, başka değerlendirici, GT görünür):** P15c 220 tekil çift. tmux çiftleri (ayar programı) dahil ve hariç ayrı raporlanır.
- **SINAMA-C (aynı program, başka değerlendirici, kör):** G4-L3-tmux'un L1 ile ortak olmayan öğeleri (200 − 88 = 112). Program ayar kümesiyle aynı; bağımsız sayılmaz, yalnız değerlendirici etkisini gösterir.
- **TAVAN:** L1 ∩ L3 ortak 88 öğe: bir değerlendiricinin hükmü öbürünü ne kadar öngörüyor. Hiçbir ölçünün bunu aşması beklenmez.
- **EK (karar dışı):** V1-ajan (rubrik v1; yalnız yakın / değil hedefi), G4-L2-tmux-gt (cömertlik kipi).
- Birim: ayar tek program (tmux). Sınama birimleri: htop; P15c'nin tmux dışı programları. 106 coreutils ikilisi tek birim kuralı burada yalnız P15c'nin 10 coreutils kaydını etkiler (ls 6 + sort 4 → tek birim).

**Hedefler (ikili):**
- `yakin` = etiket ∈ {tam, dogru_tarif} ("amaç doğru"; Berke'nin gevşek modu).
- `yaniltmaz` = etiket ≠ yanlis (analisti yanıltmayan; `yalniz_alan` dahil).
- Normalleştirme sonrası aday = GT olan çiftler (tam eşit) birincil çözümlemenin dışındadır: her ölçü onlara 1 verir ve AUC'yi şişirir. İkincil satırda dahil hâli de verilir.

## 3. Aday ölçüler (tanım ayar kümesine bakmadan donduruldu)

Tanımlar `scripts/arge/olcu/olcu.py` içinde; sözlük `scripts/arge/olcu/sozluk.json` (sha256 betik çıktısında). Sözlüğün kaynağı: bu ajanın C adlandırma geleneklerinden önsel yazdığı liste; hiçbir etiket kümesine bakılarak yazılmadı; literatürdeki karşılığı CodeWordNet (SymLM, Jin+ 2022) ama o indirilemediği için kullanılmadı (indirme yasağı). Sözlük küçük ve tutucudur: zıt anlamlı fiiller (get/set, alloc/free, open/close, create/destroy …) hiçbir kümede birleştirilmez; ayrıca ayrı bir "zıt fiil" listesi vardır (rubrik kural 4'ün mekanik karşılığı).

Ölçüler (hepsi [0, 1]):
- `tam`: ürünün bugünkü hükmü (tam eşitlik; karşılaştırma tabanı).
- `norm_tam`: normalleştirilmiş belirteç dizisi eşit.
- `P`, `R`, `F1`, `J`: belirteç kümesi kesinliği / duyarlılığı / F1 / Jaccard (sözlüksüz).
- `Ps`, `Rs`, `F1s`: sözlüklü (kısaltma açılımı + eşanlam kümesi + önek kısaltması).
- `duz`: normalleştirilmiş dizgide Levenshtein benzerliği (1 − uzaklık / en uzun).
- `Pic`: içerikli belirteç kesinliği — genel belirteçler (`handle, process, do, run, helper, main, func, sub, data, info, …`; rubrik kural 6–7) payda ve paydan düşülür; aday yalnız genel belirteçse 0.
- `Pz`, `F1z`: zıt fiil vetosu — aday ile GT'de karşılıklı zıt fiil varsa 0, yoksa `Ps` / `F1s`.
- `as_k`: asimetrik birleşik: `Pz` × [GT'nin baş fiili ya da son belirteci adayda karşılanıyor mu: 1, yoksa k]; k ∈ {0, 0,5} iki değişken (`as0`, `as5`).

## 4. Ön kayıt (ölçümden önce)

Tuttu / tutmadı ölçütleri önceden; beklentim ayrıca yazılı (tahmindir, sayı değildir).

- **Ö1 (aykırı öncül 1, hedef `yakin`).** İddia: tam eşit olmayan çiftlerde AUC(`P`) > AUC(`F1`). Ölçüt: sınama havuzunda (A + B + C, tam eşitler hariç) eşli önyükleme (2 000 tekrar, tohum 20261119) ile AUC(P) − AUC(F1) farkının %95 aralığı. Aralık tümüyle > 0 ise **tuttu**; tümüyle < 0 ise **tutmadı**; sıfırı içeriyorsa **ayırt edilemedi**. Aynısı sözlüklü çift (`Ps`, `F1s`) için.
  - Beklentim: `yakin` hedefinde **tutmaz** (kısa / yalnız alan adları P = 1 alır, `yalniz_alan` etiketini `yakin` sanar).
- **Ö2 (aykırı öncül 1, hedef `yaniltmaz`).** İddia: AUC(`P`) > AUC(`F1`), aynı ölçütle.
  - Beklentim: **tutar ya da ayırt edilemez** (yanıltmayan adın belirteçleri GT'nin alt kümesidir).
- **Ö3 (kullanılabilir ölçü var mı).** Ayar kümesinde her ölçü için eşik: tam eşit olmayan çiftlerde "ölçü ≥ t" kabulünün `yakin` kesinliği ≥ 0,90 olan en düşük t (yoksa ölçü elenir). Seçilen ölçü: bu eşikte en çok `yakin` yakalayan. Sınama havuzunda aynı eşik tek okuma. **Tuttu:** kabul edilenlerin `yakin` kesinliği nokta ≥ 0,85 ve Wilson alt ≥ 0,70, kabul sayısı ≥ 20. Kabul < 20 ise **ölçülemedi**.
  - Beklentim: **ölçülemedi ya da tutmaz** (tam eşit olmayan `yakin` çiftleri az; eşanlamla doğru adlar sözcük ölçüsüne görünmez).
- **Ö4 (yanıltıcılık süzgeci).** Seçilen asimetrik ölçünün "ölçü = 0 → yanlış" kararı: sınama havuzunda ölçüsü 0 olan çiftlerin en az %85'i `yanlis` etiketli (Wilson alt ≥ 0,80). Beklentim: tutar.
- **Ö5 (aykırı öncül 2a: tam eşitliğin "yanlış" dediklerinin bir kısmı amaçça doğru).** Ayar ve sınama kümelerinde tam eşit olmayan çiftlerin `yakin` oranı. Öncül "tuttu" sayılır: oranın Wilson alt sınırı > %5 (en az iki kümede). Taban koşusunun 119 yanlışı için hüküm yok (etiket yok); orada yalnız ölçü dağılımı verilir.
  - Beklentim: G4'te tutar (~%8–9), P15c'de tutar (~%10), htop'ta tutmaz.
- **Ö6 (aykırı öncül 2b: ikizler).** Etiketsiz mekanik sınama: aynı ikilide **başka bir fonksiyonun** GT adı, bir ölçüye göre "yakın" çıkıyor mu? Her ikili için GT adlarının rastgele değil, tam çift taraması: fonksiyon f'in adı yerine aynı ikilideki g ≠ f'in adı konsa ölçü ≥ t olan (f, g) çiftlerinin payı = **ikiz kabul oranı**. Öncül "tuttu" sayılır: seçilen eşiklerde `F1` için fonksiyonların en az %10'unun en az bir ikizi var (yani eşik üstü başka adı). `P` ve `F1` ayrı raporlanır.
  - Beklentim: tutar (gnulib `quotearg_*`, `x*alloc*` aileleri); `P`'de `F1`'den kötü.
- **Ö7 (taban koşusu).** 119 yanlışın seçilen ölçüye göre "yakın" payı. Beklentim: < %15; çoğu `oz_ad` yanlışı sıfır örtüşmeli.

Tutmayan beklenti silinmez.

## 5. Ölçümden önce eklenen kesinleştirmeler (hâlâ hiçbir ölçü–etiket ilişkisi hesaplanmadı)

- Sözlük donduruldu: `scripts/arge/olcu/sozluk.json` sha256 `85711dc615f6787189ee7b37d583fa9f70bd76b3e83176f83b863d86a858a46d` (181 kısaltma, 35 eşanlam kümesi, 32 zıt çift, 38 genel belirteç). İlk yazımdan sonra, veriyle hiçbir şey koşulmadan 5 kısaltma (`sum, cat, stat, pid, ts`) ve eşanlam kümelerindeki `to / from` çıkarıldı (yanlış eşleşme riski; önsel karar).
- Ölçü kitaplığı: `scripts/arge/olcu/olcu.py`. Yalnız rehberdeki örnek çiftlerle (değerlendirme kümesinden olmayan `session_free | session_destroy` vb.) denendi.
- Envanter betiği koşuldu: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/etiket_topla.py --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcu` → `etiketler.jsonl` (1 319 ana üçlü + 89 yem), `etiket_envanteri.json`. Küme başına etiket dağılımı (yemsiz): G4-L1-tmux 385 (tam 46, doğru tarif 30, yalnız alan 134, yanlış 175); G4-L3-tmux 200 (16 / 15 / 75 / 94); G4-L2-tmux-gt 200 (16 / 17 / 52 / 115); G4-L3-htop 97 (0 / 4 / 14 / 79); P15c 236 kayıt, 220 tekil çift (0 / 24 / 44 / 168); V1-ajan-tmux 100 (13 / 16 / 30 / 41); V1-ajan-htop 101 (0 / 4 / 32 / 65). L1 ∩ L3 tmux ortak 88. İnsan etiketi 0.
- **Ö4'ün "seçilen asimetrik ölçü"sü için seçim kuralı (önceden):** {`P`, `Ps`, `Pic`, `Pz`, `as0`, `as5`} içinde AYAR kümesinde `yaniltmaz` hedefinde AUC'si en yüksek olan (eşitlikte bu sıradaki ilk).
- **Ö1 / Ö2 önyüklemesi:** sınama havuzu A + B + C; yeniden örnekleme küme içinde tabakalı; tam eşit çiftler (normalleştirilmiş) hariç. P15c'de birim tekil (aday, GT) çiftidir (220).
- **Tavan tanımı:** L1 ∩ L3 ortak öğelerde (tam eşitler hariç) bir değerlendiricinin dört düzeyli etiketini sıralı puan (yanlış 0, yalnız alan 1, doğru tarif 2) sayıp öbürünün ikili hedefini öngörme AUC'si; iki yön.

## 6. İlk ölçüm: ROC / AUC (kalem 2)

Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/roc.py --etiketler ~/karadul_olcum/runs/arge-2026-11-19/olcu/etiketler.jsonl --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/roc.json` ve `bantlar.py` (aynı girdiyle → `bantlar.json`). Ortak sabitler `scripts/arge/olcu/sabitler.py`.

Ham sonuç (tam eşit olmayan çiftler; vekil hüküm):
- `yakin` hedefinde AUC: AYAR 0,72–0,81 (en iyi `Rs` ve `duz` 0,811); sınama havuzu 0,72–0,79 (en iyi `as5` 0,790); tmux'suz sınama 0,67–0,76. Değerlendiriciler arası tavan (L1 ∩ L3, 80 öğe): 0,961 / 0,993.
- `yaniltmaz` hedefinde AUC: AYAR 0,63–0,76; sınama havuzu 0,64–0,72; tavan 0,84.
- **Ö1 (P > F1, `yakin`): sınama havuzunda ayırt edilemedi** (fark −0,002; aralık −0,010 … +0,005). AYAR kümesinde tutmadı (−0,032; −0,056 … −0,012: F1 daha iyi). Beklentim "tutmaz" idi; sınamada fark sıfırdan ayrılamadı.
- **Ö2 (P > F1, `yaniltmaz`): ayırt edilemedi** (−0,002; −0,005 … +0,002). Beklentim "tutar ya da ayırt edilemez" idi.
- **Ö3: hiçbir ölçü ayar kümesinde 0,90 kesinliğe ulaşamadı → bütün ölçüler elendi; seçilecek eşik yok.** En yüksek eşiklerde bile kabul edilenlerin `yakin` payı %25–%40 (bant tablosu). Beklentim "ölçülemedi ya da tutmaz" idi; sonuç daha sert: ölçü eşik bile veremiyor.
- **Ö4 (sıfır puan → yanlış): tutmadı.** Seçilen asimetrik ölçü `Pic` (AYAR'da `yaniltmaz` AUC'si en yüksek). Sınama havuzunda puanı 0 olan 300 çiftin 240'ı `yanlis` (%80,0; Wilson %75,1–%84,1); eşik nokta ≥ %85 ve alt ≥ %80 idi. 9'u (%3,0) `yakin`. Beklentim "tutar" idi; **tutmadı**.
- **Ö5 (tam eşit olmayanların bir kısmı amaçça doğru): tuttu.** `yakin` oranı AYAR 30 / 339 (%8,8; %6,3–%12,4), A 4 / 97 (%4,1; %1,6–%10,1), B 22 / 220 (%10,0; %6,7–%14,7), C 11 / 104 (%10,6; %6,0–%18,0). Wilson alt sınırı üç kümede > %5 (ölçüt: en az iki küme).

Neden olmadı (ayar kümesinin örnekleri; geliştirme seti):
- **Aday ⊂ GT (belirteç kesinliği 1, duyarlılık < 1):** AYAR'da 64 çift; yalnız 14'ü `yakin`, 19'u (%29,7) `yanlis`. Örnekler: `window_pane_add` ↔ `window_pane_add_ref`, `cmd_run_shell` ↔ `cmd_run_shell_free`, `status_message` ↔ `status_message_set`, `input_csi_dispatch` ↔ `input_csi_dispatch_rm`, `event_payload_free` ↔ `event_payload_free_target`. Eksik kalan tek belirteç fonksiyonu kardeşlerinden ayıran belirteç; değerlendirici "işin kendisinin adı yardımcıya verilmiş" ya da "getter gibi okunuyor" diyor (rubrik kural 3–4).
- Yani **aykırı öncül 1'in güçlü biçimi ("kesinlik analistin zararını ölçer") vekil hükümle çelişiyor**: bütün belirteçleri doğru olan ad, eksik bıraktığı belirteç yüzünden yanıltıcı sayılıyor.
- **Uzlaşı cevabı (F1 ≥ 0,5):** AYAR'da kabul edilen 90 çiftin 21'i `yakin` (%23,3; %15,8–%33,1), 24'ü `yanlis` (%26,7). Sınama havuzunda 41 kabulün 12'si `yakin` (%29,3; %17,6–%44,5), 8'i `yanlis`.
- **Ayrık ve yakın:** `utf_wctomb` ↔ `utf8_fromwc`, `utf_mbtowc` ↔ `utf8_towc`: sözcük ölçüsü göremiyor (kitaplık kavramı üstünden eşanlam).

## 7. Yeni hipotez (ayar kümesinin örneklerinden doğdu; sınama kümelerinin örneklerine bakılmadan yazıldı)

Gözlem: yanılgıların ortak biçimi "aday, bu fonksiyonun adına benziyor ama **aynı ikilideki başka bir fonksiyonun adına daha çok ya da eşit derecede** benziyor". Mutlak benzerlik yerine **göreli** ölçü: ad, fonksiyonu kardeşleri arasında ayırt ediyor mu?

Tanım (ikili içi, GT adlarının tamamı üstünde; eşik yok, sözlük dışında parametre yok):
- `b(f)` = F1s(aday, GT(f)); `r(f)` = max over g ≠ f of F1s(aday, GT(g)) (g: aynı ikilide adresi farklı bütün GT fonksiyonları; takma adlar en yüksekle).
- `ayirt` = b − r ∈ [−1, 1] (ayırt edicilik payı).
- `kimlik` = b, eğer b > r (aday en çok bu fonksiyona benziyor, tek başına); yoksa 0.
- `kimlik_R` = aynı kapı, ama taban benzerliği Rs (GT belirteçlerinin karşılanma oranı).

Ön kayıt:
- **Ö8a:** sınama havuzunda (tam eşit hariç) `yakin` hedefinde AUC(`kimlik`) > AUC(`F1s`); eşli tabakalı önyükleme aralığı tümüyle > 0 ise tuttu. Beklentim: tmux ağırlıklı kümelerde (C) tutar; P15c'de kazanç küçük (adların çoğu ayrık); havuzda "tuttu ya da ayırt edilemedi".
- **Ö8b:** "kimlik ≥ 0,5" kabulünün `yakin` kesinliği "F1s ≥ 0,5" kabulünden yüksek (sınama havuzu; betimsel, aralıklı). Beklentim: yüksek ama 0,85'e ulaşmaz.
- **Ö8c (Ö3'ün tekrarı, yeni ölçüyle):** AYAR'da `kimlik` için 0,90 kesinlik veren eşik var mı? Varsa sınama havuzunda Ö3'ün ölçütüyle tek okuma. Beklentim: yok.
- Önkoşul denetimi: G4 anahtarındaki (adres → GT) çiftleri `workspaces/olcum_mac` GT'siyle aynı ikiliye ait mi (adres ve ad eşleşmesi); değilse GT ad listesi G4 anahtarının kendisinden alınamaz (yalnız örneklem var) ve ölçü hesaplanamaz.

## 8. Ayırt edicilik ölçüsü (Ö8) — sonuç

Önkoşul: G4 ve P15c üçlülerinin adres ve GT adı, taban dökümünün GT listesiyle eşleşti (1 312 / 1 319; 7'si `pzstd`, C++ olduğu için GT listesi dışı; uyuşmayan ad 0). Taban dökümü: `taban_dok.py` (komut betiğin başında) → `taban_a62f15e.json`; betik `urun_olc` sayılarını yeniden üretiyor (1 800 / 1 681 / 119; nüfus 21 371).

Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/kimlik.py --etiketler …/etiketler.jsonl --taban …/taban_a62f15e.json --json …/kimlik.json`.

- **Ö8a: tutmadı.** Sınama havuzunda AUC(`kimlik`) − AUC(`F1s`) = −0,143 (−0,224 … −0,062). Kapı `yakin` adların çoğunu da sıfırlıyor (AYAR'da 27 örtüşen `yakin`in 14'ü kapıdan geçemiyor: aday iki kardeşe eşit uzaklıkta). Beklentim "tuttu ya da ayırt edilemedi" idi; **tutmadı**.
- **Ö8b (betimsel):** "kimlik ≥ 0,5" kabulü sınama havuzunda 12 çift, 9'u `yakin` (%75; Wilson %46,8–%91,1), 0'ı `yanlis`; "F1s ≥ 0,5" kabulü 48 çift, 17'si `yakin` (%35,4), 8'i `yanlis`. AYAR'da kimlik 33 kabul, 13 `yakin` (%39,4), 3 `yanlis`; F1s 102 kabul, 24 `yakin`, 26 `yanlis`. Kesinlik yükseliyor ama 0,85'e ulaşmıyor; kabul sayısı küçük.
- **Ö8c: eşik yok.** `kimlik` için AYAR'da en yüksek kesinlik 0,43 (eşik 0,857, 14 kabul).
- Kapının asıl ayırdığı şey `yanlis`: örtüşen çiftlerde kapıdan geçenlerin yanlış oranı AYAR'da 3 / 33 (%9,1; %3,1–%23,6), geçmeyenlerde 57 / 160 (%35,6); sınama havuzunda 0 / 13 (Wilson üst %22,8) ve 47 / 110 (%42,7). Örneklem küçük: **yön gösterici**.
- Neden olmadı: "ayırt etme" koşulu amaç doğruluğu için ne gerekli ne yeterli. Gerekli değil: `alerts_timer_reset` adayı `alerts_reset` ile `alerts_timer`'a eşit uzaklıkta, ama değerlendirici doğru tarif diyor. Yeterli değil: kardeşi olmayan fonksiyonda her örtüşen ad kapıdan geçer.

## 9. Taban koşusunun yeniden puanlanması (kalem 4) ve ikiz yoğunluğu (Ö6, Ö7)

Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/taban_puanla.py --taban …/taban_a62f15e.json --json …/taban_puan.json`.

**Beklenmeyen bulgu (ölçüm sırasında görüldü, sonradan eklendi; ön kayıtlı değil):** 119 yanlışın örneklerine bakınca zstd adlarının GT adının küçük harfli hâli olduğu görüldü (`fse_builddtable_internal` ↔ `FSE_buildDTable_internal`). Belirteçleme deve yazımını GT'de bölüp adayda bölemediği için F1s 0,75 çıkıyordu. Bunun üzerine belirteçlemeden bağımsız bir düzey eklendi: `olcu.harf_tam` (derleyici eki ve `_N` çakışma eki soyulur, küçük harf, harf-rakam dışı atılır; dizi eşitliği). Bu, rubrik sürüm 2'nin `tam` tanımının ("yalnız biçim farkı olabilir: alt çizgi, büyük/küçük harf, `_2` gibi çakışma eki") mekanik karşılığıdır; insan hükmü gerektirmez. Etiketli kümelerde "tam eşit sayılmayan ama `harf_tam`" çift sayısı 0 (rubrikle çelişki yok).

- **119 yanlışın 40'ı yalnız biçim farkı** (`bicim`): 37'si zstd, coreutils 1, openssl 1, mac/tmux 1; hepsi `string_context/oz_ad`. Kalan 79: `kimlik_adayi` 9, `ortusen_diger` 47, `ayrik` 23.
- Yanlış oranı iki hükümle (aynı betik; makro `urun_olc` kuralıyla, taban sayısını yeniden üretiyor): **tam eşitlik** havuz 119 / 1 800 (%6,6; %5,5–%7,8), makro %31,0 (zstd %83,6); **tam + biçim** havuz 79 / 1 800 (%4,4; %3,5–%5,4), makro **%19,1** (zstd %16,4; sqlite3 %58,3 değişmedi).
- `string_context/oz_ad`: 197 adın 93'ü tam, 40'ı biçim → 133 / 197.
- **Ö7: tutmadı.** Beklentim "119 yanlışın < %15'i yakın, çoğu sıfır örtüşmeli" idi. Sıfır örtüşmeli yalnız 23 / 119 (%19,3); uzlaşı eşiği (F1s ≥ 0,5) 61 / 119'u (%51,3) "yakın" sayardı; biçim düzeyi tek başına 40 / 119 (%33,6).
- **Başka hat / onarım için not:** `oz_ad` dizgiden aldığı tanımlayıcıyı küçük harfe çeviriyor; zstd'nin %83,6'lık yanlış oranının 37 / 46'sı bu. Ad özgün yazımıyla bırakılırsa tam eşitlikte de doğru olur (ürün tarafı; ÖZ KOD hattı ya da P12d ile birlikte ön kayıtlı küçük paket).

**Ö6 (ikiz yoğunluğu, etiketsiz): tuttu.** Ad bekleyen 21 371 fonksiyonun 16 305'inin (%76,3) aynı ikilide, GT adı kendi GT adıyla F1 ≥ 0,5 olan başka bir fonksiyon var; F1 ≥ 0,8 için 6 987 (%32,7); adının kırpılmış hâli başka bir fonksiyonun adı olan 6 995 (%32,7). tmux'ta F1 ≥ 0,5 ikiz oranı %96–97. Yani "F1 ≥ 0,5 yakındır" kuralı, nüfusun dörtte üçünde bir fonksiyona kardeşinin adını versek de "yakın" der. Beklentim "tutar" idi.

## 10. Karar kuralı taslağı (kalem 5), literatür ölçüsü (kalem 3), örnek sayısı (kalem 6)

- `karar.py` (komut betiğin başında) → `karar.json`. Kayıp modeli: doğru ad 0, boş 1, kanıt satırı e, yanlış ad L, doğru aile a = 0,25, yanlış aile L; p = kanal kesinliğinin Wilson alt sınırı. Ad düzeyinin başa baş oranı L* = 1 / (1 − p_alt): gnulib 192, ELF önyükü 120, `main` 29,7, `ks1:func_kalibi` 11,9, `ks1:func_aktarma` 9,6 (n = 33), `oz_ad` 1,68 (tam) / 2,54 (tam + biçim), `ks1:assert_ust` 1,56 (n = 7). "Yanlış ≤ %10" hedefi L = 10'a, "kesin ≥ %95" L = 20'ye denk.
- `literatur_olcusu.py` → `literatur_olcusu.json`: NERO tanımıyla taban koşusu: ad verilen 1 800 fonksiyonda mikro P 0,959 / R 0,930 / F1 0,944; ad bekleyen 21 371 fonksiyonun tamamında (ad verilmeyen = boş tahmin) mikro P 0,947 / R 0,049 / F1 0,094, makro F1 0,058.
- Literatür tanımları doğrulandı (2026-11-19): NERO arXiv 1902.09122 (ar5iv HTML, değerlendirme bölümü); SymLM CCS 2022 PDF (yazar sayfası) §5 "Evaluation Metrics" (denklem 16–17) ve CodeWordNet eşleştirme paragrafı; SymGen NDSS 2025 PDF §VI-A ve Ek F (`ftp_timeleft_accept` örneği: P 0,67, R 0,50, F1 0,57). PDF'ler `pdftotext` ile okundu; içerik veri sayıldı.
- `ornek_sayisi.py` → `ornek_sayisi.json`: Wilson yarı genişlik ±0,05 için beklenen oran 0,10'da n = 141, 0,30'da 320, 0,50'de 381; ±0,03 için 384 / 892 / 1 063. Kappa ±0,10: κ 0,8 ve yaygınlık 0,30'da 168, yaygınlık 0,10'da 412. Tabakalı (örtüşen / ayrık, Neyman) tahminci ±0,03 için 343 → 255 (sınama havuzunun vekil oranlarıyla; yön gösterici).
- Yerel araçlar (komut `command -v`): `clang` (Apple clang 21.0.0), `docker`, `rustc`, `swiftc` var; `gcc-12/13/14`, çapraz GCC ve `go` yok.

## 11. Yeni hipotez Ö9 (hesaplamadan önce yazıldı): ayırt edici belirtecin duyarlılığı

Gözlem (§6): yanılgı, adayın **eksik bıraktığı** belirteçten geliyor ve o belirteç fonksiyonu kardeşlerinden ayıran belirteç. Aykırı öncül 1'in tersi: zararı kesinlik değil, **ayırt edici belirteçlerin duyarlılığı** ölçer.

Tanım: ikilideki GT adları üstünde belirteç başına `idf(t) = ln(N / df(t))` (N: GT fonksiyon sayısı; df: adında t geçen fonksiyon sayısı). `Ridf` = adayın (sözlüklü) karşıladığı GT belirteçlerinin idf toplamı / GT belirteçlerinin idf toplamı. `F1idf` = `Ps` ile `Ridf`'in harmonik ortalaması.

Ön kayıt:
- **Ö9a:** sınama havuzunda (tam eşit hariç) `yakin` hedefinde AUC(`Ridf`) > AUC(`Rs`) ve AUC(`F1idf`) > AUC(`F1s`); eşli tabakalı önyükleme aralığı tümüyle > 0 ise tuttu. Beklentim: küçük artı fark, "ayırt edilemedi".
- **Ö9b:** AYAR'da `Ridf` ya da `F1idf` için 0,90 kesinlik veren eşik var mı? Beklentim: yok.
- Sınama kümeleri bu turda üçüncü kez okunuyor (Ö1–Ö5, Ö8, Ö9); hiçbirinde eşik ya da ağırlık sınama kümesinden seçilmedi, ama çoklu okuma kaydı burada.

## 12. Ö9 sonucu ve turun kapanışı

Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/idf.py --etiketler …/etiketler.jsonl --taban …/taban_a62f15e.json --json …/idf.json`.

- **Ö9a: ayırt edilemedi.** Sınama havuzu, `yakin`: AUC(`Ridf`) − AUC(`Rs`) = +0,001 (−0,007 … +0,008); AUC(`F1idf`) − AUC(`F1s`) = +0,002 (−0,004 … +0,007). Beklentimle aynı.
- **Ö9b: eşik yok.** AYAR'da `Ridf` = 1,0 olan (GT'nin bütün belirteçlerini karşılayan) 10 tam eşit olmayan çiftin yalnız 5'i `yakin`: fazladan belirteç de yanıltıyor (`sixel_parse_attributes` ↔ `sixel_parse`, `alerts_timer_expired` ↔ `alerts_timer`).
- Neden olmadı (dört denemenin ortak sonucu): asimetrik kesinlik (Ö1–Ö2), fiil kapısı (`as0`), ayırt edicilik (Ö8), idf ağırlıklı duyarlılık (Ö9) düz belirteç F1'ini / duyarlılığını geçemedi. Sözcük ailesi ölçülerinin `yakin` AUC'si sınama havuzunda 0,72–0,79 bandında doyuyor; değerlendiriciler arası tavan 0,96–0,99. Kalan fark anlamsal: eksik belirteç de fazla belirteç de, tek belirteçlik fark da (getter / setter, işin kendisi / yardımcısı) hükmü değiştiriyor ve bu ayrım ad dizgilerinden okunamıyor (fonksiyonun ne yaptığını bilmek gerekiyor).

### Tur sonu: yaratıcılık protokolü denetimi (tek satır)

1. Denetlenebilir soru: uygulandı (her iddia ön kayıtlı, betikle sayıldı; hüküm kaynağı vekil olduğu için "insan uyumu" iddiası yok).
2. Uzlaşıyı kır: uygulandı (yasak cevap ölçülüp çürütüldü: F1 ≥ 0,5 kabulünün `yakin` kesinliği %23–%35; verilen aykırı öncül de çürüdü; üç yeni aykırı ölçü denendi, üçü de tutmadı).
3. Tek hatta kal: uygulandı (başka hatlara yalnız not: `oz_ad` küçük harf; ikiz yoğunluğu KİMLİK için).
4. İnsan uzman: uygulanamadı (insan etiketi yok); PLAN'ın ilk paketi bu.

### Başka hatlar için notlar

- **ÖZ KOD / onarım:** `string_context/oz_ad` dizgiden çıkardığı tanımlayıcıyı küçük harfe çeviriyor; 104 yanlışının 40'ı yalnız bu (zstd 37). Özgün yazım korunursa tam eşitlikte doğru olur.
- **KİMLİK:** ad bekleyen nüfusun %76,3'ünün aynı ikilide F1 ≥ 0,5 ikizi, %32,7'sinin F1 ≥ 0,8 ikizi var (`taban_puan.json` `ikiz`). Kimlik eşlemesinde "yakın ad" hiçbir belirteç eşiğiyle başarı sayılamaz; ikiz çiftleri ancak tam eşitlik (ya da biçim düzeyi) ayırır.
- **OLGU:** `taban_a62f15e.json` ikili başına bütün GT adlarını ve ürünün adlarını (kanal, hüküm) taşıyor; olgu tablosuyla adres anahtarı aynı biçimde (onaltılık, öneksiz).

### Yapılmayanlar (PLAN'a taşındı)

- B5 (kanal çatışması): taban koşusunun köken kayıtlarından aday düzeyinde döküm alınmadı; ölçüm yok.
- B2 (kalibrasyon, Brier / ECE): doğrulama seti kilitli; geliştirme setinde güven = ölçülmüş kesinlik olduğu için döngüsel; tasarım PLAN'da.
- G1 için hiçbir yeni ikili koşulmadı (Ghidra koşusu yok, indirme yok); yalnız tasarım ve indirme listesi.

## 13. OLGU ara tesliminden sonra: örnek / tekil ayrımı

Ana oturumun bildirimi: nüfusun 11 393'ü (%53,3) coreutils'teki gnulib kopyası, tekil nüfus 9 257. Bunun üzerine `tekil.py` yazıldı (komut betiğin başında) → `tekil.json`. Tekil nüfus 9 257 ve tekil ad 535 yeniden üretildi (`sonuc.md`'nin 422 / 535'iyle aynı).

- İkiz yoğunluğu tekilde F1 ≥ 0,5: %87,5; F1 ≥ 0,8: %34,7 (örnekte %76,3 / %32,7).
- Tekil ad düzeyinde yanlış: tam 113 / 535 (%21,1), tam + biçim 73 / 535 (%13,6).
- Kanal alt sınırları tekilde: gnulib 10 / 10 (0,723), ELF önyükü 30 / 30 (0,887), `main` 6 / 6 (0,610). Karar tablosu iki düzeyde de verildi (BULGULAR §7).
- Set tasarımına etkisi: birim = tekil kaynak fonksiyonu; coreutils türü çok ikilili paketler tek birim; örnek sayısı hesapları tekil üstünden.

## 14. "Zaman kısıtı yok" düzeltmesinden sonra (Berke, ana oturum üzerinden): ertelenen kalemler bu turda yapılıyor

Ana oturumun üç bildirimi: (1) OLGU tablosu hazır (§13); (2) PLAN kendi başına uygulanabilir olacak (uygulayan Opus ajanları, bu ajan orada yok); (3) hiçbir kalem atlanmayacak, yalnız verisi gerçekten olmayan "açık ölçüm" kalır. Bu yüzden §12'de "yapılmayanlar"a yazılan B5 ve B2 şimdi ölçülüyor; ayrıca 1.22.1 kolu, KİMLİK hattının yanlış eşlemeleri, ROC noktaları ve AUC aralıkları ekleniyor.

- **1.22.1 kolu (f30ac9a) yeniden puanlandı** (`taban_dok.py --agac ~/karadul_olcum/urun-f30ac9a --kok ~/karadul_olcum/runs/urun-yeni2-f30ac9a …` → `taban_yeni2_f30ac9a.json`; `taban_puanla.py` → `taban_puan_yeni2.json`): 2 261 ad, 1 589 tam, biçim 47, kimlik adayı 33, örtüşen öbür 350, ayrık 241, GT'siz 1; tam + biçim yanlış 625 / 2 261 (%27,6), makro %40,8 (tam eşitlikte %52,8; zstd %86,2 → %20,0).
- **KİMLİK hattının yanlış eşlemeleri** (`kimlik_hatalari.py`; girdi KİMLİK'in `hata_dok_{kural,tutucu}.json`'u, salt okunur): "kural" noktasında dökümdeki 174 yanlış eşlemenin (sınıf sayımı 283; tmux listesi kırpık) 94'ü F1 ≥ 0,5 (%54,0; %46,6–%61,3), 54'ü F1 ≥ 0,8 (%31,0), 57'si ayrık, **0'ı biçim** (%0; üst %2,2). "tutucu" noktasında 135 örnekte 88 / 55 / 33 / 0. Yani kimlik eşlemesinin yanlışlarının yarısından çoğu uzlaşı eşiğiyle "yakın" sayılırdı; biçim düzeyi hiçbirini kabul etmiyor.

### Ön kayıt: Ö10 (çatışma, B5) ve Ö11 (kalibrasyon, B2) — hesaplamadan önce

Veri: taban koşusunun `naming_provenance.json` kayıtları. Her uygulanan adda `runners_up` (en çok 3: strateji, ad, güven) var; ad verilmeyen fonksiyonların aday listesi tutulmuyor (yalnız sayaç) → o taraf ölçülemez.

- **Ö10a (betimsel):** uygulanan 1 800 adın kaçında en az bir yedek aday kimlik iddiası taşıyor (jenerik değil: `function_f1.is_generic_name`) ve kazananla harf dizisi farklı (çatışma)? Beklentim: çoğu yedek `cleanup_<adres>` türü jenerik; gerçek çatışma < 300.
- **Ö10b:** kazananı yanlış (tam + biçim değil) olan 79 adın kaçında yedeklerden biri doğru (tam ya da biçim)? Beklentim: ≤ 5 (birleştirici düzeltmesi için kazanılacak pay küçük).
- **Ö10c:** kazananı doğru olan adlarda yedeğin doğru olma oranı (yedek kanal başına): yedek kanalların "ad kanalı olarak" kesinliği. Beklentim: `string_context` yedekleri < %50, öbürleri < %10.
- **Ö10d (kuralın oynatılması):** BULGULAR §5 kural 5 (p alt sınırı yüksek kanal kazanır; ölçülmemiş kanal p = 0). Yedek stratejilerin ölçülmüş ad kesinliği yok → kural bugünkü kazananı değiştirmez; değişen karar sayısı 0 olmalı (yeniden üretim). Seçenek kural: yedek kanalların Ö10c'de ölçülen kesinliği p olarak kullanılırsa değişen karar sayısı ve kesinlik farkı (aynı veride ölçülüp aynı veride uygulandığı için **yön gösterici**).
- **Ö11 (kalibrasyon):** OLGU tablosundaki `guven` (köken kaydının güveni) ↔ gerçekleşen doğruluk (tam; tam + biçim), 1 800 ad. Güven değeri başına tablo, Brier puanı, ECE (0,1 genişlikli kutular). Ön adlarda güven bu setin ölçülmüş alt sınırı olduğu için döngüsel; asıl soru `string_context/oz_ad`'ın sezgisel güveni. **Tuttu** (kalibre): `oz_ad` için ECE ≤ 0,10. Beklentim: tutmaz (güven 0,7–0,9, gerçekleşen ~0,47 / 0,68).

## 15. Ö10 ve Ö11 sonuçları; ek ölçümler

- **Ö10 (çatışma; `catisma.py` → `catisma.json`):** uygulanan 1 800 adın 1 300'ünde kimlik iddialı ve kazananla farklı bir yedek var (Ö10a beklentim "< 300" idi; **tutmadı** — `api_call` ve `callee_based` jenerik olmayan adlar da üretiyor). Kazananı yanlış 79 adın 41'i çatışmalı; yedeği doğru olan **0** (Ö10b "≤ 5": tuttu). Yedek kesinliği: `api_call` 1 / 1 298, `callee_based` 1 / 709, `string_context` 99 / 109 (Ö10c: ilk ikisi beklendiği gibi; `string_context` için "< %50" beklentim **tutmadı**, çünkü bu yedeklerin 101'i kazananla aynı adı veren ikinci kanıt). Kural oynatması: ölçülmemiş p = 0 ile değişen karar 0; yedeklere bu veride ölçülen p verilince 1 karar değişiyor ve bir doğru ad kaybediliyor (yön gösterici).
- Neden böyle: geliştirme setinde gerçek anlamda "iki ölçülmüş kanal farklı ad veriyor" durumu yalnız 8; birleştirici kuralının sınanacağı çatışma nüfusu bu sette yok. Ad verilmeyen fonksiyonların elenen adayları kayıtta tutulmadığı için öbür yarı ölçülemiyor.
- **Ö11 (kalibrasyon; `kalibrasyon.py` → `kalibrasyon.json`): tutmadı.** `oz_ad` ECE 0,359 (tam), 0,156 (tam + biçim); eşik 0,10. Güven 0,80 sınıfı %28,9 / %51,3; 0,85 sınıfı %58,7 / %77,7 doğru.
- **ROC noktaları ve AUC aralıkları** (`roc_egri.py` → `roc_egri.json`): sınama havuzu `yakin` en iyi `as5` 0,790 (0,708–0,863).
- **Literatür:** SymLM denklem 18 doğrulandı (fonksiyon başına P ve R'nin ortalaması, F1 ikisinin harmonik ortalaması); `literatur_olcusu.py`'ye `symlm_*` alanları eklendi: ad verilen 0,961 / 0,955 / 0,958; nüfus 0,059 / 0,058 / 0,058.
- **Var olan set dışı kanıt:** P-S3b'nin yeniden oynatması (gnulib kanalı): Mach-O 13 / 1, korpus Debian 9.4 35 / 0, Ubuntu 9.4 35 / 0, od / pr 14 / 1 → 97 / 99. Kabul setinin programları (gettext, envsubst, idn2, gsort, gmktemp, gcat, xz) kilit belgelerindeki listelerde yok; yalnız P-S3b.md'deki sayılar alıntılandı, koşu çıktılarına bakılmadı.
- **İki düzeyli karar kuralı** (aile kapalı): L = 5 → ad 1 593; L = 10 → 1 560; L = 20 → 1 301 (`karar.json` alt sınırlarından; hesap bu oturumda betikle).

### Hepsini yeniden üretme sırası (depo kökünden; `V=~/karadul_olcum/runs/arge-2026-11-19/olcu`)

```bash
export PYTHONDONTWRITEBYTECODE=1
python scripts/arge/olcu/etiket_topla.py --cikti $V
python scripts/arge/olcu/roc.py --etiketler $V/etiketler.jsonl --json $V/roc.json
python scripts/arge/olcu/roc_egri.py --etiketler $V/etiketler.jsonl --json $V/roc_egri.json
python scripts/arge/olcu/bantlar.py --etiketler $V/etiketler.jsonl --json $V/bantlar.json
PYTHONPATH=~/karadul_olcum/urun-a62f15e python scripts/arge/olcu/taban_dok.py --agac ~/karadul_olcum/urun-a62f15e \
  --kok ~/karadul_olcum/runs/urun-onarim-a62f15e --mac-veri $PWD/workspaces/olcum_mac --json $V/taban_a62f15e.json
PYTHONPATH=~/karadul_olcum/urun-f30ac9a python scripts/arge/olcu/taban_dok.py --agac ~/karadul_olcum/urun-f30ac9a \
  --kok ~/karadul_olcum/runs/urun-yeni2-f30ac9a --mac-veri $PWD/workspaces/olcum_mac --json $V/taban_yeni2_f30ac9a.json
python scripts/arge/olcu/kimlik.py --etiketler $V/etiketler.jsonl --taban $V/taban_a62f15e.json --json $V/kimlik.json
python scripts/arge/olcu/idf.py --etiketler $V/etiketler.jsonl --taban $V/taban_a62f15e.json --json $V/idf.json
python scripts/arge/olcu/taban_puanla.py --taban $V/taban_a62f15e.json --json $V/taban_puan.json
python scripts/arge/olcu/taban_puanla.py --taban $V/taban_yeni2_f30ac9a.json --json $V/taban_puan_yeni2.json
python scripts/arge/olcu/karar.py --taban $V/taban_a62f15e.json --json $V/karar.json
python scripts/arge/olcu/literatur_olcusu.py --taban $V/taban_a62f15e.json --json $V/literatur_olcusu.json
python scripts/arge/olcu/ornek_sayisi.py --bantlar $V/bantlar.json --json $V/ornek_sayisi.json
python scripts/arge/olcu/tekil.py --olgu ~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz --taban $V/taban_a62f15e.json --json $V/tekil.json
python scripts/arge/olcu/kalibrasyon.py --olgu ~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz --json $V/kalibrasyon.json
PYTHONPATH=~/karadul_olcum/urun-a62f15e python scripts/arge/olcu/catisma.py --agac ~/karadul_olcum/urun-a62f15e \
  --kok ~/karadul_olcum/runs/urun-onarim-a62f15e --mac-veri $PWD/workspaces/olcum_mac --karar $V/karar.json --json $V/catisma.json
python scripts/arge/olcu/kimlik_hatalari.py --dok ~/karadul_olcum/runs/arge-2026-11-19/kimlik/hata_dok_kural.json --json $V/kimlik_hatalari_kural.json
```

### Altı kalemin durumu (tur sonu)

| Kalem | Durum | Açık kalan ve neden |
|---|---|---|
| 1 Etiket envanteri | tamam | — |
| 2 Aday ölçüler, ROC / AUC, ayar ↔ sınama | tamam (vekil hükümle) | insan hükmüyle uyum: **veri yok** (insan etiketi 0) → PLAN P-Ö3, P-Ö4 |
| 3 Literatür ölçüsü | tamam (NERO, SymLM, SymGen birincil kaynaktan; taban koşusunda hesaplandı) | Punstrip ve XFL tanımı ikincil kayıttan; CodeWordNet'li kıyas indirme ister |
| 4 Taban koşusunun yeniden puanlanması | tamam (iki kol, örnek ve tekil, kanal başına; KİMLİK yanlışları) | 79 belirsiz adın hükmü: insan etiketi yok |
| 5 Karar kuralı | tamam (maliyet modeli, kanal düzeyleri, çatışma oynatması, kalibrasyon) | e ve a parametreleri (analist çalışması yok); elenen adaylar (kayıtta yok) |
| 6 Set dışı tasarım | tamam (tabakalar, indirme listesi, örnek sayıları, etiket paketi) | ölçümün kendisi: Ghidra koşusu ve indirme bu turda yasak |

### Belirlenimcilik denetimi (tur sonu)

`etiket_topla`, `roc`, `bantlar`, `kimlik`, `idf`, `taban_puanla`, `karar` geçici dizine yeniden koşuldu; yedi çıktının sha256'sı `$V`'dekilerle aynı (7 / 7). `scripts/arge/olcu/` altında `__pycache__` yok. Git'te durumu değiştiren komut koşulmadı; yazılan yerler yalnız `docs/arge/2026-11-19_mythos/olcu/`, `scripts/arge/olcu/`, `~/karadul_olcum/runs/arge-2026-11-19/olcu/` (ve oturumun geçici dizini).
