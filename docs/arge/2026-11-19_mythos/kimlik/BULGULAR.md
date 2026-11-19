# KİMLİK hattı — bulgular (tur 1, 2026-11-19)

- **Soru:** kaynağı başka yerde bulunan kodun fonksiyonları, farklı derleyici / platform / sürümle yapılmış bir
  başvuru derlemesinden hangi kesinlikle ve kapsamda tanınır? Hedef: kesinliğin Wilson alt sınırı ≥ 0,95.
- **Taban:** ürün koşusu a62f15e (`~/karadul_olcum/runs/urun-onarim-a62f15e`), nüfus 21 371.
- **Betikler:** `scripts/arge/kimlik/`. **Çıktılar:** `~/karadul_olcum/runs/arge-2026-11-19/kimlik/` (aşağıda `K/`).
  Komutlar depo kökünden, `PYTHONDONTWRITEBYTECODE=1 python …` ile koşulur.
- **Ölçü:** sorgu Q (soyulmuş, ad bekleyen) → başvuru R (adları GT'den). Hüküm tam ad eşitliği (Mach-O `_` soyulur,
  derleyici klonu tabana iner), nüfus içinde (`ks1_olc.GtBirimi.nufus`; ürün ölçümüyle aynı payda).
  Aralıklar Wilson %95 (`ks1_olc.oran`). Tanımların tamamı `DEFTER.md` §3.
- **Bölme:** parametreler yalnız htop çiftinde ayarlandı; tmux, coreutils ve korpus çiftlerinde dondurulmuş
  hâliyle bir kez sayıldı (`DEFTER.md` §2, §5.3). Geliştirme seti içi ölçümdür; kilitli setlere dokunulmadı.
- Bu turda yapılan Ghidra koşuları (hepsi sıralı, aynı anda bir tane; ürün ağacı a62f15e): temiz BSim için 8
  (§2.3), `--stage static` denetimi 1, GCC derlemeleri 4, sembollü Mac tmux 1, Homebrew coreutils yeniden koşusu 3.
  §1–§5 ve §7'nin geri kalanı var olan koşu çıktılarından. İndirme yapılmadı.

## 0. Özet

1. **Aykırı öncül 1 (çapalı yayılım öğrenmesiz ≥ 0,95 verir): başvuru aynı sürümse TUTTU, sürüm farklıysa tutmadı.**
   - Aynı sürüm, GCC ↔ clang (tmux 3.8; ön kayıtlı, taze veri): 3 908 doğru / 38 yanlış, kesinlik **0,990
     [0,987–0,993]**, kapsam **%80,1**; tablo kanıtıyla (v2) 4 281 / 36, 0,992 [0,989–0,994], kapsam **%87,7** (§3.6).
   - Aynı sürüm, yalnız iyileştirme düzeyi: `-O3` ↔ `-O2` 0,981 [0,976–0,985]; `-O0` ↔ `-O2` 0,970 (alt 0,964) (§3.8).
   - Sürüm farklı (tmux 3.5a ↔ 3.8, GCC ↔ clang; ilk dondurulmuş sınama): 2 276 / 158, 0,935 [0,925–0,944], kapsam
     %51,8. coreutils 9.7 ↔ Homebrew 9.12: 316 / 47, 0,871 [0,832–0,901] (§3.1).
   - Taban ürün aynı paydada: tmux 341 / 4 396 (%7,8), htop 0 / 819.
2. **Öncül 3: sürüm farkı derleyici farkından pahalı.** tmux'ta sürüm farkı ~100 "yeniden adlandırma" yanlışı
   (`notify_pane` → `events_fire_pane` türü; 52 tekil çiftin 47'si 3.8 kaynağıyla tutarlı) ve 25–30 puan kapsam
   kaybı getiriyor; derleyici farkı ~29 satır içi türü yanlış. Sürüm eşlenince "yeniden adlandırma" sınıfı 99 → 4.
3. **Kalan gerçek hata satır içine alma** (bir derleme küçük fonksiyonu çağıranın içine gömer, kanıt bir basamak
   kayar): aynı sürümde yanlışların 29 / 38'i. Yapısal bir tanık bu türün %52–65'ini işaretliyor; işaretlilerin
   kesinliği 0,82–0,88 (karar kuralı eşiğinin altı), işaretsizlerinki 0,98–0,997 (§3.9).
4. **Aykırı öncül 2 (ad ailesi):** küme isabeti aynı derleyicide 0,990 [0,978–0,995]; aynı sürüm GCC ↔ clang
   0,941 [0,907–0,963]; sürüm farklı 0,819 [0,767–0,861]. 0,95 alt sınırı yalnız aynı derleyicide tutuyor;
   önek / sonek etiketi düzeyinde 0,978 [0,953–0,990] (aynı sürüm).
5. **Var olanlar derleyici ya da iyileştirme düzeyi değişince çalışmıyor:** BSim en iyi aday (temiz depo, iki yön)
   tmux 0,610 [0,580–0,639], htop 0,634; benzerlik eşiğini yükseltmek düzeltmiyor; `-O0` ↔ `-O2` 0,592; CFG + komut kümesi (P11 bankası) derleyiciler ve derleyici sürümleri arasında 0 eşleşme.
   **Ürünün `reference_binary` yolu** (`BinaryDiffer`) tmux'ta 328 / 174 = 0,653, `size_params` yöntemi 2 / 116;
   `ReferenceDiffer` 366 / 769 = 0,322 (§2.2).
6. **A1'e katkı:** nüfusun %63,0'ı (13 472) set içinde başka bir ikilide aynı ad + aynı boyutla duran kopya;
   %19,5'i (4 161) aynı programın öbür platform derlemesinde var; %16,8'inin (3 600) set içinde başvurusu yok (§7).
7. **Aynı derleyici kopyaları (gnulib) için genel yol:** taze çiftlerde yayılım ∪ CFG birleşimi 1 217 / 11 = 0,991
   [0,984–0,995], kapsam %47,7; beş başvuruyla `gnulib` sınıfında 660 / 9 = 0,987 [0,975–0,993], kapsam %55,9.
   Taban ürün aynı sınıfta %5,6 (§5).
8. **Başvurunun soyulmuş ya da sembollü analiz edilmesi sonucu değiştirmiyor** (fark ≤ %0,4; §3.7); koşu kuşağı
   farkı da değiştirmiyor (coreutils ↔ Homebrew yeniden koşuda birebir aynı).
9. **En ucuz yol üründe yok:** dağıtım ikilisinin build-id'si aynı derlemenin hata ayıklama dosyasını gösterir (§6).

## 1. Envanter (kalem 1)

Komut: `python scripts/arge/kimlik/envanter.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum derleme --json K/envanter.json`

| Çift | Sürümler / derleyici | Sorgu → başvuru | Fonksiyon | Nüfus | Tavan (adı başvuruda olan) | Ortak ad | Nüfusta çağıransız |
|---|---|---|---|---|---|---|---|
| htop (ayar) | Debian 3.4.1-5 GCC 14 ELF ↔ Homebrew 3.5.3 clang Mach-O | Debian → Mac | 609 | 222 | 180 (%81,1) | 515 | 184 |
| | | Mac → Debian | 597 | 597 | 515 (%86,3) | 515 | 217 |
| tmux | Debian 3.5a-3 ↔ Homebrew 3.8 | Debian → Mac | 1 920 | 1 851 | 1 712 (%92,5) | 1 754 | 628 |
| | | Mac → Debian | 2 588 | 2 545 | 1 754 (%68,9) | 1 754 | 761 |
| coreutils ↔ Homebrew (3 çift) | Debian 9.7-3 ↔ Homebrew 9.12 | cat / sort / mktemp → g* | 107 / 244 / 108 | 95 / 226 / 96 | 82 / 193 / 87 | 85 / 201 / 90 | — |
| | | g* → Debian | 136 / 353 / 141 | 124 / 300 / 127 | 85 / 201 / 90 | | — |
| coreutils içi (11 çift) | aynı paket, aynı derleyici | iki yön | — | 2 816 (toplam) | 2 112 (%75,0) | çift başına 95–157 | — |
| sürüm (5 çift) | Debian 13 9.7 ↔ korpus Debian 9.4-3 | iki yön | — | 994 | 923 (%92,9) | — | — |
| derleme (5 çift) | korpus Debian 9.4-3 ↔ Ubuntu 9.4-3ubuntu6 (LTO) | iki yön | — | 549 | 181 (%33,0) | — | — |

- Debian htop `-rdynamic` derlenmiş: 609 fonksiyonun 367'sinin adı dinamik simge tablosundan Ghidra'da hazır
  (nüfusu bu yüzden 222). Bu adlar eşleyicide çapa olarak kullanıldı (sorguda zaten bilinen bilgi).
- Debian tmux 1 920, Mac tmux 2 588 fonksiyon: GCC daha çok fonksiyonu satır içine almış; Mac → Debian
  yönünde tavan bu yüzden %68,9.
- Ubuntu derlemesi LTO'lu (ikili başına 26–42 fonksiyon; Debian'da 97–122).
- İki ana çiftte (tmux, htop) derleyici / platform farkı ile sürüm farkı **birlikte**. Hazır veride aynı sürümün
  iki derleyiciyle derlemesi yoktu; bu yüzden tmux 3.8 ve htop 3.5.3 diskteki kaynaktan Homebrew GCC 16 ile
  derlendi (§3.6, §3.8). O çiftlerin envanteri (`K/envanter_gcc.txt`, `K/envanter_duzey.txt`):

| Çift | Sorgu → başvuru | Fonksiyon | Nüfus | Tavan | Ortak ad |
|---|---|---|---|---|---|
| tmux 3.8, GCC 16 `-O2` ↔ clang (Homebrew) | GCC → clang | 2 534 | 2 335 | 2 314 (%99,1) | 2 383 |
| | clang → GCC | 2 588 | 2 545 | 2 379 (%93,5) | 2 383 |
| htop 3.5.3, GCC 16 ↔ clang | GCC → clang / clang → GCC | 638 / 597 | 582 / 597 | 577 / 581 | 581 |
| tmux 3.5a GCC 14 (Debian) ↔ 3.8 GCC 16 | Debian → GCC 16 / tersi | 1 920 / 2 534 | 1 851 / 2 335 | 1 727 / 1 730 | 1 769 |
| tmux 3.8 GCC 16 `-O3` ↔ `-O2` | `-O3` → `-O2` / tersi | 2 470 / 2 534 | 2 247 / 2 335 | 2 239 / 2 246 | 2 290 |
| tmux 3.8 GCC 16 `-O0` ↔ `-O2` | `-O0` → `-O2` / tersi | 3 265 / 2 534 | 3 265 / 2 335 | 2 407 / 2 335 | 2 407 |

## 2. Var olan yöntemlerin çıplak ölçümü (kalem 2)

### 2.1 Tekil dizgi, CFG, BSim (var olan koşu çıktılarından)

Komut: `python scripts/arge/kimlik/ciplak.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum derleme --json K/ciplak.json`

| Yöntem | tmux (derleyici + sürüm) | coreutils ↔ Homebrew | coreutils içi (aynı derleyici) | sürüm (9.4 ↔ 9.7) |
|---|---|---|---|---|
| Tekil dizgi çapası | 737 / 54 = 0,932 [0,912–0,947]; kapsam %16,8 | 53 / 6 = 0,898 [0,795–0,953]; %5,5 | 248 / 0 = 1,000 [0,985–1]; %8,8 | 108 / 0 [0,966–1]; %10,9 |
| CFG yapısı tekil (blok ≥ 3) | 20 / 27 = 0,426; %0,5 | 20 / 8 = 0,714; %2,1 | 680 / 5 = 0,993 [0,983–0,997]; %24,1 | 188 / 22 = 0,895 [0,847–0,930]; %18,9 |
| CFG + komut kümesi (P11 bankasının karşılığı) | **0 eşleşme** | **0 eşleşme** | 1 020 / 2 = 0,998 [0,993–1]; %36,2 | **0 eşleşme** |
| BSim en iyi aday ≥ 0,7 (taban koşusunun kalabalık deposu; Mac → Debian yönü; temiz ölçüm §2.3) | 303 / 127 = 0,705 [0,660–0,746]; %11,9 | 20 / 15 (yalnız bir yön; n küçük) | 198 / 19 = 0,912 [0,867–0,943] | depoda yok |
| BSim + "tek en iyi" kapısı | 276 / 60 = 0,821 [0,777–0,859]; %10,8 | 13 / 0 | 193 / 10 = 0,951 [0,912–0,973] | — |

- **H3'ün cevabı:** CFG + komut kümesi bankası yalnız aynı derleyici **ve** aynı derleme ayarında çalışıyor.
  GCC ↔ clang arasında 0; Debian 9.4 → Debian 13 (9.7) arasında da 0 eşleşme (komut çoklu kümesi hiçbir
  fonksiyonda aynı kalmıyor; olası neden derleyici sürümü ve Debian 13'ün AArch64 dal koruması bayrakları —
  neden ayrıca doğrulanmadı). Banka derleyici sürümleri arasında genelleşmiyor.
- htop (ayar çifti): tekil dizgi 104 / 2; BSim ≥ 0,7: 129 / 46 = 0,737 [0,667–0,797].
- **Ön kayıt Ö8 (BSim tek başına < 0,95): tuttu.** Ö1 (tekil dizgi, tmux: Wilson alt ≥ 0,90 ve kapsam ≤ %25): tuttu
  (alt 0,912; kapsam %16,8).

### 2.2 Ürünün var olan başvuru eşleyicileri

Komut: `python scripts/arge/kimlik/urun_bindiff.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum --json K/urun_bindiff.json`
(ürün kodu değiştirilmedi; `BinaryDiffer.compare` ve `ReferenceDiffer.match_direct` iki koşunun Ghidra
JSON'larıyla çağrıldı, başvuru adları GT'den yazıldı; eşikler ürünün öntanımı).

| Yol | Yöntem | tmux | coreutils içi (aynı derleyici) |
|---|---|---|---|
| `BinaryDiffer` (`reference_binary` ayarının çağırdığı; `_config_source`) | toplam | **328 / 174 = 0,653 [0,611–0,694]; kapsam %7,5** | 441 / 152 = 0,744 [0,707–0,777] |
| | `string_refs` | 326 / 16 = 0,953 [0,925–0,971] | 62 / 4 |
| | `size_params` | **2 / 116 = 0,017** | 23 / 127 = 0,153 |
| | `cfg_fingerprint` | **0 / 42** | 356 / 21 = 0,944 |
| `BinaryDiffer` + çağrı grafiği (`_refdb_source`) | `call_pattern` | 91 / 56 = 0,619 [0,538–0,694] | 89 / 9 = 0,908 |
| `ReferenceDiffer.match_direct` | toplam | **366 / 769 = 0,322 [0,296–0,350]** | 1 197 / 185 = 0,866 [0,847–0,883] |
| | `cfg_similarity` | 58 / 725 = 0,074 | 1 011 / 144 = 0,875 |
| | `string_fingerprint` | 304 / 12 = 0,962 [0,935–0,978] | 148 / 4 |

- Beş grubun havuzu (`K/urun_bindiff.txt` "TÜM GRUPLAR"): `BinaryDiffer` (`config`) 958 / 604 = 0,613
  [0,589–0,637]; `ReferenceDiffer` 2 056 / 1 359 = 0,602 [0,586–0,618]. Yöntem başına: `string_refs` 414 / 24 =
  0,945 [0,920–0,963]; `string_fingerprint` 476 / 18 = 0,964 [0,943–0,977]; `call_pattern` 222 / 61 = 0,784;
  `cfg_fingerprint` 445 / 139 = 0,762; `cfg_similarity` 1 529 / 1 219 = 0,556; `size_params` 99 / 441 = 0,183;
  `size_constant` 43 / 114 = 0,274; `call_propagation` 8 / 8. Karar kuralının eşiğini (Wilson alt ≥ 0,909)
  yalnız iki dizgi yöntemi geçiyor.
- coreutils ↔ Homebrew: `BinaryDiffer` 10 / 154 = 0,061; `ReferenceDiffer` 55 / 168 = 0,247. (Bu çiftlerde dizgi
  yöntemleri 0 eşleşme veriyor: P-S3 / P-S3b koşularının `ghidra_strings.json`'ında dizgi → fonksiyon bağı yok.
  Aynı ikililerin a62f15e ağacıyla yeniden koşusunda — `K/urun_bindiff_cu_mac2.txt` — `string_refs` 10 / 0,
  toplam `BinaryDiffer` 18 / 157 = 0,103, `ReferenceDiffer` 69 / 162 = 0,299.)
- **Anlamı:** analist bugün `binary_reconstruction.reference_binary` verirse ya da `~/.cache/karadul/ref_db`
  doluysa ürün çoğunlukla yanlış ad yazar. Öntanımda yol boş olduğu için taban ölçümünde görünmüyor.
  `size_params`, `cfg_fingerprint`, `cfg_similarity`, `size_constant` yöntemleri aynı derleyicide bile 0,95'in
  çok altında.
- İmza veritabanı bu turda yeniden ölçülmedi: adsız fonksiyona verdiği adlar tam eşitlikte 0 / 208 (P11),
  uygulanan ad farkı 0 (P15b); taban ölçümünün kanal kırılımında imza kanalından ad yok (OLGU `BUTCE.md` §3).

### 2.3 Temiz BSim (yalnız iki ikili içeren depo; iki yön)

Taban koşusunun BSim deposunda başka programlar da vardı ve Debian → Mac yönü yoktu. Temiz ölçüm için depo başına
yalnız iki ikili (önce başvuru, sonra sorgu) ürün ağacıyla yeniden koşuldu (`scripts/arge/kimlik/kos_bsim.sh`: htop
depoları ve tmux'un ilk adımı tam boru hattı; `kos_bsim2.sh`: kalan üç tmux koşusu `--stage static`; BSim eklemesi
ve sorgusu statik aşamada). Komut: `python scripts/arge/kimlik/bsim_temiz.py --json K/bsim_temiz.json` (metin `K/bsim_temiz.txt`).

| Çift (iki yön havuzlu; `known_executables` = 2) | En iyi aday ≥ 0,7 | ≥ 0,9 | = 1,0 | ≥ 0,7 + tek en iyi | ≥ 0,9 + tek en iyi |
|---|---|---|---|---|---|
| tmux (3.5a GCC ↔ 3.8 clang; nüfus 4 396) | 621 / 397 = **0,610 [0,580–0,639]**; kapsam %14,1 | 343 / 317 = 0,520 | 213 / 167 = 0,561 | 544 / 95 = 0,851 [0,822–0,877]; %12,4 | 270 / 35 = 0,885 [0,845–0,916]; %6,1 |
| htop (3.4.1 GCC ↔ 3.5.3 clang; nüfus 819) | 187 / 108 = 0,634 [0,578–0,687]; %22,8 | 126 / 90 = 0,583 | 97 / 68 = 0,588 | 155 / 23 = 0,871 [0,814–0,912]; %18,9 | 94 / 8 = 0,922 [0,853–0,960]; %11,5 |

- Yön başına (tmux, ≥ 0,7): Debian → Mac 308 / 165 = 0,651; Mac → Debian 313 / 232 = 0,574.
- Benzerlik eşiğini yükseltmek kesinliği artırmıyor (≥ 0,7: 0,610; = 1,0: 0,561): "eşiği ayarla" cevabının ölçümü.
  Kesinliği artıran eşik değil tekillik kapısı (0,851), o da 0,909'un altında ve kapsamı %12.
- Aynı çiftte çapalı yayılım (kural): 2 276 / 158 = 0,935, kapsam %51,8 (§3.1).
- Süre (E5 için; `ghidra_bsim.json` `bsim_detail`): tmux sorgusu 26–31 sn, depoya ekleme 25–32 sn (toplu sorgu,
  yerel kip; makine yük altındaydı). Çapalı eşleyici aynı çiftte 1,0–2,5 sn (`K/yayilim_*.txt` süre sütunu; olgu
  yükleme hariç).
- BSim'in yerel ↔ lite kip farkı bu turda ölçülmedi (lite kipi koşulmadı; açık ölçüm, sahibi E5).

## 3. Çapalı yayılım prototipi (kalem 3)

Yöntem (`scripts/arge/kimlik/esle.py`; öğrenme yok, yalnız sayım):
1. **Çapa:** sorguda Ghidra'nın zaten bildiği ad (dinamik simge) başvuruda tek fonksiyonun adıysa; iki tarafta da
   yalnız bir fonksiyonda geçen dizgi (oylar çelişmiyorsa).
2. **Yayılım:** eşlenmemiş her fonksiyonun kanıt kümesi = dizgiler + içe aktarım çağrıları (ad normalleştirilmiş;
   derleyicinin birbirine çevirdiği yerleşikler hariç) + P-code sabitleri (16 ≤ c < 2^40) + eşlenmiş çağrılanlar +
   eşlenmiş çağıranlar. Kanıtın ağırlığı 1 / log2(1 + df); df = o kanıtı taşıyan **eşlenmemiş** fonksiyon sayısı
   (eşleme ilerledikçe tekillik artar). Puan = ağırlıklı Jaccard.
3. **Belirsizlik kapısı:** puan ≥ T, ortak kanıt kütlesi ≥ `kutle`, en iyi aday ikinciden ≥ `marj` ayrı, karşılıklı
   en iyi. Geçemeyen fonksiyona ad verilmez.

Ayar (yalnız htop; `python scripts/arge/kimlik/ayar.py --json K/ayar_htop_1.json`, 750 nokta): seçim kuralı
ızgaradan önce yazıldı (Wilson alt ≥ 0,95 içinde en yüksek kapsam). Dondurulan iki nokta:
**kural** (T 0,3; marj 0,1; kütle 0,5) ve **tutucu** (kütle 1,0).

### 3.1 Dondurulmuş sayım

Komutlar: `python scripts/arge/kimlik/yayilim_olc.py sinama_tmux --egri --json K/yayilim_sinama_tmux.json`;
`… sinama_cu_mac sinama_cu_ic surum derleme --json K/yayilim_sinama_coreutils.json`;
ayar çifti `… kesif_htop --egri --json K/yayilim_kesif_htop.json`.

| Birim | Nokta | Doğru / yanlış | Kesinlik [Wilson %95] | Kapsam (doğru / nüfus) | Tavanın |
|---|---|---|---|---|---|
| htop (ayar çifti; sınama değil) | kural | 515 / 16 | 0,970 [0,952–0,981] | 515 / 819 = %62,9 | %74,1 |
| | tutucu | 467 / 9 | 0,981 [0,965–0,990] | %57,0 | %67,2 |
| **tmux** | kural | 2 276 / 158 | **0,935 [0,925–0,944]** | 2 276 / 4 396 = %51,8 | %65,7 |
| | tutucu | 2 040 / 130 | 0,940 [0,929–0,949] | %46,4 | %58,9 |
| **coreutils ↔ Homebrew** | kural | 316 / 47 | **0,871 [0,832–0,901]** | 316 / 968 = %32,6 | %42,8 |
| | tutucu | 270 / 33 | 0,891 [0,851–0,921] | %27,9 | %36,6 |
| **coreutils içi** (aynı derleyici) | kural | 1 026 / 13 | **0,987 [0,979–0,993]** | 1 026 / 2 816 = %36,4 | %48,6 |
| | tutucu | 942 / 5 | 0,995 [0,988–0,998] | %33,5 | %44,6 |
| sürüm (9.4 ↔ 9.7) | kural | 481 / 26 | 0,949 [0,926–0,965] | 481 / 994 = %48,4 | %52,1 |
| derleme (LTO ↔ LTO'suz) | kural | 119 / 23 | 0,838 [0,769–0,890] | 119 / 549 = %21,7 | %65,7 |

Aşama kırılımı (kural): tmux tekil dizgi çapası 737 / 54 (0,932), yayılım 1 539 / 104 (0,937); coreutils içi
dizgi 248 / 0, yayılım 778 / 13.
Yön başına (tmux, kural): Debian → Mac 1 118 / 76 (0,936), kapsam %60,4; Mac → Debian 1 158 / 82 (0,934), %45,5.

Taban ürünle karşılaştırma (aynı payda; `python scripts/arge/kimlik/taban_kapsam.py`, OLGU tablosundan): taban ürünün
nüfus içi doğru adı tmux'ta 136 + 205 = 341 / 4 396 (%7,8), htop'ta 0 / 819; bu yöntem (başvuru verildiğinde)
2 276 (%51,8) ve 515 (%62,9). Karar kuralı (KARARLAR A-2: Wilson alt ≥ 0,909 → ad yazabilir) açısından: tmux
0,925 ve coreutils içi 0,979 eşiği geçiyor; coreutils ↔ Homebrew 0,832 geçmiyor.

**Ön kayıt hükümleri:** Ö2 (tmux, Wilson alt ≥ 0,95) **tutmadı** (0,925). Ö3 (tmux kapsam ≥ %40) **tuttu** (%51,8).
Ö4 (coreutils ↔ Homebrew ≥ 0,95) **tutmadı** (0,832). Ö5 (coreutils içi > 0,882 ve alt ≥ 0,90) **tuttu**.

### 3.2 Kesinlik ↔ kapsam eğrisi

T × kütle ızgarası, marj 0,1 (bilgi içindir; sınama birimlerinde nokta seçmek için kullanılmadı). Kaynak:
`K/yayilim_sinama_tmux.json`, `K/yayilim_egri_coreutils.txt`, `K/yayilim_kesif_htop.json`.

| T / kütle | tmux: doğru / yanlış, kesinlik (alt), kapsam | coreutils ↔ Homebrew | coreutils içi |
|---|---|---|---|
| 0,3 / 0,5 | 2 276 / 158, 0,935 (0,925), %51,8 | 316 / 47, 0,871 (0,832), %32,6 | 1 026 / 13, 0,987 (0,979), %36,4 |
| 0,3 / 1,0 | 2 040 / 130, 0,940 (0,929), %46,4 | 270 / 33, 0,891 (0,851), %27,9 | 942 / 5, 0,995 (0,988), %33,5 |
| 0,3 / 2,0 | 1 376 / 77, 0,947 (0,934), %31,3 | 101 / 10, 0,910 (0,842), %10,4 | 666 / 3, 0,996 (0,987), %23,7 |
| 0,5 / 0,5 | 1 823 / 103, 0,947 (0,936), %41,5 | 245 / 30, 0,891 (0,849), %25,3 | 1 016 / 11, 0,989 (0,981), %36,1 |
| 0,5 / 1,0 | 1 563 / 79, 0,952 (0,940), %35,6 | 179 / 20, 0,899 (0,850), %18,5 | 934 / 3, 0,997 (0,991), %33,2 |
| 0,7 / 0,5 | 1 285 / 64, 0,953 (0,940), %29,2 | 206 / 24, 0,896 (0,849), %21,3 | 966 / 4, 0,996 (0,989), %34,3 |
| 0,7 / 1,0 | 1 145 / 57, 0,953 (0,939), %26,0 | 139 / 16, 0,897 (0,839), %14,4 | 870 / 2, 0,998 (0,992), %30,9 |
| 0,7 / 3,0 | 802 / 54, 0,937 (0,919), %18,2 | 62 / 6, 0,912 (0,821), %6,4 | 420 / 2, 0,995 (0,983), %14,9 |

**Eşiği sıkmak tmux'ta kesinliği 0,95'in üstüne taşımıyor:** kalan yanlışların tabanı tekil dizgi çapasından
geliyor (54), o da eşikle değişmiyor. Sorun eşik değil, §4'teki iki hata sınıfı.

### 3.3 Yanlışlar nereden geliyor (dondurulmuş sayımdan sonra bakıldı)

Komut: `python scripts/arge/kimlik/hata_dok.py <gruplar> --nokta kural --json K/hata_dok_kural.json` (metin `K/hata_dok_kural.txt`).

| Birim (kural) | Yanlış | Adı başvuruda yok, önerilen ad da sorguda yok ("tek taraflı": yeniden adlandırma adayı) | Adı başvuruda yok, önerilen ad sorguda başka fonksiyonda ("satır içi") | Seçilen, doğrunun çağıranı / çağrılanı ("komşu") | Aynı ad ailesi | Diğer | **Tavan içi kesinlik** (adı başvuruda olanlar) |
|---|---|---|---|---|---|---|---|
| tmux | 158 | 99 | 25 | 17 | 10 | 7 | 2 276 / 2 310 = **0,985 [0,980–0,989]** |
| coreutils ↔ Homebrew | 47 | 30 | 7 | 10 | 0 | 0 | 316 / 326 = 0,969 [0,945–0,983] |
| coreutils içi | 13 | 11 | 0 | 0 | 2 | 0 | 1 026 / 1 028 = 0,998 [0,993–1] |
| sürüm | 26 | 24 | 1 | 1 | 0 | 0 | 481 / 482 = 0,998 [0,988–1] |
| derleme (LTO) | 23 | 2 | 14 | 7 | 0 | 0 | 119 / 126 = 0,944 [0,890–0,973] |
| htop (ayar) | 16 | 3 | 6 | 3 | 1 | 3 | 515 / 522 = 0,987 [0,973–0,994] |

- **Tek taraflı sınıf** (tmux 99; 52 tekil çift, 47'si iki yönde de aynı çift): gözle bakınca yukarı akıştaki
  yeniden adlandırmalar. Örnekler (geliştirme seti): `notify_pane` → `events_fire_pane`, `status_prompt_type` →
  `prompt_type`, `control_notify_window_renamed` → `control_window_renamed_cb`, `popup_editor` → `spawn_editor`,
  `window_pane_visible` → `window_pane_is_visible`. coreutils'te gnulib'in platforma göre ad değiştirmesi
  (`fpurge` ↔ `rpl_fpurge`, `reallocarray` ↔ `rpl_reallocarray`) ve sürüm yeniden adlandırması
  (`setlocale_null` → `setlocale_null_unlocked`, `hash_find_entry` → `find_entry`).
  Eşleme doğru fonksiyonu buluyor ve **başvurunun sürümündeki adını** veriyor; tam eşitlik ölçüsü bunu yanlış
  sayıyor. Kısmi mekanik denetim (`python scripts/arge/kimlik/tek_tarafli_kaynak.py --json K/tek_tarafli_kaynak.json`;
  diskte yalnız tmux 3.8 kaynağı var): 52 tekil çiftin **47'sinde** eski (3.5a) ad 3.8 kaynağında hiç geçmiyor ve
  yeni ad orada bir fonksiyon tanımı (yeniden adlandırmayla tutarlı); 5'inde eski ad 3.8 kaynağında hâlâ var
  (`cmd_resize_pane_mouse_update`, `grid_reflow_move`, `tty_keys_find1` …: yeniden adlandırma değil). Sınıfın
  "aynı fonksiyon" olduğu tam olarak doğrulanmadı (3.5a kaynağı ya da sürümü eşlenmiş başvuru ister; §3.6). Bu yüzden şu sayı yalnız **yön gösterici**: tek taraflılar hüküm dışı bırakılırsa tmux
  2 276 / 2 335 = 0,975 [0,968–0,980]; coreutils ↔ Homebrew 316 / 333 = 0,949 [0,920–0,968].
- **Satır içi + komşu** (tmux 42, coreutils ↔ Homebrew 17, LTO 21): gerçek kimlik hatası. Örnekler:
  `control_write` ↔ `control_write_line`, `print_errno_message` ↔ `error_tail`, `version_etc_arn` ↔
  `version_etc`, `client_exit` ↔ `client_file_check_cb`. Tekil dizgi çapası da yanılıyor: dizgi bir derleyicide
  çağrılanda, öbüründe (satır içine alındığı için) çağıranda duruyor.
- **Öncül 3 (sürüm mü derleyici mi):** tam ad kesinliğinde sürüm farkı daha pahalı (tmux 99 ↔ 42; coreutils ↔
  Homebrew 30 ↔ 17; yalnız sürüm farkı olan çiftte 24 / 26; yalnız LTO farkı olan çiftte 21 / 23 satır içi).
  Ama sürümün bozduğu ad, derleyicinin bozduğu kimlik. İkisini temiz ayırmak için aynı sürümün iki
  derleyiciyle derlemesi gerekir: **elde yok → açık ölçüm** (PLAN, veri isteği V1).

### 3.4 Kaynak sınıfı başına (OLGU tablosuyla)

Komut: `python scripts/arge/kimlik/olgu_capraz.py --json K/olgu_capraz.json` (kural noktası; sorgu Debian ELF, sınıf dbgsym DWARF'ından).

| Birim | Sınıf | Nüfus | Tavan | Doğru / yanlış | Kesinlik | Kapsam |
|---|---|---|---|---|---|---|
| coreutils içi | `gnulib` | 2 444 | 2 048 | 966 / 11 | 0,989 [0,980–0,994] | %39,5 |
| | `program` | 347 | 48 | 44 / 2 | 0,957 [0,855–0,988] | %12,7 |
| coreutils ↔ Homebrew | `gnulib` | 364 | 319 | 129 / 20 | 0,866 [0,802–0,911] | %35,4 |
| | `program` | 49 | 43 | 26 / 3 | 0,897 | %53,1 |
| sürüm | `gnulib` | 488 | 428 | 208 / 15 | 0,933 [0,892–0,959] | %42,6 |
| | `program` | 33 | 33 | 32 / 0 | 1,000 [0,893–1] | %97,0 |
| tmux (Debian → Mac) | `program` | 1 756 | 1 630 | 1 081 / 72 | 0,938 [0,922–0,950] | %61,6 |
| | `uyumluluk` (`compat/`) | 95 | 82 | 37 / 4 | 0,902 | %38,9 |

### 3.5 Tablo yuvası kanıtı (v2; çağıransız fonksiyonlar için)

Nüfusun büyük kısmı çağrı grafiğinde çağıranı olmayan (adresi alınan, tablo üstünden çağrılan) fonksiyon
(Debian htop 184 / 222, Mac htop 217 / 597, Debian tmux 628 / 1 851, Mac tmux 761 / 2 545; `K/envanter.json`).
İkilinin veri bölümlerindeki işaretçi yuvaları Ghidra'sız okunabiliyor (`veri.isaretci_yuvalari`: ELF
`R_AARCH64_RELATIVE`, Mach-O zincirli düzeltmeler; `lief`). htop'ta çağıransız nüfusun yuvası olanı
Debian 127 / 184, Mac 133 / 217 (`python scripts/arge/kimlik/veri.py debian/htop mac/htop`).
İki yeni kanıt: aynı kayıtta (± pencere) duran dizgi (`t`) ve eşlenmiş fonksiyon (`k`), göreli yuva farkıyla.
Pencere ve çarpanlar yalnız htop'ta ayarlandı (pencere 8, `t` 0,5, `k` 1,0).

Komut: `python scripts/arge/kimlik/yayilim_olc.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum derleme --json K/yayilim_v2_hepsi.json`
(v1 satırları önceki çıktıyla birebir aynı: belirlenimcilik denetimi).

| Birim | v1 kural | v2 kural | Durum |
|---|---|---|---|
| htop | 515 / 16; %62,9 | 583 / 19 = 0,968 [0,951–0,980]; **%71,2** (tavanın %83,9'u) | ayar çifti |
| tmux | 2 276 / 158; %51,8 | 2 566 / 172 = 0,937 [0,927–0,946]; **%58,4** (tavanın %74,0'ı) | **ikinci bakış** |
| coreutils ↔ Homebrew | 316 / 47; %32,6 | 310 / 51 = 0,859; %32,0 | ikinci bakış |
| coreutils içi | 1 026 / 13 | 1 022 / 13 | ikinci bakış |

- "İkinci bakış": v2, tmux ve coreutils'in v1 sayıları ve hata sınıfları görüldükten sonra tasarlandı; parametresi
  orada ayarlanmadı ama ön kayıtlı sınama da sayılmaz. **Bağımsız sınaması §3.6 ve §3.8'de yapıldı** (hiç görülmemiş
  ikililer, ön kayıtlı): `derleyici` %80,1 → %87,7 (kesinlik 0,990 → 0,992), `-O3` çifti %78,0 → %86,9,
  `-O0` çifti %63,3 → %70,4, `derleyici_htop` %82,4 → %90,8; kesinlik hiçbirinde düşmedi.
- htop'ta kazancın kaynağı `k` (aynı tablodaki eşlenmiş komşu): yalnız `k` 582 / 18, yalnız `t` 535 / 18.
- tmux'ta v2 "aynı aile" türü yanlışı artırıyor (10 → 23): aynı tablonun komşu yuvaları karışıyor.
- Yer değiştirme tablosunda görünmeyen çağıransızlar (kod içinden adresi alınan geri çağrılar) için Ghidra'nın
  fonksiyona veri / kod başvurusu dökümü gerekir; bugünkü `ghidra_xrefs.json`'da yok (PLAN, PK-7).

### 3.6 Yalnız derleyici farkı: aynı sürümün GCC derlemesi (ön kayıtlı, taze veri)

Öncül 3'ü ve "sürüm eşlenirse 0,95 tutar mı" sorusunu ayırmak için tmux 3.8 ve htop 3.5.3 (Homebrew şişeleriyle
aynı sürüm; kaynak diskte) Homebrew GCC 16.2.0 `-O2` ile derlendi (`bash scripts/arge/kimlik/derle_gcc.sh`; indirme yok),
`/usr/bin/strip` ile soyuldu, GT sembollü ikilinin `nm` çıktısından (`macho_measure.py prepare`). Hipotezler ve
eşikler ölçümden önce yazıldı (`DEFTER.md` §5.9). Bu ikililer hiç görülmemişti; parametreler değişmedi.
Ürün koşusu `--stage static` (eşleyici yalnız `static/` okur; taban koşusuyla olgu eşitliği denetlendi: Debian htop
609 / 609 fonksiyon aynı, `K/static_denetim_static_asama.txt`).

Komut: `bash scripts/arge/kimlik/son_olcum.sh gcc` → `K/envanter_gcc.*`, `K/yayilim_gcc.*`, `K/hata_gcc_<nokta>.*`, `K/ciplak_gcc.*`.

| Çift (iki yön havuzlu) | Nokta | Doğru / yanlış | Kesinlik [Wilson %95] | Kapsam | Tavanın |
|---|---|---|---|---|---|
| **`derleyici`: tmux 3.8, GCC 16 ↔ Apple clang** (nüfus 4 880) | kural | 3 908 / 38 | **0,990 [0,987–0,993]** | **%80,1** | %83,3 |
| | tutucu | 3 709 / 28 | 0,993 [0,989–0,995] | %76,0 | %79,0 |
| | kural_v2 | 4 281 / 36 | **0,992 [0,989–0,994]** | **%87,7** | %91,2 |
| | tutucu_v2 | 4 170 / 26 | 0,994 [0,991–0,996] | %85,5 | %88,9 |
| `derleyici_htop`: htop 3.5.3, GCC 16 ↔ clang (nüfus 1 179; htop ayar programıydı, ikili yeni) | kural | 972 / 16 | 0,984 [0,974–0,990] | %82,4 | %83,9 |
| | kural_v2 | 1 070 / 17 | 0,984 [0,975–0,990] | %90,8 | %92,4 |
| `surum_gcc`: tmux 3.5a GCC 14 (Debian) ↔ 3.8 GCC 16 (nüfus 4 186) | kural | 2 369 / 150 | 0,940 [0,930–0,949] | %56,6 | %68,5 |
| | kural_v2 | 2 707 / 164 | 0,943 [0,934–0,951] | %64,7 | %78,3 |
| (karşılaştırma) `sinama_tmux`: 3.5a GCC 14 ↔ 3.8 clang | kural | 2 276 / 158 | 0,935 [0,925–0,944] | %51,8 | %65,7 |

Yanlış sınıfları (kural; `K/hata_gcc_kural.txt`):

| Çift | Yanlış | tek taraflı | satır içi | komşu | aile | diğer | Tavan içi kesinlik |
|---|---|---|---|---|---|---|---|
| `derleyici` (aynı sürüm, GCC ↔ clang) | 38 | **4** | 13 | 16 | 3 | 2 | 3 908 / 3 929 = 0,995 [0,992–0,997] |
| `surum_gcc` (sürüm farkı, GCC ↔ GCC) | 150 | **105** | 20 | 9 | 7 | 9 | 2 369 / 2 394 = 0,990 [0,985–0,993] |
| `sinama_tmux` (sürüm farkı, GCC ↔ clang) | 158 | **99** | 25 | 17 | 10 | 7 | 2 276 / 2 310 = 0,985 |
| `derleyici_htop` | 16 | 0 | 6 | 6 | 1 | 3 | 972 / 982 = 0,990 |

**Ön kayıtlı hükümler (G1–G7):**
- G1 (aynı sürüm, GCC ↔ clang, v1 kural: Wilson alt ≥ 0,95) → **TUTTU** (0,987). **Aykırı öncül 1, başvuru aynı
  sürümse derleyici farkına rağmen geçerli.**
- G2 ("tek taraflı" yanlış ≤ 10) → **tuttu** (4; sürüm farklıyken 99 ve 105): bu sınıfın sürüm kaynaklı olduğu
  bağımsız veride doğrulandı.
- G3 (satır içi + komşu türü yanlış > 0) → tuttu (29). G4 (kapsam ≥ %50) → tuttu (%80,1).
- G5 (`surum_gcc`'de satır içi + komşu < 42) → tuttu (29).
- G6 (v2: kapsam v1'den büyük, Wilson alt ≥ 0,95) → **tuttu** (%87,7; 0,989). Tablo yuvası kanıtının (v2) ilk
  bağımsız sınaması; §3.5'teki "ikinci bakış" kaydı bu çiftte geçerli değil.
- G7 (ad ailesi küme isabeti Wilson alt ≥ 0,95) → **tutmadı** (271 / 288 = 0,941 [0,907–0,963]; etiketli
  266 / 272 = 0,978 [0,953–0,990]).

**Öncül 3'ün temiz cevabı (tmux, kural noktası):**

| | Aynı sürüm (3.8 ↔ 3.8) | Sürüm farkı (3.5a ↔ 3.8) |
|---|---|---|
| GCC ↔ clang | 0,990; kapsam %80,1; yanlış 38 (yeniden adlandırma 4, satır içi türü 29) | 0,935; %51,8; yanlış 158 (99, 42) |
| GCC ↔ GCC (14 ↔ 16; platform da farklı) | iyileştirme düzeyi çiftleri: §3.8 | 0,940; %56,6; yanlış 150 (105, 29) |

Sürüm farkı yaklaşık 100 yeniden adlandırma yanlışı ve 25–30 puan kapsam kaybı getiriyor; derleyici farkı yaklaşık
29 satır içi türü yanlış ve birkaç puan kapsam. **Sürüm farkı derleyici farkından pahalı.** Tekil dizgi çapasının
tmux'taki 54 yanlışı sürüm eşlenince 0'a iniyor (1 085 / 0): o yanlışlar satır içinden değil sürümden geliyormuş.

Aynı çiftte çıplak yöntemler (`K/ciplak_gcc.txt`): tekil dizgi 1 085 / 0 (kapsam %22,2); CFG yapısı tekil 48 / 24;
CFG + komut kümesi 54 / 2 (kapsam %1,1). Aynı sürümde bile GCC ↔ clang arasında CFG bankası eşleşmiyor.

Eğri (`derleyici`, T / kütle → doğru / yanlış, Wilson alt, kapsam): 0,3 / 0,5 → 3 908 / 38, 0,987, %80,1;
0,5 / 1,0 → 3 527 / 21, 0,991, %72,3; 0,7 / 1,0 → 3 102 / 12, 0,993, %63,6.

### 3.7 Başvurunun sembollü analizi (ön kayıtlı)

Bu turda başvuru tarafı da soyulmuş analiz edildi (adlar GT'den). Gerçek kullanımın karşılığı için Mac tmux 3.8'in
sembollü özgün ikilisi ayrıca analiz edildi (`ek/macsym/tmux`; Ghidra 2 579 fonksiyon, 2 562'sinin adı hazır).
Komut: `python scripts/arge/kimlik/yayilim_olc.py sembollu --json K/yayilim_sembollu.json`.

| Sorgu → başvuru | Nokta | Soyulmuş başvuru | Sembollü başvuru |
|---|---|---|---|
| Debian tmux → Mac tmux | kural | 1 118 / 76 | 1 121 / 76 |
| | tutucu | 1 001 / 63 | 1 003 / 63 |
| | kural_v2 | 1 263 / 83 | 1 267 / 83 |
| GCC tmux → Mac tmux | kural | 1 919 / 17 | 1 919 / 18 |
| | tutucu_v2 | 2 050 / 11 | 2 055 / 11 |

Ön kayıt E3 (doğru sayısı ±%5 içinde) ve E4 (kesinlik aralıkları örtüşür) → **tuttu** (fark en çok %0,4).
Soyulmuş başvuru analizi bu ölçümlerde sembollü analizin sadık bir vekili.

### 3.8 Yalnız iyileştirme düzeyi (A4'ün üçüncü etkeni; ön kayıtlı, taze veri)

tmux 3.8, GCC 16, `-O0` ve `-O3` derlemeleri (`bash scripts/arge/kimlik/derle_gcc_duzey.sh`; GT'de 3 265 ve 2 335 fonksiyon,
`-O2`'de 2 422) ↔ `-O2`. Komut: `bash scripts/arge/kimlik/son_olcum.sh duzey` → `K/yayilim_duzey.*`, `K/hata_duzey_<nokta>.*`,
`K/ciplak_duzey.*`. Ön kayıt `DEFTER.md` §5.11.

| Çift (aynı sürüm, aynı derleyici) | Nokta | Doğru / yanlış | Kesinlik [Wilson] | Kapsam | tek taraflı / satır içi / komşu / aile / diğer |
|---|---|---|---|---|---|
| `-O3` ↔ `-O2` (nüfus 4 582) | kural | 3 575 / 68 | 0,981 [0,976–0,985] | %78,0 | 10 / 19 / 31 / 6 / 2 |
| | kural_v2 | 3 980 / 67 | 0,983 (alt 0,979) | %86,9 | 10 / 17 / 31 / 7 / 2 |
| `-O0` ↔ `-O2` (nüfus 5 600) | kural | 3 547 / 110 | 0,970 (alt 0,964) | %63,3 | 0 / 48 / 45 / 16 / 1 |
| | kural_v2 | 3 943 / 98 | 0,976 (alt 0,971) | %70,4 | 0 / 42 / 37 / 18 / 1 |

- Ön kayıt: I1 (`-O3` ↔ `-O2`, Wilson alt ≥ 0,95) **tuttu**; I2 (`-O0` çiftinde satır içi + komşu daha çok: 93 ↔ 50)
  **tuttu**; I3 (`-O0` ↔ `-O2`, alt ≥ 0,909) **tuttu** (0,964); I4 (tek taraflı ≤ 10) **tuttu** (10 ve 0).
- Aynı çiftlerde hazır yöntemler (`K/ciplak_duzey.txt`): `-O3` ↔ `-O2`: BSim en iyi aday ≥ 0,7: 1 328 / 365 = 0,784
  [0,764–…], "tek en iyi" kapısıyla 1 219 / 37 = 0,971 (kapsam %54,3); CFG + komut kümesi 1 216 / 2 (kapsam %26,5).
  `-O0` ↔ `-O2`: BSim 293 / 202 = 0,592, CFG + komut 0 eşleşme. İyileştirme düzeyi tek başına değişince CFG bankası
  ve BSim çöküyor; çapalı yayılım 0,970'te kalıyor.
- "Tek taraflı" sınıf aynı sürümde de 0–10 çıkıyor (iki tarafta farklı fonksiyonların satır içine alınması): sınıf
  yalnız yeniden adlandırma değil; sürüm farkının getirdiği fazlası ~95–100.

### 3.9 Satır içi tanığı (kalan yanlışların ana sınıfı için)

Sürüm eşlenince kalan yanlışların çoğu satır içi türü (`derleyici`: 29 / 38; `-O0` çifti: 93 / 110).
İki deneme:
1. **Kanıt kütlesi dengesi** (bir taraf öbüründen çok kanıtlıysa ad verme): olumsuz (§8.3).
2. **"Çağıranın çağrılanı" tanığı** (`scripts/arge/kimlik/tanik.py`): eşleme bittikten sonra, q'nun bir çağıranının
   çağırıp q'nun çağırmadığı eşlenmiş bir fonksiyonu r çağırıyorsa (ya da simetriği), q → r "tanıklı"dır. Tek
   parametre (seyreklik süzgeci) htop'ta kapatıldı (süzgeç zararlıydı); `derleyici` ve tmux çiftleri keşifte
   görüldü; `-O3` / `-O0` çiftleri dondurulmuş sınamadır (ön kayıt `DEFTER.md` §5.17).

Komut: `python scripts/arge/kimlik/tanik.py iyilestirme_o3 iyilestirme_o0 derleyici derleyici_htop sinama_tmux surum_gcc --nokta kural --kmax 1000000000 --json K/tanik_sinama_kural.json`
(ve `--nokta tutucu_v2`).

| Çift (kural) | Önce | Tanıklı: doğru / yanlış (alt kanal kesinliği) | Satır içi türünden yakalanan | Tanıksız kalan |
|---|---|---|---|---|
| `-O3` ↔ `-O2` (sınama) | 3 575 / 68 | 197 / 36 (0,845 [0,793–0,886]) | 31 / 50 | 3 378 / 32 = 0,991 [0,987–0,993] |
| `-O0` ↔ `-O2` (sınama) | 3 547 / 110 | 243 / 53 (0,821 [0,773–0,860]) | 48 / 93 | 3 304 / 57 = 0,983 [0,978–0,987] |
| `derleyici` (keşif) | 3 908 / 38 | 139 / 21 (0,869 [0,808–0,912]) | 19 / 29 | 3 769 / 17 = 0,996 [0,993–0,997] |
| `sinama_tmux` (keşif; sürüm farklı) | 2 276 / 158 | 148 / 21 (0,876 [0,818–0,917]) | 16 / 42 | 2 128 / 137 = 0,940 |

- Ön kayıt: T1 (tanıklılarda yanlış oranı, tanıksızlardakinin ≥ 5 katı) **tuttu** (`-O3`: %15,5 ↔ %0,9; `-O0`:
  %17,9 ↔ %1,7). T3 (satır içi türünün ≥ %50'si tanıklı) **tuttu** (%62, %52). T2 (düşen doğru / düşen yanlış ≤ 1,0;
  "ucuz kapı") **tutmadı** (5,5 ve 4,6).
- Okuma: tanık ucuz bir kapı değil (her yanlış için ~5 doğru ad da gidiyor), ama **alt kanal** olarak ölçülmüş
  kesinliği her çiftte karar kuralı eşiğinin (Wilson alt ≥ 0,909) altında: 0,77–0,86. Karar kuralı uygulanırsa
  tanıklı eşlemeler ad yerine kanıt satırı yazar; kapsam ~3–4 puan düşer, kalan adların kesinliği 0,98–0,997 olur.
  Karar ürün tarafınındır (PLAN PK-7).

## 4. İkiz analizi (kalem 4)

Aile kuralı (`scripts/arge/kimlik/ikiz.py`; htop'ta ayarlandı, donduruldu): kapıda kalan fonksiyonun en iyi adayının
puanı ≥ 0,3 ve kütlesi ≥ 0,5 ise, en iyi puandan 0,2 içinde kalan adaylar (en çok 8) bir **ad ailesi** olur.
"Küme isabeti": GT adı ailenin adları arasında. "Etiketli": ailenin `_` sınırında ortak öneki ya da soneki var
ve GT adı onunla uyuşuyor.

| Birim (kural) | Aile sayısı | Küme isabeti | Tavan içi küme isabeti | Etiketli (önek / sonek) | Tek üyeli (aile sayılmaz) |
|---|---|---|---|---|---|
| tmux | 259 | 212 / 259 = **0,819 [0,767–0,861]** | 212 / 233 = 0,910 [0,866–0,940] | 199 / 215 = 0,926 [0,882–0,954] | 8 / 28 |
| coreutils ↔ Homebrew | 116 | 110 / 116 = 0,948 [0,892–0,976] | 110 / 114 = 0,965 | 22 / 22 | 8 / 23 |
| coreutils içi | 598 | 592 / 598 = **0,990 [0,978–0,995]** | 592 / 598 | 221 / 221 = 1,000 [0,983–1] (hepsi önek) | 1 / 2 |
| sürüm | 237 | 224 / 237 = 0,945 [0,908–0,968] | 224 / 235 = 0,953 | 115 / 116 | 2 / 3 |
| htop (ayar) | 51 | 49 / 51 = 0,961 | 49 / 49 | 33 / 33 (30'u sonek) | 5 / 12 |

- **Ön kayıt Ö6 (küme isabeti Wilson alt ≥ 0,95):** tmux'ta **tutmadı** (0,767); coreutils içinde tuttu (0,978).
  Aykırı öncül 2 aynı derleyicide geçerli, derleyici + sürüm farkında değil (26 ailede GT adı başvuruda hiç
  yok; tavan içinde bile 0,910).
- **İkizlerin türü:** coreutils'te aileler ortak **önek** taşıyor (P11'in `quotearg_*` ↔ `*_mem` türü); htop'ta
  ortak **sonek** (`CommandScreen_delete` ↔ `EnvScreen_delete`; 30 / 33) ya da seçenek çifti
  (`actionNextScreen` ↔ `actionPrevScreen`, etiketsiz). Aile etiketi yalnız önek olarak tanımlanırsa htop
  türü programlarda boş kalır.
- Tek üyeli "aile" (tek aday var ama karşılıklılık kapısını geçemedi) güvenilmez: tmux 8 / 28. Ad sayılmamalı.
- **H3'ün sorusu (işlenen bilgisi ikizleri ayırır mı), aynı derleyici, taze 10 çift**
  (`python scripts/arge/kimlik/ayni_derleyici.py --json K/ayni_derleyici.json`): CFG yapısı + komut kümesi aynı olduğu
  için CFG-iso'nun ayıramadığı nüfus fonksiyonu 508 (nüfus 2 552'nin %19,9'u). Sabit + çağrılan kimliği kullanan
  yayılım bunların 69'una ad veriyor (66 doğru, 0,957 [0,880–0,985]); 394'ü ad ailesinde kalıyor, küme isabeti
  385 / 394 = 0,977 [0,957–0,988]; 45'i sessiz. İşlenen bilgisi ikizlerin %13,6'sını ayırıyor; çoğunun dürüst
  cevabı ad ailesi.

## 5. Aynı derleyici kopyaları: birleşim ve çok başvuru (A2, C5)

Komut: `python scripts/arge/kimlik/ayni_derleyici.py --json K/ayni_derleyici.json` (taze çiftler; kurallar sayılardan
önce `DEFTER.md` §5.7'de).

| Ölçüm | Doğru / yanlış | Kesinlik | Kapsam |
|---|---|---|---|
| Yayılım (kural), tek başvuru | 964 / 14 | 0,986 [0,976–0,992] | 964 / 2 552 = %37,8 |
| CFG + komut kümesi tekil, tek başvuru | 930 / 0 | 1,000 [0,996–1] | %36,4 |
| **Birleşim** (çelişirse ad yok; çelişen 3) | 1 217 / 11 | **0,991 [0,984–0,995]** | **%47,7** |
| Çok başvuru (5 ikili), `gnulib` sınıfı | 660 / 9 | **0,987 [0,975–0,993]** | 660 / 1 180 = **%55,9** (tavan 1 027) |
| Çok başvuru, `program` sınıfı | 23 / 2 | 0,920 | 23 / 109 = %21,1 (tavan 24) |

- Ön kayıt: birleşim Wilson alt ≥ 0,95 ve kapsamı ikisinden büyük → **tuttu**. Çok başvuruda `gnulib` kesinliği
  **tuttu**, kapsam ≥ %60 **tutmadı** (%55,9).
- Karşılaştırma (aynı ölçü değil, aynı sınıf): taban üründe `gnulib` sınıfının doğru ad kapsamı %5,6
  (634 / 11 393; OLGU `BUTCE.md` §1).
- **C5 (kitaplık kodunu işaretleme):** çok başvurulu eşlemede ad üzerinde uzlaşılan 697 fonksiyonun 669'u
  `gnulib` sınıfında (660 + 9), 25'i `program` (coreutils'in programlar arası ortak kaynak dosyaları), 3'ü
  `derleyici`. "Başka ikilide de var" işareti `gnulib` nüfusunun 669 / 1 180 = %56,7'sini kapsıyor.
  Derleyiciler arası işaretleme ölçülmedi (tmux `compat/` sınıfı 95 fonksiyon, eşlenen 41; sayı az).
- **Sınır:** bu yol başvurunun aynı derleyici ve ayarla derlenmiş olmasını ister (CFG kolu sürümler arasında 0
  eşleşme veriyor, §2.1). Gerçek kullanımda bu, dağıtımın kendi dbgsym paketi demektir (§6).

## 6. Gerçek kullanım: başvuru derlemesi nereden gelir? (kalem 5)

| Seçenek | Ne zaman | Beklenen kesinlik (bu turun ölçümüyle) | Maliyet | İndirme |
|---|---|---|---|---|
| **A. Aynı derleme (build-id eşleşmesi).** İkili bir dağıtım paketinden çıkmışsa GNU build-id'si, dağıtımın ayrık hata ayıklama dosyasını (`.build-id/xx/….debug`) birebir gösterir | soyulmuş dağıtım ikilisi | eşleme gerekmez; adlar aynı derlemeden okunur (geliştirme setinin GT'si tam olarak budur: ölçülen 116 Debian ELF'in hepsinde build-id ile tek `.debug` dosyası bulundu, `ks1_olc.gt_elf`; `K/a1_pay.json` yüklenen 118 / 118) | dosya başına 0,8–2,3 MB (htop 784 008 bayt, tmux 2 258 632 bayt; coreutils dbgsym paketi 6,8 MB) | analistin elinde yoksa evet (debuginfod ya da `-dbgsym` paketi) |
| **B. Aynı kaynak, aynı derleyici ailesi, başka program / sürüm** (dağıtımın başka paketi, kardeş ikili) | statik bağlı kitaplık kopyaları (gnulib türü) | aynı sürüm: 0,987–0,991, kapsam %48–56 (§5); sürüm farkıyla 0,949 [0,926–0,965] (§3.1) | var olan dbgsym'ler | evet |
| **C. Aynı kaynak, başka sürüm ve başka derleyici / platform** (Homebrew ↔ Debian) | programın başka dağıtımdaki derlemesi | 0,871–0,935; adı başvuruda olanlarda 0,969–0,985; kapsam %33–52 (§3.1) | başvurunun Karadul koşusu (tmux 412 sn, htop 107 sn; taban ölçümü) | evet |
| **D. Kaynaktan derleme** (sürüm biliniyorsa aynı sürüm, sembollü) | sürümü dizgilerden okunabilen açık kaynak program | aynı sürüm, başka derleyici: **0,990 [0,987–0,993], kapsam %80–88** (tmux); htop 0,984 [0,974–0,990] (§3.6); başka iyileştirme düzeyi 0,970–0,981 (§3.8) | kaynak + derleme (bu turda tmux ve htop GCC ile birkaç dakikada derlendi) + başvurunun Ghidra analizi (tmux 5–8 dk) | kaynak elde yoksa evet; ürünün var olan yolu (`reference_populator.py`: sqlite3, zlib) `allow_reference_download` arkasında |
| **E. Hazır imza kümesi** (imza VT, FLIRT, BSim deposu) | başvuru yok | imza VT 0 / 208 (P11); BSim derleyiciler arası 0,610 (tekillik kapısıyla 0,851, kapsam %12); FLIRT bekletiliyor (P08b) | sıfır | hayır |

- A seçeneği en ucuz ve kesin yoldur ama Karadul'da yok: ürünün DWARF kanalı (`enable_dwarf_naming`, kapalı)
  yalnız ikilinin kendi DWARF'ını ya da `.dSYM`'i okuyor (`karadul/analyzers/dwarf_extractor.py`, satır 114–137);
  build-id ile ayrık `.debug` dosyası arama yok (`grep -n "debuglink\|build.id" karadul/analyzers/dwarf_extractor.py` boş).
- Dış kaynak (değişebilir bilgi):
  - Claim: Debian ve Ubuntu, build-id ile hata ayıklama dosyası veren debuginfod hizmeti işletiyor.
  - Evidence: https://wiki.debian.org/Debuginfod ; https://ubuntu.com/server/docs/how-to/debugging/about-debuginfod/index.html
  - Confidence: medium (arama sonucu özetinden; sayfalar açılıp okunmadı).
  - Date checked: 2026-11-19.
  - What may change: hizmetin kapsadığı sürümler, erişilebilirlik.
- Ağa çıkan her yol `network.enabled` kapısından geçmek zorunda (P-GÜV); çevrimdışı yol: analist dosyayı kendisi verir.
- FLIRT ile çakışma (P08b): bu hattın önerdiği hiçbir paket FLIRT bayt imzalarına dokunmuyor.

## 7. A1'e katkı: nüfusta "başka yerde kaynağı bulunan kod" payı (kalem 6)

Komut: `python scripts/arge/kimlik/a1_pay.py --json K/a1_pay.json`; çapraz denetim `olgu_capraz.py` (§3.4'teki komut).

| Birim | İkili | Nüfus | Aynı birimde başka ikilide aynı ad + aynı boyut | Yalnız aynı ad | Öbür platform derlemesinde var | Set içinde başvurusu yok |
|---|---|---|---|---|---|---|
| debian/coreutils | 106 | 12 717 | 12 107 | 133 | 0 | 477 |
| debian/redis-tools | 4 | 1 458 | 1 365 | 5 | 0 | 88 |
| debian/tmux | 1 | 1 851 | 0 | 0 | 1 712 | 139 |
| mac/tmux | 1 | 2 545 | 0 | 0 | 1 754 | 791 |
| debian/htop | 1 | 222 | 0 | 0 | 180 | 42 |
| mac/htop | 1 | 597 | 0 | 0 | 515 | 82 |
| debian/zstd | 1 | 919 | 0 | 0 | 0 | 919 |
| debian/openssl | 1 | 563 | 0 | 0 | 0 | 563 |
| debian/sqlite3 | 1 | 389 | 0 | 0 | 0 | 389 |
| debian/tree | 1 | 110 | 0 | 0 | 0 | 110 |
| **Toplam** | 118 | **21 371** | **13 472 (%63,0)** | 138 (%0,6) | **4 161 (%19,5)** | **3 600 (%16,8)** |

- Nüfus toplamı taban ölçümüyle aynı (21 371); OLGU tablosunun nüfus satırlarıyla birebir (eksik 0).
- OLGU sınıflarıyla çapraz: OLGU `gnulib` 11 393 → 11 294'ü "aynı ad + aynı boyut" kopya, 2'si yalnız ad,
  97'si tek ikilide geçen gnulib fonksiyonu; `ucuncu_taraf` 881 → 878 kopya; `program` 4 977 → 1 144 kopya
  (coreutils ve redis'in programlar arası ortak dosyaları), 1 810 öbür platform derlemesinde, 1 887 başvurusuz;
  `proje_kitapligi` 720 (zstd'nin `lib/`) → hepsi başvurusuz. İki bağımsız sayım tutarlı.
- **Okuma:** ad bekleyen nüfusun %82,5'inin (13 472 + 138 + 4 161 = 17 771) kodu, geliştirme setinin kendi
  içinde başka bir yerde adıyla duruyor. "Set içinde başvurusu yok" 3 600'ün içinde de kaynağı başka yerde
  bulunanlar var (zstd'nin 720'si libzstd; dağıtımda sembollü kitaplığı bulunur) ama sette başvurusu yok.
- **Sınır:** %63,0'lık kopya payı coreutils'in 106 ikilisinden geliyor (tek birim, ortak kod). Tekil kaynak
  fonksiyonu sayımında (OLGU: nüfus 9 257) gnulib 537'dir; pay bu yüzden program düzeyinde çok daha küçüktür.
  Bu sayım bir bütçe girdisidir, genelleme değil.

## 8. Olumsuz sonuçlar (yinelenmesin)

1. Dondurulmuş çapalı yayılım **sürüm farkında** tam ad kesinliği 0,95'e ulaşmıyor (tmux 0,935; aynı derleyici
   ailesinde bile 0,940; coreutils ↔ Homebrew 0,871); eşiği sıkmak çözmüyor (§3.2).
2. Tekil dizgi çapası sürümler arasında "kesin" değil: tmux 737 / 54 (0,932); aynı sürümde GCC ↔ clang 1 085 / 0,
   ama iyileştirme düzeyi farkında yine yanılıyor (`-O0` ↔ `-O2` 976 / 34): yeniden adlandırma ve satır içine alma
   dizgiyi başka adlı fonksiyona taşıyor.
3. Satır içi kapısı olarak **kanıt kütlesi dengesi** işe yaramıyor
   (`python scripts/arge/kimlik/satir_ici.py kesif_htop sinama_tmux sinama_cu_mac derleme --nokta kural --json K/satir_ici_kural.json`):
   htop'ta denge ≥ 0,6 kapısı 34 doğru düşürüp 6 yanlış kaldırıyor (satır içi türü 9 yanlışın 2'si); tmux'ta
   (ikinci bakış) ≥ 0,5: 83 doğruya karşı 20 yanlış (42 satır içi türünün 5'i). Yalnız LTO çiftinde kısmen:
   ≥ 0,6 ile 20 doğruya karşı 13 yanlış (21'in 11'i).
4. CFG + komut kümesi bankası derleyici sürümleri arasında 0 eşleşme veriyor (§2.1).
5. Ad ailesi derleyiciler arasında 0,95 küme isabetine ulaşmıyor (tmux 0,819; tavan içi 0,910).
6. Tablodaki dizgi komşuluğu (`t`) tek başına htop'ta katkı vermiyor (535 / 18; v1 515 / 16'dan az kazanç,
   daha çok yanlış); katkı eşlenmiş tablo komşusundan (`k`).
7. Ürünün `BinaryDiffer` / `ReferenceDiffer` yöntemlerinden boyut ve CFG tabanlı olanlar derleyiciler arasında
   neredeyse hep yanlış (§2.2).
8. Satır içi tanığı "ucuz kapı" değil: düşürdüğü her yanlış için 4,6–5,5 doğru ad gidiyor (ön kayıt T2 tutmadı; §3.9).
9. Ad ailesi küme isabeti aynı sürümde de 0,95 alt sınırına ulaşmıyor (GCC ↔ clang 0,941 [0,907–0,963]; G7 tutmadı).
10. Koşu kuşağı farkı coreutils ↔ Homebrew sayılarını açıklamıyor: aynı kuşakla yeniden koşuda sonuç birebir aynı
    (316 / 47; ön kayıt E1 tutmadı; `K/yayilim_cu_mac2.txt`).

## 9. Sınırlar

- Geliştirme seti içi; iki program (tmux, htop) ve üç coreutils ikilisi. "Aynı sürüm" sonucu (§3.6, §3.8) tek
  programın (tmux) dört derlemesine ve htop'un bir derlemesine dayanıyor; tek ikiliden genelleme yok. tmux ve htop
  aynı tür (C, tablo ağırlıklı uçbirim programı). GCC derlemeleri macOS'ta (Mach-O) yapıldı; "GCC ↔ clang" farkı
  aynı platformda ölçüldü, Linux GCC ↔ macOS clang aynı sürümle ölçülmedi.
- İki tarafta da AArch64. Mimari farkı (x86-64 ↔ AArch64) ölçülmedi: elde çift yok (açık ölçüm).
- Başvuru tarafı için soyulmuş koşunun Ghidra çıktısı kullanıldı (adlar GT'den). Sembollü analizle fark ≤ %0,4
  (§3.7; tek program).
- Ek koşular (GCC derlemeleri, sembollü tmux, Homebrew coreutils yeniden koşusu) `--stage static` ile yapıldı
  (makine yükü); eşleyicinin okuduğu olgunun tam koşuyla aynı olduğu Debian htop'ta denetlendi (609 / 609).
- "Tek taraflı" sınıfın aynı fonksiyon olduğu doğrulanmadı; ona dayanan her sayı yön gösterici.
- v2 sonuçları tmux (sürüm farklı) ve coreutils çiftlerinde "ikinci bakış"; `derleyici`, `derleyici_htop` ve
  iyileştirme çiftlerinde ön kayıtlı sınama.
- "Satır içi" / "komşu" sınıflaması GT adlarından dolaylı çıkarılıyor (önerilen ad sorguda başka fonksiyonda var mı;
  seçilen, doğrunun çağrı komşusu mu); `-O0` ↔ `-O2` çiftinde bu türün 50 → 93'e çıkması sınıflamanın satır içine
  almayı ölçtüğünü destekliyor (I2), ama kaynak düzeyinde doğrulanmadı.
