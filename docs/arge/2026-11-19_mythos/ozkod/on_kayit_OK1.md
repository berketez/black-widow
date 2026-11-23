# ÖK-1 ön kaydı (OK1 paketi; P12d ile birlikte) — 2026-11-23

**Durum:** KESİN. Ölçümden (K0 / K1 / K2 / K2k ürün yeniden oynatması ve tanı taraması) ÖNCE commit'lenir. Taban main `bf62e4a`; P12d kodu dalda `4d3afca` (D1) + `45f7f85` (D2). Tutmayan beklenti silinmez; eşik sonradan değişmez.

## 1. Kollar ve set

- **K0:** main `bf62e4a`. **K1:** K0 + P12d (`45f7f85`). **K2:** K1 + ÖK-1 kodu, `binary_reconstruction.oz_ad_verbatim: true` (kolun ağacındaki `karadul.yaml` ile; alan bugün INERT, yalnız uyarı basar). **K2k:** K2 kodu, bayrak kapalı (öntanım).
- Set: geliştirme setinin 119 ikilisi; girdi `~/karadul_olcum/runs/urun-onarim-a62f15e` çalışma alanları (SALT OKUR). Ghidra koşusu yok: `c_namer` Ghidra'dan sonra koştuğu için yeniden oynatma (`yeniden.py`, P12a / P12d yöntemi, yalnız `ReconstructionStage`) geçerlidir. `PYTHONHASHSEED=0`, ikili başına ayrı önbellek.
- Hüküm aracı `scripts/measurement/urun_olc.py olc` (her kol kendi ağacının sınıflayıcısıyla: `--siniflayici-agac`) + `karsilastir`. Tam eşitlik birincil; A-3 "tam + biçim" ayrıca (P-Ö1 biçim satırı).

## 2. Ölçüm kapsamı (süre sınırı yüzünden; ölçümden önce yazıldı)

Bir kolun 119 ikilisi P12d'de yük altında yaklaşık 2 saat sürdü (iş süresi toplamı ≈ 6 saat; en ağırları redis-check-aof / rdb 38'er dk, openssl 33 dk). Sert son 21:30 olduğu için:
1. **Tanı taraması, 119 / 119, dört kol:** ürünün yükleyicileri + `_strategy_string_context` (fonksiyon başına, ana süreçte), susturmadan sonra kalan `string_context` adayları (ad, alt kanal). Bir ikilinin bu çıktısı iki kolda aynıysa `c_namer`'ın o ikiliye verdiği `string_context` adayları aynıdır; bu ikililer ürün yeniden oynatmasına alınmaz ve "tanı düzeyinde aynı; ürün koşusu yok" diye etiketlenir.
2. **Ürün yeniden oynatması:** tanıda kollar arasında farklı çıkan ikililer (K0 ↔ K1 ↔ K2) için K0, K1, K2; süre kalırsa aynı altkümede K2k. Bitmeyen ikili "kalan" yazılır; ölçüm `--eksik-izinli` ile, altküme açıkça yazılarak verilir.
3. H9 (K2k = K1) tanı düzeyinde 119 / 119 verilir; ürün düzeyinde yalnız koşulan altkümede.

## 3. Beklentiler

**H0 (P12d yeniden üretimi, K0 → K1):** `oz_ad`'da doğru ad +17, yanlış geri 0, yeni yanlış 4, öbür kanallar aynı (P12d raporundaki sayılar; main o günden beri değiştiği için ± 1 sapma açıklanarak kabul).

**ÖK-1 (plan metni aynen; K1 → K2 farkı olarak okunur):** Beklenti, `scripts/arge/ozkod/oz_ad_harf.py`'nin a62f15e tabanındaki çıktısından: `oz_ad` kanalında yanlıştan doğruya dönen 40 ad (zstd 37, coreutils 1, openssl 1, mac/tmux 1; `redis-check-rdb` ≡ `redis-check-aof` olduğu için 119'luk sayımda en çok +1 fark).
- **H1:** dönen ad 36–44.
- **H2:** doğrudan yanlışa dönen 0.
- **H3:** zstd yanlış ad ≤ 12.
- **H4:** öbür kanallar aynı.
- **H5:** yeni yanlış ≤ 2.
- **H6 (karar dışı):** program düzeyi makro yanlış oranı düşer.
- Taban P12d'yi içerdiği için `oz_ad` ad sayısı a62f15e'dekinden farklıdır; beklenti fark olarak okunur, mutlak sayı olarak değil.

**H7 (birleşik, K0 → K2):** `oz_ad` kanalında doğru ad en az +53 (17 + 36); yeni yanlış ≤ 6; öbür kanallar aynı.

**H8 (P12d'nin dört yeni yanlışı):** K2'de bunların kaçı yalnız biçim farkıdır — yön bildirilmez, sayı ilk ölçüm.

**H9 (bayrak kapalı):** K2k = K1 (ad haritası 119 / 119 aynı; ürün düzeyinde §2'deki altküme).

**H10 (bu paketin eki; yön bildirilmez, bilgi):** Planın adım 2 koşulu (tanımlayıcı ∧ iç alt çizgi ∧ küçük harf) bugün `oz_ad`'a düşen adaylarla sınırlı değildir. Kanıtı tek tanımlayıcı olup anahtar sözcük adı ondan farklı çıkan adaylar (rakam, durak sözcük, 3 harften kısa parça, 3'ten çok belirteç; bugün `tanimlayici` alt kanalı, susar) bayrak açıkken dizginin kendisini ad alır ve `oz_ad`'a geçer (`_is_own_name` sürüm 2: `ad == e`). Bunlar planın 40'lık sayımının dışında yeni adlardır; H5'e girerler. Sayıları (tanıda `tanimlayici → oz_ad` geçen aday) ve ürün hükmü ayrıca yazılır. Bu geçişin bir kısmı A-29'da elenen G1'e (tekil tanımlayıcı dizgiden ad) benzer; o yüzden ayrı raporlanır.

## 4. Kod tarafı kararları (ölçümden önce)

- `oz_ad_verbatim` alanı BAYRAK paketiyle `config.py`'de var (INERT, öntanım kapalı); `config.py`'ye yazılmaz, yama `docs/arge/2026-11-23_dalga1/yamalar/OK1__config.py.patch`.
- `scripts/measurement/alt_kanal.py` (tanım sürümü 1'in donuk başvuru kopyası) **değiştirilmez**: sha256'sı (`d0e6f544…`) N0b ön kaydında, `kesinlik_tablosu.json`'da ve `alt_kanal_olc.py`'de kilitli; değiştirmek N0b'nin donmuş ölçüm kaydını bozar (plan riski 2: "sürüm 2 diye yeni satır aç, eskisini silme"). Ürün kopyası `karadul/reconstruction/tarif/alt_kanal.py`'de `_is_own_name` sürüm 2 olur. İki kopyanın sürüm eşitliğini isteyen iki test satırı için yama bırakılır (gerekçe ilerleme dosyasında).
- Kayda `verbatim: True` alanı eklenmez: aday sınıfı ve köken yazıcısı izinli alanın dışında; harf korunmuş ad kayıttan `evidence.strip() == ad` ile çıkarılır.
