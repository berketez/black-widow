# PK-1 ön kaydı (ölçümden önce; 2026-11-23 akşam)

Kaynak metin: `kimlik/PLAN.md` PK-1 "Ön kayıt metni" (aynen aşağıda) + ana oturumun hükümleri
(`docs/arge/2026-11-23_dalga1/gonderim/PK1.md`: hüküm 1 eşik `AD_ESIGI` içe aktarılır, hüküm 6 → H5).
Bu belge kod ve ölçümden önce commit'lenir; tutmayan beklenti silinmez, eşik sonradan değişmez.

## Plan metni (aynen)

> PK-1 ön kaydı. Taban: `K/urun_bindiff.json` / `.txt` (a62f15e çıktıları, 2026-11-19; komut
> `python A/urun_bindiff.py kesif_htop sinama_tmux sinama_cu_mac sinama_cu_ic surum`). Yöntem kapısı tablosu =
> "TÜM GRUPLAR" satırları (beş grubun havuzu; nüfus içi, tam eşitlik; doğru / ad verilen, Wilson alt):
> `string_refs` 414 / 438 (0,920); `string_fingerprint` 476 / 494 (0,943); `call_pattern` 222 / 283 (0,733);
> `cfg_fingerprint` 445 / 584 (0,726); `size_params` 99 / 540 (0,153); `cfg_similarity` 1 529 / 2 748 (0,538);
> `size_constant` 43 / 157 (0,210); `call_propagation` 8 / 16 (0,280); `decompiled_hash` ölçülmedi (ad veremez).
> Eşik 0,909 (KARARLAR A-2) → ad verebilen yalnız `string_refs` ve `string_fingerprint`. Beklenen: kapıdan sonra
> tmux'ta `BinaryDiffer` adları 326 / 16 (önce 328 / 174), `ReferenceDiffer` adları 304 / 12 (önce 366 / 769);
> beş grubun havuzunda `BinaryDiffer` (`config`) 958 / 604 → 414 / 24, `ReferenceDiffer` 2 056 / 1 359 → 476 / 18;
> düşen adların hepsi `reference_evidence`'ta. H1: yeni yanlış = 0.
> H2: kaybedilen doğru (kanıt satırına inen): havuzda `BinaryDiffer` `config` 958 − 414 = 544 (çoğu aynı
> derleyicideki `cfg_fingerprint` 445), `ReferenceDiffer` 2 056 − 476 = 1 580 (`cfg_similarity` 1 529); giderilen
> yanlış 580 ve 1 341. H3: aynı derleyici çiftinde (`sinama_cu_ic`) `cfg_fingerprint` 356 / 21 (alt 0,916) tabloya
> AYRI koşul olarak yazılmaz: yöntem tek satırdır, derleyiciler arası 0 / 42 ve başvurunun derleyicisi bilinmiyor.
> Aynı derleyici kopyalarının doğru adları PK-4 (çapalı eşleyici) ile geri gelir. Tutmazsa eşik değişmez.

## Bu oturumun eklemeleri (ana oturum hükümleri)

- **Eşik:** `karadul.core.naming_labels.AD_ESIGI` = `MALIYET_ORANI_L / (MALIYET_ORANI_L + 1)` = 10 / 11
  (A-13, A-25). Karşılaştırma kesrin kendisiyle ve yuvarlanmamış Wilson alt sınırıyla yapılır; tabloda alt sınır
  elle yazılmaz, `baglama.wilson` ile hesaplanır (hüküm 1, 2). Ürünün köken kaydına ve adayın güvenine giden
  değer bu alt sınırın 4 basamağa AŞAĞI yuvarlanmışıdır (P-ÜV6a düzeni: `naming_labels.floor_confidence`).
- **Kabul ölçütü (plan):** `--kapi` ile tmux `config` kipi toplam = yalnız `string_refs` satırı 326 / 16;
  `refdb` kipinde `call_pattern` adı 0 (önce 91 / 56); `refdiffer` kipinde yalnız `string_fingerprint` 304 / 12.
  Beş grubun havuzunda 414 / 24 ve 476 / 18. Yeni yanlış 0. Tam takım yeşil (yamasız kural: ORTAK_D1 §2).
- **H4 (plan "Ürüne girişi"):** öntanımlı koşuda davranış aynı (`reference_binary` boş, `ref_db` boş ya da yok):
  ad haritasına fark 0. Denetim Ghidra'sız yeniden oynatmayla: hazır çalışma alanlarından 14 ikili üstünde
  `run_bindiff` + `run_reference_differ` öntanımlı ayarla, main (`0b4d948`) kodu ile bu dalın kodu; beklenen
  her iki kolda `bindiff_names` = `refdiff_naming` = boş ve `extracted_names` bayt bayt aynı.
- **H5 (hüküm 6; PK-11'in taze çifti `gomulu_kitaplik`, Q → R satırı, ilk ölçüm):** önce (PK-11.md)
  `BinaryDiffer` `config` 34 / 93, `refdb` 44 / 94, `ReferenceDiffer` 175 / 116. Beklenen kapıdan sonra
  `config` 6 / 0 (yalnız `string_refs`), `refdb` 6 / 0 (`call_pattern` 10 / 1 kanıt satırına iner),
  `ReferenceDiffer` 12 / 0 (yalnız `string_fingerprint`). **Hüküm: yeni yanlış 0** (tutar / tutmaz). Kalan
  adların Wilson alt sınırı yalnız raporlanır (eşik yok; ilk ölçüm; küçük n beklenir).
- **Kanıt satırı:** kapıdan düşen her eşleşme `naming_provenance.json` → `reference_evidence` bölümünde ve
  `stats["bindiff_evidence"]` / `stats["refdiff_evidence"]`'te; sayaçlar `stats["bindiff_method_gate"]` /
  `stats["refdiff_method_gate"]` (`yöntem → {ad, kanit}`). Satır biçimi P-ÜV6a'nın `ust_veri_kanit` satırıyla
  aynı alanlar (`kaynak`, `adres`, `ozgun_ad`, `nedenler`) + `anahtar`, `yontem`, `olculmus_alt`.
- **Sınama ve mutasyon (plan):** m1 karşılaştırma kaldırılır / eşik 0 alınır (hüküm 1) → (b) kırmızı;
  m2 tablo dışı yöntem `True` → (a) kırmızı; m3 kanıt satırı yazılmaz → (b) kırmızı; m4 `_add_refdiff` sabit 0,95
  geri → (c) kırmızı. Beklenen 4 / 4 (ek mutantlar eklenebilir; hepsi ölmeli).
