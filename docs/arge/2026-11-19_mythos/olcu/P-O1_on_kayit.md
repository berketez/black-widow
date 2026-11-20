# P-Ö1 — biçim satırı: ön kayıt

Yazıldı: 2026-11-20 08:2x (+03), OLCUM paketi (Dalga 0), dal tabanı `e996200`. Bu belge kod yazılmadan ve ölçüm koşulmadan önce commit'lenir; metin `olcu/PLAN.md` §3 "P-Ö1" "Ön kayıt metni"nin aynısıdır. Sonradan değiştirilmez; tutmayan beklenti silinmez, eşik değişmez (ORTAK_D0 §5).

## Ön kayıt metni (PLAN.md'den aynen)

> Ölçü: `bicim` = ürün adı GT adlarından biriyle harf dizisi olarak aynı (derleyici eki ve sondaki `_<rakam>` soyulur; küçük harf; harf-rakam dışı atılır) ve tam eşit değil. Karar ölçütlerine girmez. Beklenen: a62f15e'de biçim 40 (hepsi `string_context/oz_ad`; zstd 37, coreutils 1, openssl 1, mac/tmux 1), tam + biçim yanlış 79 / 1 800, makro 0,1914; f30ac9a'da biçim 47, yanlış 625 / 2 261, makro 0,4077. Kaynak: `$V/taban_puan.json`, `$V/taban_puan_yeni2.json` (2026-11-19). **Tuttu:** altı sayı tam eşit. **Tutmadı:** herhangi biri farklı; fark açıklanmadan satır yayımlanmaz. Bu satır "yanlış ≤ %10" kararını değiştirmez; karar tam eşitlikle verilmeye devam eder (Berke aksini söyleyene kadar).

## Kabul tablosu (PLAN.md'den aynen; ölçümden sonra P-O1.md'de doldurulur)

| Kol | Ad | Tam doğru | Biçim (tam değil) | Tam + biçim yanlış | Tam + biçim makro yanlış |
|---|---|---|---|---|---|
| a62f15e | 1 800 | 1 681 | 40 | 79 (0,043889) | 0,1914 (coreutils 0,0070; openssl 0,0769; redis-tools 0,2000; sqlite3 0,5833; tmux 0,1178; zstd 0,1636) |
| f30ac9a (1.22.1) | 2 261 | 1 589 | 47 | 625 (0,276426) | 0,4077 |

"Altı sayı": a62f15e kolunda biçim 40, tam + biçim yanlış 79 / 1 800, makro 0,1914; f30ac9a kolunda biçim 47, yanlış 625 / 2 261, makro 0,4077. Ad ve tam doğru sayıları (1 800 / 1 681; 2 261 / 1 589) zemin denetimidir: bugünkü `urun_olc` çıktısıyla aynı olmalı.

Ayrıca (PLAN.md): var olan bütün alanlar (karar (a)–(c), kanal kırılımı, `ogeler`) iki kolda bayt düzeyinde eski çıktıyla aynı (yeni alanlar hariç); `tests/test_urun_olc.py` yeşil.

## Karşılaştırma kuralı (ölçümden önce sabitlenir)

- Makro, `taban_puan*.json`'daki gibi 4 ondalığa yuvarlanarak karşılaştırılır (kaynak dosya 4 ondalık yazıyor); `urun_olc` kesirden 6 ondalık yazar, ikisi de belgeye girer.
- "Eski çıktı": a62f15e kolu için `docs/arge/2026-11-19_birlesik_olcum/urun_olcumu_onarim.json` (sha256 `b6a7b075a30f8a01…`), f30ac9a kolu için `docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni2.json` (sha256 `867453d14ac54185…`). Bayt karşılaştırmasının dışında kalacak alanlar yalnız aracın künyesi (`arac.betik_sha256`, `arac.git_head`, yeni alanlar) ve kolun kök yolları (`kol`); bunlar sonuç belgesinde tek tek yazılır.
- Ad sınıflayıcısı kuralı (birleşik ölçüm ön kaydı §2.2): worktree'nin `naming_labels.py` / `alt_kanal.py`'si a62f15e ürün ağacınınkiyle aynı (`a7f69b55…`, `e5afb85f…`); f30ac9a ağacınınkinden farklı (`f9c2e1d5…`, `d222c812…`). Bu yüzden f30ac9a kolunun kanal alanları ancak o ağacın sınıflayıcısıyla bayt eşit olabilir. Altı sayı sınıflayıcıdan bağımsızdır (hüküm ve biçim ad dizgisinden gelir). f30ac9a kolunda kanal alanlarının bayt denetimi, sınıflayıcıyı ürün ağacından yükleyen seçenek (OLCUM kalem 7) geldikten sonra yapılır; o zamana kadar bu kolda yalnız sınıflayıcıdan bağımsız alanlar denetlenir. Hangisinin yapıldığı P-O1.md'ye yazılır.

## Kaynakların künyesi

| Dosya | sha256 |
|---|---|
| `$V/taban_puan.json` | `6b71a1be6b4264bb54a59c912ef6b319ed0596759025420a890a81d1c3eac66d` |
| `$V/taban_puan_yeni2.json` | `3df41b9e774d41c9690ac495076a855f587a6e27ddcb1413aac37ec82544593b` |
| `$H/olcu.py` (taşınacak üç işlevin kaynağı) | `b915ece925d1f92063e238c80ab0e72168fda6000caa88a9e16dd32e7a01134d` |
| `$H/taban_puanla.py` (makro başvurusu) | `786de52860a7652938722f86416569cf9ce96e0b014d6c85c205b43e4af57e3c` |

`$V` = `~/karadul_olcum/runs/arge-2026-11-19/olcu`; `$H` = `scripts/arge/olcu`. Koşu kökleri: `~/karadul_olcum/runs/urun-onarim-a62f15e/`, `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` (salt okur).
