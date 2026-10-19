# G7 alıcı tip kümeleri: ön kayıt notları

Ön kayıt (`onkayit.md`) ölçümden sonra değiştirilmedi.

- **Mühür:** 2026-10-19 13:35:40 (+0300). SHA-256 `d6828667…b743db45`. Mühür dosyası `workspaces/2026-10-19_g7/veri/onkayit_muhur.txt`.
- **Mühürlenen betikler:** `cikar.py`, `olcut.py`, `deney.py`, `sinama_cikar.py`, `sinama_olcut.py`. Ölçümden sonra `shasum -c` ile denetlendi; hepsi aynı.

Aşağıdakiler, ön kaydın sustuğu ya da tam yazmadığı yerlerdir. Hiçbiri kuralı, ölçütü ya da karar eşiğini değiştirmedi.

## Zaman çizelgesi

| Adım | Saat (+0300) |
|---|---|
| Mühür | 13:35:40 |
| İlk ölçüm (`cikar.py tmux` başladı) | 13:35:46 |
| `cikar.py htop` | 13:35:49-13:35:50 |
| `deney.py` | 13:36:06-13:36:10 |
| Belirlenimcilik yeniden koşusu (geçici dizinde) | 13:41 |

Belirlenimcilik yeniden koşusunda iki `cikti.json` bayt bayt aynı çıktı. `sonuc.json` da zaman damgaları dışında aynı çıktı.

## Notlar

1. **Günlükteki boş `rc=`.** `log/cikar_*.log` dosyalarında `rc=` boş kaldı. Sebep: kabuk zsh, `${PIPESTATUS[0]}` bash değişkeni. Bu bir ölçüm sorunu değil; iki çıktı da yazıldı ve yeniden koşuyla aynı çıktı.
2. **§10'daki "en büyük kümedeki isim bekleyen payı".** Kod, bir kümedeki en çok isim bekleyen sayısının P'ye oranını hesaplıyor (`tek_kumedeki_en_buyuk_bekleyen_payi`). İki programda da bu küme en büyük kümenin kendisi: tmux 95/2545, htop 50/597.
3. **§9 p-code tanısı.** Uyum tmux'ta 1781/1781, htop'ta 270/270. Eşik %90'ın üstünde olduğu için elle inceleme yapılmadı.
4. **Ç-G.** Ön kayıtta beklendiği gibi iki programda da boş.
5. **htop'ta Ç-O = 0.** Ayrıca denetlendi: htop ikilisinin `strings -n 4` çıktısında `Sınıf_yöntem` biçiminde tek satır yok, assert izi de yok. Bu derlemede "kendi adı" kanalının malzemesi yok.
6. **Negatif kontrolün p değeri.** R = 1000 ile ulaşılabilecek en küçük p 1/1001 ≈ 0,001. Bütün kontroller bu tabanda çıktı; hiçbir karışık bölümleme gerçek saflığa ulaşmadı.

## Ön kayıt dışı eklenenler

Bunların hepsi sonuç görüldükten sonra eklendi. Hiçbiri bir ölçüte ya da karara girmez.

- **`yorum_kaynak_tipleri.py`, yalnız yorum için.** Saflığı düşük kümelerin nedenini anlamak için yazıldı. Görev tanımı kaynağa "yalnız yorum için" bakmaya izin veriyor.
  - Kaynakta, en kötü 5 kümenin üyelerinin 1. parametre tipine bakar.
  - Ayrıca bütün V1 kümelerinde kaynak tipine göre ağırlıklı saflığı hesaplar.
  - Tanımlar basit bir düzenli ifadeyle çıkarılır. Tip adı normalleştirilir: `const` atılır, `*` boşlukları düzeltilir. htop'ta taban ve alt sınıf işaretçileri ayrı tip sayılır.
  - Çıktısı `workspaces/2026-10-19_g7/veri/yorum_kaynak_tipleri.json`.
- **`tablolar.py`.** `sonuc.json`'dan Markdown tablo basar, başka bir şey yapmaz. Rapor tabloları bu çıktıdan (`workspaces/2026-10-19_g7/veri/tablolar.md`) alındı.
