# G4 etiketleme sonuçları: taban v2 ve cömertlik deneyi

- **Tarih:** 2026-10-19
- **Ön kayıt:** `onkayit.md` (42c09e5), etiketlemeden önce commit'lendi. Bu belgedeki bütün analizler orada önceden yazılmıştı; ek olarak yalnız bileşim tablosu (§5) eklendi ve öyle işaretlendi.
- **Veri:** `veri/` (anahtarlar, amaç ve etiket dosyaları, puanlama çıktıları, donma kaydı). Gövdeli paketler depoda değil; onkayit.md §1'deki komutla yeniden üretilir.
- **Yeniden üretme:**
  - Oranlar: `scripts/measurement/etiket_puan.py puan|comertlik` (komutlar §6).
  - Uyum ve bileşim: `python -I -B docs/arge/2026-10-19_g4_etiketleme/analiz.py` → `sonuc.json`.
- **Değerlendiriciler:** üç Claude Opus 5.5 ajanı (L1, L2, L3), vekil değerlendirici. İnsan değerlendirme G32'de.

## 1. Taban v2: Karadul'un bugünkü isimleri (kör protokol v2, rubrik sürüm 2)

Payda: Karadul'un isim verdiği, isim bekleyen fonksiyonlar (`sinif == "program"`). Taban v2 koşusu `taban-v2-62ad154`.

| Program | n | Tam | Yakın (tam + doğru tarif) | Yalnız alan | Yanlış | Yem kabulü |
|---|---|---|---|---|---|---|
| tmux (L1) | 385 | 46 (%11,9) [%9,1–15,6] | 76 (**%19,7**) [%16,1–24,0] | 134 (%34,8) | 175 (**%45,5**) [%40,6–50,4] | 0/39 [%0–9,0] |
| htop (L3) | 97 | 0 (%0) [%0–3,8] | 4 (**%4,1**) [%1,6–10,1] | 14 (%14,4) | 79 (**%81,4**) [%72,6–87,9] | 0/10 [%0–27,8] |

Köşeli parantezler Wilson %95 aralığı. Tutarlılık denetimi: tmux'ta tam eşleşen 2 öğeye kör değerlendirici yakın dışı etiket verdi; puanlamada bunlar anahtardan `tam` sayıldı.

**Okuma:** Plan v2'nin hedefi "verilen isimlerin ≤ %10'u yanlış". Bugün tmux'ta yanlış oranı %45,5, htop'ta %81,4; hedefin 4,5-8 katı. Yakın isim oranı tmux'ta %19,7, htop'ta %4,1.

## 2. Cömertlik deneyi (aynı 200 tmux öğesi)

| Koşul | Değerlendirici | Yakın |
|---|---|---|
| Gerçek ad görünür, gövde karartılmamış (eski protokolün eşdeğeri) | L2 | 33/200 (%16,5) [%12,0–22,3] |
| Kör (protokol v2) | L3 | 31/200 (%15,5) [%11,1–21,2] |

- **Fark (gt'li − kör): +1,0 puan**, eşli bootstrap %95 aralığı [−1,0; +3,0] (10 000 tekrar, tohum 2026101905).
- Çiftler: ikisi de yakın 30, yalnız gt'li yakın 3, yalnız kör yakın 1, ikisi de değil 166.
- Yem kabulü iki koşulda da 0/20.

**G8 kuralı (ön kayıt):** nokta tahmin > 10 puan ise v1 tabanındaki yakın oranlar geçersiz sayılırdı. Fark +1,0 puan; kural tetiklenmedi. Gerçek adın görünmesi bu değerlendiricilerde ölçülebilir bir cömertlik yaratmadı. Yine de v1 ve v2 sayıları birleştirilmez: rubrik değişti (yanlış fiil artık `yanlis`), örneklem ve koşu farklı (onkayit §3.6).

## 3. Kör değerlendiriciler arası uyum (L1 ve L3, ortak 88 tmux öğesi)

| Ölçü | Değer |
|---|---|
| Cohen kappa, dört etiket | 0,736 |
| Cohen kappa, yakın / değil | 0,953 |
| Ham uyum, dört etiket | %84,1 |
| Ham uyum, yakın / değil | %98,9 |

İki bağımsız kör değerlendirici yakın/değil kararında neredeyse tam uyuşuyor. Ayrıntılı etikette (yalnız alan ile yanlış ayrımı) uyum "önemli" düzeyde. İki değerlendirici de aynı model ailesinden; insanlarla uyum G32'de ölçülecek.

## 4. Duyarlılık: çapraz atıflı öğeler dışarıda (ön kayıt §3 madde 5)

| Program | n | Yakın | Yanlış |
|---|---|---|---|
| tmux | 233 | %16,7 [%12,5–22,1] | %52,4 [%46,0–58,7] |
| htop | 73 | %5,5 [%2,2–13,3] | %80,8 [%70,3–88,2] |

## 5. Ek (ön kayıtta yok): çapraz atıflı öğelerin bileşimi

tmux'ta çapraz atıflı öğeler (gerçek adı başka bir öğenin gövdesinde geçen 152 öğe) ile öbürleri (233):

| Grup | n | Tam | Doğru tarif |
|---|---|---|---|
| Çapraz atıflı | 152 | %12,5 | %11,8 |
| Atıfsız | 233 | %11,6 | %5,2 |

Tam payı iki grupta benzer, fark doğru tarifte. İki açıklama var:
- **Bileşim:** sık çağrılan yardımcı fonksiyonların adı Karadul için daha kolay.
- **Hoşgörü:** değerlendirici adı başka bir gövdede görüp cömertleşiyor.

Gerçek adın doğrudan görünmesi yalnız +1 puanlık fark yarattığı için (§2), daha zayıf olan bu kanalın tek başına +6,6 puan üretmesi beklenmez. Bileşim daha olası, ama bu ayrıştırılmadı.

## 6. Komutlar

```bash
V=docs/arge/2026-10-19_g4_etiketleme/veri
python -I -B scripts/measurement/etiket_puan.py puan --anahtar $V/anahtar_tmux_385_kor.json \
  --etiket $V/etiket_L1_tmux385.jsonl --amac $V/amac_L1_tmux385.jsonl
python -I -B scripts/measurement/etiket_puan.py puan --anahtar $V/anahtar_htop_kor.json \
  --etiket $V/etiket_L3_htop.jsonl --amac $V/amac_L3_htop.jsonl
python -I -B scripts/measurement/etiket_puan.py comertlik \
  --anahtar-gtli $V/anahtar_tmux_200_gt.json --etiket-gtli $V/etiket_L2_tmux200gt.jsonl \
  --anahtar-gtsiz $V/anahtar_tmux_200_kor.json --etiket-gtsiz $V/etiket_L3_tmux200.jsonl --tohum 2026101905
python -I -B docs/arge/2026-10-19_g4_etiketleme/analiz.py
```

## 7. Süreç denetimi

- Her değerlendiricinin aşama 1 dosyası denetlendi ve sha256 ile donduruldu; adaylar ancak ondan sonra verildi (`veri/donma.log`). Puanlamada `--amac` denetimi amaç cümlelerinin değişmediğini doğruladı. Hiçbir satırda amaç değişmemişti.
- Transcript denetiminde hiçbir değerlendiricinin anahtara, başka değerlendiricinin klasörüne ya da ağa eriştiği görülmedi.
  - İşaretlenen erişimlerin hepsi zararsızdı: kendi klasörlerini birleştiren bir yol değişkeni ve `cd`.
  - L1 yardımcı betiklerini oturumun geçici dizininde tuttu. Anahtarlar da o dizinde durduğu için erişimin tamamı tek tek incelendi; anahtara ya da paket dizinine erişim yok.
  - Ders: sonraki turlarda anahtarlar ajanların kullandığı geçici dizinde tutulmayacak ve denetim anahtar erişimini ayrıca arayacak.
- Kör pakette tek bir amaç cümlesinde öğenin gerçek adı geçti (`daemon`). Gövde ve dosya adı doğru karartılmıştı; ad, fonksiyonun yaptığı işin kendisi. Sızıntı sayılmadı.

## 8. Sınırlamalar

- Değerlendiriciler LLM ve kuralları tasarlayan modelle aynı aileden.
- Her ana tahmin tek bir değerlendiricinin etiketlerine dayanıyor. Uyum yalnız 88 ortak tmux öğesinde ölçüldü.
- tmux ve htop geliştirme setidir; bu sayılar kapı değil, taban.
- Yem sayıları küçük: tmux'ta 39 yem ile kabul üst sınırı %9,0; htop'ta 10 yem ile %27,8. "≤ %5" hedefi bu sayılarla gösterilemez.
