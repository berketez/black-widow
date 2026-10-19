# G4 etiketleme: taban v2 ve cömertlik deneyi (ön kayıt)

- **Tarih:** 2026-10-19. Bu belge etiketleme başlamadan commit'lendi.
- **Plan:** v2 §5 G4. Protokol `docs/arge/etiket_protokolu_v2.md`, rubrik `docs/arge/etiket_rehberi.md` sürüm 2 (sha256 `70e4cff7b679f855…`).
- **Girdi:** taban v2 makine koşusu `taban-v2-62ad154` (Ghidra 12.1.2; `scripts/measurement/macho_measure.py`). Yalnız `sinif == "program"` satırları; isim verilmiş (`tp` + `wrong`): tmux 857, htop 101.
- **Değerlendiriciler:** Claude Opus 5.5 ajanları (vekil değerlendirici). Kuralları tasarlayan modelle aynı aileden; bu bir sınırlamadır. İnsan değerlendirme G32'de yapılır.

## 1. Paketler

`etiket_paketi.py uret --azami-satir 120`, kaynaklar `workspaces/2026-10-15_oturum_scratchpad/src/{tmux-dl/tmux-3.8, htop-dl/htop-3.5.3}`.

| Paket | Satırlar | Örneklem | Tohum | Kip | Ana + yem = toplam | amac / aday / anahtar sha256 (ilk 16) |
|---|---|---|---|---|---|---|
| tmux_385_kor | tmux program | 385 | 2026101901 | kör | 385 + 39 = 424 | `818a679554f4cf96` / `e502844779ccba94` / `87a9ef59bbb995ba` |
| tmux_200_kor | tmux program | 200 | 2026101903 | kör | 200 + 20 = 220 | `e371eef1c19050aa` / `10a03221b9d807b7` / `50e1643dd20d9c9a` |
| tmux_200_gt | tmux program | 200 | 2026101903 | gt'li | 200 + 20 = 220 (aynı id'ler) | `ba29a3123648c30f` / `10a03221b9d807b7` / `cafae6aefe61aeba` |
| htop_kor | htop program | hepsi (97 uygun) | 2026101904 | kör | 97 + 10 = 107 | `1e50deb75a73f5c2` / `d42c32d57d9a99b2` / `f44f8848bb44a501` |

- Sızıntı denetimi dört pakette 0 hata.
- tmux_200 ile tmux_385'in ana öğe kesişimi 88 fonksiyon.
- Gövdesi bulunamayan/belirsiz: tmux 1/2, htop 0/4 (pakete girmez).

## 2. Atama

| Değerlendirici | Paket(ler) | Not |
|---|---|---|
| L1 | tmux_385_kor | taban v2, tmux |
| L2 | tmux_200_gt | cömertlik deneyi, gerçek ad görünür |
| L3 | tmux_200_kor, sonra htop_kor | cömertlik deneyinin kör kolu; taban v2, htop |

- Her değerlendirici yalnız kendi klasörünü görür (`workspaces/2026-10-19_g4_etiketleme/<L>/`). Anahtar hiçbirine verilmez.
- Aşama 1: amaç cümleleri. Ana oturum aşama 1 dosyasını sha256 ile dondurur, sonra `aday_paketi.jsonl`'i verir (aşama 2). Puanlamada `etiket_puan.py --amac` amaç cümlesinin değişmediğini denetler.
- Yönerge metni protokol §8; değerlendiriciye yem olduğu söylenmez (protokol §12 kararı, 2026-10-19).
- Değerlendiricinin başka dosya okumadığı transcript'teki araç çağrılarından denetlenir.

## 3. Analiz (önceden yazılmış)

1. **Taban v2 (yeni protokol):** tmux (L1, 385) ve htop (L3, 97) için tam, yakın (tam + doğru tarif), yalnız alan ve yanlış oranları, Wilson %95 aralığıyla. `tam` anahtardaki tam eşleşmeden gelir. Yemler ana sayılara girmez.
2. **Cömertlik:** aynı 200 öğede L2 (gt'li) ile L3 (kör) yakın oranı farkı; eşli bootstrap %95 aralığı (`etiket_puan.py comertlik`, tohum 2026101905). G8 kuralı: nokta tahmin > 10 puan ise v1 tabanındaki yakın oranlar geçersiz sayılır; aralık da raporlanır.
3. **Değerlendiriciler arası uyum (kör–kör):** L1 ile L3'ün ortak 88 tmux öğesinde dört etiket üzerinden ve yakın/değil ikilisinde Cohen kappa.
4. **Yem kabulü:** değerlendirici başına, bütün paketleri birleştirerek (L1: 39 yem, L3: 30 yem); Wilson aralığıyla. Hedef nokta tahminde ≤ %5; bu yem sayılarıyla üst sınırın %5'in altına inemeyeceği bilinen sınırlamadır.
5. **Duyarlılık:** `--capraz-atifsiz` (başka bir öğenin gövdesinde adı geçen öğeler dışarıda) ile 1-2 yeniden hesaplanır.
6. **v1 ile ilişki:** 15 Ekim etiketleri (sürüm 1) yalnız betimsel olarak anılır; sayılar birleştirilmez.

## 4. Sınırlamalar

- Değerlendiriciler LLM; insan değerlendiriciyle uyumları G32'de ölçülür.
- tmux ve htop geliştirme setidir; bu sayılar kapı değil, taban ve protokol kalibrasyonudur. Kapılar doğrulama setinde ölçülür (§7).
- Gövde 120 satırda kırpılır (protokol §12 kararı).
