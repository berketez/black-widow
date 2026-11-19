# OLCUM — birleşik 119 ölçümü (onarım sonrası, a62f15e) — ilerleme

- Ajan: OLCUM (Opus), kendi worktree'si; taban `main` 0984090 (a62f15e + belge).
- Koşu: `~/karadul_olcum/runs/urun-onarim-a62f15e` (ana oturum, 2026-11-19 08:1x). Ağaç `~/karadul_olcum/urun-a62f15e`.
- Taban kol: yeni2 (`urun-yeni2-f30ac9a`, 1.22.1).

## Aşama 1 — ön kayıt (körlük altında)
- Yeni koşudan yalnız künyenin `agac` bloğu okundu: a62f15e, kirli değil, `karadul` ağaçtan, 1.24.1. Öbür çıktılar okunmadı.
- Ön kayıt: `docs/arge/2026-11-19_birlesik_olcum/on_kayit.md`. İçerik:
  - kurulum ve B1–B9 bütünlük koşulları;
  - ana ölçüler;
  - H1–H16 beklentileri, eşikleri ve kaynakları;
  - ikincil ölçümler: masum kapı, kanal kesinliği, parametre adları, sağlamlık, süre;
  - aşama 2 komutları, sapma kuralı, yorum sınırları ve araç kusurları.
- Nokta beklentileri `beklenti.py` → `beklenti.json` ile hesaplandı. Yalnız `urun_olcumu_yeni2.json` okunur; taban yeniden hesapla sağlandı (2 261 / 1 589 / 672; makro %52,8).
- Bütünlük betiği `butunluk.py` taban kökte kendisine karşı sınandı. B4 beklendiği gibi düştü: 1.22.1'de VT künyesi yok. VT alanlarının yeri P15c'nin ürün koşusunda doğrulandı.
- Ana beklentiler:
  - havuz 1 827 / 1 700 / 127, yanlış %7,0 (bant %5,5–%9,0);
  - makro yanlış %31,9 (bant %25–%38; karar (a) `tutmuyor`);
  - gnulib 733 / 733 / 0, kebap 0, rol 0;
  - kaybedilen doğru 1, kazanılan doğru 112;
  - doğru ad kapsamı 1 231 / 21 371;
  - "kesin" 262 / 249, karar (b) `tutuyor`.
- Araç kusurları (değiştirilmedi): `ks1_olc` `BITTI` içeriğine bakmıyor (kısmi = 3 bitmiş sayılıyor); Mac'te `BITTI`'ye hiç bakmıyor; künye önbellek dizinini ve VT şemasını yazmıyor. Ayrıntı ön kayıt §9.

## ÖN KAYIT BİTTİ
