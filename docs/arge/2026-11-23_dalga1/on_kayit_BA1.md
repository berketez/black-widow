# BA1 — ön kayıt (ölçümden önce; sayılar ana oturumun, değiştirilmedi)

Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/BA1.md`. Kayıt anı: 2026-11-23 19:41, onarım yazılmadan önce. Kusurun yeniden üretimi (eski kalıp, gerçek satır, ayrı süreç) bu kayıttan önce yapıldı; o ölçüm hipotezlerin hiçbirini sınamaz (yalnız eski kodun takıldığını gösterir).

> H1: Kusurlu satır (`FUN_100295d40.c` satır 211, 89 karakter) yeni kalıplarla ≤ 0,1 sn'de sonuçlanır (eski: 32 karakterde 20 sn'de bitmedi).
>
> H2: Ollama çalışma alanında (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_ustveri/ws`, salt okur) adımın işleyeceği 13 554 dosyanın hepsi yeni kodla işlenir; toplam süre ≤ 300 sn (yük altında; eski kod ilk 7 310 dosyayı 36 sn'de yazmıştı); tek dosyada en uzun süre ≤ 5 sn.
>
> H3: Eski koşunun yazmayı bitirdiği 7 310 dosyada yeni çıktı eskiyle bayt eşit (7 310 / 7 310). Adımın çıktısı girdi dışında bir şeye bağlıysa (sıra, zaman damgası) bunu ayır ve karşılaştırmayı o alan dışında yap; ayırdığını yaz.
>
> H4: S8'in 8 çalışma alanında (`~/karadul_olcum/runs/dalga1-2026-11-23/P16e/s8_sonra_3`, salt okur) adımın çıktısı eski kodla yeni kod arasında bayt eşit 8 / 8.
>
> H5: `block_annotator.py`'de üstel sınıfa giren başka kalıp sayısı: yön bildirilmez, ilk ölçüm.
>
> H6: Envanterde (`karadul/reconstruction/` + `karadul/pipeline/steps/`) üstel sınıfa giren kalıp sayısı: yön bildirilmez, ilk ölçüm.

Tutmayan beklenti silinmez; eşik sonradan değişmez.
