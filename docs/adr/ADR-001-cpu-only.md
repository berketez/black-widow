# ADR-001: CPU-Only, GPU Bagimliligi Yok

**Status:** Accepted
**Date:** 2026-04-21 (v1.10.0)
**Context:** `karadul/gpu_utils.py` dosyasi v1.10.0'da silindi.

## Baglam

Karadul baslangicta bazi alt gorevler icin (signature fusion, ozellikle
byte-pattern benzerliginde cosine-distance hesaplamalari) MPS / CUDA
tabanli GPU yollari destekliyordu. `gpu_utils.py` Apple Silicon MPS
ve NVIDIA CUDA arka uclarina delege eden ince bir sarmalayiciydi ve
yalnizca TEK yerden (signature fusion) cagriliyordu.

Zamanla asagidaki sorunlar belirginlesti:

1. **Reproducibility kaybi.** Ayni binary'yi ayni config ile iki
   farkli makinede (bir M-serisi Mac, bir Linux+GPU sunucu) calistirmak
   micro-farklarla farkli sonuclar doguruyordu (floating-point
   associativity sapmalari). RE sonuclari icin bu kabul edilemezdi.

2. **Bagimlilik agirligi.** PyTorch + Metal/CUDA runtime paketleri
   kurulum yukunu 5--8 GB artiriyor ama yalnizca tek bir sicak noktaya
   hizlanma getiriyordu. CI ve Docker imajlari gereksiz yere
   sisiyordu.

3. **Test karmasi.** GPU olmayan runner'larda kod yollari sessizce
   CPU fallback'e dusuyor, performans testleri anlamsizlasiyordu.

4. **Yaygin degilim dusuk.** Perf profiling, GPU yolunun tum
   pipeline'da %2--3 speed-up getirdigini gosterdi. Yatirimin
   getirisi dusuktu.

## Karar

**v1.10.0 ile `gpu_utils.py` kaldirildi.** Signature fusion ve tum
diger ozellikler CPU-only yollari (NumPy / saf Python) kullanir.
Yeni GPU yollari **eklenmeyecek**; ornek `perf-optimizer` raporunun
onerdigi gibi Metal kernel'lari -- baska bir projeye islenebilir ama
Karadul'un reproducibility sozune aykiridir.

## Sonuclar

- CI ve Docker imajlari ~1.2 GB (onceden ~6 GB).
- `pip install karadul` kurulum suresi 60+ s'den 8--10 s'ye dustu.
- Ayni binary + ayni config --> byte-level ayni artifact garantisi.
- %2--3 perf kaybi kabul edildi; yerine signature_fusion NumPy
  vektorize yazildi ve acik kaybin onemli kismi telafi edildi.

## Alternatifler (reddedildi)

1. **Optional GPU bayragi (`--gpu`)**: Kod karmasi yaratiyor, test
   matrisi ikiye katlaniyor, default-off ise hic kullanilmayacak.
2. **Ayri paket (`karadul-gpu`)**: Bagimlilik yonetimi karmasi,
   core pipeline degisikliklerinde senkronizasyon yukunu tasimali.
