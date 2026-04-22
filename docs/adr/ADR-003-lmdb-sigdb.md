# ADR-003: Signature DB Icin LMDB

**Status:** Accepted
**Date:** 2026-04 (v1.10.0)
**Context:** v1.9.x `signature_db.py` 10K+ satir, 104 modul-seviyesi
imza sozlugu; import time ~3 GB RAM, 1.3 s cold import.

## Baglam

Karadul'un byte-pattern, FLIRT ve capa tabanli imza veritabani
v1.9.x'te saf Python dict'lerden olusuyordu. Her dict modul seviyesinde
tanimli oldugu icin `import karadul.analyzers.signature_db` komutu
butun veritabanini RAM'e yukluyordu:

- Cold import: ~1.3 s
- RAM ayak izi: ~3 GB
- Cok-process batch'te her worker kendi kopyasini tutuyordu
- Incremental update yok -- yeni imza eklemek tum dict'leri yeniden
  yaratmayi gerektiriyordu

Bu ozellikle `batch` komutu ile yuzlerce binary isleyen kullanicilari
vuruyordu: 8 worker = 24 GB.

## Karar

**v1.10.0 ile LMDB tabanli sigdb eklendi** (`sigdb_lmdb.py`). LMDB
secimi kriterleri:

1. **mmap-backed**: Butun DB disk'te kalir, OS sayfalari talep
   uzerine RAM'e getirir. Cok worker tek dosyayi paylasir -- RAM
   ayak izi sabit.
2. **Lock-free read**: Birden fazla process okurken mutex yok.
3. **Transactional write**: Tek writer, ACID garantileri.
4. **B+tree indexing**: Prefix scan / range query native.
5. **Pure C, no server**: SQLite kadar tasinabilir ama ~3x daha hizli
   point-lookup.

## Sonuclar

- Cold import: 1.3 s --> 0.02 s (dict'ler olusturulmuyor)
- RAM: ~3 GB --> ~0 MB (mmap, demand-paged)
- 8-worker batch RAM: 24 GB --> 1 GB
- Incremental update: `sigdb_lmdb.add()` O(log n)
- Config: `use_lmdb_sigdb: bool` (v1.10.0 default: `False` -- geriye
  uyumluluk; v1.11'de `True` default olacak)

## Alternatifler (reddedildi)

1. **SQLite**: Daha yavas point-lookup, concurrent write icin
   global lock.
2. **RocksDB**: Python binding kararsiz (pyrocksdb terk edilmis).
3. **FlatBuffer + mmap**: Custom format, guncellemesi zor.
4. **Olduğu gibi tut + lazy import**: Sadece 1. seviye problemi
   cozer, batch RAM sorunu devam eder.

## Migrasyon

- v1.10.0: LMDB mevcut, varsayilan KAPALI (`use_lmdb_sigdb=False`).
- v1.11.0: LMDB varsayilan ACIK; eski dict-yolu `deprecated` uyarisi.
- v1.12.0: Eski dict-yolu silinir.
