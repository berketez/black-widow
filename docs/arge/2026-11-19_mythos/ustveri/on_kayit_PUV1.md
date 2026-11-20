# Ön kayıt — P-ÜV1 (Go `pclntab` okuyucu ve üretici adım), 2026-11-20

Bu metin ölçümden ÖNCE ve okuyucu kodundan ÖNCE commit'lenir. Tutmayan beklenti silinmez; eşik
sonradan değişmez. Paket metni `docs/arge/2026-11-20_dalga0/gonderim/PUV1.md`, plan
`docs/arge/2026-11-19_mythos/ustveri/PLAN.md` "P-ÜV1".

**Bu kayıttan önce görülenler (dürüstlük notu):** başvuru betikleri
(`scripts/arge/ustveri/go_pclntab.py`, `go_say.py`, `macho.py`), araştırma çıktısı `$V/go/gh.json`
(tamamı) ve `$V/go/gh.tsv`'nin ilk üç satırı (`$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri`),
HEDEF setinin `manifest.json`'ının ilk 1 500 karakteri (terminal-notifier tamamı, docker-cli başı).
docker-cli ve docker-compose GT dosyalarına, öbür dilimlerin `.tsv` / `.json` dosyalarına bakılmadı.
SINAMA ikilisi docker-compose'un GT'sine okuyucu dondurulmadan (dondurma commit'i yazılmadan)
bakılmayacak.

## Hipotezler (plan metni aynen)

> H1: 11 / 11 dilimde (adres, ad, dosya) listesi araştırma başvurusuyla aynı. H2: sembollü iki
> ikilide adı olan girişlerin 125 125 / 125 125'inde ad sembolle aynı (iki yazım kuralıyla). H3: 9
> dilimde (Go ≥ 1.26) başlıktaki eski `textStart` alanı 0'dır ve okuyucu `moduledata.text` kullanır;
> başlığa güvenen mutant bu dilimlerde 0 doğru adres üretir. H4: yapı denetimleri bozulmamış 11
> dilimde `tutarsiz` vermez. H5: P-ÜV7'nin E türü bozuk kopyasında (komşu `_func` takası) K4 ihlal
> sayısı > 0. H6: Go olmayan 5 ikilide (htop, tmux, cat, ls, pzstd) durum `veri_yok`, ad 0. Tutmayan
> hüküm silinmez.

## Kabul ölçütü (plan metni aynen)

- 11 Go diliminde (`gh`, `limactl`, Ollama arm64 / x86_64, ollama-cli arm64 / x86_64, `colima`,
  docker-brew, `arduino-cli`, docker-cli, docker-compose) (adres, ad, dosya) üçlülerinin tamamı
  `$V/go/<ad>.tsv` ile aynı: 11 / 11 dilim, satır farkı 0. Giriş sayıları: 40 384, 40 321, 10 601,
  10 676, 25 164, 25 267, 13 082, 35 749, 29 711, 35 049, 90 078.
- Sembollü iki ikilide ad = sembol (yazım kuralları: `.abi0` eki, orta nokta): docker-cli 35 048 /
  35 048, docker-compose 90 077 / 90 077. Eşik: Wilson alt sınırı ≥ 0,999.
- K1, K2, K5, K9 ihlali 11 dilimde 0; K7 "başka gövde içi hedef" 0; 1.26+ dilimlerinde metin tabanı
  kaynağı `moduledata.text`.
- Süre: dilim başına ≤ 10 sn (araştırma betiği 0,8–1,7 sn).
- Adım: bayrak kapalıyken `go_status = kapali`, yapıt boş; Go olmayan ikilide (htop) `veri_yok`.

## Bu paketin uygulama notları (ölçümden önce)

- H5 bu pakette ölçülemeyebilir: E türü bozuk kopyayı P-ÜV7 üretir (`scripts/measurement/ustveri_bozma.py`,
  henüz yok). Bozuk kopya yoksa H5 "ölçülmedi" yazılır; sentetik testte komşu `_func` takası ayrıca
  sınanır (bu, H5'in yerine geçmez).
- H6'nın 5 ikilisi gerçek `Goruntu` (P-ÜV0) main'e girince koşulur; kullanılan yollar ve sha256
  ilerleme dosyasına yazılır. Gerçek `Goruntu` gelmeden gerçek ikili kabulü yapılmaz.
- Sıra: (1) sentetik testler ve mutasyon, (2) 11 dilim kabulü ve docker-cli (keşif) GT'si,
  (3) okuyucu dondurma commit'i, (4) docker-compose (SINAMA) GT'si bir kez.
- Wilson %95 alt sınırı `scripts/measurement/ks1_olc.py` `oran` ile.
