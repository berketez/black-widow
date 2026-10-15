#!/usr/bin/env python3
"""Makale test seti kurası (ön kayıt).

Bu betik ÖNCE commit edilir, SONRA çalıştırılır. Böylece tohum ve kurallar, kuranın
sonucu görülmeden sabitlenmiş olur. Aday havuzu ve işaretler:
docs/arge/2026-10-15_makale/test_seti_adaylari.md (§2.2, §2.3).

Kurallar:
  1. Uygunluk: gnulib kullananlar (wget, nano), güçlü kütüphane ikizi taşıyanlar (lua,
     gömülü zopfli ile pigz) ve geliştirme setine yakın olan (screen, tmux benzeri) ana
     kümeye girmez. Bu beşi ayrı "stres" alt kümesidir ve o da kilitlenir.
  2. Kalan 20 program boyuta göre üç tabakaya ayrılır: küçük (küçük ve küçük/orta),
     orta, büyük (orta/büyük ve büyük). 15 yer tabakalara 6/6/3 dağıtılır (8/8/4 oranı).
  3. Tek temsilcili alanlar (sıkıştırma: unzip, veritabanı: memcached, editör: vim)
     alan kapsamı için zorunlu dahildir; yerleri kendi tabakalarından düşülür.
  4. Kalan yerler her tabakada tohumlu rastgele seçimle doldurulur.
  5. Tohum: SHA-256("karadul-test-seti-kura-2026-10-15") değerinin ilk 16 hex basamağı.
"""
from __future__ import annotations

import hashlib
import json
import random

SEED_TEXT = "karadul-test-seti-kura-2026-10-15"

# program -> (alan, boyut tabakası); tablo §2.2'den
POOL = {
    "dash": ("kabuk", "kucuk"),
    "mawk": ("metin işleme", "kucuk"),
    "less": ("metin işleme", "kucuk"),
    "unzip": ("sıkıştırma", "kucuk"),
    "gifsicle": ("medya", "kucuk"),
    "ag": ("metin işleme", "kucuk"),
    "dcraw": ("medya", "kucuk"),          # küçük/orta
    "memcached": ("veritabanı", "kucuk"),  # küçük/orta
    "tcpdump": ("ağ", "orta"),
    "ssh": ("kripto + ağ", "orta"),
    "gpg": ("kripto", "orta"),
    "rsync": ("sistem", "orta"),
    "zsh": ("kabuk", "orta"),
    "nasm": ("geliştirme", "orta"),
    "cmus": ("medya", "orta"),
    "dnsmasq": ("ağ", "orta"),
    "lynx": ("ağ", "buyuk"),               # orta/büyük
    "vim": ("editör", "buyuk"),
    "git": ("sistem", "buyuk"),
    "haproxy": ("ağ", "buyuk"),
}
STRESS = ["wget", "nano", "screen", "lua", "pigz"]
QUOTA = {"kucuk": 6, "orta": 6, "buyuk": 3}
FORCED = ["unzip", "memcached", "vim"]


def draw() -> dict:
    seed = int(hashlib.sha256(SEED_TEXT.encode()).hexdigest()[:16], 16)
    rng = random.Random(seed)
    chosen: list[str] = []
    for stratum in ("kucuk", "orta", "buyuk"):
        members = sorted(p for p, (_, s) in POOL.items() if s == stratum)
        forced = [p for p in FORCED if p in members]
        rest = [p for p in members if p not in forced]
        k = QUOTA[stratum] - len(forced)
        chosen += forced + sorted(rng.sample(rest, k))
    return {
        "tohum_metni": SEED_TEXT,
        "tohum": seed,
        "ana_kume": chosen,
        "disarida_kalan": sorted(set(POOL) - set(chosen)),
        "stres_kumesi": STRESS,
        "alanlar": sorted({POOL[p][0] for p in chosen}),
    }


if __name__ == "__main__":
    print(json.dumps(draw(), ensure_ascii=False, indent=1))
