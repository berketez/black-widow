#!/usr/bin/env python3
"""Doğrulama seti kurası (ön kayıt, plan v2 G5).

Bu betik ÖNCE commit edilir, SONRA çalıştırılır. Böylece havuz, tabakalar, alan ve aile
etiketleri, tohum ve seçim kuralları kuranın sonucu görülmeden sabitlenmiş olur.
Kanıtlar ve gerekçeler: docs/arge/dogrulama_seti_onkayit.md.
Örnek alınan betik: scripts/measurement/test_seti_kura.py. Test setinin kotası, havuzu ve
stres listesi oradan okunur (tek kaynak); o dosya değiştirilmez.

Kurallar (ayrıntısı ön kayıt belgesinde):
  1. Havuz (VALIDATION_POOL) sabit bir listedir. Her adayın alanı, ailesi ve boyut vekili yazılıdır.
  2. Boyut vekili, Debian 13 arm64 `-dbgsym` paketinin Installed-Size değeridir (KiB).
     Tabaka eşikleri test setinin 15 ana programının aynı ölçüsünden türetilir: değerler
     sıralanır, küçük/orta sınırı 6. ile 7. değerin, orta/büyük sınırı 12. ile 13. değerin
     ortasıdır. Böylece test seti bu ölçüde 6/6/3 bölünür; doğrulama setine aynı oranla
     4/4/2 çekilir. Havuz, test setinin en küçük ve en büyük değeri arasında kalır.
  3. Aynı aileden (kod soyu) en fazla bir program seçilir; bu kısıt hiç gevşetilmez.
     Aynı alandan en fazla bir program seçilir; bu kısıt yalnız bir yer başka türlü
     doldurulamıyorsa gevşetilir ve gevşetme çıktıya yazılır.
  4. Kura: her tabakanın üyeleri alfabetik sıralanır ve tohumlu üreteçle karıştırılır
     (üreteç sırası: küçük, orta, büyük). Seçim kıt tabakadan başlar (büyük, orta, küçük):
     her tabakada karışık sırayla, kısıtları sağlayan ilk programlar alınır.
  5. Yedek sırası, tabakanın karışık sırasında seçilmeyen programlardır.
  6. Koşulamayan programın yerine aynı tabakanın yedek sırasında, kümede kalanlarla
     aile ve alan çakışmayan ilk program gelir. Yoksa alan kısıtı gevşer; o da yoksa
     komşu tabakanın (FALLBACK) yedek sırasına geçilir. Kümenin geri kalanı değişmez.
     Değişim yalnız K1, K2, K4, K5, K6 nedenleriyle yapılır. K3 (Mac şişesinde yerel
     sembol yok) değişim nedeni değildir: Mac ikilisi kaynaktan derlenir; derleme 30
     dakikada başarıyla bitmezse neden K6 olur.
  7. Tohum: SHA-256("karadul-dogrulama-seti-kura-2026-10-19") değerinin ilk 16 hex basamağı.
  8. Doğrulama stres alt kümesi: işaretli listeden (FLAGGED) 5 program. Alt tohum metni
     ana tohum metnine "/stres" eklenerek türetilir; liste alfabetik sıralanıp bu alt
     tohumla karıştırılır, ilk 5'i seçilir, kalanlar sırasıyla yedektir. Ana kuranın
     üretecine dokunmaz. Kapı günlerinde ayrı raporlanır, kapı ölçütüne girmez.

Kullanım (yalnız 2. aşamada, belge ve betik commit edildikten sonra):
  python scripts/measurement/dogrulama_seti_kura.py                          # kura
  python scripts/measurement/dogrulama_seti_kura.py --kosulamayan a:K2,b:K6  # değişim uygulanmış küme
  python scripts/measurement/dogrulama_seti_kura.py --gelistirme 2           # geliştirme seti tamamlama sırası
  python scripts/measurement/dogrulama_seti_kura.py --kosulamayan a:K1 --aktarilan c
      # c geliştirme setine aktarıldıysa ailesi ve alanı değişimde kullanılmış sayılır
  python scripts/measurement/dogrulama_seti_kura.py --denetim                # yalnız yapısal denetim, kura yok
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import random
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(__file__).resolve()
TEST_SET_SCRIPT = SCRIPT_PATH.with_name("test_seti_kura.py")
PREREGISTRATION_DOC = "docs/arge/dogrulama_seti_onkayit.md"
SCRIPT_REL = "scripts/measurement/dogrulama_seti_kura.py"


def _load_test_set_script():
    """Test seti kura betiğini salt okunur yükler (kotası, havuzu ve stres listesi için)."""
    spec = importlib.util.spec_from_file_location("test_seti_kura_ref", TEST_SET_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_TEST_KURA = _load_test_set_script()

STRATA = ("kucuk", "orta", "buyuk")             # üretecin tüketim sırası
SELECTION_ORDER = ("buyuk", "orta", "kucuk")    # seçim sırası: kıt tabaka önce
FALLBACK = {"buyuk": ("orta", "kucuk"), "orta": ("kucuk", "buyuk"), "kucuk": ("orta", "buyuk")}

TEST_SET_QUOTA = {s: _TEST_KURA.QUOTA[s] for s in STRATA}   # 6/6/3 (kilit belgesi §1)
TEST_SET_POOL_NAMES = tuple(sorted(_TEST_KURA.POOL))         # 15 ana + 5 yedek
TEST_SET_STRESS = tuple(_TEST_KURA.STRESS)                   # 5 stres programı

VALIDATION_SEED_TEXT = "karadul-dogrulama-seti-kura-2026-10-19"
VALIDATION_SIZE = 10
VALIDATION_QUOTA = {s: VALIDATION_SIZE * TEST_SET_QUOTA[s] // sum(TEST_SET_QUOTA.values()) for s in STRATA}
if sum(VALIDATION_QUOTA.values()) != VALIDATION_SIZE:
    raise RuntimeError(f"kota test setiyle orantılı bölünemedi: {VALIDATION_QUOTA}")

# Doğrulama stres alt kümesi: işaretli listeden seçilir, kapı ölçütüne girmez (ön kayıt §7).
STRESS_SEED_SUFFIX = "/stres"   # alt tohum metni = ana tohum metni + bu ek
STRESS_SIZE = 5

# Koşulamama nedenleri (ön kayıt §4.4). K3 değişim nedeni değildir: Mac'te kaynaktan derlenir.
REBUILD_REASON = "K3"
REPLACEMENT_REASONS = ("K1", "K2", "K4", "K5", "K6")

# Test setinin 15 ana programının boyut vekili: Debian 13.7 arm64 `-dbgsym` Installed-Size (KiB).
# Sürümler kilit belgesi §4.1'dekilerle aynı (2026-10-19'da Packages dizininden okundu).
TEST_SET_PROXY_KIB = {
    "dash": 309, "mawk": 370, "unzip": 569, "dcraw": 669, "gifsicle": 797,
    "dnsmasq": 1061, "rsync": 1111, "nasm": 1180, "memcached": 1789, "zsh": 3062,
    "gpg": 3312, "vim": 8971, "ssh": 9096, "haproxy": 11299, "git": 70029,
}


def thresholds(values: Iterable[float], split: Iterable[int]):
    """(küçük/orta sınırı, orta/büyük sınırı, alt sınır, üst sınır)."""
    s = sorted(values)
    k1, k2, k3 = split
    if len(s) != k1 + k2 + k3:
        raise ValueError(f"{k1 + k2 + k3} değer bekleniyordu, {len(s)} geldi")
    a, b = k1, k1 + k2
    return (s[a - 1] + s[a]) / 2, (s[b - 1] + s[b]) / 2, s[0], s[-1]


T1, T2, LOWER, UPPER = thresholds(TEST_SET_PROXY_KIB.values(), (TEST_SET_QUOTA[s] for s in STRATA))


def stratum_of(kib: float) -> str:
    if kib < T1:
        return "kucuk"
    if kib <= T2:
        return "orta"
    return "buyuk"


# program -> (alan, aile, vekil_kib). Kanıt: ön kayıt belgesi §5 ve Ek A.
VALIDATION_POOL: dict[str, tuple[str, str, int]] = {
    # --- küçük (vekil < T1) ---
    "abcm2ps": ("medya", "abcm2ps", 816),
    "bitlbee": ("iletişim", "bitlbee", 1082),
    "bmake": ("geliştirme araçları", "NetBSD make", 487),
    "bogofilter": ("iletişim", "bogofilter", 710),  # bogofilter-sqlite-dbgsym
    "bwa": ("bilim", "klib (Heng Li)", 461),
    "byacc": ("geliştirme araçları", "byacc", 330),
    "calcurse": ("kişisel bilgi ve ofis", "calcurse", 744),
    "distcc": ("geliştirme araçları", "distcc", 876),
    "dnsperf": ("ağ altyapısı", "dnsperf", 454),
    "dosfstools": ("dosya sistemi", "dosfstools", 400),
    "enscript": ("metin ve belge", "GNU enscript", 737),
    "fetchmail": ("iletişim", "fetchmail", 624),
    "flex": ("geliştirme araçları", "flex", 602),
    "frotz": ("oyun", "frotz", 579),
    "hydra": ("güvenlik", "THC-Hydra", 530),
    "iodine": ("ağ altyapısı", "iodine", 315),
    "isync": ("iletişim", "isync", 565),
    "jove": ("editör", "jove", 623),
    "kalign": ("bilim", "kalign", 504),
    "lowdown": ("metin ve belge", "lowdown", 505),
    "minicom": ("seri iletişim", "minicom", 489),
    "minimap2": ("bilim", "klib (Heng Li)", 460),
    "mle": ("editör", "mle", 339),
    "mosquitto": ("ağ altyapısı", "Eclipse Mosquitto", 949),
    "mtools": ("dosya sistemi", "GNU mtools", 567),
    "multitail": ("sistem yönetimi", "multitail", 597),
    "ne": ("editör", "ne", 484),
    "newlisp": ("dil yorumlayıcısı", "newlisp", 428),
    "ngircd": ("iletişim", "ngIRCd", 309),
    "pspg": ("metin ve belge", "pspg", 724),
    "remind": ("kişisel bilgi ve ofis", "remind", 869),
    "rmlint": ("dosya yönetimi", "rmlint", 964),
    "sc-im": ("kişisel bilgi ve ofis", "sc-im", 463),
    "squashfs-tools": ("dosya sistemi", "squashfs-tools", 559),
    "sslh": ("ağ altyapısı", "sslh", 962),
    "tcsh": ("kabuk", "csh/tcsh", 501),
    "vnstat": ("ağ altyapısı", "vnstat", 562),
    "zmap": ("ağ altyapısı", "zmap", 387),
    # --- orta (T1 <= vekil <= T2) ---
    "angband": ("oyun", "Angband", 4228),
    "chrony": ("sistem yönetimi", "chrony", 1094),
    "cscope": ("geliştirme araçları", "cscope", 1301),
    "exim": ("iletişim", "Exim", 3021),  # exim4-daemon-light-dbgsym
    "fig2dev": ("medya", "fig2dev", 1380),
    "freeciv": ("oyun", "Freeciv", 7650),  # freeciv-server-dbgsym
    "gnugo": ("oyun", "GNU Go", 1359),
    "joe": ("editör", "joe", 1226),
    "links": ("web tarayıcı", "Links (Patočka)", 2829),
    "mksh": ("kabuk", "pdksh/mksh", 1317),
    "monit": ("sistem yönetimi", "monit", 1789),
    "mpv": ("medya", "mpv", 5644),
    "nagios": ("sistem yönetimi", "Nagios", 1552),  # nagios4-core-dbgsym
    "nethack": ("oyun", "NetHack", 5279),  # nethack-console-dbgsym
    "nsd": ("ağ altyapısı", "NLnet Labs", 6663),
    "profanity": ("iletişim", "profanity", 3016),
    "splint": ("geliştirme araçları", "splint", 3862),
    "testdisk": ("dosya sistemi", "CGSecurity", 2449),
    "timidity": ("medya", "TiMidity++", 2728),
    "tin": ("iletişim", "tin", 1985),
    "vifm": ("dosya yönetimi", "vifm", 3997),
    "weechat": ("iletişim", "weechat", 2594),  # weechat-curses-dbgsym
    "zabbix": ("sistem yönetimi", "Zabbix", 1708),  # zabbix-agent-dbgsym
    # --- büyük (vekil > T2) ---
    "alpine": ("iletişim", "Alpine (UW Pine)", 13799),
    "gnome-builder": ("geliştirme araçları", "GNOME Builder", 15033),
    "ipv6calc": ("ağ altyapısı", "ipv6calc", 19715),
    "pari": ("bilim", "PARI/GP", 27007),  # pari-gp-dbgsym
    "php": ("dil yorumlayıcısı", "PHP", 14422),  # php8.4-cli-dbgsym
    "qemu-img": ("dosya sistemi", "QEMU", 24463),  # qemu-utils-dbgsym
    "tor": ("güvenlik", "Tor", 10606),
}

# İşaretli liste: başka her ölçütü sağlıyor ama ana kümeye girmiyor (test setindeki stres
# mantığı). Ana kuraya girmez; içinden STRESS_SIZE programlık stres alt kümesi alt tohumla
# çekilir (stress_draw). Kanıt: docs/arge/dogrulama_seti_kanit/isaretli_data.json.
FLAGGED: dict[str, str] = {
    "sed": "gnulib (m4/gnulib-comp.m4, lib/gnulib.mk, bootstrap.conf)",
    "tar": "gnulib (m4/gnulib-comp.m4)",
    "findutils": "gnulib (gl/m4/gnulib-comp.m4)",
    "diffutils": "gnulib (m4/gnulib-comp.m4, lib/gnulib.mk)",
    "patch": "gnulib (m4/gnulib-comp.m4)",
    "m4": "gnulib (m4/gnulib-comp.m4, lib/gnulib.mk)",
    "make": "gnulib (m4/gnulib-comp.m4)",
    "bison": "gnulib (m4/gnulib-comp.m4, lib/gnulib.mk)",
    "cpio": "gnulib (m4/gnulib-comp.m4)",
    "datamash": "gnulib (m4/gnulib-comp.m4, lib/gnulib.mk)",
    "inetutils-telnet": "gnulib (m4/gnulib-comp.m4, bootstrap.conf)",
    "unbound": "güçlü kütüphane ikizi: iç adları katalogda (7/7, lib=unbound)",
    "hatari": "üretilmiş kod baskın: derlemede üretilen 68k yorumlayıcısı (UAE gencpu)",
}

# --- Dışlama listeleri (ön kayıt belgesi §6) ---
TEST_SET_ALIASES = ("gnupg", "openssh", "the_silver_searcher", "dnsmasq-base", "vim-nox", "dash-shell")
CANDIDATES = (  # test_seti_adaylari.md §2.4a, §2.4b, §2.5 (§2.2'dekiler test setinin havuzunda)
    "jq", "xz", "mupdf", "curl", "bash", "grep", "gawk", "valkey", "neovim", "mg",
    "socat", "stunnel", "openvpn", "nginx", "lighttpd", "privoxy", "masscan", "mutt",
    "irssi", "w3m", "tig", "mc", "pv", "jhead", "mtr", "wireguard-tools",
    "universal-ctags", "gnuplot", "nmap", "mosh", "aria2", "btop", "qpdf",
    "poppler-utils", "7-zip", "exiv2", "ninja", "groff",
)
DEV_SET = (  # test_seti_adaylari.md §1 (geliştirme seti envanteri) ve takma adları
    "coreutils", "tmux", "htop", "redis", "redis-server", "zstd", "libzstd", "jpeg-xl",
    "libjxl", "calculix", "ccx", "varname_bench", "tree", "sqlite3", "sqlite", "libsqlite3",
    "openssl", "libcrypto", "libssl", "true", "uname", "echo", "ls", "z3", "faiss",
    "quantlib", "gh", "codex", "scapy", "ffmpeg", "libxul", "content_shell", "libpng",
    "javascriptcore",
)
LINEAGE = (  # yukarıdakilerin çatalı, ikizi ya da kod soyu ortakları
    "xxd", "macvim", "keydb", "redict", "zip", "dropbear", "yasm", "tmate", "busybox",
    "ash", "cgit", "fossil", "sqlcipher", "libressl", "lz4", "xxhash", "zopfli", "luajit",
    "neomutt", "wget2", "tcpslice", "pinentry", "libraw", "ufraw", "p7zip", "xpdf",
)
NEAR_DEV = (  # geliştirme setindeki programların işlevce eşleri (screen emsali)
    "dtach", "abduco", "dvtm", "toybox", "nvtop", "iftop", "bmon",
)
EXCLUDED = frozenset(TEST_SET_POOL_NAMES + TEST_SET_STRESS + TEST_SET_ALIASES + CANDIDATES
                     + DEV_SET + LINEAGE + NEAR_DEV)


def seed_from_text(text: str) -> int:
    return int(hashlib.sha256(text.encode()).hexdigest()[:16], 16)


def check_pool(pool: dict, excluded: Iterable[str] = EXCLUDED, flagged: Iterable[str] = ()) -> None:
    """Havuzun yapısal denetimi. Kura çekmez."""
    excl, flag = set(excluded), set(flagged)
    bad = sorted(set(pool) & excl)
    if bad:
        raise ValueError(f"havuzda dışlanan program: {bad}")
    bad = sorted(set(pool) & flag)
    if bad:
        raise ValueError(f"havuzda işaretli program: {bad}")
    bad = sorted(flag & excl)
    if bad:
        raise ValueError(f"işaretli listede dışlanan program: {bad}")
    for name, entry in pool.items():
        alan, aile, kib = entry
        if not alan or not aile:
            raise ValueError(f"{name}: alan ya da aile boş")
        if not (LOWER <= kib <= UPPER):
            raise ValueError(f"{name}: vekil {kib} KiB test setinin aralığı dışında [{LOWER}, {UPPER}]")


def _strata_members(pool: dict) -> dict[str, list[str]]:
    return {s: sorted(p for p, v in pool.items() if stratum_of(v[2]) == s) for s in STRATA}


def _pick(cands: Iterable[str], pool: dict, used_dom: set, used_fam: set, relax: bool):
    for p in cands:
        alan, aile = pool[p][0], pool[p][1]
        if aile in used_fam:
            continue
        if not relax and alan in used_dom:
            continue
        return p
    return None


def _fill(slot: str, sources: Iterable[str], perms: dict, pool: dict, chosen: dict,
          taken: set, notes: list, missing: int) -> int:
    """`slot` tabakasına `missing` yer doldurur; `sources` sırasıyla, önce sıkı sonra gevşek."""
    for src in sources:
        for relax in (False, True):
            while missing > 0:
                current = [p for s in STRATA for p in chosen[s]]
                used_dom = {pool[p][0] for p in current}
                used_fam = {pool[p][1] for p in current}
                cands = [p for p in perms[src] if p not in taken]
                p = _pick(cands, pool, used_dom, used_fam, relax)
                if p is None:
                    break
                chosen[slot].append(p)
                taken.add(p)
                missing -= 1
                if relax and pool[p][0] in used_dom:
                    notes.append({"program": p, "tabaka": slot, "neden": "alan kısıtı gevşetildi"})
                if src != slot:
                    notes.append({"program": p, "tabaka": slot, "neden": f"komşu tabakadan ({src})"})
    return missing


def draw(pool: dict, seed_text: str, quota: dict) -> dict:
    """Tabakalı kura. Havuz, tohum metni ve kota açıkça verilmek zorunda (varsayılan yok)."""
    seed = seed_from_text(seed_text)
    rng = random.Random(seed)
    members = _strata_members(pool)
    perms = {}
    for s in STRATA:
        order = list(members[s])
        rng.shuffle(order)
        perms[s] = order

    chosen: dict[str, list[str]] = {s: [] for s in STRATA}
    taken: set[str] = set()
    notes: list[dict] = []
    shortfall = {}
    for s in SELECTION_ORDER:
        left = _fill(s, (s,), perms, pool, chosen, taken, notes, quota[s])
        if left:
            shortfall[s] = left
    for s in SELECTION_ORDER:
        if s in shortfall:
            shortfall[s] = _fill(s, FALLBACK[s], perms, pool, chosen, taken, notes, shortfall[s])
    return {
        "tohum_metni": seed_text,
        "tohum": seed,
        "esikler_kib": {"T1": T1, "T2": T2, "alt": LOWER, "ust": UPPER},
        "kota": dict(quota),
        "siralar": perms,
        "ana_kume": chosen,
        "yedek_sirasi": {s: [p for p in perms[s] if p not in taken] for s in STRATA},
        "notlar": notes,
        "eksik": {s: n for s, n in shortfall.items() if n},
    }


def replace_failed(result: dict, pool: dict, failed: Iterable[str], blocked: Iterable[str] = ()) -> dict:
    """Koşulamayan programları değiştirir; kümenin geri kalanı yerinde kalır.

    `blocked`: geliştirme setine aktarılmış programlar. Seçilemezler; aileleri ve alanları
    kullanılmış sayılır (geliştirme setine yakın program doğrulamaya girmesin).
    """
    failed = set(failed)
    blocked = [p for p in blocked if p in pool]
    perms = result["siralar"]
    chosen = {s: list(result["ana_kume"][s]) for s in STRATA}
    taken = {p for s in STRATA for p in chosen[s]} | failed | set(blocked)
    log: list[dict] = []
    for s in SELECTION_ORDER:
        for p in list(chosen[s]):
            if p not in failed:
                continue
            chosen[s].remove(p)
            notes: list[dict] = []
            view = {k: list(v) for k, v in chosen.items()}
            view[s] = view[s] + blocked
            before = len(view[s])
            _fill(s, (s,) + FALLBACK[s], perms, pool, view, taken, notes, 1)
            new = view[s][before:]
            rep = new[0] if new else None
            if rep:
                chosen[s].append(rep)
            log.append({"cikan": p, "giren": rep, "tabaka": s, "notlar": notes})
    return {**result, "ana_kume": chosen, "degisimler": log, "kosulamayan": sorted(failed)}


def stress_seed_text(seed_text: str) -> str:
    """Stres alt kümesinin alt tohum metni: ana tohum metni + "/stres"."""
    return seed_text + STRESS_SEED_SUFFIX


def stress_draw(flagged: Iterable[str], seed_text: str, k: int) -> dict:
    """İşaretli listeden stres alt kümesi (varsayılan yok).

    `seed_text` ana tohum metnidir; alt tohum ondan türetilir, ana kuranın üretecine
    dokunulmaz. Liste alfabetik sıralanır, alt tohumla karıştırılır; ilk `k` program seçilir,
    kalanlar sırasıyla yedektir.
    """
    sub_text = stress_seed_text(seed_text)
    sub_seed = seed_from_text(sub_text)
    order = sorted(flagged)
    random.Random(sub_seed).shuffle(order)
    return {"alt_tohum_metni": sub_text, "alt_tohum": sub_seed, "boyut": k,
            "sira": order, "kume": order[:k], "yedek_sirasi": order[k:]}


def stress_replace(stress: dict, failed: Iterable[str]) -> dict:
    """Koşulamayan stres programlarının yerine sıradaki ilk koşulabilir programlar gelir."""
    failed = set(failed)
    final = [p for p in stress["sira"] if p not in failed][: stress["boyut"]]
    incoming = [p for p in final if p not in stress["kume"]]
    log = []
    for p in stress["kume"]:
        if p in failed:
            log.append({"cikan": p, "giren": incoming.pop(0) if incoming else None})
    return {**stress, "kume": final, "degisimler": log}


def parse_failures(spec: str, known: Iterable[str]) -> dict[str, str]:
    """`ad:NEDEN,ad:NEDEN` biçimini çözer (ön kayıt §4.4-4.5).

    Geçerli nedenler REPLACEMENT_REASONS'tır. K3 değişim nedeni değildir: Mac ikilisi
    kaynaktan derlenir; derleme 30 dakikada başarıyla bitmezse neden K6 yazılır.
    """
    known = set(known)
    out: dict[str, str] = {}
    for item in (x.strip() for x in spec.split(",")):
        if not item:
            continue
        name, sep, reason = (part.strip() for part in item.partition(":"))
        if not sep or not reason:
            raise ValueError(f"{item}: neden eksik (biçim ad:NEDEN, ör. {name}:K2)")
        if reason == REBUILD_REASON:
            raise ValueError(f"{name}: K3 değişim nedeni değil; Mac ikilisi kaynaktan derlenir (ön kayıt §4.4). "
                             "Derleme 30 dakikada başarıyla bitmezse neden K6'dır")
        if reason not in REPLACEMENT_REASONS:
            raise ValueError(f"{name}: bilinmeyen neden {reason}; geçerli: {', '.join(REPLACEMENT_REASONS)}")
        if name not in known:
            raise ValueError(f"{name}: havuzda ya da işaretli listede yok")
        out[name] = reason
    return out


def dev_topup_order(result: dict, pool: dict, failed: Iterable[str] = (), floor: dict | None = None) -> list[str]:
    """Geliştirme setini tamamlama sırası (ön kayıt §8).

    Korumalı yedekler (her tabakada seçilmemiş ve koşulamaz olmayan ilk `floor[s]` program)
    verilmez. Son kümeyle aynı aileden ya da alandan olanlar verilmez. Kalanlar tabakalar
    arasında küçük, orta, büyük sırasıyla dönüşümlü dizilir.
    """
    floor = result["kota"] if floor is None else floor
    failed = set(failed)
    final = [p for s in STRATA for p in result["ana_kume"][s]]
    used_dom = {pool[p][0] for p in final}
    used_fam = {pool[p][1] for p in final}
    queues = []
    for s in STRATA:
        rest = [p for p in result["siralar"][s] if p not in final and p not in failed]
        tail = rest[floor[s]:]
        queues.append([p for p in tail if pool[p][0] not in used_dom and pool[p][1] not in used_fam])
    out: list[str] = []
    while any(queues):
        for q in queues:
            if q:
                out.append(q.pop(0))
    return out


def registration_check(paths: Iterable[str], run: Callable = subprocess.run) -> tuple[bool, str]:
    """Betik ve ön kayıt belgesi git'te izleniyor ve değişmemiş mi?"""
    paths = list(paths)
    ls = run(["git", "ls-files", "--error-unmatch", "--", *paths],
             cwd=REPO_ROOT, capture_output=True, text=True)
    if ls.returncode != 0:
        return False, "ön kayıt dosyaları git'te izlenmiyor (önce commit)"
    st = run(["git", "status", "--porcelain", "--", *paths], cwd=REPO_ROOT, capture_output=True, text=True)
    if st.returncode != 0 or st.stdout.strip():
        return False, "ön kayıt dosyalarında commit edilmemiş değişiklik var"
    return True, "kayıtlı"


def _provenance() -> dict:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
    pool_json = json.dumps(VALIDATION_POOL, ensure_ascii=False, sort_keys=True).encode()
    return {
        "betik_sha256": hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest(),
        "test_seti_betigi_sha256": hashlib.sha256(TEST_SET_SCRIPT.read_bytes()).hexdigest(),
        "havuz_sha256": hashlib.sha256(pool_json).hexdigest(),
        "git_head": head.stdout.strip() if head.returncode == 0 else None,
        "python": platform.python_version(),
    }


def _structure_report() -> dict:
    check_pool(VALIDATION_POOL, EXCLUDED, FLAGGED)
    members = _strata_members(VALIDATION_POOL)
    return {
        "esikler_kib": {"T1": T1, "T2": T2, "alt": LOWER, "ust": UPPER},
        "tabaka_buyuklukleri": {s: len(m) for s, m in members.items()},
        "tabaka_alan_sayilari": {s: len({VALIDATION_POOL[p][0] for p in m}) for s, m in members.items()},
        "kota": VALIDATION_QUOTA,
        "isaretli": len(FLAGGED),
        "stres_alt_kumesi": {"aday": len(FLAGGED), "boyut": STRESS_SIZE},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--denetim", action="store_true", help="yalnız yapısal denetim (kura çekmez)")
    ap.add_argument("--kosulamayan", default="",
                    help="koşulamayanlar, virgülle ad:NEDEN (NEDEN: K1, K2, K4, K5, K6; K3 kabul edilmez)")
    ap.add_argument("--aktarilan", default="", help="geliştirme setine aktarılmış havuz programları (virgülle)")
    ap.add_argument("--gelistirme", type=int, default=0, help="geliştirme seti tamamlama sırasından ilk N")
    args = ap.parse_args(argv)

    if args.denetim:
        print(json.dumps(_structure_report(), ensure_ascii=False, indent=1))
        return 0
    ok, msg = registration_check([SCRIPT_REL, PREREGISTRATION_DOC])
    if not ok:
        print(f"KURA ÇEKİLMEDİ: {msg}", file=sys.stderr)
        return 2
    try:  # girdiler kuradan önce denetlenir
        reasons = parse_failures(args.kosulamayan, set(VALIDATION_POOL) | set(FLAGGED))
    except ValueError as exc:
        print(f"KURA ÇEKİLMEDİ: {exc}", file=sys.stderr)
        return 2
    moved = [x.strip() for x in args.aktarilan.split(",") if x.strip()]
    unknown = sorted(set(moved) - set(VALIDATION_POOL))
    if unknown:
        print(f"KURA ÇEKİLMEDİ: havuzda olmayan program: {unknown}", file=sys.stderr)
        return 2
    check_pool(VALIDATION_POOL, EXCLUDED, FLAGGED)

    result = draw(VALIDATION_POOL, VALIDATION_SEED_TEXT, VALIDATION_QUOTA)
    failed_main = [p for p in reasons if p in VALIDATION_POOL]
    failed_stress = [p for p in reasons if p in FLAGGED]
    if failed_main:
        result = replace_failed(result, VALIDATION_POOL, failed_main, blocked=moved)
        for entry in result["degisimler"]:
            entry["neden"] = reasons[entry["cikan"]]
    stress = stress_draw(FLAGGED, VALIDATION_SEED_TEXT, STRESS_SIZE)
    if failed_stress:
        stress = stress_replace(stress, failed_stress)
        for entry in stress["degisimler"]:
            entry["neden"] = reasons[entry["cikan"]]
    result["stres_alt_kumesi"] = stress
    result["kosulamama_nedenleri"] = reasons
    if args.gelistirme:
        order = dev_topup_order(result, VALIDATION_POOL, failed_main + moved)
        result["gelistirme_tamamlama"] = order[: args.gelistirme]
    result["kunye"] = _provenance()
    result["alanlar"] = {s: [VALIDATION_POOL[p][0] for p in result["ana_kume"][s]] for s in STRATA}
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
