#!/usr/bin/env python
"""KİMLİK Dalga 0 — V1 (``surum_esli``): Debian kaynak paketlerini macOS'ta iki derleyiciyle aynı bayraklarla derle.

Düzen tur 1'in ``derle_gcc.sh``'idir (PK-6_on_kayit.md §2). Adımlar (her biri idempotent; günlükler
``<KOK>/v1/gunluk/``):

  ac       Her paket kendi YENİ boş dizinine açılır: ``~/karadul_olcum/kimlik_v1/x_<paket>/`` (``.orig.tar.*`` +
           ``.debian.tar.xz``; ``tarfile`` ``data`` süzgeciyle, yol kaçışı engelli). sha256'lar ``v1_veri.json``
           ile denetlenir. Debian yamaları (``debian/patches/series``) sırayla ``/usr/bin/patch -p1`` ile denenir;
           uygulanan / uygulanamayan künyeye yazılır. Açılmış ağaç bir daha değiştirilmez.
  derle    Her derleyici (``gcc`` = Homebrew GCC 16, ``clang`` = Apple clang) için kaynak ağacı ayrı bir kopyaya
           alınır (``<KOK>/v1/src/<derleyici>/<paket>``) ve aynı bayraklarla (``-O2``) derlenir. Derleme
           ``sandbox-exec`` altında ağ KAPALI koşar. Hedefler: tree; ``programs/zstd``; sqlite3 kabuğu (kendi
           derlediği ``libsqlite3.dylib``'e dinamik bağlı, Debian'daki gibi); redis'ten yalnız ``redis-cli`` ve
           ``redis-benchmark`` (lua hedefi derlenmez, bağlanmaz). Derleme çıktısı ÇALIŞTIRILMAZ.
  hazirla  Çıktılar ``<KOK>/v1/<derleyici>/ozgun/``'a kopyalanır, ``korpus.json`` yazılır ve
           ``scripts/measurement/macho_measure.py prepare`` (Apple strip + export trie denetimi + ``nm`` GT) koşar.

Kullanım (worktree kökünden): ``python -I scripts/arge/kimlik/d0_derle.py ac|derle|hazirla [--paket …]``
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

_BURASI = Path(__file__).resolve().parent
REPO = _BURASI.parents[2]
V1_KOK = Path.home() / "karadul_olcum" / "kimlik_v1"
V1_VERI = V1_KOK / "v1_veri.json"
KOK = Path.home() / "karadul_olcum" / "runs" / "dalga0-2026-11-20" / "KIMLIK" / "v1"
GUNLUK = KOK / "gunluk"
B = Path("/opt/homebrew")
DERLEYICILER = {"gcc": str(B / "bin" / "gcc-16"), "clang": "/usr/bin/clang"}
OPT = "-O2"
PATCH = "/usr/bin/patch"
AG_KAPALI = ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)"]
PAKETLER = ("tree", "libzstd", "sqlite3", "redis")
# paket → [(ikili adı, derleme ağacındaki yolu)]
V1_HEDEF_IKILILERI = {
    "tree": [("tree", "tree")],
    "libzstd": [("zstd", "programs/zstd")],
    "sqlite3": [("sqlite3", "sqlite3")],
    "redis": [("redis-cli", "src/redis-cli"), ("redis-benchmark", "src/redis-benchmark")],
}


def sha256(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for p in iter(lambda: f.read(1 << 20), b""):
            h.update(p)
    return h.hexdigest()


def _veri() -> dict:
    return json.loads(V1_VERI.read_text(encoding="utf-8"))


def _paket(ad: str) -> dict:
    return next(p for p in _veri()["paketler"] if p["paket"] == ad)


def _kos(komut: list[str], cwd: Path, gunluk: Path, ortam: dict | None = None, ag_kapali: bool = True) -> int:
    gunluk.parent.mkdir(parents=True, exist_ok=True)
    tam = (AG_KAPALI + komut) if ag_kapali else komut
    with open(gunluk, "a", encoding="utf-8") as g:
        g.write(f"\n$ (cwd {cwd}) {' '.join(tam)}\n")
        g.flush()
        return subprocess.run(tam, cwd=cwd, env=ortam, stdout=g, stderr=subprocess.STDOUT).returncode


def kaynak_dizini(paket: str) -> Path:
    x = V1_KOK / f"x_{paket}"
    adaylar = [d for d in x.iterdir() if d.is_dir()] if x.is_dir() else []
    if len(adaylar) != 1:
        raise RuntimeError(f"{x}: tek kaynak dizini bekleniyordu, {len(adaylar)} var")
    return adaylar[0]


def ac(paket: str) -> dict:
    p = _paket(paket)
    x = V1_KOK / f"x_{paket}"
    isaret = x.parent / f".x_{paket}_acildi.json"
    if isaret.is_file():
        return json.loads(isaret.read_text(encoding="utf-8"))
    if x.exists() and any(x.iterdir()):
        raise RuntimeError(f"{x} boş değil ve açılma kaydı yok: elle bakılmalı")
    x.mkdir(parents=True, exist_ok=True)
    dosyalar = {d["ad"]: d for d in p["dosyalar"]}
    for ad, d in dosyalar.items():
        yol = V1_KOK / "indir" / paket / ad
        if sha256(yol) != d["sha256"]:
            raise RuntimeError(f"{yol}: sha256 künyeyle uyuşmuyor")
    orig = [a for a in dosyalar if ".orig." in a and "-www" not in a]
    deb = [a for a in dosyalar if a.endswith(".debian.tar.xz")]
    if len(orig) != 1 or len(deb) != 1:
        raise RuntimeError(f"{paket}: orig {orig} / debian {deb}")
    with tarfile.open(V1_KOK / "indir" / paket / orig[0]) as t:
        t.extractall(x, filter="data")
    kaynak = kaynak_dizini(paket)
    with tarfile.open(V1_KOK / "indir" / paket / deb[0]) as t:
        t.extractall(kaynak, filter="data")
    seri = kaynak / "debian" / "patches" / "series"
    uygulanan, uygulanamayan = [], []
    if seri.is_file():
        for s in seri.read_text(encoding="utf-8").splitlines():
            s = s.split("#", 1)[0].strip()
            if not s:
                continue
            ad = s.split()[0]
            kod = _kos([PATCH, "-p1", "--forward", "--batch", "-i", str(kaynak / "debian" / "patches" / ad)],
                       kaynak, GUNLUK / f"ac_{paket}.log", ag_kapali=False)
            (uygulanan if kod == 0 else uygulanamayan).append(ad)
            if kod != 0:
                # yarım kalan yamayı geri al (aynı kaynak iki derleyicide olsun)
                _kos([PATCH, "-p1", "-R", "--batch", "-i", str(kaynak / "debian" / "patches" / ad)],
                     kaynak, GUNLUK / f"ac_{paket}.log", ag_kapali=False)
    for r in kaynak.rglob("*.rej"):
        r.unlink()
    for r in kaynak.rglob("*.orig"):
        if r.is_file():
            r.unlink()
    kayit = {"paket": paket, "surum": p["surum"], "kaynak": str(kaynak), "orig": orig[0], "debian": deb[0],
             "yama_uygulanan": uygulanan, "yama_uygulanamayan": uygulanamayan,
             "tarih": time.strftime("%Y-%m-%dT%H:%M:%S")}
    isaret.write_text(json.dumps(kayit, ensure_ascii=False, indent=1), encoding="utf-8")
    return kayit


def _ortam() -> dict:
    return {"PATH": f"{B}/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(Path.home()), "LANG": "C",
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"), "MAKEFLAGS": ""}


def derle(paket: str, derleyici: str) -> dict:
    cc = DERLEYICILER[derleyici]
    hedef = KOK / "src" / derleyici / paket
    isaret = KOK / "src" / derleyici / f".{paket}_derlendi.json"
    if isaret.is_file():
        return json.loads(isaret.read_text(encoding="utf-8"))
    if hedef.exists():
        shutil.rmtree(hedef)       # yarım kalmış önceki deneme (yalnız bu paketin kendi kopyası)
    hedef.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(kaynak_dizini(paket), hedef, symlinks=True)
    g = GUNLUK / f"derle_{derleyici}_{paket}.log"
    o = _ortam()
    if paket == "tree":
        # tree Makefile'ının macOS satırı: strverscmp.o ekle; Linux'a özgü -DLINUX yok.
        kodlar = [_kos(["make", f"CC={cc}", f"CFLAGS={OPT} -std=c11 -Wall -D_DARWIN_C_SOURCE",
                        "LDFLAGS=", "OBJS=tree.o list.o hash.o color.o file.o filter.o info.o unix.o xml.o "
                        "json.o html.o strverscmp.o", "tree"], hedef, g, o)]
    elif paket == "libzstd":
        kodlar = [_kos(["make", "-j4", "-C", "programs", f"CC={cc}", f"CFLAGS={OPT}", "HAVE_ZLIB=1", "HAVE_LZMA=0",
                        "HAVE_LZ4=0", "HAVE_THREAD=1", "zstd"], hedef, g, o)]
    elif paket == "sqlite3":
        kodlar = [_kos(["./configure", f"CC={cc}", f"CFLAGS={OPT}", "--disable-tcl", "--disable-readline",
                        "--disable-editline"], hedef, g, o)]
        if kodlar[-1] == 0:
            kodlar.append(_kos(["make", "sqlite3.c", "shell.c"], hedef, g, o))
        if kodlar[-1] == 0:
            kodlar.append(_kos([cc, OPT, "-dynamiclib", "-install_name", "@rpath/libsqlite3.dylib",
                                "-DSQLITE_THREADSAFE=1", "-o", "libsqlite3.dylib", "sqlite3.c"], hedef, g, o))
        if kodlar[-1] == 0:
            kodlar.append(_kos([cc, OPT, "-I.", "-o", "sqlite3", "shell.c", "-L.", "-lsqlite3"], hedef, g, o))
    elif paket == "redis":
        # Not: ``LDFLAGS=-Wl,-exported_symbol,__mh_execute_header`` denendi (GCC'nin ``___emutls_*`` dışa
        # aktarımını kaldırmak için); GCC sürücüsü kendi ``-exported_symbol``'lerini eklediği için dışa aktarım
        # 2 → 4 ada çıktı. Geri alındı; iki derleyicide bayraklar yine aynı (PK-6.md "Sapmalar").
        ortak = [f"CC={cc}", f"OPTIMIZATION={OPT}", "MALLOC=libc", "BUILD_TLS=no", "USE_SYSTEMD=no",
                 "DEPENDENCY_TARGETS=hiredis linenoise hdr_histogram fpconv"]
        kodlar = [_kos(["make", "-j4", "-C", "src", *ortak, "redis-cli", "redis-benchmark"], hedef, g, o)]
    else:
        raise KeyError(paket)
    ciktilar = {}
    for ikili, yol in V1_HEDEF_IKILILERI[paket]:
        f = hedef / yol
        ciktilar[ikili] = {"yol": str(f), "var": f.is_file(), "sha256": sha256(f) if f.is_file() else None}
    kayit = {"paket": paket, "derleyici": derleyici, "cc": cc, "cc_surumu": subprocess.run(
                 [cc, "--version"], capture_output=True, text=True).stdout.splitlines()[0],
             "cikis_kodlari": kodlar, "ciktilar": ciktilar, "gunluk": str(g),
             "basarili": all(k == 0 for k in kodlar) and all(c["var"] for c in ciktilar.values()),
             "tarih": time.strftime("%Y-%m-%dT%H:%M:%S")}
    if kayit["basarili"]:
        isaret.write_text(json.dumps(kayit, ensure_ascii=False, indent=1), encoding="utf-8")
    return kayit


def hazirla(derleyici: str, paketler: list[str]) -> dict:
    d = KOK / derleyici
    (d / "ozgun").mkdir(parents=True, exist_ok=True)
    korpus = {"schema": "karadul-macho-corpus/1",
              "not": f"KİMLİK Dalga 0 V1 (surum_esli): Debian kaynak paketleri, {derleyici} {OPT} (d0_derle.py). "
                     "Geliştirme seti programları; kilitli set yok.", "binaries": {}}
    for paket in paketler:
        isaret = KOK / "src" / derleyici / f".{paket}_derlendi.json"
        if not isaret.is_file():
            continue
        kayit = json.loads(isaret.read_text(encoding="utf-8"))
        for ikili, c in kayit["ciktilar"].items():
            hedef = d / "ozgun" / ikili
            if not hedef.is_file() or sha256(hedef) != c["sha256"]:
                hedef.unlink(missing_ok=True)
                shutil.copyfile(c["yol"], hedef)
            korpus["binaries"][ikili] = {"set": "gelistirme", "orig": {"path": str(hedef), "sha256": c["sha256"]}}
    (d / "korpus.json").write_text(json.dumps(korpus, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    kodlar, yedek = {}, {}
    for ikili in sorted(korpus["binaries"]):
        kodlar[ikili] = _kos([sys.executable, str(REPO / "scripts" / "measurement" / "macho_measure.py"),
                              "--data-dir", str(d), "--corpus", str(d / "korpus.json"), "prepare", "--only", ikili],
                             REPO, GUNLUK / f"hazirla_{derleyici}.log",
                             dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), ag_kapali=False)
        if kodlar[ikili] != 0:
            yedek[ikili] = gcc_tls_hazirla(d, ikili)
    return {"derleyici": derleyici, "ikililer": sorted(korpus["binaries"]), "prepare_cikis": kodlar,
            "gcc_tls_yedegi": yedek}


# GCC'nin Darwin'deki öykünmeli TLS çalışma zamanı (libgcc ``emutls``): ``__thread`` kullanan programda (redis)
# GCC sürücüsü bu iki adı dışa aktarım ağacına koyuyor; Apple strip kaldırmıyor. Program adı değildir.
GCC_TLS_DISA_AKTARIM = frozenset({"___emutls_get_address", "___emutls_register_common"})


def gcc_tls_hazirla(d: Path, ikili: str) -> dict:
    """``macho_measure prepare``'ın aynısı (aynı işlevler: ``strip_binary``, ``read_exports``, ``mf.build_gt``);
    tek fark: dışa aktarım ağacında ``__mh_execute_header`` dışında YALNIZ ``GCC_TLS_DISA_AKTARIM`` adları kalmışsa
    kabul edilir ve künyeye yazılır. Soyulmuş kopyada kalan ``nm`` fonksiyon simgeleri de yalnız bu adlar olmalı;
    başka her durumda hata (GT sızıntısı yok)."""
    sys.path.insert(0, str(REPO / "scripts" / "measurement"))
    import macho_measure as mm
    mf = mm.mf
    korpus = json.loads((d / "korpus.json").read_text(encoding="utf-8"))
    spec = korpus["binaries"][ikili]
    kaynak = Path(spec["orig"]["path"])
    if sha256(kaynak) != spec["orig"]["sha256"]:
        raise RuntimeError(f"{ikili}: özgün sha256 uyuşmuyor")
    o, b = mm.orig_path(d, ikili), mm.bin_path(d, ikili)
    o.parent.mkdir(parents=True, exist_ok=True)
    if not o.is_file() or sha256(o) != spec["orig"]["sha256"]:
        o.unlink(missing_ok=True)
        shutil.copyfile(kaynak, o)
        o.chmod(0o444)
    mm.strip_binary(o, b)
    disa = mm.read_exports(b)
    fazla = set(disa) - mm.ALLOWED_EXPORTS
    kalan = {n for ns in mf.parse_nm(mf.run_nm(b)).values() for n in ns}
    if not fazla <= GCC_TLS_DISA_AKTARIM or not kalan <= GCC_TLS_DISA_AKTARIM:
        b.unlink(missing_ok=True)
        raise RuntimeError(f"{ikili}: dışa aktarım {sorted(fazla)} / nm {sorted(kalan)[:5]} izinli kümenin dışında")
    gt = mf.build_gt(o, binary=ikili, stripped=b)
    gp = mm.gt_path(d, ikili)
    gp.parent.mkdir(parents=True, exist_ok=True)
    gp.write_text(json.dumps(gt, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    kayit = {"ikili": ikili, "disa_aktarim_fazla": sorted(fazla), "nm_kalan": sorted(kalan),
             "stripped_sha256": gt["stripped_sha256"], "gt": gt["counts"]}
    (d / "corpus" / ikili / "gcc_tls_yedegi.json").write_text(json.dumps(kayit, ensure_ascii=False, indent=1),
                                                             encoding="utf-8")
    return kayit


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("adim", choices=("ac", "derle", "hazirla"))
    ap.add_argument("--paket", nargs="*", default=list(PAKETLER))
    ap.add_argument("--derleyici", nargs="*", default=list(DERLEYICILER))
    a = ap.parse_args(argv)
    for p in a.paket:
        if p not in PAKETLER:
            raise SystemExit(f"bilinmeyen paket {p}")
    if a.adim == "ac":
        for p in a.paket:
            print(json.dumps(ac(p), ensure_ascii=False))
    elif a.adim == "derle":
        for dz in a.derleyici:
            for p in a.paket:
                k = derle(p, dz)
                print(json.dumps({x: k[x] for x in ("paket", "derleyici", "cikis_kodlari", "basarili")},
                                 ensure_ascii=False), flush=True)
    else:
        for dz in a.derleyici:
            print(json.dumps(hazirla(dz, a.paket), ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
