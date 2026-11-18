#!/usr/bin/env python3
"""P08 ölçümü: imza katmanının kitaplık iddiası doğru mu (Ghidra'sız yeniden oynatma).

İki alt komut:

``oynat``  Saklı bir ürün koşusunun (``<kök>/debian/<program>/<ikili>`` ve ``<kök>/mac/<ikili>``)
           Ghidra çıktıları üstünde ``SignatureDB.match_all``'ı bu ağacın koduyla yeniden koşar ve
           her ikili için ``signature_matches.json`` yazar (ürünün yazdığı biçimle aynı).
``puanla`` Bir eşleşme kümesini (saklı ürün çıktısı ya da ``oynat`` çıktısı) ikilinin KENDİ içe
           aktarım tablosuna karşı puanlar: ELF'te sürüm gereksinimi (``.gnu.version_r``), Mach-O'da
           iki düzeyli ad alanı bağlaması. Karadul çıktısına bağlı değildir.

Ön kayıt: ``docs/arge/2026-11-18_onarim/P08_on_kayit.md``.

Kullanım:
    python scripts/measurement/p08_olc.py oynat --kok ~/karadul_olcum/runs/urun-yeni2-f30ac9a \
        --cikti ~/karadul_olcum/runs/onarim-2026-11-18/P08/<etiket> [--lmdb <yol>]
    python scripts/measurement/p08_olc.py puanla --kok ~/karadul_olcum/runs/urun-yeni2-f30ac9a \
        [--eslesme <oynat çıktısı>] --cikti <özet.json>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

DEPO = Path(__file__).resolve().parents[2]
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))

# ---------------------------------------------------------------------------
# Koşu yerleşimi
# ---------------------------------------------------------------------------


def kosulari_bul(kok: Path) -> list[tuple[str, Path]]:
    """(anahtar, çalışma alanı zaman dizini) listesi. Anahtar ``debian/<prog>/<ikili>`` / ``mac/<ikili>``."""
    out: list[tuple[str, Path]] = []
    for ws in sorted(kok.glob("debian/*/*/ws/workspaces/*/*")) + sorted(kok.glob("mac/*/ws/workspaces/*/*")):
        if not (ws / "raw").is_dir():
            continue
        rel = ws.relative_to(kok).parts
        anahtar = "/".join(rel[: rel.index("ws")])
        out.append((anahtar, ws))
    return out


def ham_ikili(ws: Path) -> tuple[Path | None, dict]:
    raw = ws / "raw"
    bilgi = json.loads((raw / "target_info.json").read_text(encoding="utf-8"))
    dosyalar = [p for p in raw.iterdir() if p.is_file() and p.name != "target_info.json"]
    return (dosyalar[0] if len(dosyalar) == 1 else None), bilgi


_PLATFORM = {"elf_binary": "elf", "macho_binary": "macho", "universal_binary": "macho", "pe_binary": "pe"}


# ---------------------------------------------------------------------------
# oynat
# ---------------------------------------------------------------------------


def oynat(kok: Path, cikti: Path, lmdb: Path | None, yalniz: set[str] | None) -> dict:
    from karadul.analyzers.signature_db import SignatureDB
    from karadul.config import Config

    cfg = Config()
    cfg.project_root = cikti  # sigs/ yok: LMDB yoksa yalnız yerleşik sözlük (künyede görünür)
    cfg.perf.use_lmdb_sigdb = True
    cfg.perf.sig_lmdb_path = lmdb
    ozet: dict[str, Any] = {"kok": str(kok), "lmdb": str(lmdb) if lmdb else None, "ikililer": {}}
    for anahtar, ws in kosulari_bul(kok):
        if yalniz and anahtar not in yalniz:
            continue
        _, bilgi = ham_ikili(ws)
        platform = _PLATFORM.get(bilgi.get("target_type", ""))

        def pick(name: str) -> Path:
            p = ws / "deobfuscated" / name
            return p if p.exists() else ws / "static" / name

        dec = ws / "deobfuscated" / "decompiled"
        t0 = time.monotonic()
        db = SignatureDB(cfg, target_platform=platform)
        info = db.backend_info()
        matches = db.match_all(pick("ghidra_functions.json"), pick("ghidra_strings.json"),
                               pick("ghidra_call_graph.json"), dec, target_platform=platform)
        hedef = cikti / anahtar / "signature_matches.json"
        hedef.parent.mkdir(parents=True, exist_ok=True)
        kayit = {
            "total": len(matches),
            "database": {k: info[k] for k in sorted(info)},
            "matches": [_kayit(m) for m in matches],
        }
        hedef.write_text(json.dumps(kayit, indent=1, ensure_ascii=False), encoding="utf-8")
        ozet["ikililer"][anahtar] = {"eslesme": len(matches), "sure_sn": round(time.monotonic() - t0, 2),
                                    "sigdb_backend": info["sigdb_backend"]}
    (cikti / "oynat_ozet.json").write_text(json.dumps(ozet, indent=1, ensure_ascii=False), encoding="utf-8")
    return ozet


def _kayit(m: Any) -> dict:
    d = {
        "original": m.original_name, "matched": m.matched_name, "library": m.library,
        "confidence": m.confidence, "purpose": m.purpose, "address": m.address,
        "method": m.match_method, "category": m.category,
    }
    libs = getattr(m, "libraries", None)
    if libs is not None:
        d["libraries"] = list(libs)
    return d


# ---------------------------------------------------------------------------
# GT: ikilinin kendi içe aktarım tablosu
# ---------------------------------------------------------------------------


def elf_ithal_saglayicilari(yol: Path) -> dict[str, str]:
    """Tanımsız dinamik simge → sürüm gereksinimindeki dosya (``libc.so.6``). Sürümsüzler yok."""
    from elftools.elf.elffile import ELFFile

    out: dict[str, str] = {}
    with open(yol, "rb") as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name(".dynsym")
        versym = elf.get_section_by_name(".gnu.version")
        verneed = elf.get_section_by_name(".gnu.version_r")
        if dynsym is None or versym is None or verneed is None:
            return out
        dizin_dosya: dict[int, str] = {}
        for vn, aux_iter in verneed.iter_versions():
            for aux in aux_iter:
                dizin_dosya[int(aux.entry["vna_other"])] = vn.name
        for i, sym in enumerate(dynsym.iter_symbols()):
            if sym.entry["st_shndx"] != "SHN_UNDEF" or not sym.name:
                continue
            ndx = versym.get_symbol(i).entry["ndx"]
            if isinstance(ndx, str):
                continue  # VER_NDX_LOCAL / GLOBAL: sürümsüz
            dosya = dizin_dosya.get(int(ndx) & 0x7FFF)
            if dosya:
                out[sym.name] = dosya
    return out


def macho_ithal_saglayicilari(yol: Path) -> dict[str, str]:
    """İçe aktarılan simge (C adı, baştaki tek ``_`` atılmış ve atılmamış) → dylib adı."""
    import lief

    out: dict[str, str] = {}
    fat = lief.MachO.parse(str(yol))
    if fat is None:
        return out
    b = fat.at(0)
    for s in b.imported_symbols:
        lib = None
        try:
            if s.has_binding_info and s.binding_info.has_library:
                lib = s.binding_info.library.name
        except Exception:  # noqa: BLE001
            lib = None
        if not lib:
            continue
        ad = s.name
        out[ad] = lib
        if ad.startswith("_"):
            out.setdefault(ad[1:], lib)
    return out


_GLIBC = {"c", "glibc", "c6", "pthread", "dl", "rt", "m", "ld-linux", "ld-linux-aarch64", "ld-linux-x86-64"}
_LIBSYSTEM_MACHO = {"system", "system.b", "c"}
_OPENSSL = {"openssl", "ssl", "crypto"}


def aile(lib: str, platform: str | None) -> str:
    """Önceden sabitlenmiş kitaplık ailesi eşlemesi (ön kayıt §1)."""
    s = (lib or "").strip()
    s = s.rsplit("/", 1)[-1]
    s = re.sub(r"\.(so)(\.[0-9.]+)?$", "", s)
    s = re.sub(r"(\.[0-9]+)*\.dylib$", "", s)
    s = re.sub(r"\.(tbd|dll|lib)$", "", s, flags=re.I)
    low = s.lower()
    if low.startswith("lib") and len(low) > 3:
        low = low[3:]
    if low == "brokenlocale":
        return "brokenlocale"
    if low.startswith("ld-linux"):
        low = "ld-linux"
    if platform == "macho":
        if low in _LIBSYSTEM_MACHO or low.startswith("system_") or low.startswith("system."):
            return "libSystem"
    if low in _GLIBC:
        return "glibc"
    if low in _OPENSSL:
        return "openssl"
    return low


def pypi_kitapliklari() -> set[str]:
    p = Path("/Users/apple/Black_Widow/sigs/pypi_native_symbols.json")
    try:
        meta = json.loads(p.read_text(encoding="utf-8"))["meta"]
        return set(meta.get("library_stats", {}))
    except (OSError, KeyError, json.JSONDecodeError):
        return set()


def puanla(kok: Path, eslesme: Path | None, cikti: Path) -> dict:
    pypi = pypi_kitapliklari()
    toplam: Counter = Counter()
    ikili_ozet: dict[str, dict] = {}
    yanlis_ornek: Counter = Counter()
    for anahtar, ws in kosulari_bul(kok):
        ham, bilgi = ham_ikili(ws)
        platform = _PLATFORM.get(bilgi.get("target_type", ""))
        if eslesme is None:
            dosya = ws / "reconstructed" / "signature_matches.json"
        else:
            dosya = eslesme / anahtar / "signature_matches.json"
        kayitlar = []
        if dosya.exists():
            kayitlar = json.loads(dosya.read_text(encoding="utf-8")).get("matches", [])
        gt: dict[str, str] = {}
        if ham is not None:
            try:
                gt = elf_ithal_saglayicilari(ham) if platform == "elf" else (
                    macho_ithal_saglayicilari(ham) if platform == "macho" else {})
            except Exception as exc:  # noqa: BLE001
                print(f"[uyarı] {anahtar}: GT okunamadı: {exc}", file=sys.stderr)
        c: Counter = Counter()
        for k in kayitlar:
            orig = k.get("original", "")
            lib = k.get("library", "") or ""
            cat = k.get("category", "") or ""
            meth = k.get("method", "")
            c["kayit"] += 1
            if lib in pypi or cat == "pypi_native":
                c["H3_pypi_iddiasi"] += 1
            if platform in ("elf", "pe") and meth == "symbol" and k.get("matched") != orig \
                    and orig.lstrip("_") == k.get("matched"):
                c["H4_alt_cizgi_silinmis"] += 1
            if meth == "symbol" and "protobuf" in lib.lower() and "google::protobuf" not in orig \
                    and "google::protobuf" in (k.get("matched") or ""):
                c["H5_protobuf_kismi"] += 1
            if orig == "entry":
                c["H6_entry"] += 1
            if meth != "symbol":
                continue
            g = gt.get(orig)
            if g is None:
                c["gt_yok"] += 1
                continue
            c["gt_li"] += 1
            if not lib:
                c["iddia_yok"] += 1
            elif aile(lib, platform) == aile(g, platform):
                c["dogru"] += 1
            else:
                c["yanlis"] += 1
                yanlis_ornek[(orig, lib, g)] += 1
        ikili_ozet[anahtar] = dict(c)
        toplam.update(c)
    d, y = toplam["dogru"], toplam["yanlis"]
    sonuc = {
        "kok": str(kok), "eslesme": str(eslesme) if eslesme else "saklı ürün çıktısı",
        "toplam": dict(toplam),
        "kesinlik": round(d / (d + y), 4) if (d + y) else None,
        "en_sik_yanlis": [[o, l, g, n] for (o, l, g), n in yanlis_ornek.most_common(40)],
        "ikililer": ikili_ozet,
    }
    cikti.parent.mkdir(parents=True, exist_ok=True)
    cikti.write_text(json.dumps(sonuc, indent=1, ensure_ascii=False), encoding="utf-8")
    return sonuc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    o = alt.add_parser("oynat")
    o.add_argument("--kok", type=Path, required=True)
    o.add_argument("--cikti", type=Path, required=True)
    o.add_argument("--lmdb", type=Path, default=None)
    o.add_argument("--yalniz", nargs="*", default=None)
    p = alt.add_parser("puanla")
    p.add_argument("--kok", type=Path, required=True)
    p.add_argument("--eslesme", type=Path, default=None)
    p.add_argument("--cikti", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.komut == "oynat":
        oz = oynat(a.kok.expanduser(), a.cikti.expanduser(), a.lmdb, set(a.yalniz) if a.yalniz else None)
        print(json.dumps({"ikili": len(oz["ikililer"]),
                          "eslesme": sum(v["eslesme"] for v in oz["ikililer"].values())}, ensure_ascii=False))
    else:
        s = puanla(a.kok.expanduser(), a.eslesme.expanduser() if a.eslesme else None, a.cikti.expanduser())
        print(json.dumps({"toplam": s["toplam"], "kesinlik": s["kesinlik"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
