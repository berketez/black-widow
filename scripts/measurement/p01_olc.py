#!/usr/bin/env python3
"""P01 ölçümü: ``binary_intelligence`` iddialarını ham ikililerde, ürünün çağırdığı biçimde say.

Çağıran ``karadul/analyzers/macho.py`` (``MachOAnalyzer.analyze_static`` adım 8): girdiler
``strings -n 4`` çıktısı (100 MB üstünde mmap), ``nm -g`` simge adları (ELF'te boşsa lief ile
dinamik simge tablosu) ve Mach-O'da ``otool -L`` kitaplık yollarıdır. Bu betik aynı yardımcıları
çağırır; Ghidra koşmaz (``analyze_decompiled`` bu ölçümün dışında).

Üç alt komut:

    topla       girdileri bir kez çıkarır ve ``<kök>/girdiler/<anahtar>.json.gz`` olarak saklar
                (önce ve sonra koşuları aynı girdiyi okusun diye)
    kos         saklı girdilerle ``BinaryIntelligence.analyze`` koşar, ``<kök>/<etiket>/`` altına
                ikili başına iddiaları ve küme başına sayımı yazar
    karsilastir iki etiketin sayımını yan yana markdown tablo olarak basar

Kümeler: ``gelistirme`` (119 ikili, ``urun_kos.isleri_topla``), ``mac_masum`` (macOS ``/bin`` ve
``/usr/bin``), ``pe_masum`` (Ghidra dağıtımındaki ve pip ``distlib`` içindeki ``.exe``),
``gercek_pozitif`` (iddiası bilinen ikililer; beklenen iddialar ``BEKLENEN`` sözlüğünde, nedeniyle).

Kullanım (worktree kökünden):
    python scripts/measurement/p01_olc.py topla --kok ~/karadul_olcum/runs/onarim-2026-11-18/P01
    python scripts/measurement/p01_olc.py kos --kok ... --etiket once
    python scripts/measurement/p01_olc.py karsilastir --kok ... --once once --sonra sonra
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import gzip
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

DEPO = Path(__file__).resolve().parents[2]
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))

ANA_DEPO = Path("/Users/apple/Black_Widow")
GHIDRA = Path.home() / "Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC"
DISTLIB = Path("/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib")

MAC_MASUM = [
    "/bin/cat", "/bin/chmod", "/bin/cp", "/bin/date", "/bin/dd", "/bin/df", "/bin/echo",
    "/bin/expr", "/bin/hostname", "/bin/kill", "/bin/ln", "/bin/ls", "/bin/mkdir", "/bin/mv",
    "/bin/ps", "/bin/pwd", "/bin/rm", "/bin/sleep", "/bin/stty", "/bin/test",
    "/usr/bin/grep", "/usr/bin/find", "/usr/bin/sort", "/usr/bin/uniq", "/usr/bin/wc",
    "/usr/bin/head", "/usr/bin/tail", "/usr/bin/diff", "/usr/bin/cut", "/usr/bin/tr",
    "/usr/bin/xargs", "/usr/bin/which", "/usr/bin/du", "/usr/bin/file", "/usr/bin/less",
    "/usr/bin/vim", "/usr/bin/top",
]

# Gerçek pozitifler: ikili → beklenen iddialar ("kategori:ad") ve gerekçe.
# Gerekçe ikilinin belgelenmiş işlevidir; iddianın kanıtı ölçümde ayrıca yazılır.
BEKLENEN: dict[str, tuple[list[str], str]] = {
    "debian/openssl/openssl": (
        ["subsystems:Encryption", "algorithms:AES", "algorithms:RSA", "algorithms:SHA-256",
         "algorithms:OpenSSL API"],
        "OpenSSL komut satırı aracı; libcrypto/libssl'e bağlı"),
    "/usr/bin/openssl": (
        ["subsystems:Encryption", "algorithms:AES", "algorithms:RSA", "algorithms:SHA-256"],
        "LibreSSL komut satırı aracı (statik libcrypto)"),
    "/usr/sbin/bluetoothd": (["subsystems:Bluetooth"], "macOS Bluetooth hizmeti"),
    "/usr/sbin/BTLEServer": (["subsystems:Bluetooth"], "macOS Bluetooth LE sunucusu"),
    "/usr/sbin/bluetoothaudiod": (["subsystems:Bluetooth"], "macOS Bluetooth ses hizmeti"),
    "/usr/libexec/bluetoothuserd": (["subsystems:Bluetooth"], "macOS Bluetooth kullanıcı hizmeti"),
    "/usr/bin/curl": (["protocols:HTTPS", "subsystems:HTTP Client"], "HTTP(S) istemcisi"),
    "/usr/libexec/nsurlsessiond": (["protocols:HTTPS"], "NSURLSession arka plan hizmeti"),
    "/usr/bin/ssh": (["protocols:SSH", "subsystems:Encryption"], "OpenSSH istemcisi"),
    "/usr/bin/nc": (["subsystems:TCP/UDP Networking"], "netcat"),
    "/usr/bin/sntp": (["protocols:NTP"], "SNTP istemcisi"),
    "/sbin/md5": (["algorithms:MD5", "algorithms:SHA-256"], "md5/sha256 özet aracı"),
    "/usr/libexec/endpointsecurityd": (["security:Endpoint Security API"],
                                       "Endpoint Security hizmeti"),
    "/usr/bin/eslogger": (["security:Endpoint Security API"], "Endpoint Security olay günlükçüsü"),
    "/usr/bin/csrutil": (["security:SIP (System Integrity)"], "SIP yapılandırma aracı"),
    "/usr/bin/kmutil": (["security:Kernel Extension"], "çekirdek uzantısı yönetim aracı"),
    "/sbin/kextload": (["security:Kernel Extension"], "kext yükleyici"),
    "/usr/sbin/kextcache": (["security:Kernel Extension"], "kext önbellek aracı"),
    "/usr/bin/codesign": (["security:Code Signing"], "kod imzalama aracı"),
    "/usr/bin/gzip": (["algorithms:zlib"], "gzip sıkıştırma"),
    "/usr/bin/bzip2": (["subsystems:Compression"], "bzip2 sıkıştırma"),
    "/usr/bin/sqlite3": (["algorithms:SQLite"], "SQLite kabuğu (statik)"),
    "/opt/anaconda3/lib/libQt5Gui.5.15.2.dylib": (["algorithms:OpenGL"],
                                                   "Qt GUI; OpenGL çağrıları"),
    "/opt/anaconda3/lib/libQt5OpenGL.5.15.2.dylib": (["algorithms:OpenGL"],
                                                      "Qt OpenGL modülü; OpenGL.framework'e bağlı"),
}

# Masum kümelerde sayımı raporda öne çıkarılan iddialar (IMZA-01 Kanıt satırı).
ODAK = [
    "algorithms:OpenGL", "algorithms:SHA-256", "algorithms:SHA-512",
    "subsystems:Bluetooth", "subsystems:Encryption", "subsystems:Licensing",
    "subsystems:Browser Engine", "protocols:HTTPS", "protocols:IPsec", "protocols:NTP",
    "protocols:HTTP/3", "security:ASLR", "security:SIP (System Integrity)",
    "security:Anti-Tampering", "security:TCC (Privacy)", "security:Kernel Extension",
]


SISTEM_EKI = "#apple_strings_nm"
YERLI_TIPLER = {"macho_binary", "universal_binary", "elf_binary", "pe_binary", "bun_binary"}


def _beklenen(anahtar: str):
    return BEKLENEN.get(anahtar.removesuffix(SISTEM_EKI))


def _guvenli_ad(anahtar: str) -> str:
    return anahtar.strip("/").replace("/", "__")


def isleri_topla() -> list[dict]:
    """Kümeler ve ikili yolları. Geliştirme seti ``urun_kos.isleri_topla`` ile toplanır."""
    sys.path.insert(0, str(DEPO / "scripts" / "measurement"))
    import urun_kos  # noqa: E402

    taban_mac = urun_kos.TABAN_MAC
    if not taban_mac.is_dir():  # worktree'de git dışı workspaces/ yok; ana depodakini oku
        taban_mac = ANA_DEPO / "workspaces/olcum_mac/runs/ol7-c-b7faeac"
    isler = []
    for is_ in urun_kos.isleri_topla(urun_kos.TABAN_DEBIAN, taban_mac):
        isler.append({"kume": "gelistirme", "anahtar": is_["anahtar"], "yol": str(is_["girdi"]),
                      "sha256": is_["sha256"]})
    for yol in MAC_MASUM:
        if Path(yol).is_file():
            isler.append({"kume": "mac_masum", "anahtar": yol, "yol": yol})
    pe = sorted(GHIDRA.rglob("*.exe")) + sorted(DISTLIB.glob("*.exe"))
    for yol in pe:
        isler.append({"kume": "pe_masum", "anahtar": str(yol), "yol": str(yol)})
    for anahtar in BEKLENEN:
        if anahtar.startswith("debian/"):
            continue  # geliştirme setinde; sayımda ayrıca gerçek pozitif olarak okunur
        if Path(anahtar).is_file():
            isler.append({"kume": "gercek_pozitif", "anahtar": anahtar, "yol": anahtar})
    return isler


def _sha(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def girdi_cikar(is_: dict) -> dict:
    """``macho.py`` adım 4, 5 ve 2 ile aynı yardımcılar; ``bi.analyze`` girdisi."""
    from karadul.analyzers.macho import MachOAnalyzer
    from karadul.config import Config
    from karadul.core.target import TargetDetector, TargetType

    yol = Path(is_["yol"])
    ozet = _sha(yol)
    if is_.get("sha256") and ozet != is_["sha256"]:
        return {**is_, "hata": "girdi_degismis"}
    cfg = Config()
    if is_.get("sistem_araci"):
        # Ürünün PATH'teki (conda) strings/nm'si yeni arm64e yükleme komutunda çıkış 1 verip
        # bütün çıktıyı düşürüyor; gerçek pozitif ölçümü için Apple araçlarıyla ikinci girdi.
        cfg.tools.strings = Path("/usr/bin/strings")
        cfg.tools.nm = Path("/usr/bin/nm")
    an = MachOAnalyzer(cfg)
    hedef = TargetDetector().detect(yol)
    is_macho = hedef.target_type in (TargetType.MACHO_BINARY, TargetType.UNIVERSAL_BINARY,
                                     TargetType.BUN_BINARY)
    dylibs = an._run_otool_libs(yol) if is_macho else None
    esik = cfg.binary_reconstruction.large_binary_threshold_mb * 1024 * 1024
    if hedef.file_size > esik:
        dizgiler = an._extract_strings_mmap(yol, min_length=cfg.analysis.string_min_length)
        yontem = "mmap"
    else:
        dizgiler = an.runner.run_strings(yol)
        yontem = "subprocess"
    simgeler = an._run_nm(yol)
    if hedef.target_type == TargetType.ELF_BINARY and not (simgeler or {}).get("symbols"):
        dyn = an._run_elf_dynsym(yol)
        if dyn is not None:
            simgeler = dyn
    return {
        **is_, "sha256": ozet, "hedef_tipi": hedef.target_type.value, "dizgi_yontemi": yontem,
        "strings": dizgiler or [],
        "symbols": [s.get("name", "") for s in (simgeler or {}).get("symbols", []) if s.get("name")],
        "dylibs": [k.get("path", "") for k in (dylibs or {}).get("libraries", []) if k.get("path")],
    }


def _topla_bir(is_: dict, kok: Path) -> str:
    hedef = kok / "girdiler" / (_guvenli_ad(is_["anahtar"]) + ".json.gz")
    if hedef.exists():
        return f"var {is_['anahtar']}"
    veri = girdi_cikar(is_)
    with gzip.open(hedef, "wt", encoding="utf-8") as f:
        json.dump(veri, f)
    satir = f"yazildi {is_['anahtar']} ({len(veri.get('strings', []))} dizgi)"
    if is_["kume"] == "gercek_pozitif" and not veri.get("strings"):
        ikinci = {**is_, "anahtar": is_["anahtar"] + SISTEM_EKI, "sistem_araci": True}
        satir += "\n" + _topla_bir(ikinci, kok)
    return satir


def kos_bir(girdi_yolu: Path) -> dict:
    import karadul
    from karadul.analyzers.binary_intelligence import BinaryIntelligence
    from karadul.config import Config

    with gzip.open(girdi_yolu, "rt", encoding="utf-8") as f:
        g = json.load(f)
    if g.get("hata"):
        return {k: g[k] for k in ("kume", "anahtar", "hata")}
    if g["hedef_tipi"] not in YERLI_TIPLER:  # ürün bu tipte MachOAnalyzer'ı çağırmaz
        return {"kume": g["kume"], "anahtar": g["anahtar"], "hata": "yerli_degil:" + g["hedef_tipi"]}
    t0 = time.monotonic()
    rapor = BinaryIntelligence(Config()).analyze(
        strings=g["strings"], symbols=g["symbols"], dylibs=g["dylibs"],
        target_name=Path(g["yol"]).name,
    ).to_dict()
    sure = round(time.monotonic() - t0, 2)
    mimari = rapor["architecture"]
    iddialar = {}
    for kat in ("subsystems", "algorithms", "security", "protocols"):
        iddialar[kat] = [
            {k: v for k, v in d.items() if k in ("name", "evidence", "confidence", "risk_level")}
            for d in mimari[kat]
        ]
    return {"kume": g["kume"], "anahtar": g["anahtar"], "hedef_tipi": g["hedef_tipi"],
            "karadul": karadul.__file__, "sure_sn": sure, "app_type": mimari["app_type"],
            "n_dizgi": len(g["strings"]), "n_simge": len(g["symbols"]),
            "n_kitaplik": len(g["dylibs"]), "iddialar": iddialar}


def kume_sayimi(sonuclar: list[dict]) -> dict:
    """{küme: {"n": ikili sayısı, "iddia": {"kat:ad": ikili sayısı}}}."""
    ozet: dict = defaultdict(lambda: {"n": 0, "iddia": Counter()})
    for s in sonuclar:
        if s.get("hata"):
            continue
        kumeler = [s["kume"]]
        if _beklenen(s["anahtar"]) and s["kume"] != "gercek_pozitif":
            kumeler.append("gercek_pozitif")
        for kume in kumeler:
            ozet[kume]["n"] += 1
            for kat, liste in s["iddialar"].items():
                for d in liste:
                    ozet[kume]["iddia"][f"{kat}:{d['name']}"] += 1
    return {k: {"n": v["n"], "iddia": dict(v["iddia"])} for k, v in ozet.items()}


def beklenen_denetimi(sonuclar: list[dict]) -> list[dict]:
    satirlar = []
    for s in sonuclar:
        if not _beklenen(s["anahtar"]) or s.get("hata"):
            continue
        beklenen, gerekce = _beklenen(s["anahtar"])
        var = {f"{kat}:{d['name']}": d for kat, liste in s["iddialar"].items() for d in liste}
        for iddia in beklenen:
            d = var.get(iddia)
            satirlar.append({"anahtar": s["anahtar"], "iddia": iddia, "var": d is not None,
                             "kanit": (d or {}).get("evidence", [])[:6],
                             "risk": (d or {}).get("risk_level"), "gerekce": gerekce})
    return satirlar


def cmd_topla(arg) -> int:
    kok = arg.kok.expanduser()
    (kok / "girdiler").mkdir(parents=True, exist_ok=True)
    isler = isleri_topla()
    (kok / "isler.json").write_text(json.dumps(isler, indent=1, ensure_ascii=False), encoding="utf-8")
    with cf.ProcessPoolExecutor(max_workers=arg.paralel) as ex:
        for satir in ex.map(_topla_bir, isler, [kok] * len(isler)):
            print(satir, flush=True)
    return 0


def cmd_kos(arg) -> int:
    import karadul

    if not str(Path(karadul.__file__).resolve()).startswith(str(DEPO.resolve())):
        raise SystemExit(f"karadul {karadul.__file__} yükleniyor, {DEPO} değil")
    kok = arg.kok.expanduser()
    cikti = kok / arg.etiket
    cikti.mkdir(parents=True, exist_ok=True)
    girdiler = sorted((kok / "girdiler").glob("*.json.gz"))
    sonuclar = []
    with cf.ProcessPoolExecutor(max_workers=arg.paralel) as ex:
        for s in ex.map(kos_bir, girdiler):
            sonuclar.append(s)
            print(f"{s['anahtar']}: {s.get('sure_sn', s.get('hata'))}", flush=True)
    sonuclar.sort(key=lambda s: (s["kume"], s["anahtar"]))
    (cikti / "ikililer.json").write_text(json.dumps(sonuclar, indent=1, ensure_ascii=False),
                                         encoding="utf-8")
    sayim = kume_sayimi(sonuclar)
    (cikti / "sayim.json").write_text(json.dumps(sayim, indent=1, ensure_ascii=False),
                                      encoding="utf-8")
    (cikti / "beklenen.json").write_text(
        json.dumps(beklenen_denetimi(sonuclar), indent=1, ensure_ascii=False), encoding="utf-8")
    for kume, v in sorted(sayim.items()):
        print(f"\n== {kume} (n={v['n']})")
        for iddia, n in sorted(v["iddia"].items(), key=lambda x: (-x[1], x[0]))[:25]:
            print(f"  {n:4d}  {iddia}")
    return 0


def cmd_karsilastir(arg) -> int:
    kok = arg.kok.expanduser()
    a = json.loads((kok / arg.once / "sayim.json").read_text(encoding="utf-8"))
    b = json.loads((kok / arg.sonra / "sayim.json").read_text(encoding="utf-8"))
    for kume in ("gelistirme", "mac_masum", "pe_masum"):
        na, nb = a.get(kume, {}).get("n"), b.get(kume, {}).get("n")
        print(f"\n### {kume} (önce n={na}, sonra n={nb})\n")
        print("| iddia | önce | sonra |\n|---|---:|---:|")
        ia, ib = a.get(kume, {}).get("iddia", {}), b.get(kume, {}).get("iddia", {})
        anahtarlar = sorted(set(ia) | set(ib), key=lambda k: (-ia.get(k, 0), k))
        odak_once = [k for k in ODAK if k in anahtarlar] + [k for k in anahtarlar if k not in ODAK]
        for k in odak_once:
            if arg.tam or k in ODAK or ia.get(k, 0) >= arg.esik or ib.get(k, 0) > 0:
                print(f"| {k} | {ia.get(k, 0)} | {ib.get(k, 0)} |")
        print(f"| *toplam iddia (ikili × iddia)* | {sum(ia.values())} | {sum(ib.values())} |")
    ba = {(r["anahtar"], r["iddia"]): r for r in
          json.loads((kok / arg.once / "beklenen.json").read_text(encoding="utf-8"))}
    bb = {(r["anahtar"], r["iddia"]): r for r in
          json.loads((kok / arg.sonra / "beklenen.json").read_text(encoding="utf-8"))}
    print("\n### gercek_pozitif (beklenen iddialar)\n")
    print("| ikili | iddia | önce | sonra | sonra kanıtı |\n|---|---|:-:|:-:|---|")
    for key in sorted(set(ba) | set(bb)):
        ra, rb = ba.get(key, {}), bb.get(key, {})
        kanit = ", ".join(f"`{e[:40]}`" for e in rb.get("kanit", [])[:3])
        print(f"| {key[0]} | {key[1]} | {'var' if ra.get('var') else 'yok'} | "
              f"{'var' if rb.get('var') else 'yok'} | {kanit} |")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    p = alt.add_parser("topla")
    p.add_argument("--kok", type=Path, required=True)
    p.add_argument("--paralel", type=int, default=6)
    p.set_defaults(f=cmd_topla)
    p = alt.add_parser("kos")
    p.add_argument("--kok", type=Path, required=True)
    p.add_argument("--etiket", required=True)
    p.add_argument("--paralel", type=int, default=6)
    p.set_defaults(f=cmd_kos)
    p = alt.add_parser("karsilastir")
    p.add_argument("--kok", type=Path, required=True)
    p.add_argument("--once", required=True)
    p.add_argument("--sonra", required=True)
    p.add_argument("--esik", type=int, default=3, help="önce sayımı bu kadar olan iddialar da yazılır")
    p.add_argument("--tam", action="store_true")
    p.set_defaults(f=cmd_karsilastir)
    arg = ap.parse_args(argv)
    return arg.f(arg)


if __name__ == "__main__":
    raise SystemExit(main())
