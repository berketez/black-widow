"""Doğrulama seti ikili sabitleme (plan v2 G5, 2. aşama).

YALITIM: hiçbir sembol/fonksiyon adı basılmaz ya da dosyaya yazılmaz. nm yalnız sayım için
çalışır (awk ile sayılır). İkililer çalıştırılmaz, analiz edilmez.
Kullanım: python3 -I sabitle.py <program> <kanit_json> <debian_index_json> <hedef_kok>
"""
import hashlib
import io
import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection

prog, kanit_json, idx_json, root = sys.argv[1:5]
kanit = json.load(open(kanit_json, encoding="utf-8"))[prog]
idx = json.load(open(idx_json, encoding="utf-8"))
P = Path(root) / prog
LOG = P / "gunluk.txt"
rec = {"program": prog, "tarih_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kanit": kanit}


def log(msg):
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(msg + "\n")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def curl(url, out, auth=False):
    cmd = ["/usr/bin/curl", "-sS", "-f", "-L", "--retry", "2", "-o", str(out)]
    if auth:
        cmd += ["-H", "Authorization: Bearer QQ=="]
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    return r.returncode, r.stderr.strip()


def run(cmd, timeout=300):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _skip_bad(member, path):
    """tarfile 'data' süzgeci; reddettiği üyeyi (ör. mutlak bağlantı) hata vermeden atlar."""
    try:
        return tarfile.data_filter(member, path)
    except tarfile.FilterError:
        return None


def safe_extract_tar(fileobj_or_path, dest, mode="r:*"):
    dest = Path(dest).resolve()
    if isinstance(fileobj_or_path, (str, Path)):
        tf = tarfile.open(fileobj_or_path, mode)
    else:
        tf = tarfile.open(fileobj=fileobj_or_path, mode=mode)
    with tf:
        for m in tf.getmembers():
            target = (dest / m.name).resolve()
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                raise RuntimeError(f"tehlikeli yol: {m.name}")
        tf.extractall(dest, filter=_skip_bad)


def ar_members(path):
    data = Path(path).read_bytes()
    assert data[:8] == b"!<arch>\n", "ar değil"
    off, out = 8, {}
    while off < len(data):
        hdr = data[off:off + 60]
        name = hdr[:16].decode().strip().rstrip("/")
        size = int(hdr[48:58].decode().strip())
        out[name] = data[off + 60: off + 60 + size]
        off += 60 + size + (size & 1)
    return out


def deb_extract(deb_path, dest):
    mem = ar_members(deb_path)
    data_name = next(n for n in mem if n.startswith("data.tar"))
    blob = mem[data_name]
    if data_name.endswith(".xz"):
        blob = lzma.decompress(blob)
        mode = "r:"
    elif data_name.endswith(".zst"):
        import zstandard
        blob = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(blob)).read()
        mode = "r:"
    else:
        mode = "r:*"
    safe_extract_tar(io.BytesIO(blob), dest, mode)
    # sembolik bağlantıları kayıt için ayrıca topla
    links = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode=mode) as tf:
        for m in tf.getmembers():
            if m.issym():
                links[m.name.lstrip("./")] = m.linkname
    return data_name, links


def resolve_in_tree(root_dir, rel, links, depth=0):
    """Ağaç içindeki sembolik bağı ağaç dışına çıkmadan çözer."""
    rel = rel.lstrip("/")
    if rel in links and depth < 10:
        target = links[rel]
        if target.startswith("/"):
            new = target.lstrip("/")
        else:
            new = os.path.normpath(os.path.join(os.path.dirname(rel), target))
        return resolve_in_tree(root_dir, new, links, depth + 1)
    return rel


def elf_info(path):
    info = {"build_id": None, "symtab": False, "func_local": 0, "func_global": 0, "func_weak": 0}
    with open(path, "rb") as fh:
        ef = ELFFile(fh)
        info["makine"] = ef["e_machine"]
        for sec in ef.iter_sections():
            if isinstance(sec, NoteSection):
                for note in sec.iter_notes():
                    if note["n_type"] == "NT_GNU_BUILD_ID":
                        info["build_id"] = note["n_desc"]
            if isinstance(sec, SymbolTableSection) and sec.name == ".symtab":
                info["symtab"] = True
                for sym in sec.iter_symbols():  # yalnız sayım; ad okunmaz
                    if sym["st_info"]["type"] != "STT_FUNC" or sym["st_shndx"] == "SHN_UNDEF":
                        continue
                    b = sym["st_info"]["bind"]
                    key = {"STB_LOCAL": "func_local", "STB_GLOBAL": "func_global", "STB_WEAK": "func_weak"}.get(b)
                    if key:
                        info[key] += 1
    return info


def nm_counts(path):
    nm = run(["/bin/sh", "-c", f"/usr/bin/nm -U '{path}' | /usr/bin/awk '{{n++}} $2==\"t\"{{t++}} $2==\"T\"{{T++}} "
                               f"END{{printf \"%d %d %d\", n, t+0, T+0}}'"])
    n, t, T = (int(x) for x in nm.stdout.split())
    return {"nm_U_satir": n, "t": t, "T": T}


# ---------------- Mac
mac = {}
md = P / "mac"
(md / "indirilen").mkdir(parents=True, exist_ok=True)
brew_name = kanit["brew"]
repo = brew_name.replace("@", "/").replace("+", "x")
url = f"https://ghcr.io/v2/homebrew/core/{repo}/blobs/sha256:{kanit['sise_sha256']}"
bottle = md / "indirilen" / f"{brew_name}--{kanit['brew_surum']}.arm64_tahoe.bottle{('.' + str(kanit['rebuild'])) if kanit['rebuild'] else ''}.tar.gz"
if not bottle.exists() or sha256(bottle) != kanit["sise_sha256"]:
    rc, err = curl(url, bottle, auth=True)
    mac["indirme_rc"] = rc
    if rc != 0:
        mac["hata"] = f"indirme başarısız: {err[:200]}"
if bottle.exists():
    mac["sise_boyut"] = bottle.stat().st_size
    mac["sise_sha256"] = sha256(bottle)
    mac["sise_sha256_eslesir"] = mac["sise_sha256"] == kanit["sise_sha256"]
    acilan = md / "acilan"
    if acilan.exists():
        shutil.rmtree(acilan)
    acilan.mkdir()
    links = {}
    with tarfile.open(bottle, "r:gz") as tf:
        for m in tf.getmembers():
            if m.issym():
                links[m.name] = m.linkname
    safe_extract_tar(bottle, acilan, "r:gz")
    # ölçülecek ikiliyi bul: <formül>/<sürüm>/(bin|sbin)/<ad>
    cands = []
    for m_name in sorted(set(links) | {str(p.relative_to(acilan)) for p in acilan.rglob("*") if p.is_file()}):
        parts = m_name.split("/")
        if len(parts) >= 4 and parts[2] in ("bin", "sbin") and parts[3] == kanit["mac_ikili"] and len(parts) == 4:
            cands.append(m_name)
    mac["aday_yollar"] = cands
    if cands:
        rel = cands[0]
        real = resolve_in_tree(acilan, rel, links)
        mac["ikili_yolu"] = rel + ("" if real == rel else f" -> {real}")
        fp = acilan / real
        if fp.is_file():
            mac["ikili_boyut"] = fp.stat().st_size
            mac["ikili_sha256"] = sha256(fp)
            mac["mimari"] = run(["/usr/bin/lipo", "-archs", str(fp)]).stdout.strip()
            u = run(["/usr/bin/dwarfdump", "--uuid", str(fp)]).stdout.split()
            mac["uuid"] = u[1] if len(u) > 1 else None
            mac.update(nm_counts(fp))
            libs = run(["/usr/bin/otool", "-L", str(fp)]).stdout.splitlines()[1:]
            mac["kutuphaneler"] = [l.strip().split(" (")[0] for l in libs]
            rp = run(["/bin/sh", "-c", f"/usr/bin/otool -l '{fp}' | /usr/bin/awk '/cmd LC_RPATH/{{f=1;next}} f&&$1==\"path\"{{print $2; f=0}}'"])
            mac["rpath"] = rp.stdout.split()
            ex = run(["/bin/sh", "-c", f"/usr/bin/xcrun dyld_info -exports '{fp}' | /usr/bin/awk 'NR>3' | /usr/bin/grep -c . || true"])
            mac["export_sayisi"] = int(ex.stdout.strip() or 0)
            bv = run(["/bin/sh", "-c", f"/usr/bin/otool -l '{fp}' | /usr/bin/awk '/cmd LC_BUILD_VERSION/{{f=1}} f&&$1==\"minos\"{{m=$2}} f&&$1==\"sdk\"{{s=$2;f=0}} END{{print m, s}}'"])
            mac["minos_sdk"] = bv.stdout.strip()
            own = [l for l in mac["kutuphaneler"]
                   if f"/opt/{brew_name}/" in l or f"/Cellar/{brew_name}/" in l or l.startswith(("@loader_path", "@executable_path"))
                   or (l.startswith("@rpath") and any(f"/{brew_name}/" in r or r.startswith("@loader_path") for r in mac["rpath"]))]
            mac["kendi_kutuphanesi"] = own
        else:
            mac["hata"] = "ikili çözülemedi"
rec["mac"] = mac

# ---------------- Debian
deb = {}
dd = P / "debian"
(dd / "indirilen").mkdir(parents=True, exist_ok=True)
r = idx[kanit["deb"]]
dbg = r["dbgsym"]
deb["paket"] = f"{kanit['deb']} {r['version']}"
deb["dbgsym"] = f"{dbg['package']} {dbg['version']}" if dbg else None
for kind, fname, want in (("paket", r["filename"], r["sha256"]), ("dbgsym", dbg["filename"] if dbg else None, dbg["sha256"] if dbg else None)):
    if not fname:
        deb[f"{kind}_hata"] = "yok"
        continue
    base = "https://deb.debian.org/debian/" if kind == "paket" else "https://deb.debian.org/debian-debug/"
    out = dd / "indirilen" / Path(fname).name
    if not out.exists() or sha256(out) != want:
        rc, err = curl(base + fname, out)
        if rc != 0:
            deb[f"{kind}_hata"] = f"indirme başarısız ({rc}): {err[:200]}"
            continue
    deb[f"{kind}_url"] = base + fname
    deb[f"{kind}_boyut"] = out.stat().st_size
    deb[f"{kind}_sha256"] = sha256(out)
    deb[f"{kind}_sha256_eslesir"] = deb[f"{kind}_sha256"] == want
    dest = dd / ("acilan_" + kind)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir()
    data_name, links = deb_extract(out, dest)
    deb[f"{kind}_veri_arsivi"] = data_name
    if kind == "paket":
        real = resolve_in_tree(dest, kanit["deb_ikili"], links)
        deb["ikili_yolu"] = "/" + kanit["deb_ikili"] + ("" if real == kanit["deb_ikili"] else f" -> /{real}")
        fp = dest / real
        if fp.is_file():
            deb["ikili_boyut"] = fp.stat().st_size
            deb["ikili_sha256"] = sha256(fp)
            ei = elf_info(fp)
            deb["build_id"] = ei["build_id"]
            deb["dagitilan_symtab_var"] = ei["symtab"]
            deb["makine"] = ei["makine"]
        else:
            deb["hata"] = "ikili pakette yok"
if deb.get("build_id") and dbg:
    bid = deb["build_id"]
    dbgf = dd / "acilan_dbgsym" / "usr/lib/debug/.build-id" / bid[:2] / (bid[2:] + ".debug")
    deb["debug_dosyasi_var"] = dbgf.is_file()
    if dbgf.is_file():
        di = elf_info(dbgf)
        deb["debug_build_id_eslesir"] = di["build_id"] == bid
        deb["debug_symtab"] = di["symtab"]
        deb["func_yerel"] = di["func_local"]
        deb["func_global"] = di["func_global"]
        deb["func_zayif"] = di["func_weak"]
        deb["debug_sha256"] = sha256(dbgf)
    deb["packages_build_ids_icinde"] = bid in dbg["build_ids"].split()
rec["debian"] = deb

# ---------------- K değerlendirmesi
k = []
if mac.get("hata") or not mac.get("sise_sha256_eslesir"):
    k.append("K1?")
if not mac.get("ikili_sha256"):
    k.append("K5? (Mac)")
if deb.get("hata") or not deb.get("ikili_sha256"):
    k.append("K5? (Debian)")
if not (deb.get("paket_sha256_eslesir") and deb.get("dbgsym_sha256_eslesir") and deb.get("debug_build_id_eslesir")):
    k.append("K2?")
if mac.get("kendi_kutuphanesi"):
    k.append("K4?")
k3 = None
if "nm_U_satir" in mac:
    if mac["nm_U_satir"] <= 1:
        k3 = "tamamen soyulmuş"
    elif mac["t"] == 0 and deb.get("func_yerel", 0) > 0:
        k3 = "yerel semboller soyulmuş"
rec["k3"] = k3
rec["k_supheleri"] = k
json.dump(rec, open(P / "sabitleme.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(json.dumps({"program": prog, "k3": k3, "k": k,
                  "mac": {x: mac.get(x) for x in ("sise_sha256_eslesir", "ikili_yolu", "nm_U_satir", "t", "T", "uuid", "kendi_kutuphanesi")},
                  "deb": {x: deb.get(x) for x in ("paket_sha256_eslesir", "dbgsym_sha256_eslesir", "ikili_yolu", "build_id",
                                                  "debug_build_id_eslesir", "packages_build_ids_icinde", "func_yerel", "func_global",
                                                  "dagitilan_symtab_var")}}, ensure_ascii=False))
