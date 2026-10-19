#!/usr/bin/env python3
"""G7 alıcı tip kümeleri: taban v2 koşusundan ham veriyi çıkarır (sonuç ölçütü hesaplamaz).

Kullanım:
    python3 -B cikar.py <program> <çıktı.json>

<program>: tmux ya da htop. Girdiler sabit yollardan okunur (aşağıdaki RUNS, CORPUS).

Çıkarılanlar (ön kayıt §2-§4):
  - evren: Ghidra'nın iç, thunk olmayan fonksiyonları; decompile C'den imza, 1. parametre adı,
    parametre değişti mi, p1 alan erişimi (nesne korumalı değişken için)
  - V1 kenarları: A, kendi değişmemiş 1. parametresini doğrudan çağrılan iç fonksiyon B'ye
    1. argüman olarak geçiriyor (decompile C'den; iç thunk hedefine çözülür)
  - V2 kenarları: A'nın değişmemiş k. parametresi B'nin j. argümanı
  - p-code tutarlılık denetimi: V1 kenarının çağrı yerinde 1. veri girdisi x0 mı
  - tablo koşuları: dyld_info -fixups rebase yuvalarının bitişik dizileri (V1+T değişkeni)
  - çapalar: Ç-G (Ghidra/export), Ç-O (GT adı ikilide aynen), Ç-K (tarif_olc.reliable_names)
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RUNS = REPO / "workspaces/olcum_mac/runs/taban-v2-62ad154"
CORPUS = REPO / "workspaces/olcum_mac/corpus"
X0 = 0x4000  # AArch64 x0 (Ghidra register uzayı ofseti)

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts/measurement"))
from tarif_olc import reliable_names  # noqa: E402  (Karadul çapası; yalnız okunur)

_C_KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "do", "else", "case", "goto"}
_CHARLIKE = {"char", "uchar", "byte", "undefined1", "undefined", "bool", "int1", "uint1",
             "signed char", "unsigned char", "sbyte"}
_IDENT = re.compile(r"[A-Za-z_]\w*")
_CALL = re.compile(r"(?<![\w.>])([A-Za-z_]\w*)\s*\(")
_INSN = re.compile(r"// --- DISASSEMBLY \((\d+) instructions\) ---")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- C metni

def mask_c(text: str) -> str:
    """Yorumları siler, dize ve karakter sabitlerinin içini 'S' ile değiştirir."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(c + "S" + c)
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def match_paren(text: str, k: int) -> int:
    """text[k] açılış ayracı; eşleşen kapanışın indeksini (-1: yok) döndürür."""
    depth = 0
    for m in range(k, len(text)):
        ch = text[m]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return m
    return -1


def split_top(s: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return parts


def strip_casts(e: str) -> str:
    """Baştaki C dönüşümlerini ve dış ayraçları soyar: '(long)param_1' → 'param_1'."""
    e = e.strip()
    while e.startswith("("):
        end = match_paren(e, 0)
        if end < 0:
            break
        rest = e[end + 1:].strip()
        if rest:
            if "(" in e[1:end]:  # iç içe ayraçlı dönüşüm (işlev işaretçisi): soyulmaz
                break
            e = rest
        else:
            e = e[1:end].strip()
    return e


def param_name(decl: str) -> str | None:
    decl = decl.strip()
    if decl in ("", "void", "..."):
        return None
    ids = _IDENT.findall(decl)
    return ids[-1] if ids else None


def is_changed(body: str, p: str) -> bool:
    """p gövdede atanıyor, artırılıyor/azaltılıyor ya da adresi alınıyor mu."""
    for m in re.finditer(r"\b" + re.escape(p) + r"\b\s*(?:[-+*/%&|^]|<<|>>)?=(?!=)", body):
        before = body[:m.start()].rstrip()
        if (not before or before[-1] in ";{}(,=:?"
                or re.search(r"\b(?:else|do)$", before)):
            return True
    if re.search(r"\b" + re.escape(p) + r"\b\s*(?:\+\+|--)", body):
        return True
    if re.search(r"(?:\+\+|--)\s*\b" + re.escape(p) + r"\b", body):
        return True
    for m in re.finditer(r"&\s*\b" + re.escape(p) + r"\b", body):
        before = body[:m.start()].rstrip()
        if not before or not (before[-1].isalnum() or before[-1] in "_)]&"):
            return True
    return False


def field_access(body: str, p: str, decl_type: str) -> bool:
    """p sabit ofsetle, karakter olmayan genişlikte okunuyor/yazılıyor mu (nesne kanıtı)."""
    pe = re.escape(p)
    for m in re.finditer(r"\*\s*\(\s*([^()]*?)\s*\*\s*\)\s*\(\s*" + pe
                         + r"\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)", body):
        base = m.group(1).replace("const ", "").strip()
        if base not in _CHARLIKE and int(m.group(2), 0) >= 1:
            return True
    pointee = decl_type.replace("const ", "").strip()
    if pointee.endswith("*"):
        pointee = pointee[:-1].strip()
        if pointee and pointee not in _CHARLIKE:
            for m in re.finditer(r"\b" + pe + r"\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]", body):
                if int(m.group(1), 0) >= 1:
                    return True
    return bool(re.search(r"\b" + pe + r"\s*->", body))


def parse_function(c_text: str, name: str) -> dict:
    """Bir decompile C dosyasını çözümler: imza, parametreler, gövdedeki çağrılar."""
    insn = _INSN.search(c_text)
    head = c_text.split("// --- DISASSEMBLY", 1)[0]
    masked = mask_c(head)
    m = re.search(r"\b" + re.escape(name) + r"\s*\(", masked)
    if not m:
        return {"durum": "imza_yok", "insn": int(insn.group(1)) if insn else None}
    k = m.end() - 1
    end = match_paren(masked, k)
    if end < 0:
        return {"durum": "imza_kapanmiyor", "insn": int(insn.group(1)) if insn else None}
    decls = split_top(masked[k + 1:end])
    params = []
    for d in decls:
        pn = param_name(d)
        if pn is None:
            continue
        params.append({"ad": pn, "tip": d[: d.rfind(pn)].strip()})
    body = masked[end + 1:]
    for p in params:
        p["degisti"] = is_changed(body, p["ad"])
    calls = []
    for cm in _CALL.finditer(body):
        ident = cm.group(1)
        if ident in _C_KEYWORDS:
            continue
        ko = cm.end() - 1
        ke = match_paren(body, ko)
        if ke < 0:
            continue
        inner = body[ko + 1:ke].strip()
        args = [strip_casts(a) for a in split_top(inner)] if inner else []
        calls.append({"hedef": ident, "arg": args})
    out = {"durum": "tamam", "insn": int(insn.group(1)) if insn else None,
           "params": params, "calls": calls}
    if params:
        out["p1_alan"] = field_access(body, params[0]["ad"], params[0]["tip"])
    return out


# --------------------------------------------------------------------------- girdiler

def load_inputs(prog: str) -> dict:
    run = RUNS / prog
    ws = next(run.glob("ws/workspaces/*/*"))
    go = ws / "static/ghidra_output"
    return {
        "run": run, "ws": ws, "go": go,
        "functions": go / "functions.json",
        "decompiled": go / "decompiled",
        "pcode": go / "pcode.jsonl",
        "score": run / "macho_score.json",
        "naming_map": ws / "reconstructed/src/naming_map.json",
        "binary": CORPUS / prog / "bin" / prog,
        "session": RUNS / "session.json",
    }


def strings_set(binary: Path) -> set[str]:
    """tarif_olc.reliable_names ile aynı çağrı: `strings -n 4`, satır kümesi."""
    res = subprocess.run(["strings", "-n", "4", str(binary)], capture_output=True, text=True)
    return set(res.stdout.split("\n"))


def table_runs(binary: Path) -> list[list[int]]:
    """dyld_info -fixups: rebase yuvaları; aynı bölümde 8 bayt aralıklı kesintisiz diziler."""
    res = subprocess.run(["/usr/bin/dyld_info", "-fixups", str(binary)], capture_output=True,
                         text=True, timeout=120)
    slots: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[3] == "rebase":
            seg, sect, addr, _, tgt = parts
            slots.setdefault((seg, sect), []).append((int(addr, 16), int(tgt, 16)))
    runs = []
    for key in sorted(slots):
        cur: list[tuple[int, int]] = []
        for a, t in sorted(slots[key]):
            if cur and a - cur[-1][0] != 8:
                runs.append([x[1] for x in cur])
                cur = []
            cur.append((a, t))
        if cur:
            runs.append([x[1] for x in cur])
    return runs


def main() -> int:
    prog, out_path = sys.argv[1], Path(sys.argv[2])
    inp = load_inputs(prog)
    fjson = json.loads(inp["functions"].read_text())["functions"]
    rows = json.loads(inp["score"].read_text())["rows"]
    pop = {int(r["addr"], 16): [g[1:] if g.startswith("_") else g for g in r["gt"]]
           for r in rows if r["sinif"] == "program"}
    other_rows = {int(r["addr"], 16): r["sinif"] for r in rows if r["sinif"] != "program"}

    by_name: dict[str, int] = {}
    internal: dict[int, dict] = {}
    thunk_target: dict[int, int] = {}
    for f in fjson:
        a = int(f["address"], 16)
        by_name.setdefault(f["name"], a)
        if f["is_external"]:
            continue
        if f["is_thunk"]:
            mt = re.fullmatch(r"thunk_FUN_([0-9a-f]+)", f["name"])
            if mt and f["source"] == "DEFAULT":
                thunk_target[a] = int(mt.group(1), 16)
            continue
        internal[a] = f

    def resolve(a: int) -> int | None:
        seen = set()
        while a in thunk_target and a not in seen:
            seen.add(a)
            a = thunk_target[a]
        return a if a in internal else None

    funcs: dict[int, dict] = {}
    durum: dict[str, int] = {}
    for a, f in sorted(internal.items()):
        cpath = inp["decompiled"] / (f["name"] + ".c")
        if not cpath.exists():
            info = {"durum": "c_yok", "insn": None}
        else:
            info = parse_function(cpath.read_text(errors="replace"), f["name"])
        durum[info["durum"]] = durum.get(info["durum"], 0) + 1
        info["ad"] = f["name"]
        info["pop"] = a in pop
        info["sinif"] = "program" if a in pop else other_rows.get(a, "gt_disi")
        funcs[a] = info

    v1, v2, unresolved_named = [], [], 0
    direct_internal_calls = 0
    for a, info in funcs.items():
        if info["durum"] != "tamam":
            continue
        pnames = {p["ad"]: i + 1 for i, p in enumerate(info["params"]) if not p["degisti"]}
        p1 = info["params"][0] if info["params"] else None
        for c in info["calls"]:
            tgt = by_name.get(c["hedef"])
            if tgt is None:
                if re.fullmatch(r"FUN_[0-9a-f]+", c["hedef"]):
                    unresolved_named += 1
                continue
            b = resolve(tgt)
            if b is None:
                continue
            direct_internal_calls += 1
            if b == a:
                continue
            if p1 and not p1["degisti"] and c["arg"] and c["arg"][0] == p1["ad"]:
                v1.append([a, b, tgt])
            for j, arg in enumerate(c["arg"], 1):
                if arg in pnames:
                    v2.append([a, pnames[arg], b, j])

    # p-code tutarlılık denetimi (V1): çağrı yerinde hedef ve 1. veri girdisi x0
    pcode_calls: dict[str, list[tuple[int, list | None]]] = {}
    with open(inp["pcode"], encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            lst = []
            for op in raw.get("ops", []):
                if op[0] == "CALL" and op[2] and op[2][0][0] == 3:
                    lst.append((op[2][0][1], op[2][1] if len(op[2]) > 1 else None))
            pcode_calls[raw["n"]] = lst
    agree = 0
    for a, b, tgt in v1:
        lst = pcode_calls.get(funcs[a]["ad"], [])
        if any(t == tgt and fi is not None and fi[0] == 1 and fi[1] == X0 for t, fi in lst):
            agree += 1

    # Tablo koşuları (V1+T)
    runs = []
    for r in table_runs(inp["binary"]):
        fs = []
        for t in r:
            b = resolve(t) if (t in internal or t in thunk_target) else None
            if b is not None and b not in fs:
                fs.append(b)
        if len(fs) >= 2:
            runs.append(fs)

    # Çapalar
    strs = strings_set(inp["binary"])
    capa_g = sorted(a for a, f in internal.items()
                    if a not in pop and not f["name"].startswith(("FUN_", "thunk_"))
                    and f["source"] != "DEFAULT")
    capa_o = {}
    for a, names in pop.items():
        hit = [n for n in names if n in strs]
        if hit:
            capa_o[a] = sorted(hit)[0]
    kesin = reliable_names(inp["run"], inp["binary"])
    capa_k = {int(k, 16): v for k, v in kesin.items() if int(k, 16) in internal}

    sess = json.loads(inp["session"].read_text())
    out = {
        "program": prog,
        "kunye": {
            "karadul_commit_kosu": sess["tree"]["commit"],
            "ghidra": sess["ghidra"]["version"] + " " + sess["ghidra"]["release"],
            "sha256": {k: sha256(inp[k]) for k in ("functions", "pcode", "score", "naming_map",
                                                   "binary")},
            "tarif_olc_sha256": sha256(REPO / "scripts/measurement/tarif_olc.py"),
            "strings": shutil.which("strings"),
            "dyld_info": "/usr/bin/dyld_info",
        },
        "c_durum": durum,
        "evren": len(funcs),
        "dogrudan_ic_cagri": direct_internal_calls,
        "cozulmeyen_FUN_cagri": unresolved_named,
        "pcode_v1_uyum": [agree, len(v1)],
        "funcs": {"%x" % a: {"ad": i["ad"], "pop": i["pop"], "sinif": i["sinif"],
                              "gt": pop.get(a), "insn": i.get("insn"), "durum": i["durum"],
                              "params": [[p["ad"], p["tip"], p["degisti"]]
                                         for p in i.get("params", [])],
                              "p1_alan": i.get("p1_alan")}
                  for a, i in funcs.items()},
        "v1": [["%x" % a, "%x" % b] for a, b, _ in v1],
        "v2": [["%x" % a, k, "%x" % b, j] for a, k, b, j in v2],
        "tablo_kosulari": [["%x" % x for x in r] for r in runs],
        "capa_g": ["%x" % a for a in capa_g],
        "capa_o": {"%x" % a: n for a, n in sorted(capa_o.items())},
        "capa_k": {"%x" % a: n for a, n in sorted(capa_k.items())},
        "karadul_adlari": {"%x" % int(k[4:], 16): v for k, v in
                           json.loads(inp["naming_map"].read_text()).get("global", {}).items()
                           if re.fullmatch(r"FUN_[0-9a-f]+", k)},
    }
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=0), encoding="utf-8")
    print(f"{prog}: evren {len(funcs)}, C durum {durum}, çözülmeyen FUN çağrısı {unresolved_named}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
