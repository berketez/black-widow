#!/usr/bin/env python3
"""C kaynak ağacından fonksiyon tanımlarını (ad -> gövde) çıkarır.

Kaynak: ``workspaces/2026-10-15_oturum_scratchpad/tarif/lib/csrc.py`` (2026-10-15).
Depoya davranışı değiştirilmeden taşındı (plan v2 G4); etiket paketi
(``etiket_paketi.py``) gövdeleri buradan alır.

Yorum ve string/char sabitleri aynı uzunlukta boşlukla maskelenir, böylece süslü
parantez eşleştirmesi bunlardan etkilenmez ama satır/ofset bilgisi korunur.
Derinlik 0'daki her `{` için geriye bakılır: hemen önünde `)` varsa eşleşen `(`
bulunur, ondan önceki tanımlayıcı fonksiyon adıdır.

Bilinen sınırlar (taşınan davranış):
- Makroyla üretilen fonksiyonlar (ör. ``RB_GENERATE``) bulunmaz.
- ``#if``/``#ifdef`` bloklarında yalnız ilk dal okunur (``#if 0`` ise ``#else``).
- Aynı adın birden çok tanımı (ör. platforma özgü dosyalar) hepsi listelenir;
  hangisinin derlendiğine karar vermek çağıranın işidir.
"""
from __future__ import annotations

import re
from pathlib import Path

_IDENT = re.compile(r"[A-Za-z_]\w*$")
_NOT_FUNC = {"if", "while", "for", "switch", "return", "sizeof", "__attribute__", "defined"}


def _mask(src: str) -> str:
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        elif c == "#" and (i == 0 or src[i - 1] == "\n"):
            # önişlemci satırı (devam satırlarıyla) yok sayılır
            j = i
            while True:
                e = src.find("\n", j)
                if e < 0:
                    e = n
                    break
                if e > 0 and src[e - 1] == "\\":
                    j = e + 1
                    continue
                break
            for k in range(i, e):
                out[k] = " "
            i = e
        else:
            i += 1
    return "".join(out)


def _drop_alt_branches(src: str) -> str:
    """#if/#ifdef bloklarında yalnız ilk dalı bırakır (#if 0 ise #else dalını).

    İki dalda da `{` açan kod (ör. `#ifdef X if (a) { #else if (b) { #endif`)
    süslü parantez sayımını bozuyordu. Satırlar aynı uzunlukta boşlukla
    değiştirilir, ofsetler korunur.
    """
    out, stack = [], []  # her giriş: o dalın atlanıp atlanmadığı
    for line in src.split("\n"):
        s = line.lstrip()
        if s.startswith("#"):
            d = s[1:].lstrip()
            if d.startswith(("ifdef", "ifndef")):
                stack.append(False)
            elif d.startswith("if"):
                stack.append(d[2:].strip().startswith("0"))
            elif d.startswith(("elif", "else")):
                if stack:
                    stack[-1] = not stack[-1] if d.startswith("else") and stack[-1] else True
            elif d.startswith("endif"):
                if stack:
                    stack.pop()
            out.append(line)
            continue
        out.append(" " * len(line) if any(stack) else line)
    return "\n".join(out)


def functions_in_file(path: Path) -> list[dict]:
    src = path.read_text(encoding="utf-8", errors="replace")
    m = _mask(_drop_alt_branches(src))
    res, depth, i, n = [], 0, 0, len(m)
    while i < n:
        c = m[i]
        if c == "{":
            if depth == 0:
                j = i - 1
                while j >= 0 and m[j].isspace():
                    j -= 1
                if j >= 0 and m[j] == ")":
                    d, k = 0, j
                    while k >= 0:
                        if m[k] == ")":
                            d += 1
                        elif m[k] == "(":
                            d -= 1
                            if d == 0:
                                break
                        k -= 1
                    t = k - 1
                    while t >= 0 and m[t].isspace():
                        t -= 1
                    mm = _IDENT.search(m[max(0, t - 200): t + 1])
                    name = mm.group(0) if mm else None
                    # gövdenin sonunu bul
                    d2, e = 0, i
                    while e < n:
                        if m[e] == "{":
                            d2 += 1
                        elif m[e] == "}":
                            d2 -= 1
                            if d2 == 0:
                                break
                        e += 1
                    if name and name not in _NOT_FUNC:
                        line_start = src.rfind("\n", 0, max(0, t - len(name))) + 1
                        res.append({
                            "name": name,
                            "file": str(path),
                            "line": src.count("\n", 0, i) + 1,
                            "text": src[line_start:e + 1],
                        })
                    i = e + 1
                    continue
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
        i += 1
    return res


def index_tree(root: Path) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for p in sorted([*root.rglob("*.c"), *root.rglob("*.h")]):
        for f in functions_in_file(p):
            idx.setdefault(f["name"], []).append(f)
    return idx
