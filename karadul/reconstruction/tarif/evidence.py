"""Fonksiyon başına kanıt paketi.

Tarif katmanının (davranıştan isim) ve ileride model katmanının ortak girdisi.
Kaynaklar Ghidra'nın statik çıktılarıdır:

- ``ghidra_functions.json``: dış (import/thunk) fonksiyonlar
- ``ghidra_xrefs.json``: çağrılanlar, çağıranlar, kullanılan string'ler
- ``ghidra_output/decompiled/FUN_<adres>.c``: decompile edilmiş gövde (geri çağrı
  kaydı, sabit argümanlar ve log mesajları için)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Çağrı ifadesi: ad ( argümanlar )
_CALL = re.compile(r"\b(_{0,3}[A-Za-z]\w*)\s*\(([^;{}]*)\)")
# Argüman olarak geçen (çağrılmayan) fonksiyon adresi
_FNREF = re.compile(r"\b(?:FUN|LAB)_([0-9a-f]+)\b(?!\s*\()")
_HEX = re.compile(r"\b0x[0-9a-fA-F]{5,}\b")
_GENERIC = re.compile(r"^(FUN|thunk_FUN|LAB|SUB|sub)_[0-9a-fA-F]+$")
_C_KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof"}


def normalize_api(name: str) -> str:
    """Mach-O import adları baştaki alt çizgiyle gelir (``_malloc``, ``___error``)."""
    return name.lstrip("_")


@dataclass
class EvidencePack:
    """Bir fonksiyonun davranışına dair kanıtlar."""

    address: str
    ghidra_name: str
    apis: list[str] = field(default_factory=list)
    api_counts: dict[str, int] = field(default_factory=dict)
    internal_callees: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    callback_registrations: list[dict] = field(default_factory=list)  # {"api", "target"}
    registered_as_callback: list[dict] = field(default_factory=list)  # {"api", "registrar"}
    large_constants: list[str] = field(default_factory=list)
    line_count: int = 0
    code_path: Path | None = None

    def read_code(self) -> str:
        if self.code_path is None or not self.code_path.exists():
            return ""
        return self.code_path.read_text(errors="replace")


def build_evidence(static_dir: Path) -> dict[str, EvidencePack]:
    """``static_dir`` (Karadul çalışma alanındaki ``static/``) içinden kanıt paketlerini kurar."""
    funcs = json.loads((static_dir / "ghidra_functions.json").read_text())["functions"]
    ext_names = {f["name"] for f in funcs if f.get("is_external") or f.get("is_thunk")}
    ext_addrs = {
        str(f.get("address", "")).lower().replace("0x", "")
        for f in funcs if f.get("is_external") or f.get("is_thunk")
    }
    xrefs = json.loads((static_dir / "ghidra_xrefs.json").read_text())["function_xrefs"]
    code_dir = static_dir / "ghidra_output" / "decompiled"

    packs: dict[str, EvidencePack] = {}
    for addr, x in xrefs.items():
        a = addr.lower()
        apis: list[str] = []
        internal: list[str] = []
        for c in x.get("functions_called", []):
            ca = str(c.get("address", "")).lower()
            if c["name"] in ext_names or ca in ext_addrs:
                apis.append(normalize_api(c["name"]))
            else:
                internal.append(ca)
        code_path = code_dir / f"FUN_{a}.c"
        code = code_path.read_text(errors="replace") if code_path.exists() else ""
        registrations = []
        for m in _CALL.finditer(code):
            callee, args = m.group(1), m.group(2)
            if _GENERIC.match(callee.lstrip("_")) or callee in _C_KEYWORDS:
                continue
            for target in _FNREF.findall(args):
                registrations.append({"api": normalize_api(callee), "target": target.lower()})
        packs[a] = EvidencePack(
            address=a,
            ghidra_name=x.get("name", ""),
            apis=sorted(set(apis)),
            api_counts={n: apis.count(n) for n in set(apis)},
            internal_callees=sorted(set(internal)),
            callers=sorted({str(c.get("address", "")).lower() for c in x.get("called_by", [])}),
            strings=[s.get("value") for s in x.get("strings_used", [])],
            callback_registrations=registrations,
            large_constants=sorted(set(_HEX.findall(code)))[:20],
            line_count=code.count("\n"),
            code_path=code_path if code_path.exists() else None,
        )
    # Ters yön: hangi fonksiyon hangi API'ye, kim tarafından geri çağrı olarak verildi?
    for a, p in packs.items():
        for reg in p.callback_registrations:
            target = packs.get(reg["target"])
            if target is not None:
                target.registered_as_callback.append({"api": reg["api"], "registrar": a})
    return packs
