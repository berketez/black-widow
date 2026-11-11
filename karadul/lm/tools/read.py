"""KaradulLM'in ilk üç okuyan aracı (``arac_sozlesmeleri.md`` §2: O1, O2, O3).

- **O1 ``get_evidence``**: fonksiyonun kanıt paketi (``karadul.reconstruction.tarif.evidence``).
  Alan metinleri pilotun biçimidir (``context.evidence_fields``); K0 paketinin kanıt kısmıdır.
- **O2 ``get_decompiled``**: Ghidra'nın decompile metni, Karadul başlık yorumları silinmiş. Tek atış
  kipinde pilotun kırpması (9.000 bayt: baştan 7.000 + sondan 2.000); döngü kipinde çağrı başına
  4.500 bayt [seçim].
- **O3 ``get_xrefs``**: çağrı kenarları ``static/ghidra_call_graph.json``'dan (arayüzle aynı kaynak).
  ``callers`` = verilen adresi ÇAĞIRANLAR, ``callees`` = verilen adresin ÇAĞIRDIKLARI,
  ``address_refs`` = metninde adı geçip çağırmayanlar (metin vekili).

Her araç saklı dosyaları okur; hiçbir şey yazmaz. Sınırlama notları (``limits``) sözleşmenin sabit
metinleridir. Hatalar ``ToolError`` koduyla bildirilir.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Optional

from karadul.lm import (
    DECOMPILED_RESULT_MAX_BYTES, ENVELOPE_OVERHEAD_BYTES, EVIDENCE_RESULT_MAX_BYTES, LINE_NUMBER_MAX,
    LOOP_CODE_LIMIT_BYTES, WARNING_MAX_CHARS, WARNINGS_MAX_ITEMS, XREFS_MAX_ROWS, XREFS_RESULT_MAX_BYTES,
)
from karadul.lm.context import (
    EVIDENCE_DATA_KEYS, PILOT_LIMITS, EvidenceLimits, clip, escape_json, evidence_fields, evidence_truncation,
    strip_header,
)
from karadul.lm.tools import (
    ADDR_PATTERN, ERR_BAD_ARGUMENT, ERR_NO_DATA, ERR_UNKNOWN_ADDRESS, KIND_FACT, KIND_FACT_AND_INFERENCE,
    KIND_PROXY, ToolContext, ToolError, ToolOutput, ToolSpec, Workspace, format_tag,
)

_ADDR_SCHEMA = {"type": "string", "pattern": ADDR_PATTERN}

# --- Sınırlama notları (sözleşme §2 "Sınırlama notu" sütunu; sabit metin) ---------------------
LIMITS_EVIDENCE = (
    "Çağıran yalnız Ghidra çağrı kenarıdır; adresi alınarak çağrılan fonksiyonun çağıranı boş görünür.",
    "Geri çağrı kaydı decompile metninden düzenli ifadeyle bulunur.",
)
LIMITS_DECOMPILED = (
    "Ghidra uyarısı varsa metin eksik ya da yanlış olabilir.",
)
LIMITS_CALL_EDGES = (
    "Dolaylı çağrılar ve veri yuvasından çağrılanlar grafikte yoktur.",
    "Yalnız program fonksiyonları (FUN_) listelenir; kütüphane çağrıları get_evidence sonucunun apis alanındadır.",
    "Çağrı sayısı ürün çıktısında yoktur; her kenar bir kez listelenir.",
)
LIMITS_ADDRESS_REFS = (
    "address_refs metin vekilidir: adın başka bir gövdede çağrı sözdizimi dışında geçmesi.",
    "Ghidra veri başvurusu ürün çıktısında yoktur.",
)

SOURCE_EVIDENCE = "static/ghidra_xrefs.json; static/ghidra_functions.json; static/ghidra_output/decompiled"
SOURCE_CALL_GRAPH = "static/ghidra_call_graph.json"
SOURCE_ADDRESS_REFS = "static/ghidra_output/decompiled; static/ghidra_call_graph.json"

PART_HEAD, PART_TAIL, PART_RANGE = "bas", "son", "aralik"
DIR_CALLERS, DIR_CALLEES, DIR_ADDRESS_REFS = "callers", "callees", "address_refs"

# Ghidra'nın decompile metnine yazdığı uyarı yorumları.
_WARNING_RE = re.compile(r"/\*\s*WARNING:\s*(.*?)\s*\*/", re.S)


def _resolve(ws: Workspace, args: Mapping[str, Any]) -> str:
    a = ws.resolve(args.get("addr"))
    if a is None:
        raise ToolError(ERR_UNKNOWN_ADDRESS)
    return a


def _stripped_code(ws: Workspace, hexaddr: str) -> str:
    raw = ws.read_code(hexaddr)
    if raw is None:
        raise ToolError(ERR_NO_DATA)
    return strip_header(raw)


# ---------------------------------------------------------------------------------------------
# O1 get_evidence


def get_evidence(ws: Workspace, args: Mapping[str, Any], ctx: ToolContext) -> ToolOutput:
    a = _resolve(ws, args)
    pack = ws.packs.get(a)
    if pack is None:
        raise ToolError(ERR_NO_DATA)
    lookup = ws.name_lookup(ctx.blind_target)
    code = ws.read_code(a)
    lines = len(strip_header(code).splitlines()) if code is not None else 0
    limits: EvidenceLimits = PILOT_LIMITS
    while True:
        fields = evidence_fields(pack, lookup, a, limits)
        data: dict[str, Any] = {"addr": f"FUN_{a}"}
        data.update({EVIDENCE_DATA_KEYS[k]: v for k, v in fields.items()})
        data["lines"] = lines
        truncated = evidence_truncation(pack, limits)
        out = ToolOutput(data=data, kind=KIND_FACT_AND_INFERENCE, source=SOURCE_EVIDENCE,
                         limits=LIMITS_EVIDENCE, truncated=truncated)
        size = len(escape_json({"data": data, "limits": list(LIMITS_EVIDENCE), "truncated": truncated}).encode("utf-8"))
        # Zarfın kalan alanları (id, tool, ok, kind, source) için sabit pay bırakılır.
        if size + ENVELOPE_OVERHEAD_BYTES <= EVIDENCE_RESULT_MAX_BYTES or limits.at_floor():
            return out
        limits = limits.halved()


# ---------------------------------------------------------------------------------------------
# O2 get_decompiled


def ghidra_warnings(code: str) -> tuple[list[str], int]:
    """Metindeki ayrı Ghidra uyarıları (geçiş sırasıyla, boşlukları sadeleşmiş, tavanlı) ve ayrı
    uyarıların toplam sayısı."""
    seen: list[str] = []
    for m in _WARNING_RE.finditer(code):
        w = " ".join(m.group(1).split())[:WARNING_MAX_CHARS]
        if w and w not in seen:
            seen.append(w)
    return seen[:WARNINGS_MAX_ITEMS], len(seen)


def _take_lines(lines: list[str], cap: int, *, from_end: bool) -> list[str]:
    """Bayt tavanına sığan tam satırlar: baştan ya da sondan."""
    out: list[str] = []
    n = 0
    for s in (reversed(lines) if from_end else lines):
        b = len(s.encode("utf-8"))
        if n + b > cap:
            break
        out.append(s)
        n += b
    if from_end:
        out.reverse()
    return out


def get_decompiled(ws: Workspace, args: Mapping[str, Any], ctx: ToolContext) -> ToolOutput:
    a = _resolve(ws, args)
    code = _stripped_code(ws, a)
    lines = code.splitlines(keepends=True)
    total = len(lines)
    warnings, warning_total = ghidra_warnings(code)
    part = args.get("part")
    truncated: Optional[dict[str, Any]] = None
    if ctx.single_shot:
        # K0: paketi sunucu kurar; pilotun tek atış kırpması (pilot_protokolu.md §3.3).
        text, clipped, omitted = clip(code)
        first, last = (1, total) if total else (0, 0)
        if clipped:
            truncated = {"omitted": omitted, "total": total}
    else:
        if part == PART_RANGE:
            lf = args.get("line_from", 1)
            lt = min(args.get("line_to", total), total)
            if lf > lt:
                raise ToolError(ERR_BAD_ARGUMENT)
            wanted = lines[lf - 1:lt]
            shown = _take_lines(wanted, LOOP_CODE_LIMIT_BYTES, from_end=False)
            first = lf
        elif part == PART_TAIL:
            wanted = lines
            shown = _take_lines(wanted, LOOP_CODE_LIMIT_BYTES, from_end=True)
            first = total - len(shown) + 1
        else:
            wanted = lines
            shown = _take_lines(wanted, LOOP_CODE_LIMIT_BYTES, from_end=False)
            first = 1
        line_cut = False
        if wanted and not shown:
            # Tek satır tavandan uzun: satırın tavana kadarki baytları verilir ve bu bildirilir.
            pick = wanted[-1] if part == PART_TAIL else wanted[0]
            shown = [pick.encode("utf-8")[:LOOP_CODE_LIMIT_BYTES].decode("utf-8", errors="ignore")]
            first = total if part == PART_TAIL else first
            line_cut = True
        text = "".join(shown)
        last = first + len(shown) - 1 if shown else first - 1
        if len(shown) < len(wanted) or line_cut:
            truncated = {"omitted": len(wanted) - len(shown) + (1 if line_cut else 0), "total": len(wanted)}
            if line_cut:
                truncated["line_cut"] = True
    data = {"addr": f"FUN_{a}", "code": text, "total_lines": total, "line_from": first, "line_to": last,
            "ghidra_warnings": warnings, "ghidra_warning_total": warning_total}
    return ToolOutput(data=data, kind=KIND_FACT, source=f"static/ghidra_output/decompiled/FUN_{a}.c",
                      limits=LIMITS_DECOMPILED, truncated=truncated)


# ---------------------------------------------------------------------------------------------
# O3 get_xrefs


_XREFS_DEFAULTS = {"offset": 0, "limit": XREFS_MAX_ROWS}


def get_xrefs(ws: Workspace, args: Mapping[str, Any], ctx: ToolContext) -> ToolOutput:
    a = _resolve(ws, args)
    direction = args["direction"]
    if direction == DIR_CALLERS:
        addrs, kind, source, limits = ws.callers(a), KIND_FACT, SOURCE_CALL_GRAPH, LIMITS_CALL_EDGES
    elif direction == DIR_CALLEES:
        addrs, kind, source, limits = ws.callees(a), KIND_FACT, SOURCE_CALL_GRAPH, LIMITS_CALL_EDGES
    else:
        addrs, kind, source, limits = ws.address_refs_to(a), KIND_PROXY, SOURCE_ADDRESS_REFS, LIMITS_ADDRESS_REFS
    if addrs is None:
        # Çağrı grafiği yok, bozuk ya da başka koşuya ait: metin yöntemine sessizce düşülmez.
        raise ToolError(ERR_NO_DATA)
    offset = args.get("offset", _XREFS_DEFAULTS["offset"])
    limit = args.get("limit", _XREFS_DEFAULTS["limit"])
    page = addrs[offset:offset + limit]
    lookup = ws.name_lookup(ctx.blind_target)
    items = [{"addr": f"FUN_{x}", "name_tag": format_tag(lookup(x))} for x in page]
    data = {"addr": f"FUN_{a}", "direction": direction, "items": items, "total": len(addrs), "offset": offset}
    truncated = {"omitted": len(addrs) - len(page), "total": len(addrs)} if len(page) < len(addrs) else None
    return ToolOutput(data=data, kind=kind, source=source, limits=limits, truncated=truncated)


# ---------------------------------------------------------------------------------------------
# Kayıt (sözleşme §5: ilk dilimde yalnız bu üç araç)

_LINE_SCHEMA = {"type": "integer", "minimum": 1, "maximum": LINE_NUMBER_MAX}

READ_TOOLS = (
    ToolSpec(
        name="get_evidence", cls="O", signature="get_evidence(addr)",
        description=(
            'facts about one function. "apis" = library functions it calls, with counts. "callees" = program '
            'functions that it calls. "callers" = program functions that call it. "callbacks_given" = functions it '
            'passes as callbacks, written api(FUN_...). "callback_of" = where it is itself passed as a callback, '
            'written "api by FUN_...". "strings" = string literals it uses. "constants" = large constants. "lines" '
            '= line count of its decompiled code. An empty list is written "none"; a list cut at its limit ends '
            'with "... and N more".'),
        args_schema={"type": "object", "properties": {"addr": _ADDR_SCHEMA}, "required": ["addr"],
                     "additionalProperties": False},
        max_result_bytes=EVIDENCE_RESULT_MAX_BYTES, func=get_evidence),
    ToolSpec(
        name="get_decompiled", cls="O", signature="get_decompiled(addr, part, line_from, line_to)",
        description=(
            'the C code Ghidra reconstructed for one function. part "bas" = from the first line; "son" = up to the '
            'last line; "aralik" = lines line_from to line_to (1-based, inclusive). "code" is the text, '
            '"line_from"/"line_to" the lines actually returned, "total_lines" the length of the whole function. '
            '"ghidra_warnings" lists Ghidra\'s own warnings for this function; if there are any, the code may be '
            "incomplete or wrong."),
        args_schema={"type": "object",
                     "properties": {"addr": _ADDR_SCHEMA, "part": {"enum": [PART_HEAD, PART_TAIL, PART_RANGE]},
                                    "line_from": _LINE_SCHEMA, "line_to": _LINE_SCHEMA},
                     "required": ["addr", "part"], "additionalProperties": False},
        max_result_bytes=DECOMPILED_RESULT_MAX_BYTES, func=get_decompiled),
    ToolSpec(
        name="get_xrefs", cls="O", signature="get_xrefs(addr, direction, offset, limit)",
        description=(
            'call edges of one function, from Ghidra\'s call graph. direction "callers" = the functions that CALL '
            'addr (edges into addr); "callees" = the functions that addr CALLS (edges out of addr); "address_refs" '
            "= functions whose decompiled text mentions addr without calling it (for example passing it as a "
            f'callback; a text match, not a Ghidra reference). "items" is the list, at most {XREFS_MAX_ROWS} per '
            'call; "total" is the full count; use "offset" to read further.'),
        args_schema={"type": "object",
                     "properties": {"addr": _ADDR_SCHEMA,
                                    "direction": {"enum": [DIR_CALLERS, DIR_CALLEES, DIR_ADDRESS_REFS]},
                                    "offset": {"type": "integer", "minimum": 0, "maximum": LINE_NUMBER_MAX},
                                    "limit": {"type": "integer", "minimum": 1, "maximum": XREFS_MAX_ROWS}},
                     "required": ["addr", "direction"], "additionalProperties": False},
        max_result_bytes=XREFS_RESULT_MAX_BYTES, func=get_xrefs,
        defaults=_XREFS_DEFAULTS),
)
