"""KaradulLM araç kaydı v2'nin yeni okuyan araçları (v2 tasarımı §3.5; P22d).

Sözleşme: ``docs/arge/2026-11-18_karadullm_v2/arac_sozlesmeleri_v2.md``. Ortak kurallar ``read.py`` ile
aynı (``arac_sozlesmeleri.md`` §1): yalnız saklı çalışma alanının dosyalarını OKUR; hiçbir şey yazmaz,
süreç başlatmaz, ağa çıkmaz, hedefi çalıştırmaz. Hiçbir araç dosya yolu, komut, URL ya da düzenli ifade
almaz: metin argümanları DÜZ alt dizgi olarak aranır (``str.find`` / ``in``), kullanıcı metninden
düzenli ifade kurulmaz (felaket geri izleme yok).

Sonuçta geçen program fonksiyonları ``items[].addr`` alanındadır: olay akışının ``dokunulan`` kuralı
(``events.touched_refs``) bu alanı okur; yeni bir adres alanı açılmadı, ``events.py``'ye yama gerekmedi.
İkiliden gelen metin (dizgi, kod satırı, tip adı) ``items`` öğelerinin başka anahtarlarında durur ve
örümceği oynatamaz.

- **O5 ``get_function_facts``**: boyut, blok, kenar, döngü, karmaşıklık, parametre sayısı, Ghidra uyarıları.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from karadul.lm.context import strip_header
from karadul.lm.tools import (
    ADDR_PATTERN, ERR_UNKNOWN_ADDRESS, FACTS_RESULT_MAX_BYTES, KIND_FACT_AND_PROXY, ToolContext, ToolError,
    ToolOutput, ToolSpec, Workspace, _hex_int, _read_json,
)
from karadul.lm.tools.read import ghidra_warnings

_ADDR_SCHEMA = {"type": "string", "pattern": ADDR_PATTERN}


def _resolve(ws: Workspace, value: Any) -> str:
    a = ws.resolve(value)
    if a is None:
        raise ToolError(ERR_UNKNOWN_ADDRESS)
    return a


def _keyed_records(ws: Workspace, cache_key: str, filename: str, section: str) -> Optional[dict[str, dict]]:
    """``static/<filename>``'ın ``section`` listesindeki kayıtlar, çalışma alanı adres yazımıyla
    anahtarlı (ilk geçen kazanır). Dosya yoksa ya da biçim bozuksa ``None`` (uydurma yok)."""
    def build() -> Optional[dict[str, dict]]:
        data = _read_json(ws.static_dir / filename)
        rows = data.get(section) if isinstance(data, dict) else None
        if not isinstance(rows, list):
            return None
        out: dict[str, dict] = {}
        for r in rows:
            if isinstance(r, dict):
                a = ws._canon(r.get("address"))
                if a is not None:
                    out.setdefault(a, r)
        return out
    return ws.cached(cache_key, build)


# ---------------------------------------------------------------------------------------------
# O5 get_function_facts

SOURCE_FACTS = "static/ghidra_cfg.json; static/ghidra_functions.json; static/ghidra_output/decompiled"
LIMITS_FACTS = (
    "Fonksiyon sınırı Ghidra'nındır.",
    "params_ghidra ghidra_functions.json'dandır; jenerik (FUN_) fonksiyonda çoğu kez 0'dır ve "
    "'parametresiz' demek değildir. params_signature decompile imzasından okunur (metin vekili).",
    "loops = döngü başlığı sayısı (Ghidra CFG'nin geri kenar hedefleri); iç içe döngü ayrı sayılır.",
    "Değeri null olan alanın kaynağı bu çalışma alanında yok: 'missing' hangi dosyanın olmadığını söyler.",
)


# Çok satırlı imzada yukarı doğru birleştirilecek en çok satır (Ghidra uzun imzayı 2-4 satıra böler).
_SIG_MAX_LINES = 8


def _int_or_none(v: Any) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def signature_params(code: str, name: Optional[str] = None) -> tuple[Optional[int], bool]:
    """Ghidra decompile imzasındaki parametre sayısı ve değişken argüman (``...``) var mı.

    İmza, gövdeyi açan ``{`` satırından önceki boş olmayan satırlardır (Ghidra'nın yazım biçimi:
    ``void FUN_x(int param_1,long param_2)`` + boş satır + ``{``; uzun imza birkaç satıra bölünür, alt
    satırlar girintili). Yukarı doğru, parantezler dengelenene kadar en çok ``_SIG_MAX_LINES`` satır
    birleştirilir. Parantez içi üst düzey virgüllerle bölünür (işlev göstericisi tipindeki iç parantezler
    sayılmaz). ``(void)`` ya da ``()`` → 0. İmza bulunamazsa ``(None, False)``: sayı uydurulmaz."""
    lines = code.splitlines()
    try:
        brace = next(i for i, s in enumerate(lines) if s.strip() == "{")
    except StopIteration:
        return None, False
    parts_up: list[str] = []
    for i in range(brace - 1, max(-1, brace - 1 - _SIG_MAX_LINES), -1):
        s = lines[i].strip()
        if not s:
            if parts_up:
                break
            continue
        parts_up.insert(0, s)
        joined = " ".join(parts_up)
        if "(" in joined and joined.count("(") == joined.count(")"):
            break
    sig = " ".join(parts_up)
    if not sig.endswith(")") or "(" not in sig or sig.startswith(("/", "*")):
        return None, False
    # Fonksiyon adından sonraki "(" ile son ")" arası. Dönüş tipinde de parantez olabilir
    # (``undefined1 (*) [16] FUN_x(…)``): ad biliniyorsa parantez adın hemen ardından aranır.
    at_name = sig.find(f"{name}(") if name else -1
    open_at = at_name + len(name) if at_name >= 0 else sig.find("(")
    inner = sig[open_at + 1:-1].strip()
    if inner in ("", "void"):
        return 0, False
    parts, depth, cur = [], 0, []
    for ch in inner:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth < 0:
                return None, False
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    if depth != 0 or any(not p for p in parts):
        return None, False
    variadic = parts[-1] == "..."
    return len(parts) - (1 if variadic else 0), variadic


def get_function_facts(ws: Workspace, args: Mapping[str, Any], ctx: ToolContext) -> ToolOutput:
    a = _resolve(ws, args.get("addr"))
    missing: list[str] = []
    cfg_all = _keyed_records(ws, "facts_cfg", "ghidra_cfg.json", "functions")
    fn_all = _keyed_records(ws, "facts_functions", "ghidra_functions.json", "functions")
    cfg = cfg_all.get(a) if cfg_all is not None else None
    fn = fn_all.get(a) if fn_all is not None else None
    if cfg_all is None:
        missing.append("static/ghidra_cfg.json")
    elif cfg is None:
        missing.append("ghidra_cfg.json: bu fonksiyonun kaydı")
    raw = ws.read_code(a)
    if raw is None:
        missing.append("static/ghidra_output/decompiled: bu fonksiyonun dosyası")
    blocks = cfg.get("blocks") if isinstance(cfg, dict) else None
    instructions = None
    if isinstance(blocks, list):
        counts = [_int_or_none(b.get("instruction_count")) if isinstance(b, dict) else None for b in blocks]
        instructions = sum(counts) if counts and all(c is not None for c in counts) else None
    loops = cfg.get("loop_headers") if isinstance(cfg, dict) else None
    back = cfg.get("back_edges") if isinstance(cfg, dict) else None
    code = strip_header(raw) if raw is not None else None
    n_sig, variadic = signature_params(code, ws.ui_name(a)) if code is not None else (None, False)
    warnings, warning_total = ghidra_warnings(code) if code is not None else ([], None)
    data = {
        "addr": f"FUN_{a}",
        "size_bytes": _int_or_none(fn.get("size")) if isinstance(fn, dict) else None,
        "blocks": _int_or_none(cfg.get("block_count")) if isinstance(cfg, dict) else None,
        "edges": _int_or_none(cfg.get("edge_count")) if isinstance(cfg, dict) else None,
        "cyclomatic": _int_or_none(cfg.get("cyclomatic_complexity")) if isinstance(cfg, dict) else None,
        "loops": len(loops) if isinstance(loops, list) else None,
        "back_edges": len(back) if isinstance(back, list) else None,
        "instructions": instructions,
        "params_ghidra": _int_or_none(fn.get("param_count")) if isinstance(fn, dict) else None,
        "params_signature": n_sig,
        "variadic": variadic if n_sig is not None else None,
        "lines": len(code.splitlines()) if code is not None else None,
        "ghidra_warnings": warnings,
        "ghidra_warning_total": warning_total,
        "missing": missing,
    }
    return ToolOutput(data=data, kind=KIND_FACT_AND_PROXY, source=SOURCE_FACTS, limits=LIMITS_FACTS)


# ---------------------------------------------------------------------------------------------
# Kayıt (v2 tasarımı §3.5; sıra full_registry'nin sırasıdır)

MORE_TOOLS = (
    ToolSpec(
        name="get_function_facts", cls="O", signature="get_function_facts(addr)",
        description=(
            'size and shape of one function from Ghidra: "size_bytes", "blocks" and "edges" of its control-flow '
            'graph, "cyclomatic" complexity, "loops" (loop headers), "instructions", "params_ghidra" (Ghidra\'s '
            'parameter count; often 0 for FUN_ functions even when it has parameters), "params_signature" (count '
            'read from the decompiled signature), "lines", "ghidra_warnings". A null value means the source is '
            'missing; "missing" names it.'),
        args_schema={"type": "object", "properties": {"addr": _ADDR_SCHEMA}, "required": ["addr"],
                     "additionalProperties": False},
        max_result_bytes=FACTS_RESULT_MAX_BYTES, func=get_function_facts),
)
