"""Rapor bölümlerinin ortak HTML ve Markdown çizimi (``report_data`` üstünden).

Çalışma alanı raporu (``reporting/html_report.py``, ``markdown_report.py``) ve temiz
çıktının raporu (``core/report_generator.py``) güvenlik ve analiz bölümlerini buradan
çizer (ARAYUZ-08: iki HTML üreticisi aynı bölümleri, aynı durum ve aynı cümleyle verir).
Her bölüm durum etiketini, tek cümlelik özetini ve kaynak yapıtını yazar; bulgu yoksa
"temiz / taranamadı / veri yok + neden" der, bölümü gizlemez.
"""

from __future__ import annotations

import html
from typing import Any

from karadul.reporting.report_data import (
    SECTION_FINDINGS,
    SECTION_ORDER,
    SECTION_PARTIAL,
    SECTION_UNKNOWN,
    ReportData,
    Section,
    status_label,
)

# Bir tabloda gösterilen en çok satır (fazlası "N more" satırıyla belirtilir).
MAX_TABLE_ROWS = 100

SECTIONS_CSS = """
.sec-status { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 0.6em; vertical-align: middle; margin-left: 8px; border: 1px solid #30363d; color: #8b949e; }
.sec-status.st-findings { color: #d29922; border-color: #d2992260; }
.sec-status.st-clean { color: #3fb950; border-color: #3fb95060; }
.sec-status.st-partial, .sec-status.st-status_unknown, .sec-status.st-not_scanned, .sec-status.st-no_data { color: #f0883e; border-color: #f0883e60; }
.sec-summary { margin: 4px 0; }
.sec-source { font-size: 0.8em; color: #6e7681; }
.packed-warning { background:#3d1417; border:1px solid #f85149; border-radius:8px; padding:14px 16px; margin:12px 0; color:#ffd7d5; }
"""


def _esc(text: Any) -> str:
    return html.escape(str(text))


def _md_cell(text: Any, limit: int = 120) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")[:limit]


def _conf(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return str(value)


def packer_identity(sec: Section) -> tuple[str, Any]:
    top = sec.items[0] if sec.items else {}
    name = str(top.get("packer_name") or top.get("technique") or top.get("name") or "?")
    return name, top.get("version")


def function_count(result: Any) -> Any:
    stages = getattr(result, "stages", {}) or {}
    if "static" not in stages:
        return None
    st = stages["static"].stats or {}
    return st.get("functions_found", st.get("ghidra_function_count", st.get("functions")))


def severity(sec: Section) -> tuple[str, str, str] | None:
    """Bulgulu bölümün önemi: (Markdown simgesi, ad, renk); skoru olmayan bölümde None.

    Eşikler: >= 0.7 yüksek, >= 0.4 orta, altı bilgi. Bilinen zararlı yazılım (IOC) eşleşmesi
    her zaman yüksek.
    """
    if sec.status not in (SECTION_FINDINGS, SECTION_PARTIAL, SECTION_UNKNOWN) or not sec.items:
        return None
    if sec.key == "ioc":
        score = 1.0
    else:
        score = sec.extra.get("score")
        if not isinstance(score, float):
            return None
    if score >= 0.7:
        return ("[HIGH]", "HIGH", "#f85149")
    if score >= 0.4:
        return ("[MED]", "MEDIUM", "#d29922")
    return ("[INFO]", "INFO", "#8b949e")


def packer_warning_lines(result: Any, sec: Section, *, markdown: bool) -> tuple[str, list[str], str]:
    """Paketli ikili uyarısı (başlık, gövde, açma komutu): decompile yalnız açıcı stub'ı gösterir.

    Berke'nin sessiz başarısızlık yasağı: analist az fonksiyon görüp Karadul'u bozuk sanmasın.
    """
    name, version = packer_identity(sec)
    ver = f" {version}" if version else ""
    score = sec.extra.get("score")
    score_txt = f" (güven {score:.2f})" if isinstance(score, float) else ""
    title = f"Bu binary paketlenmiş — {name}{ver}{score_txt}."
    n = function_count(result)
    if n is not None:
        fn = f"**{n} fonksiyon**" if markdown else f"{n} fonksiyon"
        body = [f"Decompile YALNIZCA açıcı (unpacker) stub'ını gösterir. Bu koşuda görülen {fn} "
                "açıcı stub'a aittir — gerçek program kodu DEĞİL. Gerçek kod sıkıştırılmış/şifreli "
                "halde; çalışma anında bellekte açılıyor."]
    else:
        body = ["Decompile YALNIZCA açıcı (unpacker) stub'ını gösterir; gerçek program kodu "
                "sıkıştırılmış/şifreli halde. Statik analiz sınırlıdır."]
    cmd = "upx -d <dosya>" if "upx" in name.lower() else "ilgili açma aracı ile paketi açın (unpack)"
    return title, body, cmd


# ---------------------------------------------------------------------------
# tablolar (bölüm başına sütunlar ve satırlar; HTML ve Markdown aynı içerik)
# ---------------------------------------------------------------------------

def _rows(sec: Section) -> tuple[list[str], list[list[str]]]:
    k = sec.key
    if k == "packer":
        head = ["Packer", "Version", "Category", "Confidence", "Layers", "Evidence"]
        rows = []
        for p in sec.items:
            ev = p.get("evidence", "")
            ev = "; ".join(str(e) for e in ev) if isinstance(ev, (list, tuple)) else str(ev)
            rows.append([str(p.get("packer_name") or p.get("technique") or p.get("name") or "?"),
                         str(p.get("version") or "-"), str(p.get("category", "packer")),
                         _conf(p.get("confidence", 0.0)), str(p.get("layers_matched", "")), ev[:200]])
        return head, rows
    if k == "anti_debug":
        head = ["Technique", "Category", "Confidence", "Evidence"]
        rows = [[str(f.get("technique", "?")), str(f.get("category", "?")),
                 _conf(f.get("confidence", 0.0)), str(f.get("evidence", ""))[:200]]
                for f in sec.items]
        return head, rows
    if k == "yara":
        head = ["Rule", "Tags", "Severity", "Condition", "Evidence (offset: bytes)"]
        rows = []
        for h in sec.items:
            meta = h.get("meta") if isinstance(h.get("meta"), dict) else {}
            ev = []
            for s in (h.get("strings") or [])[:3]:
                if isinstance(s, dict):
                    data = s.get("data_text") if s.get("data_text") is not None else s.get("data_hex", "")
                    ev.append(f"{s.get('offset', '?')}: {data}")
            if h.get("legacy"):
                ev.append("evidence not recorded (legacy record)")
            rows.append([str(h.get("rule", "?")), ",".join(str(t) for t in h.get("tags") or []) or "-",
                         str(meta.get("severity", "-")), str(meta.get("condition", "-"))[:120],
                         "; ".join(ev)[:200]])
        return head, rows
    if k == "ioc":
        head = ["Symbol", "Matched", "Family", "Tier", "Library", "Address", "Purpose"]
        rows = []
        for m in sec.items:
            lib = m.get("library") or m.get("lib") or ", ".join(m.get("libraries") or []) or "-"
            rows.append([str(m.get("original", m.get("symbol", m.get("name", "?")))),
                         str(m.get("matched", "")), str(m.get("family") or "-"),
                         str(m.get("tier") or "-"), str(lib), str(m.get("address") or "-"),
                         str(m.get("purpose", ""))[:160]])
        return head, rows
    if k == "crypto":
        head = ["Algorithm", "Category", "Function", "Confidence", "Evidence"]
        rows = [[str(a.get("name", "?")), str(a.get("category", "?")), str(a.get("function") or "-"),
                 _conf(a.get("confidence", 0.0)),
                 "; ".join(str(e) for e in (a.get("evidence") or []))[:200]]
                for a in sec.items]
        return head, rows
    if k == "compositions":
        head = ["Composition", "Pattern", "Domain", "Score (uncalibrated)", "Stages: functions"]
        rows = []
        for c in sec.items:
            parts = []
            for s in c.get("stages") or []:
                if not isinstance(s, dict):
                    continue
                funcs = [str(f) for f in (s.get("functions") or [])]
                shown = ", ".join(funcs[:6]) + (f" +{len(funcs) - 6}" if len(funcs) > 6 else "")
                parts.append(f"{s.get('name', '?')}: {shown or 'no function recorded'}")
            rows.append([str(c.get("name", "?")), str(c.get("pattern") or "-"), str(c.get("domain") or "-"),
                         _conf(c.get("confidence", 0.0)), " -> ".join(parts)[:400]])
        return head, rows
    return [], []


def _limited(rows: list[list[str]]) -> tuple[list[list[str]], int]:
    return rows[:MAX_TABLE_ROWS], max(0, len(rows) - MAX_TABLE_ROWS)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def section_html(sec: Section, result: Any) -> str:
    parts = [
        f"<h2>{_esc(sec.title)}</h2>",
        '<div class="card">',
        f'<div class="sec-summary"><span class="sec-status st-{_esc(sec.status)}">'
        f"{_esc(status_label(sec.status))}</span> {_esc(sec.summary)}</div>",
    ]
    sev = severity(sec)
    if sev is not None:
        score = sec.extra.get("score")
        score_txt = f" | Score: {score:.2f}" if isinstance(score, float) else ""
        parts.append(f'<div class="sec-summary">Severity: <span style="color: {sev[2]};">'
                     f"{sev[1]}</span>{score_txt}</div>")
    parts.append(f'<div class="sec-source">Source: {_esc(sec.source)}</div>')
    if sec.key == "packer" and sec.status in (SECTION_FINDINGS, SECTION_PARTIAL, SECTION_UNKNOWN) and sec.items:
        title, body, cmd = packer_warning_lines(result, sec, markdown=False)
        parts.append('<div class="packed-warning"><strong style="color:#f85149;">⚠️ '
                     f"{_esc(title)}</strong><br>" + "<br>".join(_esc(x) for x in body)
                     + f"<br>Gerçek analiz için önce paketi açın: <code>{_esc(cmd)}</code>, "
                     "sonra açılmış binary'i yeniden analiz edin.</div>")
    if sec.has_items:
        head, rows = _rows(sec)
        if head:
            shown, more = _limited(rows)
            parts.append("<table><tr>" + "".join(f"<th>{_esc(h)}</th>" for h in head) + "</tr>")
            for r in shown:
                parts.append("<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in r) + "</tr>")
            parts.append("</table>")
            if more:
                parts.append(f'<div class="sec-source">{more} more row(s) in {_esc(sec.source)}</div>')
    parts.append("</div>")
    return "\n".join(parts)


def sections_html(data: ReportData, result: Any, keys: tuple[str, ...] = SECTION_ORDER) -> str:
    return "\n".join(section_html(data.sections[k], result) for k in keys if k in data.sections)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def section_markdown(sec: Section, result: Any) -> list[str]:
    sev = severity(sec)
    heading = f"## {sec.title}" + (f" {sev[0]}" if sev else "")
    lines = [heading, "", f"- **Status:** {status_label(sec.status)} — {sec.summary}"]
    if sev is not None:
        score = sec.extra.get("score")
        score_txt = f" (score: {score:.2f})" if isinstance(score, float) else ""
        lines.append(f"- **Severity:** {sev[1].lower()}{score_txt}")
    lines += [f"- **Source:** `{sec.source}`", ""]
    if sec.key == "packer" and sec.status in (SECTION_FINDINGS, SECTION_PARTIAL, SECTION_UNKNOWN) and sec.items:
        title, body, cmd = packer_warning_lines(result, sec, markdown=True)
        lines.append(f"> ⚠️ **{title}**")
        for x in body:
            lines += [">", f"> {x}"]
        lines += [">", f"> Gerçek analiz için önce paketi açın: `{cmd}`, sonra açılmış binary'i "
                  "yeniden analiz edin.", ""]
    if sec.has_items:
        head, rows = _rows(sec)
        if head:
            shown, more = _limited(rows)
            lines.append("| " + " | ".join(head) + " |")
            lines.append("|" + "|".join("---" for _ in head) + "|")
            for r in shown:
                lines.append("| " + " | ".join(_md_cell(c) for c in r) + " |")
            if more:
                lines.append("")
                lines.append(f"*{more} more row(s) in `{sec.source}`*")
            lines.append("")
    return lines


def sections_markdown(data: ReportData, result: Any, keys: tuple[str, ...] = SECTION_ORDER) -> list[str]:
    out: list[str] = []
    for k in keys:
        if k in data.sections:
            out.extend(section_markdown(data.sections[k], result))
    return out
