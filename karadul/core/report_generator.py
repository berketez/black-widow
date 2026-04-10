"""Gelismis HTML Report Generator -- tek dosya, inline CSS/JS, dark theme.

Mevcut HTMLReporter'in uzerine kurulan zengin gorsel rapor:
- Pipeline istatistikleri (fonksiyon sayisi, rename orani, confidence)
- Before/after karsilastirma (ornek fonksiyonlar)
- Kullanilan stratejiler ve etkileri
- Dependency graph (inline SVG)
- Tek dosya HTML (CSS inline, JS inline -- dis bagimliligi yok)
"""

from __future__ import annotations

import html
import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from karadul import __version__
from karadul.core.result import PipelineResult
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)


def _esc(text: Any) -> str:
    """HTML escape."""
    return html.escape(str(text))


def _format_size(size: int) -> str:
    """Byte degerini okunabilir formata cevir."""
    if not isinstance(size, (int, float)) or size == 0:
        return "N/A"
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


# ---- Inline CSS ----
_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    background: #0d1117;
    color: #c9d1d9;
    line-height: 1.6;
    padding: 20px;
    max-width: 1100px;
    margin: 0 auto;
}
h1 { color: #f0f6fc; font-size: 1.8em; margin-bottom: 8px; }
h2 { color: #58a6ff; font-size: 1.3em; margin: 30px 0 12px 0; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
h3 { color: #c9d1d9; font-size: 1.1em; margin: 16px 0 8px 0; }
.header { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 24px; text-align: center; }
.header .subtitle { color: #8b949e; font-size: 0.95em; }
.header .version { color: #f85149; font-weight: bold; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; }
th { text-align: left; padding: 8px 12px; background: #21262d; color: #58a6ff; font-weight: 600; border: 1px solid #30363d; }
td { padding: 8px 12px; border: 1px solid #30363d; }
tr:hover { background: #1c2128; }
.pass { color: #3fb950; font-weight: bold; }
.fail { color: #f85149; font-weight: bold; }
.na { color: #8b949e; }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 12px 0; }
.stat-box { background: #21262d; border-radius: 6px; padding: 16px; text-align: center; }
.stat-box .value { font-size: 2em; font-weight: bold; color: #58a6ff; }
.stat-box .label { font-size: 0.85em; color: #8b949e; margin-top: 4px; }
.timeline { position: relative; padding-left: 32px; }
.timeline-item { position: relative; margin-bottom: 12px; padding: 10px 14px; background: #21262d; border-radius: 6px; border-left: 3px solid #30363d; }
.timeline-item.ok { border-left-color: #3fb950; }
.timeline-item.err { border-left-color: #f85149; }
.timeline-item .stage-name { font-weight: bold; color: #f0f6fc; }
.timeline-item .stage-meta { font-size: 0.85em; color: #8b949e; }
pre { background: #21262d; padding: 14px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; margin: 8px 0; white-space: pre-wrap; word-wrap: break-word; }
code { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; }
.footer { text-align: center; margin-top: 40px; padding: 16px; color: #484f58; font-size: 0.85em; border-top: 1px solid #21262d; }
.diff-container { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 12px 0; }
.diff-panel { background: #161b22; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; }
.diff-header { background: #21262d; padding: 8px 12px; font-weight: bold; font-size: 0.9em; border-bottom: 1px solid #30363d; }
.diff-header.before { color: #f85149; }
.diff-header.after { color: #3fb950; }
.diff-body { padding: 12px; font-size: 0.82em; line-height: 1.5; overflow-x: auto; }
.diff-body pre { background: transparent; padding: 0; margin: 0; }
.strategy-list { list-style: none; padding: 0; }
.strategy-list li { padding: 8px 12px; margin: 4px 0; background: #21262d; border-radius: 6px; border-left: 3px solid #58a6ff; }
.strategy-list li .name { font-weight: bold; color: #f0f6fc; }
.strategy-list li .impact { font-size: 0.85em; color: #3fb950; }
.strategy-list li .desc { font-size: 0.85em; color: #8b949e; }
.dep-graph { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; overflow-x: auto; }
.dep-graph svg { max-width: 100%; }
.confidence-bar { display: inline-block; width: 60px; height: 8px; background: #30363d; border-radius: 4px; overflow: hidden; vertical-align: middle; margin-left: 8px; }
.confidence-fill { height: 100%; border-radius: 4px; }
.naming-table td.original { color: #f85149; font-family: monospace; }
.naming-table td.recovered { color: #3fb950; font-family: monospace; }
.tab-container { margin: 12px 0; }
.tab-buttons { display: flex; gap: 0; border-bottom: 1px solid #30363d; }
.tab-btn { padding: 8px 16px; background: none; border: none; color: #8b949e; cursor: pointer; font-size: 0.9em; border-bottom: 2px solid transparent; }
.tab-btn.active { color: #58a6ff; border-bottom-color: #58a6ff; }
.tab-btn:hover { color: #c9d1d9; }
.tab-content { display: none; padding: 16px 0; }
.tab-content.active { display: block; }
@media (max-width: 768px) {
    .diff-container { grid-template-columns: 1fr; }
    .stat-grid { grid-template-columns: repeat(2, 1fr); }
}
"""

# ---- Inline JS (tab switching) ----
_JS = """
function switchTab(tabGroup, tabId) {
    var btns = document.querySelectorAll('[data-group="' + tabGroup + '"]');
    var contents = document.querySelectorAll('[data-tab-group="' + tabGroup + '"]');
    btns.forEach(function(b) { b.classList.remove('active'); });
    contents.forEach(function(c) { c.classList.remove('active'); });
    var btn = document.querySelector('[data-group="' + tabGroup + '"][data-tab="' + tabId + '"]');
    var content = document.querySelector('[data-tab-group="' + tabGroup + '"][data-tab-id="' + tabId + '"]');
    if (btn) btn.classList.add('active');
    if (content) content.classList.add('active');
}
"""


class ReportGenerator:
    """Gelismis tek-dosya HTML rapor uretici.

    Pipeline sonuclarini, workspace artifact'larini ve naming bilgilerini
    birlestirerek zengin gorsel bir rapor uretir.

    Args:
        result: Pipeline calisma sonucu.
        workspace: Calisma dizini yoneticisi.
    """

    def __init__(self, result: PipelineResult, workspace: Workspace) -> None:
        self._result = result
        self._workspace = workspace

    def generate_html(self) -> str:
        """Tam HTML rapor sayfasini string olarak uret."""
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        parts: list[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="en">')
        parts.append("<head>")
        parts.append('<meta charset="UTF-8">')
        parts.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        parts.append(f"<title>Black Widow Report -- {_esc(self._result.target_name)}</title>")
        parts.append(f"<style>{_CSS}</style>")
        parts.append("</head>")
        parts.append("<body>")

        # Header
        parts.append(self._header(now))

        # Target info
        parts.append(self._target_card())

        # Stats dashboard
        parts.append(self._stats_dashboard())

        # Pipeline timeline
        parts.append(self._pipeline_timeline())

        # Naming strategies
        parts.append(self._strategies_section())

        # Before/After comparison
        parts.append(self._before_after_section())

        # Naming map table (top 30)
        parts.append(self._naming_table())

        # Dependency graph SVG
        parts.append(self._dependency_graph_section())

        # Stage details
        parts.append(self._stage_details())

        # Footer
        parts.append(
            f'<div class="footer">'
            f"Generated by Black Widow v{_esc(__version__)} (Karadul) | {_esc(now)}"
            f"</div>"
        )

        parts.append(f"<script>{_JS}</script>")
        parts.append("</body>")
        parts.append("</html>")

        return "\n".join(parts)

    def generate_to_file(self, output_path: Path) -> Path:
        """HTML raporu dosyaya yaz."""
        content = self.generate_html()
        output_path.write_text(content, encoding="utf-8")
        return output_path

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------
    def _header(self, now: str) -> str:
        status_class = "pass" if self._result.success else "fail"
        status_text = "SUCCESS" if self._result.success else "PARTIAL"
        stages_ok = sum(1 for s in self._result.stages.values() if s.success)
        stages_total = len(self._result.stages)
        return (
            '<div class="header">'
            "<h1>BLACK WIDOW -- Analysis Report</h1>"
            f'<div class="subtitle">Target: <strong>{_esc(self._result.target_name)}</strong></div>'
            f'<div class="subtitle">'
            f'Status: <span class="{status_class}">{status_text}</span> | '
            f"Stages: {stages_ok}/{stages_total} | "
            f"Duration: {self._result.total_duration:.1f}s | "
            f'<span class="version">v{_esc(__version__)}</span>'
            f"</div>"
            "</div>"
        )

    # ------------------------------------------------------------------
    # Target card
    # ------------------------------------------------------------------
    def _target_card(self) -> str:
        rows = [
            ("Name", self._result.target_name),
            ("SHA-256", self._result.target_hash or "N/A"),
            ("Workspace", str(self._workspace.path)),
        ]

        if "identify" in self._result.stages:
            stats = self._result.stages["identify"].stats
            rows.insert(1, ("Type", stats.get("target_type", "N/A")))
            rows.insert(2, ("Language", stats.get("language", "N/A")))
            size = stats.get("file_size", 0)
            rows.insert(3, ("Size", _format_size(size) if isinstance(size, (int, float)) else "N/A"))

        table_rows = "".join(
            f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>"
            for k, v in rows
        )
        return (
            "<h2>Target Info</h2>"
            '<div class="card">'
            f"<table>{table_rows}</table>"
            "</div>"
        )

    # ------------------------------------------------------------------
    # Stats dashboard
    # ------------------------------------------------------------------
    def _stats_dashboard(self) -> str:
        stats: list[tuple[str, str]] = [
            ("Stages", f"{sum(1 for s in self._result.stages.values() if s.success)}/{len(self._result.stages)}"),
            ("Duration", f"{self._result.total_duration:.1f}s"),
        ]

        if "static" in self._result.stages:
            st = self._result.stages["static"].stats
            funcs = st.get("functions_found", st.get("ghidra_function_count", st.get("functions", "N/A")))
            strings = st.get("strings_found", st.get("ghidra_string_count", st.get("string_count", st.get("strings", "N/A"))))
            stats.append(("Functions", str(funcs)))
            stats.append(("Strings", str(strings)))

        if "reconstruct" in self._result.stages:
            st = self._result.stages["reconstruct"].stats
            if st.get("variables_renamed"):
                stats.append(("Vars Renamed", str(st["variables_renamed"])))
            if st.get("name_merger_total"):
                stats.append(("Names Merged", str(st["name_merger_total"])))
            if st.get("algorithms_detected"):
                stats.append(("Algorithms", str(st["algorithms_detected"])))
            if st.get("structs_recovered"):
                stats.append(("Structs", str(st["structs_recovered"])))
            if st.get("signature_matches"):
                stats.append(("Sig Matches", str(st["signature_matches"])))

        if "deobfuscate" in self._result.stages:
            st = self._result.stages["deobfuscate"].stats
            stats.append(("Deobf Steps", str(st.get("steps_completed", "N/A"))))

        boxes = "".join(
            f'<div class="stat-box"><div class="value">{_esc(v)}</div><div class="label">{_esc(k)}</div></div>'
            for k, v in stats
        )
        return (
            "<h2>Statistics</h2>"
            f'<div class="stat-grid">{boxes}</div>'
        )

    # ------------------------------------------------------------------
    # Pipeline timeline
    # ------------------------------------------------------------------
    def _pipeline_timeline(self) -> str:
        items: list[str] = []
        for i, (name, sr) in enumerate(self._result.stages.items(), 1):
            cls = "ok" if sr.success else "err"
            status = '<span class="pass">PASS</span>' if sr.success else '<span class="fail">FAIL</span>'

            details = ""
            if sr.stats:
                stat_parts = [f"{k}={v}" for k, v in list(sr.stats.items())[:4]]
                details = ", ".join(stat_parts)
            if sr.errors:
                details = _esc(sr.errors[0][:100])

            items.append(
                f'<div class="timeline-item {cls}">'
                f'<span class="stage-name">Stage {i} -- {_esc(name)}</span> {status}'
                f'<div class="stage-meta">{sr.duration_seconds:.1f}s | {_esc(details)}</div>'
                f"</div>"
            )

        return (
            "<h2>Pipeline Timeline</h2>"
            '<div class="timeline">'
            + "".join(items)
            + "</div>"
        )

    # ------------------------------------------------------------------
    # Strategies section
    # ------------------------------------------------------------------
    def _strategies_section(self) -> str:
        """Kullanilan naming/analiz stratejileri ve etkileri."""
        strategies: list[dict[str, str]] = []

        if "reconstruct" not in self._result.stages:
            return ""

        st = self._result.stages["reconstruct"].stats

        # Binary strategies
        if st.get("signature_matches"):
            strategies.append({
                "name": "Signature Database (FLIRT)",
                "impact": f"{st['signature_matches']} functions matched",
                "desc": "Known library functions identified via byte signatures.",
            })

        if st.get("byte_pattern_matched"):
            strategies.append({
                "name": "Byte Pattern Matching",
                "impact": f"{st['byte_pattern_matched']} FUN_xxx matched ({st.get('byte_pattern_match_rate', 'N/A')})",
                "desc": "Unknown functions matched via opcode byte patterns.",
            })

        if st.get("binary_names_extracted"):
            strategies.append({
                "name": "Binary Name Extraction",
                "impact": f"{st['binary_names_extracted']} names recovered",
                "desc": "Debug strings, build paths, RTTI used to recover original names.",
            })

        if st.get("algorithms_detected"):
            strategies.append({
                "name": "Algorithm Identification",
                "impact": f"{st['algorithms_detected']} algorithms detected",
                "desc": "Crypto, hash, compression algorithms identified via constants and structure.",
            })

        if st.get("structs_recovered") or st.get("enums_recovered"):
            structs = st.get("structs_recovered", 0)
            enums = st.get("enums_recovered", 0)
            strategies.append({
                "name": "Type Recovery",
                "impact": f"{structs} structs, {enums} enums",
                "desc": "Struct/enum types inferred from field access patterns and Ghidra metadata.",
            })

        if st.get("name_merger_total"):
            strategies.append({
                "name": "Bayesian Name Merger",
                "impact": f"{st['name_merger_total']} names merged ({st.get('name_merger_conflicts', 0)} conflicts resolved)",
                "desc": "Multiple naming sources combined via weighted Bayesian confidence.",
            })

        if st.get("comments_added"):
            strategies.append({
                "name": "Comment Generation",
                "impact": f"{st['comments_added']} comments ({st.get('vuln_warnings', 0)} security warnings)",
                "desc": "Function-level documentation and vulnerability warnings auto-generated.",
            })

        if st.get("inline_patterns_detected"):
            strategies.append({
                "name": "Inline Pattern Detection",
                "impact": f"{st['inline_patterns_detected']} patterns",
                "desc": "Compiler-inlined stdlib functions (abs, strlen, memcpy) recognized.",
            })

        # JS strategies
        if st.get("variables_renamed"):
            strategies.append({
                "name": "Context-Aware Renaming (NSA-grade)",
                "impact": f"{st['variables_renamed']} variables renamed",
                "desc": "300+ rules, 3-level data flow tracking, confidence scoring.",
            })

        if st.get("params_recovered"):
            strategies.append({
                "name": "Parameter Recovery",
                "impact": f"{st['params_recovered']} params ({st.get('params_recovery_rate', 'N/A')})",
                "desc": "Function parameters recovered via 5 strategies (this.X, call-site, destructuring).",
            })

        if st.get("naming_total"):
            strategies.append({
                "name": "NPM Naming Pipeline",
                "impact": f"{st['naming_total']} modules named (avg conf: {st.get('naming_avg_confidence', 'N/A')})",
                "desc": "npm fingerprint + source match + structural analysis for module identification.",
            })

        if st.get("source_match_names_recovered"):
            strategies.append({
                "name": "Source Matching",
                "impact": f"{st['source_match_names_recovered']} names recovered from original source",
                "desc": "Minified functions matched to original npm package source code.",
            })

        if st.get("llm_variables_named"):
            strategies.append({
                "name": "LLM-Assisted Naming",
                "impact": f"{st['llm_variables_named']} variables ({st.get('llm_model', 'N/A')})",
                "desc": "Low-confidence variables named by LLM analysis.",
            })

        if not strategies:
            return ""

        items_html = "".join(
            f'<li>'
            f'<span class="name">{_esc(s["name"])}</span> '
            f'<span class="impact">{_esc(s["impact"])}</span>'
            f'<div class="desc">{_esc(s["desc"])}</div>'
            f"</li>"
            for s in strategies
        )

        return (
            "<h2>Analysis Strategies</h2>"
            f'<ul class="strategy-list">{items_html}</ul>'
        )

    # ------------------------------------------------------------------
    # Before/After comparison
    # ------------------------------------------------------------------
    def _before_after_section(self) -> str:
        """Ornek fonksiyonlarin before/after karsilastirmasi."""
        samples = self._collect_before_after_samples()
        if not samples:
            return ""

        parts: list[str] = ["<h2>Before / After Comparison</h2>"]

        # Tab buttons
        tab_btns = []
        tab_contents = []
        for i, sample in enumerate(samples[:5]):  # En fazla 5 ornek
            tab_id = f"sample_{i}"
            active_cls = " active" if i == 0 else ""
            tab_btns.append(
                f'<button class="tab-btn{active_cls}" '
                f'data-group="diff" data-tab="{tab_id}" '
                f'onclick="switchTab(\'diff\', \'{tab_id}\')">'
                f'{_esc(sample["name"][:30])}'
                f"</button>"
            )

            before_code = _esc(sample["before"][:1500])
            after_code = _esc(sample["after"][:1500])

            tab_contents.append(
                f'<div class="tab-content{active_cls}" '
                f'data-tab-group="diff" data-tab-id="{tab_id}">'
                f'<div class="diff-container">'
                f'<div class="diff-panel">'
                f'<div class="diff-header before">Before (raw decompile/obfuscated)</div>'
                f'<div class="diff-body"><pre><code>{before_code}</code></pre></div>'
                f"</div>"
                f'<div class="diff-panel">'
                f'<div class="diff-header after">After (reconstructed)</div>'
                f'<div class="diff-body"><pre><code>{after_code}</code></pre></div>'
                f"</div>"
                f"</div>"
                f"</div>"
            )

        parts.append('<div class="tab-container">')
        parts.append('<div class="tab-buttons">' + "".join(tab_btns) + "</div>")
        parts.extend(tab_contents)
        parts.append("</div>")

        return "\n".join(parts)

    def _collect_before_after_samples(self) -> list[dict[str, str]]:
        """Before/after orneklerini workspace'ten topla."""
        samples: list[dict[str, str]] = []

        reconstructed = self._workspace.get_stage_dir("reconstructed")
        deob_dir = self._workspace.get_stage_dir("deobfuscated")
        static_dir = self._workspace.get_stage_dir("static")

        # Binary: decompiled vs commented/typed
        decompiled_dir = deob_dir / "decompiled"
        if not decompiled_dir.exists():
            decompiled_dir = static_dir / "ghidra_output" / "decompiled"

        after_dirs = [
            reconstructed / "commented",
            reconstructed / "typed",
            reconstructed / "merged",
        ]
        after_dir = None
        for d in after_dirs:
            if d.exists() and list(d.rglob("*.c")):
                after_dir = d
                break

        if decompiled_dir.exists() and after_dir:
            before_files = {f.name: f for f in decompiled_dir.rglob("*.c")}
            for after_file in sorted(after_dir.rglob("*.c")):
                if after_file.name in before_files:
                    before_content = before_files[after_file.name].read_text(
                        encoding="utf-8", errors="replace"
                    )
                    after_content = after_file.read_text(
                        encoding="utf-8", errors="replace"
                    )

                    # Sadece fark yaratan dosyalari goster
                    if before_content.strip() != after_content.strip():
                        # Ilk fonksiyonu bul
                        before_snippet = self._extract_first_function(before_content)
                        after_snippet = self._extract_first_function(after_content)

                        if before_snippet and after_snippet:
                            samples.append({
                                "name": after_file.name,
                                "before": before_snippet,
                                "after": after_snippet,
                            })

                    if len(samples) >= 5:
                        break

        # JS: deobfuscated vs reconstructed
        if not samples:
            js_deob = sorted(deob_dir.rglob("*.js"))
            js_suffixes = [".commented.js", ".typed.js", ".params.js", ".nsa_named.js"]
            for suffix in js_suffixes:
                js_after = list(reconstructed.glob(f"*{suffix}"))
                if js_after:
                    after_file = max(js_after, key=lambda f: f.stat().st_size)
                    if js_deob:
                        before_file = max(js_deob, key=lambda f: f.stat().st_size)
                        before_content = before_file.read_text(
                            encoding="utf-8", errors="replace"
                        )
                        after_content = after_file.read_text(
                            encoding="utf-8", errors="replace"
                        )

                        before_snippet = self._extract_first_function_js(before_content)
                        after_snippet = self._extract_first_function_js(after_content)

                        if before_snippet and after_snippet:
                            samples.append({
                                "name": after_file.name,
                                "before": before_snippet,
                                "after": after_snippet,
                            })
                    break

        return samples

    @staticmethod
    def _extract_first_function(content: str) -> str:
        """C kodundan ilk fonksiyonu cikar (max 40 satir)."""
        import re
        # Fonksiyon baslangicini bul: donen_tip fonksiyon_adi(...)
        pattern = re.compile(
            r"^(\w[\w\s*]+?\s+\w+\s*\([^)]*\)\s*\{)",
            re.MULTILINE,
        )
        match = pattern.search(content)
        if not match:
            # Basit fallback: ilk '{' den baslayarak 40 satir
            brace_idx = content.find("{")
            if brace_idx == -1:
                return content[:800]
            # '{' in oldugu satirin basina git
            line_start = content.rfind("\n", 0, brace_idx) + 1
            lines = content[line_start:].split("\n")[:40]
            return "\n".join(lines)

        start = match.start()
        # Eslesen '{' i bul ve kapanisina kadar al (max 40 satir)
        lines = content[start:].split("\n")[:40]
        return "\n".join(lines)

    @staticmethod
    def _extract_first_function_js(content: str) -> str:
        """JS kodundan ilk fonksiyonu cikar (max 30 satir)."""
        import re
        pattern = re.compile(
            r"^((?:export\s+)?(?:async\s+)?function\s+\w+\s*\([^)]*\)\s*\{)",
            re.MULTILINE,
        )
        match = pattern.search(content)
        if not match:
            # Arrow function veya method
            pattern2 = re.compile(
                r"^((?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_$]\w*)\s*=>)",
                re.MULTILINE,
            )
            match = pattern2.search(content)

        if not match:
            return content[:600]

        start = match.start()
        lines = content[start:].split("\n")[:30]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Naming map table
    # ------------------------------------------------------------------
    def _naming_table(self) -> str:
        """En onemli isim eslestirmelerini tablo olarak goster."""
        naming_data = self._collect_naming_data()
        if not naming_data:
            return ""

        # Confidence'a gore sirala, ilk 30'u goster
        sorted_names = sorted(
            naming_data, key=lambda x: x.get("confidence", 0), reverse=True,
        )[:30]

        rows = ""
        for entry in sorted_names:
            conf = entry.get("confidence", 0)
            if isinstance(conf, (int, float)):
                conf_pct = int(conf * 100)
                if conf >= 0.8:
                    conf_color = "#3fb950"
                elif conf >= 0.5:
                    conf_color = "#d29922"
                else:
                    conf_color = "#8b949e"
            else:
                conf_pct = 0
                conf_color = "#8b949e"

            rows += (
                f"<tr>"
                f'<td class="original">{_esc(entry.get("original", ""))}</td>'
                f'<td class="recovered">{_esc(entry.get("recovered", ""))}</td>'
                f"<td>{_esc(entry.get('source', ''))}</td>"
                f"<td>"
                f'<span class="confidence-bar">'
                f'<span class="confidence-fill" style="width:{conf_pct}%;background:{conf_color};"></span>'
                f"</span>"
                f' <span style="font-size:0.8em;color:{conf_color};">{conf_pct}%</span>'
                f"</td>"
                f"</tr>"
            )

        return (
            "<h2>Name Recovery (Top 30)</h2>"
            '<div class="card">'
            '<table class="naming-table">'
            "<tr><th>Original</th><th>Recovered</th><th>Source</th><th>Confidence</th></tr>"
            f"{rows}"
            "</table>"
            "</div>"
        )

    def _collect_naming_data(self) -> list[dict[str, Any]]:
        """Naming verilerini workspace'ten topla."""
        results: list[dict[str, Any]] = []

        # Binary names
        binary_names = self._workspace.load_json("reconstructed", "binary_names")
        if binary_names:
            for orig, info in binary_names.get("names", {}).items():
                if isinstance(info, dict):
                    results.append({
                        "original": orig,
                        "recovered": info.get("recovered", ""),
                        "source": info.get("source", "binary_extractor"),
                        "confidence": info.get("confidence", 0.0),
                    })

        # Signature matches
        sig_matches = self._workspace.load_json("reconstructed", "signature_matches")
        if sig_matches:
            for match in sig_matches.get("matches", []):
                results.append({
                    "original": match.get("original", ""),
                    "recovered": match.get("matched", ""),
                    "source": f"signature_db ({match.get('library', '')})",
                    "confidence": match.get("confidence", 0.0),
                })

        return results

    # ------------------------------------------------------------------
    # Dependency graph SVG
    # ------------------------------------------------------------------
    def _dependency_graph_section(self) -> str:
        """Basit dependency graph SVG uret."""
        graph_data = self._load_call_graph()
        if not graph_data:
            return ""

        svg = self._generate_graph_svg(graph_data)
        if not svg:
            return ""

        return (
            "<h2>Dependency Graph</h2>"
            '<div class="dep-graph">'
            f"{svg}"
            '<div style="font-size:0.8em;color:#8b949e;margin-top:8px;">'
            f'{len(graph_data.get("nodes", []))} nodes, '
            f'{len(graph_data.get("edges", []))} edges (top connections shown)'
            "</div>"
            "</div>"
        )

    def _load_call_graph(self) -> Optional[dict[str, Any]]:
        """Call graph verisini workspace'ten yukle."""
        static_dir = self._workspace.get_stage_dir("static")
        deob_dir = self._workspace.get_stage_dir("deobfuscated")

        cg_path = deob_dir / "ghidra_call_graph.json"
        if not cg_path.exists():
            cg_path = static_dir / "ghidra_call_graph.json"

        if not cg_path.exists():
            return None

        try:
            data = json.loads(cg_path.read_text(encoding="utf-8", errors="replace"))
            return data if isinstance(data, dict) else None
        except (json.JSONDecodeError, OSError):
            return None

    def _generate_graph_svg(self, graph_data: dict[str, Any]) -> str:
        """Basit force-directed layout SVG uret (en onemli 30 node)."""
        edges_raw = graph_data.get("calls", graph_data.get("edges", []))
        if not edges_raw:
            return ""

        # Edge'leri parse et
        edges: list[tuple[str, str]] = []
        for e in edges_raw:
            if isinstance(e, dict):
                caller = e.get("caller", e.get("from", ""))
                callee = e.get("callee", e.get("to", ""))
            elif isinstance(e, (list, tuple)) and len(e) >= 2:
                caller, callee = str(e[0]), str(e[1])
            else:
                continue
            if caller and callee:
                edges.append((caller, callee))

        if not edges:
            return ""

        # En cok baglantisi olan node'lari sec (max 30)
        node_degree: dict[str, int] = {}
        for caller, callee in edges:
            node_degree[caller] = node_degree.get(caller, 0) + 1
            node_degree[callee] = node_degree.get(callee, 0) + 1

        top_nodes = sorted(node_degree.keys(), key=lambda n: node_degree[n], reverse=True)[:30]
        top_set = set(top_nodes)

        # Sadece top node'lar arasindaki edge'leri filtrele
        filtered_edges = [(c, e) for c, e in edges if c in top_set and e in top_set]

        if not top_nodes:
            return ""

        # Basit dairesel layout
        width = 800
        height = 500
        cx, cy = width / 2, height / 2
        radius = min(cx, cy) - 60
        n = len(top_nodes)

        node_positions: dict[str, tuple[float, float]] = {}
        for i, node in enumerate(top_nodes):
            angle = 2 * math.pi * i / n
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            node_positions[node] = (x, y)

        # SVG olustur
        svg_parts: list[str] = []
        svg_parts.append(
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}">'
        )

        # Edges (cizgiler)
        for caller, callee in filtered_edges[:100]:  # Max 100 edge
            if caller in node_positions and callee in node_positions:
                x1, y1 = node_positions[caller]
                x2, y2 = node_positions[callee]
                svg_parts.append(
                    f'<line x1="{x1:.1f}" y1="{y1:.1f}" '
                    f'x2="{x2:.1f}" y2="{y2:.1f}" '
                    f'stroke="#30363d" stroke-width="1" opacity="0.6"/>'
                )

        # Nodes (daireler + etiketler)
        for node in top_nodes:
            x, y = node_positions[node]
            degree = node_degree.get(node, 1)
            r = max(4, min(12, 3 + degree))

            # Renk: yuksek degree = parlak mavi
            if degree >= 10:
                fill = "#58a6ff"
            elif degree >= 5:
                fill = "#388bfd"
            else:
                fill = "#1f6feb"

            short_name = node[:20] + "..." if len(node) > 20 else node
            svg_parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" '
                f'fill="{fill}" stroke="#0d1117" stroke-width="1">'
                f"<title>{_esc(node)} (degree: {degree})</title>"
                f"</circle>"
            )
            # Label (kucuk font, sadece buyuk node'lara)
            if degree >= 3 or n <= 15:
                svg_parts.append(
                    f'<text x="{x:.1f}" y="{y + r + 12:.1f}" '
                    f'text-anchor="middle" font-size="8" fill="#8b949e">'
                    f"{_esc(short_name)}"
                    f"</text>"
                )

        svg_parts.append("</svg>")
        return "\n".join(svg_parts)

    # ------------------------------------------------------------------
    # Stage details
    # ------------------------------------------------------------------
    def _stage_details(self) -> str:
        sections: list[str] = ["<h2>Stage Details</h2>"]
        for name, sr in self._result.stages.items():
            sections.append('<div class="card">')
            sections.append(f"<h3>{_esc(name)}</h3>")

            if sr.stats:
                rows = "".join(
                    f"<tr><td>{_esc(k)}</td><td>{_esc(str(v))}</td></tr>"
                    for k, v in sr.stats.items()
                )
                sections.append(
                    f"<table><tr><th>Stat</th><th>Value</th></tr>{rows}</table>"
                )

            if sr.errors:
                sections.append("<h3>Errors</h3>")
                for err in sr.errors:
                    sections.append(f"<pre><code>{_esc(err)}</code></pre>")

            sections.append("</div>")

        return "\n".join(sections)
