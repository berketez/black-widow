"""HTML rapor uretici -- tek dosya, inline CSS, dark theme.

Harici bagimliligi olmayan guzel HTML rapor uretir. Tum CSS inline'dir.
Browser'da dogrudan acilabilir.
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    max-width: 960px;
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
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 12px 0; }
.stat-box { background: #21262d; border-radius: 6px; padding: 16px; text-align: center; }
.stat-box .value { font-size: 2em; font-weight: bold; color: #58a6ff; }
.stat-box .label { font-size: 0.85em; color: #8b949e; margin-top: 4px; }
.timeline { position: relative; padding-left: 32px; }
.timeline-item { position: relative; margin-bottom: 12px; padding: 10px 14px; background: #21262d; border-radius: 6px; border-left: 3px solid #30363d; }
.timeline-item.ok { border-left-color: #3fb950; }
.timeline-item.err { border-left-color: #f85149; }
.timeline-item .stage-name { font-weight: bold; color: #f0f6fc; }
.timeline-item .stage-meta { font-size: 0.85em; color: #8b949e; }
pre { background: #21262d; padding: 14px; border-radius: 6px; overflow-x: auto; font-size: 0.9em; margin: 8px 0; }
code { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; }
.footer { text-align: center; margin-top: 40px; padding: 16px; color: #484f58; font-size: 0.85em; border-top: 1px solid #21262d; }
.arch-section { margin: 8px 0; }
.subsystem-card { background: #21262d; border-radius: 6px; padding: 12px 16px; margin: 8px 0; border-left: 3px solid #58a6ff; }
.subsystem-card.high { border-left-color: #3fb950; }
.subsystem-card.medium { border-left-color: #d29922; }
.subsystem-card.low { border-left-color: #8b949e; }
.subsystem-name { font-weight: bold; color: #f0f6fc; }
.subsystem-meta { font-size: 0.85em; color: #8b949e; }
.subsystem-evidence { font-size: 0.8em; color: #6e7681; margin-top: 4px; }
.confidence-bar { display: inline-block; width: 60px; height: 8px; background: #30363d; border-radius: 4px; overflow: hidden; vertical-align: middle; margin-left: 8px; }
.confidence-fill { height: 100%; border-radius: 4px; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.75em; margin: 2px; }
.tag-kernel { background: #f8514920; color: #f85149; border: 1px solid #f8514940; }
.tag-elevated { background: #d2992220; color: #d29922; border: 1px solid #d2992240; }
.tag-standard { background: #3fb95020; color: #3fb950; border: 1px solid #3fb95040; }
.tag-algo { background: #58a6ff20; color: #58a6ff; border: 1px solid #58a6ff40; }
.tag-proto { background: #bc8cff20; color: #bc8cff; border: 1px solid #bc8cff40; }
.arch-summary { white-space: pre-wrap; font-size: 0.9em; line-height: 1.5; }
.app-type-badge { display: inline-block; padding: 4px 16px; border-radius: 20px; font-weight: bold; font-size: 1em; background: #58a6ff30; color: #58a6ff; border: 1px solid #58a6ff60; margin: 8px 0; }
.bar-container { display: inline-block; width: 120px; height: 12px; background: #30363d; border-radius: 6px; overflow: hidden; vertical-align: middle; margin: 0 8px; }
.bar-fill { height: 100%; border-radius: 6px; }
.bar-fill.high { background: #3fb950; }
.bar-fill.medium { background: #d29922; }
.bar-fill.low { background: #f85149; }
.trace-tree { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.85em; white-space: pre; overflow-x: auto; background: #0d1117; padding: 12px; border-radius: 6px; border: 1px solid #21262d; line-height: 1.4; }
details.deep-section { margin: 8px 0; }
details.deep-section > summary { cursor: pointer; font-weight: bold; color: #58a6ff; padding: 6px 0; }
details.deep-section > summary:hover { color: #79c0ff; }
.comp-card { background: #21262d; border-radius: 6px; padding: 12px 16px; margin: 8px 0; border-left: 3px solid #bc8cff; }
.comp-name { font-weight: bold; color: #bc8cff; }
.comp-meta { font-size: 0.85em; color: #8b949e; }
.comp-stages { font-size: 0.85em; color: #c9d1d9; margin-top: 4px; }
.dispatch-stat { display: inline-block; margin-right: 16px; }
"""


class HTMLReporter:
    """Tek dosya HTML rapor uretici -- inline CSS, dark theme."""

    def generate(self, result: PipelineResult, workspace: Workspace) -> Path:
        """HTML rapor uret ve kaydet.

        Args:
            result: Pipeline calisma sonucu.
            workspace: Calisma dizini yoneticisi.

        Returns:
            Kaydedilen HTML dosyasinin yolu.
        """
        content = self._build_html(result, workspace)
        return workspace.save_artifact("reports", "report.html", content)

    def _build_html(self, result: PipelineResult, workspace: Workspace) -> str:
        """Tam HTML sayfasini olustur."""
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        parts: list[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append("<html lang=\"en\">")
        parts.append("<head>")
        parts.append("<meta charset=\"UTF-8\">")
        parts.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
        parts.append(f"<title>Black Widow Report -- {_esc(result.target_name)}</title>")
        parts.append(f"<style>{_CSS}</style>")
        parts.append("</head>")
        parts.append("<body>")

        # Header
        parts.append(self._header(result, now))

        # Target info card
        parts.append(self._target_card(result, workspace))

        # Pipeline timeline
        parts.append(self._pipeline_timeline(result))

        # Stats dashboard
        parts.append(self._stats_dashboard(result))

        # Architecture section (Binary Intelligence)
        parts.append(self._architecture_section(result, workspace))

        # v1.2: Deep Analysis section (dispatch, compositions, call traces)
        parts.append(self._deep_analysis_section(result, workspace))

        # Stage details
        parts.append(self._stage_details(result))

        # Artifacts
        parts.append(self._artifacts_table(result))

        # Footer
        parts.append(f"<div class=\"footer\">Generated by Black Widow v{_esc(__version__)} (Karadul) | {_esc(now)}</div>")

        parts.append("</body>")
        parts.append("</html>")

        return "\n".join(parts)

    def _header(self, result: PipelineResult, now: str) -> str:
        """Sayfa basligi."""
        status_class = "pass" if result.success else "fail"
        status_text = "SUCCESS" if result.success else "PARTIAL"
        return (
            "<div class=\"header\">"
            f"<h1>BLACK WIDOW -- Analysis Report</h1>"
            f"<div class=\"subtitle\">Target: <strong>{_esc(result.target_name)}</strong></div>"
            f"<div class=\"subtitle\">"
            f"Status: <span class=\"{status_class}\">{status_text}</span> | "
            f"Duration: {result.total_duration:.1f}s | "
            f"<span class=\"version\">v{_esc(__version__)}</span>"
            f"</div>"
            "</div>"
        )

    def _target_card(self, result: PipelineResult, workspace: Workspace) -> str:
        """Target bilgi karti."""
        rows = [
            ("Name", result.target_name),
            ("SHA-256", result.target_hash or "N/A"),
            ("Workspace", str(workspace.path)),
        ]

        if "identify" in result.stages:
            stats = result.stages["identify"].stats
            rows.insert(1, ("Type", stats.get("target_type", "N/A")))
            rows.insert(2, ("Language", stats.get("language", "N/A")))
            size = stats.get("file_size", 0)
            rows.insert(3, ("Size", _format_size(size) if isinstance(size, (int, float)) else "N/A"))
            rows.insert(4, ("Bundler", stats.get("bundler", "N/A")))

        table_rows = "".join(
            f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>"
            for k, v in rows
        )

        return (
            "<h2>Target Info</h2>"
            "<div class=\"card\">"
            f"<table>{table_rows}</table>"
            "</div>"
        )

    def _pipeline_timeline(self, result: PipelineResult) -> str:
        """Pipeline timeline gorsellestirilmesi."""
        items: list[str] = []

        for i, (name, sr) in enumerate(result.stages.items(), 1):
            cls = "ok" if sr.success else "err"
            status = "<span class=\"pass\">PASS</span>" if sr.success else "<span class=\"fail\">FAIL</span>"

            details = ""
            if sr.stats:
                stat_parts = []
                for k, v in list(sr.stats.items())[:3]:
                    stat_parts.append(f"{k}={v}")
                details = ", ".join(stat_parts)
            if sr.errors:
                details = _esc(sr.errors[0][:80])

            items.append(
                f"<div class=\"timeline-item {cls}\">"
                f"<span class=\"stage-name\">Stage {i} -- {_esc(name)}</span> {status}"
                f"<div class=\"stage-meta\">{sr.duration_seconds:.1f}s | {_esc(details)}</div>"
                f"</div>"
            )

        return (
            "<h2>Pipeline Timeline</h2>"
            "<div class=\"timeline\">"
            + "".join(items) +
            "</div>"
        )

    def _stats_dashboard(self, result: PipelineResult) -> str:
        """Istatistik dashboard kartlari."""
        stats: list[tuple[str, str]] = [
            ("Stages", f"{sum(1 for s in result.stages.values() if s.success)}/{len(result.stages)}"),
            ("Duration", f"{result.total_duration:.1f}s"),
        ]

        if "static" in result.stages:
            st = result.stages["static"].stats
            stats.append(("Functions", str(st.get("functions_found", st.get("ghidra_function_count", st.get("functions", "N/A"))))))
            stats.append(("Strings", str(st.get("strings_found", st.get("ghidra_string_count", st.get("string_count", st.get("strings", "N/A")))))))
            # Binary Intelligence stats
            if st.get("intel_subsystem_count") is not None:
                stats.append(("Subsystems", str(st.get("intel_subsystem_count", 0))))
                stats.append(("App Type", str(st.get("intel_app_type", "N/A"))))

        if "deobfuscate" in result.stages:
            st = result.stages["deobfuscate"].stats
            stats.append(("Deobf Steps", str(st.get("steps_completed", "N/A"))))

        if "reconstruct" in result.stages:
            st = result.stages["reconstruct"].stats
            stats.append(("Modules", str(st.get("modules_extracted", "N/A"))))
            stats.append(("Vars Renamed", str(st.get("variables_renamed", "N/A"))))
            stats.append(("Coverage", f"{st.get('coverage_percent', 'N/A')}%"))

        boxes = "".join(
            f"<div class=\"stat-box\"><div class=\"value\">{_esc(v)}</div><div class=\"label\">{_esc(k)}</div></div>"
            for k, v in stats
        )

        return (
            "<h2>Statistics</h2>"
            f"<div class=\"stat-grid\">{boxes}</div>"
        )

    def _architecture_section(self, result: PipelineResult, workspace: Workspace) -> str:
        """Binary Intelligence mimari analiz bolumu.

        intelligence_report.json dosyasini workspace'den okur ve HTML'e donusturur.
        Eger intelligence raporu yoksa bos string dondurur.
        """
        # intelligence_report.json'u bul
        intel_data = workspace.load_json("static", "intelligence_report")
        if not intel_data:
            return ""

        arch = intel_data.get("architecture", {})
        if not arch:
            return ""

        parts: list[str] = []
        parts.append("<h2>Architecture Analysis</h2>")

        # App type badge
        app_type = arch.get("app_type", "generic")
        app_name = arch.get("app_name", "Unknown")
        parts.append(
            f"<div class=\"card\">"
            f"<div style=\"text-align:center;\">"
            f"<div class=\"app-type-badge\">{_esc(app_type.upper())}</div>"
            f"<div style=\"color:#8b949e;font-size:0.9em;margin-top:4px;\">"
            f"Detected application type for <strong>{_esc(app_name)}</strong></div>"
            f"</div>"
            f"</div>"
        )

        # Subsystems
        subsystems = arch.get("subsystems", [])
        if subsystems:
            parts.append("<h3>Subsystems</h3>")
            parts.append("<div class=\"arch-section\">")
            for sub in subsystems:
                conf = sub.get("confidence", 0)
                if conf >= 0.5:
                    level_cls = "high"
                elif conf >= 0.2:
                    level_cls = "medium"
                else:
                    level_cls = "low"

                conf_pct = int(conf * 100)
                if conf >= 0.5:
                    conf_color = "#3fb950"
                elif conf >= 0.2:
                    conf_color = "#d29922"
                else:
                    conf_color = "#8b949e"

                evidence = sub.get("evidence", [])
                evidence_str = ", ".join(_esc(e[:60]) for e in evidence[:5])

                parts.append(
                    f"<div class=\"subsystem-card {level_cls}\">"
                    f"<span class=\"subsystem-name\">{_esc(sub.get('name', ''))}</span>"
                    f" <span class=\"tag tag-standard\">{_esc(sub.get('category', ''))}</span>"
                    f"<span class=\"confidence-bar\">"
                    f"<span class=\"confidence-fill\" style=\"width:{conf_pct}%;background:{conf_color};\"></span>"
                    f"</span>"
                    f" <span style=\"font-size:0.8em;color:{conf_color};\">{conf_pct}%</span>"
                    f"<div class=\"subsystem-meta\">{_esc(sub.get('description', ''))}</div>"
                    f"<div class=\"subsystem-evidence\">Evidence: {evidence_str}</div>"
                    f"</div>"
                )
            parts.append("</div>")

        # Algorithms
        algorithms = arch.get("algorithms", [])
        if algorithms:
            parts.append("<h3>Algorithms &amp; Cryptography</h3>")
            parts.append("<div class=\"card\">")

            # Kategoriye gore grupla
            algo_by_cat: dict[str, list[dict]] = {}
            for algo in algorithms:
                cat = algo.get("category", "other")
                if cat not in algo_by_cat:
                    algo_by_cat[cat] = []
                algo_by_cat[cat].append(algo)

            for cat, algos in algo_by_cat.items():
                parts.append(f"<h3 style=\"font-size:0.95em;margin:8px 0 4px;\">{_esc(cat.upper())}</h3>")
                tags = " ".join(
                    f"<span class=\"tag tag-algo\">{_esc(a.get('name', ''))}</span>"
                    for a in algos
                )
                parts.append(f"<div>{tags}</div>")

            parts.append("</div>")

        # Security Mechanisms
        security = arch.get("security", [])
        if security:
            parts.append("<h3>Security Mechanisms</h3>")
            parts.append("<div class=\"card\">")

            # Risk level'a gore grupla
            for level in ["kernel", "elevated", "standard"]:
                level_items = [s for s in security if s.get("risk_level") == level]
                if not level_items:
                    continue
                parts.append(
                    f"<h3 style=\"font-size:0.95em;margin:8px 0 4px;\">"
                    f"{_esc(level.upper())} ({len(level_items)})</h3>"
                )
                for item in level_items:
                    tag_cls = f"tag-{level}"
                    parts.append(
                        f"<div style=\"margin:4px 0;\">"
                        f"<span class=\"tag {tag_cls}\">{_esc(item.get('name', ''))}</span>"
                        f" <span style=\"font-size:0.85em;color:#8b949e;\">"
                        f"{_esc(item.get('description', ''))}</span>"
                        f"</div>"
                    )

            parts.append("</div>")

        # Protocols
        protocols = arch.get("protocols", [])
        if protocols:
            parts.append("<h3>Communication Protocols</h3>")
            parts.append("<div class=\"card\">")
            tags = " ".join(
                f"<span class=\"tag tag-proto\" title=\"{_esc(p.get('usage', ''))}\">"
                f"{_esc(p.get('name', ''))}</span>"
                for p in protocols
            )
            parts.append(f"<div>{tags}</div>")
            parts.append("</div>")

        # Architecture Summary
        summary = arch.get("architecture_summary", "")
        if summary:
            parts.append("<h3>Architecture Summary</h3>")
            parts.append(
                f"<div class=\"card\">"
                f"<pre class=\"arch-summary\"><code>{_esc(summary)}</code></pre>"
                f"</div>"
            )

        return "\n".join(parts)

    def _stage_details(self, result: PipelineResult) -> str:
        """Her stage icin detayli bilgi."""
        sections: list[str] = []
        sections.append("<h2>Stage Details</h2>")

        for name, sr in result.stages.items():
            sections.append(f"<div class=\"card\">")
            sections.append(f"<h3>{_esc(name)}</h3>")

            if sr.stats:
                rows = "".join(
                    f"<tr><td>{_esc(k)}</td><td>{_esc(str(v))}</td></tr>"
                    for k, v in sr.stats.items()
                )
                sections.append(f"<table><tr><th>Stat</th><th>Value</th></tr>{rows}</table>")

            if sr.errors:
                sections.append("<h3>Errors</h3>")
                for err in sr.errors:
                    sections.append(f"<pre><code>{_esc(err)}</code></pre>")

            sections.append("</div>")

        return "\n".join(sections)

    def _deep_analysis_section(self, result: PipelineResult, workspace: Workspace) -> str:
        """v1.2 Deep Analysis section: dispatch stats, compositions, call traces.

        Reads data from the reconstruct stage stats and workspace JSON artifacts.
        """
        if "reconstruct" not in result.stages:
            return ""

        stats = result.stages["reconstruct"].stats

        # Check if we have any deep analysis data
        has_dispatch = "dispatch_sites" in stats
        has_compositions = "compositions" in stats
        has_traces = "trace_targets" in stats

        if not (has_dispatch or has_compositions or has_traces):
            return ""

        parts: list[str] = []
        parts.append("<h2>Deep Algorithm Analysis</h2>")

        # -- 1. Dispatch Resolution Stats --
        if has_dispatch:
            total_sites = stats.get("dispatch_sites", 0)
            resolved = stats.get("dispatch_resolved", 0)
            rate_str = stats.get("dispatch_resolution_rate", "0%")
            # Parse rate percentage for bar width
            try:
                rate_pct = float(rate_str.strip("%"))
            except (ValueError, AttributeError):
                rate_pct = (resolved / total_sites * 100) if total_sites else 0

            if rate_pct >= 60:
                bar_cls = "high"
            elif rate_pct >= 30:
                bar_cls = "medium"
            else:
                bar_cls = "low"

            parts.append("<div class=\"card\">")
            parts.append("<h3>Virtual Dispatch Resolution</h3>")
            parts.append(
                f"<div class=\"dispatch-stat\">"
                f"<strong>Sites:</strong> {_esc(str(total_sites))}</div>"
                f"<div class=\"dispatch-stat\">"
                f"<strong>Resolved:</strong> {_esc(str(resolved))}</div>"
                f"<div class=\"dispatch-stat\">"
                f"<strong>Rate:</strong> "
                f"<span class=\"bar-container\">"
                f"<span class=\"bar-fill {bar_cls}\" style=\"width:{rate_pct:.0f}%;\"></span>"
                f"</span>"
                f" {rate_pct:.1f}%"
                f"</div>"
            )
            parts.append("</div>")

        # -- 2. Algorithm Compositions --
        if has_compositions:
            comp_data = workspace.load_json("reconstructed", "algorithm_compositions")
            comp_list = []
            if comp_data:
                comp_list = comp_data.get("compositions", [])

            parts.append("<div class=\"card\">")
            parts.append(
                f"<h3>Algorithm Compositions ({_esc(str(stats.get('compositions', 0)))})</h3>"
            )

            if comp_list:
                for comp in comp_list:
                    comp_name = comp.get("name", "Unknown")
                    comp_type = comp.get("type", "pipeline")
                    confidence = comp.get("confidence", 0)
                    stages = comp.get("stages", [])

                    stage_names = [
                        s.get("label", s.get("name", "?")) for s in stages
                    ]
                    stage_str = " -> ".join(stage_names[:8])
                    if len(stage_names) > 8:
                        stage_str += f" ... +{len(stage_names) - 8}"

                    parts.append(
                        f"<details class=\"deep-section\">"
                        f"<summary>"
                        f"<span class=\"comp-name\">{_esc(comp_name)}</span>"
                        f" <span class=\"tag tag-proto\">{_esc(comp_type)}</span>"
                        f" <span style=\"font-size:0.8em;color:#8b949e;\">"
                        f"confidence: {confidence:.0%}</span>"
                        f"</summary>"
                        f"<div class=\"comp-card\">"
                        f"<div class=\"comp-stages\">{_esc(stage_str)}</div>"
                    )

                    # Show stage details in a small table
                    if stages:
                        parts.append(
                            "<table style=\"font-size:0.85em;margin-top:8px;\">"
                            "<tr><th>#</th><th>Function</th><th>Label</th><th>Domain</th></tr>"
                        )
                        for i, stg in enumerate(stages, 1):
                            parts.append(
                                f"<tr>"
                                f"<td>{i}</td>"
                                f"<td><code>{_esc(stg.get('function_name', '?'))}</code></td>"
                                f"<td>{_esc(stg.get('label', stg.get('name', '')))}</td>"
                                f"<td>{_esc(stg.get('domain', ''))}</td>"
                                f"</tr>"
                            )
                        parts.append("</table>")

                    parts.append("</div></details>")
            else:
                parts.append(
                    f"<div class=\"comp-meta\">"
                    f"{_esc(str(stats.get('compositions', 0)))} compositions detected."
                    f"</div>"
                )

            parts.append("</div>")

        # -- 3. Call Traces (top 3 ASCII trees) --
        if has_traces:
            parts.append("<div class=\"card\">")
            parts.append(
                f"<h3>Deep Call Traces "
                f"({_esc(str(stats.get('trace_targets', 0)))} targets, "
                f"{_esc(str(stats.get('trace_total_nodes', 0)))} total nodes)</h3>"
            )

            # Load call_traces.md and extract ASCII trees
            trace_md_path = workspace.path / "reconstructed" / "call_traces.md"
            if trace_md_path.exists():
                try:
                    trace_content = trace_md_path.read_text(errors="replace")
                    # Extract code blocks (ASCII trees) -- up to 3
                    import re
                    code_blocks = re.findall(
                        r"## \d+\. (.+?)\n.*?```\n(.*?)```",
                        trace_content,
                        re.DOTALL,
                    )
                    for i, (target_name, tree_text) in enumerate(code_blocks[:3]):
                        tree_text = tree_text.strip()
                        # Limit tree lines to 40
                        tree_lines = tree_text.split("\n")
                        if len(tree_lines) > 40:
                            tree_text = "\n".join(tree_lines[:40])
                            tree_text += f"\n... ({len(tree_lines) - 40} more lines)"

                        parts.append(
                            f"<details class=\"deep-section\"{'open' if i == 0 else ''}>"
                            f"<summary>{_esc(target_name)}</summary>"
                            f"<div class=\"trace-tree\">{_esc(tree_text)}</div>"
                            f"</details>"
                        )
                except Exception as exc:
                    parts.append(
                        f"<div class=\"comp-meta\">Could not load trace data: {_esc(str(exc))}</div>"
                    )
            else:
                parts.append(
                    f"<div class=\"comp-meta\">"
                    f"{_esc(str(stats.get('trace_targets', 0)))} targets traced. "
                    f"See call_traces.md for details.</div>"
                )

            parts.append("</div>")

        return "\n".join(parts)

    def _artifacts_table(self, result: PipelineResult) -> str:
        """Artifact listesi tablosu."""
        all_artifacts = result.get_all_artifacts()
        if not all_artifacts:
            return ""

        rows = "".join(
            f"<tr><td>{_esc(name)}</td><td><code>{_esc(str(path))}</code></td></tr>"
            for name, path in all_artifacts.items()
        )

        return (
            "<h2>Artifacts</h2>"
            "<div class=\"card\">"
            "<table>"
            "<tr><th>Name</th><th>Path</th></tr>"
            f"{rows}"
            "</table>"
            "</div>"
        )
