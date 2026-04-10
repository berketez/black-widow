#!/usr/bin/env python3
"""
Karadul v1.3.0 -- Hacker-style CLI interface with live dashboard.

Terminalde hacker filmi gibi gorunen interaktif arayuz.
Mevcut pipeline'i oldugu gibi kullanir, ciktiyi hacker tarzinda gosterir.

Kullanim:
    python -m karadul.hacker_cli                        # Interaktif mod
    python -m karadul.hacker_cli /path/to/target        # Dogrudan analiz
    karadul-hack                                        # pyproject.toml entry point
"""

from __future__ import annotations

import io
import json
import logging
import os
import random
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pyfiglet
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from karadul import __version__

logger = logging.getLogger("karadul")

# ---------------------------------------------------------------
# Tema: koyu mor
# ---------------------------------------------------------------
KARADUL_THEME = Theme({
    "info": "purple",
    "warning": "bold bright_magenta",
    "danger": "bold magenta on black",
    "success": "bold purple",
    "header": "bold purple on black",
    "stage": "medium_purple1",
    "alert": "bold bright_magenta",
    "found": "medium_purple1",
    "target": "bold white on black",
    "logo.top": "purple",
    "logo.mid": "dark_violet",
    "logo.bot": "purple4",
    "dim": "dim white",
    "timestamp": "dim medium_purple1",
    "stat.key": "white",
    "stat.val": "medium_purple1",
})

console = Console(theme=KARADUL_THEME)

# ---------------------------------------------------------------
# ASCII Art Logo -- pyfiglet bloody font + spider
# ---------------------------------------------------------------
_SPIDER_ART = r"""
                /\    /\
               /  \  /  \
              /    \/    \
             /     /\     \
            |     /  \     |
            |    / ▄▄ \    |
             \  / ████ \  /
              \/ ██████ \/
              /\ ██████ /\
             /  \  ██  /  \
            /    \ ◆◆ /    \
           |      \██/      |
           |      |██|      |
            \     |██|     /
             \    |██|    /
              \   |██|   /
               \  |  |  /
                \ |  | /
                 \|  |/
                  \  /
                   \/
"""


def _build_logo() -> Text:
    """pyfiglet bloody font + Black Widow spider."""
    text = Text()

    # Bloody font
    bloody = pyfiglet.figlet_format("KARADUL", font="bloody")
    for line in bloody.split("\n"):
        text.append(line + "\n", style="dark_violet")

    # Spider — koyu mor gövde, parlak mor kum saati
    for line in _SPIDER_ART.split("\n"):
        if "◆" in line:
            idx = line.index("◆")
            text.append(line[:idx], style="purple4")
            text.append("◆◆", style="bold bright_magenta")
            text.append(line[idx + 2 :] + "\n", style="purple4")
        elif "█" in line or "▄" in line:
            text.append(line + "\n", style="purple4")
        else:
            text.append(line + "\n", style="dim purple")

    return text


def _ts() -> str:
    """Timestamp string: [HH:MM:SS]."""
    return time.strftime("%H:%M:%S")


def _format_size(size: int) -> str:
    """Byte degerini okunabilir formata cevir."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def _suppress_console():
    """Pipeline'in global console'unu sessiz Console ile degistir.

    Pipeline modulleri modul seviyesinde `console = Console()` olusturuyor.
    Hacker CLI kendi formatini kullanacagi icin pipeline ciktisini bastiririz.
    """
    quiet = Console(file=io.StringIO(), quiet=True)
    # Pipeline modulu
    try:
        import karadul.core.pipeline as pipeline_mod
        pipeline_mod.console = quiet
    except Exception:
        logger.debug("Pipeline console susturma basarisiz, atlaniyor", exc_info=True)


def _restore_console():
    """Pipeline console'unu geri yukle + terminal modunu sifirla."""
    try:
        import karadul.core.pipeline as pipeline_mod
        pipeline_mod.console = Console()
    except Exception:
        logger.debug("Pipeline console geri yukleme basarisiz, atlaniyor", exc_info=True)
    # Terminal cooked mode'a geri dondur (Rich.Live raw mode'da birakabiliyor)
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        termios.tcsetattr(fd, termios.TCSANOW, termios.tcgetattr(fd))
    except Exception:
        logger.debug("Terminal mode restore basarisiz, atlaniyor", exc_info=True)
    # stty sane fallback
    try:
        os.system("stty sane 2>/dev/null")
    except Exception:
        logger.debug("stty sane fallback basarisiz, atlaniyor", exc_info=True)


# ---------------------------------------------------------------
# Banner
# ---------------------------------------------------------------
def show_banner() -> None:
    """Buyuk ASCII art KARADUL logosunu goster."""
    console.print()
    console.print(Panel(
        _build_logo(),
        border_style="purple",
        padding=(1, 2),
    ))
    console.print()


# ---------------------------------------------------------------
# Target Info Box
# ---------------------------------------------------------------
def _show_target_box(info) -> None:
    """Target bilgilerini hacker-style panel icinde goster."""
    # Arch bilgisi varsa goster
    arch = info.metadata.get("arch", "")
    arch_line = f"\n[stat.key]Arch:[/]     {arch}" if arch else ""

    body = (
        f"[stat.key]Type:[/]     {info.target_type.value}\n"
        f"[stat.key]Language:[/] {info.language.value}\n"
        f"[stat.key]Size:[/]     {_format_size(info.file_size)}"
        f"{arch_line}\n"
        f"[stat.key]Hash:[/]     {info.file_hash[:16]}..."
    )

    console.print()
    console.print(Panel(
        body,
        title="[bright_magenta]TARGET IDENTIFIED[/]",
        border_style="purple",
        padding=(0, 2),
    ))


# ---------------------------------------------------------------
# Stage ciktisi -- her stage icin hacker-style log satirlari
# ---------------------------------------------------------------
def _show_stage_result(stage_name: str, stage_result, ts: str) -> None:
    """Tek bir stage sonucunu hacker-style log satirlari olarak goster."""
    status = "[bright_green]OK[/]" if stage_result.success else "[bright_red]FAIL[/]"
    duration = f"({stage_result.duration_seconds:.1f}s)"

    console.print(
        f"  [timestamp]{ts}[/] [bright_cyan]|[/] "
        f"Stage: [bright_white]{stage_name.upper()}[/] {status} {duration}"
    )

    if not stage_result.stats:
        return

    stats = stage_result.stats
    lines: list[str] = []

    # Genel sayisal stat'lari topla
    stat_mappings = [
        # Binary analyzer keys
        ("dylib_count", "Dynamic libraries"),
        ("string_count", "Strings (basic)"),
        ("symbol_count", "Symbols"),
        ("ghidra_function_count", "Ghidra functions"),
        ("ghidra_string_count", "Ghidra strings"),
        ("ghidra_call_graph_edges", "Call graph edges"),
        ("ghidra_decompiled", "Ghidra decompiled"),
        # JS analyzer keys
        ("functions", "Functions"),
        ("strings", "Strings"),
        ("imports", "Imports"),
        ("exports", "Exports"),
        ("webpack_modules", "Webpack modules"),
        ("total_lines", "Lines of code"),
        # Deobfuscation keys
        ("total_modules", "Modules"),
        ("bundle_format", "Bundle format"),
        ("unpack_modules", "Unpacked modules"),
        # Reconstruction keys
        ("modules_split", "Modules split"),
        ("variables_renamed", "Variables renamed"),
        ("params_recovered", "Params recovered"),
        ("functions_annotated", "Functions annotated"),
        ("comments_added", "Comments added"),
        ("naming_total", "Modules named"),
        # Report keys
        ("reports_generated", "Reports generated"),
        # Identify keys
        ("target_type", "Target type"),
        ("language", "Language"),
        ("bundler", "Bundler"),
    ]

    for key, label in stat_mappings:
        val = stats.get(key)
        if val is None or val == "" or val == 0:
            continue
        if isinstance(val, (dict, list)):
            continue
        # Sayi mi string mi?
        if isinstance(val, int) and val > 0:
            lines.append(f"    [timestamp]{ts}[/]   [found]|-- {label}: {val:,}[/]")
        elif isinstance(val, str) and val:
            lines.append(f"    [timestamp]{ts}[/]   [found]|-- {label}: {val}[/]")

    # Intelligence sonuclari
    intel_subsystems = stats.get("intel_subsystem_count", stats.get("subsystems", 0))
    intel_algorithms = stats.get("intel_algorithm_count", stats.get("algorithms", 0))
    intel_security = stats.get("intel_security_count", stats.get("security_mechanisms", 0))
    intel_app_type = stats.get("intel_app_type", "")

    if intel_subsystems:
        lines.append(f"    [timestamp]{ts}[/]   [found]|-- Subsystems: {intel_subsystems}[/]")
    if intel_algorithms:
        lines.append(f"    [timestamp]{ts}[/]   [found]|-- Algorithms: {intel_algorithms}[/]")
    if intel_security and int(str(intel_security)) > 0:
        lines.append(
            f"    [timestamp]{ts}[/]   "
            f"[alert]|-- ALERT: {intel_security} security mechanism(s) detected![/]"
        )
    if intel_app_type:
        lines.append(
            f"    [timestamp]{ts}[/]   "
            f"[bright_magenta]\\-- App Type: {str(intel_app_type).upper()}[/]"
        )

    # Ghidra durumu
    ghidra_success = stats.get("ghidra_success", stats.get("ghidra_analysis_success"))
    if ghidra_success:
        lines.append(f"    [timestamp]{ts}[/]   [bright_green]|-- Ghidra: analysis complete[/]")

    # Reconstruction mode
    recon_mode = stats.get("reconstruction_mode")
    if recon_mode:
        lines.append(f"    [timestamp]{ts}[/]   [found]|-- Reconstruction: {recon_mode}[/]")

    # Report formats
    formats = stats.get("formats")
    if formats and isinstance(formats, list):
        fmt_labels = {
            "report_json": "report.json",
            "report_md": "report.md",
            "report_html": "report.html",
        }
        for fmt in formats:
            label = fmt_labels.get(fmt, fmt)
            lines.append(f"    [timestamp]{ts}[/]   [found]|-- {label} generated[/]")

    for line in lines:
        console.print(line)


# ---------------------------------------------------------------
# Intelligence ALERT'leri
# ---------------------------------------------------------------
def _show_intelligence_alerts(result, ts: str) -> None:
    """Intelligence raporundaki guvenlik ve algoritma uyarilarini goster.

    workspace/static/intelligence_report.json dosyasini okur.
    """
    ws_path = result.workspace_path
    intel_candidates = [
        ws_path / "static" / "intelligence_report.json",
        ws_path / "raw" / "intelligence_report.json",
    ]

    intel_data = None
    for candidate in intel_candidates:
        if candidate.exists():
            try:
                intel_data = json.loads(candidate.read_text())
                break
            except Exception:
                logger.debug("JSON parse basarisiz, atlaniyor", exc_info=True)
                continue

    if not intel_data:
        return

    console.print()

    # Security mechanisms
    for sec in intel_data.get("security_mechanisms", []):
        name = sec.get("name", sec) if isinstance(sec, dict) else str(sec)
        console.print(
            f"  [alert]!! ALERT: {name} detected![/]"
        )

    # Algorithms
    for algo in intel_data.get("algorithms", [])[:8]:
        if isinstance(algo, dict):
            name = algo.get("name", "unknown")
            category = algo.get("category", "")
            cat_str = f" ({category})" if category else ""
        else:
            name = str(algo)
            cat_str = ""
        console.print(
            f"  [found]>> CRYPTO: {name}{cat_str}[/]"
        )

    # Subsystems (ilk 5)
    for sub in intel_data.get("subsystems", [])[:5]:
        if isinstance(sub, dict):
            name = sub.get("name", sub.get("subsystem", "unknown"))
        else:
            name = str(sub)
        console.print(
            f"  [timestamp]{ts}[/]   [info]|-- Subsystem: {name}[/]"
        )


# ---------------------------------------------------------------
# Final summary box
# ---------------------------------------------------------------
def _show_summary(result) -> None:
    """Analiz tamamlandiktan sonra ozet kutusu goster."""
    total_funcs = 0
    total_strings = 0
    total_modules = 0
    total_subsystems = 0
    total_algorithms = 0
    total_security = 0

    for sr in result.stages.values():
        if not sr.stats:
            continue
        for k, v in sr.stats.items():
            if isinstance(v, (dict, list)):
                continue
            try:
                val = int(str(v or 0))
            except (ValueError, TypeError):
                continue

            k_low = k.lower()
            if "function" in k_low or k_low == "func":
                total_funcs = max(total_funcs, val)
            elif "string" in k_low:
                total_strings = max(total_strings, val)
            elif "module" in k_low:
                total_modules = max(total_modules, val)
            elif "subsystem" in k_low:
                total_subsystems = max(total_subsystems, val)
            elif "algorithm" in k_low:
                total_algorithms = max(total_algorithms, val)
            elif "security" in k_low and "count" in k_low:
                total_security = max(total_security, val)

    # Report path
    report_dir = result.workspace_path / "reports"
    report_html = report_dir / "report.html"
    report_loc = str(report_html) if report_html.exists() else str(result.workspace_path)

    summary_body = (
        f"[stat.key]Functions:[/]  {total_funcs:,}\n"
        f"[stat.key]Strings:[/]    {total_strings:,}\n"
        f"[stat.key]Modules:[/]    {total_modules}\n"
        f"[stat.key]Subsystems:[/] {total_subsystems}\n"
        f"[stat.key]Algorithms:[/] {total_algorithms}\n"
        f"[stat.key]Security:[/]   {total_security}\n"
        f"[stat.key]Duration:[/]   {result.total_duration:.1f}s\n"
        f"\n[dim]Report: {report_loc}[/]"
    )

    console.print()
    console.print(Panel(
        summary_body,
        title="[bold bright_green]ANALYSIS COMPLETE[/]",
        border_style="bright_green",
        padding=(1, 2),
    ))
    console.print()


# ---------------------------------------------------------------
# Canli analiz simuelasyon ekrani -- Rich Live display
# ---------------------------------------------------------------

# Stage agirlik sistemi -- ETA hesaplamasi icin
# Gercek calisma surelerine dayali: identify ~0s, static ~400s (Ghidra),
# deobfuscate ~20s, reconstruct ~600-900s (naming/typing/analysis), report ~1s
_STAGE_WEIGHTS = {
    "identify": 0.01,       # ~0s, anlik
    "static": 0.30,         # ~400s (Ghidra decompilation)
    "dynamic": 0.02,        # ~10s (varsa)
    "deobfuscate": 0.02,    # ~20s
    "reconstruct": 0.63,    # ~600-900s (EN AGIR: naming, algorithm detection, type recovery)
    "report": 0.02,         # ~1s
}

# Stage aciklamalari ve simuelasyon detaylari
_STAGE_DESCRIPTIONS = {
    "identify": {
        "label": "Target Identification",
        "icon": ">>>",
        "actions": [
            "Scanning file headers...",
            "Detecting binary format...",
            "Identifying language runtime...",
            "Extracting metadata...",
            "Fingerprinting bundler...",
        ],
    },
    "static": {
        "label": "Static Analysis",
        "icon": ">>>",
        "actions": [
            "Disassembling entry point...",
            "Mapping function boundaries...",
            "Extracting string literals...",
            "Building call graph...",
            "Recovering type information...",
            "Analyzing cross-references...",
            "Identifying library signatures...",
            "Decompiling functions...",
        ],
    },
    "dynamic": {
        "label": "Dynamic Analysis",
        "icon": ">>>",
        "actions": [
            "Injecting instrumentation hooks...",
            "Tracing function calls...",
            "Monitoring memory allocations...",
            "Capturing crypto operations...",
            "Recording file I/O...",
            "Mapping loaded modules...",
        ],
    },
    "deobfuscate": {
        "label": "Deobfuscation",
        "icon": ">>>",
        "actions": [
            "Analyzing control flow flattening...",
            "Removing dead code paths...",
            "Simplifying string encodings...",
            "Reversing opaque predicates...",
            "Unpacking webpack modules...",
            "Normalizing variable names...",
        ],
    },
    "reconstruct": {
        "label": "Reconstruction",
        "icon": ">>>",
        "actions": [
            "Reconstructing: signature matching...",
            "Reconstructing: algorithm detection...",
            "Reconstructing: variable naming (19K functions)...",
            "Reconstructing: type recovery...",
            "Reconstructing: deep analysis...",
            "Reconstructing: confidence calibration...",
        ],
    },
    "report": {
        "label": "Report Generation",
        "icon": ">>>",
        "actions": [
            "Compiling JSON report...",
            "Rendering Markdown summary...",
            "Generating HTML dashboard...",
            "Indexing findings...",
        ],
    },
}


@dataclass
class LiveAnalysisState:
    """Canli analiz ekraninin durumu.

    Rich Live display bu state'i okuyarak kendini gunceller.
    Pipeline callback'leri bu state'i yazar.
    """

    target_name: str = ""
    target_type: str = ""
    total_stages: int = 0
    completed_stages: int = 0
    current_stage: str = ""
    current_action: str = ""
    stage_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    start_time: float = 0.0
    # Canli sayaclar (simuelasyon icin)
    functions_found: int = 0
    functions_total: int = 0
    strings_found: int = 0
    types_found: int = 0
    xrefs_found: int = 0
    current_function: str = ""
    current_algorithm: str = ""
    current_confidence: int = 0
    library_matches: dict[str, int] = field(default_factory=dict)
    is_running: bool = True
    # Gercek stage result stat'lari
    final_stats: dict[str, Any] = field(default_factory=dict)
    # v1.3.0: canli log stream + sub-progress
    log_buffer: Any = field(default=None)  # collections.deque
    sub_progress_msg: str = ""
    sub_progress_frac: float = -1.0  # -1 = belirsiz


def _build_live_panel(state: LiveAnalysisState) -> Panel:
    """State'ten canli analiz paneli olustur.

    Her cagirildiginda guncellenmis Rich renderables dondurur.
    """
    elapsed = time.monotonic() - state.start_time if state.start_time else 0

    # Weight-based progress: stage agirliklarini kullanarak gercekci yuzde hesapla
    completed_weight = sum(
        _STAGE_WEIGHTS.get(sname, 0.0) for sname in state.stage_results
    )
    active_weight = 0.0
    if state.current_stage and state.completed_stages < state.total_stages:
        active_weight = _STAGE_WEIGHTS.get(state.current_stage, 0.0) * 0.5

    # Bilinen ve bilinmeyen stage'lerin toplam agirligini hesapla
    all_known_stages = list(state.stage_results.keys())
    if state.current_stage and state.current_stage not in all_known_stages:
        all_known_stages.append(state.current_stage)

    known_weight_sum = sum(
        _STAGE_WEIGHTS.get(s, 0.0) for s in all_known_stages
    )
    unknown_count = state.total_stages - len(all_known_stages)
    if unknown_count > 0 and known_weight_sum < 1.0:
        unknown_per_stage = (1.0 - known_weight_sum) / unknown_count
    else:
        unknown_per_stage = 0.0
    total_weight = known_weight_sum + unknown_count * unknown_per_stage
    if total_weight <= 0:
        total_weight = 1.0

    effective_pct = min((completed_weight + active_weight) / total_weight * 100, 100.0)

    # Progress bar (karakter bazli)
    bar_width = 40
    filled = int(bar_width * effective_pct / 100)
    bar = "[bright_magenta]" + ("\u25a0" * filled) + "[/]" + "[dim]" + ("\u2591" * (bar_width - filled)) + "[/]"

    # Weight-based ETA: elapsed / completed_weight * remaining_weight
    if completed_weight > 0 and state.completed_stages < state.total_stages:
        remaining_weight = total_weight - completed_weight
        rate = elapsed / completed_weight  # saniye / birim agirlik
        remaining_time = remaining_weight * rate
        eta_str = _format_duration(remaining_time)
    elif state.completed_stages >= state.total_stages and state.total_stages > 0:
        eta_str = "done"
    else:
        eta_str = "calculating..."

    # CPU simuelasyonu (gercekci gorunmesi icin)
    cpu_pct = random.randint(78, 99) if state.is_running else 0

    lines: list[str] = []

    # Header
    lines.append(
        f" [bold bright_magenta]\u25fc KARADUL v{__version__}[/] [dim]--[/] "
        f"[bright_white]Reverse Engineering:[/] [medium_purple1]{state.target_name}[/]"
    )
    lines.append(f" [dim]{'=' * 56}[/]")

    # Progress bar
    lines.append(
        f" {bar} [bright_white]{effective_pct:>3.0f}%[/] [dim]--[/] "
        f"[bright_cyan]{state.current_action or 'Initializing...'}[/]"
    )
    lines.append("")

    # Tamamlanan stage'lerin sonuclari
    for sname, sdata in state.stage_results.items():
        success = sdata.get("success", False)
        duration = sdata.get("duration", 0)
        icon = "[bright_green]\u2714[/]" if success else "[bright_red]\u2718[/]"
        label = _STAGE_DESCRIPTIONS.get(sname, {}).get("label", sname.upper())
        lines.append(f" {icon} [bright_white]{label}[/] [dim]({duration:.1f}s)[/]")

        # Stage-specific stat satirlari
        stats = sdata.get("stats", {})
        stat_lines = _format_stage_stats(sname, stats)
        for sl in stat_lines:
            lines.append(f"   {sl}")

    # Aktif stage
    if state.current_stage and state.is_running:
        label = _STAGE_DESCRIPTIONS.get(state.current_stage, {}).get(
            "label", state.current_stage.upper()
        )
        lines.append(f" [bright_cyan]\u25b6 {label}[/]")

        # Canli sayaclar (static analysis icin detayli gosterim)
        if state.current_stage == "static":
            if state.functions_total > 0:
                lines.append(
                    f"   [dim]\u251c\u2500[/] [stat.key]Functions:[/] "
                    f"[medium_purple1]{state.functions_found:,}[/] / "
                    f"[dim]{state.functions_total:,}[/] decompiled"
                )
            if state.strings_found > 0:
                lines.append(
                    f"   [dim]\u251c\u2500[/] [stat.key]Strings:[/] "
                    f"[medium_purple1]{state.strings_found:,}[/] extracted"
                )
            if state.types_found > 0 or state.xrefs_found > 0:
                lines.append(
                    f"   [dim]\u251c\u2500[/] [stat.key]Types:[/] "
                    f"[medium_purple1]{state.types_found}[/] structs recovered"
                )
                lines.append(
                    f"   [dim]\u2514\u2500[/] [stat.key]Xrefs:[/] "
                    f"[medium_purple1]{state.xrefs_found:,}[/] cross-references mapped"
                )

        # Library signature matches
        if state.library_matches:
            total_lib = sum(state.library_matches.values())
            lines.append(
                f"   [dim]\u251c\u2500[/] [stat.key]Signature DB:[/] "
                f"[medium_purple1]{total_lib}[/] library functions identified"
            )
            for lib_name, count in list(state.library_matches.items())[:4]:
                lines.append(f"   [dim]\u2502  \u2514\u2500[/] {lib_name}: [medium_purple1]{count}[/]")

        # Current function decode
        if state.current_function:
            lines.append("")
            lines.append(
                f"   [dim]\u25b6[/] [bright_white]Current:[/] "
                f"[bright_cyan]{state.current_function}[/]"
            )
            if state.current_algorithm:
                lines.append(
                    f"   [dim]  \u2514\u2500[/] Algorithm: [medium_purple1]"
                    f"{state.current_algorithm}[/] "
                    f"([bright_green]{state.current_confidence}%[/] confidence)"
                )

    lines.append("")

    # Alt bilgi satiri
    lines.append(
        f" [dim]\u23f1 Elapsed:[/] [bright_white]{_format_duration(elapsed)}[/] "
        f"[dim]|[/] [dim]ETA:[/] [bright_white]{eta_str}[/] "
        f"[dim]|[/] [dim]CPU:[/] [bright_white]{cpu_pct}%[/]"
    )

    content = "\n".join(lines)
    return Panel(
        content,
        border_style="purple",
        padding=(1, 1),
    )


def _format_duration(seconds: float) -> str:
    """Sureyi okunabilir formatta goster."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs:02d}s"


def _stage_one_liner(stage_name: str, stats: dict[str, Any]) -> str:
    """Tamamlanan stage icin tek satirlik ozet."""
    if stage_name == "identify":
        t = stats.get("target_type", "")
        l = stats.get("language", "")
        return f"[#008800]{t} / {l}[/]" if t else ""
    elif stage_name == "static":
        fn = stats.get("ghidra_function_count", stats.get("functions", 0))
        st = stats.get("ghidra_string_count", stats.get("strings", stats.get("string_count", 0)))
        parts = []
        if fn:
            parts.append(f"{fn:,} functions")
        if st:
            parts.append(f"{st:,} strings")
        return f"[#00cc00]{', '.join(parts)}[/]" if parts else ""
    elif stage_name == "deobfuscate":
        m = stats.get("total_modules", 0)
        return f"[#00cc00]{m} modules[/]" if m else ""
    elif stage_name == "reconstruct":
        v = stats.get("variables_renamed", stats.get("naming_total", 0))
        c = stats.get("coverage_percent", 0)
        if v:
            return f"[#00cc00]{v:,} renamed[/]  [#008800]{c}% coverage[/]"
        return ""
    elif stage_name == "report":
        n = stats.get("reports_generated", 0)
        return f"[#00cc00]{n} reports[/]" if n else ""
    return ""


# ---------------------------------------------------------------
# v1.3.0 Multi-Panel Live Dashboard
# ---------------------------------------------------------------

# Tum bilinen stage isimleri siraliyla
_ALL_STAGES_ORDERED = ["identify", "static", "dynamic", "deobfuscate", "reconstruct", "report"]


def _build_dashboard(state: LiveAnalysisState) -> Group:
    """3-panelli canli dashboard olustur.

    Panel 1 (ust): Header + pipeline ilerleme + stage listesi
    Panel 2 (orta): Aktif stage detaylari + sub-progress
    Panel 3 (alt): Akan log stream
    """
    elapsed = time.monotonic() - state.start_time if state.start_time else 0

    # -- Progress hesaplama: tamamlanan stage sayisi bazli (basit, dogru) --
    total_s = max(state.total_stages, 1)
    completed_n = len(state.stage_results)

    # Aktif stage icin sub_progress varsa onu kullan, yoksa 0.5 varsay
    active_frac = 0.0
    if state.current_stage and state.current_stage not in state.stage_results:
        if state.sub_progress_frac >= 0:
            active_frac = state.sub_progress_frac
        else:
            active_frac = 0.3  # belirsiz -- yaklasik

    effective_pct = min((completed_n + active_frac) / total_s * 100, 100.0)

    # ETA: gecen sure / tamamlanan oran * kalan oran
    if effective_pct > 0 and completed_n < total_s:
        eta_sec = elapsed / (effective_pct / 100) * ((100 - effective_pct) / 100)
        eta_str = _format_duration(eta_sec)
    elif completed_n >= total_s:
        eta_str = "done"
    else:
        eta_str = "..."

    # Renk sabitleri -- kutu/baslik koyu mor, dinamik icerik koyu yesil
    M = "dark_violet"        # koyu mor -- kutular, basliklar, sureler
    DM = "purple4"           # daha koyu mor -- ikincil (separatorler)
    G = "#00cc00"            # koyu matrix yesil -- dinamik icerik
    BG = "#00ff44"           # parlak yesil -- vurgular (sayilar)
    DG = "#008800"           # soluk yesil -- ikincil metin

    # ================================================================
    # BOLUM 1: HEADER + PIPELINE
    # ================================================================
    lines: list[str] = []

    lines.append(
        f"  [{M}]\u25c6 KARADUL[/] [{DM}]v{__version__}[/]"
        f"  [{DG}]\u2502[/]  [{G}]{state.target_name}[/]"
        f"  [{DG}]({state.target_type})[/]"
    )
    lines.append(f"  [{DM}]{'─' * 60}[/]")

    # Progress bar
    bar_w = 36
    filled = int(bar_w * effective_pct / 100)
    bar = (
        f"[{M}]" + "\u2588" * filled + "[/]"
        + f"[{DG}]" + "\u2591" * (bar_w - filled) + "[/]"
    )
    lines.append(
        f"  [{M}]PIPELINE[/]  {bar}  [{M}]{effective_pct:>3.0f}%[/]"
        f"  [{DG}]{completed_n}/{state.total_stages}[/]"
        f"  [{DG}]\u23f1[/] [{DM}]{_format_duration(elapsed)}[/]"
        f"  [{DG}]ETA:[/] [{DM}]{eta_str}[/]"
    )
    lines.append("")

    # Stage listesi
    ordered_stages: list[str] = []
    for s in _ALL_STAGES_ORDERED:
        if s in state.stage_results or s == state.current_stage:
            ordered_stages.append(s)
    remaining_count = state.total_stages - len(ordered_stages)
    for s in _ALL_STAGES_ORDERED:
        if s not in ordered_stages and remaining_count > 0:
            ordered_stages.append(s)
            remaining_count -= 1

    for sname in ordered_stages:
        label = _STAGE_DESCRIPTIONS.get(sname, {}).get("label", sname.upper())

        if sname in state.stage_results:
            sdata = state.stage_results[sname]
            ok = sdata.get("success", False)
            dur = sdata.get("duration", 0)
            icon = f"[{M}]\u2714[/]" if ok else "[bright_red]\u2718[/]"
            stats = sdata.get("stats", {})
            summary = _stage_one_liner(sname, stats)
            lines.append(
                f"   {icon} [{G}]{label:<22}[/] "
                f"[{DM}]{dur:>6.1f}s[/]  {summary}"
            )
        elif sname == state.current_stage and state.is_running:
            spin_chars = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2807"
            spin_idx = int(elapsed * 7) % len(spin_chars)
            spin = spin_chars[spin_idx]
            active_dur = _format_duration(elapsed - sum(
                d.get("duration", 0) for d in state.stage_results.values()
            ))
            lines.append(
                f"   [{M}]{spin}[/] [{G}]{label:<22}[/] "
                f"[{DM}]{active_dur:>6}[/]  "
                f"[{DG}]{state.current_action}[/]"
            )
        else:
            lines.append(
                f"   [{DG}]\u25cb {label:<22}    --[/]"
            )

    # ================================================================
    # BOLUM 2: AKTIF STAGE DETAY
    # ================================================================
    lines.append(f"  [{DM}]{'─' * 60}[/]")

    if state.current_stage and state.is_running:
        label = _STAGE_DESCRIPTIONS.get(state.current_stage, {}).get(
            "label", state.current_stage.upper()
        )
        lines.append(f"  [{M}]\u25fc {label.upper()}[/]")

        if state.sub_progress_frac >= 0:
            sp_w = 30
            sp_filled = int(sp_w * state.sub_progress_frac)
            sp_bar = (
                f"[{M}]" + "\u2588" * sp_filled + "[/]"
                + f"[{DG}]" + "\u2591" * (sp_w - sp_filled) + "[/]"
            )
            sp_pct = state.sub_progress_frac * 100
            lines.append(f"  {sp_bar}  [{M}]{sp_pct:>3.0f}%[/]")

        if state.sub_progress_msg:
            lines.append(f"  [{G}]\u25b6[/] {state.sub_progress_msg}")
    else:
        if state.completed_stages >= state.total_stages and state.total_stages > 0:
            lines.append(f"  [{M}]\u2714 Analysis complete.[/]")
        else:
            lines.append(f"  [{DG}]Initializing...[/]")

    # ================================================================
    # BOLUM 3: LOG STREAM
    # ================================================================
    lines.append(f"  [{DM}]{'─' * 60}[/]")
    lines.append(f"  [{DM}]LOG STREAM[/]")

    if state.log_buffer is not None:
        recent = list(state.log_buffer)[-6:]
        for raw_line in recent:
            if "ERROR" in raw_line or "FAIL" in raw_line:
                lines.append(f"  [bright_red]{raw_line}[/]")
            elif "WARNING" in raw_line:
                lines.append(f"  [yellow]{raw_line}[/]")
            elif any(kw in raw_line for kw in ("YARA", "FLIRT", "Algorithm", "Crypto", "AES", "RSA")):
                lines.append(f"  [{G}]{raw_line}[/]")
            else:
                lines.append(f"  [{DG}]{raw_line}[/]")

    # Minimum yukseklik
    while len(lines) < 20:
        lines.append("")

    return Panel(
        "\n".join(lines),
        border_style=M,
        padding=(0, 1),
    )


def _format_stage_stats(stage_name: str, stats: dict[str, Any]) -> list[str]:
    """Tamamlanan stage icin istatistik satirlari uret."""
    lines: list[str] = []

    if stage_name == "identify":
        ttype = stats.get("target_type", "")
        lang = stats.get("language", "")
        if ttype:
            lines.append(f"[dim]\u251c\u2500[/] Type: [medium_purple1]{ttype}[/]")
        if lang:
            lines.append(f"[dim]\u2514\u2500[/] Language: [medium_purple1]{lang}[/]")

    elif stage_name == "static":
        mappings = [
            ("ghidra_function_count", "Ghidra functions"),
            ("ghidra_string_count", "Strings"),
            ("ghidra_call_graph_edges", "Call graph edges"),
            ("ghidra_decompiled", "Decompiled"),
            ("functions", "Functions"),
            ("strings", "Strings"),
            ("string_count", "Strings"),
            ("symbol_count", "Symbols"),
            ("imports", "Imports"),
        ]
        for key, label in mappings:
            val = stats.get(key)
            if val and isinstance(val, int) and val > 0:
                lines.append(f"[dim]\u251c\u2500[/] {label}: [medium_purple1]{val:,}[/]")

    elif stage_name == "deobfuscate":
        for key, label in [
            ("total_modules", "Modules"),
            ("unpack_modules", "Unpacked"),
            ("bundle_format", "Format"),
        ]:
            val = stats.get(key)
            if val and val != 0:
                if isinstance(val, int):
                    lines.append(f"[dim]\u251c\u2500[/] {label}: [medium_purple1]{val:,}[/]")
                else:
                    lines.append(f"[dim]\u251c\u2500[/] {label}: [medium_purple1]{val}[/]")

    elif stage_name == "reconstruct":
        for key, label in [
            ("modules_split", "Modules split"),
            ("variables_renamed", "Variables renamed"),
            ("functions_annotated", "Annotated"),
            ("comments_added", "Comments"),
            ("naming_total", "Named"),
        ]:
            val = stats.get(key)
            if val and isinstance(val, int) and val > 0:
                lines.append(f"[dim]\u251c\u2500[/] {label}: [medium_purple1]{val:,}[/]")

    elif stage_name == "report":
        formats = stats.get("formats", [])
        if formats and isinstance(formats, list):
            fmt_str = ", ".join(f.replace("report_", "") for f in formats)
            lines.append(f"[dim]\u2514\u2500[/] Formats: [medium_purple1]{fmt_str}[/]")

    return lines


class _LiveDashboard:
    """Rich renderable wrapper -- her render'da state'ten dashboard olusturur.

    Rich Live bu objeyi her refresh'te cagirarak guncel dashboard alir.
    Manuel live.update() gerekmez -- donma/stutter onlenir.
    """

    def __init__(self, state: LiveAnalysisState) -> None:
        self._state = state
        self._tick = 0

    def __rich_console__(self, console, options):
        # Action text rotate
        self._tick += 1
        if self._state.is_running and self._state.current_stage and self._tick % 20 == 0:
            desc = _STAGE_DESCRIPTIONS.get(self._state.current_stage, {})
            actions = desc.get("actions", [])
            if actions:
                self._state.current_action = actions[self._tick // 20 % len(actions)]

        yield _build_dashboard(self._state)


# ---------------------------------------------------------------
# Ana analiz fonksiyonu -- pipeline'i calıstir, hacker cikti goster
# ---------------------------------------------------------------
def analyze_with_live_output(target_path: str) -> None:
    """Gercek zamanli hacker-style cikti ile analiz.

    Rich Live display kullanarak pipeline calisirken canli progress gosterir.
    Pipeline callback mekanizmasi ile her stage basinda/sonunda UI guncellenir.
    Arka plan thread'i ile sayaclar simule edilir.
    """
    from karadul.config import Config
    from karadul.core.pipeline import Pipeline
    from karadul.core.target import TargetDetector, TargetType
    from karadul.stages import (
        IdentifyStage,
        StaticAnalysisStage,
        DeobfuscationStage,
        ReportStage,
    )

    config = Config.load()  # karadul.yaml varsa yukler, yoksa default
    # project_root'u karadul paket kokune set et -- CWD'ye bagli olmamasi icin
    config.project_root = Path(__file__).resolve().parent.parent
    target_file = Path(target_path).resolve()

    # v1.5.5: Computation recovery interaktif soru
    if not config.computation_recovery.enabled:
        console.print()
        console.print("  [bold]Computation power level?[/]")
        console.print("    [cyan][1][/] FULL — GPU/CPU intensive deep analysis (struct recovery, pattern matching, formula extraction)")
        console.print("    [cyan][0][/] STANDARD — Fast heuristic analysis")
        try:
            choice = console.input("   [dim]>[/] ").strip()
            if choice == "1":
                config.computation_recovery.enabled = True
                console.print("  [green]>> Computation recovery ENABLED[/]\n")
            else:
                console.print("  [dim]>> Standard analysis[/]\n")
        except (EOFError, KeyboardInterrupt):
            console.print("  [dim]>> Standard analysis[/]\n")

    # 1. Target detection -- minimal cikti, dashboard gosterecek
    console.print(f"\n  [#008800]{_ts()}[/] [dark_violet]|[/] Scanning target: [#00cc00]{target_file.name}[/]")

    detector = TargetDetector()
    try:
        info = detector.detect(target_file)
    except Exception as exc:
        console.print(f"  [bright_red]!! TARGET DETECTION FAILED: {exc}[/]")
        return

    console.print(
        f"  [#008800]{_ts()}[/] [dark_violet]|[/] "
        f"[#00cc00]{info.target_type.value}[/] / "
        f"[#00cc00]{info.language.value}[/]  "
        f"[#008800]({info.file_size / (1024*1024):.1f} MB)[/]\n"
    )

    # 2. Pipeline kur (quiet mode: pipeline kendi output'unu kapatir)
    pipeline = Pipeline(config)
    pipeline.register_stage(IdentifyStage())
    pipeline.register_stage(StaticAnalysisStage())

    # Deobfuscate + reconstruct her hedef tipi icin
    pipeline.register_stage(DeobfuscationStage())
    try:
        from karadul.stages import ReconstructionStage
        pipeline.register_stage(ReconstructionStage())
    except ImportError as exc:
        logger.warning("ReconstructionStage yuklenemedi, atlaniyor: %s", exc)

    pipeline.register_stage(ReportStage())

    total_stages = len(pipeline.registered_stages)

    # 3. Live analysis state olustur
    log_buf = deque(maxlen=50)
    state = LiveAnalysisState(
        target_name=target_file.name,
        target_type=info.target_type.value,
        total_stages=total_stages,
        start_time=time.monotonic(),
        log_buffer=log_buf,
    )

    # 4. Pipeline callback'leri -- sadece state'i gunceller, UI Rich tarafindan yenilenir
    def on_stage_start(stage_name: str, index: int, total: int) -> None:
        state.current_stage = stage_name
        desc = _STAGE_DESCRIPTIONS.get(stage_name, {})
        actions = desc.get("actions", [f"Processing {stage_name}..."])
        state.current_action = actions[0] if actions else f"Running {stage_name}..."
        state.sub_progress_msg = ""
        state.sub_progress_frac = -1.0

    def on_stage_complete(stage_name: str, result, index: int, total: int) -> None:
        state.stage_results[stage_name] = {
            "success": result.success,
            "duration": result.duration_seconds,
            "stats": dict(result.stats) if result.stats else {},
        }
        state.completed_stages = len(state.stage_results)
        if result.stats:
            state.final_stats.update(result.stats)
        if state.current_stage == stage_name:
            state.current_stage = ""
            state.current_action = "Preparing next stage..."
            state.sub_progress_msg = ""
            state.sub_progress_frac = -1.0

    def on_progress(stage_name: str, message: str, fraction: float) -> None:
        state.sub_progress_msg = message
        state.sub_progress_frac = fraction

    # 5. Rich Live display -- _LiveDashboard renderable ile otomatik refresh
    console.print(
        f"  [#008800]{_ts()}[/] [dark_violet]|[/] "
        f"Pipeline starting ({total_stages} stages)...\n"
    )

    dashboard = _LiveDashboard(state)
    pipeline_result = None

    try:
        with Live(
            dashboard,
            console=console,
            refresh_per_second=4,
            transient=True,
        ) as live:
            try:
                pipeline_result = pipeline.run(
                    target_file,
                    on_stage_start=on_stage_start,
                    on_stage_complete=on_stage_complete,
                    on_progress=on_progress,
                    log_buffer=log_buf,
                )
            except KeyboardInterrupt:
                state.is_running = False
                console.print(
                    "\n  [yellow]!! Pipeline kullanici tarafindan durduruldu (Ctrl+C)[/]\n"
                )
                _restore_console()
                return
            except Exception as exc:
                state.is_running = False
                console.print(f"\n  [alert]!! PIPELINE FAILED: {exc}[/]\n")
                _restore_console()
                return

            # Pipeline bitti
            state.is_running = False
            state.completed_stages = state.total_stages
            state.current_stage = ""
            state.current_action = "Analysis complete."
    finally:
        _restore_console()

    if pipeline_result is None:
        return

    # 6. Stage sonuclari -- hacker-style log satirlari (Live sonrasi kalici cikti)
    ts = _ts()
    for stage_name, stage_result in pipeline_result.stages.items():
        _show_stage_result(stage_name, stage_result, ts)

    # 7. Intelligence alert'leri
    _show_intelligence_alerts(pipeline_result, ts)

    # 8. Final summary
    _show_summary(pipeline_result)


# ---------------------------------------------------------------
# Interaktif mod -- REPL dongusu
# ---------------------------------------------------------------
def run_interactive() -> None:
    """Interaktif hacker CLI dongusu.

    Logo goster, hedef sor, analiz et, tekrarla.
    """
    show_banner()

    while True:
        try:
            os.system("stty sane 2>/dev/null")
            console.print(f"  [bright_magenta]>>[/] [dim]KARADUL v{__version__} target path (or 'quit')[/] ", end="")
            sys.stdout.flush()
            target = sys.stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n  [dim red]Karadul shutting down...[/]\n")
            break

        target = target.strip()

        if not target:
            continue

        if target.lower() in ("quit", "exit", "q"):
            console.print("\n  [dim red]Karadul shutting down...[/]\n")
            break

        target_path = Path(target)

        # .app bundle ise APP_BUNDLE olarak analiz et (v1.2.1+)
        if target_path.suffix == ".app" and target_path.is_dir():
            console.print(
                f"  [dim]App bundle detected — full analysis of all components[/]"
            )

        if not target_path.exists():
            console.print(f"  [bright_red]X Target not found: {target}[/]")
            continue

        try:
            analyze_with_live_output(str(target_path))
        except KeyboardInterrupt:
            console.print("\n  [dim red]Analysis interrupted.[/]\n")
        except Exception as exc:
            console.print(f"\n  [bright_red]X Unexpected error: {exc}[/]\n")


# ---------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------
def main() -> None:
    """pyproject.toml entry point: karadul-hack."""
    if len(sys.argv) > 1:
        # Dogrudan hedef verilmis
        show_banner()
        target = sys.argv[1]
        target_path = Path(target)

        if not target_path.exists():
            console.print(f"  [bright_red]X Target not found: {target}[/]")
            sys.exit(1)

        analyze_with_live_output(str(target_path))
    else:
        run_interactive()


if __name__ == "__main__":
    main()
