"""
Black Widow (Karadul) CLI -- Click-based komut satiri arayuzu.

Komutlar:
    karadul info <target>       Hedef dosya/dizin bilgilerini goster
    karadul analyze <target>    Tam analiz pipeline calistir
    karadul list                Analiz edilmis hedefleri listele
    karadul clean <target>      Workspace temizle
    karadul run <target>        Reconstructed projeyi calistir
    karadul version             Versiyon bilgisi
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from karadul import __codename__, __version__
from karadul.config import Config

logger = logging.getLogger("karadul")
from karadul.core.target import Language, TargetDetector, TargetInfo, TargetType

console = Console()
err_console = Console(stderr=True)

# Stage isimleri -- pipeline sirasina gore
STAGES: list[str] = [
    "identify",
    "static",
    "dynamic",
    "deobfuscate",
    "reconstruct",
    "report",
]

STAGE_LABELS: dict[str, str] = {
    "identify": "Identification",
    "static": "Static Analysis",
    "dynamic": "Dynamic Analysis",
    "deobfuscate": "Deobfuscation",
    "reconstruct": "Reconstruction",
    "report": "Reporting",
}


def _load_config(config_path: Optional[str]) -> Config:
    """Config dosyasini yukle. Basarisizsa varsayilan don."""
    path = Path(config_path) if config_path else None
    return Config.load(path)


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


def _print_target_info(info: TargetInfo) -> None:
    """TargetInfo'yu Rich Table olarak yazdir."""
    table = Table(title="Hedef Bilgileri", show_header=False, border_style="cyan")
    table.add_column("Alan", style="bold")
    table.add_column("Deger")

    table.add_row("Dosya", str(info.path))
    table.add_row("Tur", info.target_type.value if isinstance(info.target_type, TargetType) else str(info.target_type))
    table.add_row("Dil", info.language.value if isinstance(info.language, Language) else str(info.language))
    table.add_row("Boyut", _format_size(info.file_size))
    table.add_row("SHA-256", info.file_hash or "N/A")

    if info.metadata:
        for key, value in info.metadata.items():
            table.add_row(key, str(value))

    console.print(table)


def _print_banner() -> None:
    """Black Widow banner'ini yazdir."""
    banner = Text()
    banner.append("BLACK WIDOW", style="bold red")
    banner.append(f" v{__version__}", style="bold white")
    banner.append(" -- ", style="dim")
    banner.append(__codename__, style="bold cyan")
    banner.append("\nReverse Engineering Suite", style="dim")

    console.print(Panel(banner, border_style="red", padding=(1, 4)))


def _get_active_stages(
    stop_after: Optional[str], skip_dynamic: bool,
) -> list[str]:
    """Calistirilacak stage listesini dondur."""
    stages = list(STAGES)

    if skip_dynamic and "dynamic" in stages:
        stages.remove("dynamic")

    if stop_after:
        try:
            idx = stages.index(stop_after)
            stages = stages[: idx + 1]
        except ValueError:
            pass

    return stages


def _get_available_stages(requested: list[str]) -> list:
    """Istenen stage'lerin somut siniflarini dondur. Import hatasi olursa atla."""
    from karadul.stages import (
        IdentifyStage,
        StaticAnalysisStage,
        DeobfuscationStage,
        DynamicAnalysisStage,
        ReportStage,
    )

    stage_map: dict[str, type] = {
        "identify": IdentifyStage,
        "static": StaticAnalysisStage,
        "dynamic": DynamicAnalysisStage,
        "deobfuscate": DeobfuscationStage,
        "report": ReportStage,
    }

    # ReconstructionStage opsiyonel
    try:
        from karadul.stages import ReconstructionStage
        stage_map["reconstruct"] = ReconstructionStage
    except ImportError as exc:
        logger.warning("ReconstructionStage yuklenemedi, atlaniyor: %s", exc)

    instances = []
    for name in requested:
        cls = stage_map.get(name)
        if cls is not None:
            instances.append(cls())
    return instances


# ---------------------------------------------------------------
# Ana CLI grubu
# ---------------------------------------------------------------
@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="karadul")
@click.option("--verbose", is_flag=True, help="Debug log seviyesini ac.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """Black Widow (Karadul) v3 -- Reverse Engineering Suite"""
    # v1.7.4: SIGUSR1 graceful handling -- status dump instead of termination
    def _sigusr1_handler(signum: int, frame) -> None:  # noqa: ANN001
        """SIGUSR1 geldiginde pipeline durumunu logla (process olmesin)."""
        import threading
        active = threading.active_count()
        logger.info(
            "SIGUSR1 received (pid=%d): %d active threads, uptime=%.0fs",
            os.getpid(), active, time.monotonic() - _start_time,
        )
        # stderr'e de yaz (log gorunmuyorsa)
        print(
            f"[karadul] SIGUSR1: pid={os.getpid()}, threads={active}",
            file=sys.stderr, flush=True,
        )

    _start_time = time.monotonic()
    try:
        signal.signal(signal.SIGUSR1, _sigusr1_handler)  # v1.7.4
    except (OSError, ValueError):
        # Windows veya thread-disi context'te signal ayarlanamayabilir
        pass

    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    if ctx.invoked_subcommand is None:
        from karadul.hacker_cli import main as hacker_main
        hacker_main()


# ---------------------------------------------------------------
# karadul version
# ---------------------------------------------------------------
@main.command()
def version() -> None:
    """Versiyon bilgisini goster."""
    _print_banner()


# ---------------------------------------------------------------
# karadul info <target>
# ---------------------------------------------------------------
@main.command()
@click.argument("target", type=str)
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Config YAML dosyasi.")
@click.pass_context
def info(ctx: click.Context, target: str, config_path: Optional[str]) -> None:
    """Hedef dosya/dizin hakkinda bilgi goster."""
    _load_config(config_path)

    # v1.9.1: Smart target resolver
    from karadul.core.target_resolver import resolve_target
    try:
        target_path = resolve_target(target)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]HATA:[/bold red] {exc}")
        sys.exit(1)

    try:
        detector = TargetDetector()
        target_info = detector.detect(target_path)
    except Exception as exc:
        err_console.print(f"[bold red]HATA:[/bold red] {exc}")
        sys.exit(1)

    _print_target_info(target_info)


# ---------------------------------------------------------------
# karadul analyze <target>
# ---------------------------------------------------------------
@main.command()
@click.argument("target", type=str)
@click.option("--stage", type=click.Choice(STAGES, case_sensitive=False),
              default=None, help="Belirli stage'de dur.")
@click.option("--skip-dynamic", is_flag=True,
              help="Dinamik analizi atla.")
@click.option("--output-dir", type=click.Path(), default=None,
              help="Workspace cikti dizini (varsayilan: proje_root/workspaces).")
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Config YAML dosyasi.")
@click.option("--verbose", is_flag=True, help="Debug log.")
@click.option("--use-llm/--no-llm", default=False,
              help="LLM-assisted variable naming (Claude CLI).")
@click.option("--llm-model", default="sonnet",
              help="LLM model alias (varsayilan: sonnet, alternatif: opus).")
@click.option("--use-ml", is_flag=True, default=False,
              help="LLM4Decompile 6.7B ile kod iyilestirme.")
@click.option("--compute-recovery/--no-compute-recovery", default=None,
              help="Hesaplama bazli kurtarma (yavas ama daha dogru tip cikarimi).")
@click.option("--compute", "compute_mode", type=click.Choice(["full", "standard", "off"],  # v1.6.5
              case_sensitive=False), default=None,
              help="Hesaplama kurtarma modu: full (tum katmanlar), standard (varsayilan), off.")
@click.option("--deep/--no-deep", default=None,  # v1.6.5
              help="Derin analiz modu: computation recovery + tum alt-katmanlar aktif.")
@click.option("--output", "clean_output_dir", type=click.Path(), default=None,
              help="Temiz cikti dizini (src/, report.html, naming_map.json vb.).")
@click.option("--format", "output_format", type=click.Choice(["clean", "raw"]),
              default="clean", help="Cikti formati: clean (duzenlenmis) veya raw (ham).")
@click.pass_context
def analyze(
    ctx: click.Context,
    target: str,
    stage: Optional[str],
    skip_dynamic: bool,
    output_dir: Optional[str],
    config_path: Optional[str],
    verbose: bool,
    use_llm: bool,
    llm_model: str,
    use_ml: bool,
    compute_recovery: Optional[bool],
    compute_mode: Optional[str],           # v1.6.5
    deep: Optional[bool],                  # v1.6.5
    clean_output_dir: Optional[str],
    output_format: str,
) -> None:
    """Hedef uzerinde tam analiz pipeline calistir."""
    from karadul.core.pipeline import Pipeline
    from karadul.core.target_resolver import resolve_target

    cfg = _load_config(config_path)

    # v1.9.1: Smart target resolver -- isim, paket adi veya tam yol
    try:
        target_path = resolve_target(target)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]HATA:[/bold red] {exc}")
        sys.exit(1)

    if output_dir:
        cfg.project_root = Path(output_dir).resolve()

    # LLM naming ayarlari
    cfg.analysis.use_llm_naming = use_llm
    cfg.analysis.llm_model = llm_model

    # ML model ayarlari (LLM4Decompile)
    if use_ml:
        cfg.ml.enable_llm4decompile = True

    # Computation recovery ayarlari  # v1.6.5: --deep > --compute > --compute-recovery
    _compute_resolved = False

    if deep is not None:
        # --deep en yuksek oncelik: tum katmanlari acar
        cfg.computation_recovery.enabled = deep
        if deep:
            cfg.computation_recovery.enable_constraint_solver = True
            cfg.computation_recovery.enable_cfg_fingerprint = True
            cfg.computation_recovery.enable_signature_fusion = True
            cfg.computation_recovery.enable_formula_extraction = True
            cfg.deep_trace.enable_deep_trace = True
            cfg.deep_trace.enable_dispatch_resolution = True
            cfg.deep_trace.enable_data_flow = True
            cfg.deep_trace.enable_composition = True
        _compute_resolved = True

    if not _compute_resolved and compute_mode is not None:
        # --compute full|standard|off
        if compute_mode == "full":
            cfg.computation_recovery.enabled = True
            cfg.computation_recovery.enable_constraint_solver = True
            cfg.computation_recovery.enable_cfg_fingerprint = True
            cfg.computation_recovery.enable_signature_fusion = True
            cfg.computation_recovery.enable_formula_extraction = True
        elif compute_mode == "standard":
            cfg.computation_recovery.enabled = True
            # Standart: sadece constraint solver + cfg fingerprint
            cfg.computation_recovery.enable_formula_extraction = False
        elif compute_mode == "off":
            cfg.computation_recovery.enabled = False
        _compute_resolved = True

    if not _compute_resolved and compute_recovery is not None:
        # --compute-recovery / --no-compute-recovery (eski boolean flag, backward compat)
        cfg.computation_recovery.enabled = compute_recovery
        _compute_resolved = True

    if not _compute_resolved and target_path.is_file() and not target_path.suffix:
        # Hicbir flag verilmedi ve hedef binary gibi gorunuyor -- interaktif sor
        console.print()
        console.print("[bold]Enable computation-based recovery?[/bold] (slower but more accurate)")
        console.print("  [cyan][1][/cyan] Yes - Enhanced type inference + CFG matching + formula extraction")
        console.print("  [cyan][0][/cyan] No  - Standard analysis")
        choice = click.prompt("", type=click.IntRange(0, 1), default=0)
        cfg.computation_recovery.enabled = bool(choice)

    # Banner
    _print_banner()

    # Hedef tani
    try:
        detector = TargetDetector()
        target_info = detector.detect(target_path)
    except Exception as exc:
        err_console.print(f"[bold red]HATA:[/bold red] Hedef taninamadi: {exc}")
        sys.exit(1)

    # Target bilgileri
    console.print()
    console.print(f"[bold]Target:[/bold] {target_info.name}")
    console.print(f"[bold]Type:[/bold]   {target_info.target_type.value} ({target_info.language.value})")
    console.print(f"[bold]Size:[/bold]   {_format_size(target_info.file_size)}")
    # v1.6.5: compute/deep mode gostergesi
    if deep:
        console.print("[bold]Mode:[/bold]   [bold magenta]DEEP[/bold magenta] (all layers + deep trace)")
    elif cfg.computation_recovery.enabled:
        _mode_label = compute_mode or ("full" if compute_recovery else "enabled")
        console.print(f"[bold]Compute:[/bold] [cyan]{_mode_label}[/cyan]")
    console.print()

    # Pipeline olustur
    pipeline = Pipeline(cfg)

    # Stage'leri belirle ve kaydet
    active_stage_names = _get_active_stages(stage, skip_dynamic)
    stage_instances = _get_available_stages(active_stage_names)

    if not stage_instances:
        err_console.print("[bold red]HATA:[/bold red] Calistirilacak stage yok.")
        sys.exit(1)

    for st in stage_instances:
        pipeline.register_stage(st)

    # Pipeline calistir
    console.print(Rule("Pipeline", style="cyan"))
    console.print()

    result = pipeline.run(target_path, stages=None)  # Tum kayitli stage'leri calistir

    # Sonuc tablosu
    console.print()

    results_table = Table(
        title="Results",
        border_style="green" if result.success else "yellow",
        show_header=False,
        padding=(0, 2),
    )
    results_table.add_column("Field", style="bold")
    results_table.add_column("Value")

    # Statik analiz sonuclari
    if "static" in result.stages:
        st = result.stages["static"].stats
        functions = st.get('functions_found', st.get('ghidra_function_count', st.get('functions', 0)))
        strings = st.get('strings_found', st.get('ghidra_string_count', st.get('string_count', st.get('strings', 0))))
        results_table.add_row(
            "Functions recovered",
            f"{functions:>10}" if isinstance(functions, int) else "N/A",
        )
        results_table.add_row(
            "Strings found",
            f"{strings:>10}" if isinstance(strings, int) else "N/A",
        )

    # Deobfuscation sonuclari
    if "deobfuscate" in result.stages:
        st = result.stages["deobfuscate"].stats
        results_table.add_row("Deobf steps", str(st.get("steps_completed", "N/A")))

    # Reconstruct sonuclari
    if "reconstruct" in result.stages:
        st = result.stages["reconstruct"].stats
        results_table.add_row("Modules extracted", str(st.get("modules_extracted", "N/A")))
        results_table.add_row("Variables renamed", str(st.get("variables_renamed", "N/A")))
        results_table.add_row("Coverage", f"{st.get('coverage_percent', 'N/A')}%")
        results_table.add_row(
            "Runnable project",
            "YES" if st.get("runnable_project") else "NO",
        )

    # Computation recovery sonuclari
    if "reconstruct" in result.stages:
        st = result.stages["reconstruct"].stats
        comp_structs = st.get("computation_structs_refined")
        if comp_structs is not None:
            results_table.add_row(
                "Computation recovery",
                f"{comp_structs} structs, "
                f"{st.get('computation_arrays_detected', 0)} arrays, "
                f"{st.get('computation_cfg_matches', 0)} CFG matches, "
                f"{st.get('computation_fusion_ids', 0)} fusion IDs",
            )
        elif cfg.computation_recovery.enabled:
            results_table.add_row("Computation recovery", "Enabled (no results yet)")

    results_table.add_row("Workspace", str(result.workspace_path))

    # Report dosyalari
    if "report" in result.stages:
        report_artifacts = result.stages["report"].artifacts
        for rname, rpath in report_artifacts.items():
            results_table.add_row(rname, str(rpath.name) if isinstance(rpath, Path) else str(rpath))

    console.print(results_table)
    console.print()

    # OutputFormatter: --output flag'i verildiyse temiz cikti dizini uret
    if clean_output_dir:
        from karadul.core.output_formatter import OutputFormatter
        from karadul.core.workspace import Workspace

        # Pipeline'in kullandigi workspace'i yeniden olustur (path'ten)
        ws = Workspace.__new__(Workspace)
        ws._workspace_dir = result.workspace_path
        ws._created = True
        ws._base_dir = result.workspace_path.parent.parent
        ws._target_name = result.target_name
        ws._timestamp = result.workspace_path.name

        formatter = OutputFormatter(ws, result)
        out_path = Path(clean_output_dir).resolve()

        console.print(Rule("Output Formatting", style="cyan"))
        console.print(f"  Format: [bold]{output_format}[/bold]")
        console.print(f"  Output: [dim]{out_path}[/dim]")

        fmt_result = formatter.format_output(out_path, fmt=output_format)

        if fmt_result.success:
            console.print(
                f"  [green]OK[/green] {fmt_result.files_written} dosya yazildi"
                f" ({fmt_result.src_files} kaynak, {fmt_result.reports_generated} rapor)"
            )
        else:
            for err in fmt_result.errors:
                console.print(f"  [red]HATA:[/red] {err}")

        console.print()


# ---------------------------------------------------------------
# karadul run <target>
# ---------------------------------------------------------------
@main.command()
@click.argument("target")
@click.option("--workspace-dir", type=click.Path(), default="./workspaces/",
              help="Workspace ust dizini.")
@click.option("--yes", "-y", is_flag=True, help="Guvenlik uyarisini atla.")
def run(target: str, workspace_dir: str, yes: bool) -> None:
    """Reconstructed projeyi calistir.

    targets/{name}/reconstructed/ dizininde npm install && npm start yapar.
    """
    ws_path = Path(workspace_dir).resolve()

    # Target'in workspace'ini bul
    target_dir = ws_path / target

    if not target_dir.exists():
        # Tum alt dizinleri tara
        candidates = [d for d in ws_path.iterdir() if d.is_dir() and d.name == target]
        if not candidates:
            err_console.print(f"[bold red]HATA:[/bold red] Workspace bulunamadi: {target}")
            err_console.print(f"[dim]Aranan dizin: {ws_path}[/dim]")
            sys.exit(1)
        target_dir = candidates[0]

    # reconstructed/ dizinini bul (en son timestamp altinda)
    reconstructed = None

    # Dogrudan reconstructed/ var mi?
    if (target_dir / "reconstructed").is_dir():
        reconstructed = target_dir / "reconstructed"
    else:
        # Timestamp altdizinlerini kontrol et (en yeni)
        timestamps = sorted(
            [d for d in target_dir.iterdir() if d.is_dir()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for ts_dir in timestamps:
            candidate = ts_dir / "reconstructed"
            if candidate.is_dir():
                reconstructed = candidate
                break

    if reconstructed is None or not reconstructed.exists():
        err_console.print(
            f"[bold red]HATA:[/bold red] Reconstructed dizin bulunamadi.\n"
            f"Once 'karadul analyze' ile reconstruct stage'ini calistirin."
        )
        sys.exit(1)

    # Guvenlik uyarisi -- reconstructed kod guvenilmeyen kaynak (CWE-94)
    if not yes:
        console.print(
            "[bold yellow]UYARI:[/bold yellow] Reconstruct edilmis kod "
            "guvenilmeyen kaynaktan gelebilir."
        )
        console.print(f"   Dizin: [cyan]{reconstructed}[/cyan]")
        if not click.confirm("Kodu calistirmak istediginizden emin misiniz?"):
            console.print("[dim]Iptal edildi.[/dim]")
            return

    console.print(Panel(
        f"[bold]{target}[/bold]\n"
        f"Dizin: [cyan]{reconstructed}[/cyan]",
        title="Proje Calistiriliyor",
        border_style="green",
    ))

    # package.json var mi?
    package_json = reconstructed / "package.json"
    if package_json.exists():
        console.print("[dim]npm install --ignore-scripts...[/dim]")
        proc_install = subprocess.run(
            ["npm", "install", "--ignore-scripts"],
            cwd=str(reconstructed),
            capture_output=True,
            text=True,
        )
        if proc_install.returncode != 0:
            err_console.print(f"[yellow]npm install uyarisi:[/yellow] {proc_install.stderr[:200]}")

        console.print("[dim]npm start...[/dim]")
        proc_start = subprocess.run(
            ["npm", "start"],
            cwd=str(reconstructed),
            capture_output=False,
        )
        sys.exit(proc_start.returncode)
    else:
        # Basit JS dosyasi calistir
        js_files = list(reconstructed.glob("*.js"))
        if js_files:
            main_file = js_files[0]
            for f in js_files:
                if f.name in ("index.js", "main.js"):
                    main_file = f
                    break
            console.print(f"[dim]node {main_file.name}...[/dim]")
            proc = subprocess.run(
                ["node", str(main_file)],
                cwd=str(reconstructed),
                capture_output=False,
            )
            sys.exit(proc.returncode)
        else:
            err_console.print("[bold red]HATA:[/bold red] Calistirilacak dosya bulunamadi.")
            sys.exit(1)


# ---------------------------------------------------------------
# karadul list
# ---------------------------------------------------------------
@main.command("list")
@click.option("--output-dir", type=click.Path(), default="./workspaces/",
              help="Workspace dizini.")
def list_targets(output_dir: str) -> None:
    """Analiz edilmis hedefleri listele."""
    output_path = Path(output_dir).resolve()

    if not output_path.exists():
        console.print("[yellow]Henuz analiz edilmis hedef yok.[/yellow]")
        return

    dirs = sorted(
        [d for d in output_path.iterdir() if d.is_dir()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not dirs:
        console.print("[yellow]Henuz analiz edilmis hedef yok.[/yellow]")
        return

    table = Table(title="Analiz Edilmis Hedefler", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Hedef", style="bold")
    table.add_column("Boyut", justify="right")
    table.add_column("Son Degisiklik")

    for i, d in enumerate(dirs, 1):
        # Dizin boyutu hesapla
        total_size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
        mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(d.stat().st_mtime))
        table.add_row(str(i), d.name, _format_size(total_size), mtime)

    console.print(table)


# ---------------------------------------------------------------
# karadul clean <target>
# ---------------------------------------------------------------
@main.command()
@click.argument("target")
@click.option("--output-dir", type=click.Path(), default="./workspaces/",
              help="Workspace dizini.")
@click.confirmation_option(
    prompt="Bu hedefin workspace'ini silmek istediginizden emin misiniz?"
)
def clean(target: str, output_dir: str) -> None:
    """Hedefin workspace dizinini temizle."""
    base_dir = Path(output_dir).resolve()
    workspace_path = (base_dir / target).resolve()

    # Path traversal koruması: workspace_path, base_dir altında olmalı
    if not str(workspace_path).startswith(str(base_dir) + "/") and workspace_path != base_dir:
        err_console.print(f"[bold red]HATA:[/bold red] Gecersiz hedef adi (path traversal engellendi): {target}")
        sys.exit(1)

    if not workspace_path.exists():
        err_console.print(f"[bold red]HATA:[/bold red] Workspace bulunamadi: {workspace_path}")
        sys.exit(1)

    shutil.rmtree(workspace_path)
    console.print(f"[green]Temizlendi:[/green] {workspace_path}")


# ---------------------------------------------------------------
# karadul benchmark <binary_path>
# ---------------------------------------------------------------
@main.command()
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--ground-truth", "-g", type=click.Path(exists=True), default=None,
              help="Ground truth JSON dosyasi. Yoksa nm ile uretilir.")
@click.option("--output", "-o", type=click.Path(), default="benchmark_report.json",
              help="Cikti rapor dosyasi (varsayilan: benchmark_report.json).")
@click.option("--naming-map", "-n", type=click.Path(exists=True), default=None,
              help="Karadul naming_map.json dosyasi. Yoksa workspace'ten aranir.")
@click.option("--generate-gt-only", is_flag=True, default=False,
              help="Sadece ground truth uret, benchmark calistirma.")
def benchmark(
    binary_path: str,
    ground_truth: Optional[str],
    output: str,
    naming_map: Optional[str],
    generate_gt_only: bool,
) -> None:
    """Binary analiz edip accuracy raporu uret.

    Ground truth yoksa nm ile binary'den sembol tablosu cikarir.
    naming_map yoksa en son workspace'ten arar.

    Ornekler:
        karadul benchmark /usr/lib/libsqlite3.dylib -g gt.json -n naming_map.json
        karadul benchmark /usr/lib/libcrypto.dylib --generate-gt-only -o gt.json
    """
    import json as _json

    _print_banner()

    binary = Path(binary_path).resolve()
    output_path = Path(output).resolve()

    console.print()
    console.print(f"[bold]Binary:[/bold] {binary}")
    console.print()

    # --- Ground Truth ---
    if ground_truth:
        # Load from JSON file
        gt_path = Path(ground_truth)
        console.print(f"[dim]Ground truth:[/dim] {gt_path}")
        gt_data = _json.loads(gt_path.read_text(encoding="utf-8"))

        if "symbols" in gt_data:
            # New format: {"symbols": [{"address": ..., "name": ..., "type": ...}]}
            gt_map = {
                s["address"].replace("0x", "FUN_").replace("FUN_", "FUN_"): s["name"]
                for s in gt_data["symbols"]
            }
        else:
            # Simple format: {"FUN_xxx": "name"}
            gt_map = gt_data
    else:
        # Generate ground truth from binary using nm
        console.print("[dim]Generating ground truth from nm...[/dim]")
        try:
            from tests.benchmark.ground_truth_generator import GroundTruthGenerator

            gen = GroundTruthGenerator(demangle=True, include_data=False)
            gt_obj = gen.generate_from_binary(binary)

            if gt_obj.symbol_count == 0:
                err_console.print(
                    "[bold red]HATA:[/bold red] nm'den sembol cikarilamadi. "
                    "Binary'nin export sembolleri var mi?"
                )
                sys.exit(1)

            console.print(
                f"  [green]{gt_obj.symbol_count}[/green] sembol cikarildi "
                f"({gt_obj.function_count} fonksiyon)"
            )

            # Convert to {FUN_xxx: name} format for BenchmarkRunner
            gt_map = {}
            for s in gt_obj.symbols:
                hex_part = s.address.replace("0x", "").lstrip("0") or "0"
                gt_map[f"FUN_{hex_part.zfill(8)}"] = s.name

        except Exception as exc:
            err_console.print(f"[bold red]HATA:[/bold red] Ground truth uretimi basarisiz: {exc}")
            sys.exit(1)

    # Generate-only mode
    if generate_gt_only:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            _json.dumps(gt_map, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"\n[green]Ground truth kaydedildi:[/green] {output_path}")
        console.print(f"[dim]{len(gt_map)} sembol[/dim]")
        return

    # --- Naming Map ---
    if naming_map:
        nm_path = Path(naming_map)
    else:
        # Try to find latest naming_map in workspaces
        ws_base = Path.cwd() / "workspaces"
        nm_path = None
        if ws_base.exists():
            candidates = list(ws_base.rglob("naming_map.json"))
            if candidates:
                nm_path = max(candidates, key=lambda p: p.stat().st_mtime)
                console.print(f"[dim]Naming map (otomatik):[/dim] {nm_path}")

        if nm_path is None:
            err_console.print(
                "[bold red]HATA:[/bold red] naming_map.json bulunamadi. "
                "-n ile belirtin veya once 'karadul analyze' calistirin."
            )
            sys.exit(1)

    console.print(f"[dim]Naming map:[/dim] {nm_path}")
    console.print()

    # --- Benchmark ---
    from tests.benchmark.benchmark_runner import BenchmarkRunner

    runner = BenchmarkRunner(output_dir=output_path.parent)
    result = runner.run_from_naming_map(
        ground_truth_json=Path("/dev/null"),  # Placeholder, we override below
        naming_map_json=nm_path,
        config_info={"binary": str(binary), "ground_truth_source": "nm" if not ground_truth else "json"},
    )

    # Actually run with our gt_map directly (override JSON loading)
    nm_map_raw = _json.loads(nm_path.read_text(encoding="utf-8"))
    # v1.5.5 compat: naming_map.json artik {"global": {...}, "per_function": {...}}
    # olabilir. Benchmark icin flat map (global) kullan.
    if isinstance(nm_map_raw, dict) and "global" in nm_map_raw:
        nm_map = nm_map_raw["global"]
    else:
        nm_map = nm_map_raw
    result = runner.run_mock(gt_map, nm_map, config_info={
        "binary": str(binary),
        "ground_truth_source": "nm" if not ground_truth else "json",
        "ground_truth_symbols": len(gt_map),
    })

    # Save report
    result.save_json(output_path)

    # Display results
    console.print(Rule("Benchmark Results", style="cyan"))
    console.print()

    metrics = result.metrics
    results_table = Table(title="Accuracy Report", border_style="green")
    results_table.add_column("Metrik", style="bold")
    results_table.add_column("Deger", justify="right")

    results_table.add_row("Total Symbols", str(metrics.total_symbols))
    results_table.add_row("Exact Matches", f"[green]{metrics.exact_matches}[/green]")
    results_table.add_row("Semantic Matches", f"[cyan]{metrics.semantic_matches}[/cyan]")
    results_table.add_row("Partial Matches", f"[yellow]{metrics.partial_matches}[/yellow]")
    results_table.add_row("Wrong Names", f"[red]{metrics.wrong_names}[/red]")
    results_table.add_row("Missing Names", f"[red]{metrics.missing_names}[/red]")
    results_table.add_row("", "")
    results_table.add_row("Accuracy", f"[bold]{metrics.accuracy:.1f}%[/bold]")
    results_table.add_row("Recovery Rate", f"[bold]{metrics.recovery_rate:.1f}%[/bold]")

    console.print(results_table)
    console.print()
    console.print(f"[dim]Rapor:[/dim] {output_path}")
    console.print()


# ---------------------------------------------------------------
# karadul batch -- toplu analiz
# ---------------------------------------------------------------
@main.group()
def batch() -> None:
    """Toplu analiz komutlari."""
    pass


@batch.command("analyze")
@click.option("--targets", "-t", required=True,
              help="Hedef grubu: electron, binary, js, cursor, all veya virgule ayrilmis isimler.")
@click.option("--output-dir", type=click.Path(), default=None,
              help="Workspace ust dizini (varsayilan: proje root).")
@click.option("--skip-dynamic", is_flag=True, default=False,
              help="Dinamik analizi atla (varsayilan: False).")
@click.pass_context
def batch_analyze(ctx: click.Context, targets: str, output_dir: Optional[str], skip_dynamic: bool) -> None:
    """Tum hedefleri toplu analiz et.

    Electron uygulamalari, JS bundle'lari ve native binary'leri
    sirayla pipeline'dan gecirir.

    Ornekler:
        karadul batch analyze --targets electron
        karadul batch analyze --targets binary
        karadul batch analyze --targets all
        karadul batch analyze --targets discord,poe,avast
    """
    import json

    from karadul.batch import resolve_targets, analyze_parallel, PARALLEL_WORKERS, BatchTargetResult

    _print_banner()

    resolved = resolve_targets(targets)

    if not resolved:
        err_console.print("[bold red]HATA:[/bold red] Gecerli hedef bulunamadi.")
        sys.exit(1)

    workers = min(3, len(resolved))
    console.print(f"\n[bold]Batch Analysis:[/bold] {len(resolved)} hedef, {workers} paralel worker")
    console.print(f"[dim]Hedefler: {', '.join(resolved.keys())}[/dim]\n")

    project_root = Path(output_dir).resolve() if output_dir else Path.cwd()

    def on_complete(result):
        if result.skipped:
            console.print(f"  [yellow]{result.name}: ATLANDI[/yellow] {result.skip_reason}")
        elif result.success:
            console.print(f"  [green]{result.name}: BASARILI[/green] ({result.duration:.1f}s)")
        else:
            console.print(f"  [red]{result.name}: BASARISIZ[/red] ({result.duration:.1f}s)")

    results = analyze_parallel(
        resolved, project_root,
        skip_dynamic=skip_dynamic,
        max_workers=workers,
        callback=on_complete,
    )

    # Ozet tablosu
    summary_table = Table(title="Batch Summary", border_style="cyan")
    summary_table.add_column("#", style="dim", width=3)
    summary_table.add_column("Target", style="bold")
    summary_table.add_column("Category")
    summary_table.add_column("Status")
    summary_table.add_column("Functions", justify="right")
    summary_table.add_column("Strings", justify="right")
    summary_table.add_column("Duration", justify="right")

    for i, r in enumerate(results, 1):
        if r.skipped:
            status = "[yellow]SKIP[/yellow]"
        elif r.success:
            status = "[green]OK[/green]"
        else:
            status = "[red]FAIL[/red]"

        summary_table.add_row(
            str(i), r.name, r.category, status,
            str(r.functions_found) if not r.skipped else "-",
            str(r.strings_found) if not r.skipped else "-",
            f"{r.duration:.1f}s" if not r.skipped else "-",
        )

    console.print(summary_table)

    # Rapor kaydet
    report_path = project_root / "workspaces" / "batch_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_targets": len(results),
        "successful": sum(1 for r in results if r.success),
        "failed": sum(1 for r in results if not r.success and not r.skipped),
        "skipped": sum(1 for r in results if r.skipped),
        "results": [r.to_dict() for r in results],
    }
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    console.print(f"\n[dim]Rapor: {report_path}[/dim]")


# ---------------------------------------------------------------
# karadul diff -- binary diffing
# ---------------------------------------------------------------
@main.command()
@click.argument("binary1", type=click.Path(exists=True))
@click.argument("binary2", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Cikti dizini.")
@click.option("--json-mode", is_flag=True,
              help="Onceden uretilmis JSON'lari karsilastir (Ghidra gerektirmez).")
@click.option("--config", "config_path", type=click.Path(exists=True),
              help="Config dosyasi.")
def diff(
    binary1: str,
    binary2: str,
    output: Optional[str],
    json_mode: bool,
    config_path: Optional[str],
) -> None:
    """Iki binary arasindaki farklari goster.

    Iki binary versiyonunu karsilastirarak eklenen, silinen ve
    degistirilen fonksiyonlari listeler.

    Ornekler:
        karadul diff v1.bin v2.bin
        karadul diff --json-mode funcs_v1.json funcs_v2.json -o ./diff_out
    """
    from karadul.ghidra.program_diff import GhidraProgramDiff

    _print_banner()

    cfg = _load_config(config_path)
    differ = GhidraProgramDiff(cfg)

    path1 = Path(binary1).resolve()
    path2 = Path(binary2).resolve()
    output_dir = Path(output).resolve() if output else None

    console.print()
    console.print(f"[bold]Binary 1:[/bold] {path1.name}")
    console.print(f"[bold]Binary 2:[/bold] {path2.name}")
    console.print(f"[bold]Mod:[/bold]      {'JSON fallback' if json_mode else 'PyGhidra'}")
    console.print()

    try:
        if json_mode:
            report = differ.diff_from_json(path1, path2, output_dir)
        else:
            report = differ.diff(path1, path2, output_dir)
    except RuntimeError as exc:
        err_console.print(f"[bold red]HATA:[/bold red] {exc}")
        sys.exit(1)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]HATA:[/bold red] {exc}")
        sys.exit(1)
    except Exception as exc:
        err_console.print(f"[bold red]HATA:[/bold red] Diff basarisiz: {exc}")
        sys.exit(1)

    # Ozet tablo
    console.print(Rule("Diff Summary", style="cyan"))
    console.print()

    summary = report.summary
    summary_table = Table(show_header=False, border_style="cyan", padding=(0, 2))
    summary_table.add_column("Metrik", style="bold")
    summary_table.add_column("Deger", justify="right")

    summary_table.add_row("Functions (binary 1)", str(summary.total_functions_1))
    summary_table.add_row("Functions (binary 2)", str(summary.total_functions_2))
    summary_table.add_row("Added", f"[green]+{summary.functions_added}[/green]")
    summary_table.add_row("Removed", f"[red]-{summary.functions_removed}[/red]")
    summary_table.add_row("Modified", f"[yellow]~{summary.functions_modified}[/yellow]")
    summary_table.add_row("Unchanged", str(summary.functions_unchanged))
    summary_table.add_row(
        "Change rate",
        f"{summary.change_rate:.1%}",
    )
    summary_table.add_row("Duration", f"{report.duration_seconds:.3f}s")

    console.print(summary_table)
    console.print()

    # Degisen fonksiyonlar tablosu (added + removed + modified)
    changed = [d for d in report.function_diffs if d.status != "unchanged"]
    if changed:
        console.print(Rule("Changed Functions", style="cyan"))
        console.print()

        func_table = Table(
            title=f"{len(changed)} degisiklik",
            border_style="cyan",
        )
        func_table.add_column("Status", width=10)
        func_table.add_column("Function", style="bold")
        func_table.add_column("Address (v1)", style="dim")
        func_table.add_column("Address (v2)", style="dim")
        func_table.add_column("Size", justify="right")
        func_table.add_column("Instr", justify="right")

        # Siralama: removed > modified > added
        status_order = {"removed": 0, "modified": 1, "added": 2}
        changed.sort(key=lambda d: (status_order.get(d.status, 3), d.name))

        for fd in changed[:100]:  # ilk 100
            if fd.status == "added":
                status_text = "[green]+ ADDED[/green]"
            elif fd.status == "removed":
                status_text = "[red]- REMOVED[/red]"
            elif fd.status == "modified":
                status_text = "[yellow]~ MODIFIED[/yellow]"
            else:
                status_text = fd.status

            size_text = ""
            if fd.size_change > 0:
                size_text = f"[green]+{fd.size_change}[/green]"
            elif fd.size_change < 0:
                size_text = f"[red]{fd.size_change}[/red]"
            elif fd.status == "modified":
                size_text = "0"

            instr_text = ""
            if fd.instruction_diff is not None:
                if fd.instruction_diff > 0:
                    instr_text = f"[green]+{fd.instruction_diff}[/green]"
                elif fd.instruction_diff < 0:
                    instr_text = f"[red]{fd.instruction_diff}[/red]"
                else:
                    instr_text = "0"

            func_table.add_row(
                status_text,
                fd.name,
                fd.address1 or "-",
                fd.address2 or "-",
                size_text,
                instr_text,
            )

        console.print(func_table)

        if len(changed) > 100:
            console.print(f"[dim]... ve {len(changed) - 100} degisiklik daha[/dim]")

        console.print()
    else:
        console.print("[green]Iki binary arasinda fonksiyon farki bulunamadi.[/green]")
        console.print()

    if output:
        console.print(f"[dim]Rapor: {Path(output).resolve() / 'diff_report.json'}[/dim]")
        console.print()


# ---------------------------------------------------------------
# karadul bsim -- BSim fonksiyon benzerlik veritabani yonetimi
# ---------------------------------------------------------------
@main.group()
def bsim() -> None:
    """BSim fonksiyon benzerlik veritabani yonetimi."""
    pass


@bsim.command("create")
@click.argument("name")
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Config YAML dosyasi.")
def bsim_create(name: str, config_path: Optional[str]) -> None:
    """Yeni BSim veritabani olustur."""
    from karadul.ghidra.bsim import BSimDatabase

    cfg = _load_config(config_path)
    db = BSimDatabase(cfg)
    db_path = db.create_database(name)
    console.print(f"[green]BSim veritabani olusturuldu:[/green] {name}")
    console.print(f"[dim]Mod: {db.mode} | Konum: {db.db_path}[/dim]")
    db.close()


@bsim.command("ingest")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--db", "db_name", default="karadul_bsim",
              help="Hedef veritabani adi (varsayilan: karadul_bsim).")
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Config YAML dosyasi.")
def bsim_ingest(binary: str, db_name: str, config_path: Optional[str]) -> None:
    """Binary'yi BSim veritabanina ekle.

    PyGhidra uzerinden binary analiz edilir ve fonksiyon hash'leri
    veritabanina eklenir.
    """
    from karadul.ghidra.bsim import BSimDatabase

    cfg = _load_config(config_path)
    binary_path = Path(binary).resolve()

    console.print(f"[bold]Binary:[/bold] {binary_path}")
    console.print(f"[bold]DB:[/bold]     {db_name}")

    try:
        import pyghidra
        pyghidra.start()

        with pyghidra.open_program(str(binary_path)) as flat_api:
            program = flat_api.getCurrentProgram()
            db = BSimDatabase(cfg)
            count = db.ingest_program(program, db_name)
            console.print(
                f"[green]Basarili:[/green] {count} fonksiyon hash'lendi "
                f"(mod: {db.mode})"
            )
            db.close()
    except ImportError:
        err_console.print(
            "[bold red]HATA:[/bold red] PyGhidra bulunamadi. "
            "Ghidra + PyGhidra kurulu olmali."
        )
        sys.exit(1)
    except Exception as exc:
        err_console.print(f"[bold red]HATA:[/bold red] {exc}")
        sys.exit(1)


@bsim.command("query")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--db", "db_name", default="karadul_bsim",
              help="Sorgulanacak veritabani adi (varsayilan: karadul_bsim).")
@click.option("--min-similarity", default=0.7, type=float,
              help="Minimum benzerlik esigi (varsayilan: 0.7).")
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Config YAML dosyasi.")
def bsim_query(
    binary: str, db_name: str, min_similarity: float, config_path: Optional[str],
) -> None:
    """BSim veritabaninda benzer fonksiyonlari ara.

    Binary'deki fonksiyonlar icin veritabaninda eslesmeler aranir.
    """
    from karadul.ghidra.bsim import BSimDatabase

    cfg = _load_config(config_path)
    binary_path = Path(binary).resolve()

    console.print(f"[bold]Binary:[/bold]      {binary_path}")
    console.print(f"[bold]DB:[/bold]          {db_name}")
    console.print(f"[bold]Min benzerlik:[/bold] {min_similarity}")
    console.print()

    try:
        import pyghidra
        pyghidra.start()

        with pyghidra.open_program(str(binary_path)) as flat_api:
            program = flat_api.getCurrentProgram()
            db = BSimDatabase(cfg)
            result = db.query_all_functions(program, min_similarity)

            # Sonuc tablosu
            if result.total_matches > 0:
                match_table = Table(
                    title=f"BSim Eslesmeleri ({result.total_matches} toplam)",
                    border_style="cyan",
                )
                match_table.add_column("Fonksiyon", style="bold")
                match_table.add_column("Adres", style="dim")
                match_table.add_column("Eslesen", style="green")
                match_table.add_column("Program", style="cyan")
                match_table.add_column("Benzerlik", justify="right")

                for m in result.matches[:50]:  # ilk 50
                    sim_color = "green" if m.similarity >= 0.9 else "yellow"
                    match_table.add_row(
                        m.query_function,
                        m.query_address,
                        m.matched_function,
                        m.matched_program,
                        f"[{sim_color}]{m.similarity:.2f}[/{sim_color}]",
                    )
                console.print(match_table)
            else:
                console.print("[yellow]Esleme bulunamadi.[/yellow]")

            console.print(
                f"\n[dim]Sorgulanan: {result.total_queries} | "
                f"Eslesen: {result.total_matches} | "
                f"Sure: {result.query_duration:.2f}s[/dim]"
            )
            db.close()
    except ImportError:
        err_console.print(
            "[bold red]HATA:[/bold red] PyGhidra bulunamadi."
        )
        sys.exit(1)
    except Exception as exc:
        err_console.print(f"[bold red]HATA:[/bold red] {exc}")
        sys.exit(1)


@bsim.command("list")
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Config YAML dosyasi.")
def bsim_list(config_path: Optional[str]) -> None:
    """Mevcut BSim veritabanlarini listele."""
    from karadul.ghidra.bsim import BSimDatabase

    cfg = _load_config(config_path)
    db = BSimDatabase(cfg)
    databases = db.list_databases()

    if not databases:
        console.print("[yellow]Henuz BSim veritabani yok.[/yellow]")
        console.print(f"[dim]Konum: {db.db_path}[/dim]")
        db.close()
        return

    table = Table(title="BSim Veritabanlari", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Ad", style="bold")
    table.add_column("Mod", style="cyan")
    table.add_column("Program", justify="right")
    table.add_column("Fonksiyon", justify="right")

    for i, db_info in enumerate(databases, 1):
        table.add_row(
            str(i),
            db_info.get("name", "?"),
            db_info.get("mode", "?"),
            str(db_info.get("program_count", "?")),
            str(db_info.get("function_count", "?")),
        )

    console.print(table)
    console.print(f"\n[dim]Konum: {db.db_path}[/dim]")
    db.close()
