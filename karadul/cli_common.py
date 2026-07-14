"""
karadul.cli_common -- CLI ortak yardimcilar (B17 refactor).

Bu modul `karadul/cli.py` (Click tabanli klasik CLI) ve
`karadul/hacker_cli.py` (Rich Live tabanli hacker dashboard) arasinda
*tekrar eden* iki parcayi merkezilestirir:

1. `format_size(size)` -- byte -> insanca okunabilir string. Onceden
   her iki dosyada birebir kopya olarak (`_format_size`) yasiyordu;
   yeni stage eklenince iki yer guncellemek gerekiyordu.
2. `build_pipeline(config, ...)` -- Pipeline kurulumu ve stage register
   mantigi. Onceden cli.py:577-589 ve hacker_cli.py:1091-1103 ayri ayri
   yapiyordu. Yeni stage eklendiginde tek yerden eklenmesi yeterli.

Tasarim notlari:
- `build_pipeline` esnek kullanilabilir: cli.py karmasik filtreleme
  (--stage stop_after + --skip-dynamic) icin `stages=` parametresi ile
  cagirir; hacker_cli.py default davranis (tum stage'ler) icin
  parametresiz cagirir.
- ReconstructionStage opsiyonel (ImportError tolere edilir).
- `format_size` public (underscore yok) -- iki tarafdan da
  `from karadul.cli_common import format_size` ile import edilir.

B17 sprint, 2026-05-14.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable, Iterable, Optional

if TYPE_CHECKING:
    from karadul.config import Config
    from karadul.core.pipeline import Pipeline
    from rich.progress import Progress, TaskID

logger = logging.getLogger("karadul")


# ---------------------------------------------------------------------------
# Stage isimleri -- pipeline sirasina gore. cli.py'daki STAGES listesinin
# kanonik kopyasi. Yeni stage eklendiginde BURAYA eklenmeli (cli.py icin
# ayrica STAGES degiskeni Click choice icin lazim ama ondan da bu
# modulden referans veriliyor).
# ---------------------------------------------------------------------------
DEFAULT_STAGE_ORDER: tuple[str, ...] = (
    "identify",
    "static",
    "dynamic",
    "deobfuscate",
    "reconstruct",
    "report",
)


def format_size(size: int) -> str:
    """Byte degerini insanca okunabilir formata cevir.

    Args:
        size: Byte cinsinden boyut (>= 0).

    Returns:
        "423 B", "12.3 KB", "1.5 MB", "2.10 GB" gibi formatlanmis string.

    Ornekler:
        >>> format_size(512)
        '512 B'
        >>> format_size(2048)
        '2.0 KB'
        >>> format_size(1572864)
        '1.5 MB'
    """
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def _resolve_stage_classes(requested: Iterable[str]) -> list:
    """Istenen stage isim listesini somut stage sinif INSTANCE'larina cevir.

    ReconstructionStage opsiyonel (ImportError tolere edilir). Diger
    stage'ler `karadul.stages` paketinde her zaman bulunmalidir.

    Args:
        requested: Stage isimleri ("identify", "static", "dynamic",
                   "deobfuscate", "reconstruct", "report").

    Returns:
        Instantiate edilmis stage objeleri listesi (`requested` sirasinda).
        Bilinmeyen veya ImportError olan stage'ler atlanir.
    """
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

    # ReconstructionStage opsiyonel (LLM/ML bagimliliklari yoksa atlar).
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
        else:
            logger.debug("Bilinmeyen stage atlandi: %s", name)
    return instances


def filter_stages(
    *,
    stop_after: Optional[str] = None,
    skip_dynamic: bool = False,
) -> list[str]:
    """Default sira uzerinde filtre uygulayarak aktif stage isim listesini dondur.

    Args:
        stop_after: Bu stage'den sonrasini at (dahil bu stage). None ise
                    tumu.
        skip_dynamic: True ise "dynamic" stage'i listeden cikar.

    Returns:
        Filtre uygulanmis stage isim listesi (DEFAULT_STAGE_ORDER sirasinda).
    """
    stages = list(DEFAULT_STAGE_ORDER)

    if skip_dynamic and "dynamic" in stages:
        stages.remove("dynamic")

    if stop_after:
        try:
            idx = stages.index(stop_after)
            stages = stages[: idx + 1]
        except ValueError:
            # Bilinmeyen stop_after -> tum stage'ler kalir
            pass

    return stages


def build_pipeline(
    config: "Config",
    *,
    stages: Optional[Iterable[str]] = None,
    stop_after: Optional[str] = None,
    skip_dynamic: bool = False,
) -> "Pipeline":
    """Pipeline olustur, istenen stage'leri register et ve geri dondur.

    Iki kullanim sekli vardir:

    1. Filtre uygulama (cli.py klasik mod):
        ``build_pipeline(cfg, stop_after="static", skip_dynamic=True)``
        -> DEFAULT_STAGE_ORDER'dan filtrelenmis liste register edilir.

    2. Explicit stage listesi (gelistirici / hacker_cli.py varyant):
        ``build_pipeline(cfg, stages=["identify", "static", "report"])``
        -> Tam o sira ile register edilir.

    Eger her ikisi de None ise tum default stage'ler register edilir.

    Args:
        config: `karadul.config.Config` instance.
        stages: Explicit stage isim listesi. Verilirse `stop_after` ve
                `skip_dynamic` parametreleri yok sayilir.
        stop_after: Bu stage'de dur (dahil). Sadece `stages` None ise
                    kullanilir.
        skip_dynamic: "dynamic" stage'i atla. Sadece `stages` None ise
                      kullanilir.

    Returns:
        Stage'leri register edilmis `Pipeline` instance.

    Raises:
        Caglir tarafa hicbir exception yumuselendir-MIYOR. Pipeline'in
        kendi `__init__`'i veya stage import'lari hata uretirse yukseltir.
    """
    from karadul.core.pipeline import Pipeline

    if stages is None:
        stage_names = filter_stages(
            stop_after=stop_after, skip_dynamic=skip_dynamic,
        )
    else:
        stage_names = list(stages)

    pipeline = Pipeline(config)
    stage_instances = _resolve_stage_classes(stage_names)
    for stage in stage_instances:
        pipeline.register_stage(stage)

    return pipeline


def make_progress_callbacks(
    progress: "Progress",
    task_id: "TaskID",
    stage_labels: Optional[dict[str, str]] = None,
) -> tuple[
    Callable[[str, int, int], None],
    Callable[[str, Any, int, int], None],
    Callable[[str, str, float], None],
]:
    """Tek satirlik `rich.progress.Progress` bar icin pipeline callback'leri uret.

    `karadul.core.pipeline.Pipeline.run` uc opsiyonel callback kabul eder
    (`on_stage_start`, `on_stage_complete`, `on_progress`). Bu helper onlari
    verilen `progress` bar / `task_id` uzerine baglar. `hacker_cli.py`'nin tam
    Live dashboard'i DEGIL -- sade tek satir ilerleme cubugu (cli.py analyze).

    Bar'in `total`'i pipeline stage sayisina esit olmalidir; her stage bitince
    `advance=1` ile ilerler. Alt-ilerleme (`on_progress`) sadece aciklama
    metnini gunceller (bar konumunu degil), boylece uzun Ghidra decompile
    sirasinda ekran sessiz kalmaz.

    Args:
        progress: Aktif (context icinde acilmis) Rich Progress instance'i.
        task_id: `progress.add_task(...)` ile olusturulmus task kimligi.
        stage_labels: Stage adi -> insanca etiket eslemesi (opsiyonel). Yoksa
                      stage adi Title Case yapilir.

    Returns:
        `(on_stage_start, on_stage_complete, on_progress)` uclusu. Dogrudan
        `pipeline.run(..., on_stage_start=..., ...)` icine gecirilebilir.
    """
    labels = stage_labels or {}

    def _label(name: str) -> str:
        return labels.get(name, name.replace("_", " ").title())

    def on_stage_start(stage_name: str, index: int, total: int) -> None:
        progress.update(
            task_id,
            description=f"[cyan]{_label(stage_name)}[/cyan]",
        )

    def on_stage_complete(
        stage_name: str, result: Any, index: int, total: int,
    ) -> None:
        # result.success yoksa (savunmaci) yine de ilerlet.
        ok = getattr(result, "success", True)
        marker = "[green]OK[/green]" if ok else "[yellow]![/yellow]"
        progress.update(
            task_id,
            advance=1,
            description=f"{marker} [dim]{_label(stage_name)}[/dim]",
        )

    def on_progress(stage_name: str, message: str, fraction: float) -> None:
        desc = f"[cyan]{_label(stage_name)}[/cyan]"
        if message:
            desc += f" [dim]{message}[/dim]"
        progress.update(task_id, description=desc)

    return on_stage_start, on_stage_complete, on_progress


__all__ = [
    "DEFAULT_STAGE_ORDER",
    "format_size",
    "filter_stages",
    "build_pipeline",
    "make_progress_callbacks",
]
