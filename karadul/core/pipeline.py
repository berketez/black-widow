"""6-stage pipeline orkestrasyonu.

Pipeline, Stage nesnelerini sirali calistirir. Her stage bir oncekinin
sonuclarina PipelineContext uzerinden erisir. ErrorRecovery ile
otomatik yeniden deneme ve circuit breaker korumasini saglar.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..config import Config
from .error_recovery import ErrorRecovery
from .result import PipelineResult, StageResult
from .target import TargetDetector, TargetInfo
from .workspace import Workspace

logger = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Pipeline Context -- stage'ler arasi paylasilan veri
# ---------------------------------------------------------------------------

@dataclass
class PipelineContext:
    """Stage'ler arasi paylasilan baglamdir.

    Her stage bu context'e eriserek:
    - Hedef bilgilerine (target) ulasilir.
    - Workspace uzerinden artifact kaydetme/yukleme yapilir.
    - Onceki stage sonuclarina (results) bakilir.
    - Config'den parametreler okunur.

    Attributes:
        target: Tespit edilen hedef bilgileri.
        workspace: Calisma dizini yoneticisi.
        config: Merkezi konfigurasyon.
        results: Onceki stage sonuclari (stage_name -> StageResult).
        extra: Stage'lerin kendi aralarinda paylasmak istedigi ek veri.
    """

    target: TargetInfo
    workspace: Workspace
    config: Config
    results: dict[str, StageResult] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)  # v1.9.1: stage'ler arasi metadata
    _progress_callback: Optional[Callable[[str, str, float], None]] = field(
        default=None, repr=False,
    )

    def get_artifact_path(self, stage: str, name: str) -> Path | None:
        """Onceki bir stage'in artifact yolunu dondur."""
        if stage in self.results:
            return self.results[stage].artifacts.get(name)
        return None

    def has_stage_succeeded(self, stage: str) -> bool:
        """Belirli bir stage basarili mi kontrol et."""
        return stage in self.results and self.results[stage].success

    def report_progress(self, message: str, fraction: float = -1.0) -> None:
        """Aktif stage'in alt-ilerleme bilgisini raporla.

        Args:
            message: Gosterilecek mesaj (orn: "Naming module 47/200").
            fraction: 0.0-1.0 arasi ilerleme orani. -1 = belirsiz.
        """
        if self._progress_callback is not None:
            try:
                self._progress_callback(
                    self.extra.get("_current_stage", ""), message, fraction,
                )
            except Exception:
                logger.debug("Progress callback basarisiz, atlaniyor", exc_info=True)


# ---------------------------------------------------------------------------
# Abstract Stage
# ---------------------------------------------------------------------------

class Stage(ABC):
    """Pipeline asamasi temel sinifi.

    Her somut stage bu siniftan turemeli ve ``execute`` metodunu
    implement etmelidir.

    Attributes:
        name: Asama adi (benzersiz olmali).
        requires: Bu stage calistirilmadan once basarili olmasi gereken stage isimleri.
    """

    name: str = "unnamed"
    requires: tuple[str, ...] = ()

    @abstractmethod
    def execute(self, context: PipelineContext) -> StageResult:
        """Stage'i calistir ve sonuc dondur.

        Args:
            context: Pipeline baglami.

        Returns:
            StageResult: Calisma sonucu.
        """
        ...

    def __repr__(self) -> str:
        return f"<Stage: {self.name}>"


# ---------------------------------------------------------------------------
# Live Log Handler -- canli log yakalama
# ---------------------------------------------------------------------------

class LiveLogHandler(logging.Handler):
    """Logging mesajlarini deque buffer'a yonlendirir.

    Pipeline Live dashboard'u bu buffer'dan okuyarak
    log stream panelini gunceller.
    """

    def __init__(self, buffer: deque, max_level: int = logging.DEBUG) -> None:
        super().__init__(level=max_level)
        self.buffer = buffer
        self.setFormatter(logging.Formatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self.buffer.append(msg)
        except Exception:
            logger.debug("Log record format/buffer basarisiz, atlaniyor", exc_info=True)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class Pipeline:
    """Stage'leri sirali calistiran ana orkestrator.

    Kullanim:
        config = Config.load()
        pipeline = Pipeline(config)
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(DeobfuscationStage())
        result = pipeline.run("/path/to/target")

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._stages: dict[str, Stage] = {}
        self._stage_order: list[str] = []
        self._detector = TargetDetector()
        self._recovery = ErrorRecovery(config.retry)

    def register_stage(self, stage: Stage) -> None:
        """Pipeline'a yeni bir stage ekle.

        Stage'ler ekleme sirasina gore calistirilir.

        Args:
            stage: Eklenecek stage instance'i.

        Raises:
            ValueError: Ayni isimde bir stage zaten varsa.
        """
        if stage.name in self._stages:
            raise ValueError(f"Stage zaten kayitli: {stage.name}")
        self._stages[stage.name] = stage
        self._stage_order.append(stage.name)
        logger.debug("Stage kaydedildi: %s (requires: %s)", stage.name, stage.requires)

    def run(
        self,
        target_path: str | Path,
        stages: list[str] | None = None,
        on_stage_start: Optional[Callable[[str, int, int], None]] = None,
        on_stage_complete: Optional[Callable[[str, "StageResult", int, int], None]] = None,
        on_progress: Optional[Callable[[str, str, float], None]] = None,
        log_buffer: Optional[deque] = None,
    ) -> PipelineResult:
        """Pipeline'i calistir.

        Args:
            target_path: Analiz edilecek hedef yolu.
            stages: Calistirilacak stage isimleri (None = tumu).
            on_stage_start: Stage baslarken cagrilan callback(stage_name, index, total).
            on_stage_complete: Stage bitince cagrilan callback(stage_name, result, index, total).
            on_progress: Alt-ilerleme callback(stage_name, message, fraction).
            log_buffer: Canli log satirlarini yakalamak icin deque. Verilirse
                        LiveLogHandler otomatik eklenir/kaldirilir.

        Returns:
            PipelineResult: Tum sonuclarin ozeti.
        """
        pipeline_start = time.monotonic()

        # Quiet mode: callback verilmisse kendi console output'unu kapat
        # (hacker_cli kendi Live dashboard'unu kullaniyor)
        _quiet = on_stage_start is not None or on_stage_complete is not None

        def _print(msg: str) -> None:
            if not _quiet:
                console.print(msg)

        # 1) Target detection
        _print(f"\n[bold blue]Hedef tespit ediliyor:[/] {target_path}")
        target_info = self._detector.detect(target_path)
        # Buyuk binary tespiti
        threshold_bytes = (
            self._config.binary_reconstruction.large_binary_threshold_mb
            * 1024 * 1024
        )
        is_large_binary = target_info.file_size > threshold_bytes
        size_label = (
            f"[bold yellow]{target_info.file_size / (1024 * 1024):.0f} MB "
            f"(BUYUK BINARY)[/]"
            if is_large_binary
            else f"{target_info.file_size:,} bytes"
        )

        _print(
            f"  Tip: [green]{target_info.target_type.value}[/] | "
            f"Dil: [green]{target_info.language.value}[/] | "
            f"Boyut: {size_label}"
        )

        if is_large_binary:
            _print(
                "  [yellow]Buyuk binary modu aktif:[/] chunked Ghidra analizi, "
                "mmap string extraction, lazy string loading"
            )
            logger.info(
                "Buyuk binary tespit edildi: %.0f MB (esik: %d MB)",
                target_info.file_size / (1024 * 1024),
                self._config.binary_reconstruction.large_binary_threshold_mb,
            )

        # 2) Workspace olustur
        workspace = Workspace(
            base_dir=self._config.project_root / "workspaces",
            target_name=target_info.name,
        )
        workspace.create()
        _print(f"  Workspace: [dim]{workspace.path}[/]")

        # Target info'yu workspace'e kaydet
        workspace.save_json("raw", "target_info", target_info.to_dict())

        # 3) Context olustur
        context = PipelineContext(
            target=target_info,
            workspace=workspace,
            config=self._config,
            extra={"is_large_binary": is_large_binary},
            _progress_callback=on_progress,
        )

        # Log capture -- canli log stream icin
        _log_handler: Optional[LiveLogHandler] = None
        _prev_log_level: Optional[int] = None
        if log_buffer is not None:
            _log_handler = LiveLogHandler(log_buffer)
            karadul_logger = logging.getLogger("karadul")
            _prev_log_level = karadul_logger.level
            karadul_logger.setLevel(logging.DEBUG)
            karadul_logger.addHandler(_log_handler)

        # 4) Pipeline result
        pipeline_result = PipelineResult(
            target_name=target_info.name,
            target_hash=target_info.file_hash,
            workspace_path=workspace.path,
        )

        # 5) Calistirilacak stage'leri belirle
        run_order = self._resolve_run_order(stages)

        if not run_order:
            _print("[yellow]Calistirilacak stage yok.[/]")
            pipeline_result.total_duration = time.monotonic() - pipeline_start
            return pipeline_result

        # 6) Stage'leri sirali calistir
        if _quiet:
            # Quiet mode: Progress bar yok, sadece callback'ler ile calis
            for stage_idx, stage_name in enumerate(run_order):
                stage = self._stages[stage_name]

                missing = self._check_dependencies(stage, context)
                if missing:
                    error_msg = (
                        f"Stage [{stage_name}] bagimliliklari karsilanmadi: "
                        f"{', '.join(missing)}"
                    )
                    logger.error(error_msg)
                    result = StageResult(
                        stage_name=stage_name, success=False,
                        duration_seconds=0.0, errors=[error_msg],
                    )
                    context.results[stage_name] = result
                    pipeline_result.add_stage_result(result)
                    if on_stage_complete:
                        try:
                            on_stage_complete(stage_name, result, stage_idx, len(run_order))
                        except Exception:
                            logger.debug("on_stage_complete callback basarisiz, atlaniyor", exc_info=True)
                    continue

                context.extra["_current_stage"] = stage_name
                if on_stage_start:
                    try:
                        on_stage_start(stage_name, stage_idx, len(run_order))
                    except Exception:
                        logger.debug("on_stage_start callback basarisiz, atlaniyor", exc_info=True)

                result = self._execute_stage(stage, context)
                context.results[stage_name] = result
                pipeline_result.add_stage_result(result)

                if on_stage_complete:
                    try:
                        on_stage_complete(stage_name, result, stage_idx, len(run_order))
                    except Exception:
                        logger.debug("on_stage_complete callback basarisiz, atlaniyor", exc_info=True)
        else:
            # Normal mode: Rich Progress bar ile calistir
            _print(f"\n[bold]Pipeline baslatiliyor ({len(run_order)} stage)...[/]\n")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                pipeline_task = progress.add_task(
                    "Pipeline", total=len(run_order),
                )

                for stage_idx, stage_name in enumerate(run_order):
                    stage = self._stages[stage_name]

                    missing = self._check_dependencies(stage, context)
                    if missing:
                        error_msg = (
                            f"Stage [{stage_name}] bagimliliklari karsilanmadi: "
                            f"{', '.join(missing)}"
                        )
                        logger.error(error_msg)
                        result = StageResult(
                            stage_name=stage_name, success=False,
                            duration_seconds=0.0, errors=[error_msg],
                        )
                        context.results[stage_name] = result
                        pipeline_result.add_stage_result(result)
                        progress.update(pipeline_task, advance=1)
                        continue

                    context.extra["_current_stage"] = stage_name
                    progress.update(
                        pipeline_task,
                        description=f"[bold cyan]{stage_name}[/]",
                    )
                    result = self._execute_stage(stage, context)
                    context.results[stage_name] = result
                    pipeline_result.add_stage_result(result)
                    progress.update(pipeline_task, advance=1)

                    status_icon = "[green]OK[/]" if result.success else "[red]FAIL[/]"
                    console.print(
                        f"  {status_icon} {stage_name}: "
                        f"{result.duration_seconds:.1f}s, "
                        f"{len(result.artifacts)} artifact"
                    )
                    if result.errors:
                        for err in result.errors:
                            console.print(f"    [red]  {err}[/]")

        # 7) Log handler temizle
        if _log_handler is not None:
            karadul_logger = logging.getLogger("karadul")
            karadul_logger.removeHandler(_log_handler)
            if _prev_log_level is not None:
                karadul_logger.setLevel(_prev_log_level)

        # 8) Sonuclari kaydet
        pipeline_result.total_duration = time.monotonic() - pipeline_start
        workspace.save_json("reports", "pipeline_result", pipeline_result.to_dict())

        # Ozet
        _print(f"\n{pipeline_result.summary()}\n")

        return pipeline_result

    def _execute_stage(self, stage: Stage, context: PipelineContext) -> StageResult:
        """Tek bir stage'i ErrorRecovery ile calistir."""
        start = time.monotonic()

        try:
            result = self._recovery.execute(
                stage.execute,
                f"stage_{stage.name}",
                context,
            )
            # Stage kendi StageResult'ini dondurmelidir
            if not isinstance(result, StageResult):
                result = StageResult(
                    stage_name=stage.name,
                    success=True,
                    duration_seconds=time.monotonic() - start,
                )
            # Sureyi guncelle (retry nedeniyle degismis olabilir)
            result.duration_seconds = time.monotonic() - start
            return result

        except Exception as exc:
            duration = time.monotonic() - start
            logger.exception("Stage [%s] hatasi", stage.name)
            return StageResult(
                stage_name=stage.name,
                success=False,
                duration_seconds=duration,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

    def _resolve_run_order(self, requested: list[str] | None) -> list[str]:
        """Calistirilacak stage sirasini belirle.

        Eger ``requested`` verilmisse sadece o stage'leri (kayit sirasina gore)
        calistir. Verilmemisse tum stage'leri kayit sirasina gore calistir.
        """
        if requested is None:
            return list(self._stage_order)

        # Gecersiz stage isimleri kontrolu
        unknown = [s for s in requested if s not in self._stages]
        if unknown:
            logger.warning("Bilinmeyen stage'ler atlanacak: %s", unknown)

        # Kayit sirasini koru
        return [s for s in self._stage_order if s in requested]

    @staticmethod
    def _check_dependencies(
        stage: Stage, context: PipelineContext,
    ) -> list[str]:
        """Stage'in bagimlilik kontrolu.

        Returns:
            Eksik (basarisiz veya calistirilmamis) bagimliliklarin listesi.
            Bos liste = tum bagimliliklar karsilandi.
        """
        missing: list[str] = []
        for req in stage.requires:
            if not context.has_stage_succeeded(req):
                missing.append(req)
        return missing

    @property
    def registered_stages(self) -> list[str]:
        """Kayitli stage isimlerini dondur."""
        return list(self._stage_order)
