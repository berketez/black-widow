"""Deobfuscation zincir orkestrasyonu.

Pipeline: beautify -> synchrony -> babel_transforms -> webpack_unpack

Her adimin ciktisi bir sonrakinin girdisi olur. Bir adim basarisiz olursa
atlenir ve bir onceki basarili cikti ile devam edilir (graceful degradation).
"""

from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..core.subprocess_runner import SubprocessRunner
from ..core.workspace import Workspace
from .babel_pipeline import BabelPipeline
from .synchrony_wrapper import SynchronyWrapper

logger = logging.getLogger(__name__)


@dataclass
class DeobfuscationResult:
    """Deobfuscation zincirinin sonucu.

    Attributes:
        success: En az bir adim basarili oldu mu.
        steps_completed: Basarili tamamlanan adimlar.
        steps_failed: Basarisiz olan adimlar.
        steps_skipped: Atlanan adimlar (arac mevcut degil).
        output_file: Son basarili ciktinin yolu (None ise hicbir adim basarili degil).
        stats: Adim bazli istatistikler.
        duration_seconds: Toplam sure (saniye).
    """

    success: bool = False
    steps_completed: list[str] = field(default_factory=list)
    steps_failed: list[str] = field(default_factory=list)
    steps_skipped: list[str] = field(default_factory=list)
    output_file: Path | None = None
    stats: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0

    def summary(self) -> str:
        """Tek satirlik ozet."""
        status = "SUCCESS" if self.success else "FAILED"
        return (
            f"[{status}] Deobfuscation: "
            f"{len(self.steps_completed)} completed, "
            f"{len(self.steps_failed)} failed, "
            f"{len(self.steps_skipped)} skipped, "
            f"{self.duration_seconds:.1f}s"
        )

    def __repr__(self) -> str:
        return (
            f"DeobfuscationResult("
            f"success={self.success}, "
            f"completed={self.steps_completed}, "
            f"failed={self.steps_failed}, "
            f"skipped={self.steps_skipped}, "
            f"output={self.output_file}, "
            f"duration={self.duration_seconds:.1f}s)"
        )


# Desteklenen zincir adimlari
_KNOWN_STEPS = {"beautify", "synchrony", "babel_transforms", "webpack_unpack", "deep_pipeline"}


class DeobfuscationManager:
    """Deobfuscation pipeline orkestrasyonu.

    Zincir: beautify -> synchrony -> babel_transforms -> webpack_unpack

    Her adim:
    1. Onceki adimin ciktisini girdi olarak alir
    2. Ciktisini workspace/deobfuscated/ altina kaydeder
    3. Basarisiz olursa atlenir, bir onceki basarili cikti kullanilir

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._runner = SubprocessRunner(config)
        self._babel = BabelPipeline(config)
        self._synchrony = SynchronyWrapper(config)

    def run_chain(
        self,
        input_file: Path,
        workspace: Workspace,
        chain: list[str] | None = None,
    ) -> DeobfuscationResult:
        """Tam deobfuscation zincirini calistir.

        Args:
            input_file: Obfuscated JS dosyasi.
            workspace: Calisma dizini (sonuclar deobfuscated/ altina yazilir).
            chain: Calistirilacak adim listesi. None ise config'deki default zincir.

        Returns:
            DeobfuscationResult: Zincir sonucu.
        """
        start_time = time.monotonic()
        result = DeobfuscationResult()

        if not input_file.exists():
            result.steps_failed.append("init")
            result.stats["error"] = f"Girdi dosyasi bulunamadi: {input_file}"
            result.duration_seconds = time.monotonic() - start_time
            return result

        # Zincir adimlarini belirle
        effective_chain = chain or list(self._config.analysis.deobfuscation_chain)

        # Bilinmeyen adimlari filtrele
        for step in effective_chain:
            if step not in _KNOWN_STEPS:
                logger.warning("Bilinmeyen deobfuscation adimi atlanacak: %s", step)
        effective_chain = [s for s in effective_chain if s in _KNOWN_STEPS]

        logger.info(
            "Deobfuscation zinciri baslatiliyor: %s (adimlar: %s)",
            input_file.name,
            " -> ".join(effective_chain),
        )

        # Deobfuscated cikti dizini
        deob_dir = workspace.get_stage_dir("deobfuscated")

        # Ilk girdiyi kopyala
        current_input = deob_dir / f"00_original{input_file.suffix}"
        shutil.copy2(input_file, current_input)
        result.stats["original_size"] = input_file.stat().st_size

        # Her adimi calistir
        for idx, step_name in enumerate(effective_chain, start=1):
            step_output = deob_dir / f"{idx:02d}_{step_name}{input_file.suffix}"

            step_start = time.monotonic()
            step_success = False

            try:
                step_success = self._execute_step(
                    step_name, current_input, step_output, deob_dir,
                )
            except Exception as exc:
                logger.error(
                    "Deobfuscation adimi [%s] exception: %s", step_name, exc,
                )
                step_success = False

            step_duration = time.monotonic() - step_start
            result.stats[f"{step_name}_duration"] = round(step_duration, 3)

            if step_success and step_output.exists():
                result.steps_completed.append(step_name)
                result.stats[f"{step_name}_output_size"] = step_output.stat().st_size
                # Sonraki adimin girdisi bu cikti
                current_input = step_output
                logger.info(
                    "Adim [%s] basarili: %s (%.1fs)",
                    step_name, step_output.name, step_duration,
                )
            else:
                result.steps_failed.append(step_name)
                logger.warning(
                    "Adim [%s] basarisiz, atlaniyor (%.1fs)",
                    step_name, step_duration,
                )

        # Sonuc
        if result.steps_completed:
            result.success = True
            result.output_file = current_input
            result.stats["final_size"] = current_input.stat().st_size
        else:
            result.success = False
            result.output_file = None

        result.duration_seconds = time.monotonic() - start_time

        logger.info(
            "Deobfuscation zinciri tamamlandi: %s", result.summary(),
        )

        return result

    def _execute_step(
        self,
        step_name: str,
        input_file: Path,
        output_file: Path,
        work_dir: Path,
    ) -> bool:
        """Tek bir deobfuscation adimini calistir.

        Args:
            step_name: Adim adi.
            input_file: Girdi dosyasi.
            output_file: Cikti dosyasi.
            work_dir: Calisma dizini.

        Returns:
            Basarili ise True.
        """
        if step_name == "beautify":
            return self._step_beautify(input_file, output_file)
        elif step_name == "synchrony":
            return self._step_synchrony(input_file, output_file)
        elif step_name == "babel_transforms":
            return self._step_babel_transforms(input_file, output_file)
        elif step_name == "webpack_unpack":
            return self._step_webpack_unpack(input_file, output_file, work_dir)
        elif step_name == "deep_pipeline":
            return self._step_deep_pipeline(input_file, output_file, work_dir)
        else:
            logger.error("Bilinmeyen adim: %s", step_name)
            return False

    def _step_beautify(self, input_file: Path, output_file: Path) -> bool:
        """js-beautify ile kodu bimlendira.

        scripts/beautify.mjs cagrilir. Script yoksa basit
        fallback (girdiyi kopyala) uygulanir.
        """
        beautify_script = self._config.scripts_dir / "beautify.mjs"

        if not beautify_script.exists():
            logger.warning(
                "beautify.mjs bulunamadi (%s), girdi kopyalanarak atlaniyor",
                beautify_script,
            )
            shutil.copy2(input_file, output_file)
            return True

        try:
            result = self._runner.run_node_script(
                beautify_script,
                args=[str(input_file), str(output_file)],
                timeout=self._config.timeouts.subprocess,
            )
            # Script JSON sonuc dondurmuyorsa da cikti dosyasi olusturulmus olabilir
            if output_file.exists() and output_file.stat().st_size > 0:
                return True
            # JSON sonuc kontrolu
            return result.get("success", False)
        except (RuntimeError, FileNotFoundError) as exc:
            logger.error("beautify hatasi: %s", exc)
            # Fallback: girdiyi kopyala
            shutil.copy2(input_file, output_file)
            return True

    def _step_synchrony(self, input_file: Path, output_file: Path) -> bool:
        """synchrony ile deobfuscate et."""
        if not self._synchrony.is_available():
            logger.warning("synchrony mevcut degil, adim atlaniyor")
            return False

        return self._synchrony.deobfuscate(input_file, output_file)

    def _step_babel_transforms(
        self, input_file: Path, output_file: Path,
    ) -> bool:
        """Babel AST transform'larini uygula."""
        if not self._babel.is_available():
            logger.warning("Babel pipeline mevcut degil, adim atlaniyor")
            return False

        result = self._babel.transform(input_file, output_file)
        return result.get("success", False)

    def _step_deep_pipeline(
        self,
        input_file: Path,
        output_file: Path,
        work_dir: Path,
    ) -> bool:
        """Deep deobfuscation pipeline -- 9 phase transform + akilli modul cikarma.

        deep-deobfuscate.mjs calistirilir.
        """
        deep_script = self._config.scripts_dir / "deep-deobfuscate.mjs"
        if not deep_script.exists():
            logger.warning("deep-deobfuscate.mjs bulunamadi: %s", deep_script)
            return False

        try:
            node_args = [
                "--max-old-space-size=8192",
                str(deep_script),
                str(input_file),
                str(output_file),
                "--phases", "all",
            ]

            result = self._runner.run_command(
                [str(self._config.tools.node)] + node_args,
                timeout=300,
            )

            if output_file.exists() and output_file.stat().st_size > 0:
                logger.info("Deep deobfuscation basarili: %s", output_file.name)
                return True

            if result.parsed_json:
                return result.parsed_json.get("success", False)

            return False
        except Exception as exc:
            logger.error("Deep pipeline hatasi: %s", exc)
            return False

    def _step_webpack_unpack(
        self,
        input_file: Path,
        output_file: Path,
        work_dir: Path,
    ) -> bool:
        """Webpack bundle'i modullerine ayir.

        scripts/extract-modules.mjs cagrilir. Moduller
        work_dir/webpack_modules/ altina yazilir.
        output_file'a entry point modulu kopyalanir.
        """
        extract_script = self._config.scripts_dir / "extract-modules.mjs"

        if not extract_script.exists():
            logger.warning(
                "extract-modules.mjs bulunamadi (%s), adim atlaniyor",
                extract_script,
            )
            return False

        modules_dir = work_dir / "webpack_modules"
        modules_dir.mkdir(exist_ok=True)

        try:
            result = self._runner.run_node_script(
                extract_script,
                args=[str(input_file), str(modules_dir)],
                timeout=self._config.timeouts.subprocess,
            )

            total = result.get("total_modules", 0)
            if total == 0:
                logger.warning("Webpack module bulunamadi")
                return False

            logger.info("Webpack unpack: %d modul cikarildi", total)

            # Entry point modulunu output_file'a kopyala
            entry = result.get("entry_point", "0")
            entry_file = modules_dir / f"module_{int(entry):03d}.js"
            if entry_file.exists():
                shutil.copy2(entry_file, output_file)
            else:
                # Ilk modulu kullan
                first_module = sorted(modules_dir.glob("module_*.js"))
                if first_module:
                    shutil.copy2(first_module[0], output_file)

            return True

        except (RuntimeError, FileNotFoundError, ValueError) as exc:
            logger.error("Webpack unpack hatasi: %s", exc)
            return False
