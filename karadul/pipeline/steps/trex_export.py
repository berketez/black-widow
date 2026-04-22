"""TRex export adimi — Ghidra P-code -> .pcode-exported + .var-exported dosyalari.

Faz 1 (bu sprint): Iskelet. `trex.enabled` flag yoksa sessizce atlanir.
Faz 2 (ileride): Ghidra headless'i PCodeExporter.java + VariableExporter.java ile
    gercekten cagirip ciktilari parse eder, fusion'a evidence gonderir.

Ghidra script'leri: karadul/ghidra/scripts/trex/
Kaynak: https://github.com/secure-foundations/trex (BSD-3-Clause)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

# Ghidra script'lerinin karadul paketi icindeki yolu
_SCRIPTS_DIR = Path(__file__).parent.parent.parent / "ghidra" / "scripts" / "trex"

PCODE_EXPORTER_JAVA = _SCRIPTS_DIR / "PCodeExporter.java"
VARIABLE_EXPORTER_JAVA = _SCRIPTS_DIR / "VariableExporter.java"


@register_step(
    name="trex_export",
    requires=["binary_path"],
    produces=["trex_lifted_path", "trex_vars_path"],
    parallelizable_with=[],
)
class TRexExportStep(Step):
    """TRex icin .pcode-exported + .var-exported dosyalarini uret.

    Faz 1: Sadece iskelet — `trex.enabled` false ise atlanir.
    Faz 2: Gercek Ghidra headless cagrisini uygula.
    """

    def run(self, ctx: StepContext) -> dict[str, Any]:
        trex_cfg: dict[str, Any] = ctx.pipeline_context.config.get("trex", {})

        if not trex_cfg.get("enabled", False):
            logger.debug("TRex export devre disi (trex.enabled=false), atlanıyor.")
            return {"trex_lifted_path": None, "trex_vars_path": None}

        # Faz 2 TODO: gercek implementasyon
        # 1. Ghidra headless'i PCodeExporter.java ile cagir -> .pcode-exported
        # 2. Ghidra headless'i VariableExporter.java ile cagir -> .var-exported
        # 3. Ciktilari parse et, fusion'a evidence olarak ekle

        binary_path = Path(ctx.artifacts["binary_path"])
        workspace_dir = ctx.pipeline_context.workspace.root

        lifted_path = workspace_dir / (binary_path.name + ".pcode-exported")
        vars_path = workspace_dir / (binary_path.name + ".var-exported")

        logger.info(
            "TRex export iskelet (Faz 2'de implement edilecek). "
            "Beklenen cikti: %s, %s",
            lifted_path,
            vars_path,
        )

        # Faz 1: Gercek dosya uretilmiyor, None donuyor
        return {"trex_lifted_path": None, "trex_vars_path": None}
