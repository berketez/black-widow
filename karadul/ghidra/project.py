"""Ghidra proje yonetimi.

analyzeHeadless icin proje dizini olusturma, cikti dizini yonetimi
ve temizlik islemlerini saglar.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from karadul.config import Config
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)


class GhidraProject:
    """Ghidra proje yonetimi.

    Workspace'in static stage dizini altinda Ghidra'ya ozel
    proje ve cikti dizinleri olusturur.

    Args:
        workspace: Karadul workspace yoneticisi.
        config: Merkezi konfigurasyon.
    """

    def __init__(self, workspace: Workspace, config: Config) -> None:
        self.workspace = workspace
        self.config = config
        self.project_dir = workspace.get_stage_dir("static") / "ghidra_project"
        self._output_dir = workspace.get_stage_dir("static") / "ghidra_output"

    def create(self) -> Path:
        """Proje dizinini ve cikti dizinini olustur.

        Returns:
            Olusturulan proje dizin yolu.
        """
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Ghidra proje dizini olusturuldu: %s", self.project_dir)
        return self.project_dir

    def cleanup(self) -> None:
        """Gecici Ghidra proje dosyalarini temizle.

        analyzeHeadless -deleteProject flag'i proje dosyalarini
        siler, ama bazi kalinti dosyalar kalabilir. Bu metod
        proje dizinini tamamen temizler.
        """
        if self.project_dir.exists():
            try:
                shutil.rmtree(self.project_dir)
                logger.info("Ghidra proje dizini temizlendi: %s", self.project_dir)
            except OSError as exc:
                logger.warning(
                    "Ghidra proje dizini temizlenemedi: %s: %s",
                    self.project_dir, exc,
                )

    def get_output_dir(self) -> Path:
        """Script ciktilarinin yazildigi dizin.

        Returns:
            Cikti dizin yolu (yoksa olusturulur).
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        return self._output_dir

    def get_decompiled_dir(self) -> Path:
        """Decompile edilmis fonksiyonlarin dizini.

        Returns:
            decompiled/ dizin yolu (yoksa olusturulur).
        """
        decompiled = self._output_dir / "decompiled"
        decompiled.mkdir(parents=True, exist_ok=True)
        return decompiled
