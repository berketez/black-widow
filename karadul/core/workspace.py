"""Workspace yonetimi.

Her analiz calismasi icin izole bir calisma dizini olusturur.
Stage'ler arasi artifact paylasimini yonetir.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Her analizde olusturulacak standart alt dizinler
_STAGE_DIRS = (
    "raw",            # Orijinal dosya kopyasi + ilk extraction
    "static",         # Statik analiz ciktilari (strings, symbols, disassembly)
    "dynamic",        # Dinamik analiz ciktilari (Frida trace, runtime dump)
    "deobfuscated",   # Deobfuscation sonuclari
    "reconstructed",  # Kaynak kodu yeniden yapimi
    "reports",        # Nihai raporlar (JSON, HTML, Markdown)
)


class Workspace:
    """Analiz calisma dizini yoneticisi.

    Her hedef icin tarih damgali bir dizin olusturur ve stage'lere
    ozel alt dizinler saglar. Artifact kaydetme/yukleme islemlerini
    merkezi olarak yonetir.

    Args:
        base_dir: Tum workspace'lerin saklanacagi ust dizin.
        target_name: Hedef adi (dizin ismi olarak kullanilir).
    """

    def __init__(self, base_dir: Path, target_name: str) -> None:
        self._base_dir = Path(base_dir).resolve()
        self._target_name = self._sanitize_name(target_name)
        self._timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._workspace_dir = (
            self._base_dir / self._target_name / self._timestamp
        )
        self._created = False

    @property
    def path(self) -> Path:
        """Workspace dizin yolu."""
        return self._workspace_dir

    @property
    def target_name(self) -> str:
        """Hedef adi."""
        return self._target_name

    def create(self) -> Path:
        """Workspace dizinini ve tum alt dizinleri olustur.

        Returns:
            Olusturulan workspace dizin yolu.
        """
        if self._created:
            return self._workspace_dir

        self._workspace_dir.mkdir(parents=True, exist_ok=True)

        for stage_dir in _STAGE_DIRS:
            (self._workspace_dir / stage_dir).mkdir(exist_ok=True)

        self._created = True
        logger.info("Workspace olusturuldu: %s", self._workspace_dir)
        return self._workspace_dir

    def get_stage_dir(self, stage: str) -> Path:
        """Belirli bir stage'in dizin yolunu dondur.

        Stage adi standart listede yoksa yeni bir alt dizin olusturulur.

        Args:
            stage: Stage adi (orn: "static", "dynamic").

        Returns:
            Stage dizin yolu.
        """
        stage_path = self._workspace_dir / stage
        if not stage_path.exists():
            stage_path.mkdir(parents=True, exist_ok=True)
        return stage_path

    def save_artifact(self, stage: str, name: str, data: bytes | str) -> Path:
        """Artifact kaydet.

        Args:
            stage: Artifact'in ait oldugu stage.
            name: Dosya adi (uzantisi dahil).
            data: Dosya icerigi (bytes veya str).

        Returns:
            Kaydedilen dosyanin yolu.
        """
        stage_dir = self.get_stage_dir(stage)
        artifact_path = (stage_dir / name).resolve()
        if not str(artifact_path).startswith(str(stage_dir.resolve())):
            raise ValueError(f"Path traversal engellendi: {name}")
        artifact_path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(data, str):
            # Surrogate character'ları temizle (CLI binary'lerinde olabiliyor)
            clean_data = data.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")
            artifact_path.write_text(clean_data, encoding="utf-8")
        else:
            artifact_path.write_bytes(data)

        logger.debug("Artifact kaydedildi: %s/%s", stage, name)
        return artifact_path

    def load_artifact(self, stage: str, name: str) -> bytes | str | None:
        """Artifact yukle.

        Dosya uzantisina gore text veya binary olarak okur.
        Text uzantilari: .json, .txt, .md, .js, .py, .html, .xml, .csv, .yaml, .yml

        Args:
            stage: Artifact'in stage'i.
            name: Dosya adi.

        Returns:
            Dosya icerigi veya None (dosya yoksa).
        """
        stage_dir = self.get_stage_dir(stage)
        artifact_path = (stage_dir / name).resolve()
        # CWE-22 fix: path traversal kontrolu (save_artifact ile tutarli)
        if not str(artifact_path).startswith(str(stage_dir.resolve())):
            raise ValueError(f"Path traversal engellendi: {name}")

        if not artifact_path.exists():
            return None

        text_extensions = {
            ".json", ".txt", ".md", ".js", ".py", ".html",
            ".xml", ".csv", ".yaml", ".yml", ".log", ".ts",
        }

        if artifact_path.suffix.lower() in text_extensions:
            return artifact_path.read_text(encoding="utf-8")

        return artifact_path.read_bytes()

    def save_json(self, stage: str, name: str, data: dict[str, Any]) -> Path:
        """JSON artifact kaydet.

        Args:
            stage: Stage adi.
            name: Dosya adi (.json uzantisi otomatik eklenir).
            data: JSON-serializable dict.

        Returns:
            Kaydedilen dosyanin yolu.
        """
        if not name.endswith(".json"):
            name = f"{name}.json"

        content = json.dumps(data, indent=2, ensure_ascii=True, default=str)
        return self.save_artifact(stage, name, content)

    def load_json(self, stage: str, name: str) -> dict[str, Any] | None:
        """JSON artifact yukle.

        Args:
            stage: Stage adi.
            name: Dosya adi.

        Returns:
            Parse edilmis dict veya None (dosya yoksa/parse edilemezse).
        """
        if not name.endswith(".json"):
            name = f"{name}.json"

        content = self.load_artifact(stage, name)
        if content is None:
            return None

        text = content if isinstance(content, str) else content.decode("utf-8")
        try:
            result = json.loads(text)
            if not isinstance(result, dict):
                logger.warning("JSON dosyasi dict degil: %s/%s", stage, name)
                return None
            return result
        except json.JSONDecodeError as exc:
            logger.warning("JSON parse hatasi: %s/%s: %s", stage, name, exc)
            return None

    def get_target_info_path(self) -> Path:
        """Target bilgi dosyasinin yolunu dondur.

        Bu dosya TargetDetector sonucunu saklamak icin kullanilir.
        """
        return self._workspace_dir / "target_info.json"

    def list_artifacts(self, stage: str) -> list[Path]:
        """Bir stage'deki tum artifact'leri listele.

        Args:
            stage: Stage adi.

        Returns:
            Artifact dosya yollarinin listesi.
        """
        stage_dir = self.get_stage_dir(stage)
        if not stage_dir.exists():
            return []
        return sorted(f for f in stage_dir.iterdir() if f.is_file())

    @staticmethod
    def _sanitize_name(name: str) -> str:
        """Dosya/dizin adi icin guvenli karakter donusumu.

        Bosluklar ve ozel karakterler alt cizgi ile degistirilir.
        """
        safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
        sanitized = "".join(c if c in safe_chars else "_" for c in name)
        # Bos string kontrolu
        return sanitized or "unnamed"
