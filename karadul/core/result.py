"""Pipeline sonuc veri yapilari.

Her stage calistiktan sonra bir StageResult uretir.
Pipeline tamamlandiginda tum sonuclari PipelineResult'ta toplar.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class StageResult:
    """Tek bir pipeline asamasinin sonucu.

    Attributes:
        stage_name: Asama adi (orn: "static_analysis", "deobfuscation").
        success: Basarili tamamlanip tamamlanmadigi.
        duration_seconds: Calisma suresi (saniye).
        artifacts: Uretilen dosyalarin ad->path eslesmesi.
        stats: Istatistikler (fonksiyon sayisi, string sayisi vb.).
        errors: Hata mesajlari listesi (basarisiz ise).
        skipped: Asama BASARISIZ degil, uygulanabilir olmadigi icin ATLANDI.
            Ornek: dinamik analiz Frida yokken ya da yabanci-mimarili/cross-arch
            binary spawn edilemedigi icin atlanir. skipped=True olan asamalar
            pipeline'i "FAILED" yapmaz (bkz PipelineResult.add_stage_result) ve
            get_failed_stages()'e girmez, get_skipped_stages()'te listelenir.
    """

    stage_name: str
    success: bool
    duration_seconds: float
    artifacts: dict[str, Path] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    skipped: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict'e donustur."""
        return {
            "stage_name": self.stage_name,
            "success": self.success,
            "skipped": self.skipped,
            "duration_seconds": round(self.duration_seconds, 3),
            "artifacts": {k: str(v) for k, v in self.artifacts.items()},
            "stats": self.stats,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StageResult:
        """Dict'ten olustur."""
        return cls(
            stage_name=data["stage_name"],
            success=data["success"],
            duration_seconds=data["duration_seconds"],
            artifacts={k: Path(v) for k, v in data.get("artifacts", {}).items()},
            stats=data.get("stats", {}),
            errors=data.get("errors", []),
            # Geriye uyum: eski raporlarda "skipped" alani yok -> False.
            skipped=bool(data.get("skipped", False)),
        )

    def summary(self) -> str:
        """Tek satirlik ozet."""
        status = "SKIP" if self.skipped else ("OK" if self.success else "FAIL")
        artifact_count = len(self.artifacts)
        error_count = len(self.errors)
        return (
            f"[{status}] {self.stage_name}: "
            f"{self.duration_seconds:.1f}s, "
            f"{artifact_count} artifact(s), "
            f"{error_count} error(s)"
        )


@dataclass
class PipelineResult:
    """Tum pipeline calismasinin sonucu.

    Attributes:
        target_name: Hedef dosya/uygulama adi.
        target_hash: Hedef dosyanin SHA-256 hash'i.
        stages: Asama adi -> StageResult eslesmesi.
        total_duration: Toplam calisma suresi (saniye).
        success: Tum stage'ler basarili mi.
        workspace_path: Calisma dizini.
    """

    target_name: str
    target_hash: str
    stages: dict[str, StageResult] = field(default_factory=dict)
    total_duration: float = 0.0
    success: bool = False
    workspace_path: Path = field(default_factory=lambda: Path("."))

    def add_stage_result(self, result: StageResult) -> None:
        """Stage sonucunu ekle ve genel basariyi guncelle."""
        self.stages[result.stage_name] = result
        # Tum stage'ler basarili VEYA atlanmis (skipped) ise pipeline basarili.
        # skipped bir HATA degildir (orn: dinamik analiz Frida yokken/yabanci
        # mimaride atlanir) -> mukemmel bir statik reconstruction'i "FAILED"
        # yapmamali. Sadece gercek basarisizliklar (success=False, skipped=False)
        # pipeline'i FAILED yapar.
        self.success = all(
            sr.success or sr.skipped for sr in self.stages.values()
        )

    def get_failed_stages(self) -> list[str]:
        """Gercekten BASARISIZ stage isimlerini dondur (atlananlar haric)."""
        return [
            name for name, sr in self.stages.items()
            if not sr.success and not sr.skipped
        ]

    def get_skipped_stages(self) -> list[str]:
        """Atlanan (skipped=True) stage isimlerini dondur.

        Atlanan asamalar hata degildir; uygulanabilir olmadigi icin (orn.
        Frida yok / cross-arch spawn edilemez) calistirilamamistir.
        """
        return [name for name, sr in self.stages.items() if sr.skipped]

    def get_all_artifacts(self) -> dict[str, Path]:
        """Tum stage'lerdeki artifact'leri birlestir."""
        merged: dict[str, Path] = {}
        for sr in self.stages.values():
            for name, path in sr.artifacts.items():
                # Cakisma durumunda stage_name prefix'i ekle
                key = f"{sr.stage_name}/{name}" if name in merged else name
                merged[key] = path
        return merged

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict'e donustur."""
        return {
            "target_name": self.target_name,
            "target_hash": self.target_hash,
            "stages": {k: v.to_dict() for k, v in self.stages.items()},
            "total_duration": round(self.total_duration, 3),
            "success": self.success,
            "workspace_path": str(self.workspace_path),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PipelineResult:
        """Dict'ten olustur."""
        result = cls(
            target_name=data["target_name"],
            target_hash=data["target_hash"],
            total_duration=data["total_duration"],
            success=data["success"],
            workspace_path=Path(data["workspace_path"]),
        )
        for name, stage_data in data.get("stages", {}).items():
            result.stages[name] = StageResult.from_dict(stage_data)
        return result

    def to_json(self, indent: int = 2) -> str:
        """JSON string'e donustur."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def summary(self) -> str:
        """Pipeline sonuc ozeti."""
        lines = [
            f"Pipeline: {self.target_name} ({'SUCCESS' if self.success else 'FAILED'})",
            f"  Duration: {self.total_duration:.1f}s",
            f"  Workspace: {self.workspace_path}",
            f"  Stages ({len(self.stages)}):",
        ]
        for sr in self.stages.values():
            lines.append(f"    {sr.summary()}")

        skipped = self.get_skipped_stages()
        if skipped:
            lines.append(f"  Skipped: {', '.join(skipped)}")

        failed = self.get_failed_stages()
        if failed:
            lines.append(f"  Failed: {', '.join(failed)}")

        return "\n".join(lines)
