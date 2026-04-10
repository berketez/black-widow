"""NSA-Grade Context-Aware Variable Naming -- Karadul v1.0

3 katmanli baglam analizi ile degiskenlere anlamli isimler verir:
  Katman 1: Kullanim Baglami (require source, property erisimi, operator)
  Katman 2: Veri Akisi Grafigi (atama zincirini 3 seviye geriye takip)
  Katman 3: Akilli Isimlendirme (300+ kural, confidence scoring)

Iki Node.js scripti calistirir:
  1. context-analyzer.mjs: AST analiz et, degisken bilgisi JSON uret
  2. apply-names.mjs: JSON'daki isimleri scope-aware sekilde kodda uygula

Kullanim:
    from karadul.reconstruction.context_namer import ContextNamer
    from karadul.config import Config

    namer = ContextNamer(Config())
    result = namer.analyze_and_rename(Path("input.js"), Path("output.js"))
    print(f"Renamed: {result.variables_renamed}")
"""

from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import Config
from karadul.core.subprocess_runner import SubprocessRunner

logger = logging.getLogger(__name__)


@dataclass
class NamingResult:
    """Context-aware variable naming sonucu.

    Attributes:
        success: Islem basarili mi.
        variables_renamed: Yeniden adlandirilan degisken sayisi.
        high_confidence: Yuksek guvenle (>= 0.5) isimlendirilen sayisi.
        medium_confidence: Orta guvenle (0.2 - 0.5) isimlendirilen sayisi.
        low_confidence: Dusuk guvenle (< 0.2) isimlendirilen sayisi.
        unnamed: Isimlendirilemeyen kisa degisken sayisi.
        total_variables: Toplam degisken sayisi.
        mappings: Eski isim -> yeni isim eslesmesi.
        context_json: Tam analiz sonucu (context-analyzer ciktisi).
        output_file: Cikti dosyasi yolu.
        errors: Hata mesajlari.
    """

    success: bool
    variables_renamed: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    unnamed: int = 0
    total_variables: int = 0
    mappings: dict[str, str] = field(default_factory=dict)
    context_json: dict[str, Any] | None = None
    output_file: Path | None = None
    errors: list[str] = field(default_factory=list)


class ContextNamer:
    """NSA-grade context-aware variable naming.

    Iki asamali pipeline:
    1. context-analyzer.mjs ile Babel AST uzerinden baglam analizi
    2. apply-names.mjs ile isimleri scope-aware sekilde kodda uygulama

    Args:
        config: Merkezi konfigurasyon.
        min_confidence: Minimum confidence esigi (bu degerin altindaki
            oneriler uygulanmaz). Varsayilan 0.1.
        max_old_space_size: Node.js heap limiti (MB). 9MB dosyalar icin
            8192 oneriliyor. Varsayilan 8192.
    """

    def __init__(
        self,
        config: Config,
        min_confidence: float = 0.1,
        max_old_space_size: int = 8192,
    ) -> None:
        self.config = config
        self.runner = SubprocessRunner(config)
        self.min_confidence = min_confidence
        self.max_old_space_size = max_old_space_size
        self._analyzer_script = config.scripts_dir / "context-analyzer.mjs"
        self._applier_script = config.scripts_dir / "apply-names.mjs"

    def analyze(self, input_file: Path) -> dict[str, Any]:
        """Dosyayi analiz et, baglam JSON'u dondur.

        Args:
            input_file: Girdi JS dosyasi.

        Returns:
            context-analyzer.mjs ciktisi (variables, stats).

        Raises:
            FileNotFoundError: Dosya veya script bulunamazsa.
            RuntimeError: Script basarisiz olursa.
        """
        if not input_file.exists():
            raise FileNotFoundError(f"Girdi dosyasi bulunamadi: {input_file}")

        if not self._analyzer_script.exists():
            raise FileNotFoundError(
                f"context-analyzer.mjs bulunamadi: {self._analyzer_script}"
            )

        # Gecici JSON dosyasi olustur
        with tempfile.NamedTemporaryFile(
            suffix=".json", prefix="bw_context_", delete=False, mode="w"
        ) as tmp:
            tmp_path = Path(tmp.name)

        try:
            node_path = str(self.config.tools.node)
            cmd = [
                node_path,
                f"--max-old-space-size={self.max_old_space_size}",
                str(self._analyzer_script),
                str(input_file),
                str(tmp_path),
            ]

            result = self.runner.run_command(
                cmd,
                timeout=max(
                    self.config.timeouts.babel_parse,
                    300,  # 9MB dosyalar icin en az 5 dakika
                ),
                cwd=self.config.scripts_dir,
            )

            if not result.success:
                raise RuntimeError(
                    f"context-analyzer.mjs basarisiz (code={result.returncode}): "
                    f"{result.stderr[:500]}"
                )

            # JSON ciktisini oku
            if tmp_path.exists() and tmp_path.stat().st_size > 0:
                context_data = json.loads(tmp_path.read_text(encoding="utf-8"))
            elif result.parsed_json:
                context_data = result.parsed_json
            else:
                raise RuntimeError(
                    "context-analyzer.mjs cikti uretemedi"
                )

            return context_data

        finally:
            # Gecici dosyayi temizle
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass

    def apply(
        self,
        input_file: Path,
        names_json: dict[str, Any],
        output_file: Path,
    ) -> dict[str, Any]:
        """Analiz sonuclarini kodda uygula.

        Args:
            input_file: Girdi JS dosyasi.
            names_json: context-analyzer ciktisi.
            output_file: Cikti JS dosyasi.

        Returns:
            apply-names.mjs ciktisi (renamed, mappings).

        Raises:
            FileNotFoundError: Dosya veya script bulunamazsa.
            RuntimeError: Script basarisiz olursa.
        """
        if not input_file.exists():
            raise FileNotFoundError(f"Girdi dosyasi bulunamadi: {input_file}")

        if not self._applier_script.exists():
            raise FileNotFoundError(
                f"apply-names.mjs bulunamadi: {self._applier_script}"
            )

        # Names JSON'u gecici dosyaya yaz
        with tempfile.NamedTemporaryFile(
            suffix=".json", prefix="bw_names_", delete=False, mode="w"
        ) as tmp:
            json.dump(names_json, tmp, ensure_ascii=False)
            names_path = Path(tmp.name)

        try:
            # Cikti dizininin var oldugundan emin ol
            output_file.parent.mkdir(parents=True, exist_ok=True)

            node_path = str(self.config.tools.node)
            cmd = [
                node_path,
                f"--max-old-space-size={self.max_old_space_size}",
                str(self._applier_script),
                str(input_file),
                str(names_path),
                str(output_file),
                "--min-confidence",
                str(self.min_confidence),
            ]

            result = self.runner.run_command(
                cmd,
                timeout=max(
                    self.config.timeouts.babel_parse,
                    300,
                ),
                cwd=self.config.scripts_dir,
            )

            if not result.success:
                raise RuntimeError(
                    f"apply-names.mjs basarisiz (code={result.returncode}): "
                    f"{result.stderr[:500]}"
                )

            if result.parsed_json:
                return result.parsed_json

            raise RuntimeError("apply-names.mjs JSON ciktisi uretemedi")

        finally:
            try:
                if names_path.exists():
                    names_path.unlink()
            except OSError:
                pass

    def analyze_and_rename(
        self,
        input_file: Path,
        output_file: Path,
    ) -> NamingResult:
        """Tam pipeline: analiz et + isimleri uygula.

        Args:
            input_file: Girdi JS dosyasi (deobfuscated).
            output_file: Cikti JS dosyasi (renamed).

        Returns:
            NamingResult: Tam sonuc.
        """
        all_errors: list[str] = []

        # Adim 1: Analiz
        logger.info(
            "Context analiz basliyor: %s (%.1f MB)",
            input_file.name,
            input_file.stat().st_size / (1024 * 1024),
        )

        try:
            context_data = self.analyze(input_file)
        except (FileNotFoundError, RuntimeError) as exc:
            logger.error("Context analiz hatasi: %s", exc)
            return NamingResult(
                success=False,
                errors=[str(exc)],
            )

        # Istatistikler
        stats = context_data.get("stats", {})
        variables = context_data.get("variables", {})
        analysis_errors = context_data.get("errors", [])
        all_errors.extend(analysis_errors)

        logger.info(
            "Analiz tamamlandi: %d degisken, %d high, %d medium, %d low confidence",
            stats.get("total_named", 0),
            stats.get("named_high_confidence", 0),
            stats.get("named_medium_confidence", 0),
            stats.get("named_low_confidence", 0),
        )

        if not variables:
            logger.warning("Analiz sonucu bos -- degisken bulunamadi")
            return NamingResult(
                success=True,
                variables_renamed=0,
                context_json=context_data,
                errors=all_errors,
            )

        # Adim 2: Uygula
        logger.info("Isimler uygulanıyor: %s", output_file.name)

        try:
            apply_result = self.apply(input_file, context_data, output_file)
        except (FileNotFoundError, RuntimeError) as exc:
            logger.error("Isim uygulama hatasi: %s", exc)
            return NamingResult(
                success=False,
                context_json=context_data,
                errors=[*all_errors, str(exc)],
            )

        mappings = apply_result.get("mappings", {})
        renamed_count = apply_result.get("renamed", 0)
        apply_errors = apply_result.get("errors", [])
        all_errors.extend(apply_errors)

        logger.info(
            "Isimlendirme tamamlandi: %d degisken yeniden adlandirildi",
            renamed_count,
        )

        # Ornek mappings log
        for old, new in list(mappings.items())[:15]:
            logger.info("  %s -> %s", old, new)

        return NamingResult(
            success=True,
            variables_renamed=renamed_count,
            high_confidence=stats.get("named_high_confidence", 0),
            medium_confidence=stats.get("named_medium_confidence", 0),
            low_confidence=stats.get("named_low_confidence", 0),
            unnamed=stats.get("unnamed", 0),
            total_variables=stats.get("total_variables", 0),
            mappings=mappings,
            context_json=context_data,
            output_file=output_file if output_file.exists() else None,
            errors=all_errors,
        )

    def get_stats(self, context_json: dict) -> dict:
        """Context analiz sonucundan istatistik ozeti cikar.

        Args:
            context_json: context-analyzer.mjs ciktisi.

        Returns:
            Ozet istatistikler.
        """
        stats = context_json.get("stats", {})
        variables = context_json.get("variables", {})

        # Evidence tip dagilimi
        evidence_types: dict[str, int] = {}
        for var_info in variables.values():
            for ev in var_info.get("evidence", []):
                ev_type = ev.get("type", "unknown")
                evidence_types[ev_type] = evidence_types.get(ev_type, 0) + 1

        # Confidence dagilimi
        confidence_dist = {
            "0.0-0.1": 0,
            "0.1-0.2": 0,
            "0.2-0.3": 0,
            "0.3-0.5": 0,
            "0.5-0.7": 0,
            "0.7-1.0": 0,
        }
        for var_info in variables.values():
            conf = var_info.get("confidence", 0)
            if conf < 0.1:
                confidence_dist["0.0-0.1"] += 1
            elif conf < 0.2:
                confidence_dist["0.1-0.2"] += 1
            elif conf < 0.3:
                confidence_dist["0.2-0.3"] += 1
            elif conf < 0.5:
                confidence_dist["0.3-0.5"] += 1
            elif conf < 0.7:
                confidence_dist["0.5-0.7"] += 1
            else:
                confidence_dist["0.7-1.0"] += 1

        # Require/import bazli modüller
        require_sources: dict[str, int] = {}
        for var_info in variables.values():
            req = var_info.get("data_flow", {}).get("require_source")
            if req:
                require_sources[req] = require_sources.get(req, 0) + 1

        return {
            "total_variables": stats.get("total_variables", 0),
            "total_named": stats.get("total_named", 0),
            "high_confidence": stats.get("named_high_confidence", 0),
            "medium_confidence": stats.get("named_medium_confidence", 0),
            "low_confidence": stats.get("named_low_confidence", 0),
            "unnamed": stats.get("unnamed", 0),
            "evidence_types": dict(
                sorted(evidence_types.items(), key=lambda x: -x[1])
            ),
            "confidence_distribution": confidence_dist,
            "require_sources": dict(
                sorted(require_sources.items(), key=lambda x: -x[1])[:20]
            ),
            "rule_categories": stats.get("rule_categories", {}),
        }
