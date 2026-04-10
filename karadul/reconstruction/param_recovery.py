"""Parametre Ismi Recovery -- Karadul v1.0

Call-site analizi, this.X=param, destructuring ve property access
pattern'leri ile obfuscated parametre isimlerini geri kazanir.

Iki Node.js scripti calistirir:
  1. param-recovery.mjs: AST analiz et, parametre-isim eslesmesi JSON uret
  2. apply-params.mjs: JSON'daki isimleri kodda uygula (scope-aware)

Kullanim:
    from karadul.reconstruction.param_recovery import ParamRecovery
    from karadul.config import Config

    recovery = ParamRecovery(Config())
    result = recovery.recover(Path("input.js"))
    print(f"Recovered: {result.recovered} / {result.total_params}")

    if result.recovered > 0:
        applied = recovery.apply_to_file(
            Path("input.js"), result.recovery_json, Path("output.js")
        )
        print(f"Applied: {applied} params")
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
class ParamRecoveryResult:
    """Parametre recovery sonucu.

    Attributes:
        success: Islem basarili mi.
        total_functions: Toplam fonksiyon sayisi.
        total_params: Toplam parametre sayisi.
        obfuscated_params: Obfuscated (tek harfli) parametre sayisi.
        recovered: Geri kazanilan parametre sayisi.
        high_quality: Yuksek kaliteli (confidence >= 0.7) recovery sayisi.
        recovery_rate: Kurtarma orani (yuzde string).
        by_strategy: Strateji bazli istatistik dict.
        mappings: funcKey::paramIdx -> {original, recovered, strategy, confidence} eslesmesi.
        recovery_json: Recovery sonuclarinin kaydedildigi JSON dosya yolu.
        duration: Calisma suresi (saniye).
        errors: Hata mesajlari.
    """

    success: bool
    total_functions: int = 0
    total_params: int = 0
    obfuscated_params: int = 0
    recovered: int = 0
    high_quality: int = 0
    recovery_rate: str = "0%"
    by_strategy: dict[str, int] = field(default_factory=dict)
    mappings: dict[str, dict[str, Any]] = field(default_factory=dict)
    recovery_json: Path | None = None
    duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class ParamRecovery:
    """Call-site + this.X=param + destructuring ile parametre ismi recovery.

    Node.js'in param-recovery.mjs scriptini SubprocessRunner ile calistirir.
    Sonuclari apply-params.mjs ile kodda uygular.

    Args:
        config: Merkezi konfigurasyon.
        min_confidence: Apply asamasinda minimum confidence esigi.
            Bu degerin altindaki recovery'ler uygulanmaz. Varsayilan 0.6.
        max_old_space_size: Node.js heap limiti (MB). Varsayilan 8192.
    """

    def __init__(
        self,
        config: Config,
        min_confidence: float = 0.6,
        max_old_space_size: int = 8192,
    ) -> None:
        self.config = config
        self.runner = SubprocessRunner(config)
        self.min_confidence = min_confidence
        self.max_old_space_size = max_old_space_size
        self._recovery_script = config.scripts_dir / "param-recovery.mjs"
        self._apply_script = config.scripts_dir / "apply-params.mjs"

    def recover(
        self,
        input_file: Path,
        output_json: Path | None = None,
        timeout: int = 120,
    ) -> ParamRecoveryResult:
        """Dosyadaki obfuscated parametreleri analiz et ve recovery JSON uret.

        param-recovery.mjs calistirir. 5 strateji kullanir:
        - this.X = param (en yuksek confidence, 0.90-0.95)
        - const { X, Y } = param (destructuring, 0.88)
        - call-site object literal (0.82)
        - call-site identifier (0.72)
        - property access pattern (0.35-0.78)

        Args:
            input_file: Girdi JS dosyasi.
            output_json: Recovery sonuclarinin kaydedilecegi JSON dosya yolu.
                None ise gecici dosya olusturulur.
            timeout: Node.js script zaman asimi (saniye).

        Returns:
            ParamRecoveryResult: Analiz sonucu.
        """
        import time

        start = time.monotonic()
        errors: list[str] = []

        if not self._recovery_script.exists():
            return ParamRecoveryResult(
                success=False,
                errors=[f"param-recovery.mjs bulunamadi: {self._recovery_script}"],
            )

        input_path = Path(input_file).resolve()
        if not input_path.exists():
            return ParamRecoveryResult(
                success=False,
                errors=[f"Girdi dosyasi bulunamadi: {input_path}"],
            )

        # Cikti JSON dosyasi
        if output_json is None:
            tmp = tempfile.NamedTemporaryFile(
                suffix=".json", prefix="bw_param_recovery_",
                delete=False, mode="w",
            )
            tmp.close()
            json_path = Path(tmp.name)
        else:
            json_path = Path(output_json).resolve()
            json_path.parent.mkdir(parents=True, exist_ok=True)

        # Node.js komutu
        node_path = str(self.config.tools.node)
        cmd = [
            node_path,
            f"--max-old-space-size={self.max_old_space_size}",
            str(self._recovery_script),
            str(input_path),
            str(json_path),
        ]

        logger.info("ParamRecovery baslatiliyor: %s", input_path.name)

        # CWE-459: Tempfile cleanup -- tum path'lerde temizleme garanti
        _cleanup_temp = output_json is None  # sadece biz olusturduysa temizle
        try:
            result = self.runner.run_command(cmd, timeout=timeout)
            duration = time.monotonic() - start

            if not result.success:
                msg = f"param-recovery.mjs basarisiz (code={result.returncode})"
                if result.stderr:
                    msg += f": {result.stderr[:300]}"
                errors.append(msg)
                return ParamRecoveryResult(
                    success=False,
                    duration=duration,
                    errors=errors,
                )

            # JSON sonucunu parse et (stdout'tan)
            parsed = result.parsed_json
            if parsed is None:
                errors.append("param-recovery.mjs JSON ciktisi uretemedi")
                return ParamRecoveryResult(
                    success=False,
                    duration=duration,
                    errors=errors,
                )

            if not parsed.get("success", False):
                errs = parsed.get("errors", [])
                errors.extend(errs)
                return ParamRecoveryResult(
                    success=False,
                    duration=duration,
                    errors=errors,
                )

            # Istatistikleri cek
            stats = parsed.get("stats", {})
            total_functions = stats.get("totalFunctions", 0)
            total_params = stats.get("totalParams", 0)
            obfuscated = stats.get("obfuscatedParams", 0)
            recovered_count = stats.get("recoveredParams", 0)
            recovery_rate = stats.get("recoveryRate", "0%")
            by_strategy = stats.get("byStrategy", {})

            # Tam JSON'u oku (cikti dosyasinda)
            mappings: dict[str, dict[str, Any]] = {}
            high_quality = 0
            try:
                if json_path.exists():
                    full_data = json.loads(json_path.read_text(encoding="utf-8"))
                    recoveries = full_data.get("recoveries", {})
                    for key, info in recoveries.items():
                        mappings[key] = info
                        if info.get("confidence", 0) >= 0.7:
                            high_quality += 1
            except Exception as exc:
                errors.append(f"Recovery JSON parse hatasi: {exc}")

            logger.info(
                "ParamRecovery sonuc: %d/%d parametre recovered (%.1fs)",
                recovered_count, obfuscated, duration,
            )

            # Basarili -- temp dosya artik sonucun parcasi, temizleme
            _cleanup_temp = False
            return ParamRecoveryResult(
                success=True,
                total_functions=total_functions,
                total_params=total_params,
                obfuscated_params=obfuscated,
                recovered=recovered_count,
                high_quality=high_quality,
                recovery_rate=recovery_rate,
                by_strategy=by_strategy,
                mappings=mappings,
                recovery_json=json_path,
                duration=duration,
                errors=errors,
            )
        finally:
            if _cleanup_temp:
                json_path.unlink(missing_ok=True)

    def apply_to_file(
        self,
        input_file: Path,
        recovery_json: Path,
        output_file: Path,
        min_confidence: float | None = None,
        timeout: int = 120,
    ) -> int:
        """Recovery sonuclarini kaynak kodda uygula.

        apply-params.mjs calistirarak param-recovery.mjs ciktisindaki
        parametre isimlerini koda yazar. Sadece tek-harfli parametreleri
        rename eder, shadow kontrolu yapar.

        Args:
            input_file: Girdi JS dosyasi.
            recovery_json: param-recovery.mjs ciktisi JSON dosyasi.
            output_file: Cikti JS dosyasi.
            min_confidence: Minimum confidence esigi. None ise instance'in
                varsayilan degeri kullanilir.
            timeout: Node.js script zaman asimi (saniye).

        Returns:
            Uygulanan parametre sayisi.

        Raises:
            FileNotFoundError: Script veya girdi dosyasi yoksa.
            RuntimeError: Script basarisiz olursa.
        """
        if not self._apply_script.exists():
            raise FileNotFoundError(
                f"apply-params.mjs bulunamadi: {self._apply_script}"
            )

        input_path = Path(input_file).resolve()
        json_path = Path(recovery_json).resolve()
        out_path = Path(output_file).resolve()

        if not input_path.exists():
            raise FileNotFoundError(f"Girdi dosyasi bulunamadi: {input_path}")
        if not json_path.exists():
            raise FileNotFoundError(f"Recovery JSON bulunamadi: {json_path}")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        confidence = min_confidence if min_confidence is not None else self.min_confidence

        node_path = str(self.config.tools.node)
        cmd = [
            node_path,
            f"--max-old-space-size={self.max_old_space_size}",
            str(self._apply_script),
            str(input_path),
            str(json_path),
            str(out_path),
            "--min-confidence",
            str(confidence),
        ]

        logger.info(
            "ParamRecovery apply: %s -> %s (min_conf=%.2f)",
            input_path.name, out_path.name, confidence,
        )

        result = self.runner.run_command(cmd, timeout=timeout)

        if not result.success:
            raise RuntimeError(
                f"apply-params.mjs basarisiz (code={result.returncode}): "
                f"{result.stderr[:500]}"
            )

        parsed = result.parsed_json
        if parsed is None:
            raise RuntimeError(
                f"apply-params.mjs JSON ciktisi uretemedi\n"
                f"stdout: {result.stdout[:500]}"
            )

        if not parsed.get("success", False):
            errs = parsed.get("errors", [])
            raise RuntimeError(
                f"apply-params.mjs basarisiz: {'; '.join(errs)}"
            )

        renamed = parsed.get("renamed", 0)
        logger.info(
            "ParamRecovery apply sonuc: %d parametre rename edildi",
            renamed,
        )

        return renamed

    def recover_and_apply(
        self,
        input_file: Path,
        output_file: Path,
        recovery_json: Path | None = None,
        timeout: int = 120,
    ) -> ParamRecoveryResult:
        """Tek cagirimda recovery + apply yap.

        Oncelikle recover() ile parametreleri analiz eder.
        Sonra sonuc basarili ve recovery > 0 ise apply_to_file() ile uygular.

        Args:
            input_file: Girdi JS dosyasi.
            output_file: Cikti JS dosyasi.
            recovery_json: Ara JSON dosyasi. None ise gecici dosya.
            timeout: Her iki adim icin zaman asimi (saniye).

        Returns:
            ParamRecoveryResult: recovery_json alaninda JSON dosya yolu var.
        """
        # Adim 1: Recover
        result = self.recover(input_file, recovery_json, timeout=timeout)
        if not result.success or result.recovered == 0:
            # Recovery basarisiz veya 0 sonuc -- girdi dosyasini oldugun gibi kopyala
            if not result.success:
                logger.warning("ParamRecovery basarisiz, adim atlaniyor")
            else:
                logger.info("ParamRecovery: 0 parametre bulundu, atlanıyor")
            return result

        # Adim 2: Apply
        try:
            applied = self.apply_to_file(
                input_file, result.recovery_json, output_file,
                timeout=timeout,
            )
            logger.info(
                "ParamRecovery tamamlandi: %d recovered, %d applied",
                result.recovered, applied,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            result.errors.append(f"Apply hatasi: {exc}")
            logger.warning("ParamRecovery apply basarisiz: %s", exc)

        return result
