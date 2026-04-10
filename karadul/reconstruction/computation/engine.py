"""Computation Recovery Engine -- 4 katmanli hesaplama bazli kurtarma orkestratoru.

Katman 1-4'u sirayla calistirir, her birinin sonucunu bir sonrakine besler.
Her katman bagimsiz acilip kapatilabilir (config toggle).  Katman
bagimliliklari (z3-solver, sympy) yoksa graceful fallback uygulanir.

Kullanim:
    engine = ComputationRecoveryEngine(config)
    result = engine.recover(
        decompiled_dir, functions_json, call_graph_json,
        cfg_json, ghidra_types_json,
        existing_sig_matches, existing_algo_matches, existing_eng_matches,
    )
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.config import Config

logger = logging.getLogger(__name__)


@dataclass
class ComputationRecoveryResult:
    """Tum katmanlarin birlesmis sonucu.

    Attributes:
        success: Pipeline basariyla tamamlandi mi.
        elapsed_seconds: Toplam gecen sure (saniye).
        structs_refined: Constraint solver'in rafine ettigi struct sayisi.
        arrays_detected: Tespit edilen cok-boyutlu array sayisi.
        types_propagated: BFS ile yayilan tip sayisi.
        cfg_matches: CFG fingerprint eslesmesi sayisi (Layer 2).
        fusion_identifications: Dempster-Shafer ile kesin tanimlanan fonksiyon sayisi.
        formulas_extracted: Cikarilan matematiksel formul sayisi.
        layer_results: Katman bazli detayli sonuclar.
        naming_candidates: NameMerger'a beslenecek isim adaylari.
        param_type_inferences: Fonksiyon parametre tip cikarimlari
            {func_name: {param_name: inferred_type}}.
        return_type_inferences: Fonksiyon return tip cikarimlari
            {func_name: inferred_return_type}.
        global_variables: Tespit edilen DAT_ global degiskenler.
    """
    success: bool = False
    elapsed_seconds: float = 0.0
    structs_refined: int = 0
    arrays_detected: int = 0
    types_propagated: int = 0
    cfg_matches: int = 0
    fusion_identifications: int = 0
    formulas_extracted: int = 0
    layer_results: dict[str, Any] = field(default_factory=dict)
    naming_candidates: list[dict[str, Any]] = field(default_factory=list)
    param_type_inferences: dict[str, dict[str, str]] = field(default_factory=dict)
    return_type_inferences: dict[str, str] = field(default_factory=dict)
    global_variables: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON serialization icin dict'e donustur."""
        return {
            "success": self.success,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "structs_refined": self.structs_refined,
            "arrays_detected": self.arrays_detected,
            "types_propagated": self.types_propagated,
            "cfg_matches": self.cfg_matches,
            "fusion_identifications": self.fusion_identifications,
            "formulas_extracted": self.formulas_extracted,
            "layer_results": {
                k: v.to_dict() if hasattr(v, "to_dict") else v
                for k, v in self.layer_results.items()
            },
            "naming_candidates_count": len(self.naming_candidates),
            "param_type_inferences": self.param_type_inferences,
            "return_type_inferences": self.return_type_inferences,
            "global_variables_count": len(self.global_variables),
        }


class ComputationRecoveryEngine:
    """4 katmanli hesaplama bazli kurtarma orkestratoru.

    Her katmani sirayla calistirir.  Config'de kapatilan katmanlar atlanir.
    Katman bagimliliklari eksikse (z3, sympy) graceful fallback uygulanir.

    Args:
        config: Karadul ana konfigurasyonu.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._comp_config = config.computation_recovery

    def recover(
        self,
        decompiled_dir: Path,
        functions_json: Optional[Path] = None,
        call_graph_json: Optional[Path] = None,
        cfg_json: Optional[Path] = None,
        ghidra_types_json: Optional[Path] = None,
        existing_sig_matches: Optional[dict[str, Any]] = None,
        existing_algo_matches: Optional[dict[str, Any]] = None,
        existing_eng_matches: Optional[dict[str, Any]] = None,
        is_go_binary: bool = False,
        binary_hash: str = "",
    ) -> ComputationRecoveryResult:
        """Ana recovery pipeline'ini calistir.

        4 katmani sirayla calistirir, her katman opsiyoneldir.
        Sonuclari birlestirip ``ComputationRecoveryResult`` dondurur.

        Args:
            decompiled_dir: Ghidra decompile C dosyalarinin bulundugu dizin.
            functions_json: Ghidra fonksiyon listesi JSON.
            call_graph_json: Ghidra call graph JSON.
            cfg_json: Ghidra CFG (control flow graph) JSON.
            ghidra_types_json: Ghidra tip bilgisi JSON.
            existing_sig_matches: Mevcut signature eslesmelerini (FLIRT vb.).
            existing_algo_matches: Mevcut algoritma eslesmelerini.
            existing_eng_matches: Mevcut muhendislik eslesmelerini.
            is_go_binary: Go dilinde derlenmis binary ise True.
            binary_hash: Binary SHA256'nin ilk 16 karakteri (cross-binary cache icin).

        Returns:
            Tum katmanlarin birlesmis sonucu.
        """
        t0 = time.monotonic()
        result = ComputationRecoveryResult()

        if not self._comp_config.enabled:
            logger.debug("Computation recovery devre disi -- atlaniyor.")
            result.success = True
            result.elapsed_seconds = time.monotonic() - t0
            return result

        logger.info("Computation recovery baslatiliyor (%s)", decompiled_dir)

        # Call graph JSON'i sonraki katmanlar icin sakla
        result.layer_results["_call_graph_json"] = call_graph_json

        # --- Layer 1: Constraint Solver ---
        if self._comp_config.enable_constraint_solver:
            result = self._run_constraint_solver(
                result, decompiled_dir, functions_json,
                call_graph_json, ghidra_types_json,
                is_go=is_go_binary and self._comp_config.go_specific_patterns,
            )

        # --- Layer 2: CFG Fingerprinting ---
        if self._comp_config.enable_cfg_fingerprint:
            result = self._run_cfg_fingerprint(
                result, cfg_json, functions_json,
                binary_hash=binary_hash,
            )

        # --- Layer 3: Signature Fusion ---
        if self._comp_config.enable_signature_fusion:
            result = self._run_signature_fusion(
                result, existing_sig_matches, existing_algo_matches,
                existing_eng_matches,
            )

        # --- Layer 4: Formula Extraction ---
        if self._comp_config.enable_formula_extraction:
            result = self._run_formula_extraction(
                result, decompiled_dir, functions_json,
            )

        result.success = True
        result.elapsed_seconds = time.monotonic() - t0
        logger.info(
            "Computation recovery tamamlandi: %.1fs, %d struct, %d array, %d type propagated",
            result.elapsed_seconds,
            result.structs_refined,
            result.arrays_detected,
            result.types_propagated,
        )
        return result

    # ------------------------------------------------------------------
    # Katman calistiricilari
    # ------------------------------------------------------------------

    def _run_constraint_solver(
        self,
        result: ComputationRecoveryResult,
        decompiled_dir: Path,
        functions_json: Optional[Path],
        call_graph_json: Optional[Path],
        ghidra_types_json: Optional[Path],
        is_go: bool = False,
    ) -> ComputationRecoveryResult:
        """Layer 1: Constraint Solver'i calistir."""
        try:
            from karadul.reconstruction.computation.constraint_solver import (
                ConstraintSolver,
            )

            solver = ConstraintSolver(self._config)
            # Mevcut struct'lari ghidra_types_json'dan al (varsa)
            existing_structs: list[dict[str, Any]] = []
            if ghidra_types_json and ghidra_types_json.exists():
                import json
                try:
                    with open(ghidra_types_json) as f:
                        types_data = json.load(f)
                    existing_structs = types_data.get("structs", [])
                except (json.JSONDecodeError, KeyError):
                    logger.warning("ghidra_types_json okunamadi: %s", ghidra_types_json)

            solver_result = solver.solve(
                decompiled_dir=decompiled_dir,
                functions_json=functions_json,
                existing_structs=existing_structs,
                call_graph_json=call_graph_json,
                is_go=is_go,
            )

            result.structs_refined = solver_result.structs_refined
            result.arrays_detected = solver_result.arrays_detected
            result.types_propagated = solver_result.types_propagated
            result.param_type_inferences = solver_result.param_type_inferences
            result.return_type_inferences = solver_result.return_type_inferences
            result.global_variables = solver_result.global_variables
            result.layer_results["constraint_solver"] = solver_result
            logger.info(
                "Layer 1 (Constraint Solver): %d struct, %d array, %d propagated, "
                "%d param types, %d return types, %d globals",
                solver_result.structs_refined,
                solver_result.arrays_detected,
                solver_result.types_propagated,
                len(solver_result.param_type_inferences),
                len(solver_result.return_type_inferences),
                len(solver_result.global_variables),
            )

        except Exception:
            logger.exception("Layer 1 (Constraint Solver) hatasi")

        return result

    def _run_cfg_fingerprint(
        self,
        result: ComputationRecoveryResult,
        cfg_json: Optional[Path],
        functions_json: Optional[Path],
        binary_hash: str = "",
    ) -> ComputationRecoveryResult:
        """Layer 2: CFG Fingerprinting -- bilinen algoritma sablonlariyla eslestirme.

        v1.8.0: Cross-binary cache entegrasyonu.
        Fingerprint'ler cache'e kaydedilir ve onceki binary'lerden eslestirme yapilir.
        """
        if cfg_json is None or not cfg_json.exists():
            logger.warning(
                "Layer 2 (CFG Fingerprint): CFG JSON bulunamadi -- atlaniyor."
            )
            return result

        try:
            from karadul.reconstruction.computation.cfg_fingerprint import (
                CFGFingerprinter,
            )

            fp_config = {
                "similarity_threshold": self._comp_config.cfg_similarity_threshold,
                "hash_bonus": 0.15,
                "max_matches_per_function": 3,
            }
            fingerprinter = CFGFingerprinter(config=fp_config)
            matches = fingerprinter.match_all(cfg_json_path=cfg_json)

            result.cfg_matches = len(matches)
            result.layer_results["cfg_fingerprint"] = {
                "matches": [m.to_dict() for m in matches],
                "total_matches": len(matches),
            }
            # Sonraki katmanlar icin match listesini sakla
            result.layer_results["_cfg_match_objects"] = matches

            logger.info(
                "Layer 2 (CFG Fingerprint): %d eslesme bulundu",
                len(matches),
            )

            # ----------------------------------------------------------
            # v1.8.0: Cross-binary cache -- fingerprint extraction + cache
            # ----------------------------------------------------------
            if binary_hash:
                try:
                    import json as _json_cb

                    # CFG JSON'dan tum fonksiyonlarin fingerprint'lerini cikar
                    cfg_data = _json_cb.loads(
                        cfg_json.read_text(encoding="utf-8"),
                    )
                    functions = cfg_data.get("functions", [])
                    all_fingerprints: dict[str, Any] = {}

                    for func_cfg in functions:
                        block_count = len(func_cfg.get("blocks", []))
                        if block_count < 3:
                            continue
                        try:
                            fp = fingerprinter.fingerprint_function(func_cfg)
                            all_fingerprints[fp.function_address] = fp
                        except Exception:
                            logger.debug("Hesaplama motoru islemi basarisiz, atlaniyor", exc_info=True)
                            continue

                    # Cache'e kaydet (isimlendirilmis fonksiyonlar)
                    if all_fingerprints:
                        CFGFingerprinter.save_to_cache(
                            all_fingerprints, binary_hash,
                        )

                    # Cross-binary match
                    cross_matches = CFGFingerprinter.match_from_cache(
                        all_fingerprints,
                        exclude_binary_hash=binary_hash,
                    )

                    if cross_matches:
                        result.layer_results["cross_binary_matches"] = [
                            {
                                "func_address": addr,
                                "func_name": (
                                    all_fingerprints[addr].function_name
                                    if addr in all_fingerprints else ""
                                ),
                                "matched_name": name,
                                "source_binary": src_bh,
                                "confidence": conf,
                            }
                            for addr, name, src_bh, conf in cross_matches
                        ]
                        logger.info(
                            "Layer 2 (Cross-Binary): %d eslesme bulundu",
                            len(cross_matches),
                        )

                except Exception as exc:
                    logger.warning(
                        "Cross-binary cache hatasi (atlaniyor): %s", exc,
                    )

        except Exception:
            logger.exception("Layer 2 (CFG Fingerprint) hatasi")

        return result

    def _run_signature_fusion(
        self,
        result: ComputationRecoveryResult,
        existing_sig_matches: Optional[dict[str, Any]],
        existing_algo_matches: Optional[dict[str, Any]],
        existing_eng_matches: Optional[dict[str, Any]],
    ) -> ComputationRecoveryResult:
        """Layer 3: Signature Fusion -- Dempster-Shafer ile birlestirme."""
        try:
            from karadul.reconstruction.computation.signature_fusion import (
                SignatureFusion,
            )

            fusion_config = {
                "min_fused_confidence": self._comp_config.fusion_min_belief,
                "propagation_enabled": True,
                "propagation_decay": getattr(
                    self._comp_config, "fusion_propagation_decay", 0.50,
                ),
                "max_hops": getattr(
                    self._comp_config, "fusion_max_hops", 2,
                ),
                "min_hint": getattr(
                    self._comp_config, "fusion_min_hint", 0.15,
                ),
                # v1.7: Iterative callee-profile propagation
                "callee_profile_enabled": getattr(
                    self._comp_config, "callee_profile_enabled", True,
                ),
                "callee_profile_config": getattr(
                    self._comp_config, "callee_profile_config", {},
                ),
            }
            fusion = SignatureFusion(config=fusion_config)

            # Layer 1 constraint sonuclarini al (varsa)
            # ConstraintSolverResult.structs -> list[ConstraintStruct]
            # Her ConstraintStruct.source_functions -> list[str] (fonksiyon isimleri)
            constraint_structs: dict[str, Any] = {}
            layer1_result = result.layer_results.get("constraint_solver")
            if layer1_result and hasattr(layer1_result, "structs"):
                for s in layer1_result.structs:
                    struct_dict = s.to_dict() if hasattr(s, "to_dict") else {}
                    struct_dict["identified_type"] = s.name
                    for func_name in (s.source_functions or []):
                        constraint_structs[func_name] = struct_dict

            # Layer 2 CFG match sonuclarini al (varsa)
            cfg_matches = result.layer_results.get("_cfg_match_objects", [])

            # Call graph JSON'i bul
            call_graph_json = result.layer_results.get("_call_graph_json")

            fused = fusion.fuse(
                constraint_structs=constraint_structs,
                cfg_matches=cfg_matches,
                existing_sig_matches=existing_sig_matches,
                existing_algo_matches=existing_algo_matches,
                existing_eng_matches=existing_eng_matches,
                call_graph_json=call_graph_json,
            )

            result.fusion_identifications = len(fused)
            result.layer_results["signature_fusion"] = {
                "identifications": {
                    addr: fid.to_dict() for addr, fid in fused.items()
                },
                "total_identifications": len(fused),
            }

            # Naming candidate'leri topla
            for addr, fid in fused.items():
                for nc in fid.naming_candidates:
                    result.naming_candidates.append({
                        "function_address": addr,
                        "function_name": fid.function_name,
                        "candidate_name": nc.name,
                        "confidence": nc.confidence,
                        "source": nc.source,
                        "reason": nc.reason,
                    })

            logger.info(
                "Layer 3 (Signature Fusion): %d tanimlama, %d naming candidate",
                len(fused),
                len(result.naming_candidates),
            )

        except Exception:
            logger.exception("Layer 3 (Signature Fusion) hatasi")

        return result

    def _run_formula_extraction(
        self,
        result: ComputationRecoveryResult,
        decompiled_dir: Path,
        functions_json: Optional[Path],
    ) -> ComputationRecoveryResult:
        """Layer 4: Formula Extraction -- C kodundan matematiksel formul cikarma."""
        try:
            from karadul.reconstruction.computation.formula_extractor import (
                FormulaExtractor,
            )

            extractor = FormulaExtractor(config=self._config)

            # Layer 2 CFG match sonuclarini al (varsa)
            cfg_matches_raw = result.layer_results.get("cfg_fingerprint", {})
            cfg_matches_list = []
            if isinstance(cfg_matches_raw, dict):
                cfg_matches_list = cfg_matches_raw.get("matches", [])

            # Layer 3 fusion sonuclarini al (varsa)
            fusion_raw = result.layer_results.get("signature_fusion", {})
            fused_ids = {}
            if isinstance(fusion_raw, dict):
                fused_ids = fusion_raw.get("identifications", {})

            formulas = extractor.extract(
                decompiled_dir=decompiled_dir,
                cfg_matches=cfg_matches_list,
                fused_ids=fused_ids,
            )

            result.formulas_extracted = len(formulas)
            result.layer_results["formula_extraction"] = {
                "formulas": [f.to_dict() for f in formulas],
                "total_formulas": len(formulas),
            }

            logger.info(
                "Layer 4 (Formula Extraction): %d formul cikarildi",
                len(formulas),
            )

        except Exception:
            logger.exception("Layer 4 (Formula Extraction) hatasi")

        return result
