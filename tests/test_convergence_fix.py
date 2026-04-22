"""v1.10.0 M2 T6: Convergence loop erken exit bug fix testleri.

Bug: NameMerger bos donerse (prev_named == empty) eski kod
ZeroDivision'u try/except ile yutup converged=True donuyordu. Bu "empty
merger" early-exit bug'i. Fix: explicit check, iki iter ust uste bos
olmadikca exit yok; ayrica min_absolute_new ile "hic yeni isim yoksa
converge" secenegi eklendi.

Pure fonksiyon: karadul.pipeline.steps._feedback_helpers.check_convergence
Entegrasyon: karadul.pipeline.steps.feedback_loop.FeedbackLoopStep
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from karadul.config import BinaryReconstructionConfig, Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps import _feedback_helpers as _fh
from karadul.pipeline.steps.feedback_loop import FeedbackLoopStep


# ---------------------------------------------------------------------------
# 1-11: Pure check_convergence davranis matrisi
# ---------------------------------------------------------------------------


class TestConvergenceFix:
    """check_convergence pure fonksiyonunun bug-fix sonrasi davranisi."""

    # --- 1 ---
    def test_iter_zero_never_converged(self) -> None:
        """iter_index=0 -> DAIMA False (ilk iter tamamlanmali).

        Prev/current ne olursa olsun, ilk iterasyon early-exit yapmaz.
        """
        # prev ve current buyuk, oran cok kucuk olsa bile:
        prev = set(range(1000))
        current = prev  # 0 yeni, ratio 0
        converged, reason = _fh.check_convergence(
            iter_index=0,
            prev_named=prev,
            current_named=current,
            threshold=0.01,
        )
        assert converged is False
        assert reason == "first_iteration"

        # Ve bos durumda:
        c2, r2 = _fh.check_convergence(
            iter_index=0,
            prev_named=set(),
            current_named=set(),
            threshold=0.01,
        )
        assert c2 is False
        assert r2 == "first_iteration"

    # --- 2 ---
    def test_iter_1_empty_prev_empty_current(self) -> None:
        """Iki iter ust uste bos -> converge (no_naming_data_two_iters)."""
        converged, reason = _fh.check_convergence(
            iter_index=1,
            prev_named=set(),
            current_named=set(),
            threshold=0.01,
        )
        assert converged is True
        assert reason == "no_naming_data_two_iters"

    # --- 3 ---
    def test_iter_1_empty_prev_nonempty_current(self) -> None:
        """Onceki bos, simdi ilk sinyal -> devam et (empty_prev_first_signal).

        Bu SENARYO orijinal bug'in tam karsiligi: NameMerger iter 0'da
        bos dondu, iter 1'de sonunda calisip isim uretti. Eski kod ratio
        hesaplamaya calisinca ZeroDivision yiyor, try/except ile yutup
        converged=True donuyordu. Simdi explicit False.
        """
        converged, reason = _fh.check_convergence(
            iter_index=1,
            prev_named=set(),
            current_named={"sym_a", "sym_b"},
            threshold=0.01,
        )
        assert converged is False
        assert reason == "empty_prev_first_signal"

    # --- 4 ---
    def test_iter_1_min_new_names_zero(self) -> None:
        """Yeni isim yok (current == prev) -> converge (no_new_names)."""
        prev = {"a", "b", "c"}
        current = prev  # ayni set, hic yeni yok
        converged, reason = _fh.check_convergence(
            iter_index=1,
            prev_named=prev,
            current_named=current,
            threshold=0.01,
            min_absolute_new=1,
        )
        assert converged is True
        assert reason == "no_new_names"

    # --- 5 ---
    def test_iter_1_ratio_below_threshold(self) -> None:
        """new/prev < 0.01 -> converge (convergence_ratio_...)."""
        prev = set(f"sym_{i}" for i in range(1000))
        # 5 yeni isim -> ratio 5/1000 = 0.005
        current = prev | {"new_1", "new_2", "new_3", "new_4", "new_5"}
        converged, reason = _fh.check_convergence(
            iter_index=1,
            prev_named=prev,
            current_named=current,
            threshold=0.01,
        )
        assert converged is True
        assert reason.startswith("convergence_ratio_")
        assert "0.005" in reason

    # --- 6 ---
    def test_iter_1_ratio_above_threshold(self) -> None:
        """new/prev > 0.01 -> continue."""
        prev = set(f"sym_{i}" for i in range(100))
        # 5 yeni isim -> ratio 5/100 = 0.05 > 0.01
        current = prev | {"new_1", "new_2", "new_3", "new_4", "new_5"}
        converged, reason = _fh.check_convergence(
            iter_index=1,
            prev_named=prev,
            current_named=current,
            threshold=0.01,
        )
        assert converged is False
        assert reason == "continuing"

    # --- 7 ---
    def test_threshold_exactly_boundary(self) -> None:
        """ratio == threshold -> continue (strict < ile converge).

        prev=100, new=1 -> ratio 0.01, threshold 0.01 -> 0.01 < 0.01 False.
        """
        prev = set(f"sym_{i}" for i in range(100))
        current = prev | {"new_1"}  # ratio = 1/100 = 0.01 kesin
        converged, reason = _fh.check_convergence(
            iter_index=1,
            prev_named=prev,
            current_named=current,
            threshold=0.01,
        )
        assert converged is False
        assert reason == "continuing"

    # --- 8 ---
    def test_min_absolute_new_config_respected(self) -> None:
        """min_absolute_new=5, 3 yeni -> converge (no_new_names).

        3 yeni isim var ama min_absolute_new=5 talep ediyor -> "yeterli
        ilerleme yok" olarak converge.
        """
        prev = set(f"sym_{i}" for i in range(1000))
        current = prev | {"n1", "n2", "n3"}
        converged, reason = _fh.check_convergence(
            iter_index=1,
            prev_named=prev,
            current_named=current,
            threshold=0.001,  # ratio 0.003 > 0.001, normalde devam
            min_absolute_new=5,
        )
        assert converged is True
        assert reason == "no_new_names"

    # --- 9 ---
    def test_large_prev_small_new(self) -> None:
        """prev=1000, new=5 -> ratio 0.005 -> converge."""
        prev = set(f"sym_{i}" for i in range(1000))
        current = prev | set(f"new_{i}" for i in range(5))
        converged, reason = _fh.check_convergence(
            iter_index=1,
            prev_named=prev,
            current_named=current,
            threshold=0.01,
        )
        assert converged is True
        assert reason.startswith("convergence_ratio_")

    # --- 10 ---
    def test_zero_division_no_more(self) -> None:
        """prev bos + current bos -> True, NO exception.

        Bug'in merkezindeki assertion: kod hicbir sekilde ZeroDivisionError
        firlatmamali. Sinir durumlar (empty sets) explicit handle edilir.
        """
        # Hem bos-bos, hem bos-dolu, hem dolu-bos karsilastirmalari:
        for prev, current in [
            (set(), set()),           # iki iter bos
            (set(), {"a", "b"}),      # bos sonra dolu
            ({"a"}, {"a"}),           # hic yeni isim yok (ratio 0)
        ]:
            # Exception atilmamali, her zaman geri donmeli
            try:
                converged, reason = _fh.check_convergence(
                    iter_index=1,
                    prev_named=prev,
                    current_named=current,
                    threshold=0.01,
                )
            except ZeroDivisionError:
                pytest.fail(
                    "check_convergence ZeroDivisionError atti "
                    f"(prev={prev}, current={current})",
                )
            assert isinstance(converged, bool)
            assert isinstance(reason, str) and reason

    # --- 11 ---
    def test_convergence_reason_strings(self) -> None:
        """5 farkli reason string'inin dogru durumda donduklerini dogrula.

        Reason contract:
        - "first_iteration" (iter=0)
        - "no_naming_data_two_iters" (prev={} AND current={})
        - "empty_prev_first_signal" (prev={} AND current != {})
        - "no_new_names" (new_names < min_absolute_new)
        - "convergence_ratio_X.XXX" (ratio < threshold)
        - "continuing" (ratio >= threshold)
        """
        # first_iteration
        _, r = _fh.check_convergence(
            iter_index=0, prev_named={"a"}, current_named={"a", "b"},
            threshold=0.01,
        )
        assert r == "first_iteration"

        # no_naming_data_two_iters
        _, r = _fh.check_convergence(
            iter_index=2, prev_named=set(), current_named=set(),
            threshold=0.01,
        )
        assert r == "no_naming_data_two_iters"

        # empty_prev_first_signal
        _, r = _fh.check_convergence(
            iter_index=1, prev_named=set(), current_named={"x"},
            threshold=0.01,
        )
        assert r == "empty_prev_first_signal"

        # no_new_names
        _, r = _fh.check_convergence(
            iter_index=1, prev_named={"a", "b"}, current_named={"a", "b"},
            threshold=0.01,
        )
        assert r == "no_new_names"

        # convergence_ratio_X.XXX
        prev = set(range(1000))
        current = prev | set(range(1000, 1002))  # 2/1000 = 0.002
        _, r = _fh.check_convergence(
            iter_index=1, prev_named=prev, current_named=current,
            threshold=0.01,
        )
        assert r.startswith("convergence_ratio_")
        assert "0.002" in r

        # continuing
        prev = set(range(10))
        current = prev | {99}  # 1/10 = 0.1 >> 0.01
        _, r = _fh.check_convergence(
            iter_index=1, prev_named=prev, current_named=current,
            threshold=0.01,
        )
        assert r == "continuing"


# ---------------------------------------------------------------------------
# 12: Integration — FeedbackLoopStep empty-merger sonrasi erken cikmamali
# ---------------------------------------------------------------------------


class TestFeedbackLoopIntegrationFix:
    """FeedbackLoopStep run() icinde yeni helper davranisi dogru ciktiyor mu."""

    def test_feedback_loop_full_run_with_fix(self) -> None:
        """NameMerger iter 0'da bos dondu varsayimi: loop iter 1'de cikmamali.

        Mini integration: run_one_iteration mock'lu. 3 iter izni var.
        - Iter 0: current_named=set() (NameMerger bos)
        - Iter 1: current_named={"a","b"} (ilk sinyal)
        - Iter 2: current_named={"a","b"} (hic yeni isim)

        Bekleme:
        - Eski kod: iter 1 basinda converged (empty_prev_first_signal
          bug'i) -> 1 iter sadece.
        - Yeni kod: iter 0 -> False (first_iteration), iter 1 -> False
          (empty_prev_first_signal), iter 2 -> True (no_new_names).
        """
        config = Config()
        config.binary_reconstruction.pipeline_iterations = 3
        config.binary_reconstruction.pipeline_convergence_threshold = 0.01
        config.binary_reconstruction.pipeline_iteration_timeout = 600.0
        config.binary_reconstruction.pipeline_min_new_names_per_iter = 1

        # Fake pipeline context minimali
        fake_pc = MagicMock()
        fake_pc.config = config
        fake_pc.metadata = {}
        fake_pc.target.file_hash = "deadbeefcafebabe" + "0" * 48
        fake_pc.target.target_type = "macho"
        # workspace.get_stage_dir -> Path
        fake_pc.workspace.get_stage_dir.return_value = Path("/tmp/karadul_test_recon")

        # Fake artifacts
        fake_artifacts = {
            "c_files": [],
            "file_cache": {},
            "decompiled_dir": Path("/tmp/karadul_test_decomp"),
            "output_dir": Path("/tmp/karadul_test_out"),
            "functions_json_path": Path("/tmp/f.json"),
            "strings_json_path": Path("/tmp/s.json"),
            "call_graph_json_path": Path("/tmp/cg.json"),
            "ghidra_types_json_path": Path("/tmp/t.json"),
            "xrefs_json_path": Path("/tmp/xr.json"),
            "cfg_json_path": Path("/tmp/cfg.json"),
            "fid_json_path": Path("/tmp/fid.json"),
            "decompiled_json_path": Path("/tmp/dec.json"),
            "functions_data": {},
            "strings_data": {},
            "call_graph_data": {},
            "sig_matches": [],
            "algo_result_filtered": None,
            "eng_result_filtered": None,
            "extracted_names": {},
            "pcode_naming_candidates": [],
        }

        fake_ctx = MagicMock(spec=StepContext)
        fake_ctx.pipeline_context = fake_pc
        fake_ctx.artifacts = fake_artifacts
        fake_ctx.stats = {}
        fake_ctx.errors = []

        # Iter her cagrida dondurecegimiz ardisik durumlar:
        outcomes = [
            # iter 0: NameMerger bos, current_named = set()
            SimpleNamespace(
                iter_duration=0.1,
                current_named_set=set(),
                newly_named=set(),
                new_iter_stats={"iteration": 1, "new_names": 0,
                                "total_names": 0, "duration": 0.1},
                decompiled_dir=Path("/tmp/karadul_test_decomp"),
            ),
            # iter 1: ilk sinyal -> {"a","b"}
            SimpleNamespace(
                iter_duration=0.1,
                current_named_set={"a", "b"},
                newly_named={"a", "b"},
                new_iter_stats={"iteration": 2, "new_names": 2,
                                "total_names": 2, "duration": 0.1},
                decompiled_dir=Path("/tmp/karadul_test_decomp"),
            ),
            # iter 2: hic yeni isim yok -> converge
            SimpleNamespace(
                iter_duration=0.1,
                current_named_set={"a", "b"},
                newly_named=set(),
                new_iter_stats={"iteration": 3, "new_names": 0,
                                "total_names": 2, "duration": 0.1},
                decompiled_dir=Path("/tmp/karadul_test_decomp"),
            ),
        ]

        step = FeedbackLoopStep()

        with patch.object(
            step, "_pre_instantiate",
            return_value=(None, None, None),
        ), patch(
            "karadul.pipeline.steps.feedback_loop.run_one_iteration",
            side_effect=outcomes,
        ) as mock_run_iter:
            # LoopState import'u feedback_loop modulunde var; run()
            # LoopState'i kendi icinde olusturuyor.
            result = step.run(fake_ctx)

        # 3 iter beklenti (iter 2 sonunda no_new_names ile converged):
        assert mock_run_iter.call_count == 3, (
            f"Eski bug: iter 1'de empty_prev_first_signal yerine "
            f"converged=True donuyordu. Beklenen 3, gozlenen "
            f"{mock_run_iter.call_count}."
        )
        assert result["convergence_reason"] == "no_new_names"
        assert len(result["iteration_stats"]) == 3
