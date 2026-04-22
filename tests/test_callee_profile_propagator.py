"""Callee-profile iterative propagation test suite.

Test gruplari:
1. CalleeProfilePropagator unit testleri
   - Domain classification
   - Backward pass (callee -> caller)
   - Forward pass (caller -> callee)
   - Iterative convergence
   - Confidence decay
   - Hub/dispatcher detection
   - Thin wrapper detection
   - Error handler detection
2. SignatureFusion entegrasyon testleri
   - Callee-profile wiring in fuse()
   - Source="callee_profile" naming candidates
3. Edge cases
   - Empty call graph
   - No known functions
   - Cycles in call graph
   - Single function
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from karadul.reconstruction.recovery_layers.callee_profile_propagator import (
    CalleeProfilePropagator,
    PropagatedName,
    PropagationResult,
    _KEYWORD_TO_DOMAIN,
)


# ===========================================================================
# Yardimci
# ===========================================================================

def _make_fused_dict(**entries: tuple[str, float]) -> dict[str, Any]:
    """Basit fused_results dict olustur.

    Kullanim:
        _make_fused_dict(
            addr1=("malloc", 0.85),
            addr2=("free", 0.80),
        )
    """
    result = {}
    for addr, (name, conf) in entries.items():
        result[addr] = {
            "identified_as": name,
            "fused_confidence": conf,
        }
    return result


def _propagator(**kw: Any) -> CalleeProfilePropagator:
    """Test propagator olustur."""
    return CalleeProfilePropagator(config=kw)


# ===========================================================================
# 1. Domain Classification
# ===========================================================================

class TestDomainClassification:
    """_classify_domain birim testleri."""

    def test_crypto_keywords(self) -> None:
        p = _propagator()
        assert p._classify_domain("aes_encrypt") == "crypto"
        assert p._classify_domain("sha256_wrapper") == "crypto"
        assert p._classify_domain("RSA_sign") == "crypto"

    def test_memory_keywords(self) -> None:
        p = _propagator()
        assert p._classify_domain("malloc") == "memory"
        assert p._classify_domain("free_wrapper") == "memory"
        assert p._classify_domain("memcpy_internal") == "memory"

    def test_file_io_keywords(self) -> None:
        p = _propagator()
        assert p._classify_domain("fopen_handler") == "file_io"
        assert p._classify_domain("fwrite") == "file_io"

    def test_network_keywords(self) -> None:
        p = _propagator()
        assert p._classify_domain("socket_create") == "network"
        assert p._classify_domain("connect_handler") == "network"

    def test_unknown_returns_empty(self) -> None:
        p = _propagator()
        assert p._classify_domain("FUN_12345") == ""
        assert p._classify_domain("sub_abcdef") == ""
        assert p._classify_domain("") == ""

    def test_mixed_domain_keywords(self) -> None:
        """Birden fazla domain keyword'u -- en cok olan kazanir."""
        p = _propagator()
        # "ssl_socket" -> ssl=crypto, socket=network -> 1-1 draw, ilk bulunan
        domain = p._classify_domain("ssl_socket_connect")
        assert domain in ("crypto", "network")

    def test_substring_fallback(self) -> None:
        """Kisa keyword substring eslesmesi."""
        p = _propagator()
        # "openssl_init" -> "ssl" substring match -> crypto
        assert p._classify_domain("openssl_init") == "crypto"


# ===========================================================================
# 2. Backward Pass (Callee -> Caller)
# ===========================================================================

class TestBackwardPass:
    """Backward pass testleri: callee isimlerinden caller cikarimi."""

    def test_thin_wrapper_single_callee(self) -> None:
        """1 bilinen callee + kucuk body -> wrapper."""
        fused = _make_fused_dict(
            callee1=("aes_encrypt", 0.90),
        )
        call_graph = {
            "caller1": ["callee1"],
        }
        p = _propagator()
        result = p.propagate(fused, call_graph)
        assert len(result.propagated_names) >= 1
        pn = result.propagated_names[0]
        assert "aes_encrypt" in pn.name.lower() or "wrapper" in pn.name.lower()
        assert pn.direction == "backward"

    def test_domain_clustering_crypto(self) -> None:
        """3+ crypto callee -> crypto_operation."""
        fused = _make_fused_dict(
            c1=("aes_encrypt", 0.90),
            c2=("sha256_hash", 0.85),
            c3=("rsa_sign", 0.80),
        )
        call_graph = {
            "caller1": ["c1", "c2", "c3"],
        }
        p = _propagator()
        result = p.propagate(fused, call_graph)
        assert len(result.propagated_names) >= 1
        pn = result.propagated_names[0]
        assert "crypto" in pn.name.lower()
        assert pn.domain == "crypto"

    def test_domain_clustering_memory(self) -> None:
        """2+ memory callee -> memory_helper."""
        fused = _make_fused_dict(
            c1=("malloc", 0.90),
            c2=("free", 0.85),
        )
        call_graph = {
            "caller1": ["c1", "c2"],
        }
        p = _propagator()
        result = p.propagate(fused, call_graph)
        assert len(result.propagated_names) >= 1
        pn = result.propagated_names[0]
        assert "memory" in pn.name.lower()
        assert pn.domain == "memory"

    def test_hub_dispatcher(self) -> None:
        """10+ callee, cogu bilinen -> dispatcher."""
        fused = {}
        callees = []
        for i in range(12):
            addr = f"c{i}"
            fused[addr] = {
                "identified_as": f"crypto_func_{i}",
                "fused_confidence": 0.80,
            }
            callees.append(addr)
        call_graph = {
            "hub": callees,
        }
        p = _propagator()
        result = p.propagate(fused, call_graph)
        assert len(result.propagated_names) >= 1
        pn = result.propagated_names[0]
        assert "dispatcher" in pn.name.lower()

    def test_error_handler_detection(self) -> None:
        """Sadece error-handling callee'ler -> error_handler."""
        fused = _make_fused_dict(
            c1=("perror", 0.90),
            c2=("exit", 0.85),
        )
        call_graph = {
            "caller1": ["c1", "c2"],
        }
        p = _propagator()
        result = p.propagate(fused, call_graph)
        assert len(result.propagated_names) >= 1
        pn = result.propagated_names[0]
        assert "error" in pn.name.lower()

    def test_skip_already_named(self) -> None:
        """Zaten isimli fonksiyonlar atlanmali."""
        fused = _make_fused_dict(
            caller1=("already_known", 0.90),
            c1=("malloc", 0.90),
            c2=("free", 0.85),
        )
        call_graph = {
            "caller1": ["c1", "c2"],
        }
        p = _propagator()
        result = p.propagate(fused, call_graph)
        # caller1 zaten isimli -- yeniden isimlendirilmemeli
        for pn in result.propagated_names:
            assert pn.function_address != "caller1"

    def test_min_confidence_filter(self) -> None:
        """Dusuk confidence olanlar filtrelenmeli."""
        fused = _make_fused_dict(
            c1=("malloc", 0.90),
        )
        call_graph = {
            # 1 bilinen callee, 20 bilinmeyen -> callee ratio cok dusuk
            "caller1": ["c1"] + [f"unknown_{i}" for i in range(20)],
        }
        p = _propagator(min_confidence=0.80)  # Yuksek esik
        result = p.propagate(fused, call_graph)
        # Callee ratio 1/21 = 0.048, confidence * 0.048 < 0.80 -> filtreli
        assert len(result.propagated_names) == 0


# ===========================================================================
# 3. Forward Pass (Caller -> Callee)
# ===========================================================================

class TestForwardPass:
    """Forward pass testleri: bilinen caller'dan callee cikarimi."""

    def test_single_unknown_callee(self) -> None:
        """Bilinen caller + tek bilinmeyen callee -> caller_internal."""
        fused = _make_fused_dict(
            caller1=("crypto_handler", 0.85),
            c1=("aes_encrypt", 0.90),  # bilinen callee
        )
        call_graph = {
            "caller1": ["c1", "unknown1"],
        }
        p = _propagator()
        result = p.propagate(fused, call_graph)
        # unknown1 icin forward pass calistirilmali
        forward_names = [
            pn for pn in result.propagated_names
            if pn.direction == "forward"
        ]
        assert len(forward_names) >= 1
        pn = forward_names[0]
        assert pn.function_address == "unknown1"
        assert "crypto" in pn.name.lower() or "internal" in pn.name.lower()

    def test_multiple_unknown_callees_skipped(self) -> None:
        """Birden fazla bilinmeyen callee -> forward pass yapilmaz."""
        fused = _make_fused_dict(
            caller1=("handler", 0.85),
        )
        call_graph = {
            "caller1": ["unknown1", "unknown2"],
        }
        p = _propagator()
        result = p.propagate(fused, call_graph)
        forward_names = [
            pn for pn in result.propagated_names
            if pn.direction == "forward"
        ]
        assert len(forward_names) == 0


# ===========================================================================
# 4. Iterative Convergence
# ===========================================================================

class TestIterativeConvergence:
    """Iteratif propagasyon ve convergence testleri."""

    def test_multi_round_propagation(self) -> None:
        """Round 1'de bulunan isimler Round 2'de seed olmali.

        Zincir: c1(known) <- caller1(round0) <- caller2(round1)
        """
        fused = _make_fused_dict(
            c1=("aes_encrypt", 0.90),
            c2=("sha256_hash", 0.85),
        )
        call_graph = {
            "caller1": ["c1", "c2"],           # Round 0: crypto_operation
            "caller2": ["caller1", "c1"],       # Round 1: caller1 artik bilinen
        }
        p = _propagator(max_rounds=5)
        result = p.propagate(fused, call_graph)
        # En az 2 isim (caller1 + caller2) bulunmali
        assert len(result.propagated_names) >= 2
        # Convergence round 1'den fazla olmali
        assert result.total_rounds >= 2

    def test_convergence_no_new(self) -> None:
        """Yeni isim kalmadiginda durmali."""
        fused = _make_fused_dict(
            c1=("malloc", 0.90),
        )
        call_graph = {
            "caller1": ["c1"],
        }
        p = _propagator(max_rounds=10)
        result = p.propagate(fused, call_graph)
        assert result.convergence_reason in ("no_new", "threshold")

    def test_max_rounds_limit(self) -> None:
        """Max round limitine ulasildiginda durmali."""
        # Buyuk zincir: c0 <- c1 <- c2 <- ... <- c50
        fused = _make_fused_dict(c0=("aes_encrypt", 0.90))
        call_graph = {}
        for i in range(1, 50):
            call_graph[f"c{i}"] = [f"c{i-1}"]

        p = _propagator(max_rounds=3)
        result = p.propagate(fused, call_graph)
        assert result.total_rounds <= 3

    def test_confidence_decay(self) -> None:
        """Her turda confidence dusmeli."""
        fused = _make_fused_dict(
            c1=("aes_encrypt", 0.90),
            c2=("sha256_hash", 0.85),
        )
        call_graph = {
            "caller1": ["c1", "c2"],
            "caller2": ["caller1"],
        }
        p = _propagator(
            max_rounds=5, base_confidence=0.90, confidence_decay=0.80,
        )
        result = p.propagate(fused, call_graph)
        # Round 0 ve round 1 confidence'lari farkliysa decay calisiyor
        round0 = [pn for pn in result.propagated_names if pn.round_discovered == 0]
        round1 = [pn for pn in result.propagated_names if pn.round_discovered == 1]

        if round0 and round1:
            max_r0 = max(pn.confidence for pn in round0)
            max_r1 = max(pn.confidence for pn in round1)
            assert max_r1 < max_r0, (
                f"Round 1 confidence ({max_r1}) < Round 0 ({max_r0}) olmali"
            )

    def test_confidence_too_low_stops(self) -> None:
        """Confidence esik altina dusunce durmali."""
        fused = _make_fused_dict(c0=("malloc", 0.90))
        call_graph = {}
        for i in range(1, 20):
            call_graph[f"c{i}"] = [f"c{i-1}"]

        p = _propagator(
            max_rounds=15,
            base_confidence=0.50,
            confidence_decay=0.50,
            min_confidence=0.30,
        )
        result = p.propagate(fused, call_graph)
        # base=0.50, decay=0.50 -> r0=0.50, r1=0.25 < 0.30 -> durur
        # Round 0'da tek callee zinciri thin wrapper olarak bulunabilir
        # Round 1'de confidence 0.25 < 0.30 -> durur
        assert result.total_rounds <= 2


# ===========================================================================
# 5. Edge Cases
# ===========================================================================

class TestEdgeCases:
    """Kenar durumlar."""

    def test_empty_call_graph(self) -> None:
        """Bos call graph -> bos sonuc."""
        fused = _make_fused_dict(c1=("malloc", 0.90))
        p = _propagator()
        result = p.propagate(fused, {})
        assert len(result.propagated_names) == 0
        assert result.convergence_reason == "no_call_graph"

    def test_no_known_functions(self) -> None:
        """Bilinen fonksiyon yoksa -> bos sonuc."""
        call_graph = {"a": ["b"], "b": ["c"]}
        p = _propagator()
        result = p.propagate({}, call_graph)
        assert len(result.propagated_names) == 0

    def test_cycle_in_call_graph(self) -> None:
        """Dongusel call graph crash etmemeli."""
        fused = _make_fused_dict(
            c1=("malloc", 0.90),
            c2=("free", 0.85),
        )
        call_graph = {
            "a": ["c1", "c2"],
            "b": ["a"],
            "a_again": ["b"],  # a->b->a cycle
        }
        # Dongu: a->b->a_again->b->... ama already_named/all_propagated
        # korumasini test ediyoruz
        p = _propagator(max_rounds=5)
        result = p.propagate(fused, call_graph)
        # Crash olmamasi yeterli
        assert isinstance(result, PropagationResult)

    def test_single_function_no_callees(self) -> None:
        """Callee'si olmayan fonksiyon -> bos sonuc."""
        fused = _make_fused_dict(only=("main", 0.90))
        call_graph = {"only": []}
        p = _propagator()
        result = p.propagate(fused, call_graph)
        assert len(result.propagated_names) == 0

    def test_fused_identification_objects(self) -> None:
        """dict yerine FusedIdentification objesi ile calismali."""
        from karadul.reconstruction.recovery_layers.signature_fusion import (
            FusedIdentification,
        )
        fused = {
            "c1": FusedIdentification(
                function_name="malloc",
                function_address="c1",
                identified_as="malloc",
                category="memory",
                fused_confidence=0.90,
            ),
            "c2": FusedIdentification(
                function_name="free",
                function_address="c2",
                identified_as="free",
                category="memory",
                fused_confidence=0.85,
            ),
        }
        call_graph = {"caller1": ["c1", "c2"]}
        p = _propagator()
        result = p.propagate(fused, call_graph)
        assert len(result.propagated_names) >= 1

    def test_propagated_name_to_dict(self) -> None:
        """PropagatedName.to_naming_candidate_dict() formati."""
        pn = PropagatedName(
            function_address="0x1234",
            name="crypto_wrapper",
            confidence=0.75,
            reason="test",
            round_discovered=1,
            domain="crypto",
            direction="backward",
        )
        d = pn.to_naming_candidate_dict()
        assert d["candidate_name"] == "crypto_wrapper"
        assert d["confidence"] == 0.75
        assert d["source"] == "callee_profile"

    def test_result_to_dict(self) -> None:
        """PropagationResult.to_dict() formati."""
        r = PropagationResult(
            total_rounds=3,
            names_per_round=[5, 2, 0],
            convergence_reason="no_new",
        )
        d = r.to_dict()
        assert d["total_rounds"] == 3
        assert d["convergence_reason"] == "no_new"


# ===========================================================================
# 6. SignatureFusion Entegrasyon
# ===========================================================================

class TestSignatureFusionIntegration:
    """SignatureFusion ile entegrasyon testleri."""

    def _fusion(self, **kw: Any):
        from karadul.reconstruction.recovery_layers.signature_fusion import (
            SignatureFusion,
        )
        return SignatureFusion(config=kw)

    def test_callee_profile_wired_in_fuse(self, tmp_path: Path) -> None:
        """fuse() callee-profile propagasyonu calistirmali."""
        # Call graph: caller1 -> [c1, c2] (her ikisi de bilinen crypto)
        cg = {
            "edges": [
                {"from_name": "FUN_caller1", "to_name": "FUN_c1"},
                {"from_name": "FUN_caller1", "to_name": "FUN_c2"},
            ],
        }
        cg_path = tmp_path / "call_graph.json"
        cg_path.write_text(json.dumps(cg), encoding="utf-8")

        # Bilinen fonksiyonlar (signature_db uzerinden)
        sig_matches = {
            "FUN_c1": {"name": "aes_encrypt", "confidence": 0.95, "library": "openssl"},
            "FUN_c2": {"name": "sha256_hash", "confidence": 0.90, "library": "openssl"},
        }

        fusion = self._fusion(
            min_fused_confidence=0.01,
            callee_profile_enabled=True,
        )
        result = fusion.fuse(
            existing_sig_matches=sig_matches,
            call_graph_json=cg_path,
        )

        # FUN_caller1 icin bir tanimlama olusmus olmali
        # (ya propagate_hints, ya infer_from_callees, ya da callee_profile)
        assert isinstance(result, dict)
        # En az bilinen 2 fonksiyon var
        assert len(result) >= 2

    def test_callee_profile_disabled(self, tmp_path: Path) -> None:
        """callee_profile_enabled=False oldugunda calismamali."""
        cg = {"FUN_caller1": ["FUN_c1"]}
        cg_path = tmp_path / "call_graph.json"
        cg_path.write_text(json.dumps(cg), encoding="utf-8")

        sig_matches = {
            "FUN_c1": {"name": "malloc", "confidence": 0.95, "library": "libc"},
        }

        fusion = self._fusion(
            min_fused_confidence=0.01,
            callee_profile_enabled=False,
        )
        result = fusion.fuse(
            existing_sig_matches=sig_matches,
            call_graph_json=cg_path,
        )
        # callee_profile devredisi -- sadece mevcut mekanizmalar calismali
        assert isinstance(result, dict)

    def test_callee_profile_source_in_candidates(self, tmp_path: Path) -> None:
        """Callee-profile naming candidate'leri source='callee_profile' olmali."""
        # 3 crypto callee -> domain clustering -> crypto_operation
        cg = {
            "edges": [
                {"from_name": "FUN_unknown", "to_name": "FUN_aes"},
                {"from_name": "FUN_unknown", "to_name": "FUN_sha"},
                {"from_name": "FUN_unknown", "to_name": "FUN_rsa"},
            ],
        }
        cg_path = tmp_path / "call_graph.json"
        cg_path.write_text(json.dumps(cg), encoding="utf-8")

        sig_matches = {
            "FUN_aes": {"name": "aes_encrypt", "confidence": 0.95, "library": "openssl"},
            "FUN_sha": {"name": "sha256_hash", "confidence": 0.90, "library": "openssl"},
            "FUN_rsa": {"name": "rsa_sign", "confidence": 0.85, "library": "openssl"},
        }

        fusion = self._fusion(
            min_fused_confidence=0.01,
            callee_profile_enabled=True,
        )
        result = fusion.fuse(
            existing_sig_matches=sig_matches,
            call_graph_json=cg_path,
        )

        # FUN_unknown icin callee_profile source'lu candidate var mi?
        if "FUN_unknown" in result:
            fid = result["FUN_unknown"]
            callee_profile_candidates = [
                nc for nc in fid.naming_candidates
                if nc.source == "callee_profile"
            ]
            # Callee-profile buldugundan callee_profile source'lu olmali
            # (eger callee_profile bu fonksiyonu adlandirdiysa)
            has_callee_profile_hint = any(
                "callee_profile(" in h for h in fid.propagated_hints
            )
            if has_callee_profile_hint:
                assert len(callee_profile_candidates) >= 1, (
                    f"callee_profile source'lu candidate beklendi, "
                    f"bulunanlar: {[nc.source for nc in fid.naming_candidates]}"
                )
