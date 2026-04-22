"""v1.8.0 Bug 3 Fix: BytePatternMatcher selectivity testleri.

Two-pass selectivity filtresi:
- 1 signature 1 fonksiyona eslestiyse -> penalty yok
- 1 signature 10 fonksiyona eslestiyse -> confidence * 0.5 (suspicious)
- 1 signature 25 fonksiyona eslestiyse -> discard (noise)

Varsayilan esikler: max_selective=5, max_suspicious=20
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from karadul.analyzers.byte_pattern_matcher import BytePatternMatcher


# ---------------------------------------------------------------------------
# Test helper: sahte FLIRT signature
# ---------------------------------------------------------------------------

class FakeSig:
    """Minimal sahte signature."""

    def __init__(
        self,
        name: str,
        byte_pattern: bytes,
        mask: bytes | None = None,
        library: str = "testlib",
        size_range: tuple[int, int] = (0, 0),
        category: str = "test",
        purpose: str = "test purpose",
    ):
        self.name = name
        self.byte_pattern = byte_pattern
        self.mask = mask if mask else b"\xff" * len(byte_pattern)
        self.library = library
        self.size_range = size_range
        self.category = category
        self.purpose = purpose


# ---------------------------------------------------------------------------
# Fixture: sahte binary + functions JSON generator
# ---------------------------------------------------------------------------

def _make_binary_and_json(tmp_path, n_funcs: int, pattern: bytes):
    """n_funcs adet FUN_xxx fonksiyonu iceren sahte binary + JSON olustur.

    Her fonksiyon ayni byte pattern'e sahip (worst case: 1 sig -> N match).
    """
    # Binary: 0x1000 offset'ten baslayan fonksiyonlar, her biri 64 byte aralikli
    bin_data = bytearray(0x1000 + n_funcs * 64 + 64)
    funcs = []
    for i in range(n_funcs):
        offset = 0x1000 + i * 64
        bin_data[offset:offset + len(pattern)] = pattern
        addr = 0x100000000 + offset  # vmaddr + offset (fileoff=0 varsayimi)
        funcs.append({
            "name": f"FUN_{addr:x}",
            "address": f"{addr:x}",
            "size": 64,
        })

    bin_path = tmp_path / "test_bin"
    bin_path.write_bytes(bytes(bin_data))

    json_path = tmp_path / "funcs.json"
    json_path.write_text(json.dumps({"functions": funcs}))

    return bin_path, json_path


def _run_match(tmp_path, n_funcs, pattern, sig, **kwargs):
    """Ortak test logic: binary olustur, matcher calistir, result dondur."""
    bin_path, json_path = _make_binary_and_json(tmp_path, n_funcs, pattern)

    # Varsayilan degerler -- kwargs ile override edilebilir
    defaults = {"min_pattern_length": 16, "min_confidence": 0.50}
    defaults.update(kwargs)

    m = BytePatternMatcher(**defaults)

    otool_output = "  segname __TEXT\n   vmaddr 0x0000000100000000\n  fileoff 0\n"
    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.Mock(
            stdout=otool_output, stderr="", returncode=0,
        )
        result = m.match_unknown_functions(bin_path, json_path, [sig])
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSelectivity1to1:
    """1 signature -> 1 fonksiyon: penalty yok, normal match."""

    def test_single_match_no_penalty(self, tmp_path):
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_a", byte_pattern=pattern)

        result = _run_match(tmp_path, 1, pattern, sig)

        assert result.total_matched == 1
        match_info = list(result.matches.values())[0]
        # Confidence orijinal olmali (penalty yok)
        assert match_info["confidence"] >= 0.80


class TestSelectivity1to10:
    """1 signature -> 10 fonksiyon: suspicious range (6-20), confidence * 0.5."""

    def test_ten_matches_penalized(self, tmp_path):
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_b", byte_pattern=pattern)

        # Orijinal confidence ~0.90, penalty sonrasi ~0.45
        # min_confidence 0.40'a dusuruyoruz ki penalty sonrasi elenmemesi icin
        result = _run_match(tmp_path, 10, pattern, sig, min_confidence=0.40)

        # 10 > max_selective(5), 10 <= max_suspicious(20) -> penalty
        assert result.total_matched == 10
        for match_info in result.matches.values():
            # Penalty uygulandi: confidence * 0.5
            assert match_info["confidence"] < 0.60  # orijinal ~0.90 * 0.5 = ~0.45

    def test_ten_matches_all_penalized_below_threshold(self, tmp_path):
        """min_confidence yuksekse penalty sonrasi elenebilir."""
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_c", byte_pattern=pattern)

        # min_confidence=0.80 -> penalty sonrasi 0.45 < 0.80 -> hepsi elenir
        result = _run_match(
            tmp_path, 10, pattern, sig, min_confidence=0.80,
        )
        assert result.total_matched == 0


class TestSelectivity1to25:
    """1 signature -> 25 fonksiyon: discard (> max_suspicious=20)."""

    def test_twentyfive_matches_discarded(self, tmp_path):
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_noise", byte_pattern=pattern)

        result = _run_match(tmp_path, 25, pattern, sig)

        # 25 > max_suspicious(20) -> HEPSI discard
        assert result.total_matched == 0
        assert result.matches == {}


class TestSelectivityMixed:
    """Farkli signature'lar farkli sayida fonksiyona eslesiyor."""

    def test_mixed_selectivity(self, tmp_path):
        """3 signature: 1->1 match, 2->10 match, 3->25 match.

        Sadece sig1 ve sig2 gecmeli (sig2 penalize, sig3 discard).
        """
        pat1 = b"\xAA\xBB\xCC\xDD\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xEC"
        pat2 = b"\x11\x22\x33\x44\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xEC"
        pat3 = b"\x55\x48\x89\xE5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xEC"

        sig1 = FakeSig(name="_unique", byte_pattern=pat1)
        sig2 = FakeSig(name="_suspicious", byte_pattern=pat2)
        sig3 = FakeSig(name="_noise", byte_pattern=pat3)

        # Binary: 1 + 10 + 25 = 36 fonksiyon
        bin_data = bytearray(0x1000 + 36 * 64 + 64)
        funcs = []
        idx = 0

        # 1 fonksiyon pat1 ile
        for _ in range(1):
            offset = 0x1000 + idx * 64
            bin_data[offset:offset + 16] = pat1
            addr = 0x100000000 + offset
            funcs.append({"name": f"FUN_{addr:x}", "address": f"{addr:x}", "size": 64})
            idx += 1

        # 10 fonksiyon pat2 ile
        for _ in range(10):
            offset = 0x1000 + idx * 64
            bin_data[offset:offset + 16] = pat2
            addr = 0x100000000 + offset
            funcs.append({"name": f"FUN_{addr:x}", "address": f"{addr:x}", "size": 64})
            idx += 1

        # 25 fonksiyon pat3 ile
        for _ in range(25):
            offset = 0x1000 + idx * 64
            bin_data[offset:offset + 16] = pat3
            addr = 0x100000000 + offset
            funcs.append({"name": f"FUN_{addr:x}", "address": f"{addr:x}", "size": 64})
            idx += 1

        bin_path = tmp_path / "mixed_bin"
        bin_path.write_bytes(bytes(bin_data))
        json_path = tmp_path / "mixed_funcs.json"
        json_path.write_text(json.dumps({"functions": funcs}))

        m = BytePatternMatcher(min_pattern_length=16, min_confidence=0.40)

        otool_output = "  segname __TEXT\n   vmaddr 0x0000000100000000\n  fileoff 0\n"
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=otool_output, stderr="", returncode=0,
            )
            result = m.match_unknown_functions(
                bin_path, json_path, [sig1, sig2, sig3],
            )

        # sig1: 1 match -> penalty yok -> 1 match
        # sig2: 10 match -> penalty (conf*0.5) -> 10 match (conf*0.5 >= 0.40)
        # sig3: 25 match -> discard -> 0 match
        assert result.total_matched == 11  # 1 + 10

        # sig1'in match'i penalty almamis olmali
        sig1_matches = [
            v for v in result.matches.values()
            if v["matched_name"] == "_unique"
        ]
        assert len(sig1_matches) == 1
        assert sig1_matches[0]["confidence"] >= 0.80

        # sig2'nin match'leri penalize edilmis olmali
        sig2_matches = [
            v for v in result.matches.values()
            if v["matched_name"] == "_suspicious"
        ]
        assert len(sig2_matches) == 10
        for m_info in sig2_matches:
            assert m_info["confidence"] < 0.60  # penalty uygulandi

        # sig3: hicbir match olmamali
        sig3_matches = [
            v for v in result.matches.values()
            if v["matched_name"] == "_noise"
        ]
        assert len(sig3_matches) == 0


class TestSelectivityCustomThresholds:
    """Kullanici max_selective / max_suspicious parametrelerini ayarlayabilir."""

    def test_custom_thresholds(self, tmp_path):
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_d", byte_pattern=pattern)

        # max_selective=2, max_suspicious=8 ile 10 match -> discard
        result = _run_match(
            tmp_path, 10, pattern, sig,
            max_selective=2, max_suspicious=8,
        )
        assert result.total_matched == 0

    def test_within_selective_range(self, tmp_path):
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_e", byte_pattern=pattern)

        # max_selective=15, 10 fonksiyon -> 10 <= 15 -> penalty yok
        result = _run_match(
            tmp_path, 10, pattern, sig,
            max_selective=15, max_suspicious=30,
        )
        assert result.total_matched == 10
        for match_info in result.matches.values():
            assert match_info["confidence"] >= 0.80  # penalty yok


class TestSelectivityEdgeCases:
    """Sinir degerleri."""

    def test_exactly_max_selective(self, tmp_path):
        """Tam max_selective sayisinda match -> penalty yok.

        v1.10.0 M7 sonrasi default max_selective artik pattern uzunluguna
        orantili (``max(2, min_pattern_length//8)`` = 2 for len=16); bu
        regresyon-koruma testi eski sabit 5 davranisini explicit dogrular.
        """
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_f", byte_pattern=pattern)

        # max_selective=5 (v1.8.0 davranisi), 5 fonksiyon -> penalty yok
        result = _run_match(tmp_path, 5, pattern, sig, max_selective=5)
        assert result.total_matched == 5
        for match_info in result.matches.values():
            assert match_info["confidence"] >= 0.80

    def test_max_selective_plus_one(self, tmp_path):
        """max_selective + 1 -> penalty baslar."""
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_g", byte_pattern=pattern)

        # max_selective=5, 6 fonksiyon -> penalty (conf*0.5)
        # min_confidence=0.40 kullanarak penalty sonrasi elenmesin
        result = _run_match(
            tmp_path, 6, pattern, sig, min_confidence=0.40, max_selective=5,
        )
        assert result.total_matched == 6
        for match_info in result.matches.values():
            assert match_info["confidence"] < 0.60  # penalize edildi (orijinal ~0.90 * 0.5)

    def test_exactly_max_suspicious(self, tmp_path):
        """Tam max_suspicious -> hala penalty, discard degil."""
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_h", byte_pattern=pattern)

        # max_suspicious=20, 20 fonksiyon -> penalty ama discard degil
        result = _run_match(tmp_path, 20, pattern, sig, min_confidence=0.40)
        assert result.total_matched == 20

    def test_max_suspicious_plus_one(self, tmp_path):
        """max_suspicious + 1 -> discard."""
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_i", byte_pattern=pattern)

        # max_suspicious=20, 21 fonksiyon -> discard
        result = _run_match(tmp_path, 21, pattern, sig)
        assert result.total_matched == 0

    def test_zero_functions_no_error(self, tmp_path):
        """Hic fonksiyon yoksa hata vermemeli."""
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sig = FakeSig(name="_func_j", byte_pattern=pattern)

        result = _run_match(tmp_path, 0, pattern, sig)
        assert result.total_matched == 0
        assert result.errors == []
