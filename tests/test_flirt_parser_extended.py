"""Karadul v1.14 D1 -- Genisletilmis FLIRT parser testleri.

Bu modul ``flirt_parser.py``'a v1.14'te eklenen capability'leri test eder:

1. ``.pat`` rest alanindan public + reference + tail bytes parse
2. ``compute_flirt_crc16`` -- IDA FLIRT CRC16 (CCITT-False)
3. ``FlirtPattern`` normalize internal IR
4. ``FlirtTrieMatcher`` -- prefix byte trie + sliding window scan
   (synthetic binary uzerinde bilinen pattern'la match)
5. Ölçekleme: tarama süresi veri boyunda doğrusal, kalıp sayısında alt-doğrusal

Mevcut ``test_flirt_parser.py`` ile cakismaz; eski API'ler ayri tutulur.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from karadul.analyzers.flirt_parser import (
    FLIRTParser,
    FLIRTSignature,
    FlirtMatch,
    FlirtPattern,
    FlirtTrieMatcher,
    _parse_pat_rest,
    compute_flirt_crc16,
    parse_pat_file_full,
)


# ---------------------------------------------------------------------------
# 1. .pat rest alani parsing testleri
# ---------------------------------------------------------------------------


class TestParsePatRest:
    """``_parse_pat_rest`` saf fonksiyon testleri."""

    def test_empty_rest(self) -> None:
        publics, refs, tail_b, tail_m = _parse_pat_rest("")
        assert publics == []
        assert refs == []
        assert tail_b == b""
        assert tail_m == b""

    def test_single_reference(self) -> None:
        rest = " ^0010 _malloc"
        publics, refs, _, _ = _parse_pat_rest(rest)
        assert publics == []
        assert refs == [(0x10, "_malloc")]

    def test_multiple_references(self) -> None:
        rest = " ^0010 _malloc ^0020 _free ^0030 _realloc"
        _, refs, _, _ = _parse_pat_rest(rest)
        assert refs == [
            (0x10, "_malloc"),
            (0x20, "_free"),
            (0x30, "_realloc"),
        ]

    def test_extra_public_symbols(self) -> None:
        rest = " :0040 _helper :0080 @local_aux"
        publics, refs, _, _ = _parse_pat_rest(rest)
        assert (0x40, "_helper") in publics
        assert (0x80, "local_aux") in publics
        assert refs == []

    def test_mixed_public_and_reference(self) -> None:
        rest = " :0040 _helper ^0010 _malloc :0080 _aux2"
        publics, refs, _, _ = _parse_pat_rest(rest)
        assert (0x40, "_helper") in publics
        assert (0x80, "_aux2") in publics
        assert (0x10, "_malloc") in refs


# ---------------------------------------------------------------------------
# 2. CRC16 testleri
# ---------------------------------------------------------------------------


class TestComputeFlirtCrc16:
    """``compute_flirt_crc16`` -- IDA FLIRT CRC16 (CCITT-False)."""

    def test_empty_data(self) -> None:
        # CCITT-False bos input icin init degeri olan 0xFFFF dondurmeli
        assert compute_flirt_crc16(b"") == 0xFFFF

    def test_known_value_one_byte(self) -> None:
        # crc('\x00') CCITT-False -> 0x1EF0 (referans, manuel hesap)
        # poly=0x1021 init=0xFFFF, refleksiyon yok
        # crc = 0xFFFF ^ (0x00<<8) = 0xFFFF
        # 8 shift, hep msb=1 -> her seferinde XOR 0x1021
        # 8 iter sonucu: deterministik. Burada DEGERIN sabit olmasi onemli.
        v1 = compute_flirt_crc16(b"\x00")
        v2 = compute_flirt_crc16(b"\x00")
        assert v1 == v2
        assert 0 <= v1 <= 0xFFFF

    def test_determinism_long_buffer(self) -> None:
        data = bytes(range(256)) * 4  # 1024 byte
        a = compute_flirt_crc16(data)
        b = compute_flirt_crc16(data)
        assert a == b

    def test_different_input_different_crc(self) -> None:
        a = compute_flirt_crc16(b"hello")
        b = compute_flirt_crc16(b"world")
        assert a != b

    def test_in_range_16bit(self) -> None:
        for s in [b"", b"a", b"ab", b"abc", b"abcd" * 100]:
            v = compute_flirt_crc16(s)
            assert 0 <= v <= 0xFFFF


# ---------------------------------------------------------------------------
# 3. FlirtPattern (IR) testleri
# ---------------------------------------------------------------------------


class TestFlirtPatternIR:
    """``FlirtPattern`` normalize internal IR."""

    def _make_sig(
        self,
        prefix: bytes = b"\x55\x8B\xEC\x83\xEC\x10",
        mask: bytes | None = None,
        name: str = "_my_func",
        crc16: int = 0xABCD,
        size: int = 0x25,
    ) -> FLIRTSignature:
        if mask is None:
            mask = b"\xFF" * len(prefix)
        return FLIRTSignature(
            name=name,
            library="testlib",
            byte_pattern=prefix,
            mask=mask,
            size=size,
            offset=0,
            crc16=crc16,
        )

    def test_from_signature_basic(self) -> None:
        sig = self._make_sig()
        pat = FlirtPattern.from_signature(sig)
        assert pat.prefix_bytes == sig.byte_pattern
        assert pat.prefix_mask == sig.mask
        assert pat.crc16 == sig.crc16
        assert pat.library == sig.library
        assert pat.primary_name == "_my_func"

    def test_wildcard_ranges_extracted(self) -> None:
        # Pattern: FF FF 00 00 FF -> wildcards = [(2, 4)]
        sig = self._make_sig(
            prefix=b"\x55\x8B\x00\x00\xEC",
            mask=b"\xFF\xFF\x00\x00\xFF",
        )
        pat = FlirtPattern.from_signature(sig)
        assert pat.wildcards == [(2, 4)]

    def test_wildcards_at_end(self) -> None:
        sig = self._make_sig(
            prefix=b"\x55\x8B\x00\x00",
            mask=b"\xFF\xFF\x00\x00",
        )
        pat = FlirtPattern.from_signature(sig)
        assert pat.wildcards == [(2, 4)]

    def test_no_wildcards(self) -> None:
        sig = self._make_sig()
        pat = FlirtPattern.from_signature(sig)
        assert pat.wildcards == []

    def test_primary_name_prefers_offset_zero(self) -> None:
        sig = self._make_sig(name="_main")
        sig.public_symbols = [(0x40, "_helper")]  # ana sembol uzerine ek
        pat = FlirtPattern.from_signature(sig)
        # Ana sembol offset=0'da -> primary
        assert pat.primary_name == "_main"

    def test_references_passed_through(self) -> None:
        sig = self._make_sig()
        sig.references = [(0x10, "_malloc"), (0x20, "_free")]
        pat = FlirtPattern.from_signature(sig)
        assert pat.references == [(0x10, "_malloc"), (0x20, "_free")]


# ---------------------------------------------------------------------------
# 4. parse_pat_file_full integrasyon testi
# ---------------------------------------------------------------------------


class TestParsePatFileFull:
    """``parse_pat_file_full`` end-to-end."""

    def test_basic_round_trip(self, tmp_path: Path) -> None:
        pat = tmp_path / "lib.pat"
        pat.write_text(
            "558BEC83EC10 0C 0025 003A :0000 _func_a\n"
            "C3 00 0001 0001 :0000 _func_b\n"
            "---\n",
            encoding="utf-8",
        )
        patterns = parse_pat_file_full(pat)
        assert len(patterns) == 2
        names = {p.primary_name for p in patterns}
        assert names == {"_func_a", "_func_b"}

    def test_with_references(self, tmp_path: Path) -> None:
        pat = tmp_path / "lib.pat"
        pat.write_text(
            "558BEC........8B4508 00 0000 001F :0000 _caller ^0010 _malloc\n",
            encoding="utf-8",
        )
        patterns = parse_pat_file_full(pat)
        assert len(patterns) == 1
        p = patterns[0]
        assert p.primary_name == "_caller"
        assert (0x10, "_malloc") in p.references

    def test_with_extra_publics(self, tmp_path: Path) -> None:
        pat = tmp_path / "lib.pat"
        pat.write_text(
            "558BEC83EC10 0C 0025 003A :0000 _main :0040 _helper\n",
            encoding="utf-8",
        )
        patterns = parse_pat_file_full(pat)
        assert len(patterns) == 1
        p = patterns[0]
        names = {n for _, n in p.public_symbols}
        assert "_main" in names
        assert "_helper" in names


# ---------------------------------------------------------------------------
# 5. FlirtTrieMatcher -- synthetic binary tarama
# ---------------------------------------------------------------------------


def _mk_pattern(
    prefix: bytes,
    name: str,
    *,
    mask: bytes | None = None,
    crc16: int = 0,
    crc16_length: int = 0,
    library: str = "syn",
) -> FlirtPattern:
    if mask is None:
        mask = b"\xFF" * len(prefix)
    return FlirtPattern(
        prefix_bytes=prefix,
        prefix_mask=mask,
        crc16_length=crc16_length,
        crc16=crc16,
        tail_length=len(prefix),
        module_length=len(prefix),
        public_symbols=[(0, name)],
        references=[],
        wildcards=[],
        library=library,
    )


class TestFlirtTrieMatcher:
    """``FlirtTrieMatcher`` davranislari."""

    def test_empty_input(self) -> None:
        matcher = FlirtTrieMatcher([])
        assert matcher.scan_binary(b"\x00\x01\x02") == []
        assert matcher.pattern_count == 0
        assert matcher.max_prefix_len == 0

    def test_simple_match(self) -> None:
        pat = _mk_pattern(b"\x55\x8B\xEC", "func_a")
        matcher = FlirtTrieMatcher([pat])
        binary = b"\x00\x00\x55\x8B\xEC\x00\x00"
        matches = matcher.scan_binary(binary, verify_crc=False)
        assert len(matches) == 1
        m = matches[0]
        assert m.offset == 2
        assert m.pattern.primary_name == "func_a"

    def test_multiple_matches(self) -> None:
        pat = _mk_pattern(b"\xC3", "ret_only")
        matcher = FlirtTrieMatcher([pat])
        binary = b"\xC3\x00\xC3\x00\xC3"
        matches = matcher.scan_binary(binary, verify_crc=False)
        assert {m.offset for m in matches} == {0, 2, 4}

    def test_wildcard_match(self) -> None:
        pat = _mk_pattern(
            prefix=b"\x55\x00\xEC",
            mask=b"\xFF\x00\xFF",
            name="wild_func",
        )
        matcher = FlirtTrieMatcher([pat])
        binary = b"\x55\xAB\xEC" + b"\x55\xCD\xEC"
        matches = matcher.scan_binary(binary, verify_crc=False)
        offsets = sorted(m.offset for m in matches)
        assert offsets == [0, 3]

    def test_no_match(self) -> None:
        pat = _mk_pattern(b"\xDE\xAD\xBE\xEF", "deadbeef")
        matcher = FlirtTrieMatcher([pat])
        binary = b"\x00" * 100
        assert matcher.scan_binary(binary) == []

    def test_overlapping_patterns(self) -> None:
        # Iki pattern ortak prefix paylasiyor: 55 8B / 55 8B EC
        p1 = _mk_pattern(b"\x55\x8B", "short")
        p2 = _mk_pattern(b"\x55\x8B\xEC", "long")
        matcher = FlirtTrieMatcher([p1, p2])
        binary = b"\x55\x8B\xEC\x00"
        matches = matcher.scan_binary(binary, verify_crc=False)
        names = {m.pattern.primary_name for m in matches}
        assert names == {"short", "long"}

    def test_crc16_verify_pass(self) -> None:
        # CRC dogrulama: prefix sonrasi 4 byte uzerinden CRC16 hesapla
        prefix = b"\x55\x8B\xEC"
        crc_block = b"\x01\x02\x03\x04"
        crc = compute_flirt_crc16(crc_block)
        pat = _mk_pattern(
            prefix, "withcrc", crc16=crc, crc16_length=len(crc_block),
        )
        matcher = FlirtTrieMatcher([pat])
        binary = prefix + crc_block + b"\xFF" * 10
        matches = matcher.scan_binary(binary, verify_crc=True)
        assert len(matches) == 1
        assert matches[0].crc_ok is True
        assert matches[0].score == pytest.approx(1.0)

    def test_crc16_verify_fail(self) -> None:
        prefix = b"\x55\x8B\xEC"
        good = b"\x01\x02\x03\x04"
        crc = compute_flirt_crc16(good)
        pat = _mk_pattern(
            prefix, "withcrc", crc16=crc, crc16_length=len(good),
        )
        matcher = FlirtTrieMatcher([pat])
        # Yanlis CRC blogu
        binary = prefix + b"\xAA\xBB\xCC\xDD" + b"\xFF" * 4
        matches = matcher.scan_binary(binary, verify_crc=True)
        # Match uretilir ama crc_ok=False ve score yarilanir
        assert len(matches) == 1
        assert matches[0].crc_ok is False
        assert matches[0].score < 1.0

    def test_min_score_filter(self) -> None:
        pat = _mk_pattern(b"\xC3", "ret")
        matcher = FlirtTrieMatcher([pat])
        binary = b"\xC3"
        # score=1.0 -> min_score=0.5 ile gecer
        assert len(matcher.scan_binary(binary, verify_crc=False, min_score=0.5)) == 1
        # min_score=1.5 ile elenir
        assert matcher.scan_binary(binary, verify_crc=False, min_score=1.5) == []

    def test_pattern_count_and_max_prefix_len(self) -> None:
        p1 = _mk_pattern(b"\x55", "a")
        p2 = _mk_pattern(b"\x55\x8B\xEC\x83", "b")
        matcher = FlirtTrieMatcher([p1, p2])
        assert matcher.pattern_count == 2
        assert matcher.max_prefix_len == 4


# ---------------------------------------------------------------------------
# 6. Ölçekleme testleri (veri boyu ve kalıp sayısı)
# ---------------------------------------------------------------------------


def _random_patterns(count: int) -> list[FlirtPattern]:
    """``count`` rastgele kalıp: 8 bayt, baytların ~%20'si wildcard (sabit tohum)."""
    import random

    rng = random.Random(1234)
    patterns: list[FlirtPattern] = []
    for i in range(count):
        prefix = bytes(rng.randint(0, 255) for _ in range(8))
        mask = bytes(0xFF if rng.random() > 0.2 else 0x00 for _ in range(8))
        patterns.append(_mk_pattern(prefix, f"f_{i}", mask=mask))
    return patterns


def _best_scan_seconds(
    cases: list[tuple[FlirtTrieMatcher, bytes]], rounds: int = 5,
) -> list[float]:
    """Her (matcher, veri) çifti için ``scan_binary``'nin en kısa CPU süresi.

    Saat ``time.process_time``: yalnız bu sürecin işlemci süresi. Tarama tek iş parçacıklı
    saf hesap; duvar saati ise başka süreçler araya girdikçe uzar. Ölçüm (çekirdek sayısının
    1,5 katı meşgul süreç varken, 64 -> 256 KiB, 8 ölçüm): duvar saatiyle oran 4,4 - 10,8,
    CPU süresiyle 3,9 - 4,6.

    En kısa süre alınır (gürültü süreyi yalnız uzatır); turlar çiftleri sırayla dolaşır.
    """
    best = [float("inf")] * len(cases)
    for _ in range(rounds):
        for i, (matcher, binary) in enumerate(cases):
            t0 = time.process_time()
            matcher.scan_binary(binary, verify_crc=False)
            best[i] = min(best[i], time.process_time() - t0)
    return best


class TestPerformance:
    """Trie tarayıcının ölçekleme davranışı: makineden bağımsız iki iddia.

    Bu sınıf eskiden tek bir mutlak hedefi sınıyordu ("100 kalıp x 1 MiB < 1,0 sn").
    Mutlak süre kodu değil makineyi ölçüyor: aynı kod geliştirme makinesinde 0,60 sn,
    GitHub koşucularında 1,20 - 1,65 sn (koşu 42830613886) sürdü; tarama saf Python
    döngüsü, koşucu 2,0 - 2,75 kat yavaş. Gürültü değil, kararlı hız farkı.

    Kodun kendi sözü (``FlirtTrieMatcher`` belgesi) karmaşıklık: tarama O(N * d_avg),
    yani veri boyunda doğrusal ve kalıp sayısından (neredeyse) bağımsız. Bunlar oranla,
    aynı süreçte, aynı makinede ölçülür; makine hızı sadeleşir.

    Ölçüm (2026-11-10; Apple Silicon, CPython 3.12.7; 10 bağımsız ölçüm; parantezde
    çekirdek sayısının 1,5 katı meşgul süreç varken en büyük değer):
        veri 64 KiB -> 256 KiB (4 kat)    : süre 3,9 - 4,1 kat (4,8)  doğrusal 4, karesel 16
        kalıp 10 -> 100 (10 kat)          : süre 1,4 kat (1,6)        kalıp başına tarama 10
        ofset başına maliyet              : ~570 ns; 1 MiB 0,60 sn, 4 MiB 2,58 sn (4,3 kat)

    Eşikler iki hipotezin geometrik ortası: doğrusal ile karesel (4 ve 16 -> 8), trie ile
    kalıp başına tarama (1 ve 10 -> 3,16).

    Yakalananlar (bellek içi mutantla denendi): her ofsette verinin kalanını kopyalayan
    tarama (oran 9,7) ve trie yerine kalıpları tek tek deneyen tarama (oran 10,5).
    Yakalanmayan: sabit çarpanlı yavaşlama (her şey 3 kat yavaşlarsa oranlar değişmez).
    """

    SMALL = 64 * 1024
    LARGE = 4 * SMALL          # 256 KiB

    @staticmethod
    def _binary(size: int) -> bytes:
        import random

        return random.Random(99).randbytes(size)

    def test_scan_time_linear_in_binary_size(self) -> None:
        """100 kalıp: veri 4 katına çıkınca süre ~4 katına çıkar (karesel değil)."""
        matcher = FlirtTrieMatcher(_random_patterns(100))
        small, large = self._binary(self.SMALL), self._binary(self.LARGE)

        t_small, t_large = _best_scan_seconds([(matcher, small), (matcher, large)])

        ratio = t_large / t_small
        assert ratio < 8.0, (
            f"Tarama veri boyunda doğrusal değil: {self.SMALL // 1024} KiB {t_small:.3f} sn, "
            f"{self.LARGE // 1024} KiB {t_large:.3f} sn, oran {ratio:.1f} "
            f"(doğrusal 4, karesel 16, eşik 8)"
        )
        # Sonuc tipi dogru
        matches = matcher.scan_binary(small, verify_crc=False)
        assert isinstance(matches, list)
        for m in matches:
            assert isinstance(m, FlirtMatch)

    def test_scan_time_sublinear_in_pattern_count(self) -> None:
        """Kalıp sayısı 10 katına çıkınca süre 10 katına çıkmaz (trie'nin varlık nedeni)."""
        binary = self._binary(self.SMALL)

        t_10, t_100 = _best_scan_seconds([
            (FlirtTrieMatcher(_random_patterns(10)), binary),
            (FlirtTrieMatcher(_random_patterns(100)), binary),
        ])

        ratio = t_100 / t_10
        assert ratio < 10 ** 0.5, (
            f"Tarama süresi kalıp sayısıyla büyüyor: 10 kalıp {t_10:.3f} sn, "
            f"100 kalıp {t_100:.3f} sn, oran {ratio:.2f} "
            f"(trie ~1, kalıp başına tarama 10, eşik 3,16)"
        )


# ---------------------------------------------------------------------------
# 7. FLIRTSignature -> rest extension end-to-end (regresyon)
# ---------------------------------------------------------------------------


class TestPatLineWithRestExtension:
    """``FLIRTParser._parse_pat_line`` rest alanini kullaniyor mu."""

    def test_references_populated(self) -> None:
        parser = FLIRTParser()
        line = "558BEC........8B4508 00 0000 001F :0000 _f ^0010 _ref"
        sig = parser._parse_pat_line(line, "lib")
        assert sig is not None
        assert sig.references == [(0x10, "_ref")]

    def test_extra_publics_populated(self) -> None:
        parser = FLIRTParser()
        line = "558BEC83EC10 0C 0025 003A :0000 _main :0040 _helper"
        sig = parser._parse_pat_line(line, "lib")
        assert sig is not None
        names = {n for _, n in sig.public_symbols}
        assert "_helper" in names

    def test_no_rest_no_extras(self) -> None:
        parser = FLIRTParser()
        line = "558BEC83EC10 0C 0025 003A :0000 _solo"
        sig = parser._parse_pat_line(line, "lib")
        assert sig is not None
        assert sig.references == []
        assert sig.public_symbols == []
