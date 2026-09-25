"""Seçici (v2) FLIRT bayt imzası -- sentetik imza + sentetik arm64 fonksiyon baytları.

Kilitlenen korumalar (her biri mutation ile doğrulandı:
``scripts/flirt/mutation_specs_flirt_selective.json``,
``python scripts/mutation_probe.py --spec <o dosya>``):
  * arm64 relokasyon maskesi (ADRP/ADR, B/BL, LDR literal, ADRP'ye bağlı :lo12:)
    -> aynı kod başka adrese bağlanınca yine tanınır
  * uzunluk uyuşmazlığı, CRC16 uyuşmazlığı -> isim yok
  * ayırt edilemeyen çok-isim, aynı ismin iki fonksiyona çıkması -> isim yok
  * çağrı referansı tutmazsa -> isim yok
  * zayıf imza (referanssız + az içerik) üretilmez
  * v2 girdi doğrulaması; geçersiz v2 girdisi asla eski imzaya düşmez
  * eski (v1) biçim: liste eski gövdeye aynen gider, çok-isimli desen eskisi
    gibi isimlenir (belirsizlik kuralı yalnız v2'de)
"""
from __future__ import annotations

import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

from karadul.analyzers.byte_pattern_matcher import (
    BytePatternMatcher,
    _split_selective,
)
from karadul.analyzers.flirt_parser import (
    SELECTIVE_PREFIX_LEN,
    FLIRTParser,
    FLIRTSignature,
    apply_mask,
    arm64_content_words,
    arm64_reloc_mask,
    build_selective_entry,
    compute_flirt_crc16,
    is_weak_selective,
    masked_crc16,
    selective_signature_from_entry,
)

_REPO = Path(__file__).resolve().parents[1]


def _load_script(rel: str, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, _REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


bss = _load_script("scripts/flirt/build_selective_signatures.py", "bss_under_test")
fprec = _load_script("scripts/measurement/flirt_precision.py", "flirt_precision_under_test")

# ---------------------------------------------------------------------------
# arm64 kodlayıcılar (capstone ile elle doğrulandı; testte bağımlılık yok)
# ---------------------------------------------------------------------------
STP_FP = 0xA9BF7BFD          # stp x29, x30, [sp, #-16]!
STP_X20_X19 = 0xA9014FF4     # stp x20, x19, [sp, #16]
MOV_FP = 0x910003FD          # mov x29, sp
LDP_X20_X19 = 0xA9414FF4     # ldp x20, x19, [sp, #16]
LDP_FP = 0xA8C17BFD          # ldp x29, x30, [sp], #16
RET = 0xD65F03C0
FULL = 0xFFFFFFFF


def adrp(rd: int, pages: int) -> int:
    return 0x90000000 | ((pages & 3) << 29) | (((pages >> 2) & 0x7FFFF) << 5) | rd


def adr(rd: int, delta: int) -> int:
    return 0x10000000 | ((delta & 3) << 29) | (((delta >> 2) & 0x7FFFF) << 5) | rd


def add_imm(rd: int, rn: int, imm: int) -> int:
    return 0x91000000 | (imm << 10) | (rn << 5) | rd


def ldr_uimm(rt: int, rn: int, imm: int) -> int:
    return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt


def bl(delta: int) -> int:
    return 0x94000000 | ((delta // 4) & 0x3FFFFFF)


def b(delta: int) -> int:
    return 0x14000000 | ((delta // 4) & 0x3FFFFFF)


def ldr_lit(rt: int, delta: int) -> int:
    return 0x58000000 | (((delta // 4) & 0x7FFFF) << 5) | rt


def bcond(delta: int, cond: int) -> int:
    return 0x54000000 | (((delta // 4) & 0x7FFFF) << 5) | cond


def movz(rd: int, imm: int) -> int:
    return 0x52800000 | (imm << 5) | rd


def eor(rd: int, rn: int, rm: int) -> int:
    return 0xCA000000 | (rm << 16) | (rn << 5) | rd


def mov(rd: int, rm: int) -> int:
    return 0xAA0003E0 | (rm << 16) | rd


def code(*words: int) -> bytes:
    return b"".join(struct.pack("<I", w) for w in words)


def words_of(data: bytes) -> list[int]:
    return [w for (w,) in struct.iter_unpack("<I", data)]


def body(*, page: int = 5, lo12: int = 0x120, call: int = 0x400, tail: int = 0x55) -> bytes:
    """64 baytlık, içerik zengin sentetik fonksiyon.

    Ön ek (ilk 32 bayt): çerçeve + ADRP/ADD/LDR (maskeli) + içerik.
    CRC bölgesi (32..64): BL (maskeli) + içerik; ``tail`` son içerik sabiti.
    """
    return code(
        STP_FP, MOV_FP, adrp(8, page), add_imm(8, 8, lo12), ldr_uimm(0, 8, 16),
        movz(0, 0x1234), eor(0, 0, 1), movz(1, 0x77),
        eor(1, 1, 0), movz(2, 3), bl(call), eor(0, 0, 2),
        movz(3, tail), eor(0, 0, 3), LDP_FP, RET,
    )


# ---------------------------------------------------------------------------
# Sentetik ELF (aarch64, ET_EXEC, tek PT_LOAD: dosya ofseti 0 -> LOAD)
# ---------------------------------------------------------------------------
LOAD = 0x400000
F_OFF, G_OFF, H_OFF = 0x1000, 0x1200, 0x1400


def make_elf(path: Path, blobs: dict[int, bytes], size: int = 0x4000) -> Path:
    data = bytearray(size)
    data[0:4] = b"\x7fELF"
    data[4], data[5], data[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0xB7, 1, LOAD + F_OFF, 64, 0, 0,
                     64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, LOAD, LOAD, size, size, 0x1000)
    for off, blob in blobs.items():
        data[off:off + len(blob)] = blob
    path.write_bytes(bytes(data))
    return path


def make_functions(path: Path, funcs: list[tuple[str, int, int]]) -> Path:
    """(ad, dosya ofseti, uzunluk) -> Ghidra functions.json (adres = LOAD + ofset)."""
    path.write_text(json.dumps({"functions": [
        {"name": n, "address": f"{LOAD + off:x}", "size": s} for n, off, s in funcs
    ]}))
    return path


def fun(off: int) -> str:
    return f"FUN_{LOAD + off:08x}"


def sig(name: str, data: bytes, *, library: str = "zstd", refs=(), aliases=()) -> FLIRTSignature:
    entry = build_selective_entry(name, library, data, refs=refs, aliases=aliases)
    assert entry is not None
    s = selective_signature_from_entry(entry)
    assert s is not None
    return s


def run(tmp_path: Path, blobs: dict[int, bytes], funcs, sigs, *, path: str = "trie"):
    binary = make_elf(tmp_path / "bin", blobs)
    fj = make_functions(tmp_path / "functions.json", funcs)
    m = BytePatternMatcher(min_confidence=0.7)
    meth = m.match_unknown_functions_trie if path == "trie" else m.match_unknown_functions
    return meth(binary, fj, sigs)


PATHS = pytest.mark.parametrize("path", ["trie", "linear"])


# ---------------------------------------------------------------------------
# 1. Maske kuralı ve CRC
# ---------------------------------------------------------------------------

class TestArm64Mask:
    def test_relocation_fields_masked(self):
        ws = [adrp(8, 5), add_imm(8, 8, 0x120), ldr_uimm(0, 8, 16), bl(0x100), b(-0x40),
              ldr_lit(2, 0x20), adr(3, 0x44), add_imm(9, 1, 16), bcond(8, 8), movz(0, 7)]
        masks = words_of(arm64_reloc_mask(code(*ws)))
        assert masks == [
            0x9F00001F,   # ADRP: yalnız op + Rd
            0xFFC003FF,   # ADD x8, x8, #lo12 (x8 ADRP hedefi)
            0xFFC003FF,   # LDR x0, [x8, #lo12]
            0xFC000000,   # BL
            0xFC000000,   # B
            0xFF00001F,   # LDR literal
            0x9F00001F,   # ADR
            FULL,         # ADD x9, x1, #16: taban ADRP hedefi değil -> maskesiz
            FULL,         # B.cond fonksiyon içi -> maskesiz
            FULL,
        ]

    def test_lo12_only_after_adrp(self):
        """ADRP'den ÖNCEKİ aynı yazmaçlı ADD maskelenmez (kural sıralı)."""
        masks = words_of(arm64_reloc_mask(code(add_imm(8, 8, 0x10), adrp(8, 1), add_imm(8, 8, 0x10))))
        assert masks == [FULL, 0x9F00001F, 0xFFC003FF]

    def test_mask_idempotent_on_masked_code(self):
        data = body()
        m = arm64_reloc_mask(data)
        assert arm64_reloc_mask(apply_mask(data, m)) == m

    def test_masked_crc_equals_flirt_crc16(self):
        data = body()
        m = arm64_reloc_mask(data)
        assert masked_crc16(data, m) == compute_flirt_crc16(apply_mask(data, m))


# ---------------------------------------------------------------------------
# 2. Eşleştirici: v2 doğrulamaları
# ---------------------------------------------------------------------------

class TestSelectiveMatch:
    @PATHS
    def test_relocated_copy_is_named(self, tmp_path, path):
        """Kaynak: sayfa 5, lo12 0x120, BL +0x400. Hedef: aynı kod başka adreslere bağlı."""
        src = body()
        target = body(page=9, lo12=0x3C8, call=-0x200)
        assert src[:SELECTIVE_PREFIX_LEN] != target[:SELECTIVE_PREFIX_LEN]  # ham baytlar farklı
        res = run(tmp_path, {F_OFF: target}, [(fun(F_OFF), F_OFF, len(target))],
                  [sig("_zstd_fn", src)], path=path)
        assert res.matches[fun(F_OFF)]["matched_name"] == "_zstd_fn"
        assert res.matches[fun(F_OFF)]["match_method"] == "byte_pattern_selective"
        assert res.total_matched == 1

    @PATHS
    def test_size_mismatch_rejected(self, tmp_path, path):
        data = body()
        res = run(tmp_path, {F_OFF: data}, [(fun(F_OFF), F_OFF, len(data) + 4)],
                  [sig("_zstd_fn", data)], path=path)
        assert res.total_matched == 0
        assert res.selective_rejected_size == 1

    def test_unknown_target_size_skips_size_check(self, tmp_path):
        """functions.json size=0: uzunluk kontrolü atlanır, ön ek + CRC yeter."""
        data = body()
        res = run(tmp_path, {F_OFF: data}, [(fun(F_OFF), F_OFF, 0)], [sig("_zstd_fn", data)])
        assert res.total_matched == 1

    @PATHS
    def test_crc_mismatch_rejected(self, tmp_path, path):
        """Ön ek + uzunluk aynı; ön ek ötesinde tek içerik kelimesi farklı."""
        src, target = body(tail=0x55), body(tail=0x56)
        assert src[:SELECTIVE_PREFIX_LEN] == target[:SELECTIVE_PREFIX_LEN]
        res = run(tmp_path, {F_OFF: target}, [(fun(F_OFF), F_OFF, len(target))],
                  [sig("_zstd_fn", src)], path=path)
        assert res.total_matched == 0
        assert res.selective_prefix_hits == 1
        assert res.selective_rejected_crc == 1

    @PATHS
    def test_indistinguishable_multi_name_not_named(self, tmp_path, path):
        data = body()
        res = run(tmp_path, {F_OFF: data}, [(fun(F_OFF), F_OFF, len(data))],
                  [sig("_first", data), sig("_second", data)], path=path)
        assert res.total_matched == 0
        assert res.selective_ambiguous == 1

    def test_same_name_in_two_libraries_is_named(self, tmp_path):
        data = body()
        res = run(tmp_path, {F_OFF: data}, [(fun(F_OFF), F_OFF, len(data))],
                  [sig("_same", data, library="a"), sig("_same", data, library="b")])
        assert res.matches[fun(F_OFF)]["matched_name"] == "_same"
        assert res.selective_ambiguous == 0

    @PATHS
    def test_same_name_on_two_functions_not_named(self, tmp_path, path):
        data = body()
        res = run(tmp_path, {F_OFF: data, G_OFF: data},
                  [(fun(F_OFF), F_OFF, len(data)), (fun(G_OFF), G_OFF, len(data))],
                  [sig("_zstd_fn", data)], path=path)
        assert res.total_matched == 0
        assert res.selective_duplicate_name == 2

    @PATHS
    def test_name_already_in_binary_not_given_to_fun(self, tmp_path, path):
        """Stripped dylib: ihraç kopya Ghidra'da isimli, statik ikizi FUN_ -> ikize isim yok."""
        data = body()
        res = run(tmp_path, {F_OFF: data, G_OFF: data},
                  [(fun(F_OFF), F_OFF, len(data)), ("_zstd_fn", G_OFF, len(data))],
                  [sig("_zstd_fn", data)], path=path)
        assert res.total_matched == 0
        assert res.selective_duplicate_name == 1

    def test_alias_already_in_binary_not_given_to_fun(self, tmp_path):
        data = body()
        res = run(tmp_path, {F_OFF: data, G_OFF: data},
                  [(fun(F_OFF), F_OFF, len(data)), ("zstd_alias", G_OFF, len(data))],
                  [sig("_zstd_fn", data, aliases=["_zstd_alias"])])
        assert res.total_matched == 0

    def test_aliases_reported(self, tmp_path):
        data = body()
        res = run(tmp_path, {F_OFF: data}, [(fun(F_OFF), F_OFF, len(data))],
                  [sig("_short", data, aliases=["_longer_alias"])])
        assert res.matches[fun(F_OFF)]["aliases"] == ["_longer_alias"]


# ---------------------------------------------------------------------------
# 3. Çağrı referansları (IDA ^OFFSET name)
# ---------------------------------------------------------------------------

def wrapper(call_delta: int) -> bytes:
    """32 baytlık sarmalayıcı: içerik 1 kelime, ofset 16'da BL."""
    return code(STP_FP, MOV_FP, mov(19, 0), movz(0, 1), bl(call_delta), mov(1, 19), LDP_FP, RET)


CALL_OFF = 16  # wrapper içindeki BL ofseti


class TestCallReferences:
    def _sigs(self):
        g = body()
        return [sig("_callee", g), sig("_caller", wrapper(0x7777 * 4), refs=[(CALL_OFF, "_callee")])]

    def test_ref_to_verified_callee_named(self, tmp_path):
        f = wrapper(G_OFF - (F_OFF + CALL_OFF))
        g = body(page=11, lo12=0x10, call=0x800)  # aynı callee, başka adreslere bağlı
        res = run(tmp_path, {F_OFF: f, G_OFF: g},
                  [(fun(F_OFF), F_OFF, len(f)), (fun(G_OFF), G_OFF, len(g))], self._sigs())
        assert res.matches[fun(F_OFF)]["matched_name"] == "_caller"
        assert res.matches[fun(G_OFF)]["matched_name"] == "_callee"

    @PATHS
    def test_ref_to_other_function_rejected(self, tmp_path, path):
        """Sarmalayıcı bayt olarak aynı ama BL başka (tanınmayan) bir fonksiyona gidiyor."""
        f = wrapper(H_OFF - (F_OFF + CALL_OFF))
        h = body(tail=0x99)  # _callee değil (CRC tutmaz)
        res = run(tmp_path, {F_OFF: f, H_OFF: h},
                  [(fun(F_OFF), F_OFF, len(f)), (fun(H_OFF), H_OFF, len(h))], self._sigs(), path=path)
        assert fun(F_OFF) not in res.matches
        assert res.selective_rejected_ref == 1

    def test_ref_to_ghidra_named_callee_accepted(self, tmp_path):
        """Hedef fonksiyon Ghidra'da zaten isimli (FUN_ değil): isim eşitliği yeter."""
        f = wrapper(H_OFF - (F_OFF + CALL_OFF))
        res = run(tmp_path, {F_OFF: f, H_OFF: body(tail=0x99)},
                  [(fun(F_OFF), F_OFF, len(f)), ("callee", H_OFF, 64)], self._sigs())
        assert res.matches[fun(F_OFF)]["matched_name"] == "_caller"


# ---------------------------------------------------------------------------
# 4. İmza üretimi: kısa ve zayıf fonksiyonlar
# ---------------------------------------------------------------------------

def frame_wrapper() -> bytes:
    """Yalnız çerçeve + yazmaç taşıma + çağrı: içerik 0, kalıp kelime 9."""
    return code(STP_FP, STP_X20_X19, MOV_FP, mov(19, 0), mov(20, 1), bl(0x100),
                mov(0, 19), mov(1, 20), LDP_X20_X19, LDP_FP, b(0x200))


class TestSignatureBuilding:
    def test_short_function_not_signed(self):
        """28 bayt, içerik 7 kelime (zayıf DEĞİL): yalnız uzunluk kuralı reddetmeli."""
        short = code(*[movz(0, 0x100 + i) for i in range(7)])
        assert not is_weak_selective(short, has_refs=False)
        assert build_selective_entry("_short", "x", short) is None

    def test_content_words_ignore_frame_and_relocations(self):
        assert arm64_content_words(frame_wrapper()) == 0
        assert arm64_content_words(body()) == 8

    def test_weak_function_without_refs_not_signed(self):
        assert is_weak_selective(frame_wrapper(), has_refs=False)
        assert build_selective_entry("_w", "x", frame_wrapper()) is None

    def test_weak_function_with_ref_is_signed(self):
        e = build_selective_entry("_w", "x", frame_wrapper(), refs=[(20, "_callee")])
        assert e is not None and e["refs"] == [[20, "_callee"]]

    def test_crc_covers_rest_of_function(self):
        e = build_selective_entry("_f", "x", body())
        assert e["size"] == 64 and e["crc_len"] == 32

    def test_builder_fixpoint_drops_refs_to_weak_callee(self):
        """Zayıf callee elenince ona giden referans düşer; çağıran da zayıf kalır."""
        weak_callee = bss.SourceFunction("x", ["_weakcallee"], 0x2000, 44, frame_wrapper())
        caller = bss.SourceFunction("x", ["_caller"], 0x1000, 32, wrapper(0x2000 - (0x1000 + CALL_OFF)))
        signed, refs, weak = bss.select_signed([caller, weak_callee], min_size=32, min_content=6)
        assert signed == {} and weak == 2

        rich = bss.SourceFunction("x", ["_rich"], 0x2000, 64, body())
        signed, refs, weak = bss.select_signed([caller, rich], min_size=32, min_content=6)
        assert set(signed) == {0x1000, 0x2000} and weak == 0
        assert refs[0x1000] == [(CALL_OFF, "_rich")]

    @pytest.mark.parametrize("name", ["signatures_homebrew_bytes.json", "signatures_homebrew.json"])
    def test_builder_refuses_to_overwrite_existing_db(self, name):
        with pytest.raises(SystemExit):
            bss._check_output_path(_REPO / name)
        with pytest.raises(SystemExit):
            bss._check_output_path(_REPO / "sigs" / "new.json")
        bss._check_output_path(_REPO / "signatures_homebrew_bytes_v2.json")  # izinli


# ---------------------------------------------------------------------------
# 5. JSON yükleyici
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, entries: list[dict]) -> list[FLIRTSignature]:
    p = tmp_path / "db.json"
    p.write_text(json.dumps({"signatures": entries}))
    return FLIRTParser().load_json_signatures(p)


class TestLoader:
    def test_v2_roundtrip(self, tmp_path):
        e = build_selective_entry("_f", "zstd", body(), aliases=["_g"], refs=[(40, "_callee")])
        (s,) = _write(tmp_path, [e])
        assert s.sig_format == 2 and s.mask_rule == "arm64"
        assert s.size == 64 and s.crc16_length == 32 and s.crc16 == e["crc16"]
        assert s.references == [(40, "_callee")] and s.public_symbols == [(0, "_g")]

    @pytest.mark.parametrize("field,value", [
        ("mask_rule", "x86_64"),                  # bilinmeyen kural
        ("crc_len", 256),                         # IDA sınırı 255
        ("size", 40),                             # CRC bölgesi fonksiyon dışına taşar
        ("sig_format", 3),                        # bilinmeyen biçim
        ("refs", [[18, "_x"]]),                   # hizasız referans ofseti
        ("refs", [[64, "_x"]]),                   # fonksiyon dışında
        ("crc16", None),                          # eksik/bozuk alan
    ])
    def test_invalid_v2_entry_dropped_not_downgraded(self, tmp_path, field, value):
        e = build_selective_entry("_f", "zstd", body())
        e[field] = value
        assert _write(tmp_path, [e]) == []  # eski (yalnız ön ek) imzaya DÜŞMEZ

    def test_mask_not_derivable_from_pattern_dropped(self, tmp_path):
        e = build_selective_entry("_f", "zstd", body())
        mask = bytearray.fromhex(e["mask"])
        mask[8] = 0xFF  # ADRP kelimesinin maskesini boz
        e["mask"] = mask.hex()
        assert _write(tmp_path, [e]) == []

    def test_nonzero_bits_under_mask_dropped(self, tmp_path):
        e = build_selective_entry("_f", "zstd", body())
        pat = bytearray.fromhex(e["byte_pattern"])
        pat[9] |= 0x10  # ADRP immhi biti (maskeli) sıfır olmalı
        e["byte_pattern"] = pat.hex()
        assert _write(tmp_path, [e]) == []

    def test_legacy_entry_unchanged(self, tmp_path):
        pattern = bytes(range(32))
        (s,) = _write(tmp_path, [{"name": "_old", "library": "zstd", "confidence": 0.9,
                                  "size": 0, "byte_pattern": pattern.hex()}])
        assert s.sig_format == 1 and s.crc16_length == 0 and s.mask_rule == ""
        assert s.byte_pattern == pattern and s.mask == b"\xff" * 32


# ---------------------------------------------------------------------------
# 6. Eski biçimle uyumluluk ve karışık liste
# ---------------------------------------------------------------------------

def legacy(name: str, pattern: bytes) -> FLIRTSignature:
    return FLIRTSignature(name=name, library="zstd", byte_pattern=pattern, mask=b"\xff" * len(pattern))


class TestLegacyCompat:
    def test_legacy_list_passed_through_unchanged(self):
        sigs = [legacy("_a", bytes(32))]
        selective, rest = _split_selective(sigs)
        assert selective == [] and rest is sigs

    @PATHS
    def test_legacy_multi_name_pattern_still_named(self, tmp_path, path):
        """Eski davranış: aynı 32 bayt iki isme gidiyorsa yine BİR isim verilir."""
        data = body()
        res = run(tmp_path, {F_OFF: data}, [(fun(F_OFF), F_OFF, len(data))],
                  [legacy("_first", data[:32]), legacy("_second", data[:32])], path=path)
        assert res.total_matched == 1
        assert res.matches[fun(F_OFF)]["matched_name"] in {"_first", "_second"}
        assert res.selective_ambiguous == 0

    @PATHS
    def test_selective_decision_overrides_legacy(self, tmp_path, path):
        """v2 'belirsiz' dediği fonksiyonu eski imza isimlendiremez; diğerlerini isimlendirir."""
        data = body()
        other = code(*([movz(0, 0x4242)] * 16))
        sigs = [sig("_first", data), sig("_second", data),
                legacy("_legacy_on_ambiguous", data[:32]), legacy("_legacy_other", other[:32])]
        res = run(tmp_path, {F_OFF: data, G_OFF: other},
                  [(fun(F_OFF), F_OFF, len(data)), (fun(G_OFF), G_OFF, len(other))], sigs, path=path)
        assert fun(F_OFF) not in res.matches
        assert res.matches[fun(G_OFF)]["matched_name"] == "_legacy_other"
        assert res.selective_ambiguous == 1
        assert res.signatures_considered == 4


# ---------------------------------------------------------------------------
# 7. Ölçüm betiğinin sınıflandırması
# ---------------------------------------------------------------------------

def test_precision_classify():
    matches = {
        "FUN_10": {"matched_name": "_a"},      # doğru
        "FUN_20": {"matched_name": "_x"},      # adreste başka sembol -> yanlış
        "FUN_30": {"matched_name": "_b"},      # adreste sembol yok, isim başka adreste -> yanlış
        "FUN_40": {"matched_name": "_zzz"},    # adreste sembol yok, isim hiç yok -> doğrulanamaz
    }
    truth = {0x10: {"_a"}, 0x20: {"_c"}, 0x50: {"_b"}}
    out = fprec.classify(matches, truth, {"_a", "_b", "_c"})
    assert [a for a, _ in out["correct"]] == [0x10]
    assert sorted(a for a, *_ in out["wrong"]) == [0x20, 0x30]
    assert [a for a, _ in out["unverifiable"]] == [0x40]
