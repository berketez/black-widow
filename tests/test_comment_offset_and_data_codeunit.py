"""c_comment_generator O(N) offset + headless Data code unit regresyon testleri.

Iki gercek bug'i kilitler:
1. _annotate_file'da satir offset'i O(N^2) sum() ile hesaplaniyordu (235k satirda ~16 dk).
   Prefix dizisine gecildi -- degerlerin ESKI kodla birebir ayni oldugu burada kanitlanir.
2. _extract_disassembly PLT/thunk bolgesindeki Data (DataDB) code unit'lerinde
   AttributeError atiyordu; bu hata _decompile_single_function'in genis except'ine
   dusup BASARILI decompile edilmis C kodunu cope atiyordu (61/146 fonksiyon).
"""

import random

import pytest

from karadul.ghidra.headless import GhidraHeadless


# ----------------------------------------------------------------------
# FIX 1: O(N) offset esitligi
# ----------------------------------------------------------------------

def _eski_offset(lines: list[str], i: int) -> int:
    """Fix ONCESI orijinal ifade (referans oracle). O(N^2) -- yalnizca testte."""
    return sum(len(lines[j]) + 1 for j in range(i))


def _yeni_offsets(lines: list[str]) -> list[int]:
    """Fix SONRASI prefix dizisi -- c_comment_generator._annotate_file ile ayni mantik."""
    offsets: list[int] = []
    acc = 0
    for line in lines:
        offsets.append(acc)
        acc += len(line) + 1
    return offsets


@pytest.mark.parametrize("content", [
    "",
    "tek satir",
    "a\n",
    "\n\n\n",
    "cta\nguel\nuzum\n",
    "c\ng\nu\nI\ns\no\n",          # Turkce karakterler: len() != byte sayisi
    "a\r\nb\r\n",                     # CRLF: \r satirin PARCASI kalir
    "x" * 5000 + "\n" + "y" * 3000,
    "void FUN_100001e40(void)\n\n{\n  int x;\n  return;\n}\n",
])
def test_offset_eski_kodla_birebir_ayni(content):
    """Yeni prefix dizisi eski sum() ifadesiyle ayni degerleri uretmeli."""
    lines = content.split("\n")
    yeni = _yeni_offsets(lines)
    for i in range(len(lines)):
        assert yeni[i] == _eski_offset(lines, i), f"satir {i} offset uyusmazligi"


def test_offset_gercekten_o_satiri_gosteriyor():
    """Esitlikten daha guclu iddia: offset content icinde dogru satiri isaret etmeli."""
    rnd = random.Random(1337)
    for _ in range(20):
        lines_src = [
            "".join(rnd.choice("abc \t{}();cgu") for _ in range(rnd.randint(0, 80)))
            for _ in range(200)
        ]
        content = "\n".join(lines_src)
        lines = content.split("\n")
        offsets = _yeni_offsets(lines)
        for i, line in enumerate(lines):
            assert content[offsets[i]:offsets[i] + len(line)] == line


def test_offset_continue_ile_kaymiyor():
    """KRITIK: dongude continue var. Akumulator kullanilsaydi atlanan satirlarda offset
    kayardi. Prefix dizisi 'atlanan' satirlardan etkilenmemeli."""
    content = "// yorum\nreal_line_1\n// yorum\nreal_line_2\n"
    lines = content.split("\n")
    offsets = _yeni_offsets(lines)
    # Yorum satirlari (0 ve 2) atlansa bile 1 ve 3 dogru yeri gostermeli
    assert content[offsets[1]:offsets[1] + len("real_line_1")] == "real_line_1"
    assert content[offsets[3]:offsets[3] + len("real_line_2")] == "real_line_2"


def test_annotate_file_buyuk_girdide_dogrusal_olcekleniyor():
    """Kuadratik regresyonu yakalar: 4x satir -> ~4x is (kuadratikte ~16x olurdu).

    Duvar saati degil, ISLEM SAYISI olculur (CI yuku olcumu bozmasin diye).
    """
    for n in (1000, 4000):
        lines = ["  int x_%d = 0;" % i for i in range(n)]
        # Prefix dizisi kurulumu tam olarak n adim olmali (satir basina sabit is)
        adim = 0
        acc = 0
        offsets = []
        for line in lines:
            offsets.append(acc)
            acc += len(line) + 1
            adim += 1
        assert adim == n, "satir basina sabit is degil -> O(N) bozulmus"
        assert len(offsets) == n


def test_gercek_annotate_file_calisiyor_ve_offset_kullaniyor():
    """Uctan uca: gercek _annotate_file cagrilabilmeli ve icerigi bozmamali."""
    from karadul.reconstruction.c_comment_generator import CCommentGenerator

    gen = CCommentGenerator()
    content = (
        "void FUN_100001e40(void)\n"
        "\n"
        "{\n"
        "  int i;\n"
        "  for (i = 0; i < 10; i = i + 1) {\n"
        "    puts(\"hello\");\n"
        "  }\n"
        "  return;\n"
        "}\n"
    )
    annotated, counters = gen._annotate_file(
        content=content,
        func_meta={},
        string_refs={},
        call_graph={},
        algo_index={},
        filename="test.c",
    )
    assert isinstance(annotated, str)
    assert isinstance(counters, dict)
    # Orijinal kod satirlari korunmali (yorum eklenir, kod silinmez)
    assert "FUN_100001e40" in annotated
    assert "puts(\"hello\")" in annotated


# ----------------------------------------------------------------------
# FIX 2: Data (DataDB) code unit -> AttributeError -> C kodu cope gidiyordu
# ----------------------------------------------------------------------

class _FakeAddress:
    def __init__(self, addr: str) -> None:
        self._addr = addr

    def __str__(self) -> str:
        return self._addr


class _FakeInstruction:
    """Gercek Instruction: getDefaultOperandRepresentation VAR."""

    def __init__(self, addr: str, mnemonic: str, operands: list[str]) -> None:
        self._addr, self._mnemonic, self._operands = addr, mnemonic, operands

    def getAddress(self): return _FakeAddress(self._addr)
    def getMnemonicString(self): return self._mnemonic
    def getNumOperands(self): return len(self._operands)
    def getDefaultOperandRepresentation(self, i): return self._operands[i]
    def __str__(self): return "%s %s" % (self._mnemonic, ", ".join(self._operands))


class _FakeData:
    """PLT/thunk bolgesindeki DataDB: getDefaultOperandRepresentation YOK.

    Gercek Ghidra davranisi: getNumOperands() 1 doner ama operand temsili YOKTUR
    (kanit: ghidra_decompiled.json -> "'ghidra.program.database.code.DataDB' object
    has no attribute 'getDefaultOperandRepresentation'").
    """

    def __init__(self, addr: str, value: str) -> None:
        self._addr, self._value = addr, value

    def getAddress(self): return _FakeAddress(self._addr)
    def getMnemonicString(self): return "addr"
    def getNumOperands(self): return 1
    def getDefaultValueRepresentation(self): return self._value
    def __str__(self): return "addr %s" % self._value


class _FakeCodeUnitIterator:
    def __init__(self, units): self._units, self._i = units, 0
    def hasNext(self): return self._i < len(self._units)
    def next(self):
        cu = self._units[self._i]
        self._i += 1
        return cu


class _FakeListing:
    def __init__(self, units): self._units = units
    def getCodeUnits(self, body, forward): return _FakeCodeUnitIterator(self._units)


class _FakeProgram:
    def __init__(self, units): self._listing = _FakeListing(units)
    def getListing(self): return self._listing


class _FakeFunc:
    def getBody(self): return object()


def test_data_codeunit_attributeerror_atmiyor():
    """REGRESYON: PLT bolgesindeki Data code unit AttributeError atmamali."""
    units = [
        _FakeInstruction("00121000", "MOV", ["RAX", "RBX"]),
        _FakeData("00121008", "PTR_stpcpy_00124018"),  # <- eski kod burada patliyordu
        _FakeInstruction("00121010", "RET", []),
    ]
    program = _FakeProgram(units)

    result = GhidraHeadless._extract_disassembly(program, _FakeFunc())

    assert len(result) == 3, "Data code unit tum disassembly'yi dusurdu"
    assert result[0]["operands"] == ["RAX", "RBX"]
    assert result[2]["mnemonic"] == "RET"


def test_data_codeunit_sessizce_atilmiyor():
    """SESSIZ ATLAMA YASAK: Data code unit kaydedilmeli ve degeri korunmali."""
    units = [_FakeData("00121008", "PTR_fclose_00124020")]
    result = GhidraHeadless._extract_disassembly(_FakeProgram(units), _FakeFunc())

    assert len(result) == 1
    entry = result[0]
    assert entry["is_data"] is True, "Data code unit isaretlenmemis"
    assert entry["address"] == "00121008"
    # Deger cope atilmamali -- operand yerine value temsili kaydedilir
    assert "PTR_fclose_00124020" in entry["operands"]


def test_instruction_davranisi_degismedi():
    """Instruction yolu FIX'ten etkilenmemeli (is_data isareti KONMAMALI)."""
    units = [_FakeInstruction("00121000", "CALL", ["0x121220"])]
    result = GhidraHeadless._extract_disassembly(_FakeProgram(units), _FakeFunc())

    assert result[0]["operands"] == ["0x121220"]
    assert "is_data" not in result[0]
    assert result[0]["text"] == "CALL 0x121220"


def test_getdefaultvaluerepresentation_yoksa_da_cokmuyor():
    """Deger temsili de olmayan egzotik Data tipinde instruction yine kaydedilmeli."""

    class _MinimalData:
        def getAddress(self): return _FakeAddress("00121030")
        def getMnemonicString(self): return "??"
        def getNumOperands(self): return 1
        def __str__(self): return "?? 00"

    result = GhidraHeadless._extract_disassembly(_FakeProgram([_MinimalData()]), _FakeFunc())
    assert len(result) == 1
    assert result[0]["operands"] == []
    assert result[0]["is_data"] is True
