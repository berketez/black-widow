"""P10 kalem 4 (TIP-05): yapı kurtarma değişkeni (fonksiyon, değişken) ile tanır.

Eski kod erişimleri yalnız ``base_ptr`` ADINA göre bütün dosyalar boyunca topluyor
(ilgisiz fonksiyonların ``param_1``'leri tek yapıya karışıyordu), yeniden yazım eşlemesini
ad başına bir kez kurup her dosyadaki her fonksiyona uyguluyordu; ofseti tabanın tipine göre
ölçeklemiyordu; çağrı grafiği yayılımı "i'inci param_ = i'inci yapı" kuralıyla yapıyı başka
fonksiyonların kaynağına ekliyordu.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.reconstruction.engineering.struct_recovery import (
    EnrichedField,
    EnrichedStruct,
    StructRecoveryEngine,
    _mask_noncode,
    _offset_scale,
)

_IKI_FONKSIYON = """long FUN_0000a000(long param_1)

{
  long lVar1;
  lVar1 = *(long *)(param_1 + 8);
  *(long *)param_1 = lVar1;
  return lVar1;
}

int FUN_0000b000(long param_1)

{
  int iVar1;
  iVar1 = *(int *)(param_1 + 4);
  *(int *)(param_1 + 0x10) = iVar1;
  return iVar1;
}
"""


def _eng() -> StructRecoveryEngine:
    return StructRecoveryEngine(Config())


def _yaz(tmp_path: Path, ad: str, kod: str) -> Path:
    p = tmp_path / ad
    p.write_text(kod, encoding="utf-8")
    return p


class TestCikarma:
    def test_same_name_in_two_functions_gives_two_structs(self, tmp_path: Path) -> None:
        f = _yaz(tmp_path, "a.c", _IKI_FONKSIYON)
        ext = _eng()._extract_structs_from_code([f], {}, [])
        by_fn = {s.source_functions[0]: s for s in ext.structs}
        assert set(by_fn) == {"FUN_0000a000", "FUN_0000b000"}
        assert [x.offset for x in by_fn["FUN_0000a000"].fields] == [0, 8]
        assert [x.offset for x in by_fn["FUN_0000b000"].fields] == [4, 16]
        for s in ext.structs:
            assert len(s.source_functions) == 1
            assert ext.meta[s.name]["base_var"] == "param_1"

    def test_offset_scaled_by_declared_pointer_type(self, tmp_path: Path) -> None:
        kod = """int FUN_0000c000(int *param_1)

{
  int iVar1;
  iVar1 = *(int *)(param_1 + 1);
  iVar1 = iVar1 + *(int *)(param_1 + 2);
  return iVar1;
}
"""
        ext = _eng()._extract_structs_from_code([_yaz(tmp_path, "c.c", kod)], {}, [])
        assert len(ext.structs) == 1
        assert [x.offset for x in ext.structs[0].fields] == [4, 8]

    def test_undeclared_or_unknown_element_base_not_evidence(self, tmp_path: Path) -> None:
        kod = """void FUN_0000d000(FILE *param_1)

{
  *(int *)(DAT_00104010 + 4) = 1;
  *(int *)(DAT_00104010 + 8) = 2;
  *(int *)(param_1 + 4) = 1;
  *(int *)(param_1 + 8) = 2;
  return;
}
"""
        ext = _eng()._extract_structs_from_code([_yaz(tmp_path, "d.c", kod)], {}, [])
        assert ext.structs == []
        assert ext.unscaled_accesses == 4

    def test_width_conflict_and_overlap_no_struct(self, tmp_path: Path) -> None:
        kod = """void FUN_0000e000(long param_1,long param_2)

{
  *(int *)(param_1 + 8) = 1;
  *(long *)(param_1 + 8) = 2;
  *(int *)(param_1 + 0x10) = 3;
  *(long *)param_2 = 1;
  *(int *)(param_2 + 4) = 2;
  return;
}
"""
        ext = _eng()._extract_structs_from_code([_yaz(tmp_path, "e.c", kod)], {}, [])
        assert ext.structs == []
        assert ext.conflicts == 2

    def test_string_and_comment_text_not_evidence(self, tmp_path: Path) -> None:
        kod = """void FUN_0000f000(long param_1)

{
  /* *(int *)(param_1 + 4) */
  puts("*(int *)(param_1 + 8)");
  *(int *)(param_1 + 0xc) = 1;
  return;
}
"""
        ext = _eng()._extract_structs_from_code([_yaz(tmp_path, "f.c", kod)], {}, [])
        assert ext.structs == []  # tek gerçek ofset; yorum ve dizgi sayılmadı


def _yapi(name: str, fn: str, var: str, decl: str, alanlar) -> EnrichedStruct:
    return EnrichedStruct(
        name=name, raw_name=name, total_size=max(o + s for o, _, s in alanlar),
        fields=[EnrichedField(offset=o, raw_name=f"field_0x{o:x}", semantic_name=f"f{o}",
                              c_type=t, size=s, confidence=0.9, observed_type=t)
                for o, t, s in alanlar],
        source_functions=[fn], origin="code", base_var=var, base_decl=decl,
    )


class TestYenidenYazim:
    def test_rewrite_only_in_own_function(self) -> None:
        es = _yapi("S_a", "FUN_0000a000", "param_1", "long", [(0, "long", 8), (8, "long", 8)])
        eng = _eng()
        # C, A ile AYNI ad, AYNI ofset ve AYNI tipte erişiyor; yine de başka nesne.
        kod = _IKI_FONKSIYON + """
long FUN_0000c000(long param_1)

{
  return *(long *)(param_1 + 8);
}
"""
        out, n, per = eng._rewrite_file(kod, eng._build_binding_map([es]))
        assert n == 2 and per == {"S_a": 2}
        assert "((S_a *)param_1)->f8  /* was: *(long *)(param_1 + 8) */" in out
        # B'nin ve C'nin param_1'i (aynı ad, başka fonksiyon) değişmedi
        b = out[out.index("int FUN_0000b000"):]
        assert "S_a" not in b
        assert "*(int *)(param_1 + 4)" in b
        assert "return *(long *)(param_1 + 8);" in b

    def test_type_mismatch_not_rewritten(self) -> None:
        kod = """void FUN_00001000(long param_1)

{
  *(uint *)(param_1 + 4) = 1;
  *(int *)(param_1 + 8) = 2;
  return;
}
"""
        es = _yapi("S_t", "FUN_00001000", "param_1", "long", [(4, "int", 4), (8, "int", 4)])
        eng = _eng()
        out, n, _ = eng._rewrite_file(kod, eng._build_binding_map([es]))
        assert n == 1
        assert "*(uint *)(param_1 + 4) = 1;" in out
        assert "((S_t *)param_1)->f8" in out

    def test_rewrite_uses_scaled_offset(self) -> None:
        kod = """void FUN_00002000(int *param_1)

{
  *(int *)(param_1 + 2) = 1;
  return;
}
"""
        es = _yapi("S_s", "FUN_00002000", "param_1", "int *", [(4, "int", 4), (8, "int", 4)])
        eng = _eng()
        out, n, _ = eng._rewrite_file(kod, eng._build_binding_map([es]))
        assert n == 1 and "((S_s *)param_1)->f8" in out

    def test_declaration_change_blocks_rewrite(self) -> None:
        # Çıkarmada taban ``long`` (bayt aritmetiği) idi; bu metinde ``int *``: ``+ 2``
        # bayt 8'dir ve 8'de alan VAR — yine de bildirim değiştiği için yazılmaz.
        kod = """void FUN_00003000(int *param_1)

{
  *(int *)(param_1 + 2) = 1;
  return;
}
"""
        es = _yapi("S_d", "FUN_00003000", "param_1", "long", [(8, "int", 4), (12, "int", 4)])
        eng = _eng()
        out, n, _ = eng._rewrite_file(kod, eng._build_binding_map([es]))
        assert n == 0 and out == kod

    def test_string_untouched(self) -> None:
        kod = """void FUN_00004000(long param_1)

{
  puts("*(long *)(param_1 + 8)");
  return;
}
"""
        es = _yapi("S_q", "FUN_00004000", "param_1", "long", [(0, "long", 8), (8, "long", 8)])
        eng = _eng()
        out, n, _ = eng._rewrite_file(kod, eng._build_binding_map([es]))
        assert n == 0 and out == kod


class TestYayilim:
    def test_propagation_does_not_make_source_function(self) -> None:
        es = _yapi("S_p", "FUN_0000a000", "param_1", "long", [(0, "long", 8), (8, "long", 8)])
        eng = _eng()
        out = eng._propagate_through_call_graph(
            [es], {"FUN_0000a000": ["FUN_0000b000"]}, {"FUN_0000a000": {0: "S_p"}}, {},
        )
        s = out[0]
        assert s.source_functions == ["FUN_0000a000"]
        assert "FUN_0000b000" in s.propagated_functions
        assert set(eng._build_binding_map(out)) == {("FUN_0000a000", "param_1")}

    def test_param_map_uses_base_var_position(self, tmp_path: Path) -> None:
        kod = """void FUN_00005000(long param_1,long param_2)

{
  return;
}
"""
        f = _yaz(tmp_path, "p.c", kod)
        es = _yapi("S_m", "FUN_00005000", "param_2", "long", [(0, "long", 8), (8, "long", 8)])
        pm = _eng()._build_func_param_map([f], [es], {})
        assert pm == {"FUN_00005000": {1: "S_m"}}


class TestYerlesim:
    def test_typedef_offsets_exact(self, tmp_path: Path) -> None:
        cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if cc is None:
            pytest.skip("C derleyicisi yok")
        es = _yapi("S_y", "FUN_1", "param_1", "long",
                   [(0, "long", 8), (16, "int", 4), (22, "short", 2), (25, "int", 4)])
        es.total_size = 32
        td = StructRecoveryEngine._generate_typedef(es)
        prog = (
            "#include <stddef.h>\n#include <stdint.h>\n" + td + "\n"
            "_Static_assert(offsetof(S_y, f16) == 16, \"16\");\n"
            "_Static_assert(offsetof(S_y, f22) == 22, \"22\");\n"
            "_Static_assert(offsetof(S_y, f25) == 25, \"25\");\n"
            "_Static_assert(sizeof(S_y) == 32, \"boyut\");\n"
        )
        src = tmp_path / "y.c"
        src.write_text(prog, encoding="utf-8")
        r = subprocess.run([cc, "-fsyntax-only", "-std=c11", str(src)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def test_scale_table() -> None:
    assert _offset_scale("long") == 1
    assert _offset_scale("undefined8") == 1
    assert _offset_scale("int *") == 4
    assert _offset_scale("char *") == 1
    assert _offset_scale("long **") == 8
    assert _offset_scale("int") is None
    assert _offset_scale("FILE *") is None
    assert _offset_scale(None) is None
    assert _mask_noncode('a "x(y)" /* z */ b') == 'a' + ' ' * 16 + 'b'
