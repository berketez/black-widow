"""c_namer ADAY SIRALAMA / ILK-SECIM / esik-kenari regresyon testleri.

Mutasyon deligi (2026-07-16): _strategy_string_context'in aday secim mantigi
(agresif max-secim `conf > best`, 0.75 erken-donus esigi `>=`, klasik
`scored.sort(reverse=True); scored[0]`) davranissal olarak test EDILMIYORDU.
Bu testler GERCEK CVariableNamer._strategy_string_context'i cagirir ve secilen
adayin dogru olani oldugunu kilitler.

NOT: Cephe 1b'nin Alg1/2a body-param koduna DOKUNULMAZ; burada yalniz eski
string-context stratejisinin secim kenarlari test edilir (kaynak degismez).
"""
from __future__ import annotations

from types import SimpleNamespace

from karadul.config import Config
from karadul.reconstruction.c_namer import CVariableNamer


def _run_string_context(
    strings: list[str], addr: str = "0x401000", name: str = "FUN_00401000"
) -> list:
    """Gercek _strategy_string_context'i kos, fonksiyonun aday listesini dondur."""
    namer = CVariableNamer(Config(), min_confidence=0.15)
    namer._string_refs_by_func[addr] = strings
    namer._func_bodies[name] = ""
    func_info = SimpleNamespace(name=name, address=addr, params=[])
    namer._strategy_string_context(func_info)
    return dict(namer._candidates).get(name, [])


def test_aggressive_max_selection_picks_highest_confidence():
    """Iki agresif eslesme (0.85 vs 0.80) -> YUKSEK guvenli aday kazanir.

    "CFoo::BarBaz" -> ('foo_barbaz', 0.85); "helperFunc()" -> ('helperfunc', 0.80).
    Listede once 0.85 gelir; dogru kod `conf > best[1]` ile onu KORUR.
    Mutant `conf > best[1]` -> `conf < best[1]`: sonraki 0.80 kazanir ('helperfunc')
    -> bu assert KIRMIZI.
    """
    cands = _run_string_context(["CFoo::BarBaz", "helperFunc()"])
    assert len(cands) == 1
    assert cands[0].new_name == "foo_barbaz", (
        f"en yuksek guvenli agresif aday secilmedi: {cands[0].new_name}"
    )
    assert cands[0].confidence == 0.85


def test_aggressive_tie_keeps_first_seen():
    """ESIT guven (0.85 == 0.85) -> ILK gorulen aday korunur (`>` kenari).

    "CFoo::BarBaz" ve "CAlpha::Beta" ikisi de 0.85. Dogru `conf > best[1]`
    esitlikte ILKINI (foo_barbaz) korur. Mutant `>` -> `>=`: esitlikte
    SONUNCUYU (alpha_beta) alir -> bu assert KIRMIZI. Kararli/deterministik
    secim onemli (ayni girdi -> ayni isim)."""
    cands = _run_string_context(["CFoo::BarBaz", "CAlpha::Beta"])
    assert len(cands) == 1
    assert cands[0].new_name == "foo_barbaz", (
        f"esitlikte ilk aday korunmadi: {cands[0].new_name}"
    )


def test_aggressive_075_threshold_blocks_classic():
    """conf == 0.75 -> `if conf >= 0.75: return` klasik asamayi ATLAR (tek aday).

    "/src/net/socket.cpp" -> agresif ('net_socket', 0.75). Dogru kod 0.75'te
    erken doner -> yalniz 1 aday. Mutant `>= 0.75` -> `> 0.75`: 0.75 esigi
    gecemez, klasik de calisir ve IKINCI aday ('net_socket_cpp') eklenir ->
    len(cands) == 2 -> bu assert KIRMIZI.
    """
    cands = _run_string_context(["/src/net/socket.cpp"])
    assert len(cands) == 1, (
        f"0.75 esigi klasik asamayi atlamadi, fazladan aday olustu: "
        f"{[(c.new_name, c.confidence) for c in cands]}"
    )
    assert cands[0].new_name == "net_socket"
    assert cands[0].confidence == 0.75


def test_classic_scored_sort_picks_highest_score():
    """Agresif eslesmeyen iki string -> klasik `scored.sort` en YUKSEK skoru secer.

    "cat dog" (2 kisa kw) once; "compression dictionary window management"
    (4 uzun kw, yuksek skor) sonra gelir. Dogru `reverse=True` yuksek skoru
    secer -> 'compression_dictionary_window'. Mutant `reverse=True` -> `False`:
    dusuk skor 'cat_dog' secilir -> bu assert KIRMIZI.
    """
    cands = _run_string_context(
        ["cat dog", "compression dictionary window management"]
    )
    assert len(cands) == 1
    assert cands[0].new_name == "compression_dictionary_window", (
        f"klasik sort en yuksek skoru secmedi: {cands[0].new_name}"
    )
