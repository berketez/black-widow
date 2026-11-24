"""BA-2: iki üstel kalıbın onarımı (``c_namer._try_demangle_cpp`` ve
``constraint_solver._LINKED_LIST_RE``).

Süre ölçen ve eski (kusurlu) kalıbı çalıştıran her sınama AYRI SÜREÇTE,
zaman aşımıyla koşar: C düzeyindeki ``re`` eşleşmesi iş parçacığından
kesilemez ve SIGTERM'e yanıt vermez; ``subprocess.run(timeout=…)`` süre
dolunca çocuğu SIGKILL ile öldürür. Böylece onarım geri alınırsa (mutant)
sınama asılı kalmaz, kırmızı olur.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parents[1]

# BA-1 envanterindeki eski kalıplar (main cfe93cef; c_namer.py:3441,
# constraint_solver.py:271).
ESKI_ZN = r"_ZN(\d+\w+)+E"
ESKI_LINKED = (
    r"(?P<var>\w+)\s*=\s*\*\s*\(\s*"
    r"(?P<type>[a-zA-Z_](?:\w+\s*)*\*{0,2})\s*\*?\s*\)\s*\(\s*"
    r"(?P=var)\s*\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\)"
)
COCUK_SURE_SINIRI_SN = 15.0


def _cocukta(kod: str, girdi: dict) -> dict:
    """``kod``u ayrı süreçte koşar (bu ağacın ``karadul``u yüklenir)."""
    on = f"import sys; sys.path.insert(0, {str(KOK)!r})\n"
    try:
        cp = subprocess.run(
            [sys.executable, "-c", on + kod],
            input=json.dumps(girdi), capture_output=True, text=True,
            timeout=COCUK_SURE_SINIRI_SN, cwd=str(KOK),
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"çocuk süreç {COCUK_SURE_SINIRI_SN} sn'de bitmedi (üstel geri izleme)")
    assert cp.returncode == 0, cp.stderr[-2000:]
    return json.loads(cp.stdout.strip().splitlines()[-1])


_DEMANGLE_SURE = r"""
import json, sys, time
from karadul.reconstruction.c_namer import CVariableNamer
g = json.loads(sys.stdin.read())
out = []
for m in g["metinler"]:
    t0 = time.perf_counter()
    r = CVariableNamer._try_demangle_cpp(m)
    out.append([time.perf_counter() - t0, r])
print(json.dumps(out))
"""

_LINKED_SURE = r"""
import json, sys, time
from karadul.reconstruction.recovery_layers.constraint_solver import _LINKED_LIST_RE as K
g = json.loads(sys.stdin.read())
out = []
for m in g["metinler"]:
    t0 = time.perf_counter()
    r = [[x.span(), x.groupdict()] for x in K.finditer(m)]
    out.append([time.perf_counter() - t0, r])
print(json.dumps(out))
"""


# ---------------------------------------------------------------------------
# H1: BA-1'in düşmanca girdileri ve daha uzunları
# ---------------------------------------------------------------------------

def test_demangle_dusmanca_girdi_hizli() -> None:
    metinler = ["_ZN" + "0a" * n + "!" for n in (28, 64, 1_000, 20_000)]
    sonuc = _cocukta(_DEMANGLE_SURE, {"metinler": metinler})
    for (sure, r), m in zip(sonuc, metinler):
        assert sure <= 0.1, (len(m), sure)
        assert r is None


def test_linked_list_dusmanca_girdi_hizli() -> None:
    # 20 000'lik `a` koşusu burada yok: `var` \w+ koşusu arama başlangıcıyla
    # karesel (BA-2 ilerleme dosyası, polinom listesi); üstel değil.
    metinler = ["a=*(a" + "a" * n + "!" for n in (24, 64, 1_000)]
    metinler.append("p = *(" + "int " * 5_000 + "!")
    sonuc = _cocukta(_LINKED_SURE, {"metinler": metinler})
    for (sure, r), m in zip(sonuc, metinler):
        assert sure <= 0.1, (len(m), sure)
        assert r == []


# ---------------------------------------------------------------------------
# Davranış: geçerli girdilerde aynı sonuç
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("mangled", "beklenen"), [
    ("_ZN3foo3barEv", "foo_bar"),
    ("_ZN4core3fmt5write17h0123456789abcdefE", "core_fmt_write_h0123456789abcdef"),
    ("_ZN12E", None),          # E hemen rakamdan sonra: eşleşme yok, sonraki kural
    ("_ZN1aE", "a"),
    ("_ZNK3Foo3getEv", None),  # _ZNK: rakamla başlamıyor
])
def test_demangle_gecerli_adlar(mangled: str, beklenen: str | None) -> None:
    sonuc = _cocukta(_DEMANGLE_SURE, {"metinler": [mangled]})
    r = sonuc[0][1]
    if beklenen is None:
        # _ZN kuralı tutmadı; sonraki kurallar ne verirse versin _ZN yolu değil
        assert r is None or "_" not in r or r != beklenen
    else:
        assert r == beklenen


def test_linked_list_gecerli_satirlar() -> None:
    metinler = [
        "  p = *(struct node **)(p + 8);",
        "  lVar3 = *(long *)(lVar3 + 0x10);\n  x = 1;",
        "pcVar1 = *(code **)(pcVar1 + 0x18); q = *(int *) (q+4)",
        "a = *(unsigned long long * *)(a + 16)",
        "b=*(T)(b+0x0)",
    ]
    sonuc = _cocukta(_LINKED_SURE, {"metinler": metinler})
    gruplar = [[(d["var"], d["type"].strip(), d["offset"]) for _span, d in r] for _s, r in sonuc]
    assert gruplar == [
        [("p", "struct node **", "8")],
        [("lVar3", "long *", "0x10")],
        [("pcVar1", "code **", "0x18"), ("q", "int *", "4")],
        [("a", "unsigned long long *", "16")],
        [("b", "T", "0x0")],
    ]


# ---------------------------------------------------------------------------
# Eşdeğerlik: eski ↔ yeni kalıp (rastgele kısa girdiler; eski kalıp ayrı süreçte)
# ---------------------------------------------------------------------------

_ESDEGER = r"""
import json, random, re, sys
g = json.loads(sys.stdin.read())
eski = re.compile(g["eski"]); yeni = re.compile(g["yeni"])
rnd = random.Random(g["tohum"])
farkli = 0; eslesen = 0; n = 0
for _ in range(g["adet"]):
    m = "".join(rnd.choice(g["alfabe"]) for _ in range(rnd.randint(0, g["uzunluk"])))
    if g.get("son"):
        m += rnd.choice(g["son"])
    m = g["on"][rnd.randrange(len(g["on"]))] + m
    if g["kip"] == "match":
        a, b = eski.match(m), yeni.match(m)
        ia = None if a is None else [a.span(), a.groups()]
        ib = None if b is None else [b.span(), b.groups()]
    else:
        ia = [[x.span(), x.groupdict()] for x in eski.finditer(m)]
        ib = [[x.span(), x.groupdict()] for x in yeni.finditer(m)]
    n += 1
    eslesen += bool(ia)
    farkli += ia != ib
print(json.dumps({"n": n, "eslesen": eslesen, "farkli": farkli}))
"""


def _yeni_zn() -> str:
    kaynak = (KOK / "karadul/reconstruction/c_namer.py").read_text(encoding="utf-8")
    satir = [s for s in kaynak.splitlines() if "match = re.match(r\"_ZN" in s]
    assert len(satir) == 1
    return satir[0].split('r"', 1)[1].rsplit('"', 1)[0]


def test_demangle_eski_yeni_esdeger() -> None:
    sonuc = _cocukta(_ESDEGER, {
        "eski": ESKI_ZN, "yeni": _yeni_zn(), "tohum": 2, "adet": 40_000, "uzunluk": 12,
        "alfabe": "0123aEbE_!x", "on": ["_ZN", "_ZN1", "_ZN12", "_Z", "x_ZN"], "kip": "match",
    })
    assert sonuc["farkli"] == 0, sonuc
    assert sonuc["eslesen"] > 1_000, sonuc


def test_linked_list_eski_yeni_esdeger() -> None:
    from karadul.reconstruction.recovery_layers.constraint_solver import _LINKED_LIST_RE
    sonuc = _cocukta(_ESDEGER, {
        "eski": ESKI_LINKED, "yeni": _LINKED_LIST_RE.pattern, "tohum": 3, "adet": 40_000,
        "uzunluk": 6, "alfabe": ["p", "q", "a", " ", "  ", "*", "(", ")", "+", "=", "8",
                                  "0x1", "_", "\n", ";", "int", "char"],
        "on": ["p=*(", "p = *(int ", "p=*(a b", "q=*(T*)(q+", "p = *(long **", ""],
        "son": ["", ")(p+8)", ") (p + 0x10)", "*)(p+1)", " *)(q+2)", ")(p+", "!"],
        "kip": "finditer",
    })
    assert sonuc["farkli"] == 0, sonuc
    assert sonuc["eslesen"] > 1_000, sonuc


def test_eski_kaliplar_gercekten_ustel() -> None:
    """Sınamanın körleşmediği: eski kalıplar aynı düşmanca girdide yavaş."""
    kod = r"""
import json, re, sys, time
g = json.loads(sys.stdin.read())
k = re.compile(g["k"]); t0 = time.perf_counter(); k.search(g["m"])
print(json.dumps(time.perf_counter() - t0))
"""
    for kalip, metin in ((ESKI_ZN, "_ZN" + "0a" * 16 + "!"),
                         (ESKI_LINKED, "a=*(a" + "a" * 16 + "!")):
        s = _cocukta(kod, {"k": kalip, "m": metin})
        assert s > 0.001, (kalip, s)
