"""BA-1 — blok açıklama kalıplarında üstel geri izleme (memcpy / memset / memmove).

Gerçek kusur (2026-11-23, Ollama uçtan uca koşusu): ``FUN_100295d40.c`` satır
211, Ghidra'nın satıra böldüğü, kapanan ayracı olmayan bir
``runtime_memmove(`` çağrısı. Eski kalıp ``((?:[^()]+|\\([^)]*\\))+)`` bu satırda
20 sn'de bitmedi; süreç SIGTERM'e yanıt vermedi.

Süre ölçen sınamalar AYRI SÜREÇTE ve zaman aşımıyla koşar: C düzeyindeki
eşleşme iş parçacığından kesilemez, eski kalıp geri konursa (mutant) sınama
asılı kalmamalı, kırmızı olmalı. ``subprocess.run(timeout=...)`` süre dolunca
çocuğu SIGKILL ile öldürür.
"""
from __future__ import annotations

import json
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

from karadul.reconstruction.engineering.block_annotator import (
    MEMORY_PATTERNS,
    CodeBlockAnnotator,
)

KOK = Path(__file__).resolve().parents[1]

# Ollama çalışma alanı, reconstructed/commented/FUN_100295d40.c satır 211 (strip).
GERCEK_SATIR = (
    "runtime_memmove(field_ptr_3,iVar14,status_2 << 3,ctx,i,status,accumulator,"
    "pbVar13,iVar14,"
)

# BA-1 öncesi kalıplar (main 0b4d948, block_annotator.py:324 / 332 / 340).
ESKI = {
    ad: re.compile(
        ad + r"\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)"
    )
    for ad in ("memcpy", "memset", "memmove")
}

# Çocuk süreçte süre ölçümü: block_annotator BU ağaçtan yüklenir (mutant
# uygulanmışsa mutant kod), _detect_memory_ops gerçek yoldan çağrılır.
_COCUK = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
from karadul.reconstruction.engineering.block_annotator import CodeBlockAnnotator
satirlar = json.loads(sys.stdin.read())
an = CodeBlockAnnotator(None)
t0 = time.perf_counter()
anns = an._detect_memory_ops(satirlar, "f", 0)
print(json.dumps({"sure": time.perf_counter() - t0, "n": len(anns)}))
"""

# Yük altında bile bol: yeni kalıp gerçek satırda milisaniyenin altında;
# eski kalıp 32 karakterlik argümanda 20 sn'de bitmiyor.
_ZAMAN_ASIMI_SN = 15.0
_SURE_SINIRI_SN = 2.0


def _yeni(ad: str) -> re.Pattern:
    for pat, _tmpl, _conf in MEMORY_PATTERNS:
        if pat.pattern.startswith(ad):
            return pat
    raise AssertionError(f"{ad} kalıbı yok")


def _ayri_surecte(satirlar: list[str]) -> dict:
    try:
        cp = subprocess.run(
            [sys.executable, "-c", _COCUK, str(KOK)],
            input=json.dumps(satirlar),
            capture_output=True,
            text=True,
            timeout=_ZAMAN_ASIMI_SN,
            cwd=str(KOK),
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"_detect_memory_ops {_ZAMAN_ASIMI_SN} sn'de bitmedi "
            "(üstel geri izleme; çocuk süreç öldürüldü)"
        )
    assert cp.returncode == 0, cp.stderr[-2000:]
    return json.loads(cp.stdout)


def _sonuc(pat: re.Pattern, metin: str):
    m = pat.search(metin)
    return None if m is None else (m.span(), m.groups())


# ---------------------------------------------------------------------------
# Süre (ayrı süreç)
# ---------------------------------------------------------------------------

def test_gercek_satir_ayri_surecte_bitiyor():
    """Ollama'daki kusurlu satır (89 karakter) ve devam satırı."""
    assert len(GERCEK_SATIR) == 89
    out = _ayri_surecte(["  " + GERCEK_SATIR, "                          field_ptr);"])
    assert out["sure"] < _SURE_SINIRI_SN
    assert out["n"] == 0  # satıra bölünmüş çağrı eşleşmez (eskisi de eşleşmezdi)


@pytest.mark.parametrize("ad", ["memcpy", "memset", "memmove"])
def test_kapanmayan_uzun_satir_ayri_surecte_bitiyor(ad):
    """Kapanan ayraçsız 1 000 / 10 000 / 100 000 karakterlik satırlar."""
    govde = "status_2 << 3,ctx,i,"
    satirlar = []
    for n in (1_000, 10_000, 100_000):
        bas = f"runtime_{ad}(field_ptr_3,iVar14,"
        satirlar.append((bas + govde * (n // len(govde) + 1))[:n])
        # İçinde kapanmamış ayraç da olsun.
        satirlar.append((bas + "(long)" + govde + "(" + govde * (n // len(govde) + 1))[:n])
    out = _ayri_surecte(satirlar)
    assert out["sure"] < _SURE_SINIRI_SN
    assert out["n"] == 0


def test_kisa_kapanmayan_arguman_ayri_surecte_bitiyor():
    """Ana oturumun ölçtüğü eşik: üçüncü argümanın ilk 32 karakteri (eski: >20 sn)."""
    arg = "status_2 << 3,ctx,i,status,accumulator,pbVar13,iVar14,"[:32]
    satirlar = [f"{ad}(dst,src,{arg}" for ad in ("memcpy", "memset", "memmove")]
    out = _ayri_surecte(satirlar)
    assert out["sure"] < _SURE_SINIRI_SN
    assert out["n"] == 0


# ---------------------------------------------------------------------------
# Davranış korunur (eski kalıpla aynı eşleşme, aynı gruplar)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("satir", "beklenen"),
    [
        ("memcpy(dst, src, sizeof(double) * n);", ("dst", "src", "sizeof(double) * n")),
        ("memset(buf, 0, (size_t)len * 8);", ("buf", "0", "(size_t)len * 8")),
        ("memmove(p, q, n );", ("p", "q", "n ")),
        # İç içe ayraç: grup ilk ``)``'de kapanır (eski davranış, değişmez).
        ("memcpy(a,b,f(g(x)))", ("a", "b", "f(g(x)")),
        ("memcpy(a,b, )", ("a", "b", " ")),
        # Önekli adlar da eşleşir (kural değişmez; sayım BA1.md'de).
        ("runtime_memmove(x,y,n)", ("x", "y", "n")),
        ("_memcpy(puVar3,param_2,(long)(int)uVar1 * 0x18);",
         ("puVar3", "param_2", "(long)(int)uVar1 * 0x18")),
        (
            "memcpy(local_48,(void *)(lVar2 + 0x10),(long)iVar1 << 3);",
            None,  # ikinci argüman \w+ değil
        ),
        ("memcpy(a,b,)", None),
        ("memcpy(a,b,c", None),
    ],
)
def test_ic_ice_ayracli_cagrilar_eski_ile_ayni(satir, beklenen):
    ad = next(a for a in ("memmove", "memcpy", "memset") if a in satir)
    yeni = _sonuc(_yeni(ad), satir)
    assert yeni == _sonuc(ESKI[ad], satir)
    assert (None if yeni is None else yeni[1]) == beklenen


def test_rastgele_kisa_satirlarda_eski_ile_ayni():
    """Eski kalıbın hızlı bittiği kısa girdilerde span + gruplar birebir aynı.

    Üçüncü argüman en çok 12 karakter: eski kalıbın en kötü durumu 2^12 adım.
    """
    rnd = random.Random(20261123)
    alfabe = ["a", "b", "1", " ", ",", "(", ")", "*", "<", "x_", "\t"]
    for ad in ("memcpy", "memset", "memmove"):
        for _ in range(1500):
            on = rnd.choice(["", "  ", "runtime_", "_", "x = ", "__"])
            bas = rnd.choice([f"{ad}(d,s,", f"{ad} ( d , s , ", f"{ad}(d,s, ", f"{ad}(d s,"])
            kuyruk = "".join(rnd.choice(alfabe) for _ in range(rnd.randint(0, 12)))
            satir = on + bas + kuyruk
            assert _sonuc(_yeni(ad), satir) == _sonuc(ESKI[ad], satir), satir


def test_aciklama_metni_eski_kalipla_ayni(monkeypatch):
    """_detect_memory_ops'un ürettiği açıklama metni eski kalıplarla aynı."""
    satirlar = [
        "  memcpy(dst, src, sizeof(double) * n);",
        "    memset(local_118,0,0x100);",
        "  memmove(puVar4,puVar4 + 1,(long)iVar2 * 8);",
        "  _memcpy(__dst,__src,__n);",
        "  pvVar1 = malloc(n * sizeof(int));",
        "  runtime_memmove(field_ptr_3,iVar14,status_2 << 3,ctx);",
    ]
    an = CodeBlockAnnotator(None)
    yeni = [(a.text, a.line_number, a.confidence) for a in an._detect_memory_ops(satirlar, "f", 5)]
    eski_liste = []
    for pat, tmpl, conf in MEMORY_PATTERNS:
        ad = next((a for a in ("memcpy", "memset", "memmove") if pat.pattern.startswith(a)), None)
        eski_liste.append((ESKI[ad] if ad else pat, tmpl, conf))
    import karadul.reconstruction.engineering.block_annotator as ba

    monkeypatch.setattr(ba, "MEMORY_PATTERNS", eski_liste)
    eski = [(a.text, a.line_number, a.confidence) for a in an._detect_memory_ops(satirlar, "f", 5)]
    assert yeni == eski
    # memmove satırının ikinci argümanı ``\w+`` değil: eşleşmez (eskisi de).
    assert len(yeni) == 5
    assert yeni[0][0] == "  // Copy memory: dst <- src, size=sizeof(double) * n [type: double]"


# ---------------------------------------------------------------------------
# Yapı: üçüncü argümanın döngüsü atomik grupta
# ---------------------------------------------------------------------------

def _atomik_disi_ic_ice_yineleme(kalip: str) -> bool:
    """Atomik grup dışında, sınırsız yineleme içinde sınırsız yineleme var mı?"""
    from re import _constants as C  # type: ignore[attr-defined]
    from re import _parser as P  # type: ignore[attr-defined]

    tekrar = (C.MAX_REPEAT, C.MIN_REPEAT)

    def gez(dugumler, yineleme_icinde: bool) -> bool:
        for op, av in dugumler:
            if op == C.ATOMIC_GROUP or op == C.POSSESSIVE_REPEAT:
                continue
            if op in tekrar:
                lo, hi, alt = av
                sinirsiz = hi == C.MAXREPEAT or hi > 1
                if sinirsiz and yineleme_icinde:
                    return True
                if gez(alt, yineleme_icinde or sinirsiz):
                    return True
            elif op == C.SUBPATTERN:
                if gez(av[-1], yineleme_icinde):
                    return True
            elif op == C.BRANCH:
                if any(gez(d, yineleme_icinde) for d in av[1]):
                    return True
        return False

    return gez(P.parse(kalip), False)


@pytest.mark.parametrize("ad", ["memcpy", "memset", "memmove"])
def test_kalipta_atomik_disi_ic_ice_yineleme_yok(ad):
    assert _atomik_disi_ic_ice_yineleme(ESKI[ad].pattern) is True  # denetimin kendisi
    assert _atomik_disi_ic_ice_yineleme(_yeni(ad).pattern) is False
