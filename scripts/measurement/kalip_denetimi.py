"""Düzenli ifade denetimi: üstel / polinom geri izleme taraması (BA-1, BA-2).

BA-1'de ``scripts/arge/ba1/kalip_tara.py`` olarak yazıldı; BA-2'de buraya
taşındı ve tam takımın kapısı oldu (``tests/test_kalip_denetimi.py``).
``scripts/arge/ba1/`` betikleri bu modülü içe aktarır.

Neden kapı: ``re`` eşleşmesi GIL'i bırakmaz ve C düzeyinde SIGTERM'e yanıt
vermez (KARARLAR A-36); üstel bir kalıp süreci kilitlediğinde süreç içinden
hiçbir bekçi koşamaz. Bu sınıf ancak koda girmeden önlenebilir.

Yöntem
------
1. **Toplama (AST):** verilen ``.py`` dosyalarında ``re.<işlev>(<kalıp>, ...)``
   çağrıları (``compile``, ``search``, ``match``, ``fullmatch``, ``findall``,
   ``finditer``, ``sub``, ``subn``, ``split``). Kalıp ifadesinin türü:
   - ``sabit``: dizgi sabiti ya da sabitlerin ``+`` birleşimi;
   - ``ad``: aynı modülün üst düzeyinde sabit dizgiye bağlanan bir ad;
   - ``sablon``: çalışma anında kurulan kalıp (f-dizgi, ``+`` ile ad,
     ``"…".format(…)``, ``"…" % …``, ``"|".join(…)``). Yerleştirilen her parça
     tek bir sabit harfle (``Q``) temsil edilir ve şablon taranır. Parça
     ``re.escape(…)``'ten geçiyorsa harf gerçekten sabittir; geçmiyorsa
     yerleştirme ``kacissiz`` diye ayrıca kaydedilir (parça kalıp sözdizimi
     taşıyabilir; şablonun taranması onu kapsamaz);
   - ``taranamadi``: yukarıdakilerin hiçbiri.
   Bayraklar ``re.X`` adlarından hesaplanır.
2. **Durağan sınıflama (``re._parser`` ağacı):**
   - ``ic_ice``: atomik grup / sahiplenici niceleyici dışında, sınırsız
     yinelemenin gövdesinde sınırsız yineleme (``(a+)+``, ``(?:[^()]+|…)+``);
   - ``ortusen_secenek``: sınırsız yinelemenin gövdesinde, ilk karakter
     kümeleri kesişen iki seçenek (``(?:a|ab)+``, ``(\\w|\\d)+``);
   - ``zincir``: aynı dizide ilk karakter kümeleri kesişen en az iki sınırsız
     yineleme (``.*x.*``; polinom adayı; derece ≈ yineleme sayısı).
3. **Devingen doğrulama (ayrı süreç, bekçili):** ``ic_ice`` ve
   ``ortusen_secenek`` adaylarında düşmanca girdi kurulur: önek = yinelemeye
   götüren alt kalıbın en kısa tanığı, pompa = yineleme gövdesinin tanığı ya da
   iç yinelemenin tek karakteri ya da kesişen seçeneklerin ortak karakteri,
   sonek = eşleşmeyi bozan bir karakter (``!``, satır sonu, ``(``, ``)``,
   ``\\x00`` …; 6 pompada eşleşmediği denetlenir). Pompa sayısı 8, 12, …, 32.
   **Üstel**: süre ≥ 1 sn, ya da +4 pompada süre ≥ 8 kat (ve ≥ 10 ms), ya da
   bekçinin zaman aşımı. Bütün adaylar TEK bir çocuk süreçte ölçülür; çocuk
   her ölçümden önce ve sonra bir satır yazar, ebeveyn ``zaman_asimi`` sn
   ilerleme görmezse çocuğu SIGKILL ile öldürür (C düzeyindeki eşleşme
   SIGTERM'e yanıt vermez), o adayı üstel sayar ve sonraki adaydan yeni çocuk
   açar. (BA-1'de her ölçüm ayrı süreçti; tek süreç kapıyı ≤ 60 sn'ye indirir.)
4. **İstisna listesi** (``ISTISNALAR``): yanlış alarm olduğu ölçümle gösterilen
   kalıp (dosya + kalıp dizgisi, gerekçe, ölçülen süre). Boş başlar.

Sınır: pompa üreteci sezgisel; üretemediği düşmanca girdi biçimleri olabilir
(BA-2 ilerleme dosyasında elle sınıflanan adaylar). ``re`` dışındaki eşleştirici
(``fnmatch``, ``regex`` paketi) ve ``re`` adını başka adla içe aktaran çağrılar
taranmaz.

Kullanım (worktree kökünden):

    python scripts/measurement/kalip_denetimi.py tara --json <dosya> <yol> [<yol> ...]
    python scripts/measurement/kalip_denetimi.py gercek --json <dosya> --ws <oturum> ...
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from re import _constants as C  # type: ignore[attr-defined]
from re import _parser as P  # type: ignore[attr-defined]

KOK = Path(__file__).resolve().parents[2]
RE_ISLEVLERI = {"compile", "search", "match", "fullmatch", "findall", "finditer",
                "sub", "subn", "split"}
ALFABE = [chr(i) for i in range(32, 127)] + ["\n", "\t", "\x00"]
TERCIH = list("a0_ ,(x;=*")
SONEKLER = ["!", "\n", "", "(", ")", "\x00", ";", " ", "{", "}", "]", "\"", "'"]
TEKRAR = (C.MAX_REPEAT, C.MIN_REPEAT)
ZAMAN_ASIMI = 5.0
YER_TUTUCU = "Q"

# Kapının denetlediği yollar (depo köküne göre).
KAPI_YOLLARI = ("karadul", "ui/server.py")

# Yanlış alarm istisnaları. Her kayıt: {"dosya": "karadul/…py", "kalip": "<dizgi>",
# "gerekce": "…", "olculen_sure": "…"}. Eşleme dosya + kalıp dizgisiyle (satır
# numarası kayar). Boş başlar; tests/test_kalip_denetimi.py sayısını denetler.
ISTISNALAR: list[dict] = []


# ---------------------------------------------------------------------------
# 1. Toplama
# ---------------------------------------------------------------------------

def _sabit_dizgi(dugum: ast.AST) -> str | None:
    if isinstance(dugum, ast.Constant) and isinstance(dugum.value, str):
        return dugum.value
    if isinstance(dugum, ast.BinOp) and isinstance(dugum.op, ast.Add):
        a, b = _sabit_dizgi(dugum.left), _sabit_dizgi(dugum.right)
        if a is not None and b is not None:
            return a + b
    return None


def _bayrak(dugum: ast.AST | None) -> int | None:
    if dugum is None:
        return 0
    if isinstance(dugum, ast.Attribute) and isinstance(dugum.value, ast.Name) \
            and dugum.value.id == "re":
        return int(getattr(re, dugum.attr, 0))
    if isinstance(dugum, ast.BinOp) and isinstance(dugum.op, ast.BitOr):
        a, b = _bayrak(dugum.left), _bayrak(dugum.right)
        return None if a is None or b is None else a | b
    if isinstance(dugum, ast.Constant) and isinstance(dugum.value, int):
        return dugum.value
    return None


def _re_escape_mi(dugum: ast.AST) -> bool:
    return (isinstance(dugum, ast.Call) and isinstance(dugum.func, ast.Attribute)
            and isinstance(dugum.func.value, ast.Name) and dugum.func.value.id == "re"
            and dugum.func.attr == "escape")


def _modul_sabitleri(agac: ast.Module) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Üst düzeyde (ve sınıf gövdesinde) bir kez atanan sabit dizgi / dizgi listeleri."""
    dizgi: dict[str, str] = {}
    liste: dict[str, list[str]] = {}
    sayac: dict[str, int] = {}
    govdeler = [agac.body] + [d.body for d in agac.body if isinstance(d, ast.ClassDef)]
    for govde in govdeler:
        for d in govde:
            hedefler: list[ast.AST] = []
            deger = None
            if isinstance(d, ast.Assign):
                hedefler, deger = d.targets, d.value
            elif isinstance(d, ast.AnnAssign) and d.value is not None:
                hedefler, deger = [d.target], d.value
            for h in hedefler:
                if not isinstance(h, ast.Name):
                    continue
                sayac[h.id] = sayac.get(h.id, 0) + 1
                s = _sabit_dizgi(deger) if deger is not None else None
                if s is not None:
                    dizgi[h.id] = s
                elif isinstance(deger, (ast.List, ast.Tuple, ast.Set)):
                    ogeler = [_sabit_dizgi(e) for e in deger.elts]
                    if ogeler and all(o is not None for o in ogeler):
                        liste[h.id] = ogeler  # type: ignore[assignment]
    tek = {k for k, v in sayac.items() if v == 1}
    return ({k: v for k, v in dizgi.items() if k in tek},
            {k: v for k, v in liste.items() if k in tek})


def _sablon(dugum: ast.AST, dizgi: dict[str, str], liste: dict[str, list[str]],
            kacissiz: list[str]) -> str | None:
    """Kalıp ifadesini şablona çevirir; yerleştirilen parça ``Q``. Çözülemezse None."""
    s = _sabit_dizgi(dugum)
    if s is not None:
        return s
    if isinstance(dugum, ast.Name) and dugum.id in dizgi:
        return dizgi[dugum.id]
    if isinstance(dugum, ast.BinOp) and isinstance(dugum.op, ast.Add):
        a = _sablon(dugum.left, dizgi, liste, kacissiz)
        b = _sablon(dugum.right, dizgi, liste, kacissiz)
        if a is None or b is None:
            return None
        return a + b
    if _re_escape_mi(dugum):
        return YER_TUTUCU
    if isinstance(dugum, ast.JoinedStr):
        parcalar = []
        for v in dugum.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parcalar.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                ic = v.value
                if _re_escape_mi(ic):
                    parcalar.append(YER_TUTUCU)
                else:
                    alt = _sablon(ic, dizgi, liste, [])
                    if alt is not None and not isinstance(ic, ast.Name):
                        parcalar.append(alt)
                    elif isinstance(ic, ast.Name) and ic.id in dizgi:
                        parcalar.append(dizgi[ic.id])
                    else:
                        kacissiz.append(ast.unparse(ic))
                        parcalar.append(YER_TUTUCU)
            else:
                return None
        return "".join(parcalar)
    if isinstance(dugum, ast.Call) and isinstance(dugum.func, ast.Attribute):
        taban = _sabit_dizgi(dugum.func.value)
        if taban is not None and dugum.func.attr == "join" and len(dugum.args) == 1:
            arg = dugum.args[0]
            if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                ogeler = []
                for e in arg.elts:
                    t = _sablon(e, dizgi, liste, kacissiz)
                    if t is None:
                        kacissiz.append(ast.unparse(e))
                        t = YER_TUTUCU
                    ogeler.append(t)
                return taban.join(ogeler)
            if isinstance(arg, ast.Name) and arg.id in liste:
                return taban.join(liste[arg.id])
            if isinstance(arg, (ast.GeneratorExp, ast.ListComp)):
                if not _re_escape_mi(arg.elt):
                    kacissiz.append(ast.unparse(arg))
                return taban.join([YER_TUTUCU, YER_TUTUCU])
            kacissiz.append(ast.unparse(arg))
            return taban.join([YER_TUTUCU, YER_TUTUCU])
        if taban is not None and dugum.func.attr == "format":
            for a in list(dugum.args) + [k.value for k in dugum.keywords]:
                if not _re_escape_mi(a) and _sabit_dizgi(a) is None:
                    kacissiz.append(ast.unparse(a))
            return re.sub(r"\{[^{}]*\}", YER_TUTUCU, taban.replace("{{", "\x01").replace("}}", "\x02")) \
                .replace("\x01", "{").replace("\x02", "}")
    if isinstance(dugum, ast.BinOp) and isinstance(dugum.op, ast.Mod):
        taban = _sabit_dizgi(dugum.left)
        if taban is not None:
            sag = dugum.right.elts if isinstance(dugum.right, ast.Tuple) else [dugum.right]
            for a in sag:
                if not _re_escape_mi(a) and _sabit_dizgi(a) is None:
                    kacissiz.append(ast.unparse(a))
            return re.sub(r"%[sdr]", YER_TUTUCU, taban.replace("%%", "\x01")).replace("\x01", "%")
    return None


def kaliplari_topla(yollar: list[Path], sablonlar: bool = False) -> tuple[list[dict], int]:
    """Kalıpları toplar.

    ``sablonlar=False`` (BA-1 davranışı): yalnız ``sabit`` kalıplar döner,
    öbürleri ikinci değerde sayılır. ``sablonlar=True``: her çağrı döner
    (``tur``: sabit / ad / sablon / taranamadi; ``kacissiz``: ``re.escape``'ten
    geçmeyen yerleştirmeler).
    """
    kaliplar: list[dict] = []
    dinamik = 0
    for yol in yollar:
        dosyalar = sorted(yol.rglob("*.py")) if yol.is_dir() else [yol]
        for f in dosyalar:
            try:
                agac = ast.parse(f.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            dizgi, liste = _modul_sabitleri(agac) if sablonlar else ({}, {})
            for d in ast.walk(agac):
                if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                        and isinstance(d.func.value, ast.Name) and d.func.value.id == "re"
                        and d.func.attr in RE_ISLEVLERI and d.args):
                    continue
                kalip = _sabit_dizgi(d.args[0])
                tur = "sabit"
                kacissiz: list[str] = []
                if kalip is None:
                    dinamik += 1
                    if not sablonlar:
                        continue
                    kalip = _sablon(d.args[0], dizgi, liste, kacissiz)
                    if kalip is None:
                        tur = "taranamadi"
                    elif isinstance(d.args[0], ast.Name):
                        tur = "ad"
                    else:
                        tur = "sablon"
                bayrak_d = None
                for kw in d.keywords:
                    if kw.arg == "flags":
                        bayrak_d = kw.value
                if bayrak_d is None:
                    konum = {"compile": 1, "search": 2, "match": 2, "fullmatch": 2,
                             "findall": 2, "finditer": 2, "split": 3, "sub": 4, "subn": 4}
                    k = konum[d.func.attr]
                    if len(d.args) > k:
                        bayrak_d = d.args[k]
                bayrak = _bayrak(bayrak_d)
                kayit = {
                    "dosya": str(f.relative_to(KOK)) if f.is_relative_to(KOK) else str(f),
                    "satir": d.lineno, "islev": d.func.attr, "kalip": kalip,
                    "bayrak": bayrak if bayrak is not None else 0,
                }
                if sablonlar:
                    kayit["tur"] = tur
                    kayit["kacissiz"] = kacissiz
                    if tur == "taranamadi":
                        kayit["ifade"] = ast.unparse(d.args[0])[:200]
                kaliplar.append(kayit)
    return kaliplar, dinamik


# ---------------------------------------------------------------------------
# 2. Durağan sınıflama
# ---------------------------------------------------------------------------

def _sinirsiz(hi: int) -> bool:
    return hi == C.MAXREPEAT or hi > 50


def _ilk_kume(dugumler, bayrak: int) -> set[str]:
    """Dizinin başlayabileceği karakterler (ALFABE içinde, yaklaşık)."""
    kume: set[str] = set()
    for op, av in dugumler:
        k, bos_olabilir = _dugum_ilk(op, av, bayrak)
        kume |= k
        if not bos_olabilir:
            return kume
    return kume


def _tum_kume(dugumler, bayrak: int) -> set[str]:
    """Dizinin tüketebileceği karakterler (yaklaşık; her düğümün ilk kümesi)."""
    kume: set[str] = set()
    for op, av in dugumler:
        if op == C.SUBPATTERN:
            kume |= _tum_kume(av[-1], bayrak)
        elif op == C.ATOMIC_GROUP:
            kume |= _tum_kume(av, bayrak)
        elif op == C.BRANCH:
            for alt in av[1]:
                kume |= _tum_kume(alt, bayrak)
        elif op in TEKRAR or op == C.POSSESSIVE_REPEAT:
            kume |= _tum_kume(av[2], bayrak)
        elif op in (C.AT, C.ASSERT, C.ASSERT_NOT):
            continue
        else:
            kume |= _dugum_ilk(op, av, bayrak)[0]
    return kume


def _bos_olabilir(dugumler, bayrak: int) -> bool:
    return all(_dugum_ilk(op, av, bayrak)[1] for op, av in dugumler)


_IN_ONBELLEK: dict[tuple[str, int], frozenset[str]] = {}


def _dugum_ilk(op, av, bayrak: int) -> tuple[set[str], bool]:
    if op == C.LITERAL:
        return {chr(av)}, False
    if op == C.NOT_LITERAL:
        return {c for c in ALFABE if c != chr(av)}, False
    if op == C.ANY:
        return {c for c in ALFABE if c != "\n" or bayrak & re.DOTALL}, False
    if op == C.IN:
        desen = _in_desen(av)
        anahtar = (desen, bayrak & re.IGNORECASE)
        if anahtar not in _IN_ONBELLEK:
            try:
                d = re.compile(desen, bayrak & re.IGNORECASE)
                _IN_ONBELLEK[anahtar] = frozenset(c for c in ALFABE if d.fullmatch(c))
            except re.error:
                _IN_ONBELLEK[anahtar] = frozenset(ALFABE)
        return set(_IN_ONBELLEK[anahtar]), False
    if op in (C.SUBPATTERN,):
        alt = av[-1]
        return _ilk_kume(alt, bayrak), _bos_olabilir(alt, bayrak)
    if op in (C.ATOMIC_GROUP,):
        return _ilk_kume(av, bayrak), _bos_olabilir(av, bayrak)
    if op == C.BRANCH:
        k: set[str] = set()
        bos = False
        for alt in av[1]:
            k |= _ilk_kume(alt, bayrak)
            bos = bos or _bos_olabilir(alt, bayrak)
        return k, bos
    if op in TEKRAR or op == C.POSSESSIVE_REPEAT:
        lo, hi, govde = av
        return _ilk_kume(govde, bayrak), lo == 0 or _bos_olabilir(govde, bayrak)
    if op in (C.AT, C.ASSERT, C.ASSERT_NOT):
        return set(), True
    if op == C.GROUPREF:
        return set(ALFABE), True
    return set(ALFABE), True


def _in_desen(av) -> str:
    """IN düğümünü tek karakterlik bir sınıf kalıbına geri yazar."""
    parcalar = []
    negate = False
    for op, a in av:
        if op == C.NEGATE:
            negate = True
        elif op == C.LITERAL:
            parcalar.append(re.escape(chr(a)))
        elif op == C.RANGE:
            parcalar.append(re.escape(chr(a[0])) + "-" + re.escape(chr(a[1])))
        elif op == C.CATEGORY:
            parcalar.append({
                C.CATEGORY_DIGIT: r"\d", C.CATEGORY_NOT_DIGIT: r"\D",
                C.CATEGORY_SPACE: r"\s", C.CATEGORY_NOT_SPACE: r"\S",
                C.CATEGORY_WORD: r"\w", C.CATEGORY_NOT_WORD: r"\W",
            }.get(a, r"\w"))
    return "[" + ("^" if negate else "") + "".join(parcalar) + "]"


def siniflandir(kalip: str, bayrak: int) -> dict:
    agac = P.parse(kalip, bayrak)
    bulgular: dict[str, list] = {"ic_ice": [], "ortusen_secenek": [], "zincir": []}

    def gez(dugumler, dis_tekrar):
        # zincir: R1 … R2 (sınırsız yinelemeler) kümeleri kesişiyor ve aradaki
        # her düğümün karakterleri R1'in kümesinde (R1 onları da yutabilir):
        # bölünme noktası belirsiz → polinom geri izleme. Zincir uzunluğu ≈ derece.
        kumeler = [_tum_kume([(op, av)], bayrak) for op, av in dugumler]
        en_uzun = 1
        for i, (op, av) in enumerate(dugumler):
            if not (op in TEKRAR and _sinirsiz(av[1])):
                continue
            uzunluk = 1
            r1 = kumeler[i]
            ara_uygun = True
            for j in range(i + 1, len(dugumler)):
                jop, jav = dugumler[j]
                if jop in TEKRAR and _sinirsiz(jav[1]) and (r1 & kumeler[j]) and ara_uygun:
                    uzunluk += 1
                    r1 = kumeler[j]
                    continue
                if not kumeler[j] <= r1:
                    ara_uygun = False
                    break
            en_uzun = max(en_uzun, uzunluk)
        if en_uzun >= 2:
            bulgular["zincir"].append(en_uzun)
        for op, av in dugumler:
            if op in (C.ATOMIC_GROUP, C.POSSESSIVE_REPEAT):
                continue  # geri izleme dışarıdan içeri giremez
            if op in TEKRAR:
                lo, hi, govde = av
                sinirsiz = _sinirsiz(hi)
                if sinirsiz and dis_tekrar is not None:
                    bulgular["ic_ice"].append((dis_tekrar, (op, av)))
                if sinirsiz:
                    # gövdede kesişen seçenekler
                    for gop, gav in govde:
                        dal = gav[-1] if gop == C.SUBPATTERN else None
                        if gop == C.BRANCH or (dal and len(dal) == 1 and dal[0][0] == C.BRANCH):
                            seç = gav[1] if gop == C.BRANCH else dal[0][1][1]
                            kumeler = [_ilk_kume(s, bayrak) for s in seç]
                            for i in range(len(kumeler)):
                                for j in range(i + 1, len(kumeler)):
                                    ortak = kumeler[i] & kumeler[j]
                                    if ortak:
                                        bulgular["ortusen_secenek"].append(((op, av), ortak))
                gez(govde, (op, av) if sinirsiz else dis_tekrar)
            elif op == C.SUBPATTERN:
                gez(av[-1], dis_tekrar)
            elif op == C.BRANCH:
                for alt in av[1]:
                    gez(alt, dis_tekrar)
            elif op in (C.ASSERT, C.ASSERT_NOT):
                gez(av[1], dis_tekrar)

    gez(agac, None)
    return {"agac": agac, **bulgular}


# ---------------------------------------------------------------------------
# 3. Düşmanca girdi
# ---------------------------------------------------------------------------

def _sec(kume: set[str]) -> str:
    for c in TERCIH:
        if c in kume:
            return c
    return sorted(kume)[0] if kume else "a"


def tanik(dugumler, bayrak: int) -> str:
    """Diziyle eşleşen kısa bir dizgi (yaklaşık; ileri bakışlar yok sayılır)."""
    out = []
    for op, av in dugumler:
        if op == C.LITERAL:
            out.append(chr(av))
        elif op in (C.NOT_LITERAL, C.ANY, C.IN):
            out.append(_sec(_dugum_ilk(op, av, bayrak)[0]))
        elif op == C.SUBPATTERN:
            out.append(tanik(av[-1], bayrak))
        elif op == C.ATOMIC_GROUP:
            out.append(tanik(av, bayrak))
        elif op == C.BRANCH:
            out.append(tanik(av[1][0], bayrak))
        elif op in TEKRAR or op == C.POSSESSIVE_REPEAT:
            lo, hi, govde = av
            out.append(tanik(govde, bayrak) * max(lo, 0))
    return "".join(out)


def _icerir(dugumler, hedef) -> bool:
    for op, av in dugumler:
        if (op, av) is hedef or (op in TEKRAR and av is hedef[1]):
            return True
        if op == C.SUBPATTERN and _icerir(av[-1], hedef):
            return True
        if op == C.ATOMIC_GROUP and _icerir(av, hedef):
            return True
        if op == C.BRANCH and any(_icerir(a, hedef) for a in av[1]):
            return True
        if op in TEKRAR and _icerir(av[2], hedef):
            return True
    return False


def onek(dugumler, hedef, bayrak: int) -> str:
    for i, (op, av) in enumerate(dugumler):
        if op in TEKRAR and av is hedef[1]:
            return tanik(dugumler[:i], bayrak)
        if _icerir([(op, av)], hedef):
            bas = tanik(dugumler[:i], bayrak)
            if op == C.SUBPATTERN:
                return bas + onek(av[-1], hedef, bayrak)
            if op == C.ATOMIC_GROUP:
                return bas + onek(av, hedef, bayrak)
            if op == C.BRANCH:
                for a in av[1]:
                    if _icerir(a, hedef):
                        return bas + onek(a, hedef, bayrak)
            if op in TEKRAR:
                return bas + onek(av[2], hedef, bayrak)
    return ""


def _pompalar(sinif: dict, bayrak: int) -> list[tuple[str, tuple]]:
    """(pompa, dış_yineleme) adayları."""
    out: list[tuple[str, tuple]] = []
    for dis, ic in sinif["ic_ice"]:
        govde = dis[1][2]
        for p in sorted({tanik(govde, bayrak), _sec(_ilk_kume(ic[1][2], bayrak))}):
            if p:
                out.append((p, dis))
    for dis, ortak in sinif["ortusen_secenek"]:
        out.append((_sec(ortak), dis))
    goruldu = set()
    tekil = []
    for p, d in out:
        anahtar = (p, id(d[1]))
        if anahtar not in goruldu:
            goruldu.add(anahtar)
            tekil.append((p, d))
    return tekil[:6]


def denemeler(kalip: str, bayrak: int, sinif: dict) -> list[dict]:
    """Adayın (önek, pompa) çiftleri; sonek ve ölçüm çocuk süreçte."""
    return [{"onek": onek(sinif["agac"], dis, bayrak), "pompa": p}
            for p, dis in _pompalar(sinif, bayrak)]


# ---------------------------------------------------------------------------
# 3b. Ayrı süreçte ölçüm
# ---------------------------------------------------------------------------

_COCUK = r"""
import json, re, sys, time
g = json.loads(sys.stdin.read())
k = re.compile(g["k"], g["b"])
t0 = time.perf_counter()
m = getattr(k, g["i"])(g["m"])
print(json.dumps({"s": time.perf_counter() - t0}))
"""


def olc(kalip: str, bayrak: int, metin: str, islev: str = "search",
        zaman_asimi: float = ZAMAN_ASIMI) -> float | None:
    """Tek ölçüm, ayrı süreçte. Zaman aşımında None, çocuk hatasında -1."""
    try:
        cp = subprocess.run([sys.executable, "-I", "-c", _COCUK],
                            input=json.dumps({"k": kalip, "b": bayrak, "m": metin, "i": islev}),
                            capture_output=True, text=True, timeout=zaman_asimi)
    except subprocess.TimeoutExpired:
        return None
    if cp.returncode != 0:
        return -1.0
    return json.loads(cp.stdout)["s"]


_ARA_COCUK = r"""
import json, re, sys, time
girdi = json.loads(sys.stdin.read())
kalip = re.compile(girdi["kalip"], girdi.get("bayrak", 0))
metinler = girdi["metinler"]
t0 = time.perf_counter()
sonuc = []
for metin in metinler:
    m = kalip.search(metin)
    sonuc.append(None if m is None else [m.start(), m.end(), list(m.groups())])
sure = time.perf_counter() - t0
print(json.dumps({"sure": sure, "sonuc": sonuc}))
"""


def ayri_surecte_ara(kalip: str, metinler: list[str], zaman_asimi: float,
                     bayrak: int = 0) -> dict:
    """Kalıbı ayrı süreçte metinlerde arar (BA-1 ``kalip_sure.py``'den taşındı).

    Dönüş: ``{"sure": sn, "sonuc": [...], "zaman_asimi": False, "duvar": sn}``
    ya da süre dolduysa ``{"sure": None, "sonuc": None, "zaman_asimi": True,
    "duvar": sn}``.
    """
    veri = json.dumps({"kalip": kalip, "bayrak": bayrak, "metinler": metinler})
    t0 = time.perf_counter()
    try:
        cp = subprocess.run([sys.executable, "-I", "-c", _ARA_COCUK], input=veri,
                            capture_output=True, text=True, timeout=zaman_asimi)
    except subprocess.TimeoutExpired:
        # subprocess.run süre dolunca çocuğu kill() (SIGKILL) ile öldürür.
        return {"sure": None, "sonuc": None, "zaman_asimi": True,
                "duvar": round(time.perf_counter() - t0, 3)}
    if cp.returncode != 0:
        raise RuntimeError(f"çocuk süreç hatası: {cp.stderr[-2000:]}")
    out = json.loads(cp.stdout)
    out["zaman_asimi"] = False
    out["duvar"] = round(time.perf_counter() - t0, 3)
    return out


_TOPLU_COCUK = r"""
import json, re, sys, time
SONEKLER = json.loads(sys.argv[3])
g = json.load(open(sys.argv[1], encoding="utf-8"))
out = open(sys.argv[2], "w", encoding="utf-8")
def yaz(d):
    out.write(json.dumps(d) + "\n"); out.flush()
for a in g["adaylar"]:
    try:
        k = re.compile(a["kalip"], a["bayrak"])
    except re.error:
        yaz({"id": a["id"], "son": {"ustel": False, "hata": "derlenemedi"}})
        continue
    en_kotu = {"ustel": False}
    for d in a["denemeler"]:
        bas, pompa = d["onek"], d["pompa"]
        sonek = None
        for s in SONEKLER:
            m = bas + pompa * 6 + s
            yaz({"id": a["id"], "basla": [pompa, bas, s, 6]})
            if k.fullmatch(m) is None and k.search(m) is None:
                sonek = s
                break
        if sonek is None:
            continue
        sureler = []
        ustel = False
        kisa = None
        for n in range(8, 33, 4):
            metin = bas + pompa * n + sonek
            yaz({"id": a["id"], "basla": [pompa, bas, sonek, n]})
            t0 = time.perf_counter(); k.search(metin); s = time.perf_counter() - t0
            sureler.append([n, round(s, 6)])
            if s >= 1.0:
                ustel = True
                kisa = {"n": n, "uzunluk": len(metin), "metin": metin, "sure_sn": round(s, 3)}
                break
            if len(sureler) >= 2 and sureler[-2][1] and s >= 0.01 \
                    and s / max(sureler[-2][1], 1e-9) >= 8:
                ustel = True
                if not g["en_kisa"]:
                    break
        if ustel and kisa is None and g["en_kisa"]:
            n = sureler[-1][0]
            while n < 64:
                n += 2
                metin = bas + pompa * n + sonek
                yaz({"id": a["id"], "basla": [pompa, bas, sonek, n]})
                t0 = time.perf_counter(); k.search(metin); s = time.perf_counter() - t0
                if s >= 1.0:
                    kisa = {"n": n, "uzunluk": len(metin), "metin": metin, "sure_sn": round(s, 3)}
                    break
        sonuc = {"ustel": ustel, "pompa": pompa, "onek": bas, "sonek": sonek,
                 "sureler": sureler, "en_kisa": kisa}
        if ustel:
            en_kotu = sonuc
            break
        if not en_kotu.get("sureler"):
            en_kotu = sonuc
    yaz({"id": a["id"], "son": en_kotu})
"""


def toplu_dogrula(adaylar: list[dict], zaman_asimi: float = 2.0,
                  en_kisa: bool = False) -> dict[int, dict]:
    """Adayları tek bir çocuk süreçte doğrular; bekçi takılan adayı üstel sayar.

    ``adaylar``: ``[{"id", "kalip", "bayrak", "denemeler"}]``. Dönüş: id →
    doğrulama sonucu (``ustel``, ``pompa``, ``onek``, ``sonek``, ``sureler``,
    ``en_kisa``; zaman aşımında ``zaman_asimi``: [pompa, önek, sonek, n]).
    ``en_kisa``: üstel bulununca süresi ≥ 1 sn olan en küçük girdiyi de ara
    (rapor için; kapı aramaz).
    """
    sonuc: dict[int, dict] = {}
    kalan = list(adaylar)
    with tempfile.TemporaryDirectory(prefix="kalip_denetimi_") as td:
        tur = 0
        while kalan:
            tur += 1
            gd = Path(td) / f"g{tur}.json"
            od = Path(td) / f"c{tur}.jsonl"
            gd.write_text(json.dumps({"adaylar": kalan, "en_kisa": en_kisa}), encoding="utf-8")
            p = subprocess.Popen([sys.executable, "-I", "-c", _TOPLU_COCUK, str(gd), str(od),
                                  json.dumps(SONEKLER)])
            son_boyut, son_degisim, olduruldu = -1, time.monotonic(), False
            while p.poll() is None:
                time.sleep(0.02)
                boyut = od.stat().st_size if od.exists() else 0
                if boyut != son_boyut:
                    son_boyut, son_degisim = boyut, time.monotonic()
                elif time.monotonic() - son_degisim > zaman_asimi:
                    p.kill()  # SIGKILL: C düzeyindeki eşleşme SIGTERM'e yanıt vermez
                    p.wait()
                    olduruldu = True
                    break
            satirlar = [json.loads(s) for s in od.read_text(encoding="utf-8").splitlines()
                        if s.strip()] if od.exists() else []
            # Yarım yazılmış son satır json hatası verirse yukarıda düşer; satırlar flush'lı.
            biten = set()
            son_basla = None
            for s in satirlar:
                if "son" in s:
                    sonuc[s["id"]] = s["son"]
                    biten.add(s["id"])
                else:
                    son_basla = s
            if olduruldu:
                if son_basla is None or son_basla["id"] in biten:
                    raise RuntimeError("bekçi: takılan aday belirlenemedi")
                tid = son_basla["id"]
                pompa, bas, sonek, n = son_basla["basla"]
                sonuc[tid] = {"ustel": True, "pompa": pompa, "onek": bas, "sonek": sonek,
                              "zaman_asimi": [pompa, bas, sonek, n],
                              "en_kisa": {"n": n, "uzunluk": len(bas + pompa * n + sonek),
                                          "metin": bas + pompa * n + sonek, "sure_sn": None}}
                biten.add(tid)
            elif p.returncode != 0:
                raise RuntimeError(f"çocuk süreç çıkışı {p.returncode}")
            kalan = [a for a in kalan if a["id"] not in biten]
    return sonuc


def dogrula(kalip: str, bayrak: int, sinif: dict) -> dict:
    """Tek aday için devingen üstellik denemesi (BA-1 arayüzü; bekçili çocuk süreçte)."""
    a = {"id": 0, "kalip": kalip, "bayrak": bayrak, "denemeler": denemeler(kalip, bayrak, sinif)}
    return toplu_dogrula([a], zaman_asimi=ZAMAN_ASIMI, en_kisa=True)[0]


# ---------------------------------------------------------------------------
# 4. Kapı
# ---------------------------------------------------------------------------

def _istisna_mi(kayit: dict, istisnalar: list[dict]) -> bool:
    return any(i["dosya"] == kayit["dosya"] and i["kalip"] == kayit["kalip"] for i in istisnalar)


def denetle(kaliplar: list[dict], istisnalar: list[dict] | None = None,
            zaman_asimi: float = 2.0, en_kisa: bool = False) -> dict:
    """Kalıp kayıtlarını (``dosya``, ``satir``, ``kalip``, ``bayrak``) sınıflar ve doğrular.

    Dönüş: ``{"toplam", "derlenemeyen", "aday", "zincir", "ustel": [...],
    "istisna_ile_gecen": [...], "adaylar": [...], "zincirler": [...]}``.
    """
    istisnalar = ISTISNALAR if istisnalar is None else istisnalar
    rapor: dict = {"toplam": len(kaliplar), "derlenemeyen": 0, "aday_ic_ice": 0,
                   "aday_ortusen": 0, "zincir": 0, "ustel": [], "istisna_ile_gecen": [],
                   "adaylar": [], "zincirler": []}
    bekleyen: list[dict] = []
    kayitlar: dict[int, dict] = {}
    for i, k in enumerate(kaliplar):
        try:
            sinif = siniflandir(k["kalip"], k["bayrak"])
        except (re.error, RecursionError, OverflowError):
            rapor["derlenemeyen"] += 1
            continue
        etiket = f"{k['dosya']}:{k['satir']}"
        if sinif["zincir"]:
            rapor["zincir"] += 1
            rapor["zincirler"].append({"yer": etiket, "kalip": k["kalip"],
                                       "sinirsiz_yineleme": max(sinif["zincir"])})
        if not (sinif["ic_ice"] or sinif["ortusen_secenek"]):
            continue
        rapor["aday_ic_ice"] += bool(sinif["ic_ice"])
        rapor["aday_ortusen"] += bool(sinif["ortusen_secenek"])
        kayitlar[i] = {"yer": etiket, "dosya": k["dosya"], "kalip": k["kalip"],
                       "bayrak": k["bayrak"], "ic_ice": bool(sinif["ic_ice"]),
                       "ortusen": bool(sinif["ortusen_secenek"])}
        bekleyen.append({"id": i, "kalip": k["kalip"], "bayrak": k["bayrak"],
                         "denemeler": denemeler(k["kalip"], k["bayrak"], sinif)})
    dogrulama = toplu_dogrula(bekleyen, zaman_asimi=zaman_asimi, en_kisa=en_kisa)
    for i, satir in kayitlar.items():
        satir["dogrulama"] = dogrulama.get(i, {"ustel": False})
        rapor["adaylar"].append(satir)
        if satir["dogrulama"].get("ustel"):
            if _istisna_mi(satir, istisnalar):
                rapor["istisna_ile_gecen"].append(satir)
            else:
                rapor["ustel"].append(satir)
    rapor["ustel_sayisi"] = len(rapor["ustel"])
    return rapor


def kapi_kaliplari() -> tuple[list[dict], int]:
    """Kapının taradığı sabit kalıplar (``KAPI_YOLLARI``) ve sabit olmayan sayısı."""
    return kaliplari_topla([KOK / y for y in KAPI_YOLLARI])


# ---------------------------------------------------------------------------
# 5. Komut satırı
# ---------------------------------------------------------------------------

def _tara(args: argparse.Namespace) -> int:
    t0 = time.perf_counter()
    hepsi, dinamik = kaliplari_topla([Path(y) for y in args.yollar], sablonlar=True)
    sabit = [k for k in hepsi if k["tur"] == "sabit"]
    rapor = denetle(sabit, zaman_asimi=args.zaman_asimi, en_kisa=True)
    rapor["dinamik"] = dinamik
    # Şablonlar (sabit olmayan kalıplar): ad / sablon taranır, taranamadi sayılır.
    sablon = [k for k in hepsi if k["tur"] in ("ad", "sablon")]
    rs = denetle(sablon, zaman_asimi=args.zaman_asimi, en_kisa=True)
    rapor["sablon"] = {
        "toplam": len(hepsi) - len(sabit),
        "ad": sum(1 for k in hepsi if k["tur"] == "ad"),
        "sablon": sum(1 for k in hepsi if k["tur"] == "sablon"),
        "taranamadi": [{"yer": f"{k['dosya']}:{k['satir']}", "ifade": k.get("ifade")}
                       for k in hepsi if k["tur"] == "taranamadi"],
        "kacissiz": [{"yer": f"{k['dosya']}:{k['satir']}", "kalip": k["kalip"],
                      "parcalar": k["kacissiz"]} for k in hepsi if k.get("kacissiz")],
        "derlenemeyen": rs["derlenemeyen"], "aday_ic_ice": rs["aday_ic_ice"],
        "aday_ortusen": rs["aday_ortusen"], "zincir": rs["zincir"],
        "ustel": rs["ustel"], "adaylar": rs["adaylar"], "zincirler": rs["zincirler"],
    }
    rapor["sure_sn"] = round(time.perf_counter() - t0, 1)
    for s in rapor["adaylar"] + rs["adaylar"]:
        print(f"{'ÜSTEL ' if s['dogrulama'].get('ustel') else 'aday  '} {s['yer']}  "
              f"{s['kalip'][:90]}", flush=True)
    print(json.dumps({k: rapor[k] for k in ("toplam", "dinamik", "derlenemeyen", "aday_ic_ice",
                                           "aday_ortusen", "zincir", "ustel_sayisi", "sure_sn")},
                     ensure_ascii=False))
    print(json.dumps({k: (len(v) if isinstance(v, list) else v)
                      for k, v in rapor["sablon"].items()}, ensure_ascii=False))
    if args.json:
        Path(args.json).write_text(json.dumps(rapor, ensure_ascii=False, indent=2,
                                              default=str), encoding="utf-8")
    return 0


_GERCEK_COCUK = r"""
import json, re, sys, time
from pathlib import Path
g = json.loads(sys.stdin.read())
kaliplar = [(k["yer"], re.compile(k["kalip"], k["bayrak"])) for k in g["kaliplar"]]
# Satır (adımın satır kalıplarına verdiği birim) ve dosya (tam içerik; yalnız
# _FUNC_RE ile gövde kalıpları için anlamlı, öbürleri için üst sınır) ayrı.
en = {y: {"satir": [0.0, None], "dosya": [0.0, None]} for y, _ in kaliplar}
toplam = {y: {"satir": 0.0, "dosya": 0.0} for y, _ in kaliplar}
n_satir = 0
n_dosya = 0
for ws in g["ws"]:
    for f in sorted((Path(ws) / "reconstructed" / "commented").rglob("*.c")):
        icerik = f.read_text(encoding="utf-8", errors="replace")
        birimler = [("satir", f"{f.name}:{i}", s.strip()) for i, s in enumerate(icerik.splitlines(), 1)]
        birimler.append(("dosya", f"{f.name}", icerik))
        n_satir += len(birimler) - 1
        n_dosya += 1
        for yer, k in kaliplar:
            e = en[yer]
            t = toplam[yer]
            for tur, konum, metin in birimler:
                t0 = time.perf_counter()
                k.search(metin)
                s = time.perf_counter() - t0
                t[tur] += s
                if s > e[tur][0]:
                    e[tur] = [s, f"{Path(ws).parent.name}/{konum}"]
print(json.dumps({"satir": n_satir, "dosya": n_dosya, "en_kotu": en, "toplam": toplam}))
"""


def _gercek(args: argparse.Namespace) -> int:
    kaliplar, _ = kaliplari_topla([Path(args.modul)])
    secilen = [{"yer": f"{k['dosya']}:{k['satir']}", "kalip": k["kalip"], "bayrak": k["bayrak"]}
               for k in kaliplar]
    try:
        cp = subprocess.run([sys.executable, "-I", "-c", _GERCEK_COCUK],
                            input=json.dumps({"kaliplar": secilen, "ws": args.ws}),
                            capture_output=True, text=True, timeout=args.zaman_asimi)
    except subprocess.TimeoutExpired:
        print("ZAMAN AŞIMI")
        return 124
    if cp.returncode != 0:
        sys.stderr.write(cp.stderr[-3000:])
        return cp.returncode
    out = json.loads(cp.stdout)
    sirali = sorted(out["en_kotu"].items(), key=lambda kv: -kv[1]["satir"][0])
    print(f"{out['satir']} satır, {out['dosya']} dosya")
    for yer, e in sirali:
        print(f"satır {e['satir'][0]*1000:9.3f} ms ({e['satir'][1]})  "
              f"dosya {e['dosya'][0]*1000:9.3f} ms ({e['dosya'][1]})  {yer}  "
              f"toplam satır {out['toplam'][yer]['satir']:.2f} sn")
    if args.json:
        Path(args.json).write_text(json.dumps({"satir": out["satir"], "dosya": out["dosya"],
                                               "sirali": sirali, "toplam": out["toplam"]},
                                              ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    alt = ap.add_subparsers(dest="komut", required=True)
    t = alt.add_parser("tara")
    t.add_argument("yollar", nargs="+")
    t.add_argument("--json")
    t.add_argument("--zaman-asimi", type=float, default=ZAMAN_ASIMI)
    g = alt.add_parser("gercek")
    g.add_argument("--modul", default="karadul/reconstruction/engineering/block_annotator.py")
    g.add_argument("--ws", action="append", required=True)
    g.add_argument("--zaman-asimi", type=float, default=900.0)
    g.add_argument("--json")
    args = ap.parse_args(argv)
    return _tara(args) if args.komut == "tara" else _gercek(args)


if __name__ == "__main__":
    sys.exit(main())
