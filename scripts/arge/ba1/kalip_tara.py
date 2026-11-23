"""BA-1: düzenli ifadelerde üstel / polinom geri izleme taraması (hüküm 4 ve 6b).

Yöntem
------
1. **Toplama (AST):** verilen ``.py`` dosyalarında ``re.<işlev>(<dizgi>, ...)``
   çağrıları (``compile``, ``search``, ``match``, ``fullmatch``, ``findall``,
   ``finditer``, ``sub``, ``subn``, ``split``). Kalıp dizgisi sabit ya da sabit
   dizgilerin ``+`` birleşimiyse alınır; bayraklar ``re.X`` adlarından
   hesaplanır. Sabit olmayan kalıp (f-string, değişken) "dinamik" diye sayılır.
2. **Durağan sınıflama (``re._parser`` ağacı):**
   - ``ic_ice``: atomik grup / sahiplenici niceleyici dışında, sınırsız
     yinelemenin gövdesinde sınırsız yineleme (``(a+)+``, ``(?:[^()]+|…)+``);
   - ``ortusen_secenek``: sınırsız yinelemenin gövdesinde, ilk karakter
     kümeleri kesişen iki seçenek (``(?:a|ab)+``, ``(\\w|\\d)+``);
   - ``zincir``: aynı dizide ilk karakter kümeleri kesişen en az iki sınırsız
     yineleme (``.*x.*``; polinom adayı; derece ≈ yineleme sayısı).
3. **Devingen doğrulama (ayrı süreç, zaman aşımı):** ``ic_ice`` ve
   ``ortusen_secenek`` adaylarında düşmanca girdi kurulur: önek = yinelemeye
   götüren alt kalıbın en kısa tanığı, pompa = yineleme gövdesinin tanığı ya da
   iç yinelemenin tek karakteri ya da kesişen seçeneklerin ortak karakteri,
   sonek = eşleşmeyi bozan bir karakter (``!``, satır sonu, ``(``, ``)``, ``\\x00``
   …; küçük n'de eşleşmediği denetlenir). Pompa sayısı 8, 12, 16, 20, 24 …;
   her ölçüm ayrı çocuk süreçte ``subprocess.run(timeout=…)``. **Üstel**: n ≤ 32
   içinde zaman aşımı ya da +4 pompada süre ≥ 8 kat (ve ≥ 10 ms). En kısa
   düşmanca girdi: süresi ≥ 1 sn (ya da zaman aşımı) olan en küçük n.
4. ``gercek`` alt komutu: bir modülün bütün kalıplarının gerçek satırlarda
   (çalışma alanlarının ``reconstructed/commented/*.c``) en kötü süresi.

Kullanım (worktree kökünden):

    python scripts/arge/ba1/kalip_tara.py tara --json <dosya> <yol> [<yol> ...]
    python scripts/arge/ba1/kalip_tara.py gercek --json <dosya> --ws <oturum> ...
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import time
from pathlib import Path

from re import _constants as C  # type: ignore[attr-defined]
from re import _parser as P  # type: ignore[attr-defined]

KOK = Path(__file__).resolve().parents[3]
RE_ISLEVLERI = {"compile", "search", "match", "fullmatch", "findall", "finditer",
                "sub", "subn", "split"}
ALFABE = [chr(i) for i in range(32, 127)] + ["\n", "\t", "\x00"]
TERCIH = list("a0_ ,(x;=*")
SONEKLER = ["!", "\n", "", "(", ")", "\x00", ";", " ", "{", "}", "]", "\"", "'"]
TEKRAR = (C.MAX_REPEAT, C.MIN_REPEAT)
ZAMAN_ASIMI = 5.0


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


def kaliplari_topla(yollar: list[Path]) -> tuple[list[dict], int]:
    kaliplar: list[dict] = []
    dinamik = 0
    for yol in yollar:
        dosyalar = sorted(yol.rglob("*.py")) if yol.is_dir() else [yol]
        for f in dosyalar:
            try:
                agac = ast.parse(f.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            for d in ast.walk(agac):
                if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                        and isinstance(d.func.value, ast.Name) and d.func.value.id == "re"
                        and d.func.attr in RE_ISLEVLERI and d.args):
                    continue
                kalip = _sabit_dizgi(d.args[0])
                if kalip is None:
                    dinamik += 1
                    continue
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
                kaliplar.append({
                    "dosya": str(f.relative_to(KOK)) if f.is_relative_to(KOK) else str(f),
                    "satir": d.lineno, "islev": d.func.attr, "kalip": kalip,
                    "bayrak": bayrak if bayrak is not None else 0,
                })
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


def _dugum_ilk(op, av, bayrak: int) -> tuple[set[str], bool]:
    if op == C.LITERAL:
        return {chr(av)}, False
    if op == C.NOT_LITERAL:
        return {c for c in ALFABE if c != chr(av)}, False
    if op == C.ANY:
        return {c for c in ALFABE if c != "\n" or bayrak & re.DOTALL}, False
    if op == C.IN:
        try:
            desen = re.compile(_in_desen(av), bayrak & re.IGNORECASE)
            return {c for c in ALFABE if desen.fullmatch(c)}, False
        except re.error:
            return set(ALFABE), False
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
    try:
        cp = subprocess.run([sys.executable, "-I", "-c", _COCUK],
                            input=json.dumps({"k": kalip, "b": bayrak, "m": metin, "i": islev}),
                            capture_output=True, text=True, timeout=zaman_asimi)
    except subprocess.TimeoutExpired:
        return None
    if cp.returncode != 0:
        return -1.0
    return json.loads(cp.stdout)["s"]


def _pompalar(sinif: dict, bayrak: int) -> list[tuple[str, tuple]]:
    """(pompa, dış_yineleme) adayları."""
    out: list[tuple[str, tuple]] = []
    for dis, ic in sinif["ic_ice"]:
        govde = dis[1][2]
        for p in {tanik(govde, bayrak), _sec(_ilk_kume(ic[1][2], bayrak))}:
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


def dogrula(kalip: str, bayrak: int, sinif: dict) -> dict:
    """Aday kalıp için devingen üstellik denemesi."""
    en_kotu: dict = {"ustel": False}
    for pompa, dis in _pompalar(sinif, bayrak):
        bas = onek(sinif["agac"], dis, bayrak)
        sonek = None
        for s in SONEKLER:
            deneme = bas + pompa * 6 + s
            try:
                if re.compile(kalip, bayrak).fullmatch(deneme) is None and \
                        re.compile(kalip, bayrak).search(bas + pompa * 6 + s) is None:
                    sonek = s
                    break
            except re.error:
                break
        if sonek is None:
            continue
        sureler = []
        ustel = False
        kisa = None
        for n in range(8, 33, 4):
            metin = bas + pompa * n + sonek
            s = olc(kalip, bayrak, metin)
            sureler.append([n, None if s is None else round(s, 5)])
            if s is None or s >= 1.0:
                ustel = True
                kisa = {"n": n, "uzunluk": len(metin), "metin": metin,
                        "sure_sn": None if s is None else round(s, 3)}
                break
            if len(sureler) >= 2 and sureler[-2][1] and s >= 0.01 \
                    and s / max(sureler[-2][1], 1e-9) >= 8:
                ustel = True
        if ustel and kisa is None:
            # 1 sn'yi geçen en küçük n'yi bul (2'şer artır)
            n = sureler[-1][0]
            while n < 64:
                n += 2
                metin = bas + pompa * n + sonek
                s = olc(kalip, bayrak, metin)
                if s is None or s >= 1.0:
                    kisa = {"n": n, "uzunluk": len(metin), "metin": metin,
                            "sure_sn": None if s is None else round(s, 3)}
                    break
        sonuc = {"ustel": ustel, "pompa": pompa, "onek": bas, "sonek": sonek,
                 "sureler": sureler, "en_kisa": kisa}
        if ustel:
            return sonuc
        en_kotu = sonuc if not en_kotu.get("sureler") else en_kotu
    return en_kotu


def _tara(args: argparse.Namespace) -> int:
    kaliplar, dinamik = kaliplari_topla([Path(y) for y in args.yollar])
    rapor = {"toplam": len(kaliplar), "dinamik": dinamik, "derlenemeyen": 0,
             "aday_ic_ice": 0, "aday_ortusen": 0, "zincir": 0, "ustel": [], "adaylar": [],
             "zincirler": []}
    for k in kaliplar:
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
        d = dogrula(k["kalip"], k["bayrak"], sinif)
        satir = {"yer": etiket, "kalip": k["kalip"], "bayrak": k["bayrak"],
                 "ic_ice": bool(sinif["ic_ice"]), "ortusen": bool(sinif["ortusen_secenek"]),
                 "dogrulama": d}
        rapor["adaylar"].append(satir)
        if d.get("ustel"):
            rapor["ustel"].append(satir)
        print(f"{'ÜSTEL ' if d.get('ustel') else 'aday  '} {etiket}  {k['kalip'][:90]}",
              flush=True)
    rapor["ustel_sayisi"] = len(rapor["ustel"])
    print(json.dumps({k: rapor[k] for k in ("toplam", "dinamik", "derlenemeyen", "aday_ic_ice",
                                           "aday_ortusen", "zincir", "ustel_sayisi")},
                     ensure_ascii=False))
    if args.json:
        Path(args.json).write_text(json.dumps(rapor, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


# ---------------------------------------------------------------------------
# 4. Gerçek veride en kötü süre
# ---------------------------------------------------------------------------

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
    g = alt.add_parser("gercek")
    g.add_argument("--modul", default="karadul/reconstruction/engineering/block_annotator.py")
    g.add_argument("--ws", action="append", required=True)
    g.add_argument("--zaman-asimi", type=float, default=900.0)
    g.add_argument("--json")
    args = ap.parse_args(argv)
    return _tara(args) if args.komut == "tara" else _gercek(args)


if __name__ == "__main__":
    sys.exit(main())
