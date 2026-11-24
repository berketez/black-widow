#!/usr/bin/env python3
"""HZ-4a: döküm adımlarının (çağrı grafiği, xref, CFG) profili ve tek geçiş kıyası.

Ürün kodunu DEĞİŞTİRMEZ. İkiliyi ürünle aynı yoldan açar (``pyghidra.open_program`` +
``GhidraHeadless._run_auto_analysis``; kapatılan çözümleyiciler ``--config`` YAML'ından), sonra
decompile / BSim koşmadan yalnız üç döküm işlevini çağırır.

Kipler:

``profil``
    (a) Sayılar: fonksiyon, gövde adresi, başvurusu olan gövde adresi
        (``getReferenceSourceIterator``), yineleyicinin artan sırada olup olmadığı
        (``Address.compareTo``), örneklemde "başvurusu olan adres kümesi" eski yürüyüşle aynı mı.
    (b) Vekil nesneyle sayım: ürünün üç işlevi bir sayaç vekili üstünden koşar; her Java çağrısı
        (yöntem, yineleyici adımı, ``str()``, eşitlik) sınıf.yöntem başına sayılır ve süresi
        toplanır. Vekilin kendi yükü ölçüme dahildir (yöntem süresi vekilin içinde, ``perf_counter``
        ile, yalnız Java çağrısının çevresinde alınır).
    (c) Yalın geçiş tabanı: aynı JVM'de önemsiz bir Java çağrısının (``Address.getOffset``)
        çağrı başına süresi.
    (d) Genel simge döngüsü tek başına: eski yol (``getReferencesTo`` + ilk öğe) ↔
        ``hasReferencesTo``; simge başına hüküm farkı sayılır.
    (e) GC: her adımın çevresinde ``GarbageCollectorMXBean`` toplama süresi / sayısı farkı.
    (f) CFG'nin parçaları (blok yinelemesi, blok başına komut yineleyicisi, fonksiyon başına tek
        komut yineleyicisi, hedef kenarları) her 8. fonksiyonda yalın süreyle.

``kiyas``
    Aynı süreçte, aynı program üstünde üç işlev yeni yol → eski yol → yeni yol sırasıyla (yalın,
    vekilsiz) koşar; süreler ve GC farkı yazılır, çıktılar ``json.dumps`` metniyle karşılaştırılır
    (``_save_output`` ile aynı serileştirme). ``--yaz`` verilirse dökümler dosyaya da yazılır.

Kullanım (Ghidra kuyruğu içinden):
    python scripts/arge/hiz/hz4a_profil.py --kip profil --ikili <yol> --kok <dizin> \
        [--config <yaml>] [--cikti <json>]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any

SIMGE_ORNEKLEM_SINIRI = 0  # 0 = hepsi
KUME_ORNEKLEM_ADIMI = 25   # (a): her 25. fonksiyonda eski yürüyüşle küme kıyası
TABAN_CAGRI = 300_000      # (c)
CFG_ORNEKLEM_ADIMI = 8     # (f): her 8. fonksiyonda CFG parça denemesi


def _uptime() -> str:
    try:
        return subprocess.run(["/usr/bin/uptime"], capture_output=True, text=True).stdout.strip()
    except Exception as exc:  # pragma: no cover
        return "uptime okunamadı: %s" % exc


# --------------------------------------------------------------------------
# Sayaç vekili
# --------------------------------------------------------------------------

class _Sayac:
    def __init__(self) -> None:
        self.tablo: dict[tuple[str, str], list[float]] = {}

    def ekle(self, sinif: str, ad: str, sn: float, gecis: int = 1) -> None:
        kayit = self.tablo.get((sinif, ad))
        if kayit is None:
            kayit = self.tablo[(sinif, ad)] = [0, 0, 0.0]
        kayit[0] += 1
        kayit[1] += gecis
        kayit[2] += sn

    def ozet(self) -> dict[str, Any]:
        satirlar = [
            {"sinif": s, "yontem": a, "cagri": int(k[0]), "gecis": int(k[1]),
             "sn": round(k[2], 3), "us_cagri": round(1e6 * k[2] / k[0], 2) if k[0] else None}
            for (s, a), k in self.tablo.items()
        ]
        satirlar.sort(key=lambda r: -r["sn"])
        return {
            "toplam_cagri": sum(r["cagri"] for r in satirlar),
            "toplam_gecis": sum(r["gecis"] for r in satirlar),
            "java_cagrisi_sn": round(sum(r["sn"] for r in satirlar), 3),
            "satirlar": satirlar,
        }


_SAYAC = _Sayac()
_ARA_YAZ: Any = None
_JOBJECT: Any = None
_JARRAY: Any = None


def _sinif_adi(o: Any) -> str:
    return type(o).__name__.rsplit(".", 1)[-1]


def _ac(x: Any) -> Any:
    return x._o if isinstance(x, _Vekil) else x


def _sar(x: Any) -> Any:
    if x is None or isinstance(x, (str, bytes, bool, int, float)):
        return x
    if isinstance(x, (_JOBJECT, _JARRAY)):
        return _Vekil(x)
    return x


class _Vekil:
    __slots__ = ("_o",)

    def __init__(self, o: Any) -> None:
        object.__setattr__(self, "_o", o)

    def __getattr__(self, ad: str) -> Any:
        o = object.__getattribute__(self, "_o")
        hedef = getattr(o, ad)
        if not callable(hedef):
            return _sar(hedef)
        sinif = _sinif_adi(o)

        def cagri(*a: Any) -> Any:
            ham = [_ac(x) for x in a]
            t = time.perf_counter()
            r = hedef(*ham)
            _SAYAC.ekle(sinif, ad, time.perf_counter() - t)
            return _sar(r)

        return cagri

    def __iter__(self):
        o = self._o
        sinif = _sinif_adi(o)
        if isinstance(o, _JARRAY):
            t = time.perf_counter()
            n = len(o)
            _SAYAC.ekle(sinif, "len", time.perf_counter() - t)
            for i in range(n):
                t = time.perf_counter()
                e = o[i]
                _SAYAC.ekle(sinif, "[i]", time.perf_counter() - t)
                yield _sar(e)
            return
        t = time.perf_counter()
        it = iter(o)
        _SAYAC.ekle(sinif, "iter()", time.perf_counter() - t)
        while True:
            t = time.perf_counter()
            try:
                e = next(it)
            except StopIteration:
                _SAYAC.ekle(sinif, "hasNext(son)", time.perf_counter() - t)
                return
            _SAYAC.ekle(sinif, "hasNext+next", time.perf_counter() - t, gecis=2)
            yield _sar(e)

    def __str__(self) -> str:
        o = self._o
        t = time.perf_counter()
        s = str(o)
        _SAYAC.ekle(_sinif_adi(o), "str()", time.perf_counter() - t)
        return s

    def __eq__(self, diger: Any) -> bool:
        o = self._o
        t = time.perf_counter()
        r = o == _ac(diger)
        _SAYAC.ekle(_sinif_adi(o), "equals", time.perf_counter() - t)
        return bool(r)

    def __ne__(self, diger: Any) -> bool:
        return not self.__eq__(diger)

    def __hash__(self) -> int:
        return hash(self._o)

    def __bool__(self) -> bool:
        return True


def _vekil_modulleri() -> dict[str, Any]:
    """``_extract_cfg``'nin içeride import ettiği kurucuları sayaçlı sarmalayıcıyla değiştir."""
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    def bbm(program: Any) -> Any:
        t = time.perf_counter()
        r = BasicBlockModel(_ac(program))
        _SAYAC.ekle("BasicBlockModel", "<kurucu>", time.perf_counter() - t)
        return _sar(r)

    def ctm() -> Any:
        return _sar(ConsoleTaskMonitor())

    blok = types.ModuleType("ghidra.program.model.block")
    blok.BasicBlockModel = bbm  # type: ignore[attr-defined]
    gorev = types.ModuleType("ghidra.util.task")
    gorev.ConsoleTaskMonitor = ctm  # type: ignore[attr-defined]
    return {"ghidra.program.model.block": blok, "ghidra.util.task": gorev}


# --------------------------------------------------------------------------
# Ölçüm yardımcıları
# --------------------------------------------------------------------------

def _gc_durumu() -> dict[str, list[int]]:
    from java.lang.management import ManagementFactory

    out: dict[str, list[int]] = {}
    for b in ManagementFactory.getGarbageCollectorMXBeans():
        out[str(b.getName())] = [int(b.getCollectionCount()), int(b.getCollectionTime())]
    return out


def _gc_farki(once: dict[str, list[int]], sonra: dict[str, list[int]]) -> dict[str, Any]:
    ayrinti = {
        ad: {"sayi": sonra[ad][0] - once.get(ad, [0, 0])[0],
             "ms": sonra[ad][1] - once.get(ad, [0, 0])[1]}
        for ad in sonra
    }
    return {"toplam_ms": sum(v["ms"] for v in ayrinti.values()), "ayrinti": ayrinti}


def _olc(etiket: str, islev, *a: Any, **kw: Any) -> tuple[Any, dict[str, Any]]:
    gc0 = _gc_durumu()
    t = time.perf_counter()
    c = time.process_time()
    sonuc = islev(*a, **kw)
    sn = time.perf_counter() - t
    cpu = time.process_time() - c
    kayit = {"sn": round(sn, 3), "surec_cpu_sn": round(cpu, 3), "gc": _gc_farki(gc0, _gc_durumu())}
    print("[hz4a] %s: %.1f sn (gc %d ms)" % (etiket, sn, kayit["gc"]["toplam_ms"]), flush=True)
    return sonuc, kayit


def _sayilar(program: Any) -> dict[str, Any]:
    """(a) gövde adresi ↔ başvurusu olan adres; yineleyici sırası; örneklemde küme eşitliği."""
    fm = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()
    fonksiyon = govde = kaynak = sira_bozuk = sira_bozuk_fonk = 0
    ornek_fonk = ornek_esit = ornek_adres = 0
    cok_araliklı = 0
    i = 0
    for func in fm.getFunctions(True):
        fonksiyon += 1
        body = func.getBody()
        govde += int(body.getNumAddresses())
        if int(body.getNumAddressRanges()) > 1:
            cok_araliklı += 1
        it = ref_mgr.getReferenceSourceIterator(body, True)
        onceki = None
        liste = []
        bozuk = 0
        while it.hasNext():
            a = it.next()
            kaynak += 1
            if onceki is not None and onceki.compareTo(a) >= 0:
                bozuk += 1
            onceki = a
            liste.append(a)
        if bozuk:
            sira_bozuk += bozuk
            sira_bozuk_fonk += 1
        if i % KUME_ORNEKLEM_ADIMI == 0:
            ornek_fonk += 1
            eski = []
            ai = body.getAddresses(True)
            while ai.hasNext():
                a = ai.next()
                ornek_adres += 1
                if len(ref_mgr.getReferencesFrom(a)) > 0:
                    eski.append(str(a))
            if eski == [str(a) for a in liste]:
                ornek_esit += 1
        i += 1
    return {
        "fonksiyon": fonksiyon,
        "govde_adresi": govde,
        "basvurusu_olan_adres": kaynak,
        "oran": round(kaynak / govde, 6) if govde else None,
        "cok_aralikli_govde": cok_araliklı,
        "sira_bozuk_adim": sira_bozuk,
        "sira_bozuk_fonksiyon": sira_bozuk_fonk,
        "kume_ornek_fonksiyon": ornek_fonk,
        "kume_ornek_adres": ornek_adres,
        "kume_ornek_esit": ornek_esit,
    }


def _yalin_gecis(program: Any) -> dict[str, Any]:
    """(c) önemsiz Java çağrısı: çağrı başına süre (µs)."""
    a = program.getMinAddress()
    t = time.perf_counter()
    for _ in range(TABAN_CAGRI):
        a.getOffset()
    ilkel = time.perf_counter() - t
    fm = program.getFunctionManager()
    t = time.perf_counter()
    for _ in range(TABAN_CAGRI):
        a.getAddressSpace()
    nesne = time.perf_counter() - t
    t = time.perf_counter()
    for _ in range(TABAN_CAGRI):
        str(a)
    metin = time.perf_counter() - t
    del fm
    return {
        "cagri": TABAN_CAGRI,
        "ilkel_donuslu_us": round(1e6 * ilkel / TABAN_CAGRI, 3),
        "nesne_donuslu_us": round(1e6 * nesne / TABAN_CAGRI, 3),
        "str_us": round(1e6 * metin / TABAN_CAGRI, 3),
    }


def _simge_dongusu(program: Any) -> dict[str, Any]:
    """(d) genel simge sayımı: eski yol ↔ ``hasReferencesTo`` ve ``equals`` ↔ ``getID``."""
    from ghidra.program.model.symbol import SymbolType

    ref_mgr = program.getReferenceManager()
    disla = (int(SymbolType.FUNCTION.getID()), int(SymbolType.PARAMETER.getID()),
             int(SymbolType.LOCAL_VAR.getID()))

    def eski() -> tuple[int, int]:
        n = sayi = 0
        it = program.getSymbolTable().getAllSymbols(True)
        while it.hasNext():
            n += 1
            sym = it.next()
            st = sym.getSymbolType()
            if st != SymbolType.FUNCTION and st != SymbolType.PARAMETER and st != SymbolType.LOCAL_VAR:
                refs = ref_mgr.getReferencesTo(sym.getAddress())
                var = False
                for _ in refs:
                    var = True
                    break
                if var:
                    sayi += 1
        return n, sayi

    def yeni() -> tuple[int, int]:
        n = sayi = 0
        it = program.getSymbolTable().getAllSymbols(True)
        while it.hasNext():
            n += 1
            sym = it.next()
            if int(sym.getSymbolType().getID()) not in disla:
                if ref_mgr.hasReferencesTo(sym.getAddress()):
                    sayi += 1
        return n, sayi

    def fark() -> dict[str, int]:
        tur = huk = bakilan = 0
        it = program.getSymbolTable().getAllSymbols(True)
        while it.hasNext():
            sym = it.next()
            st = sym.getSymbolType()
            e = st != SymbolType.FUNCTION and st != SymbolType.PARAMETER and st != SymbolType.LOCAL_VAR
            y = int(st.getID()) not in disla
            if e != y:
                tur += 1
            if e:
                bakilan += 1
                var = False
                for _ in ref_mgr.getReferencesTo(sym.getAddress()):
                    var = True
                    break
                if var != bool(ref_mgr.hasReferencesTo(sym.getAddress())):
                    huk += 1
        return {"tur_suzgeci_farki": tur, "basvuru_hukmu_farki": huk, "bakilan_simge": bakilan}

    (n1, s1), k1 = _olc("simge döngüsü (eski)", eski)
    (n2, s2), k2 = _olc("simge döngüsü (hasReferencesTo + getID)", yeni)
    f, _ = _olc("simge döngüsü (fark sayımı)", fark)
    return {"simge": n1, "eski": {"sayi": s1, **k1}, "yeni": {"simge": n2, "sayi": s2, **k2},
            "fark": f}


def _cfg_parcalari(program: Any, adim: int = CFG_ORNEKLEM_ADIMI) -> dict[str, Any]:
    """(f) CFG'nin parçaları, her ``adim``'inci fonksiyonda, yalın (vekilsiz) süreyle.

    A  blok yinelemesi + blok başına adres / boyut metni
    B  blok başına ``getInstructions(blok, True)`` + komut adı (bugünkü yol)
    C  fonksiyon başına tek ``getInstructions(gövde, True)`` + komut adı + komut adresi
    D  blok başına ``getDestinations`` + hedef bloğu / akış türü (bugünkü yol)
    Ayrıca B ↔ C komut sayısı eşit mi, blok gövdenin içinde mi (``body.contains(blok)``).
    """
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    model = BasicBlockModel(program)
    fm = program.getFunctionManager()
    listing = program.getListing()
    sn = {"A": 0.0, "B": 0.0, "C": 0.0, "D": 0.0}
    say = {"fonksiyon": 0, "blok": 0, "komut_B": 0, "komut_C": 0, "kenar": 0,
           "govde_disi_blok": 0, "komut_sayisi_farkli_fonksiyon": 0, "cok_aralikli_blok": 0,
           "blok_sirasi_bozuk": 0}
    pc = time.perf_counter
    i = -1
    for func in fm.getFunctions(True):
        i += 1
        if i % adim:
            continue
        say["fonksiyon"] += 1
        body = func.getBody()
        t = pc()
        bloklar = []
        it = model.getCodeBlocksContaining(body, monitor)
        while it.hasNext():
            b = it.next()
            bloklar.append(b)
            str(b.getFirstStartAddress())
            str(b.getMaxAddress())
            int(b.getNumAddresses())
        sn["A"] += pc() - t
        say["blok"] += len(bloklar)
        t = pc()
        nb = 0
        for b in bloklar:
            ii = listing.getInstructions(b, True)
            while ii.hasNext():
                str(ii.next().getMnemonicString()).lower()
                nb += 1
        sn["B"] += pc() - t
        t = pc()
        nc = 0
        ii = listing.getInstructions(body, True)
        while ii.hasNext():
            ins = ii.next()
            str(ins.getMnemonicString()).lower()
            ins.getAddress().getOffset()
            nc += 1
        sn["C"] += pc() - t
        t = pc()
        for b in bloklar:
            d = b.getDestinations(monitor)
            while d.hasNext():
                r = d.next()
                db = r.getDestinationBlock()
                if db is None:
                    continue
                str(db.getFirstStartAddress())
                f = r.getFlowType()
                if f.isCall():
                    continue
                f.isFallthrough() or f.isConditional() or f.isUnConditional()
                say["kenar"] += 1
        sn["D"] += pc() - t
        say["komut_B"] += nb
        say["komut_C"] += nc
        if nb != nc:
            say["komut_sayisi_farkli_fonksiyon"] += 1
        onceki = None
        for b in bloklar:
            if not body.contains(b):
                say["govde_disi_blok"] += 1
            if int(b.getNumAddressRanges()) > 1:
                say["cok_aralikli_blok"] += 1
            bas = b.getFirstStartAddress()
            if onceki is not None and onceki.compareTo(bas) >= 0:
                say["blok_sirasi_bozuk"] += 1
            onceki = bas
    return {"ornekleme_adimi": adim, "sn": {k: round(v, 3) for k, v in sn.items()}, **say}


def _cfg_model_denemesi(program: Any, adim: int = CFG_ORNEKLEM_ADIMI) -> dict[str, Any]:
    """(g) Blok modeli önbelleği: program boyunca TEK ``BasicBlockModel`` (bugünkü yol; bulunan
    bloklar ``SimpleBlockModel.foundBlockMap``'te birikir) ↔ fonksiyon başına TAZE model.

    Her ``adim``'inci fonksiyonda bloklar + hedef kenarları iki yolla çıkarılır; süreler ayrı
    toplanır, (başlangıç, bitiş, boyut) ve (kaynak, hedef, akış) listeleri karşılaştırılır.
    Ortak model yalnız örneklenen fonksiyonlarda büyür (ürün koşusunda 8 kat daha çok blok
    birikir): ortak yolun süresi burada alt sınırdır.
    """
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    ortak = BasicBlockModel(program)
    fm = program.getFunctionManager()
    pc = time.perf_counter

    def cikar(model: Any, body: Any) -> tuple[list, list]:
        bloklar, kenarlar = [], []
        it = model.getCodeBlocksContaining(body, monitor)
        while it.hasNext():
            b = it.next()
            bas = str(b.getFirstStartAddress())
            bloklar.append((bas, str(b.getMaxAddress()), int(b.getNumAddresses())))
            d = b.getDestinations(monitor)
            while d.hasNext():
                r = d.next()
                db = r.getDestinationBlock()
                if db is None:
                    continue
                f = r.getFlowType()
                kenarlar.append((bas, str(db.getFirstStartAddress()), bool(f.isCall()),
                                 bool(f.isFallthrough()), bool(f.isConditional()),
                                 bool(f.isUnConditional())))
        return bloklar, kenarlar

    sn_ortak = sn_taze = sn_kurucu = 0.0
    fonk = esit = blok = 0
    ceyrek: list[float] = []  # ortak modelin süresi, örneklemin dört çeyreğinde (birikme etkisi)
    ornek = [f for i, f in enumerate(fm.getFunctions(True)) if i % adim == 0]
    for j, func in enumerate(ornek):
        body = func.getBody()
        t = pc()
        a = cikar(ortak, body)
        dt = pc() - t
        sn_ortak += dt
        q = min(3, 4 * j // max(1, len(ornek)))
        while len(ceyrek) <= q:
            ceyrek.append(0.0)
        ceyrek[q] += dt
        t = pc()
        taze = BasicBlockModel(program)
        sn_kurucu += pc() - t
        t = pc()
        b = cikar(taze, body)
        sn_taze += pc() - t
        fonk += 1
        blok += len(a[0])
        if a == b:
            esit += 1
    return {"ornekleme_adimi": adim, "fonksiyon": fonk, "blok": blok, "esit_fonksiyon": esit,
            "ortak_model_sn": round(sn_ortak, 3), "taze_model_sn": round(sn_taze, 3),
            "taze_kurucu_sn": round(sn_kurucu, 3),
            "ortak_model_ceyrek_sn": [round(x, 3) for x in ceyrek]}


def _metin(veri: Any) -> str:
    return json.dumps(veri, indent=2, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------
# Kipler
# --------------------------------------------------------------------------

def _guvenli(out: dict[str, Any], ad: str, islev, *a: Any) -> None:
    """Bir bölüm düşerse öbürleri koşsun; hata metni çıktıya yazılır, ara sonuç diske."""
    import traceback

    try:
        out[ad], out[ad + "_olcum"] = _olc(ad, islev, *a)
    except Exception as exc:
        out[ad + "_hata"] = "%s: %s\n%s" % (type(exc).__name__, exc, traceback.format_exc())
        print("[hz4a] %s DÜŞTÜ: %s" % (ad, exc), flush=True)
    if _ARA_YAZ is not None:
        _ARA_YAZ(out)


def _profil(GH: Any, program: Any, out: dict[str, Any]) -> dict[str, Any]:
    global _SAYAC
    _guvenli(out, "yalin_gecis_once", _yalin_gecis, program)
    _guvenli(out, "sayilar", _sayilar, program)
    _guvenli(out, "simge_dongusu", _simge_dongusu, program)
    _guvenli(out, "cfg_parcalari", _cfg_parcalari, program)
    _guvenli(out, "cfg_model_denemesi", _cfg_model_denemesi, program)

    vekil = _Vekil(program)
    gercek = {ad: sys.modules.get(ad) for ad in ("ghidra.program.model.block", "ghidra.util.task")}
    adimlar: dict[str, Any] = {}
    for ad, islev, shim in (
        ("call_graph", GH._extract_call_graph, False),
        ("xref", GH._extract_xrefs, False),
        ("cfg", GH._extract_cfg, True),
    ):
        _SAYAC = _Sayac()
        if shim:
            sys.modules.update(_vekil_modulleri())
        try:
            _, kayit = _olc("vekilli " + ad, islev, vekil)
        except Exception as exc:
            import traceback
            adimlar[ad] = {"hata": "%s: %s\n%s" % (type(exc).__name__, exc,
                                                    traceback.format_exc()),
                           "sayac": _SAYAC.ozet()}
            out["vekilli_adimlar"] = adimlar
            if _ARA_YAZ is not None:
                _ARA_YAZ(out)
            continue
        finally:
            if shim:
                for mad, m in gercek.items():
                    if m is not None:
                        sys.modules[mad] = m
                    else:
                        sys.modules.pop(mad, None)
        ozet = _SAYAC.ozet()
        kayit["sayac"] = ozet
        kayit["java_payi"] = round(ozet["java_cagrisi_sn"] / kayit["sn"], 4) if kayit["sn"] else None
        kayit["gc_payi"] = round(kayit["gc"]["toplam_ms"] / 1000.0 / kayit["sn"], 4) if kayit["sn"] else None
        adimlar[ad] = kayit
        out["vekilli_adimlar"] = adimlar
        if _ARA_YAZ is not None:
            _ARA_YAZ(out)
    _guvenli(out, "yalin_gecis_sonra", _yalin_gecis, program)
    return out


def _butce_denemesi(GH: Any, H: Any, program: Any, sure: dict[str, Any],
                    tam_metin: dict[str, str]) -> dict[str, Any]:
    """Yeni yolda gerçek programla bütçe kesilmesi (H5'in aynı süreçteki kolu).

    Her adım, tam koşu süresinin ~%40'ı kadar bütçeyle (ürünün denetçisi, ``_AdimDenetcisi``)
    yeniden koşar: çıktı geçerli JSON mu, ``kismi`` / ``islenen`` / ``toplam`` / ``neden`` var mı,
    ``islenen`` ≤ ``toplam`` mı, işlenen fonksiyonların kayıtları tam çıktıdakilerle aynı mı.
    """
    tam = {ad: json.loads(m) for ad, m in tam_metin.items()}
    toplam = int(tam["call_graph"]["total_functions"])
    out: dict[str, Any] = {}

    def denetci(adim: str, tam_sn: float) -> Any:
        return H._AdimDenetcisi(adim, max(0.02, 0.4 * tam_sn), 0, time.monotonic(), toplam=toplam)

    def ozet(veri: dict[str, Any], d: Any, islenen_kayit: bool) -> dict[str, Any]:
        json.loads(json.dumps(veri, default=str))
        return {"kesildi": bool(d.doldu), "kismi": veri.get("kismi"),
                "islenen": veri.get("islenen"), "toplam": veri.get("toplam"),
                "neden": veri.get("neden"), "butce_sn": round(d.butce_sn, 3),
                "islenen_toplamdan_kucuk_esit": (veri.get("islenen") is None
                                                 or veri["islenen"] <= veri["toplam"]),
                "islenen_kayitlar_tamla_ayni": islenen_kayit}

    d = denetci("ghidra.call_graph", sure["call_graph"]["sn"])
    t = H._BasvuruTablosu(program)
    v = GH._extract_call_graph(program, denetci=d, tablo=t)
    ayni = all(tam["call_graph"]["nodes"].get(a) == n for a, n in v["nodes"].items())
    out["call_graph"] = ozet(v, d, ayni and len(v["nodes"]) == (v.get("islenen") or toplam))

    d = denetci("ghidra.xref", sure["xref"]["sn"])
    v = GH._extract_xrefs(program, denetci=d, tablo=H._BasvuruTablosu(program), tek_gecis=True)
    ayni = all(tam["xrefs"]["function_xrefs"].get(a) == n
               for a, n in v["function_xrefs"].items())
    out["xref"] = ozet(v, d, ayni and (len(v["function_xrefs"]) == (v.get("islenen") or toplam)))
    out["xref"]["statistics"] = v["statistics"]

    d = denetci("ghidra.cfg", sure["cfg"]["sn"])
    v = GH._extract_cfg(program, denetci=d)
    n = len(v["functions"])
    out["cfg"] = ozet(v, d, v["functions"] == tam["cfg"]["functions"][:n])
    out["cfg"]["dokulen_fonksiyon"] = n
    return out


def _kiyas(GH: Any, program: Any, yaz: Path | None) -> dict[str, Any]:
    from karadul.ghidra import headless as H

    def kos(tek: bool, etiket: str) -> tuple[dict[str, str], dict[str, Any]]:
        tablo = H._BasvuruTablosu(program) if tek else None
        sure: dict[str, Any] = {}
        cg, sure["call_graph"] = _olc(etiket + " call_graph", GH._extract_call_graph, program,
                                     tablo=tablo)
        xr, sure["xref"] = _olc(etiket + " xref", GH._extract_xrefs, program, tablo=tablo,
                                tek_gecis=tek)
        tablo = None
        cf, sure["cfg"] = _olc(etiket + " cfg", GH._extract_cfg, program)
        sure["toplam_sn"] = round(sum(sure[a]["sn"] for a in ("call_graph", "xref", "cfg")), 3)
        metin = {"call_graph": _metin(cg), "xrefs": _metin(xr), "cfg": _metin(cf)}
        return metin, sure

    out: dict[str, Any] = {}
    y1, out["yeni_1"] = kos(True, "yeni(1)")
    e, out["eski"] = kos(False, "eski")
    y2, out["yeni_2"] = kos(True, "yeni(2)")
    out["esit_yeni1_eski"] = {ad: y1[ad] == e[ad] for ad in e}
    out["esit_yeni2_eski"] = {ad: y2[ad] == e[ad] for ad in e}
    out["bayt"] = {ad: len(e[ad].encode("utf-8")) for ad in e}
    out["oran_yeni1_eski"] = round(out["yeni_1"]["toplam_sn"] / out["eski"]["toplam_sn"], 4)
    out["oran_yeni2_eski"] = round(out["yeni_2"]["toplam_sn"] / out["eski"]["toplam_sn"], 4)
    out["butce_denemesi"] = _butce_denemesi(GH, H, program, out["yeni_2"], e)
    if yaz is not None:
        yaz.mkdir(parents=True, exist_ok=True)
        for ad in e:
            (yaz / ("eski_%s.json" % ad)).write_text(e[ad], encoding="utf-8")
            if y1[ad] != e[ad]:
                (yaz / ("yeni1_%s.json" % ad)).write_text(y1[ad], encoding="utf-8")
            if y2[ad] != e[ad]:
                (yaz / ("yeni2_%s.json" % ad)).write_text(y2[ad], encoding="utf-8")
    return out


def main() -> int:
    global _JOBJECT, _JARRAY, _ARA_YAZ
    ap = argparse.ArgumentParser()
    ap.add_argument("--kip", choices=("profil", "kiyas"), required=True)
    ap.add_argument("--ikili", required=True, type=Path)
    ap.add_argument("--kok", required=True, type=Path, help="Ghidra projesi ve çıktı dizini")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--cikti", type=Path)
    ap.add_argument("--yaz", action="store_true", help="kiyas: dökümleri dosyaya da yaz")
    ap.add_argument("--analiz-siniri", type=int, default=3600)
    a = ap.parse_args()

    import karadul
    from karadul.config import Config
    from karadul.ghidra import headless as H

    cfg = Config.load(a.config) if a.config else Config()
    gh = H.GhidraHeadless(cfg)
    kurulum = Path(gh.analyze_headless).parent.parent
    a.kok.mkdir(parents=True, exist_ok=True)
    proje = a.kok / "proje"
    proje.mkdir(exist_ok=True)

    out: dict[str, Any] = {
        "kip": a.kip, "ikili": str(a.ikili), "karadul": str(Path(karadul.__file__).parent),
        "ghidra": str(kurulum), "config": str(a.config) if a.config else None,
        "pid": os.getpid(), "uptime_bas": _uptime(), "baslangic": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    hedef = a.cikti or (a.kok / ("hz4a_%s.json" % a.kip))
    hedef.parent.mkdir(parents=True, exist_ok=True)

    def ara_yaz(veri: dict[str, Any]) -> None:
        hedef.write_text(json.dumps(veri, indent=1, ensure_ascii=False, default=str),
                         encoding="utf-8")

    _ARA_YAZ = ara_yaz
    H._ensure_pyghidra_started(
        kurulum, heap_mb=getattr(getattr(cfg, "analysis", None), "ghidra_max_heap_mb", None))
    import jpype
    import pyghidra

    _JOBJECT, _JARRAY = jpype.JObject, jpype.JArray
    with pyghidra.open_program(binary_path=str(a.ikili), project_location=str(proje),
                               project_name="hz4a_" + a.kip, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        bilgi, out["otomatik_analiz_olcum"] = _olc("otomatik analiz", gh._run_auto_analysis,
                                                  program, a.analiz_siniri)
        out["otomatik_analiz"] = {k: v for k, v in bilgi.items()
                                  if k in ("status", "duration_s", "disabled_analyzers")}
        out["uptime_analiz_sonu"] = _uptime()
        if a.kip == "profil":
            _profil(H.GhidraHeadless, program, out)
        else:
            out.update(_kiyas(H.GhidraHeadless, program, a.kok / "dokum" if a.yaz else None))
    out["uptime_son"] = _uptime()
    out["bitis"] = time.strftime("%Y-%m-%d %H:%M:%S")
    ara_yaz(out)
    print("[hz4a] yazıldı: %s" % hedef, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
