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


def _metin(veri: Any) -> str:
    return json.dumps(veri, indent=2, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------
# Kipler
# --------------------------------------------------------------------------

def _profil(GH: Any, program: Any) -> dict[str, Any]:
    global _SAYAC
    out: dict[str, Any] = {}
    out["yalin_gecis_once"] = _yalin_gecis(program)
    out["sayilar"], out["sayilar_olcum"] = _olc("sayılar", _sayilar, program)
    out["simge_dongusu"] = _simge_dongusu(program)

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
    out["yalin_gecis_sonra"] = _yalin_gecis(program)
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
        cf, sure["cfg"] = _olc(etiket + " cfg", GH._extract_cfg, program, tek_gecis=tek)
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
    global _JOBJECT, _JARRAY
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
            out.update(_profil(H.GhidraHeadless, program))
        else:
            out.update(_kiyas(H.GhidraHeadless, program, a.kok / "dokum" if a.yaz else None))
    out["uptime_son"] = _uptime()
    out["bitis"] = time.strftime("%Y-%m-%d %H:%M:%S")
    hedef = a.cikti or (a.kok / ("hz4a_%s.json" % a.kip))
    hedef.parent.mkdir(parents=True, exist_ok=True)
    hedef.write_text(json.dumps(out, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    print("[hz4a] yazıldı: %s" % hedef, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
