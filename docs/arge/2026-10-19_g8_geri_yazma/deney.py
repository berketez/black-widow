"""G8 deneyi: koşul başına geri yazma, yeniden decompile ve ölçüm.

Kullanım:  python3 -I -B deney.py C0 C1 C2 C3 C4

Her koşul taban projenin ayrı bir kopyasında koşulur (projeler/<koşul>/).
Yeniden analiz yapılmaz; programa yalnız ad (setName), prototip
(ApplyFunctionSignatureCmd) ve tip (DataTypeManager.resolve) yazılır.

Koşullar (ön kayıt §4):
  C0  taban
  C1  ad
  C2  ad + prototip; bütün struct/union tipleri içi boş yer tutucu
  C3  ad + prototip + struct window_pane (ve değerle gömdüğü yapılar) tam yerleşimle
  C4  ad + prototip + erişilebilir bütün yapılar tam
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
import olcut  # noqa: E402
import tipler  # noqa: E402

KOSULLAR = {
    "C0": {"ad": False, "prototip": False, "tam": None},
    "C1": {"ad": True, "prototip": False, "tam": None},
    "C2": {"ad": True, "prototip": True, "tam": "yok"},
    "C3": {"ad": True, "prototip": True, "tam": "kapanis"},
    "C4": {"ad": True, "prototip": True, "tam": "hepsi"},
}
YAPI = "window_pane"


ONEK = "g8__"


def prototip_metni(hedefler: list[dict]) -> str:
    """Kaynaktaki tanım imzaları, ad önekiyle. tmux.h aynı fonksiyonları parametre
    adı OLMADAN bildirir ve ayrıştırıcı ilk bildirimi tutar; önek, parametre adlarını
    taşıyan tanım imzasının ayrı bir FunctionDefinition olarak ayrıştırılmasını sağlar.
    Uygulamadan önce ad gerçek ada çevrilir."""
    satirlar = ["", "/* G8: hedef fonksiyonların kaynaktaki tanım imzaları */"]
    for h in hedefler:
        satirlar.append(f"{h['donus']} {ONEK}{h['ad']}({h['parametreler']});")
    return "\n".join(satirlar) + "\n"


def erisilebilir_bilesikler(kokler: list) -> dict:
    """Köklerden (fonksiyon tanımları) işaretçi, dizi, typedef ve bileşen üzerinden
    erişilebilen bütün struct/union tipleri: {yol: tip}."""
    from ghidra.program.model.data import (Composite, Pointer, Array, TypeDef,  # type: ignore
                                           FunctionDefinition)
    gorulen: dict[str, object] = {}
    ziyaret: set = set()
    yigin = list(kokler)
    while yigin:
        t = yigin.pop()
        if t is None:
            continue
        anahtar = (str(t.getPathName()), t.getClass().getName())
        if anahtar in ziyaret:
            continue
        ziyaret.add(anahtar)
        if isinstance(t, Pointer):
            yigin.append(t.getDataType())
        elif isinstance(t, Array):
            yigin.append(t.getDataType())
        elif isinstance(t, TypeDef):
            yigin.append(t.getDataType())
        elif isinstance(t, FunctionDefinition):
            yigin.append(t.getReturnType())
            for a in t.getArguments():
                yigin.append(a.getDataType())
        elif isinstance(t, Composite):
            gorulen[str(t.getPathName())] = t
            for c in t.getDefinedComponents():
                yigin.append(c.getDataType())
    return gorulen


def yer_tutucu(t):
    from ghidra.program.model.data import Structure, StructureDataType, UnionDataType  # type: ignore
    if isinstance(t, Structure):
        return StructureDataType(t.getCategoryPath(), t.getName(), 0)
    return UnionDataType(t.getCategoryPath(), t.getName())


def geri_yaz(program, kosul: str, hedefler: list[dict], dtm, fdefs: dict) -> dict:
    """Koşulun gerektirdiği bilgiyi programa yazar; ne yazıldığını döndürür."""
    from ghidra.program.model.symbol import SourceType  # type: ignore
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd, FunctionRenameOption  # type: ignore
    from ghidra.program.model.data import DataTypeConflictHandler, Composite  # type: ignore
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore

    K = KOSULLAR[kosul]
    rapor: dict = {"kosul": kosul, **K}
    if not K["ad"]:
        return rapor
    t0 = time.perf_counter()
    fm = program.getFunctionManager()
    pdtm = program.getDataTypeManager()
    keep = DataTypeConflictHandler.KEEP_HANDLER
    tx = program.startTransaction(f"G8 geri yazma {kosul}")
    basarili = False
    try:
        adlar = []
        for h in hedefler:
            f = fm.getFunctionAt(ortak.adres(program, h["adres"]))
            onceki = f.getName()
            f.setName(h["ad"], SourceType.USER_DEFINED)
            adlar.append({"adres": h["adres"], "once": onceki, "sonra": f.getName()})
        rapor["ad_yazilan"] = len(adlar)

        if K["prototip"]:
            kokler = [fdefs[h["ad"]] for h in hedefler]
            erisilebilir = erisilebilir_bilesikler(kokler)
            wp = [t for t in erisilebilir.values() if t.getName() == YAPI]
            if len(wp) != 1:
                raise RuntimeError(f"{YAPI} erişilebilir kümede tek değil: {len(wp)}")
            if K["tam"] == "yok":
                tam = {}
            elif K["tam"] == "kapanis":
                tam = {str(t.getPathName()): t for t in tipler.kapanis_kumesi(wp[0])}
            else:
                tam = dict(erisilebilir)
            tutucu = {y: t for y, t in erisilebilir.items() if y not in tam}
            # Tabanda zaten bulunan tipler (analizin Ghidra'nın mac_osx.gdt arşivinden kütüphane
            # imzalarıyla getirdikleri, ör. timeval, termios) KEEP ile olduğu gibi kalır.
            onceden = {y for y in erisilebilir if pdtm.getDataType(y) is not None}
            conflict_once = sorted(str(d.getPathName()) for d in pdtm.getAllDataTypes()
                                   if ".conflict" in d.getName())
            # 1) yer tutucular önce: KEEP ile tam tiplerin işaretçi alanları bunlara bağlanır
            for t in tutucu.values():
                pdtm.resolve(yer_tutucu(t), keep)
            # 2) tam tipler
            for t in tam.values():
                pdtm.resolve(t, keep)
            # 3) prototipler
            sonuclar = []
            mon = ConsoleTaskMonitor()
            for h in hedefler:
                fd = fdefs[h["ad"]]
                fd_p = pdtm.resolve(fd, keep)
                giris = ortak.adres(program, h["adres"])
                cmd = ApplyFunctionSignatureCmd(giris, fd_p, SourceType.USER_DEFINED, True,
                                                FunctionRenameOption.NO_CHANGE)
                ok = bool(cmd.applyTo(program, mon))
                f = fm.getFunctionAt(giris)
                sonuclar.append({
                    "adres": h["adres"], "ad": h["ad"], "uygulandi": ok,
                    "hata": None if ok else str(cmd.getStatusMsg()),
                    "hedef_prototip": str(fd.getPrototypeString()),
                    "programdaki_prototip": str(f.getSignature().getPrototypeString()),
                    "imza_kaynagi": str(f.getSignatureSource()),
                })
            rapor["prototip"] = sonuclar
            rapor["prototip_uygulanan"] = sum(1 for s in sonuclar if s["uygulandi"])
            # 4) programdaki tiplerin denetimi
            denetim = {"erisilebilir": len(erisilebilir), "tam_beklenen": len(tam),
                       "yer_tutucu_beklenen": len(tutucu), "tam_bulunan": 0, "bos_bulunan": 0,
                       "tabanda_vardi": [], "kaynakta_opak": 0, "uyusmazlik": []}
            for y, t in erisilebilir.items():
                p = pdtm.getDataType(y)
                if p is None:
                    denetim["uyusmazlik"].append({"yol": y, "durum": "programda yok"})
                    continue
                bos = (p.getNumComponents() == 0) if isinstance(p, Composite) else None
                if y in onceden:
                    denetim["tabanda_vardi"].append({"yol": y, "boyut_program": p.getLength(),
                                                     "boyut_ayristirilan": t.getLength(),
                                                     "esit": p.getLength() == t.getLength()})
                    continue
                if t.getNumComponents() == 0:
                    denetim["kaynakta_opak"] += 1  # tmux.h/SDK'da yalnız ileri bildirim
                    if not bos:
                        denetim["uyusmazlik"].append({"yol": y, "durum": "opak bekleniyordu"})
                    continue
                if y in tam:
                    if bos or p.getLength() != t.getLength():
                        denetim["uyusmazlik"].append({"yol": y, "durum": "tam bekleniyordu",
                                                      "boyut": p.getLength(), "beklenen": t.getLength()})
                    else:
                        denetim["tam_bulunan"] += 1
                else:
                    if not bos:
                        denetim["uyusmazlik"].append({"yol": y, "durum": "boş bekleniyordu",
                                                      "boyut": p.getLength()})
                    else:
                        denetim["bos_bulunan"] += 1
            pwp = pdtm.getDataType(str(wp[0].getPathName()))
            denetim["window_pane_programda"] = {"boyut": pwp.getLength(), "bilesen": pwp.getNumComponents()}
            # adı .conflict ile biten tip oluştu mu?
            denetim["conflict_tipleri_once"] = conflict_once
            denetim["conflict_tipleri_sonra"] = sorted(str(d.getPathName()) for d in pdtm.getAllDataTypes()
                                                       if ".conflict" in d.getName())
            rapor["tip_denetimi"] = denetim
        basarili = True
    finally:
        program.endTransaction(tx, basarili)
    rapor["uygulama_sn"] = round(time.perf_counter() - t0, 3)
    rapor["adlar"] = adlar
    return rapor


def olc_koşul(program, secim: dict, kosul: str) -> list[dict]:
    fm = program.getFunctionManager()
    dec = ortak.Decompiler(program)
    for a in secim["isinma"]:
        dec.c(fm.getFunctionAt(ortak.adres(program, a)))
    cikti_dizin = ortak.CIKTILAR / kosul
    cikti_dizin.mkdir(parents=True, exist_ok=True)
    kayitlar = []
    ogeler = [("hedef", h["adres"], h["ad"]) for h in secim["hedefler"]] + \
             [("cagiran", c["adres"], None) for c in secim["cagiranlar"]]
    for rol, adr, gt in ogeler:
        f = fm.getFunctionAt(ortak.adres(program, adr))
        c1, t1, h1 = dec.c(f)
        c2, t2, h2 = dec.c(f)
        kayit = {"rol": rol, "adres": adr, "gt_ad": gt, "ghidra_adi": f.getName(),
                 "sure_sn": [round(t1, 4), round(t2, 4)], "sure_ort_sn": round((t1 + t2) / 2, 4),
                 "hata": h1 or None}
        if c1 is None:
            kayit["olcut"] = None
        else:
            (cikti_dizin / f"{rol}_{adr}.c").write_text(c1, encoding="utf-8")
            kayit["olcut"] = olcut.olc(c1)
            kayit["belirlenimci"] = (c1 == c2)
        kayitlar.append(kayit)
    dec.kapat()
    return kayitlar


def main(kosullar: list[str]) -> None:
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    hedefler = secim["hedefler"]
    ortak.jvm_baslat()

    dtm = fdefs = None
    tip_raporu = None
    if any(KOSULLAR[k]["prototip"] for k in kosullar):
        dtm, parser, tip_raporu = tipler.tipleri_ayristir(prototip_metni(hedefler))
        if tip_raporu["ayristirma"] != "başarılı":
            raise SystemExit("ayrıştırma başarısız: " + tip_raporu.get("ayristirma_hatasi", ""))
        tum = parser.getFunctions()
        fdefs = {}
        tx = dtm.startTransaction("ad düzeltme")
        try:
            for h in hedefler:
                fd = tum.get(ONEK + h["ad"])
                if fd is None:
                    raise SystemExit(f"prototip ayrıştırılamadı: {h['ad']}")
                fd.setName(h["ad"])
                fdefs[h["ad"]] = fd
        finally:
            dtm.endTransaction(tx, True)

    for k in kosullar:
        hedef = ortak.PROJELER / k
        ortak.proje_kopyala(ortak.PROJELER / "taban", hedef)
        proje, program = ortak.proje_ac(hedef)
        try:
            uygulama = geri_yaz(program, k, hedefler, dtm, fdefs)
            proje.save(program)
            t0 = time.perf_counter()
            kayitlar = olc_koşul(program, secim, k)
            sure = time.perf_counter() - t0
        finally:
            proje.close()
        cikti = {"kunye": ortak.kunye(), "kosul": k, "uygulama": uygulama,
                 "tip_raporu": tip_raporu if KOSULLAR[k]["prototip"] else None,
                 "olcum_toplam_sn": round(sure, 1), "fonksiyonlar": kayitlar}
        ortak.json_yaz(ortak.VERI / f"olcum_{k}.json", cikti)
        hedef_k = [x for x in kayitlar if x["rol"] == "hedef"]
        print(k, "uygulama:", {a: uygulama.get(a) for a in ("ad_yazilan", "prototip_uygulanan", "uygulama_sn")},
              "hedef hata:", sum(1 for x in hedef_k if x["olcut"] is None),
              "belirlenimci değil:", sum(1 for x in kayitlar if x.get("belirlenimci") is False),
              "süre:", round(sure, 1))


if __name__ == "__main__":
    bilinmeyen = [k for k in sys.argv[1:] if k not in KOSULLAR]
    if bilinmeyen or len(sys.argv) < 2:
        raise SystemExit(f"koşul ver: {list(KOSULLAR)}")
    main(sys.argv[1:])
