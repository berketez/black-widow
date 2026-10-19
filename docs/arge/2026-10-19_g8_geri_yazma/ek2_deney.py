"""G8 ek 2: K4 (yalnız ad, Ghidra tipleri korunur) ve K4' (K4 + bilinen yerleşim için tip).

Kullanım:  python3 -I -B ek2_deney.py K4 K4p

onkayit_ek2.md §2. K4p, K4' koşuludur (dosya ve dizin adlarında tırnak yok).
Ölçüm deney.py'nin `olc_koşul` işleviyle (aynı ayarlar, ısınma, iki koşu).
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
import deney  # noqa: E402
import tipler  # noqa: E402
import ek_deney  # noqa: E402


def konum(storage, yigin_sirasi: dict) -> int | None:
    """ABI konumu: x0-x7 / w0-w7 -> 0-7; yığın -> 8 + ofset sırası; öbürü None."""
    if storage.isRegisterStorage():
        m = re.fullmatch(r"[xw]([0-7])", str(storage.getRegister().getName()))
        return int(m.group(1)) if m else None
    if storage.isStackStorage():
        return 8 + yigin_sirasi[int(storage.getStackOffset())]
    return None


def yapi_hazirla(program, dtm_kaynak):
    """C3'teki gibi: window_pane ve değerle gömdüğü yapılar tam, işaretçiyle erişilenler boş."""
    from ghidra.program.model.data import DataTypeConflictHandler, PointerDataType  # type: ignore
    wp = tipler.yapilar(dtm_kaynak, "window_pane")[0]
    erisilebilir = deney.erisilebilir_bilesikler([wp])
    tam = {str(t.getPathName()): t for t in tipler.kapanis_kumesi(wp)}
    pdtm = program.getDataTypeManager()
    keep = DataTypeConflictHandler.KEEP_HANDLER
    onceden = {y for y in erisilebilir if pdtm.getDataType(y) is not None}
    for y, t in erisilebilir.items():
        if y not in tam:
            pdtm.resolve(deney.yer_tutucu(t), keep)
    for t in tam.values():
        pdtm.resolve(t, keep)
    pwp_tip = pdtm.getDataType(str(wp.getPathName()))
    denetim = {"erisilebilir": len(erisilebilir), "tam": len(tam), "tabanda_vardi": sorted(onceden),
               "window_pane_programda": {"boyut": pwp_tip.getLength(), "bilesen": pwp_tip.getNumComponents()}}
    return PointerDataType(pwp_tip), denetim


def wp_isaretcisi_mi(dt) -> bool:
    from ghidra.program.model.data import Pointer, TypeDef  # type: ignore
    if not isinstance(dt, Pointer):
        return False
    t = dt.getDataType()
    while isinstance(t, TypeDef):
        t = t.getBaseDataType()
    return t is not None and t.getName() == "window_pane"


def geri_yaz(program, kosul: str, hedefler: list[dict], fdefs: dict, dtm_kaynak) -> dict:
    from ghidra.program.model.symbol import SourceType  # type: ignore
    from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore
    rapor: dict = {"kosul": kosul, "fonksiyonlar": []}
    t0 = time.perf_counter()
    fm = program.getFunctionManager()
    tx = program.startTransaction(f"G8 {kosul}")
    ok = False
    try:
        pwp = None
        if kosul == "K4p":
            pwp, rapor["tip_denetimi"] = yapi_hazirla(program, dtm_kaynak)
        dec = ortak.Decompiler(program)
        for h in hedefler:
            f = fm.getFunctionAt(ortak.adres(program, h["adres"]))
            f.setName(h["ad"], SourceType.USER_DEFINED)
            kaynak = list(fdefs[h["ad"]].getArguments())
            res = dec.ifc.decompileFunction(f, ortak.FUNC_TIMEOUT, dec.monitor)
            hf = res.getHighFunction() if res is not None else None
            kayit = {"adres": h["adres"], "ad": h["ad"], "kaynak_param": len(kaynak),
                     "ghidra_param": None, "adlandirilan": [], "eslenemeyen": [], "kaynakta_yok": [],
                     "tip_yazilan": [], "donus_tipi_yazildi": False, "hata": None}
            if hf is None:
                kayit["hata"] = "decompile başarısız"
                rapor["fonksiyonlar"].append(kayit)
                continue
            lsm = hf.getLocalSymbolMap()
            semboller = [lsm.getParamSymbol(i) for i in range(lsm.getNumParams())]
            kayit["ghidra_param"] = len(semboller)
            yigin = sorted({int(s.getStorage().getStackOffset()) for s in semboller
                            if s.getStorage().isStackStorage()})
            yigin_sirasi = {o: i for i, o in enumerate(yigin)}
            for s in semboller:
                k = konum(s.getStorage(), yigin_sirasi)
                if k is None:
                    kayit["eslenemeyen"].append(str(s.getStorage()))
                    continue
                if k >= len(kaynak):
                    kayit["kaynakta_yok"].append(k)
                    continue
                ad = str(kaynak[k].getName())
                dt = pwp if (pwp is not None and wp_isaretcisi_mi(kaynak[k].getDataType())) else None
                try:
                    HighFunctionDBUtil.updateDBVariable(s, ad, dt, SourceType.USER_DEFINED)
                    kayit["adlandirilan"].append({"konum": k, "ad": ad})
                    if dt is not None:
                        kayit["tip_yazilan"].append(k)
                except Exception as exc:
                    kayit["hata"] = f"{ad}: {exc}"[:300]
            if pwp is not None and wp_isaretcisi_mi(fdefs[h["ad"]].getReturnType()):
                f.setReturnType(pwp, SourceType.USER_DEFINED)
                kayit["donus_tipi_yazildi"] = True
            kayit["programdaki_imza"] = str(f.getSignature().getPrototypeString())
            kayit["imza_kaynagi"] = str(f.getSignatureSource())
            rapor["fonksiyonlar"].append(kayit)
        dec.kapat()
        ok = True
    finally:
        program.endTransaction(tx, ok)
    fk = rapor["fonksiyonlar"]
    rapor["uygulama_sn"] = round(time.perf_counter() - t0, 3)
    rapor["ad_yazilan"] = len(hedefler)
    rapor["parametre_adlandirilan"] = sum(len(x["adlandirilan"]) for x in fk)
    rapor["parametre_kaynak_toplam"] = sum(x["kaynak_param"] for x in fk)
    rapor["parametre_ghidra_toplam"] = sum(x["ghidra_param"] or 0 for x in fk)
    rapor["eslenemeyen"] = sum(len(x["eslenemeyen"]) for x in fk)
    rapor["kaynakta_yok"] = sum(len(x["kaynakta_yok"]) for x in fk)
    rapor["tip_yazilan_parametre"] = sum(len(x["tip_yazilan"]) for x in fk)
    rapor["donus_tipi_yazilan"] = sum(1 for x in fk if x["donus_tipi_yazildi"])
    rapor["hatali"] = [x["adres"] for x in fk if x["hata"]]
    return rapor


def isinma(secim: dict) -> None:
    """Süreçte koşullardan önce bütün küme bir kez decompile edilir; sonuçlar atılır (ön kayıt §2)."""
    proje, program = ortak.proje_ac(ortak.PROJELER / "K0")
    try:
        fm = program.getFunctionManager()
        dec = ortak.Decompiler(program)
        for a in [h["adres"] for h in secim["hedefler"]] + [c["adres"] for c in secim["cagiranlar"]]:
            dec.c(fm.getFunctionAt(ortak.adres(program, a)))
        dec.kapat()
    finally:
        proje.close()


def main(kosullar: list[str]) -> None:
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    ortak.jvm_baslat()
    dtm, fdefs = ek_deney.kaynak_prototipleri(secim["hedefler"])
    isinma(secim)
    for k in kosullar:
        if k not in ("K4", "K4p"):
            raise SystemExit(f"bilinmeyen koşul {k}")
        ek_deney.kosul_calistir(k, secim, lambda program, k=k: geri_yaz(program, k, secim["hedefler"], fdefs, dtm))


if __name__ == "__main__":
    main(sys.argv[1:])
