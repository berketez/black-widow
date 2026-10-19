"""G8 taban projesi ve fonksiyon seçimi.

Kullanım:
  python3 -I -B taban.py analiz   # strip'li tmux'u yeni projeye al, otomatik analiz, kaydet
  python3 -I -B taban.py secim    # ön kayıt §3 (e)-(f) + tohumlu sıra -> 20 hedef + çağıranlar

Çıktılar: workspaces/2026-10-19_g8/projeler/taban/ (Ghidra projesi, git dışı),
          workspaces/2026-10-19_g8/veri/taban_analiz.json, secim.json
"""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402

TABAN = ortak.PROJELER / "taban"
SECIM_TOHUMU = 8691180542497554626   # SHA-256("karadul-g8-geri-yazma-2026-10-19")[:16]
HEDEF_SAYISI = 20


def analiz() -> None:
    ortak.jvm_baslat()
    from ghidra.base.project import GhidraProject  # type: ignore
    from ghidra.program.flatapi import FlatProgramAPI  # type: ignore
    from ghidra.program.util import GhidraProgramUtilities  # type: ignore
    from ghidra.app.script import GhidraScriptUtil  # type: ignore
    from java.io import File  # type: ignore

    if (TABAN / f"{ortak.PROJE_ADI}.gpr").exists():
        raise SystemExit(f"{TABAN} zaten var; taban yeniden kurulmaz")
    TABAN.mkdir(parents=True, exist_ok=True)
    kunye = ortak.kunye()
    t0 = time.time()
    proje = GhidraProject.createProject(str(TABAN), ortak.PROJE_ADI, False)
    program = proje.importProgram(File(str(ortak.STRIP_TMUX)))
    proje.saveAs(program, "/", ortak.PROGRAM_ADI, True)
    t_import = time.time() - t0
    GhidraScriptUtil.acquireBundleHostReference()
    try:
        t1 = time.time()
        # Karadul'un yolu (pyghidra.open_program(analyze=True)) ile aynı: varsayılan analizörler
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            FlatProgramAPI(program).analyzeAll(program)
            GhidraProgramUtilities.markProgramAnalyzed(program)
        t_analiz = time.time() - t1
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
    fm = program.getFunctionManager()
    toplam = fm.getFunctionCount()
    fun = thunk = 0
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        if f.isThunk():
            thunk += 1
        elif f.getName().startswith("FUN_"):
            fun += 1
    bilgi = {
        "kunye": kunye,
        "dil": str(program.getLanguageID()),
        "derleyici": str(program.getCompilerSpec().getCompilerSpecID()),
        "imaj_tabani": str(program.getImageBase()),
        "ice_aktarma_sn": round(t_import, 1),
        "analiz_sn": round(t_analiz, 1),
        "fonksiyon": toplam, "fun_adli": fun, "thunk": thunk,
    }
    proje.save(program)
    proje.close()
    ortak.json_yaz(ortak.VERI / "taban_analiz.json", bilgi)
    print(json.dumps(bilgi, ensure_ascii=False, indent=1))


def secim() -> None:
    adaylar = json.loads((ortak.VERI / "kaynak_adaylar.json").read_text())["adaylar"]
    sira = sorted(adaylar, key=lambda a: int(a["adres"], 16))
    random.Random(SECIM_TOHUMU).shuffle(sira)

    ortak.jvm_baslat()
    proje, program = ortak.proje_ac(TABAN)
    try:
        fm = program.getFunctionManager()
        dec = ortak.Decompiler(program)
        secilen, elenen = [], []
        for sira_no, a in enumerate(sira):
            if len(secilen) == HEDEF_SAYISI:
                break
            f = fm.getFunctionAt(ortak.adres(program, a["adres"]))
            if f is None:
                elenen.append({**a, "sira": sira_no, "neden": "e: bu adreste fonksiyon girişi yok"})
                continue
            if f.isThunk():
                elenen.append({**a, "sira": sira_no, "neden": "e: thunk"})
                continue
            if not f.getName().startswith("FUN_"):
                elenen.append({**a, "sira": sira_no, "neden": f"e: Ghidra adlandırmış ({f.getName()})"})
                continue
            c, sure, hata = dec.c(f)
            if c is None:
                elenen.append({**a, "sira": sira_no, "neden": f"f: taban decompile başarısız ({hata})"})
                continue
            secilen.append({**a, "sira": sira_no, "ghidra_adi": f.getName(),
                            "govde_bayt": int(f.getBody().getNumAddresses())})
        dec.kapat()
        if len(secilen) < HEDEF_SAYISI:
            raise SystemExit(f"yalnız {len(secilen)} hedef bulundu")

        # Doğrudan çağıranlar
        hedef_adres = {s["adres"] for s in secilen}
        rm = program.getReferenceManager()
        cagiranlar: dict[str, dict] = {}
        for s in secilen:
            giris = ortak.adres(program, s["adres"])
            it = rm.getReferencesTo(giris)
            s["cagiran_adresleri"] = []
            while it.hasNext():
                r = it.next()
                if not r.getReferenceType().isCall():
                    continue
                cf = fm.getFunctionContaining(r.getFromAddress())
                if cf is None:
                    continue
                ca = "0x" + str(cf.getEntryPoint()).lower().lstrip("0")
                if ca in hedef_adres:
                    s["cagiran_adresleri"].append(ca)
                    continue
                s["cagiran_adresleri"].append(ca)
                cagiranlar.setdefault(ca, {"adres": ca, "ghidra_adi": cf.getName(),
                                           "thunk": bool(cf.isThunk()),
                                           "govde_bayt": int(cf.getBody().getNumAddresses()),
                                           "cagirdigi_hedefler": []})
                if s["adres"] not in cagiranlar[ca]["cagirdigi_hedefler"]:
                    cagiranlar[ca]["cagirdigi_hedefler"].append(s["adres"])
        # Isınma için ölçülen kümede olmayan 5 fonksiyon (adrese göre ilk 5 FUN_)
        olculen = hedef_adres | set(cagiranlar)
        isinma = []
        it = fm.getFunctions(True)
        while it.hasNext() and len(isinma) < 5:
            f = it.next()
            ad = "0x" + str(f.getEntryPoint()).lower().lstrip("0")
            if f.getName().startswith("FUN_") and not f.isThunk() and ad not in olculen:
                isinma.append(ad)
    finally:
        proje.close()

    cikti = {
        "kunye": ortak.kunye(),
        "tohum": SECIM_TOHUMU,
        "aday_sayisi": len(sira),
        "incelenen": len(secilen) + len(elenen),
        "hedefler": secilen,
        "elenenler": elenen,
        "cagiranlar": sorted(cagiranlar.values(), key=lambda c: int(c["adres"], 16)),
        "isinma": isinma,
    }
    ortak.json_yaz(ortak.VERI / "secim.json", cikti)
    print(f"hedef {len(secilen)}, elenen {len(elenen)}, çağıran {len(cagiranlar)}")
    for s in secilen:
        print(s["sira"], s["adres"], s["ad"], s["dosya"], "çağıran:", len(s["cagiran_adresleri"]))
    for e in elenen:
        print("ELENDİ", e["sira"], e["adres"], e["ad"], e["neden"])


if __name__ == "__main__":
    {"analiz": analiz, "secim": secim}[sys.argv[1]]()
