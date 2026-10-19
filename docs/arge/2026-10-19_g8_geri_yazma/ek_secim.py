"""G8 ek, K3: `struct client` hedeflerinin seçimi (ön kayıt §3 (e)-(f), aynı tohum).

taban.py `secim()` ile aynı kural; girdi k3_kaynak_adaylar.json, çıktı k3_secim.json.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
from taban import SECIM_TOHUMU, HEDEF_SAYISI, TABAN  # noqa: E402

GIRDI = ortak.VERI / "k3_kaynak_adaylar.json"
CIKTI = ortak.VERI / "k3_secim.json"


def adres_metni(a) -> str:
    return "0x" + str(a).lower().lstrip("0")


def main() -> None:
    adaylar = json.loads(GIRDI.read_text())["adaylar"]
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
            c, _, hata = dec.c(f)
            if c is None:
                elenen.append({**a, "sira": sira_no, "neden": f"f: taban decompile başarısız ({hata})"})
                continue
            secilen.append({**a, "sira": sira_no, "ghidra_adi": f.getName(),
                            "govde_bayt": int(f.getBody().getNumAddresses())})
        dec.kapat()
        if len(secilen) < HEDEF_SAYISI:
            raise SystemExit(f"yalnız {len(secilen)} hedef bulundu")
        hedef_adres = {s["adres"] for s in secilen}
        rm = program.getReferenceManager()
        cagiranlar: dict[str, dict] = {}
        for s in secilen:
            it = rm.getReferencesTo(ortak.adres(program, s["adres"]))
            s["cagiran_adresleri"] = []
            while it.hasNext():
                r = it.next()
                if not r.getReferenceType().isCall():
                    continue
                cf = fm.getFunctionContaining(r.getFromAddress())
                if cf is None:
                    continue
                ca = adres_metni(cf.getEntryPoint())
                s["cagiran_adresleri"].append(ca)
                if ca in hedef_adres:
                    continue
                cagiranlar.setdefault(ca, {"adres": ca, "ghidra_adi": cf.getName(),
                                           "thunk": bool(cf.isThunk()),
                                           "govde_bayt": int(cf.getBody().getNumAddresses()),
                                           "cagirdigi_hedefler": []})
                if s["adres"] not in cagiranlar[ca]["cagirdigi_hedefler"]:
                    cagiranlar[ca]["cagirdigi_hedefler"].append(s["adres"])
        olculen = hedef_adres | set(cagiranlar)
        isinma = []
        it = fm.getFunctions(True)
        while it.hasNext() and len(isinma) < 5:
            f = it.next()
            ad = adres_metni(f.getEntryPoint())
            if f.getName().startswith("FUN_") and not f.isThunk() and ad not in olculen:
                isinma.append(ad)
    finally:
        proje.close()
    cikti = {"kunye": ortak.kunye(), "yapi": "client", "tohum": SECIM_TOHUMU, "aday_sayisi": len(sira),
             "incelenen": len(secilen) + len(elenen), "hedefler": secilen, "elenenler": elenen,
             "cagiranlar": sorted(cagiranlar.values(), key=lambda c: int(c["adres"], 16)), "isinma": isinma}
    ortak.json_yaz(CIKTI, cikti)
    print(f"hedef {len(secilen)}, elenen {len(elenen)}, çağıran {len(cagiranlar)}")
    for s in secilen:
        print(s["sira"], s["adres"], s["ad"], s["dosya"], "çağıran:", len(s["cagiran_adresleri"]))
    for e in elenen:
        print("ELENDİ", e["sira"], e["adres"], e["ad"], e["neden"])


if __name__ == "__main__":
    main()
