"""G8 sağlamlık denetimi (ön kayıt dışı, tanımlayıcı): çağrı kuralı uyarısı.

C2-C4 çıktılarında "WARNING: Unknown calling convention -- yet parameter storage is
locked" yorumu var: prototipi uygulanan fonksiyonun çağrı kuralı 'unknown' kaldı.
Bu betik C3'ü geçici bir kopyada yeniden uygular, 20 hedefin çağrı kuralını
derleyici tanımının varsayılanına çeker, hedefleri ve çağıranları yeniden decompile
eder ve metni (uyarı yorumu çıkarılarak) deney.py'nin C3 çıktısıyla karşılaştırır.
Geçici proje sonunda silinir. Çıktı: veri/saglamlik_cc.json, ciktilar/C3_cdecl/
"""
import json, re, shutil, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak, tipler, deney  # noqa: E402


def uyarisiz(c: str) -> str:
    """Uyarı yorumunu, boş satırları ve imzadaki açık '__cdecl' belirtecini yok sayar."""
    c = re.sub(r"/\* WARNING: Unknown calling convention[^*]*\*/", "", c)
    c = c.replace("__cdecl ", "")
    return "\n".join(s for s in c.split("\n") if s.strip())


def main():
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    hedefler = secim["hedefler"]
    ortak.jvm_baslat()
    dtm, parser, _ = tipler.tipleri_ayristir(deney.prototip_metni(hedefler))
    tum = parser.getFunctions(); fdefs = {}
    tx = dtm.startTransaction("ad")
    for h in hedefler:
        fd = tum.get(deney.ONEK + h["ad"]); fd.setName(h["ad"]); fdefs[h["ad"]] = fd
    dtm.endTransaction(tx, True)
    gecici = ortak.PROJELER / "_saglamlik_cc"
    ortak.proje_kopyala(ortak.PROJELER / "taban", gecici)
    proje, program = ortak.proje_ac(gecici)
    try:
        deney.geri_yaz(program, "C3", hedefler, dtm, fdefs)
        fm = program.getFunctionManager()
        varsayilan = program.getCompilerSpec().getDefaultCallingConvention().getName()
        once = [str(fm.getFunctionAt(ortak.adres(program, h["adres"])).getCallingConventionName()) for h in hedefler]
        tx = program.startTransaction("cc")
        for h in hedefler:
            fm.getFunctionAt(ortak.adres(program, h["adres"])).setCallingConvention(varsayilan)
        program.endTransaction(tx, True)
        dec = ortak.Decompiler(program)
        ayni = farkli = 0; farklar = []
        for rol, adr in [("hedef", h["adres"]) for h in hedefler] + [("cagiran", c["adres"]) for c in secim["cagiranlar"]]:
            c, _, _ = dec.c(fm.getFunctionAt(ortak.adres(program, adr)))
            (ortak.CIKTILAR / "C3_cdecl").mkdir(parents=True, exist_ok=True)
            (ortak.CIKTILAR / "C3_cdecl" / f"{rol}_{adr}.c").write_text(c, encoding="utf-8")
            ref = (ortak.CIKTILAR / "C3" / f"{rol}_{adr}.c").read_text()
            if uyarisiz(c) == uyarisiz(ref):
                ayni += 1
            else:
                farkli += 1; farklar.append(adr)
        dec.kapat()
    finally:
        proje.close()
    shutil.rmtree(gecici)
    out = {"kunye": ortak.kunye(), "varsayilan_cagri_kurali": varsayilan,
           "onceki_cagri_kurallari": sorted(set(once)), "ayni": ayni, "farkli": farkli, "farkli_adresler": farklar}
    ortak.json_yaz(ortak.VERI / "saglamlik_cc.json", out)
    print(out)


if __name__ == "__main__":
    main()
