"""Yerleşim imzasının bağımsız yeniden hesaplanması: pyelftools'un kendi DIE arayüzüyle
(dwarf_tip.py'nin Cozucu'su ve yardımcıları kullanılmaz). Yalnız dwz'siz dosyalarda.
İmza dilbilgisi dwarf_tip.py modül belgesindeki tanımdır; burada sıfırdan uygulanır."""
import hashlib, json, posixpath, random, sys
from collections import Counter
from pathlib import Path
from elftools.elf.elffile import ELFFile

NIT = {"DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type", "DW_TAG_atomic_type"}
YAPI = {"DW_TAG_structure_type": "struct", "DW_TAG_union_type": "union", "DW_TAG_class_type": "class"}

class Eksik(Exception): pass

def soy(die):
    """typedef ve niteleyicileri soy; (derinlik, uç DIE, ilk işaretçi DIE)"""
    d, ilk = 0, None
    for _ in range(64):
        if die is None: return d, None, ilk
        t = die.tag
        if t == "DW_TAG_typedef" or t in NIT:
            die = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
            continue
        if t in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
            d += 1; ilk = ilk or die
            die = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
            continue
        return d, die, ilk
    raise Eksik("derin")

def bs(die):
    a = die.attributes.get("DW_AT_byte_size")
    return a.value if a is not None else None

def ofs(m, ust):
    a = m.attributes.get("DW_AT_data_member_location")
    if a is None: return 0 if ust == "union" else None
    v = a.value
    if isinstance(v, int): return v
    if isinstance(v, list) and v and v[0] == 0x23:
        n = k = 0; i = 1
        while i < len(v):
            b = v[i]; n |= (b & 0x7f) << k; k += 7; i += 1
            if not b & 0x80: break
        return n
    return None

def metin(o):
    if o[0] == "y": return f"{o[1]}:{o[2]}{o[3]}"
    if o[0] == "b": return f"b{o[1]}:{o[2]}"
    if o[0] == "d": return f"{o[1]}:[{o[2]}x{o[3]}{{{o[4]}}}]"
    return f"{o[1]}:u{o[2]}{{{o[3]}}}"

def liste(ogeler):
    s = sorted(ogeler, key=lambda o: ((o[1] if o[0] == "b" else o[1] * 8), metin(o)))
    return ",".join(metin(o) for o in s) or "-"

def kaydir(o, dlt):
    return ("b", o[1] + 8 * dlt, o[2]) if o[0] == "b" else (o[0], o[1] + dlt) + tuple(o[2:])

def tip_ogeleri(tdie, at, ic):
    if ic > 20: raise Eksik("ic")
    d, uc, ilk = soy(tdie)
    if d >= 1:
        return [("y", at, (bs(ilk) or 8), "p")]
    if uc is None: raise Eksik("void")
    if uc.tag in ("DW_TAG_base_type", "DW_TAG_enumeration_type"):
        if bs(uc) is None: raise Eksik("boyut")
        return [("y", at, bs(uc), "s")]
    if uc.tag in YAPI:
        if "DW_AT_declaration" in uc.attributes: raise Eksik("bildirim")
        _, _, o = kume(uc, ic + 1)
        return [kaydir(x, at) for x in o]
    if uc.tag == "DW_TAG_array_type":
        n, e, m = dizi(uc, ic + 1)
        return [("d", at, n, e, m)]
    raise Eksik(uc.tag)

def boyut(tdie, ic):
    d, uc, ilk = soy(tdie)
    if d >= 1: return bs(ilk) or 8
    if uc is None: return None
    if uc.tag in YAPI: return bs(uc)
    if uc.tag == "DW_TAG_array_type":
        n, e, _ = dizi(uc, ic + 1)
        return n * e if isinstance(n, int) and isinstance(e, int) else None
    return bs(uc)

def dizi(adie, ic):
    sayi = None; ilk = True
    for c in adie.iter_children():
        if c.tag != "DW_TAG_subrange_type": continue
        if "DW_AT_count" in c.attributes: n = c.attributes["DW_AT_count"].value
        elif "DW_AT_upper_bound" in c.attributes:
            u = c.attributes["DW_AT_upper_bound"]; v = u.value
            if u.form == "DW_FORM_data1" and v >= 128: v -= 256
            if u.form == "DW_FORM_data2" and v >= 1 << 15: v -= 1 << 16
            if u.form == "DW_FORM_data4" and v >= 1 << 31: v -= 1 << 32
            lb = c.attributes.get("DW_AT_lower_bound")
            n = max(v - (lb.value if lb else 0) + 1, 0)
        else: n = None
        sayi = n if ilk else (None if n is None or sayi is None else sayi * n); ilk = False
    et = adie.get_DIE_from_attribute("DW_AT_type")
    d, uc, _ = soy(et)
    if d == 0 and uc is not None and uc.tag == "DW_TAG_array_type":
        n2, e2, m2 = dizi(uc, ic + 1)
        s = sayi * n2 if isinstance(sayi, int) and isinstance(n2, int) else None
        return (s if s is not None else "?"), e2, m2
    m = liste(tip_ogeleri(et, 0, ic + 1))
    e = boyut(et, ic + 1)
    return (sayi if sayi is not None else "?"), (e if e is not None else "?"), m

def kume(die, ic):
    tur = YAPI[die.tag]; b = bs(die)
    if b is None: raise Eksik("boyut")
    uyeler = [c for c in die.iter_children() if c.tag in ("DW_TAG_member", "DW_TAG_inheritance")
              and "DW_AT_declaration" not in c.attributes and "DW_AT_external" not in c.attributes]
    def uye(c):
        if "DW_AT_bit_size" in c.attributes:
            bit = c.attributes["DW_AT_bit_size"].value
            if "DW_AT_data_bit_offset" in c.attributes:
                return [("b", c.attributes["DW_AT_data_bit_offset"].value, bit)]
            o = ofs(c, tur) or 0; eski = c.attributes.get("DW_AT_bit_offset"); bb = c.attributes.get("DW_AT_byte_size")
            return [("b", o * 8 if eski is None or bb is None else o * 8 + bb.value * 8 - eski.value - bit, bit)]
        o = ofs(c, tur)
        if o is None: raise Eksik("ofset")
        return tip_ogeleri(c.get_DIE_from_attribute("DW_AT_type"), o, ic + 1)
    if tur == "union":
        alt = sorted({liste(uye(c)) for c in uyeler})
        return tur, b, [("u", 0, b, "|".join(alt) or "-")]
    o = []
    for c in uyeler: o.extend(uye(c))
    return tur, b, o

def imza(die):
    t, b, o = kume(die, 0)
    return f"{t}/{b}/{liste(o)}"

sonuc = {}
for ad, debug, belge in [a.split("=") for a in sys.argv[1:]]:
    d = json.loads(Path(belge).read_text())
    tablo = {k: y for k, y in d["yapilar"].items() if k.startswith("ana:") and (y.get("yerlesim") or {}).get("durum") == "tam"}
    c = Counter(); farklar = []
    with open(debug, "rb") as f:
        dw = ELFFile(f).get_dwarf_info(relocate_dwarf_sections=True, follow_links=False)
        for k, y in sorted(tablo.items()):
            die = dw.get_DIE_from_refaddr(int(k.split(":0x")[1], 16))
            try:
                s = imza(die)
            except Eksik as h:
                c["bagimsiz_eksik:" + str(h)] += 1; continue
            if s == y["yerlesim"]["imza"]: c["ayni"] += 1
            else:
                c["farkli"] += 1; farklar.append((k, y["kimlik"], s[:120], y["yerlesim"]["imza"][:120]))
    sonuc[ad] = {"tanim": len(tablo), **c, "farklar": farklar[:5]}
    print(ad, len(tablo), dict(c), farklar[:3])
json.dump(sonuc, open("capraz_yerlesim_sonuc.json", "w"), ensure_ascii=False, indent=1)
