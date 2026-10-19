"""G8 okunurluk ölçütleri — ön kayıtla dondurulan tanımlar.

Girdi: Ghidra'nın `DecompiledFunction.getC()` metni (tek fonksiyon).
Çıktı: ham sayılar ve 100 satıra oranlar.

Bu dosyanın SHA-256'sı ön kayıtta (onkayit.md) yazılıdır. Ölçümden sonra
değişirse gerekçesi onkayit_notlari.md'ye düşülür.

Kullanım:
    from olcut import olc
    m = olc(c_text)          # {'satir': ..., 'undefined': ..., ...}
    python3 olcut.py --test  # sentetik örneklerle öz-sınama
"""

from __future__ import annotations

import re
import sys

# ---------------------------------------------------------------------------
# 1. Temizlik: yorumlar silinir, dize ve karakter sabitlerinin içi boşaltılır.
#    Satır yapısı korunur (blok yorumun içindeki satır sonları kalır), boş
#    satırlar satır sayısına girmez.
# ---------------------------------------------------------------------------


def temizle(c: str) -> str:
    out: list[str] = []
    i, n = 0, len(c)
    while i < n:
        ch = c[i]
        nxt = c[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "*":
            j = c.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("\n" * c.count("\n", i, j))
            i = j
        elif ch == "/" and nxt == "/":
            j = c.find("\n", i)
            i = n if j == -1 else j
        elif ch in ("\"", "'"):
            q = ch
            j = i + 1
            while j < n and c[j] != q and c[j] != "\n":
                j += 2 if c[j] == "\\" else 1
            out.append(q + q)
            i = j + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# 2. Desenler
# ---------------------------------------------------------------------------

# Ghidra'nın tipsizlik belirteci: undefined, undefined1, undefined2, undefined4, undefined8 ...
RE_UNDEFINED = re.compile(r"\bundefined\d*\b")

# İşaretçi tipine dönüşüm ve hemen ardından açılan parantez: "(T *)(" ya da "(T **)("
RE_PTR_CAST_HEAD = re.compile(
    r"\(\s*(?:(?:const|volatile|unsigned|signed|struct|union|enum)\s+)*"
    r"[A-Za-z_]\w*\s*\*+\s*\)\s*\("
)

# Tip dönüşümü: "(tip)" ya da "(tip *)" ve ardından bir işlenen başlangıcı.
# Önünde tanıtıcı karakteri ya da ']' varsa (çağrı, dizin) sayılmaz; önünde ')' varsa
# yalnız dönüşüm zincirinin devamıysa sayılır (tip_donusumleri). "if (x) goto" gibi
# denetim anahtar sözcüklerinin koşulu sayılmaz.
RE_CAST = re.compile(
    r"(?<![\w\]])(?<!\bif )(?<!\bfor )(?<!\bwhile )(?<!\bswitch )"
    r"\(\s*(?:(?:const|volatile|unsigned|signed|struct|union|enum)\s+)*"
    r"[A-Za-z_]\w*(?:\s+(?:long|int|short|char))*\s*\**\s*\)"
    r"(?=\s*(?:[\w(*!~\-'\"]|&(?!&)))"
)
RE_CAST_ADI = re.compile(r"([A-Za-z_]\w*)(?:\s+(?:long|int|short|char))*\s*\**\s*\)$")


def _imza_parametre_adlari(temiz: str) -> set[str]:
    """İmza satırındaki parametre adları (Ghidra her parametreyi 'tip ad' yazar)."""
    for satir in temiz.split("\n"):
        if "(" in satir and satir.strip():
            acilis = satir.index("(")
            kapanis = _kapanis(satir, acilis)
            if kapanis == -1:
                return set()
            adlar = set()
            for parca in satir[acilis + 1:kapanis].split(","):
                m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", parca)
                if m and m.group(1) != "void":
                    adlar.add(m.group(1))
            return adlar
    return set()


def tip_donusumleri(temiz: str) -> list[str]:
    """RE_CAST eşleşmeleri, iki süzgeçle:
    - Önünde ')' olan aday yalnız bir dönüşüm zincirinin devamıysa sayılır:
      "(int *)(ulong)x" -> 2; "(*f)(x) - 1" içindeki "(x)" sayılmaz.
    - Parantez içindeki ad bir değişkense sayılmaz: Ghidra'nın varsayılan yerel ya da
      parametre adı (RE_DEFAULT_VAR) veya imzadaki bir parametre adı. Örnek:
      "if (((bVar19) && ...)" bir dönüşüm değildir."""
    parametreler = _imza_parametre_adlari(temiz)
    kabul: list[str] = []
    son_bitis = -1
    for m in RE_CAST.finditer(temiz):
        k = m.start() - 1
        while k >= 0 and temiz[k] in " \t":
            k -= 1
        if k >= 0 and temiz[k] == ")" and k + 1 != son_bitis:
            continue
        ad = RE_CAST_ADI.search(m.group(0))
        if ad and "*" not in m.group(0):
            if RE_DEFAULT_VAR.fullmatch(ad.group(1)) or ad.group(1) in parametreler:
                continue
        kabul.append(m.group(0))
        son_bitis = m.end()
    return kabul

# Ghidra'nın varsayılan yerel/parametre adları
RE_DEFAULT_VAR = re.compile(
    r"\b(?:param_\d+"
    r"|local_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)?|local_res\w+"
    r"|[a-z]{1,8}Var\d+"
    r"|[a-z]{1,8}Stack_\w+"
    r"|in_\w+|extraout_\w+|unaff_\w+)\b"
)

# Ghidra'nın varsayılan genel adları (fonksiyon, veri, etiket, işaretçi, switch)
RE_DEFAULT_GLOBAL = re.compile(
    r"\b(?:FUN|DAT|LAB|SUB)_[0-9a-fA-F]+\b|\bPTR_\w+|\bswitchD_\w+|\bcaseD_\w+"
)
RE_FUN = re.compile(r"\bFUN_[0-9a-fA-F]+\b")


def _kapanis(s: str, acilis: int) -> int:
    """s[acilis] == '(' iken eşleşen ')' konumu; yoksa -1."""
    derinlik = 0
    for k in range(acilis, len(s)):
        if s[k] == "(":
            derinlik += 1
        elif s[k] == ")":
            derinlik -= 1
            if derinlik == 0:
                return k
    return -1


def _ust_duzey_toplama(ifade: str) -> bool:
    """İfadenin en üst düzeyinde ikili '+' ya da '-' var mı (-> ve ++/-- hariç)."""
    derinlik = 0
    onceki = ""  # en son boşluk olmayan karakter (derinlik 0'da)
    for k, ch in enumerate(ifade):
        if ch in "([":
            derinlik += 1
        elif ch in ")]":
            derinlik -= 1
        if derinlik == 0 and ch in "+-":
            sonraki = ifade[k + 1] if k + 1 < len(ifade) else ""
            if sonraki in (">", ch) or (k > 0 and ifade[k - 1] == ch):
                pass
            elif onceki and (onceki.isalnum() or onceki in "_)]"):
                return True
        if not ch.isspace():
            onceki = ch
    return False


def isaretci_aritmetigi(temiz: str) -> tuple[int, int]:
    """(P1, P2) döndürür.

    P2: "(T *)(EXPR)" biçimindeki her işaretçi dönüşümü; EXPR'nin en üst düzeyinde
        ikili + ya da - varsa (taban + ofset, taban + indis*boyut).
    P1: P2'nin, dönüşümün hemen önünde '*' (bellek okuma/yazma) olan alt kümesi,
        yani "*(T *)(x + 0x..)".
    """
    p1 = p2 = 0
    for m in RE_PTR_CAST_HEAD.finditer(temiz):
        acilis = m.end() - 1
        kapanis = _kapanis(temiz, acilis)
        if kapanis == -1:
            continue
        if not _ust_duzey_toplama(temiz[acilis + 1:kapanis]):
            continue
        p2 += 1
        k = m.start() - 1
        while k >= 0 and temiz[k] in " \t":
            k -= 1
        if k >= 0 and temiz[k] == "*":
            p1 += 1
    return p1, p2


def olc(c: str) -> dict:
    """Bir fonksiyonun C metninden ölçütleri hesaplar."""
    t = temizle(c)
    satirlar = [s for s in t.split("\n") if s.strip()]
    L = len(satirlar)
    U = len(RE_UNDEFINED.findall(t))
    P1, P2 = isaretci_aritmetigi(t)
    C = len(tip_donusumleri(t))
    A = t.count("->")
    D = len(RE_DEFAULT_VAR.findall(t))
    G = len(RE_DEFAULT_GLOBAL.findall(t))
    F = len(RE_FUN.findall(t))

    def oran(x: int) -> float:
        return 100.0 * x / L if L else 0.0

    return {
        "satir": L,
        "undefined": U, "undefined_100": oran(U),
        "ptr_aritmetik": P1, "ptr_aritmetik_100": oran(P1),
        "ptr_aritmetik_genis": P2, "ptr_aritmetik_genis_100": oran(P2),
        "tip_donusumu": C, "tip_donusumu_100": oran(C),
        "ok_erisim": A, "ok_erisim_100": oran(A),
        "varsayilan_ad": D, "varsayilan_ad_100": oran(D),
        "varsayilan_genel": G, "varsayilan_genel_100": oran(G),
        "fun_ad": F, "fun_ad_100": oran(F),
    }


# ---------------------------------------------------------------------------
# Öz-sınama (sentetik, Ghidra biçiminde örnekler; ölçülen kümeden değil)
# ---------------------------------------------------------------------------

def _test() -> None:
    ornek = (
        "/* WARNING: Removing unreachable block (ram,0x100001234) */\n"
        "\n"
        "undefined8 FUN_100001784(long *param_1,long param_2,undefined8 param_3)\n"
        "{\n"
        "  undefined4 uVar1;\n"
        "  char acStack_78 [16];\n"
        "  \n"
        "  *(undefined4 *)(*(long *)(param_2 + 0x88) + 0x34) = 0xffffffff;\n"
        "  uVar1 = *(undefined4 *)(param_2 + 0x10);\n"
        "  FUN_100010d88(param_2 + 8,(int *)(ulong)uVar1,\"a->b (int)x + 1\");\n"
        "  (**(code **)(*param_1 + 0x10))(param_1);\n"
        "  if (bVar1) goto LAB_100001800;\n"
        "  if (((bVar1) && (param_3 != 0)) && (lVar2 != 0)) {\n"
        "  }\n"
        "  lVar2 = (long)(int)uVar1 - 1;\n"
        "  pcVar3 = (char *)(lVar2 + param_2);\n"
        "  *(char *)(param_2 + -1) = '\\0';\n"
        "  return (char *)0x0;\n"
        "}\n"
    )
    m = olc(ornek)
    # satır: imza, {, 2 bildirim, 10 deyim/blok satırı, return, } = 16
    assert m["satir"] == 16, m
    assert m["undefined"] == 5, m  # undefined8, undefined8, undefined4 x3
    # P1: *(undefined4 *)(…+0x34), *(long *)(param_2+0x88), *(undefined4 *)(param_2+0x10),
    #     *(code **)(*param_1+0x10), *(char *)(param_2 + -1) = 5
    assert m["ptr_aritmetik"] == 5, m
    # P2 = P1 + (char *)(lVar2 + param_2) = 6
    assert m["ptr_aritmetik_genis"] == 6, m
    # dönüşümler: (undefined4 *) x2, (long *), (int *), (ulong), (code **), (long), (int),
    #             (char *) x3  = 11 ; "if (bVar1) goto", "((bVar1) &&" ve dize içi sayılmaz
    assert m["tip_donusumu"] == 11, m
    assert m["ok_erisim"] == 0, m
    # varsayılan adlar: param_1 x3, param_2 x6, param_3 x2, uVar1 x4, acStack_78 x1,
    #                   bVar1 x2, lVar2 x3, pcVar3 = 22
    assert m["varsayilan_ad"] == 22, m
    assert m["fun_ad"] == 2, m
    assert m["varsayilan_genel"] == 3, m  # FUN x2, LAB x1

    sonra = (
        "void window_pane_x(window_pane *wp,int flags)\n"
        "{\n"
        "  wp->flags = wp->flags | flags;\n"
        "  (wp->base).grid = (grid *)0x0;\n"
        "  *(long *)((long)wp->window + 0x28) = 0;\n"
        "}\n"
    )
    m2 = olc(sonra)
    assert m2["satir"] == 6, m2
    assert m2["ok_erisim"] == 4, m2
    assert m2["ptr_aritmetik"] == 1, m2
    assert m2["tip_donusumu"] == 3, m2  # (grid *), (long *), (long)
    assert m2["varsayilan_ad"] == 0, m2
    assert m2["undefined"] == 0, m2
    print("olcut.py öz-sınama: GEÇTİ")


if __name__ == "__main__":
    if "--test" in sys.argv:
        _test()
