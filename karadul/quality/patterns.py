"""Ghidra varsayilan isim/tip kaliplari -- readability skorlama icin.

Bu modul, Ghidra decompile ciktisinda sik gorulen generic (anlamsiz)
isim kaliplarini tek merkezden tanimlar. Skorlayicinin tum metric
modulleri bu sabitleri import ederek kullanir; boylece tutarli kalir.

Magic number YOK -- her esik/agirlik ``config.py`` icinde tanimli.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Fonksiyon isim kaliplari
# ---------------------------------------------------------------------------
# Ghidra varsayilani: FUN_<hex_address>
# Ornek: FUN_00401000, FUN_100001234, FUN_0804a2f0
RE_GHIDRA_FUNC_NAME = re.compile(r"^FUN_[0-9a-fA-F]+$")

# Thunk / external isim kaliplari (anlamli sayilmazlar)
RE_GHIDRA_THUNK = re.compile(r"^thunk_FUN_[0-9a-fA-F]+$")

# IDA Pro / objdump varsayilan kaliplari -- destek icin
RE_IDA_FUNC_NAME = re.compile(r"^sub_[0-9a-fA-F]+$")
RE_LOC_NAME = re.compile(r"^loc(?:ret)?_[0-9a-fA-F]+$")

# Anlamli isim: snake_case veya camelCase, en az 3 karakter, rakamla baslamaz
RE_MEANINGFUL_SNAKE = re.compile(r"^[a-z][a-z0-9_]{2,}$")
RE_MEANINGFUL_CAMEL = re.compile(r"^[a-z][a-zA-Z0-9]{2,}$")
RE_MEANINGFUL_PASCAL = re.compile(r"^[A-Z][a-zA-Z0-9]{2,}$")


# ---------------------------------------------------------------------------
# Parametre isim kaliplari
# ---------------------------------------------------------------------------
# Ghidra varsayilani: param_1, param_2, ...
RE_GHIDRA_PARAM = re.compile(r"^param_\d+$")

# Ghidra bazen "in_stack_*", "in_FS_OFFSET" gibi kayit isimleri uretir
RE_GHIDRA_IN_REG = re.compile(r"^in_[A-Z][A-Za-z0-9_]*$")

# Cok kisa (tek harf) parametreler -- anlamsiz sayilir ama cezalandirma hafif
RE_SHORT_NAME = re.compile(r"^[a-zA-Z]$")


# ---------------------------------------------------------------------------
# Lokal degisken kaliplari
# ---------------------------------------------------------------------------
# Ghidra tipik lokal kaliplari:
#   iVar1, iVar2   -- int variable
#   lVar1          -- long variable
#   uVar1          -- unsigned
#   piVar1         -- pointer to int
#   pcVar1         -- pointer to char
#   plVar1         -- pointer to long
#   local_10, local_1c  -- stack offset tabanli
#   auStack_10     -- auto stack buffer
#   in_stack_ffff... -- input stack
RE_GHIDRA_LOCAL_VAR = re.compile(
    r"^(?:"
    r"[iul]Var\d+"             # iVar1, uVar3, lVar2
    r"|p[iclsu]Var\d+"         # piVar1, pcVar2 (pointer-to-X)
    r"|ppVar\d+"               # pointer-to-pointer
    r"|local_[0-9a-fA-F]+"     # local_10, local_1c
    r"|auStack_[0-9a-fA-F]+"   # auStack_20
    r"|uStack_[0-9a-fA-F]+"    # uStack_18
    r"|piStack_[0-9a-fA-F]+"   # piStack_10
    r"|in_stack_[0-9a-fA-F]+"  # in_stack_ffff0000
    r"|_Var\d+"                # _Var1 (nadir)
    r"|Var\d+"                 # Var1 (nadir)
    r")$"
)


# ---------------------------------------------------------------------------
# Tip kaliplari
# ---------------------------------------------------------------------------
# Ghidra generic tipler: undefined, undefined1, undefined2, undefined4, undefined8
# Bunlar "bilinmiyor, N byte" anlaminda -- anlamsiz tip.
RE_GHIDRA_UNDEFINED_TYPE = re.compile(r"^undefined(?:\d+)?$")

# Ghidra ozel generic pointer tipler
RE_GHIDRA_GENERIC_PTR = re.compile(r"^(?:code|byte|dword|qword|word)\s*\*?$")


# ---------------------------------------------------------------------------
# Kod yapisi kaliplari
# ---------------------------------------------------------------------------
# goto / etiket kullanimi -- decompiler goto ciktisi icin
RE_C_GOTO = re.compile(r"^\s*goto\s+\w+\s*;", re.MULTILINE)
RE_C_LABEL = re.compile(r"^\s*(?:LAB|case)_?\w*\s*:", re.MULTILINE)

# Tek satir yorum ve blok yorum kaliplari (C89/C99)
RE_C_LINE_COMMENT = re.compile(r"//[^\n]*")
RE_C_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)

# Fonksiyon imzasi kabaca: "return_type name(args) {"
# Bu sadece kalan pycparser'sz fallback icindir.
RE_C_FUNCTION_DEF = re.compile(
    r"^[\w\s\*]+?\s+(\w+)\s*\([^;{]*\)\s*\{",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Yardimci siniflandirma fonksiyonlari
# ---------------------------------------------------------------------------

def is_ghidra_func_name(name: str) -> bool:
    """Fonksiyon ismi Ghidra varsayilani mi?"""
    if not name:
        return True
    return bool(
        RE_GHIDRA_FUNC_NAME.match(name)
        or RE_GHIDRA_THUNK.match(name)
        or RE_IDA_FUNC_NAME.match(name)
    )


def is_ghidra_param_name(name: str) -> bool:
    """Parametre ismi Ghidra varsayilani mi?"""
    if not name:
        return True
    return bool(RE_GHIDRA_PARAM.match(name) or RE_GHIDRA_IN_REG.match(name))


def is_ghidra_local_name(name: str) -> bool:
    """Lokal degisken ismi Ghidra varsayilani mi?"""
    if not name:
        return True
    return bool(RE_GHIDRA_LOCAL_VAR.match(name))


def is_ghidra_type(type_name: str) -> bool:
    """Tip adi Ghidra generic'i mi?"""
    if not type_name:
        return True
    stripped = type_name.strip().rstrip("*").strip()
    return bool(
        RE_GHIDRA_UNDEFINED_TYPE.match(stripped)
        or RE_GHIDRA_GENERIC_PTR.match(stripped)
    )


def is_meaningful_name(name: str, min_length: int = 3) -> bool:
    """Isim anlamli mi (snake_case / camelCase / PascalCase)?

    Args:
        name: Degerlendirilecek isim.
        min_length: Minimum uzunluk.

    Returns:
        True ise Ghidra-jenerikten cikmis, anlami olan isim.
    """
    if not name or len(name) < min_length:
        return False
    if is_ghidra_func_name(name) or is_ghidra_param_name(name):
        return False
    if is_ghidra_local_name(name):
        return False
    return bool(
        RE_MEANINGFUL_SNAKE.match(name)
        or RE_MEANINGFUL_CAMEL.match(name)
        or RE_MEANINGFUL_PASCAL.match(name)
    )
