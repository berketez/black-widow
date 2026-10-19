#!/usr/bin/env python3
"""cikar.py çözümleyicisinin elle doğrulanmış örneklerle sınaması (sonuç ölçütü değil).

Kullanım: python3 -B sinama_cikar.py
Her denetim başarısızsa AssertionError verir. Sentetik parçacıklar ve taban v2'den
elle okunmuş birkaç gerçek dosya kullanılır.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cikar import (field_access, is_changed, mask_c, parse_function,  # noqa: E402
                   split_top, strip_casts)


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)
    print("tamam:", msg)


def synthetic() -> None:
    check(strip_casts("(long)param_1") == "param_1", "dönüşüm soyulur")
    check(strip_casts("(undefined8 *)param_1") == "param_1", "işaretçi dönüşümü soyulur")
    check(strip_casts("(param_1)") == "param_1", "dış ayraç soyulur")
    check(strip_casts("param_1 + 0x10") == "param_1 + 0x10", "ofset korunur")
    check(strip_casts("*(undefined8 *)(param_1 + 0x10)") != "param_1", "alan yükleme p1 değil")
    check(strip_casts("(void (*)(int))param_1") != "param_1", "iç içe dönüşüm soyulmaz (tutucu)")
    check(split_top("a,f(b,c),d[1,2]") == ["a", "f(b,c)", "d[1,2]"], "üst düzey virgül")
    m = mask_c('x = "a(b,\\"c)"; // yorum (\n y = \'(\'; /* (( */ z(1);')
    check("(" not in m.replace("z(1)", ""), "dize, karakter ve yorum maskelenir")
    check(is_changed("{ param_1 = param_1 + 1; }", "param_1"), "atama değişiklik")
    check(is_changed("{ for (; x; param_1 = param_1 + 8) {} }", "param_1"), "for adımı değişiklik")
    check(is_changed("{ param_1 += 8; }", "param_1"), "bileşik atama değişiklik")
    check(is_changed("{ LAB_1:\n param_1 = 0; }", "param_1"), "etiket sonrası atama")
    check(is_changed("{ x = *param_1++; }", "param_1"), "son artırma değişiklik")
    check(is_changed("{ f(&param_1); }", "param_1"), "adres alma değişiklik")
    check(not is_changed("{ *param_1 = 5; }", "param_1"), "işaretçi üstünden yazma değişiklik değil")
    check(not is_changed("{ *(long *)param_1 = 5; }", "param_1"), "dönüşümlü yazma değişiklik değil")
    check(not is_changed("{ *(long *)(param_1 + 8) = 5; }", "param_1"), "alan yazma değişiklik değil")
    check(not is_changed("{ if (param_1 == 0) {} x = y & param_1; }", "param_1"),
          "karşılaştırma ve ikili & değişiklik değil")
    check(not is_changed("{ param_10 = 1; }", "param_1"), "param_10 ayrı değişken")
    check(not is_changed("{ if (param_1 <= 3) {} }", "param_1"), "<= atama değil")
    check(field_access("{ x = *(long *)(param_1 + 0x10); }", "param_1", "long"), "8 bayt alan")
    check(not field_access("{ x = *(char *)(param_1 + 1); }", "param_1", "long"), "bayt okuma nesne değil")
    check(field_access("{ x = param_1[2]; }", "param_1", "long *"), "dizinli 8 bayt alan")
    check(not field_access("{ x = param_1[2]; }", "param_1", "char *"), "dizinli karakter nesne değil")
    src = ("void FUN_1(long param_1,int param_2)\n{\n  FUN_2(param_1,1);\n"
           "  FUN_3((char *)param_1);\n  FUN_4(param_1 + 8);\n"
           "  FUN_5(*(undefined8 *)(param_1 + 0x10));\n  FUN_6(param_2,param_1);\n"
           "  FUN_7(\"a(b\",param_1);\n  return;\n}\n// --- DISASSEMBLY (7 instructions) ---\n")
    info = parse_function(src, "FUN_1")
    calls = {c["hedef"]: c["arg"] for c in info["calls"]}
    check(info["params"][0]["ad"] == "param_1" and not info["params"][0]["degisti"], "imza ve p1")
    check(calls["FUN_2"][0] == "param_1" and calls["FUN_3"][0] == "param_1", "p1 doğrudan ve dönüşümlü")
    check(calls["FUN_4"][0] != "param_1" and calls["FUN_5"][0] != "param_1", "ofset ve alan p1 değil")
    check(calls["FUN_6"] == ["param_2", "param_1"], "konumlar (V2)")
    check(calls["FUN_7"] == ['"S"', "param_1"], "dize içindeki ayraç çözümlemeyi bozmaz")
    check(info["insn"] == 7, "talimat sayısı başlıktan")


def real() -> None:
    go = next((Path(__file__).resolve().parents[3]
               / "workspaces/olcum_mac/runs/taban-v2-62ad154/tmux").glob(
        "ws/workspaces/*/*/static/ghidra_output/decompiled"))
    info = parse_function((go / "FUN_100001f98.c").read_text(), "FUN_100001f98")
    calls = [(c["hedef"], c["arg"]) for c in info["calls"]]
    check(info["params"][0]["ad"] == "param_1" and not info["params"][0]["degisti"],
          "FUN_100001f98: p1 değişmiyor")
    check(calls[0] == ("FUN_10009c114", ["param_1 + 0xf0", "0xffffffff"]),
          "FUN_100001f98: p1+0xf0 ofsetli argüman (p1 değil)")
    check(("FUN_100001fdc", ["*(undefined8 *)(lVar1 + 0x10)"]) in calls,
          "FUN_100001f98: alan yükleme argümanı")
    check(info["p1_alan"] is False, "FUN_100001f98: p1 doğrudan okunmuyor (yalnız adres)")
    info = parse_function((go / "FUN_1000a4ee8.c").read_text(), "FUN_1000a4ee8")
    calls = [(c["hedef"], c["arg"]) for c in info["calls"]]
    check(("FUN_1000a4d98", ["param_1", "1"]) in calls, "FUN_1000a4ee8: p1 → FUN_1000a4d98.p1")
    check([p["ad"] for p in info["params"]] == ["param_1", "param_2"], "FUN_1000a4ee8: iki parametre")


if __name__ == "__main__":
    synthetic()
    real()
    print("bütün denetimler geçti")
