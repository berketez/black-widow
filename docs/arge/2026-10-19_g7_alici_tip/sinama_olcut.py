#!/usr/bin/env python3
"""olcut.py ve deney.py için sentetik sınama (gerçek veri okumaz; sonuç ölçütü üretmez).

Kullanım: python3 -B sinama_olcut.py <geçici_dizin>
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deney  # noqa: E402
from olcut import (cluster_purity, prefix, prefix_set, propagate, purity_table,  # noqa: E402
                   shuffle_control, wilson)


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)
    print("tamam:", msg)


def main() -> None:
    tmp = Path(sys.argv[1])
    tmp.mkdir(parents=True, exist_ok=True)
    check(prefix("window_pane_resize", 1) == "window", "Ö1 ilk parça")
    check(prefix("window_pane_resize", 2) == "window_pane", "Ö2 üç parçada ilk iki")
    check(prefix("window_resize", 2) == "window", "Ö2 iki parçada ilk parça")
    check(prefix("xmalloc", 1) is None and prefix("xmalloc", 2) is None, "tek parça önek yok")
    check(prefix("CPUMeter_init", 1) == "CPUMeter", "CamelCase ilk parça")
    check(prefix("__x_y", 1) == "x", "baştaki fazla alt çizgi atlanır")
    check(prefix_set(["a_b_c", "a_d_e"], 2) == frozenset({"a_b", "a_d"}), "çok adlı GT")
    check(cluster_purity([frozenset({"a"}), frozenset({"a"}), frozenset({"b"})])[:2] == (2, 3),
          "küme saflığı 2/3")
    t = purity_table([[frozenset({"a"})] * 3, [frozenset({"a"}), frozenset({"b"})]])
    check(abs(t["agirlikli"] - 4 / 5) < 1e-12 and t["medyan"] == 0.75, "ağırlıklı 4/5, medyan 0,75")
    pure = [[frozenset({p})] * 5 for p in "abcdefghij"]
    c = shuffle_control(pure, 1)
    check(c["gercek"] == 1.0 and c["gecerli"], "saf ve farklı önekli kümeler kontrolü geçer")
    mixed = [[frozenset({"a"})] * 5 for _ in range(10)]
    c = shuffle_control(mixed, 1)
    check(not c["gecerli"], "tek önekli havuz: karışık da saf, kontrol geçmez")
    w = wilson(5, 10)
    check(w is not None and w[0] < 0.5 < w[1], "Wilson aralığı")
    cl = {"1": 0, "2": 0, "3": 0, "4": 1, "5": 1}
    members = {0: ["1", "2", "3"], 1: ["4", "5"]}
    gts = {"1": frozenset({"win"}), "2": frozenset({"win"}), "3": frozenset({"tty"}),
           "4": frozenset({"tty"}), "5": frozenset({"tty"})}
    r = propagate(["1", "2", "3", "4", "5"], cl, members, {"1": "win_set_x"}, gts, 1)
    check(r["oneri"]["k"] == 2 and r["kesinlik"]["k"] == 1, "yayılım: 2 öneri, 1 doğru")
    r = propagate(["1", "2", "3"], cl, members, {"1": "win_a_b", "2": "tty_a_b"}, gts, 1)
    check(r["oneri"]["k"] == 0 and r["celiski_sustu"] == 1, "çelişkide öneri yok")

    def fn(pop, gt, params, alan=True):
        return {"ad": "FUN_x", "pop": pop, "sinif": "program" if pop else "gt_disi", "gt": gt,
                "insn": 10, "durum": "tamam", "params": params, "p1_alan": alan}
    p = [["param_1", "long", False]]
    data = {
        "program": "sentetik", "kunye": {}, "c_durum": {"tamam": 6}, "evren": 6,
        "dogrudan_ic_cagri": 4, "cozulmeyen_FUN_cagri": 0, "pcode_v1_uyum": [3, 3],
        "funcs": {"a": fn(True, ["win_set_a"], p), "b": fn(True, ["win_get_b"], p),
                  "c": fn(True, ["tty_x_y"], p), "d": fn(True, ["tty_z_w"], p, False),
                  "e": fn(True, ["main"], []), "f": fn(False, None, p)},
        "v1": [["a", "b"], ["c", "d"], ["f", "a"]],
        "v2": [["a", 1, "b", 1], ["c", 1, "d", 1], ["f", 1, "a", 1], ["a", 1, "c", 2]],
        "tablo_kosulari": [["b", "c"]],
        "capa_g": [], "capa_o": {"a": "win_set_a"}, "capa_k": {"c": "tty_x_y"},
        "karadul_adlari": {},
    }
    res = deney.measure(data, "V1", tmp)
    check(res["kumeye_dusen"]["k"] == 4 and res["tekil"]["k"] == 1, "V1: 4 kümede, 1 tekil")
    check(res["capali"]["Ç-O"]["kapsam"]["k"] == 1, "V1: Ç-O çapalı kapsam yalnız b")
    check(res["duzey"]["Ö1"]["saflik"]["agirlikli"] == 1.0, "V1 Ö1 saflık 1")
    check(res["duzey"]["Ö2"]["saflik"]["agirlikli"] == 0.5, "V1 Ö2 saflık 0,5 (fiil parçası)")
    res = deney.measure(data, "V1-N", tmp)
    check(res["kumeye_dusen"]["k"] == 2, "V1-N: alan erişimsiz d'ye giden kenar düşer")
    res = deney.measure(data, "V1+T", tmp)
    check(res["kumeye_dusen"]["k"] == 4 and res["en_buyuk_kume"] == 5, "V1+T: tablo b-c birleşir")
    res = deney.measure(data, "V2", tmp)
    check(res["en_buyuk_kume"] == 3, "V2: a.p1 ≡ c.p2, c.p1 kümesi ayrı kalır")

    def per(p1, c1, p2, c2):
        d = {"Ö1": {"saflik": {"agirlikli": p1}, "negatif_kontrol": {"gecerli": c1}},
             "Ö2": {"saflik": {"agirlikli": p2}, "negatif_kontrol": {"gecerli": c2}}}
        return {"degiskenler": {"V1": {"duzey": d}}}
    r = deney.reading({"x": per(0.95, True, 0.92, True), "y": per(0.95, True, 0.92, True)})
    check(r["x"]["karar"] == "saf" and r["genel"] == "saf (iki programda da)", "okuma: saf")
    r = deney.reading({"x": per(0.95, True, 0.70, True), "y": per(0.80, False, 0.5, False)})
    check(r["x"]["karar"] == "yalnız Ö1 düzeyinde saf" and r["y"]["karar"] == "saf değil"
          and r["genel"] == "programa bağlı", "okuma: Ö1 düzeyinde / saf değil / programa bağlı")
    r = deney.reading({"x": per(0.95, False, 0.95, True)})
    check(r["x"]["karar"].startswith("geçersiz"), "okuma: eşik üstü ama kontrol geçmedi → geçersiz")
    print("bütün denetimler geçti")


if __name__ == "__main__":
    main()
