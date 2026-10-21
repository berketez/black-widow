"""c_namer belirlenimcilik testleri — ÖL-7 (plan v2.2 G9) düzeltmesi.

ÖL-7 ölçümü (docs/arge/2026-10-21_g9_n0/ol7_sonuc.md): aynı commit'le iki koşu
yalnız çakışma son eklerinde (`_2`, `_3` …) ayrışıyordu. İki kaynak vardı:

  A. İşçi sonuçları `as_completed` (bitiş) sırasıyla birleştiriliyordu. Anahtar
     sırası, dolayısıyla son ek ataması ve farklı işçilerden gelen eşit güvenli
     adayların hangisinin kazandığı zamanlamaya bağlıydı.
  B. Fonksiyon içinde `set` dolaşımı: `_strategy_dataflow` (local/DAT_/auto
     değişkenleri), `_strategy_api_call` (tek API ipucu, baskın çağrılan) ve
     `_strategy_call_graph` (callee_based) sırası karma tohumuna
     (PYTHONHASHSEED) bağlıydı.

Bu testler çıktının (naming_map.json, isimlendirilmiş .c dosyaları,
naming_provenance.json, CNamingResult) bitiş sırasından ve karma tohumundan
bağımsız olduğunu kilitler. Düzeltmesiz kodda ikisi de kırmızıdır.
"""
from __future__ import annotations

import concurrent.futures as cf
import dataclasses
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from typing import Any

from karadul.config import Config
from karadul.reconstruction import c_namer
from karadul.reconstruction.c_namer import CVariableNamer

REPO_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Sentetik Ghidra çıktısı
# ---------------------------------------------------------------------------

# A: dört fonksiyon aynı klasik ada çıkar ("telemetry_sampler_queue") ve her biri
# aynı yerel adları üretir (param_1 -> "s", local_8 -> "len"): işlevler arası
# çakışma; son eki kimin alacağı anahtar sırasına bağlı.
_DUP_STRINGS = [
    "telemetry sampler queue drained",
    "telemetry sampler queue stalled",
    "telemetry sampler queue resumed",
    "telemetry sampler queue flushed",
]
_DUP_FUNCS = ["FUN_00001000", "FUN_00002000", "FUN_00003000", "FUN_00004000"]

# B: tek fonksiyonda son 4 hanesi aynı beş DAT_ -> beşi de "global_1234" (0.3);
# son ek sırası dataflow'un DAT_ dolaşım sırasına bağlı.
_DATS = ["DAT_00011234", "DAT_00021234", "DAT_00031234", "DAT_00041234", "DAT_00051234"]
# B: eşit güvenli (0.5) tek API ipuçları, ortak combo yok -> api_call ve
# callee_based adayının öneki dolaşım sırasına bağlı.
_TIED_APIS = ["memcpy", "memmove", "memset"]
# B: eşit uzunlukta, ipucu tablolarında olmayan çağrılanlar -> baskın çağrılan
# (api_call 3. dal) sıralama anahtarına bağlı.
_DOMINANT = ["lib_alpha", "lib_gamma"]
# B: tek fonksiyonda free() ile kullanılan dört local_XX ve dört uVarN. Anahtarları
# ilk ekleyen dataflow (free(PARAM) -> "buffer"); kazanan ad api_param'dan ("ptr").
# Sekizi aynı ada çıktığı için son ek sırası dataflow'un local/auto dolaşımına bağlı.
_FREED_LOCALS = ["local_28", "local_10", "local_20", "local_18"]
_FREED_AUTOS = ["uVar3", "uVar1", "uVar4", "uVar2"]


_FUNCS: list[tuple[str, str, list[tuple[str, str]], str, str]] = []
_BODIES: dict[str, str] = {}
for _i, _fn in enumerate(_DUP_FUNCS):
    _addr = _fn[4:]
    _FUNCS.append((_fn, _addr, [("param_1", "char *")], "int", _DUP_STRINGS[_i]))
    _BODIES[_fn] = (
        f"int {_fn}(char *param_1)\n{{\n  int local_8;\n"
        "  local_8 = strlen(param_1);\n  return local_8;\n}\n"
    )
# A: iki farklı çağıran aynı geri çağrıya eşit güvenle (0.75) farklı ad önerir
_FUNCS += [
    ("FUN_00005000", "00005000", [], "void", ""),
    ("FUN_00006000", "00006000", [], "void", ""),
    ("FUN_0000c000", "0000c000", [], "void", ""),
    ("FUN_00007000", "00007000", [], "void", ""),
    ("FUN_00008000", "00008000", [("param_1", "char *"), ("param_2", "char *")],
     "void", "checksum ledger reconciliation pass"),
    ("FUN_00009000", "00009000", [], "void", "archive index compaction sweep"),
    ("FUN_0000a000", "0000a000", [], "void", ""),
]
_BODIES["FUN_00005000"] = "void FUN_00005000(void)\n{\n  atexit(FUN_0000c000);\n  return;\n}\n"
_BODIES["FUN_00006000"] = "void FUN_00006000(void)\n{\n  signal(2,FUN_0000c000);\n  return;\n}\n"
_BODIES["FUN_0000c000"] = "void FUN_0000c000(void)\n{\n  return;\n}\n"
_BODIES["FUN_00007000"] = (
    "void FUN_00007000(void)\n{\n"
    + "".join(f"  {d} = {k + 1};\n" for k, d in enumerate(_DATS))
    + "  return;\n}\n"
)
_BODIES["FUN_00008000"] = (
    "void FUN_00008000(char *param_1,char *param_2)\n{\n"
    + "".join(f"  {api}(param_1,param_2,8);\n" for api in _TIED_APIS)
    + "  return;\n}\n"
)
_BODIES["FUN_0000a000"] = (
    "void FUN_0000a000(void)\n{\n"
    + "".join(f"  long {v};\n" for v in _FREED_LOCALS)
    + "".join(f"  undefined8 {v};\n" for v in _FREED_AUTOS)
    + "".join(f"  free({v});\n" for v in _FREED_LOCALS + _FREED_AUTOS)
    + "  return;\n}\n"
)
_BODIES["FUN_00009000"] = (
    "void FUN_00009000(void)\n{\n"
    + "".join(f"  {c}();\n" for c in _DOMINANT)
    + "  return;\n}\n"
)


def build_workspace(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True)
    decompiled = root / "decompiled"
    decompiled.mkdir()
    functions = {"functions": [
        {"name": n, "address": a, "size": 64, "return_type": r,
         "parameters": [{"name": p, "type": t, "ordinal": k}
                        for k, (p, t) in enumerate(params)]}
        for n, a, params, r, _s in _FUNCS
    ]}
    strings = {"strings": [
        {"address": f"0002{k:04x}", "value": s, "length": len(s), "type": "string",
         "function": a}
        for k, (_n, a, _p, _r, s) in enumerate(_FUNCS) if s
    ]}
    names = {a: n for n, a, *_ in _FUNCS}
    edges = [("00005000", "0000c000"), ("00006000", "0000c000")]
    call_graph = {
        "nodes": {a: {"name": n, "address": a} for a, n in names.items()},
        "edges": [{"from": s, "to": d, "from_name": names[s], "to_name": names[d]}
                  for s, d in edges],
    }
    paths = {
        "functions": root / "ghidra_functions.json",
        "strings": root / "ghidra_strings.json",
        "call_graph": root / "ghidra_call_graph.json",
        "decompiled": decompiled,
    }
    paths["functions"].write_text(json.dumps(functions), encoding="utf-8")
    paths["strings"].write_text(json.dumps(strings), encoding="utf-8")
    paths["call_graph"].write_text(json.dumps(call_graph), encoding="utf-8")
    for n, a, *_ in _FUNCS:
        (decompiled / f"{n}.c").write_text(
            f"// Function: {n}\n// Address: {a}\n\n{_BODIES[n]}", encoding="utf-8")
    return paths


class _SerialExecutor:
    """ProcessPoolExecutor yerine: aynı süreçte, gönderim sırasıyla çalıştırır."""

    def __init__(self, max_workers=None, initializer=None, initargs=()):
        if initializer is not None:
            initializer(*initargs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, fn, *args, **kwargs):
        fut: cf.Future = cf.Future()
        try:
            fut.set_result(fn(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001 - Future'a aynen taşınır
            fut.set_exception(exc)
        return fut


def _outputs(out: Path, result: Any) -> dict[str, Any]:
    files = {p.name: p.read_bytes() for p in sorted(out.iterdir()) if p.is_file()}
    fields = dataclasses.asdict(result)
    fields["output_files"] = [Path(p).name for p in fields["output_files"]]
    return {"files": files, "result": fields}


def _run(ws: dict[str, Path], out: Path) -> Any:
    namer = CVariableNamer(Config(), min_confidence=0.15)
    result = namer.analyze_and_rename(
        ws["decompiled"], ws["functions"], ws["strings"], ws["call_graph"], out)
    assert result.success, result.errors
    return result


# ---------------------------------------------------------------------------
# A: bitiş sırası
# ---------------------------------------------------------------------------

def _completion_orders(n: int) -> dict[str, list[int]]:
    shuffled = list(range(n))
    random.Random(20261021).shuffle(shuffled)
    return {"gonderim": list(range(n)), "ters": list(range(n))[::-1], "karisik": shuffled}


def test_output_independent_of_completion_order(tmp_path, monkeypatch):
    """İşçi sonuçları hangi sırada biterse bitsin çıktı bayt bayt aynı."""
    ws = build_workspace(tmp_path / "ws")
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", _SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)

    outputs = {}
    for label, order in _completion_orders(len(_FUNCS)).items():
        def permuted(fs, timeout=None, _order=order):
            futs = list(fs)
            return [futs[i] for i in _order]
        monkeypatch.setattr(c_namer, "as_completed", permuted)
        out = tmp_path / f"out_{label}"
        outputs[label] = _outputs(out, _run(ws, out))

    ref = outputs["gonderim"]
    # Fikstür gerçekten çakışma ve eşitlik içeriyor (boş karşılaştırma değil)
    nm = json.loads(ref["files"]["naming_map.json"])
    assert sorted(nm["global"][f] for f in _DUP_FUNCS) == [
        "telemetry_sampler_queue", "telemetry_sampler_queue_2",
        "telemetry_sampler_queue_3", "telemetry_sampler_queue_4"]
    assert nm["global"]["FUN_0000c000"] in ("exit_handler", "signal_handler")
    for label in ("ters", "karisik"):
        got = outputs[label]
        assert got["files"].keys() == ref["files"].keys()
        for name in ref["files"]:
            assert got["files"][name] == ref["files"][name], f"{label}: {name} farklı"
        assert got["result"] == ref["result"], label


def test_equal_confidence_cross_worker_tie_goes_to_lower_index(tmp_path, monkeypatch):
    """Farklı işçilerden eşit güvenli iki aday: gönderim sırasında önce gelen kazanır."""
    ws = build_workspace(tmp_path / "ws")
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", _SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)
    monkeypatch.setattr(c_namer, "as_completed", lambda fs, timeout=None: list(fs)[::-1])
    out = tmp_path / "out"
    _run(ws, out)
    nm = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))
    # FUN_00005000 (atexit) FUN_00006000'dan (signal) önce gönderilir
    assert nm["global"]["FUN_0000c000"] == "exit_handler"
    assert nm["global"]["FUN_00001000"] == "telemetry_sampler_queue"


# ---------------------------------------------------------------------------
# B: karma tohumu (PYTHONHASHSEED)
# ---------------------------------------------------------------------------

_SUBPROCESS_RUN = r"""
import concurrent.futures as cf, sys
from pathlib import Path
from karadul.config import Config
from karadul.reconstruction import c_namer

class _Serial:
    def __init__(self, max_workers=None, initializer=None, initargs=()):
        if initializer is not None:
            initializer(*initargs)
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False
    def submit(self, fn, *args, **kwargs):
        fut = cf.Future()
        fut.set_result(fn(*args, **kwargs))
        return fut

c_namer.ProcessPoolExecutor = _Serial
c_namer.as_completed = lambda fs, timeout=None: list(fs)
ws, out = Path(sys.argv[1]), Path(sys.argv[2])
res = c_namer.CVariableNamer(Config(), min_confidence=0.15).analyze_and_rename(
    ws / "decompiled", ws / "ghidra_functions.json", ws / "ghidra_strings.json",
    ws / "ghidra_call_graph.json", out)
assert res.success, res.errors
print(c_namer.__file__)
"""

_HASH_SEEDS = ("0", "1", "2", "3", "4", "5")


def test_output_independent_of_hash_seed(tmp_path):
    """Farklı PYTHONHASHSEED ile (sabit gönderim sırası) çıktı bayt bayt aynı."""
    build_workspace(tmp_path / "ws")
    env_base = {k: v for k, v in os.environ.items() if k != "PYTHONHASHSEED"}
    env_base["PYTHONPATH"] = str(REPO_ROOT)
    procs = {}
    for seed in _HASH_SEEDS:
        out = tmp_path / f"out_seed{seed}"
        procs[seed] = (out, subprocess.Popen(
            [sys.executable, "-c", _SUBPROCESS_RUN, str(tmp_path / "ws"), str(out)],
            cwd=REPO_ROOT, env={**env_base, "PYTHONHASHSEED": seed},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    files = {}
    for seed, (out, proc) in procs.items():
        stdout, stderr = proc.communicate(timeout=300)
        assert proc.returncode == 0, stderr[-2000:]
        # Alt süreç bu testle aynı c_namer'ı yükledi
        assert Path(stdout.strip().splitlines()[-1]).resolve() == Path(c_namer.__file__).resolve()
        files[seed] = {p.name: p.read_bytes() for p in sorted(out.iterdir()) if p.is_file()}

    ref = files[_HASH_SEEDS[0]]
    nm = json.loads(ref["naming_map.json"])
    assert sorted(nm["global"][d] for d in _DATS) == [
        "global_1234", "global_1234_2", "global_1234_3", "global_1234_4", "global_1234_5"]
    assert sorted(nm["per_function"]["FUN_0000a000"].values()) == [
        "ptr", "ptr_2", "ptr_3", "ptr_4", "ptr_5", "ptr_6", "ptr_7", "ptr_8"]
    for seed in _HASH_SEEDS[1:]:
        assert files[seed].keys() == ref.keys()
        for name in ref:
            assert files[seed][name] == ref[name], f"PYTHONHASHSEED={seed}: {name} farklı"


def test_function_internal_order_is_source_order(tmp_path, monkeypatch):
    """B'nin sözleşmesi: DAT_ son ekleri kaynak sırasıyla; eşit ipuçlarında ad sırası."""
    ws = build_workspace(tmp_path / "ws")
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", _SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)
    monkeypatch.setattr(c_namer, "as_completed", lambda fs, timeout=None: list(fs))
    out = tmp_path / "out"
    _run(ws, out)
    nm = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))
    assert [nm["global"][d] for d in _DATS] == [
        "global_1234", "global_1234_2", "global_1234_3", "global_1234_4", "global_1234_5"]
    prov = json.loads((out / "naming_provenance.json").read_text(encoding="utf-8"))
    tied = {r["strategy"]: r["new_name"] for r in prov["global"]["FUN_00008000"]["runners_up"]}
    assert tied["api_call"] == "copy_8000"        # memcpy < memmove < memset
    assert tied["callee_based"] == "copy_8000"
    dominant = {r["strategy"]: r["new_name"] for r in prov["global"]["FUN_00009000"]["runners_up"]}
    assert dominant["api_call"] == "calls_lib_gamma"   # eşit uzunlukta ad sırasıyla son
    # local_XX ve uVarN: gövdede ilk görülme sırası (dataflow anahtarı ilk ekler)
    locals_ = nm["per_function"]["FUN_0000a000"]
    assert [locals_[v] for v in _FREED_LOCALS + _FREED_AUTOS] == [
        "ptr", "ptr_2", "ptr_3", "ptr_4", "ptr_5", "ptr_6", "ptr_7", "ptr_8"]
