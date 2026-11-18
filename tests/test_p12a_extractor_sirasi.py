"""P12a kalem 1 — Faz 1 ad çıkarıcısında dizgi → fonksiyon sırası karma tohumundan bağımsız.

Kök neden (ölçüldü): ``BinaryNameExtractor._load_strings`` bir dizgiye başvuran fonksiyonları
``set``'te toplayıp listeye çeviriyordu. ``_strategy_string_intelligence`` bu listeyi dolaşıp
adı İLK uygun fonksiyona veriyor; sıra ``PYTHONHASHSEED``'e bağlıydı. Aynı girdi (Debian
``true``, GHIDRA-16 dizgi bağı açık) tohum 0 ↔ 7'de iki fonksiyona farklı ad veriyordu
(``org_team`` ↔ ``org_software``); ``sqlite3``'te 6 genel ad.

Bu test yama ``yamalar/P12a__binary_name_extractor.py.patch`` ile birlikte gelir: yamasız
kodda kırmızıdır.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Sekiz fonksiyon aynı dizgiye başvuruyor; xref sırası bilerek adres sırası değil.
_REFS = ["FUN_00008000", "FUN_00001000", "FUN_00007000", "FUN_00002000",
         "FUN_00006000", "FUN_00003000", "FUN_00005000", "FUN_00004000"]

_PROBE = r"""
import json, sys
from pathlib import Path
from karadul.reconstruction.binary_name_extractor import BinaryNameExtractor
ext = BinaryNameExtractor()
ext._load_strings(Path(sys.argv[1]))
print(json.dumps({str(k): v for k, v in ext._string_to_funcs.items()}))
"""


def _strings_json(tmp_path: Path) -> Path:
    xrefs = [{"from_address": f"0x{0x100 + i:x}", "from_function": fn,
              "from_func_addr": "0x" + fn[4:]} for i, fn in enumerate(_REFS)]
    # Yinelenen başvuru (aynı fonksiyondan ikinci xref) tekrar sayılmaz
    xrefs.append({"from_address": "0x900", "from_function": _REFS[2],
                  "from_func_addr": "0x" + _REFS[2][4:]})
    data = {"strings": [{"address": "0x20000", "value": "telemetry queue drained",
                         "length": 23, "type": "string", "xrefs": xrefs}]}
    path = tmp_path / "ghidra_strings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_string_to_funcs_xref_sirasinda_ve_tohumdan_bagimsiz(tmp_path: Path) -> None:
    path = _strings_json(tmp_path)
    env_base = {k: v for k, v in os.environ.items() if k != "PYTHONHASHSEED"}
    sonuclar = {}
    for tohum in ("0", "7", "99", "1234"):
        out = subprocess.run(
            [sys.executable, "-c", _PROBE, str(path)], cwd=REPO_ROOT, check=True,
            capture_output=True, text=True,
            env={**env_base, "PYTHONHASHSEED": tohum, "PYTHONDONTWRITEBYTECODE": "1",
                 "PYTHONPATH": str(REPO_ROOT)},
        )
        sonuclar[tohum] = json.loads(out.stdout.strip().splitlines()[-1])
    for tohum, harita in sonuclar.items():
        assert harita == {str(0x20000): _REFS}, f"PYTHONHASHSEED={tohum}: {harita}"
