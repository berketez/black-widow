"""G8: MaxSMT ofset çıkarımının doğrulanması (salt okur deney).

Şüphe (Onuncu Adam, plan v2 §2 madde 4): computation_struct_recovery.py
LOAD/STORE girdileri arasında 4096'dan küçük ilk sabiti ofset sayıyor. p-code'da
LOAD/STORE'un 0. girdisi adres uzayı kimliğini taşıyan bir sabittir; o hâlde
çıkarılan "ofset"lerin büyük kısmı tek bir değerde (uzay kimliği) toplanır.

Kullanım: maxsmt_ofset.py <pcode.jsonl>
Çıktı: çıkarılan ofsetlerin dağılımı ve LOAD/STORE 0. girdisinin sabit değerleri.
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/Users/apple/Black_Widow")
from karadul.analyzers.pcode_analyzer import PcodeAnalyzer  # noqa: E402
from karadul.pipeline.steps.computation_struct_recovery import (  # noqa: E402
    _extract_accesses_per_function,
)

jsonl = Path(sys.argv[1])
res = PcodeAnalyzer().analyze_streaming(jsonl)
per_fn = _extract_accesses_per_function(res)
offsets = Counter(a.offset for accs in per_fn.values() for a in accs)
total = sum(offsets.values())

space_ids: Counter = Counter()
first_const_is_input0 = 0
loadstore = 0
for fn in res.functions:
    for op in getattr(fn, "ops", []) or []:
        if getattr(op, "mnemonic", "") not in ("LOAD", "STORE"):
            continue
        loadstore += 1
        inputs = getattr(op, "inputs", []) or []
        if inputs and getattr(inputs[0], "is_constant", False):
            space_ids[int(getattr(inputs[0], "offset", -1))] += 1
        for i, inp in enumerate(inputs):
            if getattr(inp, "is_constant", False) and getattr(inp, "offset", None) is not None \
                    and 0 <= int(inp.offset) < 4096:
                if i == 0:
                    first_const_is_input0 += 1
                break

summary = {
    "pcode": str(jsonl),
    "fonksiyon": len(res.functions),
    "load_store": loadstore,
    "cikarilan_erisim": total,
    "farkli_ofset": len(offsets),
    "en_sik_ofsetler": offsets.most_common(10),
    "en_sik_ofset_payi": round(offsets.most_common(1)[0][1] / total, 4) if total else None,
    "load_store_girdi0_sabit_degerleri": space_ids.most_common(5),
    "ofsetin_girdi0_dan_alindigi_load_store": first_const_is_input0,
}
print(json.dumps(summary, ensure_ascii=False, indent=1))
