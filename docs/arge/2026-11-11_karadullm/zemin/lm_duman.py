"""KaradulLM çekirdeğinin gerçek yerel sunucuyla duman testi: başlat, yokla, şemalı tek istek, bellek, kapat."""
import json, sys, time
from pathlib import Path
from karadul.lm.backend import LlamaServerBackend
from karadul.lm import probe, memory_guard, protocol
from karadul.lm.audit import AuditLog

cikti = Path(sys.argv[1]); cikti.mkdir(parents=True, exist_ok=True)
ikili = Path.home() / ".lmstudio/extensions/backends/llama.cpp-mac-arm64-apple-metal-advsimd-2.60.0/llama-server"
model = Path.home() / ".lmstudio/models/lmstudio-community/Qwen3.8-27B-GGUF/Qwen3.8-27B-Q4_K_M.gguf"
gunluk = AuditLog(cikti / "denetim.jsonl")
b = LlamaServerBackend(ikili, model, cikti / "durum", audit=gunluk, ready_timeout=300)
sonuc = {}
try:
    t0 = time.monotonic(); b.start(); sonuc["baslatma_sn"] = round(time.monotonic() - t0, 1)
    sonuc["saglik"] = b.health()
    sonuc["yetenek"] = getattr(b.capabilities(), "level", None)
    y = probe.run_probe(b, audit=gunluk)
    sonuc["yoklama"] = {k: v for k, v in y.as_dict().items() if k != "requests"}
    sonuc["T_ad_oner_sn"] = probe.expected_name_suggest_sec(y.prefill_tps, y.gen_tps)
    sonuc["kip"] = probe.decide_mode(sonuc["T_ad_oner_sn"])
    # Şemaya zorlanmış tek istek: yapay, ikili verisi içermeyen bir "ad öner" sorusu.
    iletiler = [{"role": "system", "content": "You name C functions. Answer only with the JSON object the schema requires."},
                {"role": "user", "content": "A function takes a pointer and a length, loops over the bytes and returns their sum modulo 256. "
                                            "Propose a C function name."}]
    t1 = time.monotonic()
    r = b.chat(iletiler, schema=protocol.NAME_ANSWER_SCHEMA, max_tokens=128, purpose="duman")
    sonuc["semali_istek"] = {"sure_sn": round(time.monotonic() - t1, 2), "finish_reason": r.finish_reason,
                             "icerik": r.content, "prompt_tokens": r.prompt_tokens}
    try:
        sonuc["semali_istek"]["sema_hukmu"] = str(protocol.parse_turn(r.content, r.finish_reason, protocol.NAME_ANSWER_SCHEMA))[:300]
    except Exception as e:
        sonuc["semali_istek"]["sema_hukmu"] = f"HATA {type(e).__name__}: {e}"[:300]
    m = memory_guard.measure_process(b.pid)
    sonuc["bellek"] = m.as_dict() if m else None
except Exception as e:
    sonuc["hata"] = f"{type(e).__name__}: {e}"[:500]
finally:
    try:
        b.stop("istek")
    except Exception as e:
        sonuc["durdurma_hatasi"] = f"{type(e).__name__}: {e}"[:300]
(cikti / "duman_sonuc.json").write_text(json.dumps(sonuc, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8")
print(json.dumps(sonuc, ensure_ascii=False, indent=1, default=str))
