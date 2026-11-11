"""Şemaya zorlanmış araç çağrısı zarfı denemesi (zemin ölçümü, 2026-11-11; tasarım §3.1 Yol A, Z5).

Pilotun yalın bayraklarıyla (`--cache-ram 0 --ctx-checkpoints 0`) bir `llama-server` başlatır; tek JSON zarfı
şemasını (`anyOf`: araç başına bir nesne + `final`, ortak `properties` yok) `response_format` ile verip
10 yapay istek gönderir. Her yanıtı elle yazılmış katı doğrulayıcıyla denetler (jsonschema paketi
kuruluysa onunla da). Girdi yapaydır; adresler uydurmadır, ikiliden veri yoktur.

Sunucu yalnız 127.0.0.1'e bağlanır; --api-key `secrets.token_hex` ile üretilir, kayda "<gizli>" yazılır.

Kullanım: python3 -I sema_denemesi.py --cikti sema_denemesi.json --gunluk /scratch/sema.log
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

SABLON = Path("/Users/apple/Black_Widow/workspaces/2026-10-19_g6_pilot/sablon/qwen38_chat-template.jinja")
PORT = 8139

import sys
sys.dont_write_bytecode = True
sys.path.insert(0, "/Users/apple/Black_Widow/scripts/measurement")
import llm_pilot  # noqa: E402 — bayraklar pilotun kendi komut kurucusundan alınır (sabit tekrar yok)


def pilot_komutu(port: int, cikar: tuple[str, ...] = ()) -> list[str]:
    """Pilotun yalın llama-server komutu (llm_pilot.LlamaSunucu.komut), port değiştirilmiş;
    `cikar`daki bayraklar değerleriyle birlikte çıkarılır."""
    k = llm_pilot.LlamaSunucu(sablon=SABLON, port=port).komut(llm_pilot.MODELLER["qwen38"])
    out, i = [], 0
    while i < len(k):
        if k[i] in cikar:
            i += 2
            continue
        out.append(k[i])
        i += 1
    return out


ADRES = {"type": "string", "pattern": "^0x[0-9a-f]{1,16}$"}
AD = {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,63}$"}


def cagri(arac: str, args_props: dict) -> dict:
    return {"type": "object",
            "properties": {"kind": {"const": "call"}, "tool": {"const": arac},
                           "args": {"type": "object", "properties": args_props,
                                    "required": list(args_props), "additionalProperties": False}},
            "required": ["kind", "tool", "args"], "additionalProperties": False}


ZARF = {"anyOf": [
    cagri("get_evidence", {"address": ADRES}),
    cagri("get_decompiled", {"address": ADRES}),
    cagri("get_xrefs", {"address": ADRES, "direction": {"enum": ["to", "from"]}}),
    cagri("propose_name", {"address": ADRES, "name": AD, "reason": {"type": "string", "maxLength": 200}}),
    {"type": "object", "properties": {"kind": {"const": "final"}, "text": {"type": "string", "maxLength": 400}},
     "required": ["kind", "text"], "additionalProperties": False},
]}

SISTEM = ("Bir tersine mühendislik asistanısın. Her turda YALNIZ tek bir JSON nesnesi yaz.\n"
          "Araç çağırmak için: {\"kind\":\"call\",\"tool\":<ad>,\"args\":{...}}. Araçlar:\n"
          "- get_evidence {address}  - get_decompiled {address}  - get_xrefs {address, direction: to|from}\n"
          "- propose_name {address, name, reason}\n"
          "Bitirmek için: {\"kind\":\"final\",\"text\":<kısa açıklama>}. Adresler küçük harfli 0x… biçimindedir.")

# Yapay görevler (uydurma adresler)
GOREVLER = [
    "0x1000a3f0 adresindeki fonksiyonun kanıtını getir.",
    "0x10002b10 fonksiyonunun decompile çıktısını iste.",
    "0x10004c88 fonksiyonunu kimler çağırıyor? Gelen başvuruları iste.",
    "0x10007d20 fonksiyonu yalnız bir tamponu sıfırlıyor; ona ad öner.",
    "0x1000f004 fonksiyonunun çağırdığı fonksiyonları (giden başvurular) iste.",
    "Elimde yeterli kanıt yok; kullanıcıya bunu söyleyerek bitir.",
    "0x100013a0 adresindeki fonksiyon bir sağlama toplamı hesaplıyor; ad öner.",
    "0x1000beef fonksiyonunun kanıt paketini getir.",
    "0x10009000 için decompile metnini getir.",
    "İş bitti; üç fonksiyona ad önerildiğini özetleyerek bitir.",
]


def dogrula(nesne) -> tuple[bool, str]:
    """ZARF'ın elle yazılmış katı denetimi: tam olarak bir dala uymalı."""
    if not isinstance(nesne, dict):
        return False, "nesne değil"
    def uy(sema: dict, d) -> bool:
        if not isinstance(d, dict) or set(d) != set(sema["required"]):
            return False
        for k, alt in sema["properties"].items():
            v = d[k]
            if "const" in alt and v != alt["const"]:
                return False
            if "enum" in alt and v not in alt["enum"]:
                return False
            if alt.get("type") == "string":
                if not isinstance(v, str):
                    return False
                if "pattern" in alt and not re.search(alt["pattern"], v):
                    return False
                if "maxLength" in alt and len(v) > alt["maxLength"]:
                    return False
            if alt.get("type") == "object" and not uy(alt, v):
                return False
        return True
    eslesen = [i for i, s in enumerate(ZARF["anyOf"]) if uy(s, nesne)]
    return (len(eslesen) == 1, f"eşleşen dal {eslesen}")


def footprint_gib(pid: int):
    try:
        r = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"Footprint:\s*([\d.]+)\s*(KB|MB|GB)", r.stdout)
    return None if not m else float(m.group(1)) * {"KB": 1 / 1048576, "MB": 1 / 1024, "GB": 1.0}[m.group(2)]


def bellek(pid: int) -> dict:
    r = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    rss = int(r.stdout.strip()) / 1048576 if r.stdout.strip() else 0.0
    fp = footprint_gib(pid) or 0.0
    return {"rss_gib": round(rss, 3), "footprint_gib": round(fp, 3), "ust_gib": round(rss + fp, 3)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cikti", type=Path, required=True)
    ap.add_argument("--gunluk", type=Path, required=True)
    ap.add_argument("--esik", type=float, default=22.0)
    ns = ap.parse_args()
    once = subprocess.run(["pgrep", "-fl", "llama-server"], capture_output=True, text=True).stdout.strip()
    if once:
        raise SystemExit(f"başka llama-server çalışıyor, durdum: {once}")
    try:
        import jsonschema  # type: ignore
    except ImportError:
        jsonschema = None
    anahtar = secrets.token_hex(16)
    komut = pilot_komutu(PORT) + ["--api-key", anahtar]
    kayit = {"komut": [("<gizli>" if x == anahtar else x) for x in komut], "zarf_semasi": ZARF, "sistem": SISTEM,
             "baslangic": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "yuk_once": [round(x, 2) for x in os.getloadavg()],
             "jsonschema_paketi": None if jsonschema is None else getattr(jsonschema, "__version__", "?"),
             "denemeler": []}
    gunluk = open(ns.gunluk, "wb")
    surec = subprocess.Popen(komut, stdout=gunluk, stderr=subprocess.STDOUT, process_group=0)
    tepe = {"ust_gib": 0.0}
    dur = threading.Event()

    def bekci():
        nonlocal tepe
        while not dur.is_set() and surec.poll() is None:
            b = bellek(surec.pid)
            if b["ust_gib"] > tepe["ust_gib"]:
                tepe = b
            if b["ust_gib"] > ns.esik:
                kayit["bekci_asimi"] = b
                surec.terminate()
                return
            dur.wait(1.5)

    try:
        t0 = time.time()
        while True:
            if surec.poll() is not None:
                raise RuntimeError(f"llama-server erken çıktı ({surec.returncode})")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=5) as r:
                    if r.status == 200:
                        break
            except (urllib.error.URLError, OSError):
                pass
            if time.time() - t0 > 600:
                raise RuntimeError("hazır olmadı")
            time.sleep(1)
        threading.Thread(target=bekci, daemon=True).start()
        for i, g in enumerate(GOREVLER):
            govde = {"model": "qwen38", "temperature": 0, "seed": 20261019, "max_tokens": 256, "stream": False,
                     "chat_template_kwargs": {"enable_thinking": False},
                     "messages": [{"role": "system", "content": SISTEM}, {"role": "user", "content": g}],
                     "response_format": {"type": "json_schema",
                                         "json_schema": {"name": "zarf", "strict": True, "schema": ZARF}}}
            istek = urllib.request.Request(f"http://127.0.0.1:{PORT}/v1/chat/completions",
                                           data=json.dumps(govde).encode(),
                                           headers={"Content-Type": "application/json",
                                                    "Authorization": f"Bearer {anahtar}"})
            d = {"i": i, "gorev": g}
            t1 = time.time()
            try:
                with urllib.request.urlopen(istek, timeout=600) as y:
                    yanit = json.load(y)
                d["sure_sn"] = round(time.time() - t1, 3)
                secim = (yanit.get("choices") or [{}])[0]
                icerik = (secim.get("message") or {}).get("content") or ""
                d["bitis"] = secim.get("finish_reason")
                d["icerik"] = icerik
                d["usage"] = yanit.get("usage")
                d["timings"] = yanit.get("timings")
                try:
                    nesne = json.loads(icerik)
                    d["json_gecerli"] = True
                    d["sema_uygun"], d["aciklama"] = dogrula(nesne)
                    if jsonschema is not None:
                        try:
                            jsonschema.validate(nesne, ZARF)
                            d["jsonschema_uygun"] = True
                        except jsonschema.ValidationError as e:  # type: ignore[attr-defined]
                            d["jsonschema_uygun"] = False
                            d["jsonschema_hata"] = str(e)[:200]
                except json.JSONDecodeError as e:
                    d["json_gecerli"], d["sema_uygun"], d["aciklama"] = False, False, str(e)[:120]
            except urllib.error.HTTPError as e:
                d["sure_sn"] = round(time.time() - t1, 3)
                d["http_hata"] = f"{e.code}: {e.read()[:300].decode(errors='replace')}"
                d["sema_uygun"] = False
            kayit["denemeler"].append(d)
    except Exception as e:  # noqa: BLE001
        kayit["hata"] = f"{type(e).__name__}: {e}"
    finally:
        dur.set()
        if surec.poll() is None:
            surec.terminate()
            try:
                surec.wait(timeout=60)
            except subprocess.TimeoutExpired:
                surec.kill()
                surec.wait(timeout=60)
        gunluk.close()
    den = kayit["denemeler"]
    kayit["ozet"] = {"deneme": len(den), "sema_uygun": sum(1 for d in den if d.get("sema_uygun")),
                     "json_gecerli": sum(1 for d in den if d.get("json_gecerli")),
                     "ortalama_sure_sn": round(sum(d.get("sure_sn", 0) for d in den) / len(den), 3) if den else None,
                     "bellek_tepe": tepe}
    kayit["gunluk_dilbilgisi_satirlari"] = [s[:220] for s in ns.gunluk.read_text(errors="replace").splitlines()
                                            if re.search(r"grammar|schema|json", s, re.I)][:15]
    kayit["bitis"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    kayit["sonra_pgrep"] = subprocess.run(["pgrep", "-fl", "llama-server"], capture_output=True, text=True).stdout.strip()
    ns.cikti.write_text(json.dumps(kayit, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(kayit["ozet"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
