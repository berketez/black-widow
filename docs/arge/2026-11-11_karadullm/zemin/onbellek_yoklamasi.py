"""Önek önbelleği yoklaması (zemin ölçümü, 2026-11-11).

Bir `llama-server` yapılandırmasını başlatır, uzun ortak önekli üç ardışık istek gönderir, sunucuyu kapatır.
Girdi tamamen yapaydır (sabit tohumla üretilmiş sözcük dizisi); ikiliden veri içermez.

İstekler (düşünme kapalı, sıcaklık 0):
- r1: sistem (uzun yapay metin) + kullanıcı u1
- r2 "ek": r1'in iletileri + r1'in yanıtı (asistan) + kullanıcı u2  -> ajan döngüsünün büyüyen konuşması
- r3 "dal": aynı sistem + farklı kullanıcı u3                      -> pilotun deseni (ortak sistem istemi)

Her istek için: usage.prompt_tokens, usage.prompt_tokens_details.cached_tokens, timings.prompt_n,
timings.cache_n, timings.prompt_ms, duvar saati. Bellek: arka planda her ~1,5 sn `llama-server` için
RSS (`ps`) + phys_footprint (`footprint -p`); üst sınır = RSS + footprint (pilot tanımı).
Üst sınır --esik GiB'ı aşarsa sunucu sonlandırılır ve yapılandırma "sığmadı" olarak yazılır.

Sunucu yalnız 127.0.0.1'e bağlanır; --api-key her koşuda `secrets.token_hex` ile üretilir ve kayda
"<gizli>" olarak geçer.

Kullanım:
  python3 -I onbellek_yoklamasi.py --ad a --cikti sonuc_a.json --gunluk /scratch/a.log -- --cache-ram 0 --ctx-checkpoints 0
  ("--" sonrası, yalın temel bayraklara EKLENEN bayraklardır.)
"""
from __future__ import annotations

import argparse
import json
import random
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

YOKLAMA_METIN_TOHUMU = 20261111


YAPAY_SOZCUK_LISTESI = ("register stack frame pointer offset buffer length index table entry handler callback symbol "
          "section segment header field value flag mask count size limit cursor parser token stream reader "
          "writer encoder decoder checksum digest key cipher block state context session socket packet queue "
          "worker thread mutex lock signal timer event loop dispatch route config option argument result "
          "error status code string array list map node tree graph edge vertex path file directory archive").split()


def yapay_metin(n_sozcuk: int, rnd: random.Random) -> str:
    satirlar = []
    for i in range(0, n_sozcuk, 12):
        s = " ".join(rnd.choice(YAPAY_SOZCUK_LISTESI) for _ in range(12))
        satirlar.append(f"{i // 12 + 1:04d}. {s} {rnd.randint(0, 65535):#06x}.")
    return "\n".join(satirlar)


def footprint_gib(pid: int):
    try:
        r = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"Footprint:\s*([\d.]+)\s*(KB|MB|GB)", r.stdout)
    return None if not m else float(m.group(1)) * {"KB": 1 / 1048576, "MB": 1 / 1024, "GB": 1.0}[m.group(2)]


def rss_gib(pid: int):
    r = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    return int(r.stdout.strip()) / 1048576 if r.stdout.strip() else None


class Bekci(threading.Thread):
    def __init__(self, surec: subprocess.Popen, esik: float):
        super().__init__(daemon=True)
        self.surec, self.esik = surec, esik
        self.tepe = {"rss_gib": 0.0, "footprint_gib": 0.0, "ust_gib": 0.0}
        self.asim = None
        self.dur = threading.Event()

    def ornek(self) -> dict:
        rss = rss_gib(self.surec.pid) or 0.0
        fp = footprint_gib(self.surec.pid) or 0.0
        o = {"rss_gib": round(rss, 3), "footprint_gib": round(fp, 3), "ust_gib": round(rss + fp, 3)}
        if o["ust_gib"] > self.tepe["ust_gib"]:
            self.tepe = o
        return o

    def run(self):
        while not self.dur.is_set() and self.surec.poll() is None:
            o = self.ornek()
            if o["ust_gib"] > self.esik:
                self.asim = {"zaman": time.strftime("%H:%M:%S"), **o}
                self.surec.terminate()
                return
            self.dur.wait(1.5)


def istek(anahtar: str, govde: dict) -> tuple[dict, float]:
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}/v1/chat/completions", data=json.dumps(govde).encode(),
                               headers={"Content-Type": "application/json", "Authorization": f"Bearer {anahtar}"})
    t0 = time.time()
    with urllib.request.urlopen(r, timeout=900) as y:
        d = json.load(y)
    return d, time.time() - t0


def ozet(d: dict, sure: float) -> dict:
    u = d.get("usage") or {}
    t = d.get("timings") or {}
    return {"sure_sn": round(sure, 3), "prompt_tokens": u.get("prompt_tokens"),
            "cached_tokens": (u.get("prompt_tokens_details") or {}).get("cached_tokens"),
            "completion_tokens": u.get("completion_tokens"),
            "timings_prompt_n": t.get("prompt_n"), "timings_cache_n": t.get("cache_n"),
            "timings_prompt_ms": t.get("prompt_ms"), "prompt_per_second": t.get("prompt_per_second"),
            "predicted_n": t.get("predicted_n"), "predicted_per_second": t.get("predicted_per_second")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ad", required=True)
    ap.add_argument("--cikti", type=Path, required=True)
    ap.add_argument("--gunluk", type=Path, required=True)
    ap.add_argument("--esik", type=float, default=22.0)
    ap.add_argument("--sozcuk", type=int, default=2200)
    ap.add_argument("ek", nargs="*")
    ns = ap.parse_args()

    once = subprocess.run(["pgrep", "-fl", "llama-server"], capture_output=True, text=True).stdout.strip()
    if once:
        raise SystemExit(f"başka llama-server çalışıyor, durdum: {once}")

    rnd = random.Random(YOKLAMA_METIN_TOHUMU)
    sistem = "Aşağıdaki yapay başvuru metnini oku ve yalnız sorulana kısa cevap ver.\n\n" + yapay_metin(ns.sozcuk, rnd)
    u1 = "Satır 0001'deki son onaltılık sayıyı yaz. Yalnız sayı."
    u2 = "Satır 0002'deki son onaltılık sayıyı yaz. Yalnız sayı."
    u3 = "Satır 0003'teki ilk sözcüğü yaz. Yalnız sözcük."

    anahtar = secrets.token_hex(16)
    # Pilot komutundan --cache-ram ve --ctx-checkpoints çıkarılır; yapılandırma bunları "--" sonrasında verir
    # (hiç vermezse llama.cpp öntanımlısı geçerlidir).
    komut = pilot_komutu(PORT, cikar=("--cache-ram", "--ctx-checkpoints")) + list(ns.ek) + ["--api-key", anahtar]
    kayit = {"ad": ns.ad, "ek_bayraklar": ns.ek,
             "komut": [("<gizli>" if x == anahtar else x) for x in komut],
             "baslangic": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "yuk_ortalamasi_once": None,
             "istekler": {}, "bellek_ornekleri": {}, "sigmadi": False}
    import os
    kayit["yuk_ortalamasi_once"] = [round(x, 2) for x in os.getloadavg()]

    gunluk = open(ns.gunluk, "wb")
    surec = subprocess.Popen(komut, stdout=gunluk, stderr=subprocess.STDOUT, process_group=0)
    bekci = Bekci(surec, ns.esik)
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
                raise RuntimeError("600 sn'de hazır olmadı")
            time.sleep(1)
        kayit["hazir_sn"] = round(time.time() - t0, 1)
        bekci.start()
        kayit["bellek_ornekleri"]["hazir"] = bekci.ornek()

        def govde(mesaj):
            return {"model": "qwen38", "messages": mesaj, "temperature": 0, "seed": 20261019, "max_tokens": 24,
                    "stream": False, "chat_template_kwargs": {"enable_thinking": False}}

        m1 = [{"role": "system", "content": sistem}, {"role": "user", "content": u1}]
        d1, s1 = istek(anahtar, govde(m1))
        kayit["istekler"]["r1"] = ozet(d1, s1)
        kayit["bellek_ornekleri"]["r1_sonra"] = bekci.ornek()
        a1 = ((d1.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        m2 = m1 + [{"role": "assistant", "content": a1}, {"role": "user", "content": u2}]
        d2, s2 = istek(anahtar, govde(m2))
        kayit["istekler"]["r2_ek"] = ozet(d2, s2)
        kayit["bellek_ornekleri"]["r2_sonra"] = bekci.ornek()
        m3 = [{"role": "system", "content": sistem}, {"role": "user", "content": u3}]
        d3, s3 = istek(anahtar, govde(m3))
        kayit["istekler"]["r3_dal"] = ozet(d3, s3)
        kayit["bellek_ornekleri"]["r3_sonra"] = bekci.ornek()
    except Exception as e:  # noqa: BLE001 — her hata kayda geçer, sunucu yine kapatılır
        kayit["hata"] = f"{type(e).__name__}: {e}"
    finally:
        bekci.dur.set()
        if surec.poll() is None:
            surec.terminate()
            try:
                surec.wait(timeout=60)
            except subprocess.TimeoutExpired:
                surec.kill()
                surec.wait(timeout=60)
        gunluk.close()
    kayit["bellek_tepe"] = bekci.tepe
    kayit["bekci_asimi"] = bekci.asim
    kayit["sigmadi"] = bekci.asim is not None
    kayit["yuk_ortalamasi_sonra"] = [round(x, 2) for x in os.getloadavg()]
    metin = ns.gunluk.read_text(errors="replace")
    kayit["gunluk_kontrol_noktasi_satirlari"] = [s[:220] for s in metin.splitlines()
                                                 if re.search(r"checkpoint|prompt cache|forcing full|cache state|restored", s, re.I)][:20]
    kayit["gunluk_secim_satirlari"] = [s[:220] for s in metin.splitlines() if "selected slot" in s][:10]
    kayit["bitis"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    kayit["sonra_pgrep"] = subprocess.run(["pgrep", "-fl", "llama-server"], capture_output=True, text=True).stdout.strip()
    ns.cikti.write_text(json.dumps(kayit, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: kayit[k] for k in ("ad", "istekler", "bellek_tepe", "sigmadi", "sonra_pgrep")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
