#!/usr/bin/env python3
"""Onarım ajanları için takılma bekçisi (CLAUDE.md §27).

Her ajan için: worktree'deki yeni commit'ler, değişen dosyaların ve transcript'in son
etkinlik zamanı, "## PAKET BİTTİ" işareti, model düşmesi. Yalnız olay satırı basar.
Kullanım: bekci.py AD=ajan_id [AD=ajan_id ...]
"""
import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path

DEPO = Path("/Users/apple/Black_Widow")
# Alt ajan transcript dizini oturuma özel: BEKCI_OTURUM_DIZINI verilmezse en son
# değişen oturumun subagents dizini alınır.
_PROJE = Path.home() / ".claude/projects/-Users-apple-Black-Widow"
OTURUM = Path(os.environ["BEKCI_OTURUM_DIZINI"]) if os.environ.get("BEKCI_OTURUM_DIZINI") else max(
    _PROJE.glob("*/subagents"), key=lambda p: p.stat().st_mtime)
TABAN = "e9d2d08"
SESSIZ_ESIK_SN = 20 * 60
ARALIK_SN = 60
BEKLENEN_MODEL = "claude-opus-5-5"


def yaz(s: str) -> None:
    print(f"{dt.datetime.now():%H:%M} {s}", flush=True)


def git(wt: Path, *arg: str) -> str:
    r = subprocess.run(["git", "-C", str(wt), *arg], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def transcript_son(tr: Path) -> tuple[float, str]:
    """Son olay zaman damgası (epoch) ve son görülen model adı; içerik basılmaz."""
    if not tr.exists():
        return 0.0, ""
    boy = tr.stat().st_size
    with open(tr, "rb") as f:
        f.seek(max(0, boy - 400_000))
        satirlar = f.read().decode("utf-8", "replace").splitlines()
    ts, model = 0.0, ""
    for s in reversed(satirlar):
        try:
            o = json.loads(s)
        except Exception:
            continue
        if not ts and o.get("timestamp"):
            try:
                ts = dt.datetime.fromisoformat(o["timestamp"].replace("Z", "+00:00")).timestamp()
            except Exception:
                pass
        if not model:
            m = (o.get("message") or {}).get("model") if isinstance(o.get("message"), dict) else None
            if m:
                model = m
        if ts and model:
            break
    return ts, model


def wt_son(wt: Path) -> float:
    son = 0.0
    for satir in git(wt, "status", "--porcelain", "--untracked-files=all").splitlines():
        yol = wt / satir[3:].split(" -> ")[-1]
        try:
            son = max(son, yol.stat().st_mtime)
        except OSError:
            pass
    ct = git(wt, "log", "-1", "--format=%ct")
    if ct:
        son = max(son, float(ct))
    return son


def main() -> None:
    ajanlar = dict(a.split("=", 1) for a in sys.argv[1:])
    durum = {ad: {"commitler": set(), "sessiz": False, "bitti": False, "model_uyari": False}
             for ad in ajanlar}
    for ad, aid in ajanlar.items():  # mevcut commit'leri sessizce yükle (yeniden kurulumda tekrar basma)
        wt = DEPO / ".claude/worktrees" / f"agent-{aid}"
        if wt.exists():
            durum[ad]["commitler"].update(c.split(" ", 1)[0] for c in git(wt, "log", "--format=%h %s", "main..HEAD").splitlines())
    yaz("bekçi başladı: " + ", ".join(ajanlar))
    while True:
        simdi = time.time()
        for ad, aid in ajanlar.items():
            d = durum[ad]
            wt = DEPO / ".claude/worktrees" / f"agent-{aid}"
            tr = OTURUM / f"agent-{aid}.jsonl"
            if not wt.exists():
                continue
            for c in git(wt, "log", "--format=%h %s", "main..HEAD").splitlines()[::-1]:
                h = c.split(" ", 1)[0]
                if h not in d["commitler"]:
                    d["commitler"].add(h)
                    yaz(f"{ad} commit {c[:150]}")
            ilerleme = list((wt / "docs/arge/2026-11-18_onarim").glob(f"{ad.replace('Ü', 'U')}*.md"))
            if not d["bitti"] and any("## PAKET BİTTİ" in p.read_text(errors="replace") for p in ilerleme):
                d["bitti"] = True
                yaz(f"{ad} PAKET BİTTİ işareti yazıldı")
            tts, model = transcript_son(tr)
            if model and not model.startswith(BEKLENEN_MODEL) and not d["model_uyari"]:
                d["model_uyari"] = True
                yaz(f"{ad} MODEL DÜŞMESİ: {model}")
            son = max(tts, wt_son(wt))
            if son and simdi - son > SESSIZ_ESIK_SN and not d["bitti"]:
                if not d["sessiz"]:
                    d["sessiz"] = True
                    yaz(f"{ad} SESSİZ {int((simdi - son) / 60)} dk (transcript iç zamanı + worktree)")
            elif d["sessiz"] and simdi - son <= SESSIZ_ESIK_SN:
                d["sessiz"] = False
                yaz(f"{ad} yeniden hareketli")
        time.sleep(ARALIK_SN)


if __name__ == "__main__":
    main()
