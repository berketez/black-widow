"""Bağımsız KaradulLM terminali: ``python -m karadul.lm`` (KaradulLM v2 tasarımı §11.1 karar 10 (b); P22e kalem 4).

Arayüz panelinin aynı oturum çekirdeği (``session.open_session``), düz metin çıktıyla: satırlar standart girdiden
okunur, ``Session.submit``'e verilir, olaylar ``repl.render`` ile yazılır. Ölçüm ve başsız kullanım içindir.

- Kabuk değildir: girdi yalnız ``repl.parse``'ın kapalı komut kümesine gider.
- Model isteğe bağlıdır. ``--llama-server`` + ``--model`` verilmezse oturum modelsiz açılır (plan, not,
  öneri listesi çalışır; model işleri "model yok" diye reddedilir). Verilirse sunucu ikilisi
  ``modes.check_server_binary``'den geçer (adı ``llama-server``, çalışma alanının dışında, analiz edilen
  ikiliyle aynı değil); tek alt süreç ``backend.LlamaServerBackend``'in kapalı komut listesidir.
- İkili özeti (defter ve depoların dizini) arayüzle aynı kuralla çalışma alanından okunur; bulunamazsa
  ``--ikili-sha256`` istenir (uydurulmaz).

Çıkış kodu: 0 normal kapanış; 2 açılamadı (çalışma alanı, ikili özeti, sunucu ikilisi).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Optional, Sequence, TextIO

from karadul.lm.audit import AuditLog, session_log_path
from karadul.lm.backend import LlamaServerBackend
from karadul.lm.modes import DEFAULT_MODE, SESSION_MODES, ServerBinaryRefused, check_server_binary
from karadul.lm.repl import TERMINAL_COMMAND, render
from karadul.lm.session import CLOSE_EXIT, Session, SessionError, new_session_id, open_session, workspace_binary_sha256

# Olay akışını okurken bekleme aralığı (sn) [bu iş]: yalnız çıktı tazeleme sıklığı; işin süresini etkilemez.
POLL_SEC = 0.2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m karadul.lm",
                                description="KaradulLM terminali (kabuk değildir; komutlar için /yardim).")
    p.add_argument("--calisma-alani", required=True, help="saklı Karadul çalışma alanı (…/workspaces/<ad>/<zaman>)")
    p.add_argument("--ikili-sha256", help="analiz edilen ikilinin sha256'sı (çalışma alanından okunamazsa)")
    p.add_argument("--llama-server", help="yerel llama-server ikilisi (verilmezse model yok)")
    p.add_argument("--model", help="model dosyası (GGUF)")
    p.add_argument("--sablon", help="sohbet şablonu dosyası (isteğe bağlı)")
    p.add_argument("--kip", choices=SESSION_MODES, default=DEFAULT_MODE, help="başlangıç kipi")
    p.add_argument("--depo", help="defter / özet / içerik deposu kökü (öntanım ~/.karadul/lm)")
    return p


def _drain(s: Session, last: int, out: TextIO) -> int:
    r = s.stream.since(last)
    if r["tasma"]:
        print(f"! {r['kacan']} olay kaçırıldı", file=out)
    for e in r["olaylar"]:
        for line in render(e):
            print(line, file=out)
    out.flush()
    return int(r["son"])


def main(argv: Optional[Sequence[str]] = None, *, stdin: Optional[TextIO] = None,
         stdout: Optional[TextIO] = None) -> int:
    args = build_parser().parse_args(argv)
    inp = stdin if stdin is not None else sys.stdin
    out = stdout if stdout is not None else sys.stdout
    ws = Path(args.calisma_alani)
    sha = (args.ikili_sha256 or "").lower() or workspace_binary_sha256(ws)
    if not sha:
        print("✗ ikili özeti çalışma alanında bulunamadı; --ikili-sha256 verin", file=out)
        return 2
    store = Path(args.depo) if args.depo else None
    sid = new_session_id()
    backend: Any = None
    if args.llama_server or args.model:
        if not (args.llama_server and args.model):
            print("✗ model için --llama-server ve --model birlikte verilmeli", file=out)
            return 2
        try:
            binary = check_server_binary(Path(args.llama_server), ws, sha)
            audit = AuditLog(session_log_path(sha, sid, store))
        except (ServerBinaryRefused, ValueError) as e:
            print(f"✗ {e}", file=out)
            return 2
        base = store if store is not None else Path.home() / ".karadul" / "lm"
        backend = LlamaServerBackend(binary, Path(args.model), base / "sunucu",
                                     template_path=Path(args.sablon) if args.sablon else None, audit=audit)
    try:
        s = open_session(ws, backend=backend, binary_sha256=sha, store_root=store, session_id=sid, mode=args.kip)
    except SessionError as e:
        print(f"✗ {e}", file=out)
        return 2
    last = _drain(s, 0, out)
    interactive = hasattr(inp, "isatty") and inp.isatty()
    try:
        while not s.closed:
            if interactive:
                print(f"{TERMINAL_COMMAND}> ", end="", file=out, flush=True)
            line = inp.readline()
            if not line:
                break
            if not interactive:
                print(f"{TERMINAL_COMMAND}> {line.rstrip(chr(10)).rstrip(chr(13))}", file=out)
            s.submit(line.rstrip("\n").rstrip("\r"))
            while True:
                idle = s.wait_idle(POLL_SEC)
                last = _drain(s, last, out)
                if idle or s.closed:
                    break
    except KeyboardInterrupt:
        print("", file=out)
    finally:
        if not s.closed:
            s.close(CLOSE_EXIT)
        _drain(s, last, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
