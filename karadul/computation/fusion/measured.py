"""Ölçülmüş kesinliğe bağlı kanıt füzyonu (P11 / TIP-02, BORU-03).

Eski ``SignatureFuser`` her adayı AYRI puanlıyordu, ağırlıklar elle seçilmişti ve
Platt kalibratörü hiç ``fit`` edilmeden kimlik olarak çalışıyordu: tek kanıtlı
en iyi aday sabit 0,182 olasılık alıyordu (kabul 0,90). Burada:

- Kanıt **adres** başına toplanır (imza ve CFG-iso aynı anahtarı kullanır);
  aynı adresin aynı adı veren kanıtları TEK adayda birleşir.
- Bir kaynağın olasılığı o kaynağın geliştirme setinde ölçülmüş kesinliğinin
  Wilson %95 alt sınırıdır (``measured_precision.py``; kökeni dosyada). İki
  kaynak aynı adı veriyorsa alt sınırların büyüğü alınır: kaynaklar bağımsız
  sayılmaz (aynı ikiliden, çoğu kez aynı ipucundan gelirler).
- Ölçümü olmayan kaynağın olasılığı yoktur; karar ``abstain`` + neden.
- Aynı adreste reddedilmeyen birden çok farklı ad varsa kabul edilen ad
  ``abstain`` olur (çelişki).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

ACCEPT = "accept"
REJECT = "reject"
ABSTAIN = "abstain"



@dataclass
class Evidence:
    """Bir adres için tek kaynaktan gelen ad kanıtı."""

    source: str              # "imza:<yöntem>" ya da "cfg_iso:<şablon kaynağı>"
    name: str
    raw_score: float = 0.0   # kaynağın kendi (kalibre olmayan) puanı; karar için kullanılmaz


@dataclass
class FusedName:
    """Bir adres için birleşmiş ad adayı."""

    address: str
    name: str
    sources: list[str] = field(default_factory=list)
    probability: Optional[float] = None
    decision: str = ABSTAIN
    reason: str = ""


def load_measured_precision_document(path: Optional[Path] = None) -> dict[str, Any]:
    """Ölçüm belgesinin tamamı (köken + kaynaklar).

    ``path`` verilirse aynı biçimde bir JSON dosyası okunur; yoksa depodaki
    ``measured_precision.MEASURED_PRECISION``.
    """
    if path is not None:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    from .measured_precision import MEASURED_PRECISION
    return MEASURED_PRECISION


def load_measured_precision(path: Optional[Path] = None) -> dict[str, dict[str, Any]]:
    """``{kaynak: {"n", "dogru", "wilson_alt"}}``."""
    return dict(load_measured_precision_document(path).get("kaynaklar", {}))


def fuse_by_address(
    evidence_by_address: dict[str, list[Evidence]],
    table: dict[str, dict[str, Any]],
    accept_threshold: float = 0.90,
    reject_threshold: float = 0.30,
) -> dict[str, list[FusedName]]:
    """Adres başına kanıtları ad başına tek adayda birleştir ve karar ver."""
    out: dict[str, list[FusedName]] = {}
    for address in sorted(evidence_by_address):
        by_name: dict[str, list[Evidence]] = {}
        for ev in evidence_by_address[address]:
            if ev.name:
                by_name.setdefault(ev.name, []).append(ev)
        fused: list[FusedName] = []
        for name in sorted(by_name):
            sources = sorted({ev.source for ev in by_name[name]})
            measured = [table[s]["wilson_alt"] for s in sources
                        if s in table and table[s].get("wilson_alt") is not None]
            unmeasured = [s for s in sources if s not in table]
            fn = FusedName(address=address, name=name, sources=sources)
            if not measured:
                fn.reason = "ölçülmemiş kaynak: " + ", ".join(unmeasured)
            else:
                fn.probability = round(max(float(p) for p in measured), 4)
                if fn.probability >= accept_threshold:
                    fn.decision = ACCEPT
                elif fn.probability < reject_threshold:
                    fn.decision = REJECT
                    fn.reason = "ölçülmüş kesinlik düşük"
                else:
                    fn.reason = "ölçülmüş kesinlik eşik arasında"
            fused.append(fn)
        # Çelişki: aynı adreste reddedilmeyen birden çok farklı ad varsa kabul
        # yok (kabul edilen ad, ona karşı çıkan kanıtı yok sayardı).
        accepted = [f for f in fused if f.decision == ACCEPT]
        rivals = [f for f in fused if f.decision != REJECT]
        if accepted and len(rivals) > 1:
            for f in accepted:
                f.decision = ABSTAIN
                f.reason = "aynı adreste çelişen adlar"
        if fused:
            out[address] = fused
    return out
