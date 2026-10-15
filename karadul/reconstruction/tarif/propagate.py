"""Çağrı grafiğinde yayılım (sabit noktaya kadar, en fazla ``MAX_ROUNDS`` tur).

Kurallar (ölçümle seçildi, 2026-10-15 tmux kör etiketleme):
  Y1 Geri çağrı bağlamı (yukarıdan): rol almış geri çağrının (``on_timer``...) kaydedeni
     isimliyse kaydedenin bağlamı önek olur: ``alerts_on_timer``. Ölçülen başarı %83.
  Y2 Sarmalayıcı (aşağıdan): tek iç çağrısı isimli bir fonksiyon olan kısa fonksiyon, o işi
     yapar. Yalnız kesin, geri çağrı ya da API kaynaklı isimler taşınır. Log kaynaklı isimler
     taşınmaz, çünkü yanlış log isimleri sarmalayıcılara yayılıyordu ("out of range" ailesi).
  Y4 Yardımcı (yukarıdan, ipucu): yalnız bir isimli fonksiyon tarafından çağrılan küçük
     fonksiyon, o fonksiyonun yardımcısıdır. Başarı sayılmaz, yorum olarak gösterilir.
Fiil-ailesi kuralı (Y3) ölçümde %0 başarı verdiği için kaldırıldı.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from karadul.reconstruction.tarif.evidence import EvidencePack
from karadul.reconstruction.tarif.rules import Naming, context_prefix

MAX_ROUNDS = 6
_ROLE = re.compile(r"^(on_[a-z]+|compare_for_[a-z]+|handle_signal|cleanup_at_exit|thread_main)$")
_WRAPPER_MAX_LINES = 30
_HELPER_MAX_LINES = 40
_TRANSFERABLE = ("kesin", "geri_cagri", "api")
_NOISE_APIS = frozenset({"free", "stack_chk_fail", "error", "strlen", "memcpy", "bzero", "memset", "chkstk_darwin"})


def _is_name(names: Mapping[str, Naming], a: str) -> bool:
    return a in names and not names[a].is_hint


def propagate(
    names: dict[str, Naming],
    packs: Mapping[str, EvidencePack],
    population: set[str],
) -> dict[str, Naming]:
    """``names`` sözlüğünü yerinde genişletir ve döndürür."""
    for _ in range(MAX_ROUNDS):
        new: dict[str, Naming] = {}
        for a in population:
            p = packs.get(a)
            if p is None:
                continue
            cur = names.get(a)
            # Y1: geri çağrı rolüne kaydedenin bağlamını ekle
            if cur is not None and _ROLE.match(cur.name):
                ctxs = {
                    context_prefix(names[r["registrar"]].name)
                    for r in p.registered_as_callback if _is_name(names, r["registrar"])
                }
                if len(ctxs) == 1:
                    new[a] = Naming(f"{ctxs.pop()}_{cur.name}", "yayilim:Y1", 8.0)
                continue
            if cur is not None:
                continue
            # Y2: sarmalayıcı
            named_callees = [c for c in p.internal_callees if _is_name(names, c)]
            meaningful_api = [x for x in p.apis if x not in _NOISE_APIS]
            if (len(p.internal_callees) == 1 and named_callees and not meaningful_api
                    and p.line_count <= _WRAPPER_MAX_LINES):
                src = names[named_callees[0]]
                if src.source.startswith(_TRANSFERABLE):
                    new[a] = Naming(src.name, "yayilim:Y2", 7.0)
                    continue
            # Y4: yardımcı (ipucu)
            named_callers = [c for c in p.callers if _is_name(names, c)]
            if len(p.callers) == 1 and named_callers and p.line_count <= _HELPER_MAX_LINES:
                new[a] = Naming(f"{context_prefix(names[named_callers[0]].name)}_helper", "ipucu:Y4", 3.0)
        if not new:
            break
        names.update(new)
    return names
