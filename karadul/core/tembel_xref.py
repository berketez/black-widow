"""ÖL-10: ``ghidra_xrefs.json``'ı K1'in iki dosyasından Ghidra'sız türetmek.

Kaynak: ``OL10_TASARIM.md`` §1.3 ve §7.1 adım 4. ``GhidraHeadless._extract_xrefs``'in fonksiyon
başına üç alanı K1 çıktılarından kurulur:

- ``strings_used``: ``ghidra_strings.json`` ``strings[].xrefs[]`` içinde ``from_func_addr`` bu
  fonksiyon olan başvurular; fonksiyon içinde başvuranın adresine göre artan (dökümün gövde
  tarama sırası), dizgi adresi başına ilk başvuru; öğe ``{"address", "value"}``.
- ``functions_called``: ``ghidra_call_graph.json`` ``nodes[f].callees`` (aynı tarama sırası,
  aynı tekilleştirme; ``{"name", "address"}``).
- ``called_by``: ``nodes[f].callers``, ``caller_sort_key`` ile (P16e kuralı).

``statistics.total_globals_with_xrefs`` sembol tablosundan gelir, K1'de yoktur: ``None`` yazılır
("ölçülmedi"; 0 yazılmaz). Ek alanlar ``kapsam`` ("tam_nufus") ve ``kaynak`` ("turetildi").
Modül dosya okumaz; Ghidra'ya bağlı değildir.
"""
from __future__ import annotations

from typing import Any, Mapping

from karadul.ghidra.headless import _address_sort_key, caller_sort_key

KAPSAM_TAM_NUFUS = "tam_nufus"
KAYNAK_TURETILDI = "turetildi"


def _liste(belge: Mapping[str, Any] | None, alan: str) -> list:
    v = (belge or {}).get(alan) if isinstance(belge, Mapping) else None
    return v if isinstance(v, list) else []


def _ad_adres(ogeler: Any) -> list[dict[str, Any]]:
    return [{"name": c.get("name"), "address": c.get("address")}
            for c in ogeler or [] if isinstance(c, Mapping)]


def turet(
    functions_doc: Mapping[str, Any],
    strings_doc: Mapping[str, Any] | None,
    call_graph_doc: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """``_extract_xrefs`` biçiminde belge (bütün fonksiyonlar; seçilmeyenler dahil)."""
    # fonksiyon adresi (Ghidra dizgisi) -> [(başvuranın sıralama anahtarı, dizgi anahtarı, adres, değer)]
    basvuru: dict[str, list[tuple]] = {}
    dizgi_kullanilan: set[str] = set()
    for s in _liste(strings_doc, "strings"):
        if not isinstance(s, Mapping) or s.get("address") is None:
            continue
        sa = str(s["address"])
        for x in s.get("xrefs") or []:
            if not isinstance(x, Mapping):
                continue
            ff = x.get("from_func_addr")
            if not ff:
                continue
            basvuru.setdefault(str(ff), []).append(
                (_address_sort_key(str(x.get("from_address") or "")), _address_sort_key(sa),
                 sa, s.get("value")))
            dizgi_kullanilan.add(sa)

    nodes = (call_graph_doc or {}).get("nodes", {}) if isinstance(call_graph_doc, Mapping) else {}
    nodes = nodes if isinstance(nodes, Mapping) else {}

    sira: list[tuple[str, str]] = []
    gorulen: set[str] = set()
    for f in _liste(functions_doc, "functions"):
        if isinstance(f, Mapping) and f.get("address") is not None:
            a = str(f["address"])
            if a not in gorulen:
                gorulen.add(a)
                sira.append((a, f.get("name")))
    for k, n in nodes.items():  # fonksiyon listesinde olmayan düğüm (olağan durumda yok)
        a = str((n or {}).get("address") or k) if isinstance(n, Mapping) else str(k)
        if a not in gorulen:
            gorulen.add(a)
            sira.append((a, n.get("name") if isinstance(n, Mapping) else None))

    func_xrefs: dict[str, Any] = {}
    for a, ad in sira:
        kullanilan: list[dict[str, Any]] = []
        gorulen_dizgi: set[str] = set()
        for _k1, _k2, sa, deger in sorted(basvuru.get(a, ()), key=lambda t: (t[0], t[1])):
            if sa not in gorulen_dizgi:
                gorulen_dizgi.add(sa)
                kullanilan.append({"address": sa, "value": deger})
        n = nodes.get(a) if isinstance(nodes.get(a), Mapping) else {}
        func_xrefs[a] = {
            "name": ad,
            "address": a,
            "strings_used": kullanilan,
            "functions_called": _ad_adres(n.get("callees")),
            "called_by": sorted(_ad_adres(n.get("callers")), key=caller_sort_key),
        }

    program = None
    for belge in (functions_doc, call_graph_doc, strings_doc):
        if isinstance(belge, Mapping) and belge.get("program") is not None:
            program = belge.get("program")
            break
    return {
        "program": program,
        "statistics": {
            "total_functions": len(func_xrefs),
            "total_strings_with_xrefs": len(dizgi_kullanilan),
            "total_globals_with_xrefs": None,
        },
        "function_xrefs": func_xrefs,
        "kapsam": KAPSAM_TAM_NUFUS,
        "kaynak": KAYNAK_TURETILDI,
    }
