"""R1 ``find_refs``'in ters dizini (KaradulLM v2 tasarımı §3.5; P22d).

Ters arama "bu ithal adını kim çağırıyor", "bu dizgiyi kim kullanıyor" sorusudur. Kaynak
``static/ghidra_xrefs.json``'daki ``function_xrefs[].functions_called`` ve ``strings_used``; ithal
kümesi ``static/ghidra_functions.json``'daki dış / thunk fonksiyonlar. Ayrım ve ad yazımı
``karadul.reconstruction.tarif.evidence.build_evidence`` ile AYNI (``get_evidence.apis`` alanı bu
kuraldan geliyor; iki araç aynı ikiliye aynı cevabı vermeli, ``tests/test_lm_tools_v2.py`` kilitler).
``ghidra_strings.json[].function`` kullanılmaz: htop'ta 0 / 1 937 dolu (tasarım §3.5 R1 satırı).

Yaşam döngüsü:

- Dizin bir çalışma alanı nesnesi için **bir kez** kurulur ve bellekte durur (``Workspace`` önbelleği).
  Diske yazılmaz: araçlar dosya yazmaz (sözleşme §1.1).
- Kurulurken iki kaynak dosyanın parmak izi (boyut, değişiklik zamanı ns, düğüm no) alınır. Her
  sorguda parmak izi yeniden okunur (iki ``stat``):
  * ``ghidra_xrefs.json`` değiştiyse dizin yeniden kurulur (kurulum sayacı artar);
  * ``ghidra_functions.json`` değiştiyse çalışma alanının kendi adres tablosu (``Workspace``) da
    bayattır: dizin kurulmaz, araç ``veri_bayat`` döner. Oturum çalışma alanını yeniden açmalıdır.
  * Kaynak dosya okunamıyorsa (yok, bozuk) araç ``veri_yok`` döner; boş dizin uydurulmaz.

Bu modül yalnız standart kitaplığı ve ``karadul`` paketini içe aktarır; süreç başlatmaz, ağa çıkmaz.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from karadul.lm.tools import file_fingerprint
from karadul.reconstruction.tarif.evidence import normalize_api

FUNCTIONS_FILE = "ghidra_functions.json"
XREFS_FILE = "ghidra_xrefs.json"
INDEX_SOURCES = (FUNCTIONS_FILE, XREFS_FILE)

Fingerprint = tuple[tuple[str, Optional[int], Optional[int], Optional[int]], ...]


class IndexUnavailable(Exception):
    """Dizin kurulamıyor: kaynak dosya yok ya da beklenen biçimde değil."""


class IndexStale(Exception):
    """Çalışma alanının adres tablosu (``ghidra_functions.json``) oturum açıldıktan sonra değişti."""


def fingerprint(static_dir: Path) -> Fingerprint:
    """Kaynak dosyaların parmak izi (``file_fingerprint``: ad, boyut, değişiklik zamanı ns, düğüm no)."""
    return tuple(file_fingerprint(Path(static_dir) / name) for name in INDEX_SOURCES)


def _part(fp: Fingerprint, name: str) -> Any:
    return next((row for row in fp if row[0] == name), None)


@dataclass(frozen=True)
class ReverseIndex:
    """Ters dizin. Adresler çalışma alanı yazımıyla (``Workspace._canon``)."""

    fingerprint: Fingerprint
    # İthal adları (``normalize_api`` yazımı: baştaki alt çizgiler atılmış).
    imports: frozenset[str]
    # İthal adı → {çağıran adres: ``functions_called`` içindeki kayıt sayısı}. Çağrılmayan ithal yok.
    import_callers: Mapping[str, Mapping[str, int]]
    # (dizgi değeri, onu kullanan adresler artan sırayla); değer başına bir satır, değer sırasıyla.
    strings: tuple[tuple[str, tuple[str, ...]], ...]

    @classmethod
    def build(cls, static_dir: Path, canon: Callable[[Any], Optional[str]],
              fp: Optional[Fingerprint] = None) -> "ReverseIndex":
        static_dir = Path(static_dir)
        fp = fingerprint(static_dir) if fp is None else fp
        funcs = _load(static_dir / FUNCTIONS_FILE).get("functions")
        xrefs = _load(static_dir / XREFS_FILE).get("function_xrefs")
        if not isinstance(funcs, list) or not isinstance(xrefs, dict):
            raise IndexUnavailable("functions / function_xrefs beklenen biçimde değil")
        # evidence.build_evidence ile aynı ayrım: adı ya da adresi dış / thunk fonksiyonunki olan çağrı
        # bir ithal çağrısıdır.
        ext = [f for f in funcs if isinstance(f, dict) and (f.get("is_external") or f.get("is_thunk"))]
        ext_names = {f.get("name") for f in ext if isinstance(f.get("name"), str)}
        ext_addrs = {str(f.get("address", "")).lower().replace("0x", "") for f in ext}
        imports = frozenset(normalize_api(n) for n in ext_names if normalize_api(n))
        callers: dict[str, dict[str, int]] = {}
        by_string: dict[str, set[str]] = {}
        for key, x in xrefs.items():
            if not isinstance(x, dict):
                continue
            a = canon(key)
            if a is None:
                continue
            for c in x.get("functions_called") or []:
                if not isinstance(c, dict) or not isinstance(c.get("name"), str):
                    continue
                ca = str(c.get("address", "")).lower()
                if c["name"] in ext_names or ca in ext_addrs:
                    api = normalize_api(c["name"])
                    if api:
                        row = callers.setdefault(api, {})
                        row[a] = row.get(a, 0) + 1
            for s in x.get("strings_used") or []:
                v = s.get("value") if isinstance(s, dict) else None
                if isinstance(v, str) and v:
                    by_string.setdefault(v, set()).add(a)
        strings = tuple((v, tuple(sorted(addrs, key=lambda h: int(h, 16))))
                        for v, addrs in sorted(by_string.items()))
        # Adı dış fonksiyonunkinden farklı ama adresi bir thunk'ın olan çağrı da ithal çağrısıdır ve
        # ``get_evidence.apis``'te o adla görünür: modelin oradan okuduğu her ad sorulabilmeli.
        imports = imports | frozenset(callers)
        return cls(fingerprint=fp, imports=imports,
                   import_callers={k: dict(v) for k, v in callers.items()}, strings=strings)


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as e:
        raise IndexUnavailable(f"{path.name} okunamadı: {type(e).__name__}") from e
    if not isinstance(data, dict):
        raise IndexUnavailable(f"{path.name} nesne değil")
    return data


def reverse_index(ws: Any) -> ReverseIndex:
    """Çalışma alanının ters dizini: önbellekte varsa ve kaynakları değişmediyse o, değilse kurulur.

    ``IndexStale``: ``ghidra_functions.json`` çalışma alanı nesnesi kurulduktan sonra değişti.
    ``IndexUnavailable``: kaynak dosya yok ya da bozuk.
    """
    cache = ws._cache
    fp = fingerprint(ws.static_dir)
    # Çalışma alanının adres tablosu ``Workspace`` kurulurken okunan ``ghidra_functions.json``'a dayanır;
    # o dosyanın o anki parmak izi ``Workspace.functions_fingerprint``'tedir.
    if _part(fp, FUNCTIONS_FILE) != ws.functions_fingerprint:
        raise IndexStale(FUNCTIONS_FILE)
    idx = cache.get("reverse_index")
    if idx is None or idx.fingerprint != fp:
        idx = ReverseIndex.build(ws.static_dir, ws._canon, fp)
        cache["reverse_index"] = idx
        cache["reverse_index_builds"] = cache.get("reverse_index_builds", 0) + 1
    return idx
