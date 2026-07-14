"""Kalıcı manuel-override deposu -- "Analist İncele & Düzelt" (Faz 1).

Analistin arayüzden elle verdiği fonksiyon isimlerini ve parametre
isimlerini binary bazında KALICI olarak saklar. Karadul'un deterministik
hattı her koştuğunda bu override'lar tekrar uygulanabilsin diye disk üstünde
tutulur (in-memory model yeniden üretilse bile kaybolmaz).

Depo konumu:
    ~/.karadul/overrides/<binary_hash>.json

`binary_hash`, ilgili binary'nin STABİL anahtarıdır (analiz raporundaki
`target.hash`, yani sha256 hex). Böylece aynı binary farklı çalıştırmalarda
aynı override dosyasına düşer.

Depo şekli (v1):
    {
      "version": 1,
      "binary": "expr",                 # binary stem (bilgi amaçlı, opsiyonel)
      "binary_hash": "<sha256 hex>",
      "overrides": {                    # addr -> kayıt (fonksiyon ismi)
        "FUN_00104df0": {
          "name": "syntax_expecting_instead",
          "source": "manual",
          "confidence": 1.0,
          "ts": "2026-07-14T12:00:00+00:00",
          "note": "..."                 # opsiyonel; yoksa anahtar hiç yok
        }
      },
      "params": {                       # fn_addr -> {eski_param -> yeni_param}
        "FUN_00104df0": {"param_1": "flags"}
      }
    }

Güvenlik / dayanıklılık:
  * `binary_hash` yalnızca [0-9a-f] olabilir -> path traversal imkânsız.
  * Yazımlar ATOMİK'tir (tmp dosya + os.replace) -> yarım/bozuk JSON olmaz.
  * Tüm oku-değiştir-yaz döngüsü modül-seviye kilit altında -> thread-safe.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import threading
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
# Doğrulama desenleri (path traversal + geçersiz sembol koruması)
# ---------------------------------------------------------------------------
_HASH_RE = re.compile(r"^[0-9a-f]+$")                 # sadece küçük-harf hex
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")    # C tanımlayıcısı
_ADDR_HEX_RE = re.compile(r"^(FUN_|DAT_)[0-9a-fA-F]+$")

_VERSION = 1
_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Yol yardımcıları
# ---------------------------------------------------------------------------
def overrides_dir() -> Path:
    """~/.karadul/overrides dizinini döndür (yoksa oluştur)."""
    d = Path.home() / ".karadul" / "overrides"
    d.mkdir(parents=True, exist_ok=True)
    return d


def overrides_file(binary_hash: str) -> Path:
    """<binary_hash>.json yolunu döndür.

    `binary_hash` yalnızca [0-9a-f] karakterlerinden oluşmalı; aksi hâlde
    (nokta, eğik çizgi, '..' vb.) path traversal riski var -> ValueError.
    """
    if not isinstance(binary_hash, str) or not _HASH_RE.fullmatch(binary_hash):
        raise ValueError(f"geçersiz binary_hash (yalnızca [0-9a-f]): {binary_hash!r}")
    return overrides_dir() / f"{binary_hash}.json"


# ---------------------------------------------------------------------------
# İç yardımcılar
# ---------------------------------------------------------------------------
def _skeleton(binary_hash: str, binary: str | None = None) -> dict:
    return {
        "version": _VERSION,
        "binary": binary,
        "binary_hash": binary_hash,
        "overrides": {},
        "params": {},
    }


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _validate_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise ValueError(f"geçersiz isim (C tanımlayıcısı olmalı): {name!r}")
    return name


def _validate_addr(addr: str) -> str:
    """addr ya FUN_/DAT_<hex> ya da mevcut bir sembol (C tanımlayıcısı) olmalı.

    Her iki durumda da '/', '.', '..' gibi path karakterleri dışlanır ->
    dosya adı olarak asla kullanılmadığı için ayrıca güvenli, ama sözleşme
    gereği yine de doğruluyoruz.
    """
    if not isinstance(addr, str) or not (
        _ADDR_HEX_RE.fullmatch(addr) or _NAME_RE.fullmatch(addr)
    ):
        raise ValueError(f"geçersiz addr (FUN_/DAT_<hex> veya sembol): {addr!r}")
    return addr


def _read(binary_hash: str, binary: str | None = None) -> dict:
    """Diskten oku; yoksa/bozuksa iskelet döndür (kilit çağıranda)."""
    fp = overrides_file(binary_hash)
    if fp.is_file():
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "overrides" in data:
                # geriye dönük emniyet: eksik alanları tamamla
                data.setdefault("version", _VERSION)
                data.setdefault("binary_hash", binary_hash)
                data.setdefault("overrides", {})
                data.setdefault("params", {})
                if binary and not data.get("binary"):
                    data["binary"] = binary
                return data
        except (json.JSONDecodeError, OSError, TypeError):
            pass
    return _skeleton(binary_hash, binary)


def _atomic_write(binary_hash: str, data: dict) -> None:
    """data'yı <binary_hash>.json'a atomik yaz (tmp + os.replace)."""
    fp = overrides_file(binary_hash)
    tmp = fp.with_name(f".{fp.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, fp)  # atomik (aynı dizin, aynı fs)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Genel API
# ---------------------------------------------------------------------------
def load(binary_hash: str) -> dict:
    """Bu binary'nin override deposunu döndür (yoksa iskelet)."""
    with _LOCK:
        return _read(binary_hash)


def set_name(
    binary_hash: str,
    addr: str,
    name: str,
    *,
    binary: str | None = None,
    note: str | None = None,
) -> dict:
    """addr için manuel isim ata (upsert). Yazdığı kaydı döndürür.

    Kayıt: {"name","source":"manual","confidence":1.0,"ts":<iso>, "note"?}.
    """
    _validate_addr(addr)
    _validate_name(name)
    rec: dict = {
        "name": name,
        "source": "manual",
        "confidence": 1.0,
        "ts": _now_iso(),
    }
    if note:
        rec["note"] = str(note)
    with _LOCK:
        data = _read(binary_hash, binary)
        if binary and not data.get("binary"):
            data["binary"] = binary
        data["overrides"][addr] = rec
        _atomic_write(binary_hash, data)
    return rec


def set_param(binary_hash: str, fn_addr: str, param: str, new: str) -> dict:
    """fn_addr fonksiyonunda `param` parametresini `new` olarak yeniden adlandır.

    params[fn_addr][param] = new. İlgili fonksiyonun param eşlemesini döndürür.
    """
    _validate_addr(fn_addr)
    _validate_name(param)
    _validate_name(new)
    with _LOCK:
        data = _read(binary_hash)
        pmap = data["params"].setdefault(fn_addr, {})
        pmap[param] = new
        _atomic_write(binary_hash, data)
        return dict(pmap)


def remove(binary_hash: str, addr: str) -> dict:
    """addr için tüm override'ları (isim + param eşlemesi) sil. Güncel depoyu döndür."""
    _validate_addr(addr)
    with _LOCK:
        data = _read(binary_hash)
        data["overrides"].pop(addr, None)
        data["params"].pop(addr, None)
        _atomic_write(binary_hash, data)
        return data


def all_names(binary_hash: str) -> dict:
    """Düz addr -> name eşlemesi (isim override'ları için hızlı uygula)."""
    with _LOCK:
        data = _read(binary_hash)
    return {a: rec.get("name") for a, rec in data.get("overrides", {}).items()
            if isinstance(rec, dict) and rec.get("name")}
