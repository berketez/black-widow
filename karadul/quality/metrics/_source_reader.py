"""Ortak kaynak dosya okuyucu (v1.10.0 C2).

Quality metric'leri ayni path icin defalarca disk I/O yapmak yerine
``file_cache`` (dosya_adi -> kaynak) kullanarak in-memory okuyabilir.
Bu helper cache hit/miss mantigini tek yerde topluyor -- 6 metric
dosyasinda kopya kod olmasin.

Cache miss sessiz disk fallback: yeni eklenen dosyalar (cache'e
girmemis) yine okunur. Bu graceful degradation sayesinde caller
cache'i kismen doldurabilir.
"""

from __future__ import annotations

from pathlib import Path


def read_source(
    path: Path,
    file_cache: dict[str, str] | None,
) -> str | None:
    """Dosyanin kaynak kodunu dondur; ``None`` okunamadiysa.

    Oncelik: ``file_cache[path.name]`` -> disk fallback.
    Disk hatasi (OSError, UnicodeError) None olarak iletilir; caller
    bunu "kaynak yok, bu dosyayi atla" seklinde yorumlar.
    """
    if file_cache is not None:
        cached = file_cache.get(path.name)
        if cached is not None:
            return cached
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None
