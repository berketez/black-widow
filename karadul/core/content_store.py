"""In-memory content store -- pipeline fazlari arasi dosya I/O eliminasyonu.

Pipeline boyunca C dosya iceriklerini bellekte tutar.
Disk I/O sadece load_from_directory() ve flush_to_directory() ile yapilir.

Bellek kullanimi: 5000 fonksiyon x ort. 2KB = ~10MB (trivial).
100K fonksiyonlu binary icin bile ~500MB (36GB RAM'de sorun degil).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


class ContentStore:
    """Pipeline boyunca C dosya iceriklerini bellekte tutan store.

    Kullanim:
        store = ContentStore()
        store.load_from_directory(decompiled_dir)

        # Her faz store uzerinde calisir
        for stem, content in store.items():
            modified = process(content)
            store.set(stem, modified)

        # En sonda diske yaz
        store.flush_to_directory(output_dir)
    """

    def __init__(self) -> None:
        self._contents: dict[str, str] = {}
        self._dirty: set[str] = set()

    def load_from_directory(self, directory: Path, pattern: str = "*.c") -> int:
        """Dizindeki dosyalari bellige yukle. Dosya sayisini dondurur."""
        count = 0
        for f in sorted(directory.rglob(pattern)):
            content = f.read_text(encoding="utf-8", errors="replace")
            self._contents[f.stem] = content
            count += 1
        logger.info("ContentStore: %d dosya yuklendi (%s)", count, directory)
        return count

    def get(self, stem: str) -> Optional[str]:
        """Dosya icerigini getir."""
        return self._contents.get(stem)

    def set(self, stem: str, content: str) -> None:
        """Dosya icerigini guncelle."""
        self._contents[stem] = content
        self._dirty.add(stem)

    def items(self) -> Iterator[tuple[str, str]]:
        """Tum (stem, content) ciftlerini dondur."""
        return iter(self._contents.items())

    def stems(self) -> list[str]:
        return list(self._contents.keys())

    def __len__(self) -> int:
        return len(self._contents)

    def __contains__(self, stem: str) -> bool:
        return stem in self._contents

    def flush_to_directory(self, directory: Path, only_dirty: bool = False) -> int:
        """Bellekteki icerikleri diske yaz."""
        directory.mkdir(parents=True, exist_ok=True)
        written = 0
        targets = self._dirty if only_dirty else self._contents.keys()
        for stem in targets:
            content = self._contents.get(stem)
            if content is not None:
                (directory / f"{stem}.c").write_text(content, encoding="utf-8")
                written += 1
        self._dirty.clear()
        logger.info("ContentStore: %d dosya yazildi -> %s", written, directory)
        return written

    def memory_usage_mb(self) -> float:
        """Yaklasik bellek kullanimi (MB)."""
        total_bytes = sum(len(c.encode("utf-8")) for c in self._contents.values())
        return total_bytes / (1024 * 1024)
