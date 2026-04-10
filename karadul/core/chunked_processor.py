"""GB-scale dosya isleme -- buyuk JS dosyalarini chunk'lara ayirarak isle.

200MB+ dosyalar icin Babel parse memory patlatir. Bu modul:
  1. Dosyayi satir satir okur (readline benzeri)
  2. Brace matching ile top-level block sinirlarini bulur
  3. Her chunk'i ayri dosyaya yazar
  4. Opsiyonel olarak her chunk'i stream-parse.mjs ile isle
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Top-level statement baslangic pattern'leri
_TOP_LEVEL_STARTS = (
    "function ",
    "async function ",
    "class ",
    "const ",
    "let ",
    "var ",
    "export ",
    "module.exports",
    "exports.",
    "Object.defineProperty",
    "__webpack_require__",
    '"use strict"',
    "'use strict'",
)


@dataclass
class ChunkInfo:
    """Tek bir chunk'in bilgileri.

    Attributes:
        path: Chunk dosya yolu.
        index: Chunk sirasi (0-based).
        start_line: Orijinal dosyadaki baslangic satiri.
        end_line: Orijinal dosyadaki bitis satiri.
        size_bytes: Chunk boyutu (byte).
        line_count: Chunk satir sayisi.
    """

    path: Path
    index: int
    start_line: int
    end_line: int
    size_bytes: int
    line_count: int


@dataclass
class ChunkResult:
    """Chunk isleme sonucu.

    Attributes:
        chunk: Islenen chunk bilgisi.
        success: Basarili mi.
        data: Islem sonucu (processor_fn'in dondurdugu).
        error: Hata mesaji (basarisiz ise).
    """

    chunk: ChunkInfo
    success: bool
    data: Any = None
    error: str | None = None


@dataclass
class SplitResult:
    """Dosya bolme sonucu.

    Attributes:
        success: Bolme basarili mi.
        chunks: Olusan chunk bilgileri.
        total_lines: Orijinal dosyadaki toplam satir.
        errors: Hata mesajlari.
    """

    success: bool
    chunks: list[ChunkInfo] = field(default_factory=list)
    total_lines: int = 0
    errors: list[str] = field(default_factory=list)


class ChunkedProcessor:
    """Buyuk JS dosyalarini chunk'lara ayirarak isle.

    Strateji:
    1. Dosyayi satir satir oku (bellek tasirmaz)
    2. Brace counting ile top-level block sinirlarini bul
    3. max_chunk_mb'dan buyuk olunca yeni chunk olustur
    4. Her chunk'i bagimsiz processor_fn ile isle (paralel veya sirali)

    Args:
        config: Merkezi konfigurasyon.
        max_chunk_mb: Her chunk'in maksimum boyutu (MB).
    """

    def __init__(self, config: Any, max_chunk_mb: int = 50) -> None:
        self._config = config
        self.max_chunk_mb = max_chunk_mb
        self._max_chunk_bytes = max_chunk_mb * 1024 * 1024

    def split_js_file(
        self, input_file: Path, output_dir: Path,
    ) -> SplitResult:
        """JS dosyasini top-level statement'lara gore bol.

        Brace matching ile block sinirlarini bulur.
        Her chunk max_chunk_mb'dan kucuk olur.

        Args:
            input_file: Bolunecek JS dosyasi.
            output_dir: Chunk dosyalarinin yazilacagi dizin.

        Returns:
            SplitResult: Bolme sonucu.
        """
        if not input_file.exists():
            return SplitResult(
                success=False,
                errors=[f"Dosya bulunamadi: {input_file}"],
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        errors: list[str] = []
        chunks: list[ChunkInfo] = []

        try:
            total_lines = 0
            chunk_index = 0
            current_lines: list[str] = []
            current_size = 0
            depth = 0
            chunk_start_line = 1
            in_block_comment = False

            with open(input_file, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, start=1):
                    total_lines = line_num

                    # Block comment tracking
                    stripped = line.strip()
                    if not in_block_comment and stripped.startswith("/*"):
                        in_block_comment = True
                    if in_block_comment and "*/" in line:
                        in_block_comment = False

                    # Brace counting (basit - string icerisini ignored degil)
                    if not in_block_comment:
                        for ch in line:
                            if ch == "{":
                                depth += 1
                            elif ch == "}":
                                depth -= 1
                                if depth < 0:
                                    depth = 0

                    current_lines.append(line)
                    current_size += len(line.encode("utf-8", errors="replace"))

                    # Chunk boundary: depth 0'da ve yeterince buyuk
                    at_boundary = (
                        depth == 0
                        and not in_block_comment
                        and current_size >= self._max_chunk_bytes
                    )

                    # Veya yeni top-level statement basliyor ve chunk bos degil
                    new_statement = (
                        depth == 0
                        and not in_block_comment
                        and self._is_top_level_start(stripped)
                        and current_size >= self._max_chunk_bytes * 0.7
                    )

                    if (at_boundary or new_statement) and len(current_lines) > 0:
                        chunk_info = self._write_chunk(
                            output_dir, chunk_index, current_lines,
                            chunk_start_line, line_num,
                        )
                        chunks.append(chunk_info)
                        chunk_index += 1
                        current_lines = []
                        current_size = 0
                        chunk_start_line = line_num + 1

            # Kalan satirlari son chunk olarak yaz
            if current_lines:
                chunk_info = self._write_chunk(
                    output_dir, chunk_index, current_lines,
                    chunk_start_line, total_lines,
                )
                chunks.append(chunk_info)

        except OSError as exc:
            return SplitResult(
                success=False,
                errors=[f"Dosya okunamadi: {exc}"],
            )

        logger.info(
            "Chunked split: %s -> %d chunk (%.1f MB each avg)",
            input_file.name,
            len(chunks),
            sum(c.size_bytes for c in chunks) / max(len(chunks), 1) / (1024 * 1024),
        )

        return SplitResult(
            success=len(chunks) > 0,
            chunks=chunks,
            total_lines=total_lines,
            errors=errors,
        )

    def process_chunks(
        self,
        chunks: list[ChunkInfo],
        processor_fn: Callable[[Path], dict],
        *,
        parallel: bool = False,
        max_workers: int = 4,
    ) -> list[ChunkResult]:
        """Her chunk'i processor_fn ile isle.

        Args:
            chunks: Islenecek chunk listesi.
            processor_fn: Her chunk dosyasi icin cagirilacak fonksiyon.
                Path alir, dict dondurur.
            parallel: Paralel isleme kullanilsin mi.
            max_workers: Paralel isleme icin thread sayisi.

        Returns:
            ChunkResult listesi (chunk sirasina gore).
        """
        results: list[ChunkResult] = []

        if parallel and len(chunks) > 1:
            results = self._process_parallel(chunks, processor_fn, max_workers)
        else:
            results = self._process_sequential(chunks, processor_fn)

        success_count = sum(1 for r in results if r.success)
        logger.info(
            "Chunk processing: %d/%d basarili",
            success_count, len(chunks),
        )

        return results

    def merge_results(self, results: list[ChunkResult]) -> dict:
        """Chunk sonuclarini birlestir.

        Her chunk'in data dict'lerini merge eder.

        Args:
            results: ChunkResult listesi.

        Returns:
            Birlestirilmis sonuc dict'i.
        """
        merged: dict[str, Any] = {
            "total_chunks": len(results),
            "successful_chunks": sum(1 for r in results if r.success),
            "failed_chunks": sum(1 for r in results if not r.success),
            "errors": [r.error for r in results if r.error],
        }

        # Data dict'lerini birlestir (listeler concat, sayilar topla)
        for r in results:
            if not r.success or r.data is None:
                continue

            for key, value in r.data.items():
                if key not in merged:
                    merged[key] = value
                elif isinstance(value, list) and isinstance(merged[key], list):
                    merged[key].extend(value)
                elif isinstance(value, (int, float)) and isinstance(merged[key], (int, float)):
                    merged[key] += value
                elif isinstance(value, dict) and isinstance(merged[key], dict):
                    merged[key].update(value)

        return merged

    # ---------------------------------------------------------------
    # Private methods
    # ---------------------------------------------------------------

    @staticmethod
    def _is_top_level_start(stripped_line: str) -> bool:
        """Satirin top-level statement baslangici olup olmadigini kontrol et."""
        if not stripped_line:
            return False
        return any(stripped_line.startswith(prefix) for prefix in _TOP_LEVEL_STARTS)

    @staticmethod
    def _write_chunk(
        output_dir: Path,
        index: int,
        lines: list[str],
        start_line: int,
        end_line: int,
    ) -> ChunkInfo:
        """Chunk'i dosyaya yaz ve ChunkInfo dondur."""
        chunk_num = str(index + 1).zfill(5)
        chunk_path = output_dir / f"chunk_{chunk_num}.js"

        content = "".join(lines)
        chunk_path.write_text(content, encoding="utf-8")

        return ChunkInfo(
            path=chunk_path,
            index=index,
            start_line=start_line,
            end_line=end_line,
            size_bytes=len(content.encode("utf-8", errors="replace")),
            line_count=len(lines),
        )

    @staticmethod
    def _process_sequential(
        chunks: list[ChunkInfo],
        processor_fn: Callable[[Path], dict],
    ) -> list[ChunkResult]:
        """Chunk'lari sirali isle."""
        results = []
        for chunk in chunks:
            try:
                data = processor_fn(chunk.path)
                results.append(ChunkResult(
                    chunk=chunk,
                    success=True,
                    data=data,
                ))
            except Exception as exc:
                results.append(ChunkResult(
                    chunk=chunk,
                    success=False,
                    error=f"{type(exc).__name__}: {exc}",
                ))
        return results

    @staticmethod
    def _process_parallel(
        chunks: list[ChunkInfo],
        processor_fn: Callable[[Path], dict],
        max_workers: int,
    ) -> list[ChunkResult]:
        """Chunk'lari paralel isle."""
        results: list[ChunkResult | None] = [None] * len(chunks)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {}
            for i, chunk in enumerate(chunks):
                future = executor.submit(processor_fn, chunk.path)
                future_to_idx[future] = (i, chunk)

            for future in as_completed(future_to_idx):
                idx, chunk = future_to_idx[future]
                try:
                    data = future.result()
                    results[idx] = ChunkResult(
                        chunk=chunk,
                        success=True,
                        data=data,
                    )
                except Exception as exc:
                    results[idx] = ChunkResult(
                        chunk=chunk,
                        success=False,
                        error=f"{type(exc).__name__}: {exc}",
                    )

        return [r for r in results if r is not None]
