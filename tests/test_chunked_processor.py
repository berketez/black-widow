"""ChunkedProcessor testleri -- GB-scale dosya isleme.

Test edilen islemler:
- JS dosyasini top-level statement'lara gore bolme
- Chunk boyutu kontrolu
- Paralel ve sirali isleme
- Sonuc birlestirme
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.chunked_processor import (
    ChunkedProcessor,
    ChunkInfo,
    ChunkResult,
)


@pytest.fixture
def config() -> Config:
    """Test konfigurasyon."""
    return Config()


@pytest.fixture
def simple_js(tmp_path: Path) -> Path:
    """Basit JS dosyasi -- 3 top-level fonksiyon."""
    content = """\
function hello() {
  console.log("hello");
}

function world() {
  console.log("world");
}

const add = (a, b) => {
  return a + b;
};
"""
    path = tmp_path / "simple.js"
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def large_js(tmp_path: Path) -> Path:
    """Buyuk JS dosyasi -- 100+ top-level statement."""
    lines = []
    for i in range(150):
        lines.append(f"function func_{i}(x) {{")
        lines.append(f'  console.log("function {i}", x);')
        lines.append(f"  return x + {i};")
        lines.append("}")
        lines.append("")

    path = tmp_path / "large.js"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


@pytest.fixture
def nested_js(tmp_path: Path) -> Path:
    """Ic ice brace'li JS dosyasi."""
    content = """\
function outer() {
  function inner() {
    if (true) {
      for (let i = 0; i < 10; i++) {
        console.log(i);
      }
    }
  }
  inner();
}

class MyClass {
  constructor() {
    this.data = {};
  }

  process() {
    return Object.keys(this.data).map(k => {
      return { key: k, value: this.data[k] };
    });
  }
}
"""
    path = tmp_path / "nested.js"
    path.write_text(content, encoding="utf-8")
    return path


class TestSplitJsFile:
    """split_js_file testleri."""

    def test_split_nonexistent_file(self, config: Config, tmp_path: Path):
        """Olmayan dosya icin basarisiz sonuc."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        result = chunker.split_js_file(
            tmp_path / "nonexistent.js",
            tmp_path / "output",
        )
        assert result.success is False
        assert "bulunamadi" in result.errors[0]

    def test_split_simple(self, config: Config, simple_js: Path, tmp_path: Path):
        """Basit dosya tek chunk olarak yazilir (chunk limiti asmiyor)."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)  # 1MB limit
        output_dir = tmp_path / "chunks"

        result = chunker.split_js_file(simple_js, output_dir)

        assert result.success is True
        assert result.total_lines > 0
        assert len(result.chunks) >= 1
        # Her chunk dosyasi mevcut olmali
        for chunk in result.chunks:
            assert chunk.path.exists()
            assert chunk.size_bytes > 0

    def test_split_creates_output_dir(self, config: Config, simple_js: Path, tmp_path: Path):
        """Output dizini yoksa olusturulur."""
        output_dir = tmp_path / "deep" / "nested" / "chunks"
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        result = chunker.split_js_file(simple_js, output_dir)

        assert result.success is True
        assert output_dir.exists()

    def test_split_preserves_content(self, config: Config, simple_js: Path, tmp_path: Path):
        """Chunk'lar birlestirince orijinal icerik korunur."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        output_dir = tmp_path / "chunks"
        result = chunker.split_js_file(simple_js, output_dir)

        original = simple_js.read_text()
        combined = ""
        for chunk in sorted(result.chunks, key=lambda c: c.index):
            combined += chunk.path.read_text()

        # Her satir korunmus olmali
        assert original.strip() == combined.strip()

    def test_split_nested_braces(self, config: Config, nested_js: Path, tmp_path: Path):
        """Ic ice brace'ler dogru islenir."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        output_dir = tmp_path / "chunks"
        result = chunker.split_js_file(nested_js, output_dir)

        assert result.success is True
        # Nested yapida depth=0 olan yerler sinir noktasi
        # En az 1 chunk olmali
        assert len(result.chunks) >= 1

    def test_split_line_tracking(self, config: Config, large_js: Path, tmp_path: Path):
        """Chunk'larin satir numaralari dogru."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        output_dir = tmp_path / "chunks"
        result = chunker.split_js_file(large_js, output_dir)

        # Ilk chunk 1. satirdan baslamali
        if result.chunks:
            assert result.chunks[0].start_line == 1

        # Son chunk'in end_line'i total_lines olmali
        if len(result.chunks) > 1:
            assert result.chunks[-1].end_line == result.total_lines

    def test_split_chunk_info_fields(self, config: Config, simple_js: Path, tmp_path: Path):
        """ChunkInfo tum alanlari dogru doldurulur."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        output_dir = tmp_path / "chunks"
        result = chunker.split_js_file(simple_js, output_dir)

        for chunk in result.chunks:
            assert isinstance(chunk, ChunkInfo)
            assert isinstance(chunk.path, Path)
            assert chunk.index >= 0
            assert chunk.start_line >= 1
            assert chunk.end_line >= chunk.start_line
            assert chunk.size_bytes > 0
            assert chunk.line_count > 0


class TestProcessChunks:
    """process_chunks testleri."""

    def test_sequential_processing(self, config: Config, simple_js: Path, tmp_path: Path):
        """Sirali isleme dogru calisir."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        output_dir = tmp_path / "chunks"
        split_result = chunker.split_js_file(simple_js, output_dir)

        def processor(path: Path) -> dict:
            content = path.read_text()
            return {"lines": content.count("\n"), "size": len(content)}

        results = chunker.process_chunks(
            split_result.chunks, processor, parallel=False,
        )

        assert len(results) == len(split_result.chunks)
        assert all(r.success for r in results)
        assert all(r.data is not None for r in results)

    def test_parallel_processing(self, config: Config, large_js: Path, tmp_path: Path):
        """Paralel isleme dogru calisir."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        output_dir = tmp_path / "chunks"
        split_result = chunker.split_js_file(large_js, output_dir)

        def processor(path: Path) -> dict:
            content = path.read_text()
            return {"lines": content.count("\n")}

        results = chunker.process_chunks(
            split_result.chunks, processor, parallel=True, max_workers=2,
        )

        assert len(results) == len(split_result.chunks)
        assert all(r.success for r in results)

    def test_processor_error_handling(self, config: Config, simple_js: Path, tmp_path: Path):
        """Processor hatasi ChunkResult.error olarak yakalanir."""
        chunker = ChunkedProcessor(config, max_chunk_mb=1)
        output_dir = tmp_path / "chunks"
        split_result = chunker.split_js_file(simple_js, output_dir)

        def failing_processor(path: Path) -> dict:
            raise ValueError("Test hatasi")

        results = chunker.process_chunks(
            split_result.chunks, failing_processor, parallel=False,
        )

        assert len(results) == len(split_result.chunks)
        assert all(not r.success for r in results)
        assert all("ValueError" in r.error for r in results)

    def test_empty_chunks_list(self, config: Config):
        """Bos chunk listesi bos sonuc dondurur."""
        chunker = ChunkedProcessor(config)

        def processor(path: Path) -> dict:
            return {}

        results = chunker.process_chunks([], processor)
        assert results == []


class TestMergeResults:
    """merge_results testleri."""

    def test_merge_empty(self, config: Config):
        """Bos sonuc listesi."""
        chunker = ChunkedProcessor(config)
        merged = chunker.merge_results([])

        assert merged["total_chunks"] == 0
        assert merged["successful_chunks"] == 0

    def test_merge_numbers(self, config: Config, tmp_path: Path):
        """Sayisal degerler toplanir."""
        chunk_info = ChunkInfo(
            path=tmp_path / "test.js",
            index=0, start_line=1, end_line=10,
            size_bytes=100, line_count=10,
        )
        results = [
            ChunkResult(chunk=chunk_info, success=True, data={"count": 5, "total": 100}),
            ChunkResult(chunk=chunk_info, success=True, data={"count": 3, "total": 50}),
        ]

        chunker = ChunkedProcessor(config)
        merged = chunker.merge_results(results)

        assert merged["count"] == 8
        assert merged["total"] == 150
        assert merged["total_chunks"] == 2
        assert merged["successful_chunks"] == 2

    def test_merge_lists(self, config: Config, tmp_path: Path):
        """Listeler concat edilir."""
        chunk_info = ChunkInfo(
            path=tmp_path / "test.js",
            index=0, start_line=1, end_line=10,
            size_bytes=100, line_count=10,
        )
        results = [
            ChunkResult(chunk=chunk_info, success=True, data={"items": ["a", "b"]}),
            ChunkResult(chunk=chunk_info, success=True, data={"items": ["c"]}),
        ]

        chunker = ChunkedProcessor(config)
        merged = chunker.merge_results(results)

        assert merged["items"] == ["a", "b", "c"]

    def test_merge_with_failures(self, config: Config, tmp_path: Path):
        """Basarisiz chunk'lar hata listesinde toplanir."""
        chunk_info = ChunkInfo(
            path=tmp_path / "test.js",
            index=0, start_line=1, end_line=10,
            size_bytes=100, line_count=10,
        )
        results = [
            ChunkResult(chunk=chunk_info, success=True, data={"count": 5}),
            ChunkResult(chunk=chunk_info, success=False, error="Parse hatasi"),
        ]

        chunker = ChunkedProcessor(config)
        merged = chunker.merge_results(results)

        assert merged["successful_chunks"] == 1
        assert merged["failed_chunks"] == 1
        assert "Parse hatasi" in merged["errors"]


class TestChunkedProcessorInit:
    """ChunkedProcessor init ve config testleri."""

    def test_default_max_chunk(self, config: Config):
        """Varsayilan max_chunk_mb degeri."""
        chunker = ChunkedProcessor(config)
        assert chunker.max_chunk_mb == 50
        assert chunker._max_chunk_bytes == 50 * 1024 * 1024

    def test_custom_max_chunk(self, config: Config):
        """Ozel max_chunk_mb degeri."""
        chunker = ChunkedProcessor(config, max_chunk_mb=10)
        assert chunker.max_chunk_mb == 10
        assert chunker._max_chunk_bytes == 10 * 1024 * 1024
