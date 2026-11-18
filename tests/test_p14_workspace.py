"""P14 / BORU-09: aynı adlı iki hedef aynı saniyede başlarsa aynı çalışma dizinini paylaşmamalı.

Eski davranış: ``base/<ad>/<YYYYmmdd_HHMMSS>`` + ``mkdir(exist_ok=True)``; ``a/main.js`` ile
``b/main.js`` aynı saniyede başlarsa ikisi tek dizine yazıyordu (gösterim: 8 eşzamanlı
``create()`` → 1 dizin).
"""

from __future__ import annotations

import threading
from pathlib import Path

from karadul.core.workspace import Workspace


def _same_second(base: Path, name: str, stamp: str) -> Workspace:
    w = Workspace(base, name)
    w._timestamp = stamp
    # Eski kodda yol kurucu içinde kurulur; aynı saniyeyi her iki sürümde de taklit et.
    w._workspace_dir = w._workspace_dir.parent / stamp
    return w


class TestUniqueWorkspace:
    def test_same_name_same_second_distinct_dirs(self, tmp_path) -> None:
        base = tmp_path / "workspaces"
        a = _same_second(base, Path("/a/dist/main.js").stem, "20261118_120000")
        b = _same_second(base, Path("/b/out/main.js").stem, "20261118_120000")
        pa, pb = a.create(), b.create()
        assert pa != pb
        assert pa.name == "20261118_120000"
        assert pb.name == "20261118_120000_2"
        # Her biri kendi stage dizinlerine sahip; birinin yazdığı öbüründe yok.
        a.save_json("reports", "pipeline_result", {"hedef": "a"})
        assert b.load_json("reports", "pipeline_result") is None

    def test_third_gets_suffix_3(self, tmp_path) -> None:
        base = tmp_path / "workspaces"
        paths = [_same_second(base, "main", "20261118_120000").create() for _ in range(3)]
        assert [p.name for p in paths] == [
            "20261118_120000", "20261118_120000_2", "20261118_120000_3",
        ]

    def test_concurrent_creates_are_unique(self, tmp_path) -> None:
        base = tmp_path / "workspaces"
        paths: list[Path] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker() -> None:
            w = _same_second(base, "main", "20261118_120000")
            barrier.wait()
            p = w.create()
            with lock:
                paths.append(p)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(paths) == 8
        assert len(set(paths)) == 8

    def test_create_idempotent_per_instance(self, tmp_path) -> None:
        w = Workspace(tmp_path, "x")
        assert w.create() == w.create()
        assert w.path == w.create()

    def test_explicit_dir_reused(self, tmp_path) -> None:
        d = tmp_path / "ws"
        w1 = Workspace(tmp_path, "x", workspace_dir=d)
        w2 = Workspace(tmp_path, "x", workspace_dir=d)
        assert w1.create() == w2.create() == d.resolve()

    def test_sub_workspace_still_unique(self, tmp_path) -> None:
        w = Workspace(tmp_path, "paket")
        w.create()
        s1 = w.create_sub_workspace("libfoo.dylib")
        s2 = w.create_sub_workspace("libfoo.dylib")
        assert s1.path != s2.path
        assert s2.path.name == "libfoo.dylib_2"
        assert (s1.path / "static").is_dir() and (s2.path / "static").is_dir()
