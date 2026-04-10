"""Naming pipeline sonuc veri yapilari.

NamingResult: Tek bir modulun isimlendirme sonucu.
NamingManifest: Tum modullerin toplu sonuclari, conflict resolution ve istatistikler.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class NamingResult:
    """Tek bir modulun isimlendirme sonucu."""

    module_id: str  # Orijinal modul ID (dosya adi, uzantisiz)
    original_file: str  # Orijinal dosya adi (orn: "A.js")
    new_filename: str  # Yeni dosya adi, kebab-case (orn: "mcp-session-handler.js")
    category: str  # Klasor yolu (orn: "vendor/rxjs", "tools", "api")
    description: str  # Tek satir aciklama
    confidence: float  # 0.0 - 1.0
    source: str  # "npm_fingerprint", "structural", "cross_ref", "llm"
    npm_package: str | None = None  # npm paketi (varsa)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id,
            "original_file": self.original_file,
            "new_filename": self.new_filename,
            "category": self.category,
            "description": self.description,
            "confidence": self.confidence,
            "source": self.source,
            "npm_package": self.npm_package,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NamingResult:
        return cls(**data)


def _sanitize_filename(name: str) -> str:
    """Dosya adini kebab-case'e cevir, 3-40 karakter arasi tut."""
    # @ ve / karakterlerini temizle
    name = name.replace("@", "").replace("/", "-")
    # Alphanumeric olmayanlari tire yap
    name = re.sub(r"[^a-z0-9\-.]", "-", name.lower())
    # Birden fazla tireyi tekile indir
    name = re.sub(r"-+", "-", name)
    # Bas/son tireleri sil
    name = name.strip("-")
    # .js uzantisi yoksa ekle
    if not name.endswith(".js"):
        name = name + ".js"
    # Uzunluk siniri (uzanti haric)
    stem = name[:-3]
    if len(stem) < 3:
        stem = stem.ljust(3, "x")
    if len(stem) > 40:
        stem = stem[:40]
    return stem + ".js"


@dataclass
class NamingManifest:
    """Tum modullerin isimlendirme sonuclari."""

    results: dict[str, NamingResult] = field(default_factory=dict)
    statistics: dict[str, dict] = field(default_factory=dict)
    source_match_mappings: dict[str, dict[str, str]] = field(default_factory=dict)
    # source_match_mappings: {module_id: {minified_name: original_name}}

    def add_result(self, result: NamingResult) -> None:
        """Tek sonuc ekle. Daha yuksek confidence varsa guncelle."""
        existing = self.results.get(result.module_id)
        if existing is None or result.confidence > existing.confidence:
            self.results[result.module_id] = result

    def add_results(self, results: list[NamingResult], source: str) -> None:
        """Toplu sonuc ekle, source istatistiklerini guncelle."""
        added = 0
        for r in results:
            old = self.results.get(r.module_id)
            self.add_result(r)
            if old is None or r.confidence > old.confidence:
                added += 1
        self.statistics[source] = {
            "attempted": len(results),
            "added": added,
        }

    def resolve_conflicts(self) -> int:
        """Ayni dosya adini paylasan modulleri coz -- suffix ekle (-2, -3, ...)."""
        # category/filename bazinda gruplama
        from collections import defaultdict

        path_to_ids: dict[str, list[str]] = defaultdict(list)
        for mid, result in self.results.items():
            key = f"{result.category}/{result.new_filename}"
            path_to_ids[key].append(mid)

        conflicts_resolved = 0
        for path_key, module_ids in path_to_ids.items():
            if len(module_ids) <= 1:
                continue
            # Confidence'a gore sirala -- en yuksek orijinal ismi alir
            sorted_ids = sorted(
                module_ids,
                key=lambda mid: self.results[mid].confidence,
                reverse=True,
            )
            for idx, mid in enumerate(sorted_ids):
                if idx == 0:
                    continue  # En yuksek confidence orijinal ismi tutar
                result = self.results[mid]
                stem = result.new_filename
                if stem.endswith(".js"):
                    stem = stem[:-3]
                result.new_filename = f"{stem}-{idx + 1}.js"
                conflicts_resolved += 1

        return conflicts_resolved

    def get_unnamed(self) -> list[str]:
        """Bu manifest'te henuz isimlendirilmemis modul ID'leri dondurmez.
        Cagiran taraf tum modullerin listesini bilmeli."""
        return []

    def get_unnamed_from(self, all_module_ids: set[str]) -> list[str]:
        """Verilen tum modul ID'leri icinden henuz isimlendirilmemisleri dondur."""
        return sorted(all_module_ids - set(self.results.keys()))

    def save(self, path: Path) -> None:
        """Manifest'i JSON olarak kaydet."""
        data = {
            "results": {mid: r.to_dict() for mid, r in self.results.items()},
            "statistics": self.statistics,
            "summary": self.summary(),
        }
        # Source match mappings varsa kaydet
        if self.source_match_mappings:
            data["source_match_mappings"] = self.source_match_mappings
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: Path) -> NamingManifest:
        """JSON'dan manifest yukle."""
        with open(path) as f:
            data = json.load(f)
        manifest = cls()
        for mid, rdict in data.get("results", {}).items():
            manifest.results[mid] = NamingResult.from_dict(rdict)
        manifest.statistics = data.get("statistics", {})
        manifest.source_match_mappings = data.get("source_match_mappings", {})
        return manifest

    def summary(self) -> dict[str, Any]:
        """Istatistik ozeti."""
        source_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        confidences: list[float] = []

        for r in self.results.values():
            source_counts[r.source] = source_counts.get(r.source, 0) + 1
            category_counts[r.category] = category_counts.get(r.category, 0) + 1
            confidences.append(r.confidence)

        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        return {
            "total_named": len(self.results),
            "by_source": source_counts,
            "by_category": dict(
                sorted(category_counts.items(), key=lambda x: -x[1])
            ),
            "avg_confidence": round(avg_confidence, 3),
            "statistics": self.statistics,
        }
