"""Pipeline DAG denetleme araci — sadece rapor uretir, dosya degistirmez.

Karadul pipeline'inda her `@register_step(...)` dekorator'unu AST ile parse
eder; `requires` ve `produces` listelerini cikarir. Sonra:

- Ureticisi olmayan `requires` (DAG'da kirik kenar) listelenir
- Tuketicisi olmayan `produces` ("dead artifact") listelenir
- Step bazinda ozet tablo
- JSON ozet ve markdown rapor `--out` yoluna yazilir

Calistirma:

    python -m karadul.scripts.audit_pipeline_dag
    python -m karadul.scripts.audit_pipeline_dag --out AUDIT.md

Tasarim notu: Dinamik import yapmiyoruz — registry yan etkilerine girmemek
icin AST-only. Bu sayede degisiklikten once/sonra ayni script ile karsilastirma
yapilabilir.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class StepInfo:
    """Bir step dekoratoruunden cikarilan metadata."""

    name: str
    file: str
    requires: tuple[str, ...]
    produces: tuple[str, ...]


@dataclass
class AuditReport:
    """Toplanan rapor verileri."""

    steps: list[StepInfo] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    # Producer/consumer haritalari (lazy)
    _producer_of: dict[str, str] = field(default_factory=dict)
    _consumers_of: dict[str, list[str]] = field(default_factory=dict)

    def build_indexes(self) -> None:
        """produces/requires haritalarini yeniden hesapla."""
        self._producer_of.clear()
        self._consumers_of.clear()
        for s in self.steps:
            for p in s.produces:
                # Duplikasyon hatasi runner tarafindan zaten yakalaniyor;
                # burada sadece son ureticiyi kaydet, ayrica uyari ver.
                if p in self._producer_of:
                    self.parse_errors.append(
                        f"DUPLICATE produces '{p}': "
                        f"{self._producer_of[p]} ve {s.name}",
                    )
                self._producer_of[p] = s.name
            for r in s.requires:
                self._consumers_of.setdefault(r, []).append(s.name)

    def dead_artifacts(self) -> list[tuple[str, str]]:
        """Tuketicisi olmayan produces. (artifact, producer_step)."""
        out: list[tuple[str, str]] = []
        for art, producer in sorted(self._producer_of.items()):
            if art not in self._consumers_of:
                out.append((art, producer))
        return out

    def missing_producers(self) -> list[tuple[str, str]]:
        """Ureticisi olmayan requires. (artifact, consumer_step).

        Pipeline runtime'da `seed_artifacts` veya `pipeline_context.metadata`
        ile besleniyor olabilir; bu yuzden 'kirik' degil, 'dis girdi' olarak
        yorumlanmali. Yine de raporda gosteriyoruz.
        """
        out: list[tuple[str, str]] = []
        for art, consumers in sorted(self._consumers_of.items()):
            if art not in self._producer_of:
                for c in consumers:
                    out.append((art, c))
        return out

    def summary(self) -> dict[str, int]:
        return {
            "steps": len(self.steps),
            "produces_total": sum(len(s.produces) for s in self.steps),
            "requires_total": sum(len(s.requires) for s in self.steps),
            "dead_artifacts": len(self.dead_artifacts()),
            "missing_producers": len(self.missing_producers()),
        }


def _extract_str_list(node: ast.expr | None) -> tuple[str, ...]:
    """Bir ast.List/ast.Tuple node'undan str sabitlerini cikar."""
    if node is None:
        return ()
    if isinstance(node, (ast.List, ast.Tuple)):
        items: list[str] = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                items.append(elt.value)
        return tuple(items)
    return ()


def _extract_register_step(call: ast.Call) -> tuple[str, tuple[str, ...], tuple[str, ...]] | None:
    """`register_step(name=..., requires=..., produces=...)` parse et."""
    name_val: str | None = None
    requires: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant):
            if isinstance(kw.value.value, str):
                name_val = kw.value.value
        elif kw.arg == "requires":
            requires = _extract_str_list(kw.value)
        elif kw.arg == "produces":
            produces = _extract_str_list(kw.value)
    if name_val is None:
        return None
    return name_val, requires, produces


def scan_file(path: Path) -> list[StepInfo]:
    """Bir dosyadaki tum @register_step kullanmalarini cikar."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    out: list[StepInfo] = []
    for node in ast.walk(tree):
        # Class veya function decorator olabilir
        decorators: list[ast.expr] = []
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = list(node.decorator_list)
        for dec in decorators:
            call: ast.Call | None = None
            if isinstance(dec, ast.Call):
                # @register_step(...)
                func = dec.func
                if (isinstance(func, ast.Name) and func.id == "register_step") or (
                    isinstance(func, ast.Attribute) and func.attr == "register_step"
                ):
                    call = dec
            if call is None:
                continue
            parsed = _extract_register_step(call)
            if parsed is None:
                continue
            name, requires, produces = parsed
            out.append(
                StepInfo(
                    name=name,
                    file=str(path),
                    requires=requires,
                    produces=produces,
                ),
            )
    return out


def scan_steps_dir(steps_dir: Path) -> AuditReport:
    rep = AuditReport()
    for py in sorted(steps_dir.glob("*.py")):
        if py.name.startswith("_") or py.name == "__init__.py":
            continue
        try:
            infos = scan_file(py)
        except SyntaxError as exc:
            rep.parse_errors.append(f"{py.name}: {exc}")
            continue
        rep.steps.extend(infos)
    rep.build_indexes()
    return rep


def format_markdown(rep: AuditReport) -> str:
    s = rep.summary()
    lines: list[str] = []
    lines.append("# Pipeline DAG Denetimi")
    lines.append("")
    lines.append("## Ozet")
    lines.append("")
    lines.append(f"- Step sayisi: **{s['steps']}**")
    lines.append(f"- Toplam produces: **{s['produces_total']}**")
    lines.append(f"- Toplam requires: **{s['requires_total']}**")
    lines.append(f"- Olu artifact (tuketicisi yok): **{s['dead_artifacts']}**")
    lines.append(f"- Disaridan beslenen (ureticisi yok): **{s['missing_producers']}**")
    lines.append("")

    if rep.parse_errors:
        lines.append("## Parse uyarilari")
        lines.append("")
        for e in rep.parse_errors:
            lines.append(f"- {e}")
        lines.append("")

    lines.append("## Olu artifact'lar")
    lines.append("")
    lines.append("Bir step tarafindan `produces` edilen fakat hicbir step'in")
    lines.append("`requires` listesinde bulunmayan artifact'lar:")
    lines.append("")
    lines.append("| Artifact | Producer step |")
    lines.append("|---|---|")
    for art, producer in rep.dead_artifacts():
        lines.append(f"| `{art}` | `{producer}` |")
    lines.append("")

    lines.append("## Disaridan beslenen requires")
    lines.append("")
    lines.append("Pipeline disindan (seed_artifacts / pipeline_context.metadata)")
    lines.append("gelmesi beklenen girdiler:")
    lines.append("")
    lines.append("| Artifact | Consumer step |")
    lines.append("|---|---|")
    for art, consumer in rep.missing_producers():
        lines.append(f"| `{art}` | `{consumer}` |")
    lines.append("")

    lines.append("## Step ozeti")
    lines.append("")
    lines.append("| Step | requires | produces |")
    lines.append("|---|---|---|")
    for st in sorted(rep.steps, key=lambda x: x.name):
        req = ", ".join(f"`{r}`" for r in st.requires) or "—"
        prod = ", ".join(f"`{p}`" for p in st.produces) or "—"
        lines.append(f"| `{st.name}` | {req} | {prod} |")
    lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--steps-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "pipeline" / "steps",
        help="Tarama yapilacak steps/ dizini",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Markdown raporun yazilacagi yol (default: stdout)",
    )
    ap.add_argument(
        "--json",
        type=Path,
        default=None,
        help="JSON ozetin yazilacagi yol",
    )
    args = ap.parse_args(argv)

    if not args.steps_dir.exists():
        print(f"steps dir bulunamadi: {args.steps_dir}", file=sys.stderr)
        return 2

    rep = scan_steps_dir(args.steps_dir)
    md = format_markdown(rep)

    if args.out:
        args.out.write_text(md, encoding="utf-8")
    else:
        print(md)

    if args.json:
        payload = {
            "summary": rep.summary(),
            "dead_artifacts": rep.dead_artifacts(),
            "missing_producers": rep.missing_producers(),
            "steps": [
                {
                    "name": s.name,
                    "file": s.file,
                    "requires": list(s.requires),
                    "produces": list(s.produces),
                }
                for s in rep.steps
            ],
            "parse_errors": rep.parse_errors,
        }
        args.json.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
