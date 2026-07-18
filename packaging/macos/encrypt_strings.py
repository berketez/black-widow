#!/usr/bin/env python3
"""Black Widow motor koruma — string literal şifreleme (Faz B).

Nuitka derlemeden ÖNCE bir modülün kaynağını dönüştürür: seçilen string
literal'lerini rotating-XOR ile şifreli ``bytes`` sabitine çevirir ve yerlerine
runtime çözücü ``_kd(b'...')`` çağrısı koyar. Modülün başına küçük bir ``_kd``
çözücü enjekte edilir. Nuitka derleyince: şifreli bytes ``.so`` içinde durur,
çözme mantığı MAKİNE KODU olur -> ``strings``/``grep`` artık düz metni GÖRMEZ.

Sınır (dürüst): çözücü + anahtar ``.so`` içinde (makine kodu). Kararlı bir RE'ci
çözücüye breakpoint koyup RAM'den düz metni alabilir. Amaç STATİK analizi
(``strings``, grep, hex editör) kör etmek, mükemmel kripto değil.

Güvenlik (bozmama) için ŞU string'ler ŞİFRELENMEZ:
  * docstring (modül/sınıf/fonksiyon ilk-ifade string'i) — no_docstrings zaten siler
  * f-string parçaları (JoinedStr içi)
  * annotation string'leri (AnnAssign/arg/returns) — introspection'ı bozmayalım
  * ``__all__`` değerleri (yıldız-import sözleşmesi)
  * dunder-görünümlü string (``^__\\w+__$``) — çoğu özel anlam taşır
  * çok kısa (< MIN_LEN) — düşük fayda, yüksek risk

Kullanım: transformed = transform_source(src_text, seed); dosyaya yaz -> Nuitka.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

MIN_LEN = 4  # bundan kısa string'ler şifrelenmez
_DUNDER_RE = re.compile(r"^__\w+__$")

# Enjekte edilecek çözücü. rotating-XOR: keystream[i] = (seed ^ (i*131+7)) & 0xFF.
# XOR kendi tersi -> şifreleme ve çözme AYNI keystream. Fonksiyon adı bilinçli
# jenerik (``_kd``); Nuitka'da makine koduna döner.
_DECODER_TMPL = (
    "def _kd(_b, _s={seed}):\n"
    "    return bytes(c ^ ((_s ^ (i * 131 + 7)) & 0xFF) "
    "for i, c in enumerate(_b)).decode('utf-8')\n"
)


def _keystream_byte(seed: int, i: int) -> int:
    return (seed ^ (i * 131 + 7)) & 0xFF


def _encrypt(s: str, seed: int) -> bytes:
    raw = s.encode("utf-8")
    return bytes(c ^ _keystream_byte(seed, i) for i, c in enumerate(raw))


def _collect_skip_ids(tree: ast.AST) -> set[int]:
    """ŞifrelenMEYECEK Constant düğümlerinin id()'lerini topla."""
    skip: set[int] = set()

    def mark(node) -> None:
        for n in ast.walk(node):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                skip.add(id(n))

    # docstring'ler: modül/sınıf/fonksiyon gövdesinin ilk ifadesi string ise
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) \
                    and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                skip.add(id(body[0].value))
        # annotation'lar (from __future__ import annotations ile string olurlar)
        if isinstance(node, ast.AnnAssign) and node.annotation is not None:
            mark(node.annotation)
        if isinstance(node, ast.arg) and node.annotation is not None:
            mark(node.annotation)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.returns is not None:
            mark(node.returns)
        # f-string parçaları
        if isinstance(node, ast.JoinedStr):
            mark(node)
        # __all__ = [...] değerleri
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "__all__":
                    mark(node.value)
    return skip


class _Enc(ast.NodeTransformer):
    def __init__(self, seed: int, skip: set[int]):
        self.seed = seed
        self.skip = skip
        self.count = 0

    def visit_Constant(self, node: ast.Constant):
        if not isinstance(node.value, str):
            return node
        if id(node) in self.skip:
            return node
        s = node.value
        if len(s) < MIN_LEN or _DUNDER_RE.match(s):
            return node
        enc = _encrypt(s, self.seed)
        self.count += 1
        # _kd(b'...') çağrısı üret
        call = ast.Call(
            func=ast.Name(id="_kd", ctx=ast.Load()),
            args=[ast.Constant(value=enc)],
            keywords=[],
        )
        return ast.copy_location(call, node)


def _seed_for(name: str) -> int:
    # deterministik ama modül-başına DEĞİŞEN seed (her .so farklı keystream ->
    # RE'ci tek anahtarla toptan çözemez). 1..255 (0 keystream'i zayıflatır).
    h = 0
    for ch in name.encode("utf-8"):
        h = (h * 131 + ch) & 0xFFFFFFFF
    return (h % 255) + 1


def transform_source(src: str, seed: int) -> tuple[str, int]:
    """Kaynağı dönüştür. (yeni_kaynak, şifrelenen_string_sayısı) döner.
    Şifrelenecek string yoksa kaynağı DEĞİŞTİRMEDEN döner (idempotent-güvenli)."""
    tree = ast.parse(src)
    skip = _collect_skip_ids(tree)
    enc = _Enc(seed, skip)
    new_tree = enc.visit(tree)
    if enc.count == 0:
        return src, 0
    ast.fix_missing_locations(new_tree)
    body = new_tree.body

    # _kd çözücüsünü __future__ import'larından SONRA, ilk gerçek ifadeden ÖNCE ekle.
    insert_at = 0
    for i, stmt in enumerate(body):
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
            insert_at = i + 1
        elif isinstance(stmt, ast.Expr) and isinstance(
            getattr(stmt, "value", None), ast.Constant
        ):
            insert_at = i + 1  # modül docstring'ini atla
        else:
            break
    decoder_ast = ast.parse(_DECODER_TMPL.format(seed=seed)).body
    new_body = body[:insert_at] + decoder_ast + body[insert_at:]
    new_tree.body = new_body
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree), enc.count


def transform_file(path: Path) -> int:
    src = path.read_text(encoding="utf-8")
    seed = _seed_for(path.name)
    new_src, n = transform_source(src, seed)
    if n:
        path.write_text(new_src, encoding="utf-8")
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="String literal şifreleme (Faz B)")
    ap.add_argument("files", nargs="+", help="dönüştürülecek .py dosyaları")
    args = ap.parse_args()
    total = 0
    for f in args.files:
        p = Path(f)
        n = transform_file(p)
        total += n
        print(f"  {p.name}: {n} string şifrelendi")
    print(f"toplam {total} string şifrelendi")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
