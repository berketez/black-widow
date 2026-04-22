"""DtsNamer testleri -- TypeScript .d.ts export isim eslestirme.

Test edilen senaryolar:
- parse_dts: function, class, interface, type, const, enum, namespace, default, export list
- match_exports: exact, order-based, runtime-filtered, partial
- rename_minified: tam workflow (mock fetch ile)
- Edge case'ler: bos input, nested generics, re-export, parametre sayma
"""

from __future__ import annotations

import pytest

from karadul.reconstruction.dts_namer import (
    DtsExport,
    DtsMatchResult,
    DtsNamer,
    DtsNamerResult,
    _count_params,
)


# ---------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------


@pytest.fixture
def namer() -> DtsNamer:
    """Varsayilan DtsNamer (network cagrisiz)."""
    return DtsNamer()


@pytest.fixture
def sample_dts() -> str:
    """Ornek .d.ts icerigi."""
    return """\
export declare function createElement(type: string, props?: any): Element;
export declare function render(element: Element, container: HTMLElement): void;
export declare function useState<T>(initial: T): [T, (v: T) => void];
export declare class Component<P = {}> {
    props: P;
    render(): Element;
}
export interface Config {
    debug: boolean;
    version: string;
}
export type Reducer<S, A> = (state: S, action: A) => S;
export declare const version: string;
export declare enum Mode {
    Development = 0,
    Production = 1,
}
export declare namespace internal {
    function __SECRET_API(): void;
}
"""


@pytest.fixture
def lodash_dts() -> str:
    """Lodash-benzeri .d.ts icerigi."""
    return """\
export declare function chunk<T>(array: T[], size?: number): T[][];
export declare function compact<T>(array: T[]): T[];
export declare function concat<T>(...values: T[]): T[];
export declare function difference<T>(array: T[], ...values: T[][]): T[];
export declare function drop<T>(array: T[], n?: number): T[];
export declare function flatten<T>(array: T[]): T[];
export declare function head<T>(array: T[]): T | undefined;
export declare function last<T>(array: T[]): T | undefined;
export declare function uniq<T>(array: T[]): T[];
export declare function zip<T>(...arrays: T[][]): T[][];
"""


# ---------------------------------------------------------------
# parse_dts testleri
# ---------------------------------------------------------------


class TestParseDts:
    """parse_dts() -- .d.ts dosya parse testleri."""

    def test_parse_functions(self, namer: DtsNamer, sample_dts: str) -> None:
        """Fonksiyonlar dogru parse edilmeli."""
        exports = namer.parse_dts(sample_dts)
        funcs = [e for e in exports if e.kind == "function"]
        func_names = {f.name for f in funcs}
        assert "createElement" in func_names
        assert "render" in func_names
        assert "useState" in func_names

    def test_parse_class(self, namer: DtsNamer, sample_dts: str) -> None:
        """Class'lar dogru parse edilmeli."""
        exports = namer.parse_dts(sample_dts)
        classes = [e for e in exports if e.kind == "class"]
        assert len(classes) == 1
        assert classes[0].name == "Component"

    def test_parse_interface(self, namer: DtsNamer, sample_dts: str) -> None:
        """Interface'ler dogru parse edilmeli."""
        exports = namer.parse_dts(sample_dts)
        ifaces = [e for e in exports if e.kind == "interface"]
        assert len(ifaces) == 1
        assert ifaces[0].name == "Config"

    def test_parse_type_alias(self, namer: DtsNamer, sample_dts: str) -> None:
        """Type alias'lar dogru parse edilmeli."""
        exports = namer.parse_dts(sample_dts)
        types = [e for e in exports if e.kind == "type"]
        assert len(types) == 1
        assert types[0].name == "Reducer"

    def test_parse_const(self, namer: DtsNamer, sample_dts: str) -> None:
        """Const export'lar dogru parse edilmeli."""
        exports = namer.parse_dts(sample_dts)
        consts = [e for e in exports if e.kind == "const"]
        assert len(consts) == 1
        assert consts[0].name == "version"

    def test_parse_enum(self, namer: DtsNamer, sample_dts: str) -> None:
        """Enum export'lar dogru parse edilmeli."""
        exports = namer.parse_dts(sample_dts)
        enums = [e for e in exports if e.kind == "enum"]
        assert len(enums) == 1
        assert enums[0].name == "Mode"

    def test_parse_namespace(self, namer: DtsNamer, sample_dts: str) -> None:
        """Namespace export'lar dogru parse edilmeli."""
        exports = namer.parse_dts(sample_dts)
        ns = [e for e in exports if e.kind == "namespace"]
        assert len(ns) == 1
        assert ns[0].name == "internal"

    def test_parse_empty(self, namer: DtsNamer) -> None:
        """Bos dts icerigi bos liste dondurmeli."""
        assert namer.parse_dts("") == []
        assert namer.parse_dts("   \n\n") == []

    def test_parse_no_exports(self, namer: DtsNamer) -> None:
        """Export olmayan .d.ts bos liste dondurmeli."""
        code = """
        interface Foo { x: number; }
        type Bar = string;
        function helper(): void;
        """
        assert namer.parse_dts(code) == []

    def test_parse_export_list(self, namer: DtsNamer) -> None:
        """export { A, B, C } syntax'i dogru parse edilmeli."""
        code = "export { foo, bar, baz }"
        exports = namer.parse_dts(code)
        names = {e.name for e in exports}
        assert names == {"foo", "bar", "baz"}

    def test_parse_export_as(self, namer: DtsNamer) -> None:
        """export { A as B } syntax'i dogru parse edilmeli."""
        code = "export { internal as api, helper as util }"
        exports = namer.parse_dts(code)
        names = {e.name for e in exports}
        assert "api" in names
        assert "util" in names

    def test_parse_default_export(self, namer: DtsNamer) -> None:
        """export default ... dogru parse edilmeli."""
        code = "export default function createApp(): App;"
        exports = namer.parse_dts(code)
        assert len(exports) >= 1
        defaults = [e for e in exports if e.is_default]
        assert len(defaults) >= 1
        assert defaults[0].name == "createApp"

    def test_parse_no_duplicate_names(self, namer: DtsNamer) -> None:
        """Ayni isim birden fazla kez eklenmemeli."""
        code = """\
export declare function foo(): void;
export { foo };
"""
        exports = namer.parse_dts(code)
        foo_count = sum(1 for e in exports if e.name == "foo")
        assert foo_count == 1

    def test_parse_param_count(self, namer: DtsNamer) -> None:
        """Fonksiyon parametre sayisi dogru hesaplanmali."""
        code = """\
export declare function noArgs(): void;
export declare function oneArg(x: number): number;
export declare function twoArgs(a: string, b: number): boolean;
export declare function threeArgs(a: string, b: number, c?: boolean): void;
"""
        exports = namer.parse_dts(code)
        funcs = {e.name: e.param_count for e in exports if e.kind == "function"}
        assert funcs["noArgs"] == 0
        assert funcs["oneArg"] == 1
        assert funcs["twoArgs"] == 2
        assert funcs["threeArgs"] == 3

    def test_parse_abstract_class(self, namer: DtsNamer) -> None:
        """abstract class da tespit edilmeli."""
        code = "export declare abstract class BaseComponent {}"
        exports = namer.parse_dts(code)
        assert len(exports) == 1
        assert exports[0].name == "BaseComponent"
        assert exports[0].kind == "class"

    def test_parse_const_enum(self, namer: DtsNamer) -> None:
        """const enum da tespit edilmeli."""
        code = "export declare const enum Direction { Up, Down, Left, Right }"
        exports = namer.parse_dts(code)
        assert len(exports) == 1
        assert exports[0].name == "Direction"
        assert exports[0].kind == "enum"


# ---------------------------------------------------------------
# _count_params testleri
# ---------------------------------------------------------------


class TestCountParams:
    """_count_params() utility fonksiyonu."""

    def test_empty_params(self) -> None:
        assert _count_params("") == 0

    def test_single_param(self) -> None:
        assert _count_params("x: number") == 1

    def test_two_params(self) -> None:
        assert _count_params("a: string, b: number") == 2

    def test_nested_generic(self) -> None:
        """Nested generics icindeki virgul sayilmamali."""
        assert _count_params("arr: Array<Map<string, number>>, n: number") == 2

    def test_callback_param(self) -> None:
        """Callback icindeki virgul sayilmamali."""
        assert _count_params("fn: (a: string, b: number) => void, ctx: any") == 2


# ---------------------------------------------------------------
# match_exports testleri
# ---------------------------------------------------------------


class TestMatchExports:
    """match_exports() -- minified export eslestirme testleri."""

    def test_exact_match_all(self, namer: DtsNamer) -> None:
        """Tum isimler eslesmisse exact match."""
        minified = ["foo", "bar", "baz"]
        dts = [
            DtsExport(name="foo", kind="function"),
            DtsExport(name="bar", kind="function"),
            DtsExport(name="baz", kind="const"),
        ]
        result = namer.match_exports(minified, dts)
        assert result.confidence == 1.0
        assert result.method == "exact"
        assert result.matched == {"foo": "foo", "bar": "bar", "baz": "baz"}

    def test_order_based_match(self, namer: DtsNamer) -> None:
        """Isimler farkli ama sayi esit ise order-based eslestirme."""
        minified = ["a", "b", "c"]
        dts = [
            DtsExport(name="chunk", kind="function"),
            DtsExport(name="compact", kind="function"),
            DtsExport(name="concat", kind="function"),
        ]
        result = namer.match_exports(minified, dts)
        assert result.matched == {"a": "chunk", "b": "compact", "c": "concat"}
        assert result.method == "exact+order"
        # v1.10.0 Batch 3D: sahte >= 0 yerine gercek davranis testi.
        # Order-based match icin match_exports 0.7 sabit guven verir (bkz.
        # dts_namer.py:409). Bu degisirse test kasitli kirilmali.
        assert result.confidence == pytest.approx(0.7)

    def test_runtime_filtered_match(self, namer: DtsNamer) -> None:
        """dts'de type/interface gibi runtime olmayan export'lar filtrelenmeli."""
        minified = ["a", "b"]
        dts = [
            DtsExport(name="create", kind="function"),
            DtsExport(name="Options", kind="interface"),
            DtsExport(name="destroy", kind="function"),
            DtsExport(name="Config", kind="type"),
        ]
        result = namer.match_exports(minified, dts)
        assert result.matched == {"a": "create", "b": "destroy"}
        assert "runtime_filtered" in result.method

    def test_partial_match(self, namer: DtsNamer) -> None:
        """Sayi uyusmazligi varsa kismi eslestirme."""
        minified = ["a", "b", "c", "d", "e"]
        dts = [
            DtsExport(name="alpha", kind="function"),
            DtsExport(name="beta", kind="function"),
            DtsExport(name="gamma", kind="function"),
        ]
        result = namer.match_exports(minified, dts)
        assert len(result.matched) == 3
        assert "a" in result.matched
        assert result.unmatched_minified == ["d", "e"]

    def test_empty_minified(self, namer: DtsNamer) -> None:
        """Bos minified listesi bos sonuc dondurmeli."""
        dts = [DtsExport(name="foo", kind="function")]
        result = namer.match_exports([], dts)
        assert len(result.matched) == 0
        assert result.unmatched_dts == ["foo"]

    def test_empty_dts(self, namer: DtsNamer) -> None:
        """Bos dts listesi bos sonuc dondurmeli."""
        result = namer.match_exports(["a", "b"], [])
        assert len(result.matched) == 0
        assert result.unmatched_minified == ["a", "b"]

    def test_mixed_exact_and_order(self, namer: DtsNamer) -> None:
        """Bazi isimler exact eslesmis, kalanlar order ile eslesmeli."""
        minified = ["chunk", "b", "c"]
        dts = [
            DtsExport(name="chunk", kind="function"),
            DtsExport(name="compact", kind="function"),
            DtsExport(name="concat", kind="function"),
        ]
        result = namer.match_exports(minified, dts)
        assert result.matched["chunk"] == "chunk"
        assert "b" in result.matched
        assert "c" in result.matched

    def test_match_result_to_dict(self, namer: DtsNamer) -> None:
        """DtsMatchResult.to_dict() calismali."""
        result = namer.match_exports(["a"], [DtsExport(name="foo", kind="function")])
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "matched" in d
        assert "confidence" in d


# ---------------------------------------------------------------
# fetch_dts_content (mock) testleri
# ---------------------------------------------------------------


class TestFetchDts:
    """fetch_dts_content() -- mock ile test."""

    def test_fetch_with_mock(self) -> None:
        """Mock fetcher ile .d.ts indirme."""
        mock_content = "export declare function foo(): void;"
        namer = DtsNamer(fetcher=lambda url: mock_content)
        content = namer.fetch_dts_content("test-pkg")
        assert content == mock_content

    def test_fetch_returns_none(self) -> None:
        """Mock fetcher None dondururse None donmeli."""
        namer = DtsNamer(fetcher=lambda url: None)
        content = namer.fetch_dts_content("nonexistent")
        assert content is None


# ---------------------------------------------------------------
# rename_minified testleri (tam workflow)
# ---------------------------------------------------------------


class TestRenameMinified:
    """rename_minified() -- tam workflow testleri."""

    def test_rename_full_workflow(self, lodash_dts: str) -> None:
        """Tam workflow: fetch + parse + match."""
        namer = DtsNamer(fetcher=lambda url: lodash_dts)
        minified = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
        result = namer.rename_minified("lodash", minified, dts_content=lodash_dts)
        assert isinstance(result, DtsNamerResult)
        assert result.success is True
        assert result.matches_found == 10
        assert result.mapping["a"] == "chunk"
        assert result.mapping["j"] == "zip"

    def test_rename_with_dts_content(self) -> None:
        """dts_content dogrudan verildiginde fetch atlanmali."""
        dts = """\
export declare function foo(): void;
export declare function bar(x: number): string;
"""
        namer = DtsNamer()
        result = namer.rename_minified("test", ["a", "b"], dts_content=dts)
        assert result.success is True
        assert result.mapping["a"] == "foo"
        assert result.mapping["b"] == "bar"

    def test_rename_no_dts(self) -> None:
        """DTS bulunamazsa hata mesaji donmeli."""
        namer = DtsNamer(fetcher=lambda url: None)
        result = namer.rename_minified("nonexistent", ["a", "b"])
        assert result.success is False
        assert len(result.errors) > 0

    def test_rename_result_to_dict(self, lodash_dts: str) -> None:
        """DtsNamerResult.to_dict() calismali."""
        namer = DtsNamer(fetcher=lambda url: lodash_dts)
        result = namer.rename_minified("lodash", ["a"], dts_content=lodash_dts)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "mapping" in d
        assert "success" in d


# ---------------------------------------------------------------
# load_dts_from_file testleri
# ---------------------------------------------------------------


class TestLoadDtsFromFile:
    """load_dts_from_file() -- lokal dosya testleri."""

    def test_load_from_file(self, namer: DtsNamer, tmp_path) -> None:
        """Lokal .d.ts dosyasindan export okumali."""
        dts_file = tmp_path / "index.d.ts"
        dts_file.write_text(
            "export declare function hello(): string;\n"
            "export declare function world(n: number): void;\n",
            encoding="utf-8",
        )
        exports = namer.load_dts_from_file(dts_file)
        assert len(exports) == 2
        assert exports[0].name == "hello"
        assert exports[1].name == "world"

    def test_load_nonexistent_file(self, namer: DtsNamer, tmp_path) -> None:
        """Olmayan dosya bos liste dondurmeli."""
        exports = namer.load_dts_from_file(tmp_path / "nope.d.ts")
        assert exports == []


# ---------------------------------------------------------------
# DtsExport data class testleri
# ---------------------------------------------------------------


class TestDtsExport:
    """DtsExport data class testleri."""

    def test_to_dict(self) -> None:
        """DtsExport.to_dict() calismali."""
        exp = DtsExport(
            name="foo",
            kind="function",
            signature="export declare function foo(): void",
            is_default=False,
            param_count=0,
        )
        d = exp.to_dict()
        assert d["name"] == "foo"
        assert d["kind"] == "function"
        assert d["param_count"] == 0

    def test_default_values(self) -> None:
        """Varsayilan degerler dogru olmali."""
        exp = DtsExport(name="bar", kind="const")
        assert exp.signature == ""
        assert exp.is_default is False
        assert exp.param_count == -1
