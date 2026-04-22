"""DWARF debug info extractor -- ground truth isim cikartici.

Debug bilgisi iceren binary'lerden (DWARF formatinda) gercek fonksiyon,
parametre ve lokal degisken isimlerini cikarir. Bu bilgi:
  1. n-gram DB egitimi icin ground truth olusturur
  2. Karadul signature DB'ye eklenir
  3. Ghidra ciktisiyla karsilastirma yapilarak reconstruction dogrulugu olculur

macOS'ta dwarfdump kullanir (/usr/bin/dwarfdump). Binary'nin kendisinde
veya yanindaki .dSYM bundle'inda debug info arar.

Kullanim:
    from karadul.analyzers.dwarf_extractor import DwarfExtractor

    ext = DwarfExtractor(Path("/usr/bin/sample"))
    if ext.has_debug_info():
        funcs = ext.extract_functions()
        gt = ext.to_ground_truth()
        sigs = ext.to_signature_json(lib_name="sample")
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# dwarfdump ciktisindaki indentation seviyesini baz alan regex'ler.
# Ornek satirlar:
#   0x0000002d:   DW_TAG_subprogram
#                   DW_AT_name	("calculate")
#                   DW_AT_low_pc	(0x0000000100000460)
_RE_TAG = re.compile(
    r"^0x[0-9a-f]+:\s+(DW_TAG_\w+)",
)
_RE_ATTR = re.compile(
    r"^\s+(DW_AT_\w+)\s+\((.+)\)\s*$",
)
# Indentation derinligini olcmek icin -- alt DIE'ler daha fazla indent'li
_RE_INDENT = re.compile(r"^(0x[0-9a-f]+:)(\s+)")
# NULL satiri -- bir DIE blogunun bitisini isaret eder
_RE_NULL = re.compile(r"^\s+NULL\s*$")

# Varsayilan timeout (saniye)
_DEFAULT_TIMEOUT = 30


@dataclass
class DwarfVariable:
    """DWARF'tan cikarilan degisken/parametre bilgisi.

    Attributes:
        name: Gercek degisken adi (orn: "buffer", "count").
        type_name: Tip bilgisi (orn: "int", "char *", "struct stat").
        is_param: True ise fonksiyon parametresi, False ise lokal degisken.
    """

    name: str
    type_name: str
    is_param: bool


@dataclass
class DwarfFunction:
    """DWARF'tan cikarilan fonksiyon bilgisi.

    Attributes:
        name: Gercek fonksiyon adi.
        address: Fonksiyon baslangic adresi (Ghidra ile eslestirme icin).
        params: Parametre listesi (sirali).
        locals: Lokal degisken listesi.
        return_type: Donus tipi.
        source_file: Kaynak dosya yolu.
        line_number: Kaynak dosyadaki satir numarasi.
    """

    name: str
    address: int
    params: list[DwarfVariable] = field(default_factory=list)
    locals: list[DwarfVariable] = field(default_factory=list)
    return_type: str = ""
    source_file: str = ""
    line_number: int = 0


class DwarfExtractor:
    """DWARF debug bilgisinden ground truth isim cikartici.

    macOS dwarfdump aracini kullanarak binary'deki fonksiyon, parametre
    ve lokal degisken isimlerini cikarir.

    Args:
        binary_path: Analiz edilecek binary dosya yolu.
        timeout: dwarfdump icin maksimum calisma suresi (saniye).
    """

    def __init__(self, binary_path: Path, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self.binary_path = Path(binary_path)
        self.timeout = timeout
        self._dwarf_target = self._resolve_dwarf_target()

    def _resolve_dwarf_target(self) -> Path | None:
        """dwarfdump icin hedef dosya yolunu belirle.

        macOS'ta debug info genelde binary'nin yanindaki .dSYM bundle'indadir.
        Binary'nin kendisinde debug info yoksa .dSYM aranir.

        Returns:
            dwarfdump'a verilecek Path, yoksa None.
        """
        if not self.binary_path.exists():
            logger.warning("Binary bulunamadi: %s", self.binary_path)
            return None

        # Oncelik: .dSYM bundle (macOS standard)
        dsym_path = self.binary_path.parent / f"{self.binary_path.name}.dSYM"
        if dsym_path.exists() and dsym_path.is_dir():
            logger.debug("dSYM bundle bulundu: %s", dsym_path)
            return dsym_path

        # Fallback: binary'nin kendisi (Linux ELF veya embedded DWARF)
        return self.binary_path

    def has_debug_info(self) -> bool:
        """Binary'de DWARF debug bilgisi var mi kontrol et.

        dwarfdump --debug-info ciktisinin bos olup olmadigina bakar.
        Hem binary'nin kendisini hem .dSYM bundle'ini dener.

        Returns:
            True: debug info mevcut, False: yok veya dwarfdump bulunamadi.
        """
        if self._dwarf_target is None:
            return False

        try:
            proc = subprocess.run(
                ["dwarfdump", "--debug-info", str(self._dwarf_target)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            logger.warning("dwarfdump bulunamadi (macOS CLT kurulu mu?)")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("dwarfdump timeout (has_debug_info)")
            return False

        if proc.returncode != 0:
            return False

        # dwarfdump ciktisinda DW_TAG_ varsa debug info mevcuttur.
        # Bos ciktida sadece header satiri olur: "file format Mach-O ..."
        # ve ".debug_info contents:" -- ama hic DW_TAG olmaz.
        for line in proc.stdout.splitlines():
            if "DW_TAG_" in line:
                return True
        return False

    def extract_functions(self) -> list[DwarfFunction]:
        """Tum fonksiyonlari parametreleri ve lokalleriyle birlikte cikar.

        dwarfdump --debug-info ciktisini satir satir incremental parse eder.
        Buyuk binary'ler icin tum ciktiyi bellegte tutmaz -- subprocess'in
        stdout'unu satir satir okur.

        Returns:
            DwarfFunction listesi. Debug info yoksa bos liste.
        """
        if self._dwarf_target is None:
            return []

        functions: list[DwarfFunction] = []
        total_params = 0
        total_locals = 0

        try:
            for func in self._parse_dwarf_stream():
                functions.append(func)
                total_params += len(func.params)
                total_locals += len(func.locals)
        except FileNotFoundError:
            logger.warning("dwarfdump bulunamadi (macOS CLT kurulu mu?)")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(
                "dwarfdump timeout (%ds), %d fonksiyon cikarildi (kismi sonuc)",
                self.timeout, len(functions),
            )
            # Kismi sonuc -- timeout'a kadar parse edilen fonksiyonlari dondur
            return functions

        logger.info(
            "DWARF extraction tamamlandi: %d fonksiyon, %d parametre, %d lokal",
            len(functions), total_params, total_locals,
        )
        return functions

    def to_ground_truth(self) -> dict[str, dict]:
        """n-gram DB egitimi icin ground truth formatina cevir.

        Returns:
            {func_name: {
                "params": {0: "count", 1: "buffer", ...},
                "locals": {"local_var_10": "result", ...},
                "return_type": "int",
                "source_file": "/path/to/source.c",
            }}

        Not: locals dict'inde key olarak simdiye kadar Ghidra'nin urettigi
        generic isim kullanilmiyor -- sadece gercek isim. Eslestirme icin
        adres bazli matching gerekli (bu is DwarfExtractor'in disinda).
        """
        functions = self.extract_functions()
        result: dict[str, dict] = {}

        for func in functions:
            params_dict = {}
            for idx, param in enumerate(func.params):
                params_dict[idx] = param.name

            locals_dict = {}
            for local in func.locals:
                # Key: gercek isim (eslestirme icin adres bilgisi ayrica tutulabilir)
                locals_dict[local.name] = {
                    "type": local.type_name,
                }

            result[func.name] = {
                "address": hex(func.address) if func.address else "0x0",
                "params": params_dict,
                "locals": locals_dict,
                "return_type": func.return_type,
                "source_file": func.source_file,
                "line_number": func.line_number,
            }

        return result

    def to_signature_json(self, lib_name: str = "") -> dict:
        """Karadul signature DB formatina cevir.

        Signature DB'de her fonksiyon icin parametre ve tip bilgisi tutulur.
        Bu format karadul/analyzers/signature_db.py ile uyumludur.

        Args:
            lib_name: Kutuphane/binary adi (orn: "libssl", "nginx").

        Returns:
            {"library": lib_name,
             "source": "dwarf",
             "functions": {
                 func_name: {
                     "address": "0x...",
                     "return_type": "int",
                     "params": [{"name": "count", "type": "int"}, ...],
                     "locals": [{"name": "result", "type": "int"}, ...],
                 }, ...
             }}
        """
        functions = self.extract_functions()

        func_dict: dict[str, dict] = {}
        for func in functions:
            func_dict[func.name] = {
                "address": hex(func.address) if func.address else "0x0",
                "return_type": func.return_type,
                "source_file": func.source_file,
                "line_number": func.line_number,
                "params": [
                    {"name": p.name, "type": p.type_name}
                    for p in func.params
                ],
                "locals": [
                    {"name": v.name, "type": v.type_name}
                    for v in func.locals
                ],
            }

        return {
            "library": lib_name or self.binary_path.stem,
            "source": "dwarf",
            "binary": str(self.binary_path),
            "function_count": len(func_dict),
            "functions": func_dict,
        }

    # ------------------------------------------------------------------
    # Incremental DWARF parser
    # ------------------------------------------------------------------

    def _parse_dwarf_stream(self) -> Iterator[DwarfFunction]:
        """dwarfdump ciktisini incremental olarak parse et.

        subprocess.Popen ile dwarfdump calistirip stdout'u satir satir okur.
        Tum ciktiyi bellegte tutmaz -- buyuk binary'ler (100MB+ dwarfdump output)
        icin guvenlidir.

        v1.10.0 Fix Sprint HIGH-5: Popen context manager + TimeoutExpired
        durumunda kill/wait ile kaynak sizintisi onlendi.

        Yields:
            DwarfFunction nesneleri (her DW_TAG_subprogram icin bir tane).
        """
        with subprocess.Popen(
            ["dwarfdump", "--debug-info", str(self._dwarf_target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Satir buffered
        ) as proc:
            try:
                yield from self._parse_lines(proc.stdout)
            finally:
                # Process'i temiz kapat
                try:
                    if proc.stdout is not None:
                        proc.stdout.close()
                except Exception:
                    logger.debug("Session/kaynak kapatma basarisiz, atlaniyor", exc_info=True)
                try:
                    if proc.stderr is not None:
                        proc.stderr.close()
                except Exception:
                    logger.debug("Session/kaynak kapatma basarisiz, atlaniyor", exc_info=True)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        pass

    def _parse_lines(self, line_iter) -> Iterator[DwarfFunction]:
        """dwarfdump satir stream'ini parse et.

        State machine:
          IDLE -> DW_TAG_subprogram goruldugunde -> FUNC
          FUNC -> DW_TAG_formal_parameter goruldugunde -> PARAM
          FUNC -> DW_TAG_variable goruldugunde -> LOCAL
          FUNC/PARAM/LOCAL -> yeni DW_TAG_subprogram veya NULL -> emit + IDLE/FUNC

        dwarfdump ciktisinda indentation onemli:
          - DW_TAG_subprogram ustunde
          - DW_TAG_formal_parameter ve DW_TAG_variable onun alt DIE'leri

        Yields:
            DwarfFunction nesneleri.
        """
        # Aktif fonksiyon parse state'i
        current_func: _FuncParseState | None = None
        # Aktif parametre/lokal parse state'i
        current_child: _ChildParseState | None = None
        # Indent tracking -- subprogram'in indent seviyesini bilmek lazim
        func_indent: int = 0
        # True iken attribute'lar fonksiyona uygulanmaz
        # (DW_TAG_lexical_block gibi irrelevant child DIE icindeyken)
        in_ignored_child: bool = False

        for line in line_iter:
            line = line.rstrip("\n")

            # Bos satir -- atla
            if not line.strip():
                continue

            # NULL satiri -- bir DIE blogunun kapanisi
            null_match = _RE_NULL.match(line)
            if null_match:
                # Aktif child varsa kaydet
                if current_child is not None and current_func is not None:
                    self._commit_child(current_func, current_child)
                    current_child = None
                # Ignored child (lexical_block vb.) kapandi
                in_ignored_child = False
                continue

            # Yeni TAG satiri mi?
            tag_match = _RE_TAG.match(line)
            if tag_match:
                tag_name = tag_match.group(1)

                # Indent seviyesini hesapla
                indent_match = _RE_INDENT.match(line)
                indent = len(indent_match.group(2)) if indent_match else 0

                # -- DW_TAG_subprogram: yeni fonksiyon baslangici --
                if tag_name == "DW_TAG_subprogram":
                    # Onceki aktif child'i kaydet
                    if current_child is not None and current_func is not None:
                        self._commit_child(current_func, current_child)
                        current_child = None

                    # Onceki fonksiyonu emit et
                    if current_func is not None:
                        func = current_func.to_dwarf_function()
                        if func is not None:
                            yield func

                    current_func = _FuncParseState()
                    func_indent = indent
                    current_child = None
                    in_ignored_child = False
                    continue

                # -- Fonksiyon icindeyken alt DIE'ler --
                if current_func is not None and indent > func_indent:
                    # Onceki child'i kaydet
                    if current_child is not None:
                        self._commit_child(current_func, current_child)
                        current_child = None

                    if tag_name == "DW_TAG_formal_parameter":
                        current_child = _ChildParseState(is_param=True)
                        in_ignored_child = False
                    elif tag_name == "DW_TAG_variable":
                        current_child = _ChildParseState(is_param=False)
                        in_ignored_child = False
                    elif tag_name == "DW_TAG_lexical_block":
                        # Lexical block -- icindeki variable'lar da lokal
                        # AMA attribute'lari (DW_AT_low_pc vb.) fonksiyona
                        # uygulanmamali -- in_ignored_child ile koru
                        current_child = None
                        in_ignored_child = True
                    else:
                        # Baska tag'ler (DW_TAG_label vb.) -- atla
                        current_child = None
                        in_ignored_child = True
                    continue

                # Farkli indent'te baska bir tag -- fonksiyon bitmis demek
                if current_func is not None and indent <= func_indent:
                    if current_child is not None:
                        self._commit_child(current_func, current_child)
                        current_child = None

                    func = current_func.to_dwarf_function()
                    if func is not None:
                        yield func
                    current_func = None

                    # Bu yeni tag bir subprogram olabilir (yukarida handle edildi)
                    if tag_name == "DW_TAG_subprogram":
                        current_func = _FuncParseState()
                        func_indent = indent
                continue

            # Attribute satiri mi?
            attr_match = _RE_ATTR.match(line)
            if attr_match:
                attr_name = attr_match.group(1)
                attr_value = attr_match.group(2).strip()

                # Ignored child icindeyken (lexical_block vb.) attribute'lari atla
                # yoksa DW_AT_low_pc gibi degerler fonksiyonun adresini bozar
                if in_ignored_child:
                    continue

                # Aktif child varsa -- child'in attribute'u
                if current_child is not None:
                    self._apply_child_attr(current_child, attr_name, attr_value)
                # Aktif fonksiyon varsa -- fonksiyonun attribute'u
                elif current_func is not None:
                    self._apply_func_attr(current_func, attr_name, attr_value)

        # Son fonksiyon -- stream bitti
        if current_child is not None and current_func is not None:
            self._commit_child(current_func, current_child)
        if current_func is not None:
            func = current_func.to_dwarf_function()
            if func is not None:
                yield func

    # ------------------------------------------------------------------
    # Attribute application
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_func_attr(state: _FuncParseState, attr: str, value: str) -> None:
        """Fonksiyon DIE'sine ait attribute'u state'e uygula."""
        if attr == "DW_AT_name":
            state.name = _strip_quotes(value)
        elif attr == "DW_AT_low_pc":
            state.address = _parse_hex(value)
        elif attr == "DW_AT_type":
            state.return_type = _extract_type_name(value)
        elif attr == "DW_AT_decl_file":
            state.source_file = _strip_quotes(value)
        elif attr == "DW_AT_decl_line":
            state.line_number = _parse_int(value)

    @staticmethod
    def _apply_child_attr(state: _ChildParseState, attr: str, value: str) -> None:
        """Parametre/lokal DIE'sine ait attribute'u state'e uygula."""
        if attr == "DW_AT_name":
            state.name = _strip_quotes(value)
        elif attr == "DW_AT_type":
            state.type_name = _extract_type_name(value)

    @staticmethod
    def _commit_child(func_state: _FuncParseState, child: _ChildParseState) -> None:
        """Parse edilen child'i (param/lokal) fonksiyon state'ine ekle."""
        if not child.name:
            return  # Isimsiz -- atla (compiler generated olabilir)

        var = DwarfVariable(
            name=child.name,
            type_name=child.type_name or "<unknown>",
            is_param=child.is_param,
        )

        if child.is_param:
            func_state.params.append(var)
        else:
            func_state.locals.append(var)


# ------------------------------------------------------------------
# Internal parse state dataclass'lari
# ------------------------------------------------------------------

@dataclass
class _FuncParseState:
    """DW_TAG_subprogram parse ederken gecici state."""

    name: str = ""
    address: int = 0
    return_type: str = ""
    source_file: str = ""
    line_number: int = 0
    params: list[DwarfVariable] = field(default_factory=list)
    locals: list[DwarfVariable] = field(default_factory=list)

    def to_dwarf_function(self) -> DwarfFunction | None:
        """State'i DwarfFunction'a cevir. Isimsiz ise None dondur."""
        if not self.name:
            return None
        return DwarfFunction(
            name=self.name,
            address=self.address,
            params=list(self.params),
            locals=list(self.locals),
            return_type=self.return_type,
            source_file=self.source_file,
            line_number=self.line_number,
        )


@dataclass
class _ChildParseState:
    """DW_TAG_formal_parameter veya DW_TAG_variable parse state'i."""

    is_param: bool
    name: str = ""
    type_name: str = ""


# ------------------------------------------------------------------
# String/value parse yardimcilari
# ------------------------------------------------------------------

def _strip_quotes(value: str) -> str:
    """dwarfdump attribute degerindeki tirnaklari soy.

    Ornek: '"calculate"' -> 'calculate'
           '"/tmp/test.c"' -> '/tmp/test.c'
    """
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _parse_hex(value: str) -> int:
    """Hex adres degerini int'e cevir.

    Ornek: '0x0000000100000460' -> 4294968416
    """
    value = value.strip()
    # Bazen degerden sonra ek bilgi olabiliyor, orn: "0x100 (relocated)"
    # Ilk hex token'i al
    hex_match = re.match(r"(0x[0-9a-fA-F]+)", value)
    if hex_match:
        return int(hex_match.group(1), 16)
    return 0


def _parse_int(value: str) -> int:
    """Integer deger parse et. Hata durumunda 0 dondur."""
    try:
        return int(value.strip())
    except ValueError:
        return 0


def _extract_type_name(value: str) -> str:
    """DW_AT_type attribute'undan tip ismini cikar.

    dwarfdump formati:
      (0x000000f0 "int")
      (0x000000f4 "char *")
      (0x000000fe "Point")

    Tirnak icindeki ismi dondurur. Tirnak yoksa ham degeri dondurur.
    """
    # Tirnak icindeki ismi bul
    quote_match = re.search(r'"([^"]*)"', value)
    if quote_match:
        return quote_match.group(1)
    return value.strip()
