"""P-Code dataflow analiz modulu.

Ghidra'nin P-Code intermediate representation'ini analiz ederek
def-use chain, alias detection ve variable lifetime hesaplar.
Bu bilgiler NameMerger'a ek guvenilirlik kaynagi olarak beslenir.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class VarnodeInfo:
    """Tek bir P-Code varnode'unun bilgileri.

    Varnode, P-Code'un temel veri tasiyan birimdir. Register, constant,
    unique temporary veya memory adresi olabilir.
    """
    space: str
    offset: int
    size: int
    is_constant: bool = False
    is_register: bool = False
    is_unique: bool = False
    high_variable: str | None = None

    @property
    def key(self) -> str:
        """Varnode'u benzersiz tanimlamak icin anahtar."""
        return "%s:%d:%d" % (self.space, self.offset, self.size)


@dataclass
class PcodeOpInfo:
    """Tek bir P-Code operasyonunun bilgileri.

    Mnemonic: COPY, INT_ADD, STORE, LOAD, CALL, BRANCH vb.
    Her op'un bir output varnode'u (sonuc) ve bir veya daha fazla
    input varnode'u (operand) vardir.
    """
    mnemonic: str
    seq_num: int
    address: str
    output: VarnodeInfo | None = None
    inputs: list[VarnodeInfo] = field(default_factory=list)


@dataclass
class FunctionPcode:
    """Bir fonksiyonun tum P-Code bilgileri."""
    name: str
    address: str
    ops: list[PcodeOpInfo] = field(default_factory=list)
    high_variables: list[dict] = field(default_factory=list)


@dataclass
class PcodeAnalysisResult:
    """P-Code analizinin toplam sonucu."""
    total_functions: int = 0
    total_pcode_ops: int = 0
    functions: list[FunctionPcode] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# JSON parsing yardimcilari
# ---------------------------------------------------------------------------

def _parse_varnode(raw: dict | None) -> VarnodeInfo | None:
    """JSON dict'ten VarnodeInfo olustur. Eksik alan varsa None dondurur."""
    if raw is None or not isinstance(raw, dict):
        return None
    try:
        return VarnodeInfo(
            space=raw.get("space", "unknown"),
            offset=int(raw.get("offset", 0)),
            size=int(raw.get("size", 0)),
            is_constant=bool(raw.get("is_constant", False)),
            is_register=bool(raw.get("is_register", False)),
            is_unique=bool(raw.get("is_unique", False)),
            high_variable=raw.get("high_variable"),
        )
    except (TypeError, ValueError) as exc:
        logger.debug("Varnode parse hatasi: %s", exc)
        return None


def _parse_pcode_op(raw: dict) -> PcodeOpInfo | None:
    """JSON dict'ten PcodeOpInfo olustur."""
    if not isinstance(raw, dict):
        return None
    try:
        inputs_raw = raw.get("inputs", [])
        inputs = []
        if isinstance(inputs_raw, list):
            for inp in inputs_raw:
                vn = _parse_varnode(inp)
                if vn is not None:
                    inputs.append(vn)

        return PcodeOpInfo(
            mnemonic=str(raw.get("mnemonic", "UNKNOWN")),
            seq_num=int(raw.get("seq_num", 0)),
            address=str(raw.get("address", "0x0")),
            output=_parse_varnode(raw.get("output")),
            inputs=inputs,
        )
    except (TypeError, ValueError) as exc:
        logger.debug("PcodeOp parse hatasi: %s", exc)
        return None


def _parse_function(raw: dict) -> FunctionPcode | None:
    """JSON dict'ten FunctionPcode olustur."""
    if not isinstance(raw, dict):
        return None
    try:
        ops = []
        for op_raw in raw.get("ops", []):
            op = _parse_pcode_op(op_raw)
            if op is not None:
                ops.append(op)

        return FunctionPcode(
            name=str(raw.get("name", "unknown")),
            address=str(raw.get("address", "0x0")),
            ops=ops,
            high_variables=raw.get("high_variables", []),
        )
    except (TypeError, ValueError) as exc:
        logger.debug("Function parse hatasi: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Ana analizci
# ---------------------------------------------------------------------------

class PcodeAnalyzer:
    """P-Code dataflow analizci.

    Ghidra pcode_analysis.py script'inin urettigi JSON ciktiyi yukler,
    parse eder ve dataflow analizi yapar:
    - Def-use chain: her degiskenin tanimlandigi ve kullanildigi yerler
    - Alias detection: COPY op'larindan alias ciftleri
    - Variable lifetime: degisken yasam suresi (first def -> last use)
    - Naming confidence boost: NameMerger'a beslenecek ek guven skorlari
    """

    def analyze(self, pcode_json_path: Path) -> PcodeAnalysisResult:
        """P-Code JSON dosyasini yukle ve parse et.

        Args:
            pcode_json_path: ghidra_pcode.json dosya yolu.

        Returns:
            PcodeAnalysisResult: Parse edilmis sonuc.
            JSON parse hatasi durumunda bos result doner, exception fırlatmaz.
        """
        try:
            with open(pcode_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning("P-Code JSON yuklenemedi: %s — %s", pcode_json_path, exc)
            return PcodeAnalysisResult()

        if not isinstance(data, dict):
            logger.warning("P-Code JSON root dict degil: %s", type(data))
            return PcodeAnalysisResult()

        # Fonksiyonlari parse et
        functions: list[FunctionPcode] = []
        raw_functions = data.get("functions", [])
        if isinstance(raw_functions, list):
            for raw_func in raw_functions:
                func = _parse_function(raw_func)
                if func is not None:
                    functions.append(func)

        total_ops = sum(len(f.ops) for f in functions)

        return PcodeAnalysisResult(
            total_functions=len(functions),
            total_pcode_ops=total_ops,
            functions=functions,
            stats=data.get("stats", {}),
        )

    def compute_def_use_chains(self, func: FunctionPcode) -> dict[str, dict]:
        """Fonksiyon icindeki her varnode icin def-use chain hesapla.

        Def: Bir varnode'un output olarak gorundugu op (varnode'a yazma).
        Use: Bir varnode'un input olarak gorundugu op (varnode'dan okuma).

        Args:
            func: P-Code bilgisi yuklu fonksiyon.

        Returns:
            dict: varnode_key -> {"defs": [seq_num, ...], "uses": [seq_num, ...]}
        """
        chains: dict[str, dict[str, list[int]]] = {}

        for op in func.ops:
            # Output varnode = definition
            if op.output is not None:
                key = op.output.key
                if key not in chains:
                    chains[key] = {"defs": [], "uses": []}
                chains[key]["defs"].append(op.seq_num)

            # Input varnode'lar = use
            for inp in op.inputs:
                key = inp.key
                if key not in chains:
                    chains[key] = {"defs": [], "uses": []}
                chains[key]["uses"].append(op.seq_num)

        return chains

    def detect_aliases(self, func: FunctionPcode) -> list[tuple[str, str]]:
        """COPY operasyonlarindan alias ciftlerini tespit et.

        COPY op: output <- input[0]. Eger iki varnode'un biri digerinin
        COPY'si ise, ayni degiskene referans veriyorlar demektir.

        Args:
            func: P-Code bilgisi yuklu fonksiyon.

        Returns:
            list: (kaynak_key, hedef_key) alias ciftleri.
        """
        aliases: list[tuple[str, str]] = []

        for op in func.ops:
            if op.mnemonic != "COPY":
                continue
            if op.output is None or len(op.inputs) == 0:
                continue
            source = op.inputs[0]
            target = op.output
            aliases.append((source.key, target.key))

        return aliases

    def variable_lifetime_analysis(
        self, func: FunctionPcode
    ) -> dict[str, tuple[int, int]]:
        """Her varnode icin yasam suresi hesapla.

        Yasam suresi = (ilk definition seq_num, son use seq_num).
        Eger varnode hic tanimlanmamissa (sadece use), def olarak -1 kullanilir.
        Eger varnode hic kullanilmamissa (sadece def), use olarak def ile ayni kullanilir.

        Args:
            func: P-Code bilgisi yuklu fonksiyon.

        Returns:
            dict: varnode_key -> (first_def_seq, last_use_seq)
        """
        chains = self.compute_def_use_chains(func)
        lifetimes: dict[str, tuple[int, int]] = {}

        for key, chain in chains.items():
            defs = chain["defs"]
            uses = chain["uses"]

            if defs:
                first_def = min(defs)
            else:
                # Hic def yok — disaridan gelen parametre veya global
                first_def = -1

            if uses:
                last_use = max(uses)
            elif defs:
                # Hic use yok — dead definition (yazildi ama okunmadi)
                last_use = max(defs)
            else:
                # Ne def ne use — bu olmamalı ama savunmaci kodlama
                last_use = -1

            lifetimes[key] = (first_def, last_use)

        return lifetimes

    def naming_confidence_boost(self, func: FunctionPcode) -> dict[str, float]:
        """Her high-level degisken icin isimlendirme guven artisi hesapla.

        NameMerger'a beslenecek ek skor: dataflow analizine gore degiskenin
        ne kadar "anlamli" oldugunu olcer.

        Kurallar:
        - Cok kullanilan degiskenler (>5 use) -> yuksek boost (0.7-1.0)
        - Tek use degiskenler -> dusuk boost (0.1-0.2)
        - Register-based degiskenler -> orta boost (0.4-0.6)
        - Sadece constant iceren degiskenler -> sifir boost (0.0)

        Args:
            func: P-Code bilgisi yuklu fonksiyon.

        Returns:
            dict: degisken_adi -> confidence_boost (0.0-1.0)
        """
        chains = self.compute_def_use_chains(func)
        boosts: dict[str, float] = {}

        # high_variable adi -> {total_uses, is_register, is_constant_only}
        var_stats: dict[str, dict] = {}

        for op in func.ops:
            # Output tarafindaki high variable'i kaydet
            if op.output is not None and op.output.high_variable is not None:
                name = op.output.high_variable
                if name not in var_stats:
                    var_stats[name] = {
                        "total_uses": 0,
                        "total_defs": 0,
                        "is_register": False,
                        "all_inputs_constant": True,
                    }
                var_stats[name]["total_defs"] += 1
                if op.output.is_register:
                    var_stats[name]["is_register"] = True

            # Input tarafindaki high variable'lari kaydet
            for inp in op.inputs:
                if inp.high_variable is not None:
                    name = inp.high_variable
                    if name not in var_stats:
                        var_stats[name] = {
                            "total_uses": 0,
                            "total_defs": 0,
                            "is_register": False,
                            "all_inputs_constant": True,
                        }
                    var_stats[name]["total_uses"] += 1
                    if inp.is_register:
                        var_stats[name]["is_register"] = True
                    if not inp.is_constant:
                        var_stats[name]["all_inputs_constant"] = False

        # Boost hesapla
        for name, stats in var_stats.items():
            uses = stats["total_uses"]
            is_reg = stats["is_register"]
            const_only = stats["all_inputs_constant"] and uses > 0 and stats["total_defs"] == 0

            if const_only:
                # Sadece constant — isimlendirme icin veri yok
                boosts[name] = 0.0
            elif uses > 5:
                # Cok kullanilan degisken — yuksek guven
                # 6 use -> 0.7, 10+ use -> 1.0 (lineer interpolasyon)
                boost = min(1.0, 0.7 + (uses - 6) * 0.075)
                boosts[name] = round(boost, 3)
            elif is_reg:
                # Register-based — orta guven
                # Use sayisina gore 0.4-0.6 arasi
                boost = min(0.6, 0.4 + uses * 0.05)
                boosts[name] = round(boost, 3)
            elif uses <= 1:
                # Tek use — dusuk guven
                boosts[name] = 0.1 if uses == 1 else 0.05
            else:
                # 2-5 use arasi, register degil
                boost = 0.2 + (uses - 2) * 0.1
                boosts[name] = round(min(boost, 0.5), 3)

        return boosts

    def get_dataflow_summary(self, result: PcodeAnalysisResult) -> dict:
        """Tum analiz sonuclari icin istatistik ozeti.

        Toplam fonksiyon, op, degisken sayilari; mnemonic dagilimi;
        ortalama yasam suresi ve alias oranini icerir.

        Args:
            result: analyze() ciktisi.

        Returns:
            dict: Istatistik ozeti.
        """
        total_aliases = 0
        total_vars = 0
        total_lifetime_span = 0
        lifetime_count = 0
        mnemonic_dist: dict[str, int] = {}

        for func in result.functions:
            # Alias sayisi
            aliases = self.detect_aliases(func)
            total_aliases += len(aliases)

            # Degisken sayisi
            total_vars += len(func.high_variables)

            # Yasam suresi ortalamasi
            lifetimes = self.variable_lifetime_analysis(func)
            for key, (first_def, last_use) in lifetimes.items():
                if first_def >= 0 and last_use >= 0:
                    span = last_use - first_def
                    total_lifetime_span += span
                    lifetime_count += 1

            # Mnemonic dagilimi
            for op in func.ops:
                mnemonic_dist[op.mnemonic] = mnemonic_dist.get(op.mnemonic, 0) + 1

        avg_lifetime = (
            round(total_lifetime_span / lifetime_count, 2)
            if lifetime_count > 0
            else 0.0
        )

        # En yaygin 10 mnemonic
        sorted_mnemonics = sorted(
            mnemonic_dist.items(), key=lambda x: x[1], reverse=True
        )
        top_mnemonics = dict(sorted_mnemonics[:10])

        return {
            "total_functions": result.total_functions,
            "total_pcode_ops": result.total_pcode_ops,
            "total_high_variables": total_vars,
            "total_aliases": total_aliases,
            "avg_variable_lifetime_span": avg_lifetime,
            "mnemonic_distribution_top10": top_mnemonics,
            "stats": result.stats,
        }

    # -------------------------------------------------------------------
    # JSONL streaming analiz
    # -------------------------------------------------------------------

    def analyze_streaming(self, jsonl_path: Path) -> PcodeAnalysisResult:
        """JSONL formatindaki pcode dosyasini satir satir analiz et.

        Her satir bir fonksiyonun compact pcode verisi:
        {"n": "func_name", "a": "addr", "ops": [[mnemonic, out, ins], ...], "vars": [...]}

        Bellek kullanimi: tek fonksiyon ~50KB (dosyanin tamami yuklenmez).
        """
        result = PcodeAnalysisResult()

        if not jsonl_path.exists():
            logger.warning("JSONL dosyasi bulunamadi: %s", jsonl_path)
            return result

        functions: list[FunctionPcode] = []

        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.debug("JSONL satir %d parse hatasi: %s", line_num, exc)
                    continue

                func = self._parse_jsonl_function(raw)
                if func is not None:
                    functions.append(func)
                    result.total_pcode_ops += len(func.ops)

        result.total_functions = len(functions)
        result.functions = functions
        return result

    def _parse_jsonl_function(self, raw: dict) -> FunctionPcode | None:
        """Compact JSONL satirindan FunctionPcode olustur.

        Compact format: ops = [[mnemonic, [space,offset,size], [[space,offset,size],...]], ...]
        Space lookup (ters): {0:"unique", 1:"register", 2:"const", 3:"ram", 4:"stack"}
        """
        _SPACE_REVERSE = {0: "unique", 1: "register", 2: "const", 3: "ram", 4: "stack"}

        name = raw.get("n", raw.get("name", "unknown"))
        address = raw.get("a", raw.get("address", "0x0"))

        ops = []
        for i, op_raw in enumerate(raw.get("ops", [])):
            if not isinstance(op_raw, (list, tuple)) or len(op_raw) < 1:
                continue

            mnemonic = op_raw[0]

            # Output varnode
            output = None
            if len(op_raw) > 1 and op_raw[1] is not None:
                out = op_raw[1]
                if isinstance(out, (list, tuple)) and len(out) >= 3:
                    output = VarnodeInfo(
                        space=_SPACE_REVERSE.get(out[0], "unknown"),
                        offset=int(out[1]),
                        size=int(out[2]),
                        is_constant=(out[0] == 2),
                        is_register=(out[0] == 1),
                        is_unique=(out[0] == 0),
                    )

            # Input varnodes
            inputs = []
            if len(op_raw) > 2 and isinstance(op_raw[2], list):
                for inp_raw in op_raw[2]:
                    if isinstance(inp_raw, (list, tuple)) and len(inp_raw) >= 3:
                        inputs.append(VarnodeInfo(
                            space=_SPACE_REVERSE.get(inp_raw[0], "unknown"),
                            offset=int(inp_raw[1]),
                            size=int(inp_raw[2]),
                            is_constant=(inp_raw[0] == 2),
                            is_register=(inp_raw[0] == 1),
                            is_unique=(inp_raw[0] == 0),
                        ))

            ops.append(PcodeOpInfo(
                mnemonic=mnemonic,
                seq_num=i,
                address=address,
                output=output,
                inputs=inputs,
            ))

        high_variables = raw.get("vars", raw.get("high_variables", []))

        return FunctionPcode(
            name=name,
            address=address,
            ops=ops,
            high_variables=high_variables,
        )

    # -------------------------------------------------------------------
    # Fonksiyon siniflandirma (mnemonic dagilimi)
    # -------------------------------------------------------------------

    def classify_function(self, func: FunctionPcode) -> tuple[str, float]:
        """Mnemonic dagiliminda fonksiyon tipini tahmin et.

        Returns:
            (classification_name, confidence) tuple.
            classification_name: "memory_operation", "dispatch_handler", "math_computation",
                                "validator_checker", "struct_accessor", "initializer_setup",
                                "generic" (siniflandirilamadi)
            confidence: 0.0-0.70 arasi (kasitli dusuk — Bayesian fusion'da diger kaynaklarla birlesecek)
        """
        if not func.ops:
            return ("generic", 0.0)

        total = len(func.ops)
        dist: dict[str, int] = {}
        for op in func.ops:
            dist[op.mnemonic] = dist.get(op.mnemonic, 0) + 1

        # Oranlar
        load_store = (dist.get("LOAD", 0) + dist.get("STORE", 0)) / total
        calls = (dist.get("CALL", 0) + dist.get("CALLIND", 0)) / total
        float_ops = sum(v for k, v in dist.items() if k.startswith("FLOAT_")) / total
        cbranch = dist.get("CBRANCH", 0) / total
        ptradd = (dist.get("PTRADD", 0) + dist.get("PTRSUB", 0)) / total
        copy_ops = dist.get("COPY", 0) / total
        int_arith = sum(dist.get(k, 0) for k in ("INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV")) / total

        # Siniflandirma (oncelik sirasinda)
        if float_ops > 0.15:
            conf = min(0.70, 0.40 + (float_ops - 0.15) * 2.0)
            return ("math_computation", round(conf, 3))

        if load_store > 0.40:
            conf = min(0.65, 0.40 + (load_store - 0.40) * 1.25)
            return ("memory_operation", round(conf, 3))

        if calls > 0.20 and int_arith < 0.10:
            conf = min(0.60, 0.35 + (calls - 0.20) * 1.25)
            return ("dispatch_handler", round(conf, 3))

        if cbranch > 0.12:
            conf = min(0.55, 0.30 + (cbranch - 0.12) * 2.5)
            return ("validator_checker", round(conf, 3))

        if ptradd > 0.10:
            conf = min(0.50, 0.25 + (ptradd - 0.10) * 2.5)
            return ("struct_accessor", round(conf, 3))

        if copy_ops > 0.30 and cbranch < 0.05:
            conf = min(0.50, 0.25 + (copy_ops - 0.30) * 1.25)
            return ("initializer_setup", round(conf, 3))

        return ("generic", 0.0)

    # -------------------------------------------------------------------
    # Naming candidate uretimi
    # -------------------------------------------------------------------

    def generate_naming_candidates(self, func: FunctionPcode) -> list[dict]:
        """Fonksiyon icin pcode-bazli naming candidate'leri uret.

        Iki katman:
        1. Fonksiyon siniflandirma -> fonksiyon ismi candidate
        2. Variable confidence boost -> mevcut candidate'ler icin boost bilgisi

        Returns:
            list of dicts: [
                {"function_name": "FUN_xxx", "candidate_name": "math_compute_XYZ",
                 "confidence": 0.55, "source": "pcode_dataflow",
                 "reason": "float_ops=%42, classify=math_computation"},
                ...
            ]
        """
        candidates = []

        # 1. Fonksiyon siniflandirma
        classification, conf = self.classify_function(func)
        if classification != "generic" and conf > 0.0:
            # Fonksiyon isim onerisi
            candidate_name = classification
            # Eger fonksiyon adresi varsa suffix ekle (cakisma onleme)
            if func.address and func.address != "0x0":
                addr_short = func.address.lstrip("0x").lstrip("0")[:6]
                candidate_name = "%s_%s" % (classification, addr_short)

            candidates.append({
                "function_name": func.name,
                "candidate_name": candidate_name,
                "confidence": conf,
                "source": "pcode_dataflow",
                "reason": "classify=%s" % classification,
            })

        # 2. Variable confidence boost bilgisi
        boosts = self.naming_confidence_boost(func)
        if boosts:
            # En yuksek boost'lu degiskenleri rapor et (naming quality gostergesi)
            avg_boost = sum(boosts.values()) / len(boosts) if boosts else 0.0
            if avg_boost > 0.3:
                candidates.append({
                    "function_name": func.name,
                    "candidate_name": "",  # Boost, isim degil
                    "confidence": 0.0,
                    "source": "pcode_boost",
                    "reason": "avg_var_boost=%.3f, n_vars=%d" % (avg_boost, len(boosts)),
                    "boost_scores": boosts,  # NameMerger pre-scaling icin
                })

        return candidates
