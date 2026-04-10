"""Iterative callee-profile function naming propagation.

Callee profilleme ile fonksiyon adlandirma yayilimi:
Bir fonksiyonun cagirdigi bilinen fonksiyonlarin domain dagilimina bakarak
fonksiyonu adlandirir. Iteratif calisir -- her turda bulunan yeni isimler
sonraki turun seed set'ine eklenir. Convergence'a kadar tekrar eder.

Bidirectional:
  - Backward: callee -> caller (callee'ler biliniyorsa caller cikarilir)
  - Forward: caller -> callee (caller biliniyorsa, tek callee olan callee cikarilir)

Kullanim:
    from karadul.reconstruction.computation.callee_profile_propagator import (
        CalleeProfilePropagator,
    )
    propagator = CalleeProfilePropagator(config)
    new_identifications = propagator.propagate(
        fused_results=fused,
        call_graph=call_graph,
    )
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain tanimlari -- callee isimlerinden domain cikarimi
# ---------------------------------------------------------------------------

# Anahtar kelime -> domain eslesmesi.
# Callee isimlerindeki anahtar kelimeler bu tablo ile domain'e eslestirilir.
_KEYWORD_TO_DOMAIN: dict[str, str] = {
    # Crypto
    "aes": "crypto", "sha": "crypto", "md5": "crypto", "rsa": "crypto",
    "hmac": "crypto", "evp": "crypto", "ssl": "crypto", "tls": "crypto",
    "encrypt": "crypto", "decrypt": "crypto", "cipher": "crypto",
    "hash": "crypto", "digest": "crypto", "sign": "crypto", "verify": "crypto",
    # Memory
    "malloc": "memory", "calloc": "memory", "realloc": "memory",
    "free": "memory", "memset": "memory", "memcpy": "memory",
    "memmove": "memory", "alloc": "memory", "_znwm": "memory",
    "_zdlpv": "memory",
    # File I/O
    "fopen": "file_io", "fclose": "file_io", "fread": "file_io",
    "fwrite": "file_io", "fprintf": "file_io", "fscanf": "file_io",
    "fseek": "file_io", "ftell": "file_io", "fflush": "file_io",
    "fputs": "file_io", "fgets": "file_io",
    # Network
    "socket": "network", "connect": "network", "bind": "network",
    "listen": "network", "accept": "network", "send": "network",
    "recv": "network", "getaddrinfo": "network", "gethostbyname": "network",
    "select": "network", "poll": "network", "epoll": "network",
    # String
    "strlen": "string", "strcpy": "string", "strncpy": "string",
    "strcmp": "string", "strncmp": "string", "strcat": "string",
    "strstr": "string", "strtok": "string", "strdup": "string",
    "sprintf": "string", "snprintf": "string",
    # Math
    "sin": "math", "cos": "math", "tan": "math", "sqrt": "math",
    "exp": "math", "log": "math", "pow": "math", "fabs": "math",
    "floor": "math", "ceil": "math", "round": "math",
    # Linear algebra
    "dgemm": "linear_algebra", "dgemv": "linear_algebra",
    "sgemm": "linear_algebra", "dgetrf": "linear_algebra",
    "dgetrs": "linear_algebra", "blas": "linear_algebra",
    "lapack": "linear_algebra", "matrix": "linear_algebra",
    # Concurrency
    "pthread": "concurrency", "mutex": "concurrency", "thread": "concurrency",
    "lock": "concurrency", "unlock": "concurrency", "semaphore": "concurrency",
    "condition": "concurrency",
    # Compression
    "deflate": "compression", "inflate": "compression", "compress": "compression",
    "uncompress": "compression", "zlib": "compression", "gzip": "compression",
    # Database
    "sqlite": "database", "sql": "database", "query": "database",
    "database": "database", "prepare": "database",
    # Process
    "fork": "process", "exec": "process", "waitpid": "process",
    "pipe": "process", "dup2": "process", "spawn": "process",
    # Filesystem
    "opendir": "filesystem", "readdir": "filesystem", "closedir": "filesystem",
    "stat": "filesystem", "chmod": "filesystem", "chown": "filesystem",
    "mkdir": "filesystem", "rmdir": "filesystem", "unlink": "filesystem",
    # Parsing
    "xml": "parsing", "json": "parsing", "parse": "parsing",
    "yaml": "parsing", "dom": "parsing", "sax": "parsing",
    # Image
    "png": "image", "jpeg": "image", "jpg": "image", "pixel": "image",
    "image": "image", "bitmap": "image",
    # Sorting
    "qsort": "sorting", "sort": "sorting", "bsearch": "sorting",
    # Error handling
    "perror": "error_handling", "strerror": "error_handling",
    "errno": "error_handling", "abort": "error_handling",
    "exit": "error_handling", "atexit": "error_handling",
    "assert": "error_handling",
}

# Domain -> varsayilan isimlendirme sabitleri
_DOMAIN_NAMING: dict[str, dict[str, str]] = {
    "crypto": {"wrapper": "crypto_operation", "helper": "crypto_helper",
               "dispatcher": "crypto_dispatcher"},
    "memory": {"wrapper": "memory_manager", "helper": "memory_helper",
               "dispatcher": "memory_dispatcher"},
    "file_io": {"wrapper": "file_handler", "helper": "file_io_helper",
                "dispatcher": "file_io_dispatcher"},
    "network": {"wrapper": "network_handler", "helper": "network_helper",
                "dispatcher": "network_dispatcher"},
    "string": {"wrapper": "string_processor", "helper": "string_helper",
               "dispatcher": "string_dispatcher"},
    "math": {"wrapper": "math_operation", "helper": "math_helper",
             "dispatcher": "math_dispatcher"},
    "linear_algebra": {"wrapper": "linalg_operation", "helper": "linalg_helper",
                       "dispatcher": "linalg_dispatcher"},
    "concurrency": {"wrapper": "concurrency_handler", "helper": "thread_helper",
                    "dispatcher": "concurrency_dispatcher"},
    "compression": {"wrapper": "compression_handler", "helper": "compression_helper",
                    "dispatcher": "compression_dispatcher"},
    "database": {"wrapper": "database_handler", "helper": "database_helper",
                 "dispatcher": "database_dispatcher"},
    "process": {"wrapper": "process_handler", "helper": "process_helper",
                "dispatcher": "process_dispatcher"},
    "filesystem": {"wrapper": "filesystem_handler", "helper": "fs_helper",
                   "dispatcher": "filesystem_dispatcher"},
    "parsing": {"wrapper": "parser_wrapper", "helper": "parser_helper",
                "dispatcher": "parser_dispatcher"},
    "image": {"wrapper": "image_processor", "helper": "image_helper",
              "dispatcher": "image_dispatcher"},
    "sorting": {"wrapper": "sorting_wrapper", "helper": "sorting_helper",
                "dispatcher": "sorting_dispatcher"},
    "error_handling": {"wrapper": "error_handler", "helper": "error_helper",
                       "dispatcher": "error_dispatcher"},
}


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class PropagatedName:
    """Iteratif propagasyon ile bulunan fonksiyon adi.

    Attributes:
        function_address: Fonksiyon adresi veya key.
        name: Atanan isim.
        confidence: Guven skoru [0, 1].
        source: "callee_profile" sabiti.
        reason: Nasil cikarildiginin aciklamasi.
        round_discovered: Hangi turda bulundu (0-based).
        domain: Domain siniflandirmasi.
        direction: "backward" (callee->caller) veya "forward" (caller->callee).
    """
    function_address: str
    name: str
    confidence: float
    source: str = "callee_profile"
    reason: str = ""
    round_discovered: int = 0
    domain: str = ""
    direction: str = "backward"

    def to_naming_candidate_dict(self) -> dict[str, Any]:
        """NameMerger'a beslenecek formatta dict dondur."""
        return {
            "function_address": self.function_address,
            "function_name": "",  # Caller tarafindan doldurulacak
            "candidate_name": self.name,
            "confidence": round(self.confidence, 4),
            "source": self.source,
            "reason": self.reason,
        }


@dataclass
class PropagationResult:
    """Iteratif propagasyonun toplam sonucu.

    Attributes:
        propagated_names: Tum turlarda bulunan isimler.
        total_rounds: Toplam tur sayisi.
        names_per_round: Her turda bulunan yeni isim sayisi.
        convergence_reason: Neden durdu ("max_rounds", "threshold", "no_new").
    """
    propagated_names: list[PropagatedName] = field(default_factory=list)
    total_rounds: int = 0
    names_per_round: list[int] = field(default_factory=list)
    convergence_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_names": len(self.propagated_names),
            "total_rounds": self.total_rounds,
            "names_per_round": self.names_per_round,
            "convergence_reason": self.convergence_reason,
        }


# ---------------------------------------------------------------------------
# CalleeProfilePropagator
# ---------------------------------------------------------------------------

class CalleeProfilePropagator:
    """Iteratif callee-profile bazli fonksiyon adlandirma yayilimi.

    Args:
        config: Opsiyonel config dict:
            - max_rounds (int): Maksimum iterasyon sayisi (varsayilan 10).
            - convergence_threshold (float): Yeni isim orani esigi (varsayilan 0.01).
            - min_callees_for_domain (int): Domain cikarimi icin min callee (varsayilan 2).
            - min_confidence (float): Minimum kabul edilir confidence (varsayilan 0.30).
            - base_confidence (float): Round 0 base confidence (varsayilan 0.90).
            - confidence_decay (float): Her turda confidence carpani (varsayilan 0.80).
            - hub_threshold (int): Hub fonksiyon icin min callee (varsayilan 10).
            - thin_wrapper_max_callees (int): Thin wrapper max callee sayisi (varsayilan 2).
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        self._max_rounds: int = config.get("max_rounds", 10)
        self._convergence_threshold: float = config.get("convergence_threshold", 0.01)
        self._min_callees_for_domain: int = config.get("min_callees_for_domain", 2)
        self._min_confidence: float = config.get("min_confidence", 0.30)
        self._base_confidence: float = config.get("base_confidence", 0.90)
        self._confidence_decay: float = config.get("confidence_decay", 0.80)
        self._hub_threshold: int = config.get("hub_threshold", 10)
        self._thin_wrapper_max_callees: int = config.get(
            "thin_wrapper_max_callees", 2,
        )
        logger.info(
            "CalleeProfilePropagator baslatildi: max_rounds=%d, "
            "convergence=%.2f, min_callees=%d, base_conf=%.2f, decay=%.2f",
            self._max_rounds,
            self._convergence_threshold,
            self._min_callees_for_domain,
            self._base_confidence,
            self._confidence_decay,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def propagate(
        self,
        fused_results: dict[str, Any],
        call_graph: dict[str, list[str]],
        signature_matches: list[Any] | None = None,
    ) -> PropagationResult:
        """Iteratif callee-profile propagasyonu calistir.

        Args:
            fused_results: Mevcut FusedIdentification sonuclari.
                {addr: FusedIdentification} veya {addr: dict with "identified_as"}.
            call_graph: {caller_addr: [callee_addr, ...]} eslesmesi.
            signature_matches: Opsiyonel signature DB match listesi.
                Her eleman .original_name, .matched_name, .confidence, .category
                attribute'larina sahip olmali (veya ayni key'lere sahip dict).
                Confidence >= 0.70 olanlar ek seed olarak eklenir.

        Returns:
            PropagationResult: Bulunan tum yeni isimler ve istatistikler.
        """
        result = PropagationResult()

        if not call_graph:
            result.convergence_reason = "no_call_graph"
            return result

        # Reverse call graph: callee -> [caller, ...]
        reverse_cg: dict[str, list[str]] = {}
        for caller, callees in call_graph.items():
            for callee in callees:
                reverse_cg.setdefault(callee, []).append(caller)

        # Seed set: bilinen (named) fonksiyonlar
        # addr -> (name, domain, confidence)
        known: dict[str, tuple[str, str, float]] = {}
        for addr, fid in fused_results.items():
            name = self._get_identified_name(fid)
            if name:
                conf = self._get_confidence(fid)
                domain = self._classify_domain(name)
                known[addr] = (name, domain, conf)

        # Signature DB match'lerden ek seed ekle (confidence >= 0.70)
        _sig_seed_count = 0
        if signature_matches:
            for m in signature_matches:
                if isinstance(m, dict):
                    orig = m.get("original_name", m.get("original", ""))
                    matched = m.get("matched_name", m.get("matched", ""))
                    conf = m.get("confidence", 0.0)
                    cat = m.get("category", "")
                else:
                    orig = getattr(m, "original_name", "")
                    matched = getattr(m, "matched_name", "")
                    conf = getattr(m, "confidence", 0.0)
                    cat = getattr(m, "category", "")
                if not orig or not matched or conf < 0.70:
                    continue
                # Zaten fused_results'tan biliniyor mu?
                if orig in known:
                    continue
                domain = cat if cat else self._classify_domain(matched)
                known[orig] = (matched, domain, conf)
                _sig_seed_count += 1

            if _sig_seed_count:
                logger.info(
                    "Callee-profile: %d ek seed signature_matches'ten eklendi "
                    "(toplam known=%d)",
                    _sig_seed_count, len(known),
                )

        total_functions = len(set(call_graph.keys()) | set(reverse_cg.keys()))
        if total_functions == 0:
            result.convergence_reason = "no_functions"
            return result

        # Already-named: propagasyon ile degistirilmeyecekler
        already_named: set[str] = set(known.keys())
        # Propagasyonla bulunanlar (tum turlar)
        all_propagated: dict[str, PropagatedName] = {}

        for round_num in range(self._max_rounds):
            round_confidence = self._round_confidence(round_num)

            if round_confidence < self._min_confidence:
                result.convergence_reason = "confidence_too_low"
                break

            new_in_round: list[PropagatedName] = []

            # --- Backward: callee -> caller ---
            backward = self._backward_pass(
                known, call_graph, reverse_cg, already_named,
                all_propagated, round_num, round_confidence,
            )
            new_in_round.extend(backward)

            # --- Forward: caller -> callee ---
            forward = self._forward_pass(
                known, call_graph, reverse_cg, already_named,
                all_propagated, round_num, round_confidence,
            )
            new_in_round.extend(forward)

            result.names_per_round.append(len(new_in_round))

            if not new_in_round:
                result.convergence_reason = "no_new"
                result.total_rounds = round_num + 1
                break

            # Yeni bulunan isimleri seed set'e ekle
            for pn in new_in_round:
                known[pn.function_address] = (pn.name, pn.domain, pn.confidence)
                all_propagated[pn.function_address] = pn

            # Convergence check: yeni isim orani < threshold
            new_ratio = len(new_in_round) / max(total_functions, 1)
            if new_ratio < self._convergence_threshold:
                result.convergence_reason = "threshold"
                result.total_rounds = round_num + 1
                break
        else:
            result.convergence_reason = "max_rounds"
            result.total_rounds = self._max_rounds

        result.propagated_names = list(all_propagated.values())

        if result.propagated_names:
            logger.info(
                "Callee-profile propagation: %d isim bulundu, %d round, "
                "sebep=%s, round basina=%s",
                len(result.propagated_names),
                result.total_rounds,
                result.convergence_reason,
                result.names_per_round,
            )

        return result

    # ------------------------------------------------------------------
    # Backward pass: callee -> caller
    # ------------------------------------------------------------------

    def _backward_pass(
        self,
        known: dict[str, tuple[str, str, float]],
        call_graph: dict[str, list[str]],
        reverse_cg: dict[str, list[str]],
        already_named: set[str],
        all_propagated: dict[str, PropagatedName],
        round_num: int,
        round_confidence: float,
    ) -> list[PropagatedName]:
        """Callee isimlerinden caller ismi cikar.

        Kurallar:
        - 1 bilinen callee + thin body -> "known_func_wrapper"
        - 2+ callee ayni domain -> "domain_wrapper" / "domain_helper"
        - 3+ crypto callee -> "crypto_operation"
        - 10+ bilinen callee -> "dispatcher" / "main_loop"
        - Sadece error-handling callee'ler -> "error_handler"
        """
        new_names: list[PropagatedName] = []

        for caller_addr, callee_addrs in call_graph.items():
            # Zaten isimli mi?
            if caller_addr in already_named or caller_addr in all_propagated:
                continue

            # Callee profili olustur
            callee_domains: list[str] = []
            callee_known_names: list[str] = []
            callee_known_count = 0
            total_callees = len(callee_addrs)

            for callee_addr in callee_addrs:
                info = known.get(callee_addr)
                if info:
                    name, domain, _conf = info
                    callee_known_names.append(name)
                    if domain:
                        callee_domains.append(domain)
                    callee_known_count += 1

            if callee_known_count == 0:
                continue

            # Domain dagilimi
            domain_counts = Counter(callee_domains)
            top_domain, top_count = (
                domain_counts.most_common(1)[0] if domain_counts else ("", 0)
            )

            inferred_name: str | None = None
            reason_parts: list[str] = []

            # Kural 1: Thin wrapper -- 1 callee, sadece o bilinen
            if (total_callees <= self._thin_wrapper_max_callees
                    and callee_known_count == 1):
                base_name = callee_known_names[0].lower().rstrip("_")
                # _caller suffix'li isimleri temizle
                for suffix in ("_caller", "_wrapper", "_handler"):
                    if base_name.endswith(suffix):
                        base_name = base_name[:-len(suffix)]
                inferred_name = f"{base_name}_wrapper"
                reason_parts.append(
                    f"thin wrapper: 1 known callee '{callee_known_names[0]}', "
                    f"{total_callees} total"
                )

            # Kural 2: Hub / dispatcher -- 10+ callee, cogu bilinen
            elif (total_callees >= self._hub_threshold
                  and callee_known_count >= total_callees * 0.5):
                if top_domain and top_count >= 3:
                    naming = _DOMAIN_NAMING.get(top_domain, {})
                    inferred_name = naming.get("dispatcher", f"{top_domain}_dispatcher")
                else:
                    inferred_name = "dispatcher"
                reason_parts.append(
                    f"hub: {total_callees} callees, "
                    f"{callee_known_count} known, top_domain={top_domain}"
                )

            # Kural 3: Sadece error-handling callee'ler
            elif (callee_known_count >= 1
                  and top_domain == "error_handling"
                  and top_count == len(callee_domains)):
                inferred_name = "error_handler"
                reason_parts.append(
                    f"all {callee_known_count} known callees are error_handling"
                )

            # Kural 4: Domain bazli -- 2+ callee ayni domain
            elif top_count >= self._min_callees_for_domain:
                naming = _DOMAIN_NAMING.get(top_domain, {})
                # 3+ -> wrapper, 2 -> helper
                if top_count >= 3:
                    inferred_name = naming.get("wrapper", f"{top_domain}_operation")
                else:
                    inferred_name = naming.get("helper", f"{top_domain}_helper")
                reason_parts.append(
                    f"domain clustering: {top_count} callees in '{top_domain}' "
                    f"(total {callee_known_count} known of {total_callees})"
                )

            if inferred_name is None:
                continue

            confidence = round_confidence * min(
                callee_known_count / max(total_callees, 1), 1.0,
            )
            if confidence < self._min_confidence:
                continue

            new_names.append(PropagatedName(
                function_address=caller_addr,
                name=inferred_name,
                confidence=round(confidence, 4),
                reason="; ".join(reason_parts),
                round_discovered=round_num,
                domain=top_domain,
                direction="backward",
            ))

        return new_names

    # ------------------------------------------------------------------
    # Forward pass: caller -> callee
    # ------------------------------------------------------------------

    def _forward_pass(
        self,
        known: dict[str, tuple[str, str, float]],
        call_graph: dict[str, list[str]],
        reverse_cg: dict[str, list[str]],
        already_named: set[str],
        all_propagated: dict[str, PropagatedName],
        round_num: int,
        round_confidence: float,
    ) -> list[PropagatedName]:
        """Bilinen caller'dan callee ismi cikar.

        Kurallar:
        - Caller bilinen + tek bilinmeyen callee -> "caller_sub" / "caller_internal"
        - Bilinen caller crypto_init ise, callee "key_setup" olabilir
        """
        new_names: list[PropagatedName] = []

        for caller_addr, callee_addrs in call_graph.items():
            caller_info = known.get(caller_addr)
            if not caller_info:
                continue

            caller_name, caller_domain, caller_conf = caller_info

            # Bilinmeyen callee'leri bul
            unknown_callees: list[str] = []
            for callee_addr in callee_addrs:
                if (callee_addr not in already_named
                        and callee_addr not in all_propagated):
                    unknown_callees.append(callee_addr)

            if not unknown_callees:
                continue

            # Kural: tek bilinmeyen callee -> caller'in alt fonksiyonu
            if len(unknown_callees) == 1:
                callee_addr = unknown_callees[0]
                base = caller_name.lower()
                # _wrapper, _handler gibi suffix'leri temizle
                for suffix in ("_wrapper", "_handler", "_operation",
                               "_caller", "_helper", "_manager"):
                    if base.endswith(suffix):
                        base = base[:-len(suffix)]
                        break

                inferred_name = f"{base}_internal"
                confidence = round_confidence * 0.7 * min(caller_conf, 1.0)

                if confidence < self._min_confidence:
                    continue

                new_names.append(PropagatedName(
                    function_address=callee_addr,
                    name=inferred_name,
                    confidence=round(confidence, 4),
                    reason=f"forward: only unknown callee of '{caller_name}' "
                           f"(domain={caller_domain})",
                    round_discovered=round_num,
                    domain=caller_domain,
                    direction="forward",
                ))

        return new_names

    # ------------------------------------------------------------------
    # Yardimci metodlar
    # ------------------------------------------------------------------

    def _round_confidence(self, round_num: int) -> float:
        """Tur numarasina gore base confidence hesapla.

        Round 0: base_confidence (0.90)
        Round 1: base * decay (0.72)
        Round 2: base * decay^2 (0.576)
        ...

        Args:
            round_num: 0-based tur numarasi.

        Returns:
            float: Bu tur icin base confidence.
        """
        return self._base_confidence * (self._confidence_decay ** round_num)

    @staticmethod
    def _get_identified_name(fid: Any) -> str:
        """FusedIdentification veya dict'ten identified_as al."""
        if isinstance(fid, dict):
            return fid.get("identified_as", "")
        return getattr(fid, "identified_as", "") or ""

    @staticmethod
    def _get_confidence(fid: Any) -> float:
        """FusedIdentification veya dict'ten confidence al."""
        if isinstance(fid, dict):
            return fid.get("fused_confidence", 0.0)
        return getattr(fid, "fused_confidence", 0.0)

    @staticmethod
    def _classify_domain(name: str) -> str:
        """Fonksiyon ismine bakarak domain siniflandirmasi yap.

        Args:
            name: Fonksiyon adi (orn: "aes_encrypt", "malloc_wrapper").

        Returns:
            str: Domain (orn: "crypto", "memory"). Bos string = bilinmeyen.
        """
        if not name:
            return ""
        name_lower = name.lower()

        # Exact keyword match -- isim parcalarindan domain bul
        # Underscore ile parcala, her parcayi kontrol et
        parts = name_lower.replace("-", "_").split("_")
        domain_hits: Counter[str] = Counter()
        for part in parts:
            if part in _KEYWORD_TO_DOMAIN:
                domain_hits[_KEYWORD_TO_DOMAIN[part]] += 1

        # En cok hit alan domain'i sec
        if domain_hits:
            return domain_hits.most_common(1)[0][0]

        # Substring fallback -- kisa keyword'ler icin (ssl, aes, md5, vb.)
        for keyword, domain in _KEYWORD_TO_DOMAIN.items():
            if len(keyword) >= 3 and keyword in name_lower:
                return domain

        return ""
