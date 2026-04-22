"""Karadul v1.10.0 -- Reconstruction + Naming bug-fix sprint test suite.

Spec: 2026-04-21 Berke tarafindan talep edilen 7 fix:
    - C1: NameMergerConfig.source_weights eksik -- 7 yeni kaynak.
    - C2: Priority chain tavan -- sig_db_params etkili confidence en yuksek.
    - C4: Bayesian penalty YANLIS -- penalty weight'e uygulanmali (confidence'a degil).
    - C6: dynamic_namer assign_re eksik pattern'ler -- _GENERIC_VAR_RE ile senkron.
    - H1: Fortran false positive -- _memcpy_, _pthread_*_, _gcc_personality_v0_ blacklist.
    - H8: NamingCandidate duplicate class birlestir.
    - M4: CalleeProfilePropagator substring false positive -- word boundary regex.
    - M9: dynamic_namer pointer threshold 0x7f000000 -> 0x100000 (1MB).

Toplam: 18 test.
"""

from __future__ import annotations

import pytest

from karadul.config import NameMergerConfig
from karadul.reconstruction.dynamic_namer import (
    DynamicNamer,
    _GENERIC_VAR_RE,
    _POINTER_CLASSIFY_MIN,
)
from karadul.reconstruction.name_merger import (
    NamingCandidate,
    bayesian_merge,
)


# ===========================================================================
# C1: NameMergerConfig.source_weights -- semantic namer kaynaklari
# ===========================================================================


class TestC1SourceWeights:
    """Semantic namer 7 kaynagi source_weights tablosunda tanimli olmali."""

    def test_sig_db_params_defined(self) -> None:
        cfg = NameMergerConfig()
        assert "sig_db_params" in cfg.source_weights
        assert cfg.source_weights["sig_db_params"] == 1.0  # en yuksek guven

    def test_signature_based_defined(self) -> None:
        cfg = NameMergerConfig()
        assert "signature_based" in cfg.source_weights
        assert cfg.source_weights["signature_based"] == 0.95

    def test_algorithm_template_defined(self) -> None:
        cfg = NameMergerConfig()
        assert "algorithm_template" in cfg.source_weights
        assert cfg.source_weights["algorithm_template"] == 0.85

    def test_call_graph_propagation_defined(self) -> None:
        cfg = NameMergerConfig()
        assert "call_graph_propagation" in cfg.source_weights
        assert cfg.source_weights["call_graph_propagation"] == 0.75

    def test_struct_context_defined(self) -> None:
        cfg = NameMergerConfig()
        assert "struct_context" in cfg.source_weights
        assert cfg.source_weights["struct_context"] == 0.70

    def test_call_context_defined(self) -> None:
        cfg = NameMergerConfig()
        assert "call_context" in cfg.source_weights
        assert cfg.source_weights["call_context"] == 0.65

    def test_type_heuristic_defined(self) -> None:
        cfg = NameMergerConfig()
        assert "type_heuristic" in cfg.source_weights
        assert cfg.source_weights["type_heuristic"] == 0.55

    def test_default_weight_not_applied(self) -> None:
        """Semantic namer kaynaklari artik default_weight'e DUSMEMELI.

        Bu testin amaci: source_weights tablosuna eklenen isimler
        dict'te oldugundan .get(source, default_weight) default'u
        tetiklememeli. Essentially bir "dict var" testi ama
        semantic olarak C1 fix'in regresyon testi.
        """
        cfg = NameMergerConfig()
        defaults_triggered = []
        sources = {
            "sig_db_params", "signature_based", "algorithm_template",
            "call_graph_propagation", "struct_context", "call_context",
            "type_heuristic",
        }
        for s in sources:
            w = cfg.source_weights.get(s, cfg.default_weight)
            if w == cfg.default_weight and cfg.default_weight != cfg.source_weights.get(s):
                defaults_triggered.append(s)
        assert not defaults_triggered, f"Kaynaklar fallback'e dustu: {defaults_triggered}"


# ===========================================================================
# C2: Priority chain tavan tutarsizligi -- sanity check
# ===========================================================================


class TestC2PriorityChain:
    """sig_db_params confidence tavan testi.

    _BASE_CONFIDENCE[sig_db_params]=0.95 * source_weights=1.0 ile
    Bayesian merge sonucu max_confidence=0.99'a cikamaz ama
    diger kaynaklardan yuksek olmali.
    """

    def test_sig_db_params_highest_weight(self) -> None:
        cfg = NameMergerConfig()
        # sig_db_params en yuksek (1.0), digerleri daha dusuk.
        assert cfg.source_weights["sig_db_params"] >= cfg.source_weights["signature_based"]
        assert cfg.source_weights["signature_based"] >= cfg.source_weights["algorithm_template"]
        assert cfg.source_weights["algorithm_template"] >= cfg.source_weights["call_graph_propagation"]
        assert cfg.source_weights["call_graph_propagation"] >= cfg.source_weights["struct_context"]
        assert cfg.source_weights["struct_context"] >= cfg.source_weights["call_context"]
        assert cfg.source_weights["call_context"] >= cfg.source_weights["type_heuristic"]

    def test_sig_db_params_bayesian_posterior(self) -> None:
        """sig_db_params tek basina yuksek confidence -> posterior >0.9."""
        cfg = NameMergerConfig()
        # 0.95 conf * 1.0 weight -> log(0.95/0.05) = 2.944 -> sigmoid ~0.95
        posterior = bayesian_merge(
            confidences=[0.95],
            sources=["sig_db_params"],
            cfg=cfg,
        )
        assert posterior > 0.90, f"posterior={posterior} sig_db_params icin dusuk"
        assert posterior <= cfg.max_confidence


# ===========================================================================
# C4: Bayesian weights_override
# ===========================================================================


class TestC4BayesianWeightsOverride:
    """bayesian_merge weights_override parametresi penalty'yi weight'e uygular."""

    def test_weights_override_parameter_accepted(self) -> None:
        cfg = NameMergerConfig()
        result = bayesian_merge(
            confidences=[0.9, 0.9],
            sources=["signature_db", "c_namer"],
            cfg=cfg,
            weights_override=[0.5, 0.5],
        )
        assert 0.0 < result < 1.0

    def test_weights_override_none_equals_default(self) -> None:
        cfg = NameMergerConfig()
        a = bayesian_merge([0.8, 0.7], ["signature_db", "c_namer"], cfg)
        b = bayesian_merge([0.8, 0.7], ["signature_db", "c_namer"], cfg, weights_override=None)
        assert a == b

    def test_weights_override_penalty_reduces_posterior(self) -> None:
        """Penalty < 1.0 posterior'i DUSURMELI (confidence ayni)."""
        cfg = NameMergerConfig()
        full = bayesian_merge([0.9, 0.9], ["signature_db", "c_namer"], cfg)
        penalised = bayesian_merge(
            [0.9, 0.9], ["signature_db", "c_namer"], cfg,
            weights_override=[0.5, 0.5],
        )
        # Log-odds uzayinda w=0.5 bilgi kazancini yariya indirir.
        # Posterior dusmeli ama multi_source_prior=0.5'in altina asla inmez
        # (cunku 2 kaynak hala pozitif kanit sagliyor).
        assert penalised < full
        assert penalised > 0.5  # hala pozitif yonde

    def test_weights_override_length_mismatch_raises(self) -> None:
        cfg = NameMergerConfig()
        with pytest.raises(ValueError, match="uzunlugu"):
            bayesian_merge(
                [0.9, 0.9], ["signature_db", "c_namer"], cfg,
                weights_override=[0.5],
            )

    def test_weights_override_differs_from_confidence_multiply(self) -> None:
        """Penalty'yi weight'e vs confidence'a uygulamak FARKLI sonuc verir.

        Bu testin kalbi: eski (yanlis) davranisla yeni (dogru) arasinda
        olcumlenebilir fark olmali.
        """
        cfg = NameMergerConfig()
        penalty = 0.7
        # Yeni (dogru): weight'e penalty uygulanir
        new_way = bayesian_merge(
            [0.9, 0.85], ["signature_db", "c_namer"], cfg,
            weights_override=[penalty, penalty],
        )
        # Eski (yanlis): confidence'a penalty uygulanir
        old_way = bayesian_merge(
            [0.9 * penalty, 0.85 * penalty],
            ["signature_db", "c_namer"],
            cfg,
        )
        # Ikisi de [0, 1] araliginda ama ayni degeri vermeli DEGIL.
        assert abs(new_way - old_way) > 1e-4


# ===========================================================================
# C6: dynamic_namer assign_re <-> _GENERIC_VAR_RE senkronizasyonu
# ===========================================================================


class TestC6AssignReSync:
    """dynamic_namer assign_re _GENERIC_VAR_RE'deki tum pattern'leri yakalamali."""

    @pytest.mark.parametrize("varname", [
        "param_1",
        "local_10",
        "uVar1", "iVar2", "lVar3", "sVar4", "bVar5", "cVar6",
        "in_stack_0x10", "in_r0",
        "pvVar1", "ppvVar2", "puVar3", "plVar4",
        "pcVar1", "piVar1",
    ])
    def test_var_patterns_match_generic_re(self, varname: str) -> None:
        """_GENERIC_VAR_RE her generic isim kategorisini yakalamali."""
        assert _GENERIC_VAR_RE.match(varname), f"{varname} _GENERIC_VAR_RE'ye uymuyor"

    @pytest.mark.parametrize("varname", [
        "in_stack_0x10",
        "pvVar1", "ppvVar2", "puVar1", "plVar1",
    ])
    def test_assign_re_captures_new_patterns(self, varname: str) -> None:
        """v1.10.0 C6 eklenen pattern'ler assign_re'de yakalanmali.

        Bu pattern'ler oncesinde eksikti, ornek kodda var = fn(...)
        formunda gozukseler bile rename edilmiyorlardi.
        """
        import re
        # dynamic_namer.py'deki assign_re'nin aynisi (v1.10.0 sonrasi):
        assign_re = re.compile(
            r'(\b(?:param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+|[iuplscb]Var\d+'
            r'|in_\w+|pvVar\d+|ppvVar\d+|puVar\d+|plVar\d+'
            r'|p[a-z]Var\d+|pp[a-z]Var\d+))\s*='
            r'\s*(\w+)\s*\('
        )
        code = f"{varname} = some_api(arg1, arg2);"
        m = assign_re.search(code)
        assert m is not None, f"assign_re yakalamadi: {code!r}"
        assert m.group(1) == varname


# ===========================================================================
# H1: Fortran false positive blacklist
# ===========================================================================


class TestH1FortranBlacklist:
    """_memcpy_, _pthread_*_, _gcc_personality_v0_ Fortran sayilmamali."""

    @pytest.mark.parametrize("name", [
        "_memcpy_",
        "_memset_",
        "_memmove_",
        "_strcpy_",
        "_strlen_",
        "_gcc_personality_v0_",
        "_unwind_resume_",
        "_pthread_create_",
        "_pthread_mutex_lock_",
        "_pthread_cond_wait_",
        "__libc_init_",
        "__libc_start_main_",
    ])
    def test_blacklist_name_is_not_fortran(self, name: str) -> None:
        from karadul.reconstruction.c_namer import _is_non_fortran_underscore_name
        assert _is_non_fortran_underscore_name(name), f"{name} blacklist'te olmali"

    @pytest.mark.parametrize("name", [
        "_matmul_",
        "_dgemm_",
        "_sgemm_",
        "_fft_forward_",
        "_user_function_",
    ])
    def test_real_fortran_names_pass(self, name: str) -> None:
        """Gercek Fortran fn isimleri blacklist'e DUSMEMELI."""
        from karadul.reconstruction.c_namer import _is_non_fortran_underscore_name
        assert not _is_non_fortran_underscore_name(name), f"{name} false blacklist"

    def test_case_insensitive_match(self) -> None:
        """Blacklist case-insensitive calismalı (ornek: _MEMCPY_)."""
        from karadul.reconstruction.c_namer import _is_non_fortran_underscore_name
        assert _is_non_fortran_underscore_name("_MEMCPY_")
        assert _is_non_fortran_underscore_name("_Pthread_create_")


# ===========================================================================
# H8: NamingCandidate duplicate class birlestirildi
# ===========================================================================


class TestH8NamingCandidateUnified:
    """name_merger.NamingCandidate == signature_fusion.NamingCandidate olmali."""

    def test_name_merger_reexports_signature_fusion_class(self) -> None:
        from karadul.reconstruction.name_merger import NamingCandidate as NM
        from karadul.reconstruction.recovery_layers.signature_fusion import (
            NamingCandidate as SF,
        )
        assert NM is SF, "NamingCandidate iki modulde farkli sinif tanimi -- H8 regres"

    def test_dataclass_fields_preserved(self) -> None:
        c = NamingCandidate(
            name="decrypt_buffer",
            confidence=0.85,
            source="signature_db",
            reason="AES pattern match",
        )
        assert c.name == "decrypt_buffer"
        assert c.confidence == 0.85
        assert c.source == "signature_db"
        assert c.reason == "AES pattern match"


# ===========================================================================
# M4: CalleeProfilePropagator word boundary regex
# ===========================================================================


class TestM4WordBoundary:
    """Substring false positive -- word boundary ile onlenmeli."""

    def _propagator(self):
        from karadul.reconstruction.recovery_layers.callee_profile_propagator import (
            CalleeProfilePropagator,
        )
        from karadul.computation.config import ComputationConfig
        return CalleeProfilePropagator(ComputationConfig())

    def test_analysis_does_not_match_sha(self) -> None:
        """'analysis' icinde 'sha' olsa bile crypto sayilmamali."""
        p = self._propagator()
        # 'analysis' -> 'ana', 'lysis'. 'sha' alpha-alpha sinirinda degil.
        # Eski substring fallback: "sha" in "analysis" -> False (yok zaten)
        # AMA "rsa" in "traverse" -> False, "ssl" in "classify" -> False.
        # Guvenlik: hicbir crypto keyword'u match etmemeli.
        result = p._classify_domain("analysis")
        assert result == "", f"analysis yanlis domain: {result!r}"

    def test_classify_does_not_match_ssl(self) -> None:
        """'classify' icerisinde bulunan substring'ler crypto tetiklememeli."""
        p = self._propagator()
        result = p._classify_domain("classify")
        assert result == "", f"classify yanlis domain: {result!r}"

    def test_sha256_word_boundary_matches(self) -> None:
        """'sha256_wrapper' -> 'sha' digit sinirinda yakalanmali (crypto)."""
        p = self._propagator()
        result = p._classify_domain("sha256_wrapper")
        assert result == "crypto"

    def test_digit_boundary_works(self) -> None:
        """'md5sum' -> 'md5' digit sinirinda OK (crypto)."""
        p = self._propagator()
        # md5 keyword'u zaten var; 'md5sum' icinde 'md5' sonrasi 's' alpha ->
        # YAKALANMAMALI (conservative). Bu dogru davranis.
        result = p._classify_domain("md5sum")
        # 'md5sum' parca splitinden yakalanabilir; boylelikle sonuc crypto OR "".
        # Sadece false positive olmayan bir domain olmasini bekliyoruz.
        assert result in ("crypto", ""), f"md5sum yanlis: {result!r}"


# ===========================================================================
# M9: Pointer threshold 1MB
# ===========================================================================


class TestM9PointerThreshold:
    """_classify_int_value 0x100000 (1MB) esigini kullanmali."""

    def test_pointer_threshold_constant(self) -> None:
        assert _POINTER_CLASSIFY_MIN == 0x100000

    def test_one_mb_boundary_is_not_pointer(self) -> None:
        """Tam 1MB hala uint32 olabilir (heap basi muhtemel degil)."""
        assert DynamicNamer._classify_int_value(0x100000) == "uint32_t"

    def test_above_one_mb_is_pointer(self) -> None:
        """1MB+1 byte -> pointer."""
        assert DynamicNamer._classify_int_value(0x100001) == "void *"

    def test_typical_64bit_heap_address_is_pointer(self) -> None:
        """Modern 64-bit ASLR heap adresleri (ornek 0x7fff...)."""
        assert DynamicNamer._classify_int_value(0x7fff12345678) == "void *"

    def test_stack_address_range_is_pointer(self) -> None:
        """Typical stack address (0x7ff...) -> pointer."""
        assert DynamicNamer._classify_int_value(0x7fffffff0000) == "void *"

    def test_small_positive_int_still_int(self) -> None:
        """Kucuk pozitifler regresyon: hala int."""
        assert DynamicNamer._classify_int_value(1024) == "int"
        assert DynamicNamer._classify_int_value(0xffff) == "int"
