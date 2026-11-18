"""P04a kalem 2 — bileşim şablonu kanıt kapısı (MUH-03).

Olumsuz örnekler gerçek çıktılardan alınmış adlarla (MUH-03 kanıtı): her ELF'te
bulunan çalışma zamanı adları, ad alt dizgisi, parantez içi "şunlarda kullanılır"
listesi, kendi adını yineleyen API tespiti, sabit parmak izi, çıplak sözcük
eşleşmesi. Olumlu örnek gerçek bir hesap zincirini taklit eder (CalculiX
``linstatic`` → ``mafillsm`` / ``spooles_factor`` / ``spooles_solve``; çağrı
çizgesi ve algoritma tespiti birlikte).
"""
from __future__ import annotations

from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
from karadul.reconstruction.engineering.composition_analyzer import (
    _TEMPLATE_DEFINING_STAGES,
    KNOWN_COMPOSITIONS,
    AlgorithmCompositionAnalyzer,
    _detection_rejection,
    _is_runtime_or_import_name,
    _name_tokens,
    _tokens_match,
)

SABLON_ADLARI = {t["name_template"] for t in KNOWN_COMPOSITIONS.values()}


def _cizge(kenarlar: list[tuple[str, str]], ekler: tuple[str, ...] = ()) -> dict:
    adlar = list(dict.fromkeys([a for k in kenarlar for a in k] + list(ekler)))
    adres = {ad: f"{0x101000 + 0x10 * i:08x}" for i, ad in enumerate(adlar)}
    nodes = {adres[a]: {"name": a, "address": adres[a], "callers": [], "callees": []}
             for a in adlar}
    for a, b in kenarlar:
        nodes[adres[a]]["callees"].append({"name": b, "address": adres[b]})
        nodes[adres[b]]["callers"].append({"name": a, "address": adres[a]})
    return {"nodes": nodes}


def _algo(ad, kategori, fonk, yontem="structural", kanit=None, guven=0.8):
    return AlgorithmMatch(
        name=ad, category=kategori, confidence=guven, detection_method=yontem,
        evidence=kanit if kanit is not None else [f"{ad}: matched 'a[i] = a[i] - l * b[j];'"],
        function_name=fonk, address="0x0")


def _raporlanan(sonuc) -> set[str]:
    return {c.name for c in sonuc.compositions if c.name in SABLON_ADLARI}


# --- belirteç eşleşmesi ------------------------------------------------------

def test_tam_belirtec_alt_dizgiyi_eslemez():
    assert not _tokens_match(("lu",), _name_tokens("fflush"))
    assert not _tokens_match(("dt",), _name_tokens("bindtextdomain"))
    assert not _tokens_match(("gm",), _name_tokens("gmtime_r"))
    assert not _tokens_match(("cl",), _name_tokens("_ITM_deregisterTMCloneTable"))
    assert not _tokens_match(("alloc",), _name_tokens("malloc"))
    assert _tokens_match(("dt",), _name_tokens("compute_dt"))
    assert _tokens_match(("ssl", "connect"), _name_tokens("SSL_connect"))
    assert _tokens_match(("handshake",), _name_tokens("SSLHandshake"))
    # çekim eki: yalnız >= 6 harfli tek belirteç
    assert _tokens_match(("encrypt",), _name_tokens("OpenSSL symmetric encryption"))
    assert not _tokens_match(("init",), _name_tokens("initialize"))


def test_calisma_zamani_ve_ithal_adlari():
    for ad in ("_DT_INIT", "_DT_FINI", "_INIT_0", "__gmon_start__",
               "_ITM_deregisterTMCloneTable", "fflush", "_malloc", "free",
               "___strcat_chk", "__printf_chk", "entry", "_start"):
        assert _is_runtime_or_import_name(ad), ad
    for ad in ("spooles_solve", "_mafillsm_", "FUN_00103374", "u_free"):
        assert not _is_runtime_or_import_name(ad), ad


# --- tespit kalitesi -----------------------------------------------------------

def test_kanit_sayilmayan_tespitler():
    kutuk = {"name": "OpenSSL symmetric decryption", "category": "symmetric_cipher",
             "function_name": "EVP_DecryptInit_ex",
             "evidence": ["API call: EVP_DecryptInit_ex()"], "detection_method": "api"}
    assert _detection_rejection(kutuk) == "detection only restates the function's own name"
    sabit = {"name": "rc4", "category": "symmetric_encryption", "function_name": "_linstatic",
             "evidence": ["decimal: 0", "decimal: 4"], "detection_method": "constant"}
    assert _detection_rejection(sabit) == "constant-only detection"
    sozcuk = {"name": "isa_atmosphere", "category": "aerospace", "function_name": "_densitys_",
              "evidence": ["isa_atmosphere: matched 'DENSITY'"], "detection_method": "structural"}
    assert _detection_rejection(sozcuk) == "structural detection matched a bare keyword"
    calisma = {"name": "x", "category": "hash", "function_name": "_DT_INIT",
               "evidence": [], "detection_method": "api"}
    assert _detection_rejection(calisma) == "detection in runtime/import function"
    gercek = {"name": "lu_factorization", "category": "linear_algebra",
              "function_name": "_dgesv_", "evidence": ["API call: _dgetrf_ (LAPACK)"],
              "detection_method": "api"}
    assert _detection_rejection(gercek) is None
    yapi = {"name": "cholesky", "category": "linear_algebra", "function_name": "f",
            "evidence": ["cholesky_decomposition: matched '(dVar42 - dVar46) / local_2a0'"],
            "detection_method": "structural"}
    assert _detection_rejection(yapi) is None


# --- olumsuz: MUH-03'ün gerçek belirtileri ------------------------------------

def test_coreutils_cat_adlarindan_sablon_yok():
    """cat: Factor=fflush, Timestep=_DT_INIT, Aero=_ITM_…, Gravity=__gmon_start__."""
    cg = _cizge([("_DT_INIT", "FUN_00103374"), ("FUN_00103374", "fflush"),
                 ("FUN_00103374", "malloc"), ("FUN_00103374", "free"),
                 ("FUN_00103374", "_ITM_deregisterTMCloneTable"),
                 ("FUN_00103374", "__gmon_start__"), ("FUN_00103374", "_INIT_0")])
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=[])
    assert _raporlanan(sonuc) == set()
    # tam belirteç + çalışma zamanı dışlaması: aday bile değiller
    adaylar = {c.name for c in sonuc.pending_compositions}
    assert not adaylar & {"Transient CFD Time-Stepping", "Matrix Solve Pipeline",
                          "Rocket / Trajectory Simulation Loop"}


def test_galois_parantezi_sifreleme_asamasi_sayilmaz():
    """sqlite3/zstd: zlib + "Galois field operations (ECC, AES-GF)" → Compress-then-Encrypt değil."""
    cg = _cizge([("driver", "FUN_a"), ("driver", "FUN_b"), ("driver", "FUN_c")])
    algos = [
        _algo("zlib inflate", "compression", "FUN_a", "api", ["API call: inflate()"]),
        _algo("zlib deflate", "compression", "FUN_c", "api", ["API call: deflate()"]),
        _algo("Galois field operations (ECC, AES-GF)", "symmetric_cipher", "FUN_b"),
    ]
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=algos)
    assert "Compress-then-Encrypt Pipeline" not in _raporlanan(sonuc)


def test_tanimlayici_asama_yoksa_vpn_denmez():
    """openssl: TLS el sıkışması + sertifika + şifreleme kanıtlı, tünel yok → VPN değil."""
    cg = _cizge([("cmd", "FUN_hs"), ("cmd", "FUN_cert"), ("cmd", "FUN_enc")])
    algos = [
        _algo("TLS handshake (client)", "protocol", "FUN_hs", "api", ["API call: SSL_connect()"]),
        _algo("TLS certificate verification", "protocol", "FUN_cert", "api",
              ["API call: SSL_get_verify_result()"]),
        _algo("OpenSSL symmetric encryption", "symmetric_cipher", "FUN_enc", "api",
              ["API call: EVP_EncryptInit_ex()"]),
    ]
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=algos)
    assert "VPN Tunnel Setup Pipeline" not in _raporlanan(sonuc)
    vpn = [c for c in sonuc.pending_compositions if c.name == "VPN Tunnel Setup Pipeline"]
    assert vpn and "tunnel_setup" in vpn[0].evidence_gate["reason"]


def _fea_algolari(fonk_asm="mafillsm", fonk_fac="spooles_factor", fonk_sol="spooles_solve"):
    return [
        _algo("gauss_quadrature", "fea_integration", fonk_asm, "constant+structural",
              ["decimal: 0.5773502691896257", "fea_gauss: matched 'w[i] * f(xi[i])'"]),
        _algo("cholesky", "linear_algebra", fonk_fac),
        _algo("triangular_solve", "linear_algebra", fonk_sol),
    ]


_FEA_KENAR = [("linstatic", "mafillsm"), ("linstatic", "spooles_factor"),
              ("linstatic", "spooles_solve"), ("linstatic", "results")]


def test_bagsiz_kanit_sablon_degil():
    """Aynı kanıtlar ama çağrı çizgesinde ortak sürücü yok → bekler."""
    cg = _cizge([("a", "mafillsm"), ("b", "spooles_factor"), ("c", "spooles_solve")])
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=_fea_algolari())
    assert "Linear Static FEA Pipeline" not in _raporlanan(sonuc)
    bek = [c for c in sonuc.pending_compositions if c.name == "Linear Static FEA Pipeline"]
    assert bek and "not linked" in bek[0].evidence_gate["reason"]


def test_program_girisi_surucu_sayilmaz():
    """``entry`` bütün programa iner; bağ kanıtı olamaz."""
    cg = _cizge([("entry", "mafillsm"), ("entry", "spooles_factor"),
                 ("entry", "spooles_solve")])
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=_fea_algolari())
    assert "Linear Static FEA Pipeline" not in _raporlanan(sonuc)


def test_tek_fonksiyonluk_kanit_sablon_degil():
    cg = _cizge([("drv", "spooles")])
    algos = [_algo("lu_factorization", "linear_algebra", "spooles", "api",
                   ["API call: _dgetrf_ (LAPACK)"]),
             _algo("lu_solve", "linear_algebra", "spooles", "api",
                   ["API call: _dgetrs_ (LAPACK)"])]
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=algos)
    assert "Matrix Solve Pipeline" not in _raporlanan(sonuc)


def test_alan_disi_tespit_asamayi_kanitlamaz():
    """CalculiX'te "conjugate_gradient_method" (optimizasyon) ML "backward" aşaması değildir."""
    cg = _cizge([("drv", "f1"), ("drv", "f2"), ("drv", "f3")])
    algos = [_algo("batch_norm", "ml_normalization", "f1"),
             _algo("conjugate_gradient_method", "optimization", "f2"),
             _algo("adam_optimizer", "ml_optimization", "f3")]
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=algos)
    assert "ML Training Loop" not in _raporlanan(sonuc)


# --- olumlu: gerçek hesap zinciri ---------------------------------------------

def test_gercek_fea_zinciri_sablonu_verir():
    cg = _cizge(_FEA_KENAR)
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=_fea_algolari())
    assert "Linear Static FEA Pipeline" in _raporlanan(sonuc)
    c = next(c for c in sonuc.compositions if c.name == "Linear Static FEA Pipeline")
    assert c.evidence_gate["passed"] is True
    assert c.evidence_gate["driver"] == "linstatic"
    assert set(c.evidence_gate["backed_stages"]) >= {"assembly", "solve"}
    assert "until convergence" not in c.description
    assert "not verified" in c.description
    assert 0.0 < c.confidence <= 0.95
    d = sonuc.to_dict()
    assert any(x["name"] == "Linear Static FEA Pipeline" for x in d["compositions"])


def test_soyulmus_ikilide_tespit_adiyla_sablon():
    """FUN_ adlı (soyulmuş) ikili: kanıt yalnız tespit adından; zincir yine bulunur."""
    cg = _cizge([("FUN_main", "FUN_1"), ("FUN_main", "FUN_2"), ("FUN_2", "FUN_3")])
    algos = [_algo("lu_factorization", "linear_algebra", "FUN_1", "api",
                   ["API call: dgetrf_ (LAPACK)"]),
             _algo("lu_solve", "linear_algebra", "FUN_3", "api",
                   ["API call: dgetrs_ (LAPACK)"])]
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=algos)
    assert "Matrix Solve Pipeline" in _raporlanan(sonuc)


def test_kayitli_json_function_anahtari():
    """``algorithms.json`` ``function`` anahtarıyla yazar; yeniden oynatma da eşlemeli."""
    cg = _cizge(_FEA_KENAR)
    algos = [{**a.to_dict(), "function": a.function_name} for a in _fea_algolari()]
    for a in algos:
        del a["function_name"]
    sonuc = AlgorithmCompositionAnalyzer().analyze(call_graph=cg, algorithms=algos)
    assert "Linear Static FEA Pipeline" in _raporlanan(sonuc)


def test_tanimlayici_asama_tablosu_tutarli():
    assert set(_TEMPLATE_DEFINING_STAGES) == set(KNOWN_COMPOSITIONS)
    for k, gruplar in _TEMPLATE_DEFINING_STAGES.items():
        assert gruplar
        for g in gruplar:
            for st in g:
                assert st in KNOWN_COMPOSITIONS[k]["stages"], (k, st)
