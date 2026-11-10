"""karadul/reconstruction/tarif/alt_kanal.py — ürün alt kanal sınıflayıcısı ve karar tablosu.

Plan v2.2 N1 adım 3 (tasarım §3.1-§3.2). Ürün modülü, donuk ölçüm betiğinin
(``scripts/measurement/alt_kanal.py``; tanım sürümü 1'in başvuru kopyası) kopyasıdır. Bu dosya iki
kopyanın ayrışmadığını ve karar tablosunun N0b sonucuyla aynı olduğunu kilitler. Başvuru betiği
dosya yolundan yüklenir; ürün kodu onu içe aktarmaz.

Etiket, gerçek ad ya da GT kullanılmaz. Depodaki N0b kayıtları yalnız yeniden sınıflanır; kayıt
içeriği başarısızlık iletisine yazılmaz (yalnız dosya adı ve anahtar).

Kilitlenen davranışlar:
  (a) sabitler başvuru betiğiyle aynı: düzenli ifadeler (desen ve bayrak), durak sözcükler, şablon
      yer tutucuları, sayısal sınırlar, alt kanal adları ve sırası, karar ve etiket sözlüğü;
      başvuru betiği N0b'nin ölçtüğü dosya (sha256),
  (b) sınıflama başvuru betiğiyle aynı: sapma dizgilerinde ve tohumlu rastgele dizgilerde alt kanal,
      her yüklemin tek başına değeri ve ``k``,
  (c) depodaki N0b atamaları ürün sınıflayıcısıyla yeniden üretilir,
  (d) anahtar sözcük çıkarımı ve kod yolu sabitleri c_namer'la aynı; c_namer'ın kendi adayları iki
      sınıflayıcıda aynı alt kanala düşer,
  (e) karar tablosu ``kesinlik_tablosu.json`` ile aynı; 9 alt kanal susar, 2'si "doğrulanmadı"
      etiketiyle kalır; kararı eksik alt kanal susar,
  (f) her alt kanalın sınır durumları (beklenen değerler açık yazılı),
  (g) arayüz: dört alanlı çağrı, çakışma ekinden önceki ad, bilinmeyen alt kanal, yalnız standart
      kitaplık.

Mutasyon koruması: ``scripts/measurement/mutation_specs_adim3_alt_kanal.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import random
import sys
from collections import Counter
from pathlib import Path

import pytest

from karadul.reconstruction.tarif import alt_kanal as U
from tests.test_alt_kanal import _cesitli_dizgiler, _sapma_dizgileri

KOK = Path(__file__).resolve().parents[1]
BASVURU_YOLU = KOK / "scripts" / "measurement" / "alt_kanal.py"
ONKAYIT_DIZINI = KOK / "docs" / "arge" / "2026-10-21_g10_n0b"
TABLO_YOLU = ONKAYIT_DIZINI / "kesinlik_tablosu.json"

_spec = importlib.util.spec_from_file_location("alt_kanal_basvuru_kopyasi", BASVURU_YOLU)
R = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = R
_spec.loader.exec_module(R)

SUSAN = frozenset({"agresif", "kod_parcasi", "bicim_parcasi", "tek_sozcuk", "tanimlayici",
                   "hata_iletisi", "bicim_dizgisi", "duz_metin", "diger"})
KALAN = ("oz_ad", "kebap_ad")


def klasik(kanit, kaynak="string_ref", **ek):
    """Klasik yolun bu kanıttan kuracağı köken kaydı (ad ve güven başvuru kopyasından)."""
    ad, k = R.klasik_ad(kanit)
    kayit = {"strategy": "string_context", "new_name": ad, "confidence": R.klasik_guven(k),
             "evidence": kanit, "code_path": "classic", "rule": "keywords",
             "evidence_origin": kaynak}
    kayit.update(ek)
    return kayit


def agresif(kanit, ad, guven=0.55, kural="error_verb", kaynak="string_ref"):
    return {"strategy": "string_context", "new_name": ad, "confidence": guven, "evidence": kanit,
            "code_path": "aggressive", "rule": kural, "evidence_origin": kaynak}


def kanal(kanit, **kw):
    return U.classify_record(klasik(kanit, **kw))


def _tablo():
    return json.loads(TABLO_YOLU.read_text(encoding="utf-8"))


def _sha256(yol):
    return hashlib.sha256(yol.read_bytes()).hexdigest()


# --------------------------------------------------------------------------------------------
# (a) sabitler ↔ başvuru betiği


def test_basvuru_betigi_n0b_nin_olctugu_dosya():
    # Karşılaştırılan başvuru, N0b adım 2'nin sha256'sını kaydettiği betiktir (donuk kopya).
    assert _sha256(BASVURU_YOLU) == _tablo()["onkosul"]["alt_kanal_sha256"]


@pytest.mark.parametrize("urun, basvuru", [
    ("KEYWORD_RE", "ANAHTAR_SOZCUK_RE"),
    ("FORMAT_SPEC_RE", "BICIM_BELIRTECI_RE"),
    ("IDENTIFIER_RE", "TANIMLAYICI_RE"),
    ("KEBAB_RE", "KEBAP_RE"),
    ("C_OPERATOR_RE", "C_ISLECI_RE"),
    ("GHIDRA_AUTO_NAME_RE", "GHIDRA_OTO_AD_RE"),
    ("ERROR_RE", "HATA_RE"),
])
def test_duzenli_ifadeler_basvuruyla_ayni(urun, basvuru):
    u, r = getattr(U, urun), getattr(R, basvuru)
    assert u.pattern == r.pattern
    assert u.flags == r.flags


@pytest.mark.parametrize("urun, basvuru", [
    ("DEFINITION_VERSION", "TANIM_SURUMU"),
    ("STRATEGY", "STRATEJI"),
    ("PATH_AGGRESSIVE", "AGRESIF_YOL"),
    ("PATH_CLASSIC", "KLASIK_YOL"),
    ("STOP_WORDS", "DURAK_SOZCUKLER"),
    ("MIN_STRING_LENGTH", "KISA_DIZGI"),
    ("MAX_KEYWORDS", "AZAMI_ANAHTAR"),
    ("NAME_PARTS", "AD_PARCASI"),
    ("TEMPLATE_PLACEHOLDERS", "SABLON_YER_TUTUCULARI"),
    ("SUBCHANNEL_NAMES", "ALT_KANAL_ADLARI"),
    ("DECISIONS", "KARARLAR"),
    ("KEPT_DECISIONS", "URUNDE_KALAN_KARARLAR"),
    ("DECISION_LABELS", "GUVEN_ETIKETLERI"),
])
def test_sabitler_basvuruyla_ayni(urun, basvuru):
    u, r = getattr(U, urun), getattr(R, basvuru)
    assert u == r
    assert type(u) is type(r)


def test_alt_kanal_listesi_ve_sirasi():
    assert U.SUBCHANNEL_NAMES == (
        "agresif", "kod_parcasi", "bicim_parcasi", "oz_ad", "tek_sozcuk", "tanimlayici",
        "kebap_ad", "hata_iletisi", "bicim_dizgisi", "duz_metin", "diger")
    assert [s.name for s in U.SUBCHANNELS] == [a.ad for a in R.ALT_KANALLAR]
    assert len(set(U.SUBCHANNEL_NAMES)) == len(U.SUBCHANNEL_NAMES) == 11
    assert U.DEFINITION_VERSION == 1


# --------------------------------------------------------------------------------------------
# (b) sınıflama ↔ başvuru betiği


def _esit(kayit):
    """Bir kayıt iki sınıflayıcıda aynı alt kanala, aynı yüklem değerlerine ve aynı k'ya düşer."""
    r = R.sinifla(kayit)
    girdi = U.record_input(kayit)
    assert U.classify_record(kayit) == r["alt_kanal"], kayit
    assert U.predicate_values(girdi) == r["yuklemler"], kayit
    assert list(U.predicate_values(girdi)) == list(r["yuklemler"])
    assert girdi.k == r["k"], kayit
    return r["alt_kanal"]


def _kayit_cesitleri(kanit):
    """Aynı kanıt için kayıt çeşitleri: iki kaynak, klasik ve agresif yol, ad çeşitleri."""
    for kaynak in ("string_ref", "body_literal"):
        yield klasik(kanit, kaynak=kaynak)
        # Ad kanıtın küçük harfli hâli: klasik ad kırpılmış olsa da oz_ad yüklemi tutar.
        yield klasik(kanit, kaynak=kaynak, new_name=kanit.strip().lower())
        yield klasik(kanit, kaynak=kaynak, new_name="baska_ad")
        # Çakışma eki: sınıflama ekten önceki ada (proposed_name) bakar.
        ad = R.klasik_ad(kanit)[0]
        yield klasik(kanit, kaynak=kaynak, new_name=ad + "_2", proposed_name=ad)
        yield agresif(kanit, "handle_x", kaynak=kaynak)
    # Kanıt alanları eksik kayıt (başka stratejinin rakibi gibi): boş dizgi sayılır.
    yield {"strategy": "string_context", "new_name": R.klasik_ad(kanit)[0], "evidence": kanit}


def test_sapma_dizgilerinde_siniflama_basvuruyla_ayni():
    n = 0
    for kanit in _sapma_dizgileri():
        for kayit in _kayit_cesitleri(kanit):
            _esit(kayit)
            n += 1
    assert n > 5000


_PARCALAR = (
    "cmdq_append", "Panel_new", "TERM_PROGRAM", "grid_set_cells", "server_client_lost",
    "window", "pane", "set", "the", "failed", "invalid", "usage", "too many", "could not",
    "can't", "badge", "monitor", "activity", "session", "x", "ab", "A", "Z9", "7",
    "%lld", "%s", "%%", "%5.2f", "%1$s", "%-8lu", "%.*s", "% d", "50%", "%", "%siB",
    "#{", "${", "{{", "#[", "}", "]", "->", "==", "!=", "<=", ">=", "&&", "||",
    "FUN_1000a1d6c", "DAT_100008000", "thunk_FUN_00101234", "local_28", "param_2", "pcVar1",
    "auStack_58", "undefined4", "undefined", "extraout_x1", "unaff_x19", "in_stack",
    "\n", "\t", " ", "  ", "-", "_", "__", ".", ",", ":", ";", "(", ")", "/", "\"", "'",
)


_SOZCUKLER = ("window", "pane", "monitor", "activity", "session", "set", "the", "failed",
              "Panel", "TERM", "exit", "on", "x9", "mode1")
_AYRACLAR = ("-", "_", " ", ".", "")


def _rastgele_dizgiler(tohum=20261110, adet=2500):
    """Tohumlu dizgiler: yarısı serbest parça dizisi, yarısı tek ayraçla bağlanmış sözcükler.

    İkinci biçim tanımlayıcı, kebap ve düz metin yüklemlerinin sınırlarına düşer; serbest dizide
    bunlar seyrek kalır.
    """
    rng = random.Random(tohum)
    cikti = []
    for i in range(adet):
        if i % 2:
            ayrac = rng.choice(_AYRACLAR)
            cikti.append(ayrac.join(rng.choice(_SOZCUKLER) for _ in range(rng.randint(1, 5))))
        else:
            cikti.append("".join(rng.choice(_PARCALAR) for _ in range(rng.randint(1, 6))))
    return cikti


def test_rastgele_dizgilerde_siniflama_basvuruyla_ayni():
    sayim: Counter = Counter()
    for kanit in _rastgele_dizgiler():
        for kayit in _kayit_cesitleri(kanit):
            sayim[_esit(kayit)] += 1
    # Karşılaştırma boş değil: nüfus on bir alt kanalın hepsine yeterince düşüyor.
    assert set(sayim) == set(U.SUBCHANNEL_NAMES)
    assert min(sayim.values()) >= 20, sayim


def test_rastgele_dizgiler_belirlenimci():
    assert _rastgele_dizgiler() == _rastgele_dizgiler()
    assert _rastgele_dizgiler(tohum=1) != _rastgele_dizgiler(tohum=2)


def test_her_aday_tam_bir_alt_kanala_duser_ve_ilk_tutan_kazanir():
    for kanit in _cesitli_dizgiler() + _rastgele_dizgiler(adet=300):
        for kayit in _kayit_cesitleri(kanit):
            girdi = U.record_input(kayit)
            degerler = U.predicate_values(girdi)
            assert degerler["diger"] is True
            ilk = next(ad for ad in U.SUBCHANNEL_NAMES if degerler[ad])
            assert U.classify_input(girdi) == ilk, kayit


# --------------------------------------------------------------------------------------------
# (c) depodaki N0b atamaları


def _depodaki_kayitlar():
    return sorted(ONKAYIT_DIZINI.glob("kayitlar_*.jsonl"))


@pytest.mark.skipif(not _depodaki_kayitlar(), reason="ön kayıt kayıt dosyaları yok")
def test_depodaki_atamalar_urun_siniflayicisiyla_yeniden_uretilir():
    """tests/test_alt_kanal.py'deki döngü ve alanlarla; karşılaştırılan ürün sınıflayıcısı."""
    beklenen_ozet = _tablo()["onkosul"]["kayitlar_sha256"]
    n = 0
    farkli = []
    for yol in _depodaki_kayitlar():
        # Yeniden sınıflanan nüfus N0b adım 2'nin ölçtüğü dosyalardır.
        program = yol.stem.removeprefix("kayitlar_")
        assert _sha256(yol) == beklenen_ozet[program], yol.name
        for satir in yol.read_text(encoding="utf-8").splitlines():
            s = json.loads(satir)
            if s["strateji"] != U.STRATEGY:
                continue
            kayit = {"strategy": s["strateji"], "new_name": s["ad"],
                     "proposed_name": s["onerilen_ad"], "confidence": s["guven"],
                     "evidence": s["kanit"], "code_path": s["kod_yolu"], "rule": s["kural"],
                     "evidence_origin": s["kanit_kaynagi"]}
            girdi = U.record_input(kayit)
            tutanlar = [ad for ad, d in U.predicate_values(girdi).items() if d]
            if (U.classify_record(kayit), girdi.k, tutanlar) != (
                    s["alt_kanal"], s["k"], s["yuklemler"]):
                farkli.append((yol.name, s["anahtar"]))
            n += 1
    assert farkli == []
    assert n > 0


# --------------------------------------------------------------------------------------------
# (d) c_namer


def test_anahtar_sozcukler_c_namer_ile_ayni():
    from karadul.reconstruction import c_namer as cn

    for s in _sapma_dizgileri() + _rastgele_dizgiler(adet=500):
        sozcukler = U.extract_keywords(s)
        assert [w for w, _, _ in sozcukler] == cn._extract_keywords_from_string(s), s
        # Konumlar sözcüğün dizgideki yeridir (bicim_parcasi bu aralıklara bakar).
        assert all(s[bas:son].lower() == w for w, bas, son in sozcukler), s


def test_kod_yolu_ve_kanit_kaynagi_sabitleri_c_namer_ile_ayni():
    from karadul.reconstruction import c_namer as cn

    assert cn.STRING_CONTEXT_CODE_PATHS == (U.PATH_AGGRESSIVE, U.PATH_CLASSIC)
    assert cn.STRING_CONTEXT_EVIDENCE_ORIGINS == ("string_ref", U.ORIGIN_BODY_LITERAL)


def test_c_namer_adaylari_iki_siniflayicida_ayni_alt_kanala_duser():
    """Süzgecin çağıracağı biçim: adayın dört alanı. Köken kaydına yazılan girdiyle aynı sonuç."""
    from karadul.config import Config
    from karadul.reconstruction import c_namer as cn

    yollar: Counter = Counter()
    for s in _sapma_dizgileri():
        adlandirici = cn.CVariableNamer(Config())
        adlandirici._string_refs_by_func = {"1000": [s]}
        adlandirici._func_bodies = {}
        adlandirici._strategy_string_context(cn._FunctionInfo(name="FUN_00001000", address="1000"))
        for aday in adlandirici._candidates.get("FUN_00001000", []):
            assert aday.strategy == U.STRATEGY
            urun = U.classify(evidence=aday.evidence, name=aday.new_name,
                              code_path=aday.code_path, evidence_origin=aday.evidence_origin)
            kayit = cn._ProvenanceRecorder._candidate_entry(aday)
            assert urun == R.sinifla(kayit)["alt_kanal"], s
            assert urun == U.classify_record(kayit), s
            yollar[aday.code_path] += 1
    assert yollar["classic"] > 100
    assert yollar["aggressive"] > 0


# --------------------------------------------------------------------------------------------
# (e) karar tablosu


def test_susan_ve_kalan_alt_kanallar():
    assert U.SILENCED_SUBCHANNELS == SUSAN
    assert U.KEPT_SUBCHANNELS == KALAN
    assert len(U.SILENCED_SUBCHANNELS) == 9
    assert U.SILENCED_SUBCHANNELS | set(U.KEPT_SUBCHANNELS) == set(U.SUBCHANNEL_NAMES)
    assert not U.SILENCED_SUBCHANNELS & set(U.KEPT_SUBCHANNELS)
    for ad in U.SUBCHANNEL_NAMES:
        assert U.is_silenced(ad) is (ad in SUSAN)


def test_kalan_alt_kanallarin_etiketi_dogrulanmadi():
    assert U.LABEL_UNVERIFIED == "doğrulanmadı"
    assert U.LABEL_VERIFIED == "doğrulandı"
    assert U.label_for("oz_ad") == "doğrulanmadı"
    assert U.label_for("kebap_ad") == "doğrulanmadı"
    for ad in SUSAN:
        assert U.label_for(ad) is None


def test_karar_tablosu_kesinlik_tablosuyla_ayni():
    tablo = _tablo()
    assert dict(U.SUBCHANNEL_DECISIONS) == tablo["ana_kararlar"]
    assert list(U.SUBCHANNEL_DECISIONS) == list(U.SUBCHANNEL_NAMES)
    assert U.KEPT_DECISIONS == frozenset(tablo["kural"]["urunde_kalan_kararlar"])
    assert dict(U.DECISION_LABELS) == tablo["kural"]["guven_etiketleri"]
    birlesik = tablo["ana"]["birlesik"]["alt_kanallar"]
    assert list(birlesik) == list(U.SUBCHANNEL_NAMES)
    for ad in U.SUBCHANNEL_NAMES:
        karar = birlesik[ad]["karar"]
        assert karar["karar"] == U.SUBCHANNEL_DECISIONS[ad]
        assert U.is_silenced(ad) is (not karar["urunde"]), ad
        assert U.label_for(ad) == karar["guven_etiketi"], ad
    assert tablo["hepsini_kapatir"] is (not U.KEPT_SUBCHANNELS)


def test_karar_basvuru_kuraliyla_ayni_yorumlanir():
    # Ürün tablosundaki her karar, başvuru betiğinin "üründe kalır" ve etiket kuralıyla okunur.
    for ad, karar in U.SUBCHANNEL_DECISIONS.items():
        assert karar in U.DECISIONS
        k = {"karar": karar}
        assert U.is_silenced(ad) is (not R.urunde_kalir(k)), ad
        assert U.label_for(ad) == R.guven_etiketi(k), ad
    assert not R.hepsini_kapatir({ad: {"karar": k} for ad, k in U.SUBCHANNEL_DECISIONS.items()})


@pytest.mark.parametrize("karar, susar", [
    ("dogrulandi", False), ("belirsiz", False), ("zayif", True), ("olculemedi", True),
    ("bilinmeyen_karar", True),
])
def test_silenced_from_yalniz_kalan_kararlar_ad_verir(karar, susar):
    kararlar = {ad: karar for ad in U.SUBCHANNEL_NAMES}
    assert U.silenced_from(kararlar) == (frozenset(U.SUBCHANNEL_NAMES) if susar else frozenset())


def test_silenced_from_karari_eksik_alt_kanal_susar():
    # Ölçülmemiş kanal ad vermez: tabloda hiç geçmeyen alt kanal susan kümededir.
    kararlar = dict(U.SUBCHANNEL_DECISIONS)
    del kararlar["oz_ad"]
    assert U.silenced_from(kararlar) == SUSAN | {"oz_ad"}
    assert U.silenced_from({}) == frozenset(U.SUBCHANNEL_NAMES)
    # Tabloda fazladan duran, tanımda olmayan ad kümeye girmez.
    assert U.silenced_from(dict(U.SUBCHANNEL_DECISIONS, yeni_kanal="zayif")) == SUSAN


# --------------------------------------------------------------------------------------------
# (f) alt kanalların sınır durumları (beklenen değerler açık)


def test_agresif_kod_yolu_her_bicimden_once():
    assert U.classify_record(agresif("cmdq_append() failed", "cmdq_append", 0.80,
                                     kural="func_paren")) == "agresif"
    assert U.classify_record(agresif("cmdq_append", "cmdq_append")) == "agresif"
    assert U.classify_record(agresif(");\n  FUN_1000a1d6c(", "x", kaynak="body_literal")) == "agresif"
    # Kod yolu boş ya da klasik: agresif değil.
    assert U.classify(evidence="cmdq_append", name="cmdq_append", code_path="",
                      evidence_origin="string_ref") == "oz_ad"


def test_kod_parcasi_yalniz_gercek_olmayan_govde_literali():
    assert kanal(");\n  FUN_1000a1d6c(&local_28,", kaynak="body_literal") == "kod_parcasi"
    # Aynı satırdaki kod parçası: satır sonu yok ama Ghidra'nın kendiliğinden verdiği ad var.
    assert kanal(",0x2000);  FUN_10002286c(lVar1,", kaynak="body_literal") == "kod_parcasi"
    # Gövdeden okunmuş gerçek literal kod parçası değildir.
    assert kanal("synchronize-panes", kaynak="body_literal") == "kebap_ad"
    # Dizgi tablosundaki gerçek bir satır sonu ya da Ghidra adı kod parçası sayılmaz.
    assert kanal("Usage:\n  tmux new-session", kaynak="string_ref") == "hata_iletisi"
    assert kanal("call FUN_1000a1d6c now", kaynak="string_ref") == "duz_metin"
    # Gerçek literaldeki İngilizce sözcük Ghidra adı sayılmaz; rakamlı tip adı sayılır.
    assert kanal("value is undefined here", kaynak="body_literal") == "duz_metin"
    assert kanal("x = *(undefined4 *)", kaynak="body_literal") == "kod_parcasi"


def test_kod_parcasi_bicim_parcasindan_once():
    kanit = ";\n  _printf(\"%lld"
    girdi = U.record_input(klasik(kanit, kaynak="body_literal"))
    assert U.predicate_values(girdi)["bicim_parcasi"] is True
    assert kanal(kanit, kaynak="body_literal") == "kod_parcasi"
    assert kanal(kanit, kaynak="string_ref") == "bicim_parcasi"


def test_bicim_parcasi_ad_kuran_sozcuk_belirtece_tasiyor():
    assert kanal("%lld") == "bicim_parcasi"
    assert kanal("r:%siB/s w:%siB/s") == "bicim_parcasi"
    # Belirtece taşan sözcük adın ikinci parçası.
    assert kanal("took %llu milliseconds") == "bicim_parcasi"


def test_bicim_parcasi_dorduncu_sozcuk_ada_girmez():
    # Dördüncü anahtar sözcük ada girmez: belirtece taşsa da biçim parçası sayılmaz.
    assert [w for w, _, _ in U.extract_keywords("alpha beta gamma %lld")] == [
        "alpha", "beta", "gamma", "lld"]
    assert kanal("alpha beta gamma %lld") == "bicim_dizgisi"


def test_bicim_parcasi_bitisik_sozcuk_tasma_degil():
    # Sözcük belirtece yalnız bitişik (aralıklar kesişmiyor): biçim parçası değil.
    assert U.format_specs("value%d items") == [(5, 7)]
    assert U.extract_keywords("value%d items")[0] == ("value", 0, 5)
    assert kanal("value%d items") == "bicim_dizgisi"
    assert kanal("%d,items here") == "bicim_dizgisi"


def test_bicim_belirteci_yuzde_yuzde_ve_bosluk_bayragi():
    assert U.format_specs("%%sessions-changed") == []
    assert kanal("%%sessions-changed") == "diger"
    assert U.format_specs("%%%u bytes") == [(2, 4)]
    # Boşluk bayrağı alınmaz: düz metindeki "50% done" belirteç değil.
    assert U.format_specs("50% done now") == []
    assert kanal("50% done now") == "duz_metin"
    # Belirtece taşmayan sözcükler: biçim dizgisi.
    assert kanal("%s: received secondary DA %.*s") == "bicim_dizgisi"


def test_oz_ad_ve_tanimlayici():
    assert kanal("cmdq_append") == "oz_ad"
    assert kanal("  cmdq_append ") == "oz_ad"           # baştaki ve sondaki boşluk atılır
    assert kanal("Panel_new") == "oz_ad"                # küçük harf var, ad dizginin küçüğü
    # Tümü büyük harf: sabit ya da ortam değişkeni, kendi adı sayılmaz.
    assert klasik("TERM_PROGRAM_VERSION")["new_name"] == "term_program_version"
    assert kanal("TERM_PROGRAM_VERSION") == "tanimlayici"
    # Ad dizgiden farklı: durak sözcük, kısa parça, rakam, dördüncü parça.
    assert klasik("grid_set_cells")["new_name"] == "grid_cells"
    assert kanal("grid_set_cells") == "tanimlayici"
    assert kanal("cmd_if_shell_exec") == "tanimlayici"
    assert kanal("input_key_mode1") == "tanimlayici"
    assert kanal("cmd_find_from_session_window") == "tanimlayici"
    # Alt çizgisiz tanımlayıcı ne oz_ad ne tanimlayici.
    assert kanal("MouseMoveStatusRight") == "tek_sozcuk"
    assert klasik("input9mode")["new_name"] == "input_mode"
    assert kanal("input9mode") == "diger"
    assert kanal("ab") == "diger"


def test_oz_ad_cakisma_ekinden_once_gelen_adla():
    kayit = klasik("args_copy", new_name="args_copy_2", proposed_name="args_copy")
    assert U.classify_record(kayit) == "oz_ad"
    # Ek ada işlemişse (proposed_name yok) ad dizgiden farklıdır.
    assert U.classify_record(klasik("args_copy", new_name="args_copy_2")) == "tanimlayici"


def test_tek_sozcuk_bicim_kanallarindan_once():
    assert kanal("window") == "tek_sozcuk"
    assert kanal("too small") == "tek_sozcuk"              # "too" durak sözcük
    assert kanal("gettimeofday failed") == "tek_sozcuk"    # hata iletisinden önce
    assert kanal("server_client_lost") == "tek_sozcuk"     # tanımlayıcıdan önce
    # k = 0 tek sözcük değildir.
    assert U.record_input(klasik("the and for")).k == 0
    assert kanal("the and for") == "duz_metin"
    assert kanal("") == "diger"


def test_kebap_ad():
    assert kanal("monitor-activity") == "kebap_ad"
    assert kanal("remain-on-exit") == "kebap_ad"
    assert kanal(" remain-on-exit\n") == "kebap_ad"        # boşluk atılır
    assert kanal("Monitor-Activity") == "diger"            # büyük harf: kebap değil
    assert kanal("no-detach-on-destroy,") == "diger"       # sondaki virgül
    assert kanal("monitor_activity-pane") == "diger"       # alt çizgi: tek belirteç değil


def test_hata_iletisi_ve_sozcuk_siniri():
    assert kanal("invalid sort order") == "hata_iletisi"
    assert kanal("usage: tmux [-2CDlNuVv] [-c shell-command]") == "hata_iletisi"
    assert kanal("cannot swap down on floating pane") == "hata_iletisi"
    assert kanal("couldn't create window %d") == "hata_iletisi"   # biçim dizgisinden önce
    assert kanal("user option %s must be a string") == "hata_iletisi"
    assert kanal("Illegal Window Size") == "hata_iletisi"         # harf büyüklüğüne bakılmaz
    assert kanal("badge count changed") == "duz_metin"            # "bad" sözcük sınırında


def test_bicim_dizgisi_duz_metin_diger():
    assert kanal("remove wait channel %s") == "bicim_dizgisi"
    for yer_tutucu in ("#{session_name}:#{window_index}", "#[fg=colour1]pane", "${HOME}/config",
                       "{{window.name}}"):
        assert kanal(yer_tutucu) == "bicim_dizgisi", yer_tutucu
    assert kanal("window only linked to one session") == "duz_metin"
    assert kanal("Available Columns") == "duz_metin"
    assert kanal("kern.osrelease") == "diger"
    assert kanal("gl->cellused <= gl->cellsize") == "diger"       # C işleci
    assert kanal("/tmp/tmux.XXXXXXXX") == "diger"


# --------------------------------------------------------------------------------------------
# (g) arayüz


def test_classify_dort_alan_kayitla_ayni_sonuc():
    for kanit in _cesitli_dizgiler():
        for kayit in _kayit_cesitleri(kanit):
            ad = kayit.get("proposed_name") or kayit["new_name"]
            assert U.classify(evidence=kayit["evidence"], name=ad,
                              code_path=kayit.get("code_path", ""),
                              evidence_origin=kayit.get("evidence_origin", "")) \
                == U.classify_record(kayit)


def test_classify_yalniz_anahtar_sozcuklu_arguman_alir():
    with pytest.raises(TypeError):
        U.classify("cmdq_append", "cmdq_append", "classic", "string_ref")


def test_record_input_eksik_ve_bos_alanlar():
    girdi = U.record_input({"new_name": "x", "evidence": None})
    assert girdi == U.ClassifierInput("", "", "", "", "x", [])
    assert U.classify_input(girdi) == "diger"
    assert U.classify_record({}) == "diger"


def test_bilinmeyen_alt_kanal_hata_verir():
    for islev in (U.is_silenced, U.label_for):
        with pytest.raises(ValueError):
            islev("string_context")
        with pytest.raises(ValueError):
            islev("")


def test_modul_yalniz_standart_kitaplik_ve_etiket_sozlugunu_kullanir():
    # Ürün ölçüm betiğini ve c_namer'ı içe aktarmaz (döngü ve paketleme). Tek iç bağımlılık,
    # ağır bağımlılığı olmayan etiket sözlüğüdür (karadul.core.naming_labels).
    agac = ast.parse(Path(U.__file__).read_text(encoding="utf-8"))
    moduller = set()
    for dugum in ast.walk(agac):
        if isinstance(dugum, ast.Import):
            moduller.update(a.name for a in dugum.names)
        elif isinstance(dugum, ast.ImportFrom):
            assert dugum.level == 0
            moduller.add(dugum.module or "")
    assert moduller == {"__future__", "re", "collections.abc", "typing", "karadul.core.naming_labels"}
    from karadul.core import naming_labels
    assert U.LABEL_VERIFIED is naming_labels.LABEL_VERIFIED
    assert U.LABEL_UNVERIFIED is naming_labels.LABEL_UNVERIFIED
