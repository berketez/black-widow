"""HZ-7a: düzenli ifade deseni önbelleği ve satır ön süzgeci (çıktıyı değiştirmez).

Sınananlar:
- 20 küçük C gövdesinde (elle yazılmış, Ghidra biçeminde; geliştirme setinden alınmadı:
  depo herkese açık) ``_strategy_dataflow`` + ``_strategy_local_var_naming`` aday listesi
  (anahtar sırası, ad, güven, strateji, gerekçe) eski davranışla aynı. Eski davranış iki
  yoldan gelir: (a) aynı stratejiler önbelleksiz derleyici ve süzgeçsiz aramayla
  (``_ozel_desen`` ve ``_ozel_desen_suzgec_uygun`` yerine eski yol), (b) main
  ``ed28e36b``'nin ürün koduyla (HZ-7a öncesi) üretilmiş sabit özet.
- Ön süzgecin doğruluk koşulu iki desen listesinin HER öğesinde; liste değişirse özet
  sınaması kırmızı olur.
- Ad yalnız başka bir tanımlayıcının parçası olarak geçtiğinde (alt dizgi) davranış aynı.
- ``re.error`` yolu (yerel değişken: atla ve günlüğe yaz; veri akışı: yükselt), hatanın da
  önbelleğe girmesi; önbellek sınırı dolunca sonuç aynı; anahtar adı içerir; sayaçlar.
- ``api_param_db``: büyük desenler örnek başına bir kez kurulur; sonuç eski yolla aynı;
  ``_desenleri_sifirla``.
"""

from __future__ import annotations

import hashlib
import json
import re
from types import SimpleNamespace

import pytest

import karadul.reconstruction.api_param_db as A
import karadul.reconstruction.c_namer as C
from karadul.config import Config
from karadul.reconstruction.api_param_db import APIParamDB
from karadul.reconstruction.c_namer import CVariableNamer, _FunctionInfo

# ---------------------------------------------------------------------------
# 20 gövde: (ad, parametreler, gövde). Parametreler ``_strategy_dataflow``'un parametre
# döngüsü içindir (dict biçimi: Ghidra ``ghidra_functions.json``).
# ---------------------------------------------------------------------------


def _p(*adlar: str) -> list[dict[str, str]]:
    return [{"name": a, "type": "long"} for a in adlar]


GOVDELER: list[tuple[str, list[dict[str, str]], str]] = [
    ("FUN_00101000", _p("param_1", "param_2"), """
void FUN_00101000(char *param_1,long param_2)
{
  size_t sVar1;
  char *pcVar2;
  int iVar3;

  sVar1 = strlen(param_1);
  pcVar2 = (char *)malloc(sVar1 + 1);
  strcpy(pcVar2,param_1);
  iVar3 = strcmp(pcVar2,"--help");
  if (iVar3 == 0) {
    free(pcVar2);
    return;
  }
  memcpy(param_2,pcVar2,sVar1);
  free(pcVar2);
  return;
}
"""),
    ("FUN_00101100", _p("param_1", "param_2", "param_3"), """
long FUN_00101100(long *param_1,int param_2,long param_3)
{
  long lVar1;
  int iVar2;
  uint uVar3;

  lVar1 = 0;
  for (iVar2 = 0; iVar2 < param_2; iVar2 = iVar2 + 1) {
    lVar1 = lVar1 + param_1[iVar2];
    uVar3 = uVar3 + 1;
  }
  if (param_3 == 0) {
    return -1;
  }
  *(long *)(param_3 + 0x10) = lVar1;
  return lVar1;
}
"""),
    ("FUN_00101200", _p("param_1"), """
int FUN_00101200(char *param_1)
{
  FILE *pFVar1;
  int iVar2;
  size_t sVar3;
  undefined8 local_118;
  char local_108 [256];

  pFVar1 = fopen(param_1,"r");
  if (pFVar1 == (FILE *)0x0) {
    perror("fopen");
    return -1;
  }
  sVar3 = fread(local_108,1,0x100,pFVar1);
  local_118 = sVar3;
  iVar2 = fclose(pFVar1);
  return iVar2;
}
"""),
    ("FUN_00101300", _p("param_1", "param_2"), """
void FUN_00101300(int param_1,undefined8 param_2)
{
  int iVar1;
  ssize_t sVar2;
  undefined local_48 [64];

  iVar1 = socket(2,1,0);
  if (iVar1 < 0) {
    return;
  }
  iVar1 = connect(iVar1,param_2,0x10);
  sVar2 = send(param_1,local_48,0x40,0);
  sVar2 = recv(param_1,local_48,0x40,0);
  close(param_1);
  return;
}
"""),
    ("FUN_00101400", _p("param_1"), """
double FUN_00101400(double *param_1)
{
  double dVar1;
  double dVar2;
  double dVar3;

  dVar1 = param_1[0] * param_1[0] + param_1[1] * param_1[1];
  dVar2 = sqrt(dVar1);
  dVar3 = atan2(param_1[1],param_1[0]);
  dVar1 = exp(dVar3);
  dVar1 = log(dVar2);
  dVar3 = pow(dVar1,2.0);
  dVar2 = fabs(dVar3);
  return dVar2;
}
"""),
    ("FUN_00101500", _p("param_1"), """
long * FUN_00101500(long *param_1)
{
  long *plVar1;
  long *plVar2;

  plVar1 = param_1;
  while (plVar1 != (long *)0x0) {
    plVar2 = *(long **)plVar1;
    plVar1 = *(long **)(plVar1 + 0x8);
    if (plVar2 == (long *)0x0) break;
  }
  return plVar1;
}
"""),
    ("FUN_00101600", _p("param_1", "param_2"), """
uint FUN_00101600(uint param_1,uint param_2)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;

  uVar1 = param_1 >> 4;
  uVar2 = param_2 << 3;
  uVar3 = param_1 & 0xff;
  uVar1 |= uVar2;
  uVar2 &= 0xf0f0;
  uVar3 ^= uVar1;
  uVar1 >>= 2;
  return uVar1 + uVar3;
}
"""),
    ("FUN_00101700", _p("param_1", "param_2"), """
int FUN_00101700(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;

  iVar1 = (param_1 < param_2) ? param_1 : param_2;
  iVar2 = (param_1 > param_2) ? param_1 : param_2;
  iVar3 = param_1 / param_2;
  iVar3 = param_1 % param_2;
  switch(iVar1) {
  case 0:
    return iVar2;
  }
  return iVar3;
}
"""),
    ("FUN_00101800", _p("param_1"), """
void FUN_00101800(long param_1)
{
  char *pcVar1;
  char *pcVar2;
  char *pcVar3;
  long lVar4;

  pcVar1 = getenv("HOME");
  pcVar2 = strchr(pcVar1,0x2f);
  pcVar3 = strrchr(pcVar1,0x2e);
  pcVar2 = strstr(pcVar1,"tmp");
  lVar4 = strtol(pcVar3,(char **)0x0,10);
  snprintf((char *)param_1,0x100,"%s",pcVar2);
  return;
}
"""),
    ("FUN_00101900", _p("param_1", "param_2"), """
int FUN_00101900(undefined8 param_1,int param_2)
{
  int iVar1;
  long lVar2;
  undefined8 uVar3;

  lVar2 = dlopen(param_1,1);
  if (lVar2 == 0) {
    return -1;
  }
  uVar3 = dlsym(lVar2,"init");
  iVar1 = FUN_00104000(uVar3,param_2);
  if (iVar1 != 0) {
    return iVar1;
  }
  return 0;
}
"""),
    # Alt dizgi: ``param_1`` yalnız ``param_10`` içinde, ``uVar1`` ayrıca ``uVar12`` /
    # ``puVar1`` içinde geçiyor.
    ("FUN_00101a00", _p("param_1", "param_10"), """
void FUN_00101a00(long param_10,long param_11)
{
  uint uVar1;
  uint uVar12;
  uint *puVar1;

  *param_10 = 0;
  free(param_10);
  uVar12 = 0;
  puVar1 = &uVar12;
  uVar1 = *puVar1;
  uVar12 = uVar12 + 1;
  if (uVar1 == 0) {
    return;
  }
  return;
}
"""),
    ("FUN_00101b00", _p("param_1", "param_2"), """
void FUN_00101b00(float *param_1,int param_2)
{
  int iVar1;
  int iVar2;
  float fVar3;

  for (iVar1 = 0; iVar1 < param_2; iVar1 = iVar1 + 1) {
    for (iVar2 = 0; iVar2 < 3; iVar2 = iVar2 + 1) {
      fVar3 = param_1[iVar1 * 3 + 0];
      param_1[iVar1 * 4 + iVar2] = fVar3;
    }
  }
  return;
}
"""),
    ("FUN_00101c00", _p("param_1"), """
int FUN_00101c00(int param_1)
{
  int iVar1;
  int iVar2;
  long local_20;
  int local_14;

  iVar1 = fork();
  if (iVar1 == -1) {
    return -1;
  }
  iVar2 = getpid();
  local_20 = time((time_t *)0x0);
  local_14 = atoi("42");
  local_14 = local_14 + param_1;
  if (local_14 > 100) {
    return 1;
  }
  return iVar2;
}
"""),
    ("FUN_00101d00", _p("param_1", "param_2"), """
void FUN_00101d00(long param_1,long param_2)
{
  long lVar1;
  undefined8 *puVar2;
  long local_30;

  local_30 = 0;
  while (local_30 < param_2) {
    lVar1 = *(long *)(param_1 + local_30 * 8);
    if (lVar1 == 0) break;
    local_30 = local_30 + 1;
  }
  puVar2 = (undefined8 *)realloc(param_1,local_30 * 8);
  memset(puVar2,0,local_30);
  DAT_00105010 = puVar2;
  return;
}
"""),
    ("FUN_00101e00", _p("param_1"), """
undefined8 FUN_00101e00(long param_1)
{
  int iVar1;
  bool bVar2;
  char cVar3;

  bVar2 = false;
  iVar1 = 0;
  do {
    cVar3 = *(char *)(param_1 + iVar1);
    if (cVar3 == '\\0') break;
    iVar1 = iVar1 + 1;
  } while (!bVar2);
  if (bVar2) {
    return 1;
  }
  while (iVar1) {
    iVar1--;
  }
  return 0;
}
"""),
    ("FUN_00101f00", _p("param_1", "param_2", "param_3"), """
long FUN_00101f00(int param_1,long param_2,long param_3)
{
  ssize_t sVar1;
  long lVar2;

  sVar1 = write(param_1,param_2,param_3);
  if (sVar1 != -1) {
    lVar2 = read(param_1,param_2,param_3);
    return lVar2;
  }
  fwrite(param_2,1,param_3,stderr);
  printf("%ld\\n",param_3);
  return sVar1;
}
"""),
    ("FUN_00102000", [], """
void FUN_00102000(void)
{
  undefined4 uVar1;
  int iVar2;
  undefined8 local_28;
  undefined4 local_1c;
  undefined2 local_16;
  char *local_10;

  uVar1 = FUN_00103000();
  local_28 = FUN_00103100(uVar1);
  iVar2 = inflateEnd(local_28);
  local_1c = (int)local_28;
  local_16 = 0;
  local_10 = (char *)0x0;
  FUN_00103200(local_10,local_16,local_1c,iVar2);
  return;
}
"""),
    ("FUN_00102100", _p("param_1"), """
int FUN_00102100(long param_1)
{
  int iVar1;
  long lVar2;
  int iVar3;

  iVar3 = 0;
  for (lVar2 = param_1; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x18)) {
    iVar1 = FUN_00104100(lVar2);
    iVar3 += iVar1;
    iVar3 *= 2;
  }
  iVar1 = iVar3 - 1;
  iVar1 -= 4;
  return iVar1;
}
"""),
    ("FUN_00102200", _p("param_1", "param_2"), """
void FUN_00102200(char *param_1,char *param_2)
{
  char *pcVar1;
  size_t sVar2;
  int iVar3;

  pcVar1 = strdup(param_1);
  strcat(pcVar1,param_2);
  sVar2 = strlen(pcVar1);
  iVar3 = memcmp(pcVar1,param_2,sVar2);
  if (iVar3 != 0) {
    sprintf(param_1,"%s",pcVar1);
  }
  strncpy(param_2,pcVar1,sVar2);
  free(pcVar1);
  return;
}
"""),
    ("FUN_00102300", _p("param_1"), """
undefined8 FUN_00102300(long param_1)
{
  undefined8 uVar1;
  long lVar2;
  ulong uVar3;
  float fVar4;
  double dVar5;

  lVar2 = mmap(0,0x1000,3,0x22,0xffffffff,0);
  uVar1 = FUN_00104200(param_1);
  uVar3 = (ulong)lVar2 >> 0xc;
  fVar4 = (float)uVar3;
  dVar5 = (double)fVar4;
  dVar5 = floor(dVar5);
  dVar5 = ceil(dVar5);
  uVar1 = (uint)dVar5;
  return uVar1;
}
"""),
]

assert len(GOVDELER) == 20


def _aday_listesi(ad: str, params: list[dict[str, str]], govde: str,
                  config: Config | None = None) -> list:
    """Veri akışı + yerel değişken stratejilerinin aday listesi (sıra korunur)."""
    namer = CVariableNamer(config or Config(), min_confidence=0.15)
    namer._func_bodies[ad] = govde
    fi = _FunctionInfo(name=ad, address="0x1000", params=list(params))
    namer._strategy_dataflow(fi)
    namer._strategy_local_var_naming(fi)
    return [
        [k, [[c.old_name, c.new_name, round(c.confidence, 6), c.strategy, c.reason]
             for c in v]]
        for k, v in namer._candidates.items()
    ]


def butun_adaylar(config: Config | None = None) -> list:
    return [[ad, _aday_listesi(ad, prm, gv, config)] for ad, prm, gv in GOVDELER]


def ozet(veri: list) -> str:
    return hashlib.sha256(
        json.dumps(veri, ensure_ascii=False, sort_keys=False).encode("utf-8")
    ).hexdigest()


# main ``ed28e36b``'nin ürün koduyla (HZ-7a öncesi; sabit ağaç ``~/karadul_olcum/urun-ed28e36b``)
# üretildi: ``PYTHONPATH=<ağaç> python HZ7a/eski_ozet.py <bu dosya>`` (koşu kökünde; tohum 0 ve
# 77 aynı özet). Bu dalın koduyla da aynı özet çıktı (2026-11-27).
ESKI_KOD_OZETI = "46cd19cf83a5febdd454391e9343f8525ca4bbda2f0b0db7a2918cccfecc9bfa"
ESKI_KOD_ADAY_SAYISI = 76


@pytest.fixture()
def eski_yol(monkeypatch: pytest.MonkeyPatch):
    """Eski davranış: her çağrıda yeniden derleme, satır ön süzgeci yok."""

    def _derle(kalip, ad, _ust_sinir):
        metin = kalip if isinstance(kalip, str) else kalip.pattern
        return re.compile(metin.replace("PARAM", re.escape(ad)))

    monkeypatch.setattr(C, "_ozel_desen", _derle)
    monkeypatch.setattr(C, "_ozel_desen_suzgec_uygun", lambda _k: False)


@pytest.fixture()
def temiz_onbellek():
    C._OZEL_DESEN_ONBELLEGI.clear()
    yield
    C._OZEL_DESEN_ONBELLEGI.clear()


# ---------------------------------------------------------------------------
# 1. Eşitlik
# ---------------------------------------------------------------------------


def test_yeni_yol_eski_kodun_ozetiyle_ayni(temiz_onbellek) -> None:
    yeni = butun_adaylar()
    assert sum(len(a) for _, a in yeni) == ESKI_KOD_ADAY_SAYISI
    assert ozet(yeni) == ESKI_KOD_OZETI


def test_eski_yol_da_eski_kodun_ozetini_verir(eski_yol) -> None:
    """Sınamanın körleşmediği: önbelleksiz yardımcıyla aynı stratejiler aynı özeti verir."""
    assert ozet(butun_adaylar()) == ESKI_KOD_OZETI


def test_yeni_eski_aday_listesi_govde_govde_esit(temiz_onbellek, monkeypatch) -> None:
    yeni = butun_adaylar()
    # İkinci koşu: önbellek dolu (isabet yolu) — yine aynı.
    yeni2 = butun_adaylar()
    with monkeypatch.context() as m:
        m.setattr(C, "_ozel_desen",
                  lambda k, ad, _u: re.compile(
                      (k if isinstance(k, str) else k.pattern).replace("PARAM", re.escape(ad))))
        m.setattr(C, "_ozel_desen_suzgec_uygun", lambda _k: False)
        eski = butun_adaylar()
    for (ad, y), (_, y2), (_, e) in zip(yeni, yeni2, eski):
        assert y == e, ad
        assert y2 == e, ad
    # Sınama boş değil: her iki stratejiden aday var.
    stratejiler = {c[3] for _, a in eski for _, cs in a for c in cs}
    assert {"dataflow", "local_var"} <= stratejiler
    assert sum(len(a) for _, a in eski) == ESKI_KOD_ADAY_SAYISI


def test_alt_dizgi_ad_eski_davranisla_ayni(temiz_onbellek, monkeypatch) -> None:
    """``param_1`` gövdede yalnız ``param_10`` içinde; ``uVar1`` ayrıca ``uVar12`` / ``puVar1``.

    Eski yol (alt dizgi ``in`` denetimi + desen) ``*param_10``'u ``param_1`` için
    ``\\*\\s*param_1`` deseniyle eşler; ön süzgeç de bu satırı tutar (``param_1``
    ``param_10``'un alt dizgisi): sonuç eskisiyle aynı kalmalı.
    """
    ad, prm, gv = next(g for g in GOVDELER if g[0] == "FUN_00101a00")
    yeni = _aday_listesi(ad, prm, gv)
    with monkeypatch.context() as m:
        m.setattr(C, "_ozel_desen",
                  lambda k, a, _u: re.compile(
                      (k if isinstance(k, str) else k.pattern).replace("PARAM", re.escape(a))))
        m.setattr(C, "_ozel_desen_suzgec_uygun", lambda _k: False)
        eski = _aday_listesi(ad, prm, gv)
    assert yeni == eski
    d = dict(yeni)
    # Alt dizgiden gelen aday (sınama boş değil): ``param_1`` → ``ptr``.
    assert [c[1] for c in d[f"{ad}::param_1"]] == ["ptr"]
    # ``uVar1``'in satırları ``uVar12`` / ``puVar1`` satırlarını da içerir; desen sınırı ayırır.
    assert f"{ad}::uVar1" in d
    assert any("uVar12" in ln and "uVar1" in ln for ln in gv.splitlines())


# ---------------------------------------------------------------------------
# 2. Ön süzgecin doğruluk koşulu (iki liste, her öğe)
# ---------------------------------------------------------------------------

# Liste içerikleri (desen metni, önerilen ad, güven) değişirse bu özet tutmaz: koşulu
# yeniden doğrula, aşağıdaki iki kümeyi ve özeti birlikte güncelle.
PARAM_LISTE_OZETI = "be38dc78bb111ce4d545fb5e70f3f131e9c5a4d23a68fd0ad0d1e602349194bd"
YEREL_LISTE_OZETI = "7c0988369981e3ce82cab9575db0145257f3cd7d8a375c7a1bcab97cf2c5dfe3"
# Koşulu sağlamayan öğeler (liste sırası): ``PARAM`` iki kez geçenler.
PARAM_SUZGECSIZ: tuple[int, ...] = ()
YEREL_SUZGECSIZ: tuple[int, ...] = (66, 68, 71, 92, 93)


def _liste_ozeti(liste) -> str:
    return hashlib.sha256(
        json.dumps([[p.pattern, s, c] for p, s, c in liste]).encode("utf-8")
    ).hexdigest()


@pytest.mark.parametrize("liste_adi,beklenen_ozet,suzgecsiz", [
    ("_PARAM_USAGE_PATTERNS", PARAM_LISTE_OZETI, PARAM_SUZGECSIZ),
    ("_LOCAL_VAR_USAGE_PATTERNS", YEREL_LISTE_OZETI, YEREL_SUZGECSIZ),
])
def test_suzgec_kosulu_her_oge(liste_adi, beklenen_ozet, suzgecsiz) -> None:
    liste = getattr(C, liste_adi)
    assert _liste_ozeti(liste) == beklenen_ozet, (
        f"{liste_adi} değişti: ön süzgeç koşulunu her öğe için yeniden doğrula")
    hesap = tuple(i for i, (p, _s, _c) in enumerate(liste)
                  if not C._ozel_desen_suzgec_uygun(p))
    assert hesap == suzgecsiz
    for i, (p, _s, _c) in enumerate(liste):
        tek = p.pattern.count("PARAM") == 1
        assert C._ozel_desen_suzgec_uygun(p) == (i not in suzgecsiz)
        if i not in suzgecsiz:
            assert tek, (i, p.pattern)


def _ornek_satirlar() -> list[str]:
    satirlar: list[str] = []
    for _ad, _p, gv in GOVDELER:
        satirlar.extend(gv.splitlines())
    return satirlar


@pytest.mark.parametrize("liste_adi", ["_PARAM_USAGE_PATTERNS", "_LOCAL_VAR_USAGE_PATTERNS"])
def test_suzgecli_desen_adsiz_satirla_eslesmez(liste_adi) -> None:
    """Anlamsal denetim: süzgeçli şablonların eşleştiği her satır adı içerir.

    Satırlar 20 gövdeden; adlar gövdelerdeki Ghidra adları. Yan sınama olarak süzgeçsiz
    şablonlarda da aynı özellik tutar (``PARAM`` iki kez ama zorunlu).
    """
    satirlar = _ornek_satirlar()
    adlar = sorted({m for gv in (g[2] for g in GOVDELER)
                    for m in re.findall(r"\b(?:param_\d+|local_[0-9a-f]+|[a-z]{1,4}Var\d+)\b", gv)})
    assert len(adlar) >= 40
    eslesme = 0
    for p, _s, _c in getattr(C, liste_adi):
        if not C._ozel_desen_suzgec_uygun(p):
            continue
        for ad in adlar:
            d = re.compile(p.pattern.replace("PARAM", re.escape(ad)))
            for ln in satirlar:
                if d.search(ln):
                    eslesme += 1
                    assert ad in ln, (p.pattern, ad, ln)
    assert eslesme >= 50


@pytest.mark.parametrize("kalip,beklenen", [
    (r"PARAM", True),
    (r"\bPARAM\s*=", True),
    (r"(PARAM)", True),
    (r"(?:a(?:PARAM))", True),
    (r"(?>PARAM)", True),
    # Son karaktere uygulanan niceleyici işaret çiftini ayırır → tutucu: süzgeçsiz.
    (r"PARAM+", False),
    (r"(?:PARAM){2}", True),
    (r"PARAM?", False),
    (r"(?:PARAM)?x", False),
    (r"PARAM{0,2}", False),
    (r"(?:PARAM)*", False),
    (r"a|PARAM", False),
    (r"(?=PARAM)", False),
    (r"(?<!PARAM)x", False),
    (r"(?i)PARAM", False),
    (r"(?i:PARAM)", False),
    (r"[PARAM]", False),
    (r"PARAM\s*=\s*PARAM", False),
    (r"x", False),
    (r"(PARAM", False),
])
def test_suzgec_kosulu_yapisal(kalip, beklenen) -> None:
    assert C._param_zorunlu_tek(kalip) is beklenen


# ---------------------------------------------------------------------------
# 3. Önbellek: anahtar, hata yolu, sınır, sayaçlar
# ---------------------------------------------------------------------------


def test_anahtar_adi_icerir(temiz_onbellek) -> None:
    k = C._LOCAL_VAR_USAGE_PATTERNS[1][0]
    a = C._ozel_desen(k, "uVar1", 1000)
    b = C._ozel_desen(k, "uVar2", 1000)
    assert a.pattern != b.pattern
    assert a.search("uVar1 = malloc(8);") and not b.search("uVar1 = malloc(8);")
    once = dict(C._OZEL_DESEN_SAYAC)
    assert C._ozel_desen(k, "uVar1", 1000) is a
    assert C._OZEL_DESEN_SAYAC["isabet"] == once["isabet"] + 1
    assert C._OZEL_DESEN_SAYAC["derleme"] == once["derleme"]
    # Aynı şablon metni, aynı ad → aynı desen metni (eski yol).
    assert a.pattern == k.pattern.replace("PARAM", re.escape("uVar1"))


def test_ikinci_kosuda_derleme_yok(temiz_onbellek) -> None:
    butun_adaylar()
    once = dict(C._OZEL_DESEN_SAYAC)
    butun_adaylar()
    assert C._OZEL_DESEN_SAYAC["derleme"] == once["derleme"]
    assert C._OZEL_DESEN_SAYAC["isabet"] > once["isabet"]


class _BozukKalip:
    """Derlenemeyen şablon (yalnız ``.pattern`` okunur)."""

    pattern = "(PARAM"


def test_re_error_yerel_degisken_atlar_ve_onbellege_girer(temiz_onbellek, monkeypatch,
                                                         caplog) -> None:
    ad, prm, gv = GOVDELER[0]
    temel = _aday_listesi(ad, prm, gv)
    liste = [(_BozukKalip(), "bozuk", 0.99)] + list(C._LOCAL_VAR_USAGE_PATTERNS)
    monkeypatch.setattr(C, "_LOCAL_VAR_USAGE_PATTERNS", liste)
    once = dict(C._OZEL_DESEN_SAYAC)
    with caplog.at_level("DEBUG", logger=C.logger.name):
        bozuklu = _aday_listesi(ad, prm, gv)
    assert bozuklu == temel  # bozuk desen atlandı, kalan sonuç aynı
    hata1 = C._OZEL_DESEN_SAYAC["hata"] - once["hata"]
    assert hata1 >= 1
    assert "Local var pattern derlenemedi" in caplog.text
    # İkinci koşu: hatalar önbellekten gelir, yeniden derleme denenmez.
    ara = dict(C._OZEL_DESEN_SAYAC)
    assert _aday_listesi(ad, prm, gv) == temel
    assert C._OZEL_DESEN_SAYAC["hata"] == ara["hata"]
    # Yükselen hata eski ``re.compile``'ınkiyle aynı ileti.
    with pytest.raises(re.error) as bilgi:
        C._ozel_desen(_BozukKalip(), "uVar1", 1000)
    with pytest.raises(re.error) as eski:
        re.compile("(uVar1")
    assert str(bilgi.value) == str(eski.value)


def test_re_error_veri_akisi_yukseltir(temiz_onbellek, monkeypatch) -> None:
    """Eski ``_strategy_dataflow`` derleme hatasını yakalamıyordu: yine yükselir (iki kez)."""
    liste = list(C._PARAM_USAGE_PATTERNS) + [(_BozukKalip(), "bozuk", 0.99)]
    monkeypatch.setattr(C, "_PARAM_USAGE_PATTERNS", liste)
    ad, prm, gv = GOVDELER[0]
    for _ in range(2):
        with pytest.raises(re.error):
            _aday_listesi(ad, prm, gv)


def test_onbellek_siniri_dolunca_sonuc_ayni(temiz_onbellek) -> None:
    temel = butun_adaylar()
    C._OZEL_DESEN_ONBELLEGI.clear()
    cfg = Config()
    cfg.perf.desen_onbellegi_ust_sinir = 7
    once = dict(C._OZEL_DESEN_SAYAC)
    kucuk = butun_adaylar(cfg)
    assert kucuk == temel
    assert len(C._OZEL_DESEN_ONBELLEGI) <= 7
    assert C._OZEL_DESEN_SAYAC["temizleme"] - once["temizleme"] >= 10


def test_ust_sinir_ayardan_okunur() -> None:
    cfg = Config()
    assert C._ozel_desen_ust_siniri(cfg) == cfg.perf.desen_onbellegi_ust_sinir
    cfg.perf.desen_onbellegi_ust_sinir = 123
    assert C._ozel_desen_ust_siniri(cfg) == 123
    # Geçersiz değer / ayarsız nesne: alanın öntanımı.
    from karadul.config import PerfConfig
    assert C._ozel_desen_ust_siniri(None) == PerfConfig.desen_onbellegi_ust_sinir
    assert C._ozel_desen_ust_siniri(SimpleNamespace(perf=SimpleNamespace(
        desen_onbellegi_ust_sinir="çok"))) == PerfConfig.desen_onbellegi_ust_sinir


# ---------------------------------------------------------------------------
# 4. api_param_db: örnek başına bir kez
# ---------------------------------------------------------------------------

C_KODU = """
  iVar1 = socket(2,1,0);
  iVar2 = connect(iVar1,local_28,0x10);
  sVar3 = send(param_1,local_48,0x40,0);
  qsort(param_2,param_3,8,FUN_00104000);
  signal(2,FUN_00104100);
  pthread_create(&local_10,(pthread_attr_t *)0x0,FUN_00104200,param_1);
  SSL_CTX_set_verify(param_4,1,FUN_00104300);
  memcpy(local_48,param_2,uVar4);
"""


class _SayacRe:
    """``re`` vekili: ``compile`` çağrılarını sayar, gerisini ``re``'ye bırakır."""

    def __init__(self) -> None:
        self.derleme = 0

    def compile(self, *a, **k):
        self.derleme += 1
        return re.compile(*a, **k)

    def __getattr__(self, ad):
        return getattr(re, ad)


def _eski_propagate(db: APIParamDB, c_code: str) -> dict[str, str]:
    renames: dict[str, str] = {}
    call_re = re.compile(
        r'\b(' + '|'.join(re.escape(n) for n in sorted(db._db, key=len, reverse=True))
        + r')\s*\(([^)]*)\)'
    )
    for match in call_re.finditer(c_code):
        func_name = match.group(1)
        param_names = db._db.get(func_name)
        if not param_names:
            continue
        args = [a.strip() for a in match.group(2).split(",")]
        for arg, pname in zip(args, param_names):
            if re.match(r'^(param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+)$', arg):
                if arg not in renames:
                    renames[arg] = pname
    return renames


def test_api_propagate_bir_kez_kurar_ve_ayni_sonuc(monkeypatch) -> None:
    db = APIParamDB()
    beklenen = _eski_propagate(db, C_KODU)
    assert beklenen  # sınama boş değil
    sayac = _SayacRe()
    monkeypatch.setattr(A, "re", sayac)
    for _ in range(3):
        assert db.propagate_params(C_KODU) == beklenen
    assert sayac.derleme == 1


def test_api_reverse_bir_kez_kurar_ve_ayni_sonuc(monkeypatch) -> None:
    db = APIParamDB()
    beklenen = APIParamDB().reverse_propagate_function_names(C_KODU)
    assert len(beklenen) >= 3
    sayac = _SayacRe()
    monkeypatch.setattr(A, "re", sayac)
    for _ in range(3):
        assert db.reverse_propagate_function_names(C_KODU) == beklenen
    assert sayac.derleme == 2  # fun_re + call_start_re, ilk çağrıda


def test_api_desenleri_sifirla() -> None:
    db = APIParamDB()
    kod = "  hz7a_ozel_api(param_1,local_10);\n"
    assert db.propagate_params(kod) == {}
    db._db["hz7a_ozel_api"] = ["alfa", "beta"]
    # Saklanan desen eski sözlükle kuruldu: yeni ad görülmez (sıfırlama sözleşmesi).
    assert db.propagate_params(kod) == {}
    db._desenleri_sifirla()
    assert db.propagate_params(kod) == {"param_1": "alfa", "local_10": "beta"}
