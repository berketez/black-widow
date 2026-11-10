#!/usr/bin/env python3
"""Karadul çıktı sağlamlığı denetimi (2026-11-10).

Var olan Karadul koşularının çıktı ağaçlarını GT'siz, mekanik olarak denetler.
Yalnız okur; tek yazdığı dosya ``sonuc.json``'dur (bu betiğin yanına).

Kalemler:
  1. Tamamlanma ve rapor dürüstlüğü   (rapordaki sayılar ↔ disk)
  2. Boş ya da eksik çıktı
  3. İç tutarlılık                     (ad haritası ↔ çıktı dosyaları)
  4. C'nin biçimsel sağlamlığı         (ham Ghidra ↔ son çıktı)
  5. Sessiz hatalar                    (günlük, rapor, gizlenen uyarılar)
  6. Ölçek                             (süre ve boyut ↔ fonksiyon sayısı)
  7. Belirlenimcilik                   (aynı girdi → aynı çıktı; koşu çiftleri)

Kullanım:
    python docs/arge/2026-11-10_cikti_saglamligi/denetle.py [--is N] [--yalniz KİMLİK_ÖNEKİ]

Yasak: bu betik GT taşıyan hiçbir dosyayı açmaz (``macho_score.json``,
``downloads/`` altı, ``*.gt.json``, dSYM, ``.debug``). Adların doğru olup
olmadığını yargılamaz; yalnız bütünlüğe ve tutarlılığa bakar.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import multiprocessing
import os
import re
import sys
import time

# ---------------------------------------------------------------------------
# Yollar
# ---------------------------------------------------------------------------
BETIK_DIZINI = os.path.dirname(os.path.abspath(__file__))
DEPO = os.path.abspath(os.path.join(BETIK_DIZINI, "..", "..", ".."))
DEBIAN_KOK = os.path.expanduser("~/karadul_olcum/n1_debian13")
DEBIAN_KUNYE = os.path.join(DEBIAN_KOK, "kosu_kunyesi.json")
MAC_KOK = os.path.join(DEPO, "workspaces", "olcum_mac", "runs")
MAC_ETIKETLER = ("ol7-a-9a36142", "ol7-c-b7faeac", "ol7-d-b7faeac")
# "119 ikili" kümesine giren Mac koşusu. ol7-a (9a36142) c_namer belirlenimcilik
# düzeltmesinden (b7faeac) ÖNCE üretildi; ol7-c ve ol7-d sonra.
MAC_ANA_ETIKET = "ol7-c-b7faeac"
MAC_PROGRAMLAR = ("tmux", "htop")
SINIF_JSON = os.path.join(DEPO, "docs", "arge", "2026-10-21_g11_n1", "ks1_sinif.json")
YENIDEN_KOK = os.path.expanduser("~/karadul_olcum/runs/saglamlik-2026-11-10")
# Kalem 7: bugünkü ağaçla yeniden koşulan ikili -> saklı Debian koşusu
YENIDEN_ESLESME = {
    "tree": "debian/tree/tree",
    "true": "debian/coreutils/true",
    "redis-benchmark": "debian/redis-tools/redis-benchmark",
}
# Aynı girdinin (aynı sha256 ya da aynı ikili) iki ayrı koşusu: doğal yineleme
DOGAL_CIFTLER = (
    ("mac/ol7-c-b7faeac/tmux", "mac/ol7-d-b7faeac/tmux"),
    ("mac/ol7-c-b7faeac/htop", "mac/ol7-d-b7faeac/htop"),
    ("mac/ol7-a-9a36142/tmux", "mac/ol7-c-b7faeac/tmux"),
    ("mac/ol7-a-9a36142/htop", "mac/ol7-c-b7faeac/htop"),
    ("debian/redis-tools/redis-check-aof", "debian/redis-tools/redis-check-rdb"),
)
CIKTI_JSON = os.path.join(BETIK_DIZINI, "sonuc.json")

# ---------------------------------------------------------------------------
# Eşikler ve sabitler
# ---------------------------------------------------------------------------
BEKLENEN_DEBIAN_ELF = 117
BEKLENEN_IKILI = 119                 # 117 ELF + 2 Mach-O
VARSAYILAN_IS = 3                    # paralel işçi (işlemci başka ölçümlerde)
ORNEK_SINIRI = 5                     # kusur başına saklanan örnek sayısı
GUVEN_ESIGI = 0.7                    # config.py:472 "min_naming_confidence"
DECOMPILED_JSON_SINIRI = 500         # ghidra/headless.py: results[:500]
GHIDRA_ZAMAN_ASIMI_S = 7200          # config.py Timeouts.ghidra
TUR_ZAMAN_ASIMI_S = 600.0            # config.py pipeline_iteration_timeout
ZAMAN_ASIMI_YAKINLIK = 0.5           # sınırın bu oranını aşan "yaklaşıyor"
OLCEK_USTEL_UYARI = 1.3              # log-log eğim bunu aşarsa "doğrusal üstü"
OUT_ZORUNLU = ("report.json", "report.html", "naming_map.json",
               "dependency_graph.json", "README.md", "src")
# Son çıktıda aşama aşama hangi dizinler ayrıştırılır (sırayla)
ASAMALAR = (
    ("ham", "static/ghidra_output/decompiled"),
    ("deobf", "deobfuscated/decompiled"),
    ("struct", "reconstructed/struct_recovered"),
    ("semantik", "reconstructed/semantic_named"),
    ("aciklamali", "reconstructed/annotated"),
)
C_ANAHTAR = frozenset("""auto break case char const continue default do double
else enum extern float for goto if inline int long register restrict return
short signed sizeof static struct switch typedef union unsigned void volatile
while _Bool _Complex _Imaginary""".split())
# Ghidra'nın ve types.h'nin tip adları: fonksiyona ad olarak verilirse tip
# düzeltme adımının metin değişimine (undefined -> uint64_t) takılır
TIP_ADLARI = frozenset("""undefined undefined1 undefined2 undefined4 undefined8
byte uint ulong ushort uchar bool code word dword qword size_t ssize_t
uint8_t uint16_t uint32_t uint64_t int8_t int16_t int32_t int64_t""".split())
CAGRI_DISI = frozenset({"if", "while", "for", "switch", "return", "sizeof",
                        "do", "else", "case", "goto"})
# Etiketten önce gelirse "düşerek ulaşma" saymadığımız, dönmeyen çağrılar
DONMEYEN = ("__stack_chk_fail", "abort", "exit", "_exit", "__assert_fail",
            "__assert_rtn", "xalloc_die", "__cxa_throw", "_Unwind_Resume",
            "__builtin_unreachable", "halt_baddata")
LOG_KALIPLARI = {
    "hata": r"\b(error|errors|hata|exception|failed|failure|basarisiz|başarısız)\b",
    "uyari": r"\b(warning|warn|uyari|uyarı)\b",
    "traceback": r"Traceback \(most recent call last\)",
    "atlama": r"\b(skip|skipped|skipping|atlan\w*)\b",
    "zaman_asimi": r"\b(timeout|timed out|zaman asimi|zaman aşımı)\b",
}
YASAK_DOSYA_ADLARI = ("macho_score.json",)   # GT; asla açılmaz

# ---------------------------------------------------------------------------
# C ayrıştırma yardımcıları (hafif; derleyici değil, sözcüksel denetim)
# ---------------------------------------------------------------------------
RE_BASLIK_AD = re.compile(r"^// Function: (.*)$", re.M)
RE_BASLIK_ADRES = re.compile(r"^// Address:\s+(\S+)\s*$", re.M)
RE_DISASM = re.compile(r"^// --- DISASSEMBLY \((\d+) instructions\) ---\s*$", re.M)
RE_DISASM_SATIR = re.compile(r"^// [0-9a-fA-F]{5,}\s", re.M)
RE_SOZCUK = re.compile(
    r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)
# Karadul'un belge bloğu: "/**" satırı, " * ..." satırları, " */" satırı.
# Satır bazında tanınır; böylece içine gömülü "/* was: x */" bloğu erken
# kapatsa bile (C kuralı) ad çıkarımı için bloğun tamamı atılabilir.
RE_BELGE = re.compile(r"^/\*\*[ \t]*\n(?:[ \t]*\*(?!/).*\n)*?[ \t]*\*/[ \t]*\n", re.M)
RE_BELGE_ADRES = re.compile(r"^\s*\*\s*@address\s+(?:0x)?([0-9a-fA-F]+)\s*$", re.M)
RE_ONISLEMCI = re.compile(r"^[ \t]*#.*$", re.M)
RE_AYRAC = re.compile(r"[{}]")
RE_TANIMLAYICI = re.compile(r"[A-Za-z_]\w*")
RE_C_AD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RE_CAGRI = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
RE_DIZGI = re.compile(r"\"(?:\\.|[^\"\\\n])*\"")
RE_UYARI = re.compile(r"/\*\s*WARNING:\s*(.*?)\*/", re.S)
RE_SATIR_ICI = re.compile(r"inlined from (LAB_[0-9a-fA-F]+)")
# Decompile'ın eksik ya da kuşkulu olduğunu söyleyen Ghidra uyarıları
# (dış semboller için üretilen "Bad instruction" taslakları ve bilgilendirme
# uyarıları -- "Subroutine does not return", "Unknown calling convention",
# "Globals starting with" -- bu kümede değil)
RE_KRITIK_UYARI = re.compile(
    r"Could not recover jumptable|Too many branches|Type propagation algorithm"
    r"|Removing unreachable block|Unable to|Exceeded|Treating indirect jump"
    r"|Heritage AFTER dead removal|Restarted to delay|Inlined function"
    r"|Switch with [N\d]+ destination|Ignoring partial resolution", re.I)
RE_ALGORITMA = re.compile(r"ALGORITHM:\s*([^(*\n]+)")
RE_ALGO_SATIR = re.compile(r"^.*(?:ALGORITHM:|@algorithm).*\n?", re.M)
RE_SONEK = re.compile(r"_\d+\b")
RE_DOKUM_SIZINTI = re.compile(r"^[ \t]*\*[ \t]*@\w+", re.M)


def yorumsuz(metin: str, dizgileri_koru: bool = False) -> str:
    """Yorumları (ve istenirse dizgi içeriklerini) siler; C kurallarıyla."""
    def degistir(m: re.Match) -> str:
        s = m.group(0)
        if s.startswith("/*"):
            return "".join("\n" if c == "\n" else " " for c in s)
        if s.startswith("//"):
            return ""
        if dizgileri_koru:
            return s
        return '""' if s[0] == '"' else "' '"
    return RE_SOZCUK.sub(degistir, metin)


def bloklara_bol(metin: str) -> list[str]:
    """Dosyayı ``// Function:`` başlıklarından fonksiyon bloklarına böler."""
    bas = [m.start() for m in RE_BASLIK_AD.finditer(metin)]
    if not bas:
        return []
    bas.append(len(metin))
    return [metin[bas[i]:bas[i + 1]] for i in range(len(bas) - 1)]


def govde_araligi(kod: str):
    """İlk '{' ile eşinin konumu. (bas, son, derinlik) döner."""
    derinlik = 0
    bas = None
    for m in RE_AYRAC.finditer(kod):
        if m.group() == "{":
            if bas is None:
                bas = m.start()
            derinlik += 1
        elif bas is not None:
            derinlik -= 1
            if derinlik == 0:
                return bas, m.start(), 0
    return bas, None, derinlik


def tanim_adi(imza: str):
    """İmza metninden (ilk '{' öncesi) tanımlanan fonksiyonun adını çıkarır.

    Parametre listesi imzadaki son parantez grubudur; ad ondan hemen önceki
    sözcüktür. Böylece Ghidra'nın ``undefined1 (*) [16] f(...)`` biçimi de
    doğru okunur.
    """
    s = imza.rstrip()
    son = s.rfind(")")
    if son < 0:
        return None
    derinlik = 0
    bas = None
    for i in range(son, -1, -1):
        c = s[i]
        if c == ")":
            derinlik += 1
        elif c == "(":
            derinlik -= 1
            if derinlik == 0:
                bas = i
                break
    if bas is None:
        return None
    on = s[:bas].rstrip()
    if on.endswith("()") and on[:-2].rstrip().endswith("operator"):
        return "operator()"
    m = re.search(r"([^\s\*&()]+)$", on)
    return m.group(1) if m else None


def ust_duzey_deyim(metin: str) -> int:
    """Metindeki üst düzey deyim sayısı (ayraç ve parantez derinliği 0'da
    biten ';' ya da '}')."""
    n = ayrac = parantez = 0
    for c in metin:
        if c == "(":
            parantez += 1
        elif c == ")":
            parantez -= 1
        elif c == "{":
            ayrac += 1
        elif c == "}":
            ayrac -= 1
            if ayrac == 0 and parantez == 0:
                n += 1
        elif c == ";" and ayrac == 0 and parantez == 0:
            n += 1
    return n


def durum_bul(kod: str):
    """Fonksiyon gövdesinin sözcüksel durumu ve aralığı."""
    bas, son, _ = govde_araligi(kod)
    if bas is None:
        return "govde_yok", None, None
    if son is None:
        return "kapanmamis", bas, None
    if kod[son + 1:].strip():
        return "erken_kapanan", bas, son
    return "tam", bas, son


def blok_coz(blok: str, ayrinti: bool = False) -> dict:
    """Tek fonksiyon bloğunu çözer.

    ``kati_durum``: C kurallarıyla (iç içe yorum dahil) gövde durumu.
    ``durum``: Karadul belge bloğu satır bazında atıldıktan sonraki durum
    (ad ve sayaç çıkarımı bundan yapılır).
    """
    ad = RE_BASLIK_AD.search(blok)
    adres = RE_BASLIK_ADRES.search(blok)
    dis = RE_DISASM.search(blok)
    kod_kismi = blok[:dis.start()] if dis else blok
    s = {
        "adres": adres.group(1).lower() if adres else None,
        "baslik_ad": ad.group(1).strip() if ad else None,
        "dis_bildirilen": int(dis.group(1)) if dis else None,
        "dis_satir": len(RE_DISASM_SATIR.findall(blok[dis.end():])) if dis else None,
    }
    kati = RE_ONISLEMCI.sub("", yorumsuz(kod_kismi))
    s["belge_sizinti"] = bool(RE_DOKUM_SIZINTI.search(kati))
    s["kati_durum"] = durum_bul(kati)[0]
    belgeler = RE_BELGE.findall(kod_kismi)
    # İç içe yorum: belge bloğunun son satırından ÖNCE bir "*/" geçiyorsa C
    # kuralıyla blok orada kapanır; kalan satırlar (en azından " */") kod olur.
    s["belge_ic_ice"] = any("*/" in b.rstrip().rsplit("\n", 1)[0] for b in belgeler)
    s["belge_adres"] = None
    if belgeler:
        ma = RE_BELGE_ADRES.search(belgeler[0])
        if ma:
            s["belge_adres"] = ma.group(1).lower()
    belgesiz = RE_BELGE.sub("", kod_kismi)
    kod = RE_ONISLEMCI.sub("", yorumsuz(belgesiz))
    durum, bas, son = durum_bul(kod)
    s["durum"] = durum
    if bas is None:
        s.update(tanim=None, parantez=0, kod_satir=0, noktali=0, goto=0,
                 cagri=0, bos_govde=False)
        govde = ""
    else:
        govde = kod[bas:son + 1] if son is not None else kod[bas:]
        s["tanim"] = tanim_adi(kod[:bas])
        s["parantez"] = govde.count("(") - govde.count(")")
        s["kod_satir"] = sum(1 for satir in govde.split("\n") if satir.strip())
        s["noktali"] = govde.count(";")
        s["goto"] = len(re.findall(r"\bgoto\b", govde))
        s["cagri"] = sum(1 for x in RE_CAGRI.findall(govde) if x not in CAGRI_DISI)
        ic = govde[1:-1] if son is not None else govde[1:]
        s["bos_govde"] = ic.strip() == ""
    if ayrinti:
        s["tanimlayicilar"] = set(RE_TANIMLAYICI.findall(kod))
        dizgili = yorumsuz(belgesiz, dizgileri_koru=True)
        s["dizgiler"] = collections.Counter(RE_DIZGI.findall(dizgili))
        s["kod"] = kod
        s["kod_dizgili"] = " ".join(RE_ONISLEMCI.sub("", dizgili).split())
    return s


def oku(yol: str):
    """(metin, utf8_bozuk, nul_var, yerine_koyma_sayisi)"""
    with open(yol, "rb") as f:
        ham = f.read()
    bozuk = False
    try:
        metin = ham.decode("utf-8")
    except UnicodeDecodeError:
        bozuk = True
        metin = ham.decode("utf-8", errors="replace")
    return metin, bozuk, (b"\x00" in ham), metin.count("�")


def json_oku(yol: str):
    try:
        with open(yol, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def c_dosyalari(dizin: str, ozyineli: bool = True) -> list[str]:
    if not os.path.isdir(dizin):
        return []
    if not ozyineli:
        return sorted(os.path.join(dizin, f) for f in os.listdir(dizin)
                      if f.endswith(".c") and os.path.isfile(os.path.join(dizin, f)))
    out = []
    for dp, _dn, fs in os.walk(dizin):
        for f in fs:
            if f.endswith(".c"):
                out.append(os.path.join(dp, f))
    return sorted(out)


def dizin_boyutu(dizin: str):
    """(dosya_sayisi, bayt, sifir_baytli_yollar)"""
    n = b = 0
    sifir = []
    for dp, _dn, fs in os.walk(dizin):
        for f in fs:
            if f in YASAK_DOSYA_ADLARI:
                continue
            p = os.path.join(dp, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            n += 1
            b += st.st_size
            if st.st_size == 0:
                sifir.append(p)
    return n, b, sifir


def sha1(metin: str) -> str:
    return hashlib.sha1(metin.encode("utf-8", errors="replace")).hexdigest()


def ornek_ekle(liste: list, oge, sinir: int = ORNEK_SINIRI) -> None:
    if len(liste) < sinir:
        liste.append(oge)


# ---------------------------------------------------------------------------
# Koşuların bulunması
# ---------------------------------------------------------------------------
def siniflari_oku() -> dict:
    d = json_oku(SINIF_JSON) or {}
    return {k: v.get("boyut_tabakasi") for k, v in d.get("birimler", {}).items()}


def kosulari_bul() -> list[dict]:
    tabaka = siniflari_oku()
    kosular = []
    if os.path.isdir(DEBIAN_KOK):
        for program in sorted(os.listdir(DEBIAN_KOK)):
            pd = os.path.join(DEBIAN_KOK, program)
            if not os.path.isdir(pd):
                continue
            for elf in sorted(os.listdir(pd)):
                kd = os.path.join(pd, elf)
                if not os.path.isdir(kd):
                    continue
                kosular.append({
                    "kimlik": f"debian/{program}/{elf}", "kume": "debian",
                    "platform": "debian", "program": program, "elf": elf,
                    "kok": kd, "log": os.path.join(kd, "kosu.log"),
                    "tabaka": tabaka.get(f"debian/{program}"),
                    "ana_kume": True, "etiket": "n1_debian13",
                })
    for etiket in MAC_ETIKETLER:
        for program in MAC_PROGRAMLAR:
            kd = os.path.join(MAC_KOK, etiket, program)
            if not os.path.isdir(kd):
                continue
            kosular.append({
                "kimlik": f"mac/{etiket}/{program}", "kume": "mac",
                "platform": "mac", "program": program, "elf": program,
                "kok": kd, "log": os.path.join(kd, "karadul.log"),
                "tabaka": tabaka.get(f"mac/{program}"),
                "ana_kume": etiket == MAC_ANA_ETIKET, "etiket": etiket,
            })
    if os.path.isdir(YENIDEN_KOK):
        for ad in sorted(os.listdir(YENIDEN_KOK)):
            kd = os.path.join(YENIDEN_KOK, ad)
            if not os.path.isdir(kd) or ad not in YENIDEN_ESLESME:
                continue
            esas = YENIDEN_ESLESME[ad].split("/")
            kosular.append({
                "kimlik": f"yeniden/{ad}", "kume": "yeniden",
                "platform": "debian", "program": esas[1], "elf": ad,
                "kok": kd, "log": os.path.join(kd, "kosu.log"),
                "tabaka": tabaka.get(f"debian/{esas[1]}"),
                "ana_kume": False, "etiket": "saglamlik-2026-11-10",
            })
    return kosular


def calisma_alani(kok: str):
    """ws/workspaces/<ad>/<zaman> — tam bir tane beklenir."""
    wk = os.path.join(kok, "ws", "workspaces")
    adaylar = []
    if os.path.isdir(wk):
        for ad in sorted(os.listdir(wk)):
            d = os.path.join(wk, ad)
            if os.path.isdir(d):
                for zaman in sorted(os.listdir(d)):
                    z = os.path.join(d, zaman)
                    if os.path.isdir(z):
                        adaylar.append(z)
    return adaylar


# ---------------------------------------------------------------------------
# Aşama dizinlerinin ayrıştırılması
# ---------------------------------------------------------------------------
def dizin_coz(dizin: str, ayrinti: bool = False, ozyineli: bool = True) -> dict:
    """Dizindeki .c dosyalarını çözer.

    Dönen: {"fonk": {adres: [kayıt, ...]}, "dosya": n, "basliksiz": [...],
            "utf8_bozuk": n, "nul": n, "yerine_koyma": n, "cok_fonksiyonlu": n}
    """
    fonk: dict[str, list] = collections.defaultdict(list)
    ozet = {"dosya": 0, "basliksiz": [], "utf8_bozuk": 0, "nul": 0,
            "yerine_koyma": 0, "cok_fonksiyonlu": 0, "sifir_bayt": 0}
    for yol in c_dosyalari(dizin, ozyineli):
        ozet["dosya"] += 1
        metin, bozuk, nul, yk = oku(yol)
        ozet["utf8_bozuk"] += bozuk
        ozet["nul"] += nul
        ozet["yerine_koyma"] += (yk > 0)
        if not metin:
            ozet["sifir_bayt"] += 1
        bloklar = bloklara_bol(metin)
        if not bloklar:
            ornek_ekle(ozet["basliksiz"], yol, 50)
            continue
        if len(bloklar) > 1:
            ozet["cok_fonksiyonlu"] += 1
        for blok in bloklar:
            k = blok_coz(blok, ayrinti)
            k["yol"] = yol
            if ayrinti:
                k["metin"] = blok
            fonk[k["adres"]].append(k)
    ozet["fonk"] = fonk
    return ozet


def durum_sayimi(coz: dict) -> dict:
    c = collections.Counter()
    for _adres, kayitlar in coz["fonk"].items():
        k = kayitlar[0]
        c[k["durum"]] += 1
        if k["parantez"] != 0:
            c["parantez_dengesiz"] += 1
        if k["belge_sizinti"]:
            c["belge_sizinti"] += 1
        if k["belge_ic_ice"]:
            c["belge_ic_ice"] += 1
        if k["kati_durum"] != "tam":
            c["kati_bozuk"] += 1
    c["fonksiyon"] = len(coz["fonk"])
    return dict(c)


# ---------------------------------------------------------------------------
# Tek koşunun denetimi
# ---------------------------------------------------------------------------
def kosu_denetle(kosu: dict):
    t0 = time.time()
    s: dict = {k: kosu[k] for k in ("kimlik", "kume", "platform", "program",
                                    "elf", "tabaka", "ana_kume", "etiket", "kok")}
    kusur: dict[str, int] = collections.Counter()
    ornek: dict[str, list] = collections.defaultdict(list)
    iz: dict = {"kimlik": kosu["kimlik"]}
    s["kusur"] = kusur
    s["ornek"] = ornek

    kok = kosu["kok"]
    out = os.path.join(kok, "out")
    alanlar = calisma_alani(kok)
    s["calisma_alani_sayisi"] = len(alanlar)
    if len(alanlar) != 1:
        kusur["calisma_alani_tek_degil"] = 1
    if not alanlar:
        s["hata"] = "çalışma alanı yok"
        kusur["bitmedi"] = 1
        return dict(s, kusur=dict(kusur), ornek=dict(ornek)), iz
    ws = alanlar[-1]
    s["ws"] = ws

    k1 = s["k1"] = {}
    k2 = s["k2"] = {}
    k3 = s["k3"] = {}
    k4 = s["k4"] = {}
    k5 = s["k5"] = {}
    k6 = s["k6"] = {}

    # ---------------- K1: tamamlanma -----------------------------------
    if kosu["kume"] == "debian":
        bitti = os.path.join(kok, "BITTI")
        ic = open(bitti).read().strip() if os.path.isfile(bitti) else None
        k1["bitti"] = ic
        if not ic or not ic.startswith("ok"):
            kusur["bitmedi"] = 1
        else:
            try:
                k1["bitti_sure_s"] = float(ic.split()[1])
            except (IndexError, ValueError):
                pass
    elif kosu["kume"] == "mac":
        rj = json_oku(os.path.join(kok, "run.json")) or {}
        k1["bitti"] = f"{rj.get('status')} exit={rj.get('exit_code')}"
        k1["bitti_sure_s"] = rj.get("duration_s")
        k1["hedef_sha256"] = rj.get("target_sha256")
        if rj.get("status") != "ok" or rj.get("exit_code") != 0:
            kusur["bitmedi"] = 1
    else:
        kj = json_oku(os.path.join(kok, "kunye.json")) or {}
        k1["bitti"] = f"exit={kj.get('cikis_kodu')}"
        k1["bitti_sure_s"] = kj.get("sure_s")
        k1["kunye"] = kj
        zt = os.path.join(kok, "zaman.txt")
        if os.path.isfile(zt):
            m = re.search(r"(\d+)\s+maximum resident set size", open(zt).read())
            if m:
                k6["en_yuksek_rss_bayt"] = int(m.group(1))
        if kj.get("cikis_kodu") != 0:
            kusur["bitmedi"] = 1

    # Günlük
    log_metin = ""
    if os.path.isfile(kosu["log"]):
        log_metin = open(kosu["log"], encoding="utf-8", errors="replace").read()
    else:
        kusur["log_yok"] = 1
    log_satir = log_metin.split("\n")
    k5["log_satir"] = len(log_satir)
    lg = k1["log"] = {}
    m = re.search(r"OK (\d+) dosya yazildi \((\d+) kaynak, (\d+) rapor\)", log_metin)
    if m:
        lg["yazilan"], lg["kaynak"], lg["rapor"] = map(int, m.groups())
    else:
        kusur["log_yazildi_satiri_yok"] = 1
    for anahtar, etiket in (("fonksiyon", "Functions recovered"),
                            ("dizgi", "Strings found"),
                            ("degisken", "Variables renamed")):
        m = re.search(re.escape(etiket) + r"\s*│\s*(\S+)", log_metin)
        if m:
            try:
                lg[anahtar] = int(m.group(1))
            except ValueError:
                lg[anahtar] = m.group(1)
    lg["na_alan"] = len(re.findall(r"│\s+N/A\s", log_metin))

    # Raporlar
    rapor = json_oku(os.path.join(ws, "reports", "report.json"))
    presult = json_oku(os.path.join(ws, "reports", "pipeline_result.json"))
    out_rapor = json_oku(os.path.join(out, "report.json"))
    if rapor is None:
        kusur["rapor_yok"] = 1
        s["hata"] = "reports/report.json yok ya da bozuk"
        return dict(s, kusur=dict(kusur), ornek=dict(ornek)), iz
    hat = rapor.get("pipeline", {})
    asama = hat.get("stages", {})
    k1["rapor_basarili"] = hat.get("success")
    k1["karadul_surumu"] = rapor.get("karadul_version")
    k1["ghidra"] = (rapor.get("environment", {}).get("ghidra", {}) or {}).get("version")
    k1["hedef_hash"] = rapor.get("target", {}).get("hash")
    k1["hedef_tur"] = rapor.get("target", {}).get("type")
    k1["dil"] = (asama.get("identify", {}).get("stats", {}) or {}).get("language")
    k1["asamalar"] = {a: {"basarili": v.get("success"), "atlandi": v.get("skipped"),
                          "hata_sayisi": len(v.get("errors") or []),
                          "sure_s": v.get("duration")}
                      for a, v in asama.items()}
    if not hat.get("success"):
        kusur["rapor_basarisiz"] = 1
    for a, v in asama.items():
        if not v.get("success"):
            kusur["asama_basarisiz"] += 1
        if v.get("errors"):
            kusur["asama_hatasi"] += len(v["errors"])
            for e in v["errors"]:
                ornek_ekle(ornek["asama_hatasi"], f"{a}: {str(e)[:200]}")
    ozet_r = rapor.get("summary", {})
    if ozet_r.get("failed_stages"):
        kusur["rapor_basarisiz"] = 1
    if presult is not None and presult.get("success") != hat.get("success"):
        kusur["rapor_pipeline_result_celisiyor"] = 1
    st = asama.get("static", {}).get("stats", {}) or {}
    de = asama.get("deobfuscate", {}).get("stats", {}) or {}
    rc = asama.get("reconstruct", {}).get("stats", {}) or {}

    # ---------------- Aşama dizinleri -----------------------------------
    fj = json_oku(os.path.join(ws, "static", "ghidra_functions.json")) or {}
    fonksiyonlar = fj.get("functions", []) or []
    adres_kayit = {str(f.get("address", "")).lower(): f for f in fonksiyonlar}
    ad_adres = collections.defaultdict(list)
    for f in fonksiyonlar:
        ad_adres[f.get("name")].append(str(f.get("address", "")).lower())
    dj = json_oku(os.path.join(ws, "static", "ghidra_decompiled.json")) or {}

    coz = {}
    for kisa, goreli in ASAMALAR:
        coz[kisa] = dizin_coz(os.path.join(ws, goreli),
                              ayrinti=(kisa == "ham"),
                              ozyineli=(kisa != "struct"))
    coz["son"] = dizin_coz(out, ayrinti=True)
    ham = coz["ham"]
    son = coz["son"]
    k4["asama_durumu"] = {kisa: durum_sayimi(c) for kisa, c in coz.items()}
    k4["asama_dosya"] = {kisa: c["dosya"] for kisa, c in coz.items()}

    # ---------------- K1: sayı karşılaştırmaları ------------------------
    sayilar = k1["sayilar"] = []

    def karsilastir(ad: str, **degerler):
        d = {k: v for k, v in degerler.items()}
        gercek = [v for v in d.values() if v is not None]
        esit = len(set(gercek)) <= 1 and len(gercek) == len(d)
        sayilar.append({"ad": ad, "degerler": d, "esit": esit})
        if not esit:
            kusur["sayi:" + ad] = 1

    ham_adres = set(ham["fonk"])
    karsilastir("fonksiyon_sayisi",
                rapor_static=st.get("ghidra_function_count"),
                functions_json_total=fj.get("total"),
                functions_json_liste=len(fonksiyonlar),
                functions_json_tekil_adres=len(adres_kayit),
                rapor_ozet=ozet_r.get("total_functions"),
                log=lg.get("fonksiyon"),
                out_rapor=(out_rapor or {}).get("statistics", {}).get("functions"))
    karsilastir("decompile_sayisi",
                rapor_static=st.get("ghidra_decompiled"),
                decompiled_json_success=dj.get("success"),
                ham_c_dosya=ham["dosya"],
                ham_tekil_adres=len(ham_adres))
    k1["decompile_basarisiz"] = dj.get("failed")
    k1["decompile_atlanan"] = dj.get("skipped")
    if dj.get("failed"):
        kusur["decompile_basarisiz"] = dj["failed"]
    if dj.get("skipped"):
        kusur["decompile_atlanan"] = dj["skipped"]
    k1["decompiled_json_kayit"] = len(dj.get("functions") or [])
    if dj.get("success") and k1["decompiled_json_kayit"] < dj["success"]:
        kusur["decompiled_json_kirpik"] = dj["success"] - k1["decompiled_json_kayit"]
    karsilastir("deobf_girdi", rapor=de.get("input_files"), ham_c_dosya=ham["dosya"])
    karsilastir("deobf_cikti", rapor=de.get("output_files"), deobf_c_dosya=coz["deobf"]["dosya"])
    karsilastir("reconstruct_kaynak", rapor=rc.get("source_c_files"),
                deobf_c_dosya=coz["deobf"]["dosya"])
    karsilastir("aciklamali_dosya", rapor=rc.get("annotated_files"),
                disk=coz["aciklamali"]["dosya"])
    proje = os.path.join(ws, "reconstructed", "project")
    proje_n, _pb, _ps = dizin_boyutu(proje) if os.path.isdir(proje) else (None, 0, [])
    karsilastir("proje_dosya", rapor=rc.get("project_files"), disk=proje_n)
    out_n, out_b, out_sifir = dizin_boyutu(out) if os.path.isdir(out) else (None, 0, [])
    src_n, _sb, _ss = (dizin_boyutu(os.path.join(out, "src"))
                       if os.path.isdir(os.path.join(out, "src")) else (None, 0, []))
    karsilastir("log_yazilan_dosya", log=lg.get("yazilan"), out_disk=out_n)
    karsilastir("log_kaynak_dosya", log=lg.get("kaynak"), out_src_disk=src_n)
    # İmza eşleşmeleri
    sm = json_oku(os.path.join(ws, "reconstructed", "signature_matches.json")) or {}
    karsilastir("imza_eslesme", rapor=rc.get("signature_matches"),
                json_total=sm.get("total"), json_liste=len(sm.get("matches") or []))
    gs = json_oku(os.path.join(ws, "static", "ghidra_strings.json")) or {}
    karsilastir("dizgi_sayisi", rapor_static=st.get("ghidra_string_count"),
                json_total=gs.get("total"), json_liste=len(gs.get("strings") or []),
                rapor_ozet=ozet_r.get("total_strings"), log=lg.get("dizgi"))
    dg = json_oku(os.path.join(out, "dependency_graph.json")) or {}
    karsilastir("cagri_grafi_kenar", rapor_static=st.get("ghidra_call_graph_edges"),
                out_total=dg.get("total_edges"), out_liste=len(dg.get("edges") or []))
    karsilastir("cagri_grafi_dugum", out_total=dg.get("total_nodes"),
                out_liste=len(dg.get("nodes") or []), fonksiyon=len(fonksiyonlar))
    al = json_oku(os.path.join(ws, "reconstructed", "algorithms.json")) or {}
    karsilastir("algoritma_sayisi", rapor=rc.get("algorithms_detected"),
                json_total=al.get("total"), json_liste=len(al.get("algorithms") or []))
    # Tur sayacı
    turlar = sorted(int(m.group(1)) for k in rc
                    for m in [re.match(r"timing_c_naming_iter(\d+)$", k)] if m)
    k1["gozlenen_tur"] = len(turlar)
    k1["rapor_tur"] = rc.get("pipeline_iterations_run")
    k1["yakinsama_nedeni"] = rc.get("convergence_reason")
    karsilastir("tur_sayisi", rapor=rc.get("pipeline_iterations_run"), gozlenen=len(turlar))
    if rc.get("convergence_reason") in (None, "unknown"):
        kusur["yakinsama_nedeni_bilinmiyor"] = 1
    # İthal sayacı: rapor 0 derken Ghidra thunk/harici fonksiyon listeliyor mu
    thunk = sum(1 for f in fonksiyonlar if f.get("is_thunk"))
    k1["ghidra_thunk"] = thunk
    k1["rapor_ithal"] = ozet_r.get("total_imports")
    k1["rapor_sembol"] = st.get("symbol_count")
    if thunk > 0 and not ozet_r.get("total_imports"):
        kusur["ithal_sayaci_sifir"] = 1

    # ---------------- Ad haritaları -------------------------------------
    recon = os.path.join(ws, "reconstructed")
    tur_haritalari = []          # (tur_no, harita, köken)
    for ad in sorted(os.listdir(recon)) if os.path.isdir(recon) else []:
        m = re.match(r"src(?:_iter(\d+))?$", ad)
        if not m:
            continue
        h = json_oku(os.path.join(recon, ad, "naming_map.json"))
        kk = json_oku(os.path.join(recon, ad, "naming_provenance.json"))
        if h is not None:
            tur_haritalari.append((int(m.group(1) or 0), h, kk))
    tur_haritalari.sort(key=lambda x: x[0])
    k3["tur_haritasi_sayisi"] = len(tur_haritalari)
    out_harita_j = json_oku(os.path.join(out, "naming_map.json")) or {}
    out_harita = out_harita_j.get("mappings") or {}
    karsilastir("out_harita_toplam", bildirilen=out_harita_j.get("total_mappings"),
                liste=len(out_harita))
    ilk = tur_haritalari[0][1] if tur_haritalari else {"global": {}, "per_function": {}}
    sonh = tur_haritalari[-1][1] if tur_haritalari else ilk
    son_koken = tur_haritalari[-1][2] if tur_haritalari else None
    ilk_koken = tur_haritalari[0][2] if tur_haritalari else None

    def harita_toplam(h):
        return len(h.get("global", {})) + sum(len(v) for v in h.get("per_function", {}).values())

    karsilastir("degisken_sayisi", rapor=rc.get("variables_renamed"),
                rapor_ozet=ozet_r.get("variables_renamed"), log=lg.get("degisken"),
                son_tur_haritasi=harita_toplam(sonh) if tur_haritalari else None,
                strateji_toplami=(sum(rc["naming_by_strategy"].values())
                                  if isinstance(rc.get("naming_by_strategy"), dict) else None))
    k3["ilk_tur_harita_toplam"] = harita_toplam(ilk)
    k3["son_tur_harita_toplam"] = harita_toplam(sonh)
    # Turlar arası fark
    ig, sg = ilk.get("global", {}), sonh.get("global", {})
    k3["turlar_arasi_global_fark"] = len(set(ig.items()) ^ set(sg.items()))
    k3["turlar_arasi_fonksiyon_adi_farki"] = sum(
        1 for k in set(ig) | set(sg) if k.startswith("FUN_") and ig.get(k) != sg.get(k))
    if k3["turlar_arasi_fonksiyon_adi_farki"]:
        kusur["turlar_arasi_fonksiyon_adi_farki"] = k3["turlar_arasi_fonksiyon_adi_farki"]

    def duz(h):
        return {(f, o): n for f, v in h.get("per_function", {}).items() for o, n in v.items()}
    k3["turlar_arasi_yerel_fark"] = len(set(duz(ilk).items()) ^ set(duz(sonh).items()))

    # out haritası ↔ çalışma alanı haritası
    out_cn = {k: v.get("new_name") for k, v in out_harita.items() if v.get("source") == "c_namer"}
    k3["out_harita_kaynak"] = dict(collections.Counter(v.get("source") for v in out_harita.values()))
    k3["out_cnamer_esit_son_tur"] = out_cn == {k: v for k, v in sg.items() if v and v != k}
    k3["out_cnamer_esit_ilk_tur"] = out_cn == {k: v for k, v in ig.items() if v and v != k}
    if not (k3["out_cnamer_esit_son_tur"] or k3["out_cnamer_esit_ilk_tur"]):
        kusur["out_harita_ws_haritadan_farkli"] = 1

    # ---------------- K3: fonksiyon düzeyi ad tutarlılığı ---------------
    ham_ad = {a: (f.get("name") or "") for a, f in adres_kayit.items()}
    son_ad: dict[str, str] = {}
    son_fonk = son["fonk"]
    eksik = [a for a in adres_kayit if a not in son_fonk]
    fazla = [a for a in son_fonk if a not in adres_kayit]
    k2["out_fonksiyon"] = len(son_fonk)
    k2["out_eksik_fonksiyon"] = len(eksik)
    k2["out_fazla_adres"] = len(fazla)
    if eksik:
        kusur["out_eksik_fonksiyon"] = len(eksik)
        for a in eksik[:ORNEK_SINIRI]:
            ornek_ekle(ornek["out_eksik_fonksiyon"], f"{a} {ham_ad.get(a)}")
    cift_adres = {a: v for a, v in son_fonk.items() if len(v) > 1}
    k4["son_cift_tanimli_adres"] = len(cift_adres)
    if cift_adres:
        kusur["cift_tanim_adres"] = len(cift_adres)
        for a, v in list(cift_adres.items())[:ORNEK_SINIRI]:
            ornek_ekle(ornek["cift_tanim_adres"],
                       f"{a}: " + ", ".join(os.path.relpath(x["yol"], kok) for x in v[:3]))

    def son_kayit(adres):
        v = son_fonk.get(adres)
        return v[0] if v else None

    def taban(ad):
        return (ad or "").split("::")[-1]

    sayac = collections.Counter()
    ad_grup = collections.defaultdict(list)
    for adres, f in adres_kayit.items():
        hk = ham["fonk"].get(adres)
        sk = son_kayit(adres)
        if not hk or not sk:
            continue
        hk = hk[0]
        ham_tanim = hk["tanim"]
        son_tanim = sk["tanim"]
        son_ad[adres] = son_tanim
        ad_grup[son_tanim].append(adres)
        rn = ham_ad[adres]
        if taban(ham_tanim) != taban(rn):
            sayac["ham_tanim_ghidra_adindan_farkli"] += 1
            ornek_ekle(ornek["ham_tanim_ghidra_adindan_farkli"], f"{adres} {rn} / {ham_tanim}")
        esleme = out_harita.get(rn)
        if son_tanim != ham_tanim:
            sayac["ad_degisen_fonksiyon"] += 1
            if esleme is None:
                sayac["haritasiz_degisim"] += 1
                ornek_ekle(ornek["haritasiz_degisim"], f"{adres} {rn} -> {son_tanim}")
            elif esleme.get("new_name") != son_tanim:
                sayac["degisim_haritadan_farkli"] += 1
                ornek_ekle(ornek["degisim_haritadan_farkli"],
                           f"{adres} {rn} -> {son_tanim} (harita: {esleme.get('new_name')})")
            else:
                sayac["harita_uygulanan"] += 1
        elif esleme is not None and esleme.get("new_name") not in (rn, ham_tanim):
            kay = esleme.get("source") or "?"
            sayac["harita_uygulanmayan"] += 1
            sayac["harita_uygulanmayan:" + kay] += 1
            ornek_ekle(ornek["harita_uygulanmayan"],
                       f"{adres} {rn} -> {esleme.get('new_name')} ({kay}, güven {esleme.get('confidence')})")
        if sk["baslik_ad"] != son_tanim and taban(sk["baslik_ad"]) != taban(son_tanim):
            sayac["baslik_tanim_farkli"] += 1
            ornek_ekle(ornek["baslik_tanim_farkli"],
                       f"{os.path.relpath(sk['yol'], kok)}: başlık {sk['baslik_ad']} / tanım {son_tanim}")
        if sk["belge_adres"] and sk["belge_adres"].lstrip("0") != adres.lstrip("0"):
            sayac["belge_adres_farkli"] += 1
            ornek_ekle(ornek["belge_adres_farkli"],
                       f"{os.path.relpath(sk['yol'], kok)}: başlık {adres} / @address {sk['belge_adres']}")
    # Aynı ad iki fonksiyona
    ciftler = {ad: v for ad, v in ad_grup.items() if ad and len(v) > 1}
    sayac["son_ayni_adli_grup"] = len(ciftler)
    sayac["son_ayni_adli_fonksiyon"] = sum(len(v) for v in ciftler.values())
    yaratilan = {ad: v for ad, v in ciftler.items() if len({ham_ad[a] for a in v}) > 1}
    sayac["karadul_yarattigi_cift_ad_grup"] = len(yaratilan)
    sayac["karadul_yarattigi_cift_ad_fonksiyon"] = sum(len(v) for v in yaratilan.values())
    for ad, v in list(yaratilan.items())[:ORNEK_SINIRI]:
        ornek_ekle(ornek["karadul_yarattigi_cift_ad"],
                   f"{ad}: " + ", ".join(f"{a}({ham_ad[a]})" for a in v[:4]))
    ham_cift = sum(1 for _n, v in ad_adres.items() if len(v) > 1)
    sayac["ham_ayni_adli_grup"] = ham_cift
    # Harita içinde aynı yeni ad iki ayrı fonksiyon anahtarına
    yeni_ad_anahtar = collections.defaultdict(list)
    for kaynak_h in (sg,):
        for k, v in kaynak_h.items():
            if k.startswith(("FUN_", "thunk_")):
                yeni_ad_anahtar[v].append(k)
    hcift = {n: ks for n, ks in yeni_ad_anahtar.items() if len(ks) > 1}
    sayac["harita_ayni_ad_iki_anahtar"] = len(hcift)
    for n, ks in list(hcift.items())[:ORNEK_SINIRI]:
        ornek_ekle(ornek["harita_ayni_ad_iki_anahtar"], f"{n}: {ks[:4]}")
    # Yeni ad, ikilide zaten var olan başka bir fonksiyonun adıyla çakışıyor mu
    cakisan = [(k, v) for k, v in sg.items()
               if k.startswith("FUN_") and v in ad_adres and v != k]
    sayac["yeni_ad_var_olan_fonksiyonla_cakisiyor"] = len(cakisan)
    for k, v in cakisan[:ORNEK_SINIRI]:
        ornek_ekle(ornek["yeni_ad_var_olan_fonksiyonla_cakisiyor"], f"{k} -> {v}")
    # Geçersiz C tanımlayıcısı: (a) C anahtar sözcüğü, (b) Ghidra/C tip adı
    # (tip düzeltme adımı bu adı metin olarak değiştirir), (c) geçersiz karakter
    gecersiz = []
    for k, v in out_harita.items():
        yeni = v.get("new_name")
        tur = None
        if not isinstance(yeni, str) or not RE_C_AD.match(yeni):
            tur = "gecersiz_karakter"
        elif yeni in C_ANAHTAR:
            tur = "anahtar_sozcuk"
        elif yeni in TIP_ADLARI:
            tur = "tip_adi"
        if tur:
            gecersiz.append((k, yeni, v.get("source"), tur))
    for fad, yer in sonh.get("per_function", {}).items():
        for eski, yeni in yer.items():
            if not isinstance(yeni, str) or not RE_C_AD.match(yeni):
                gecersiz.append((f"{fad}::{eski}", yeni, "c_namer_yerel", "gecersiz_karakter"))
            elif yeni in C_ANAHTAR:
                gecersiz.append((f"{fad}::{eski}", yeni, "c_namer_yerel", "anahtar_sozcuk"))
    sayac["gecersiz_c_adi"] = len(gecersiz)
    for g in gecersiz:
        sayac["gecersiz_c_adi:" + g[3]] += 1
        ornek_ekle(ornek["gecersiz_c_adi:" + g[3]], f"{g[0]} -> {g[1]!r} ({g[2]})")
        ornek_ekle(ornek["gecersiz_c_adi"], f"{g[0]} -> {g[1]!r} ({g[2]}, {g[3]})")
    # out haritasının anahtar sınıfları
    sinif = collections.Counter()
    ozdes = 0
    yetim = []
    for k, v in out_harita.items():
        if v.get("new_name") == k:
            ozdes += 1
        if k in ad_adres:
            sinif["fonksiyon"] += 1
        elif k.startswith("DAT_"):
            sinif["veri"] += 1
        else:
            sinif["yetim"] += 1
            yetim.append(k)
    k3["out_harita_anahtar_sinifi"] = dict(sinif)
    sayac["out_harita_ozdes_esleme"] = ozdes
    sayac["yetim_anahtar"] = len(yetim)
    for y in yetim[:ORNEK_SINIRI]:
        ornek_ekle(ornek["yetim_anahtar"], f"{y} -> {out_harita[y].get('new_name')}")

    # Veri (DAT_) ve fonksiyon adlarının çıktıdaki izi
    son_tanimlayici: set = set()
    for _a, v in son_fonk.items():
        for kayit in v:
            son_tanimlayici |= kayit["tanimlayicilar"]
    ham_tanimlayici: set = set()
    for _a, v in ham["fonk"].items():
        ham_tanimlayici |= v[0]["tanimlayicilar"]
    son_yorum_metin_tanimlayici: set = set()
    for _a, v in son_fonk.items():
        for kayit in v:
            dis = RE_DISASM.search(kayit["metin"])
            govde_metni = kayit["metin"][:dis.start()] if dis else kayit["metin"]
            yorumlar = " ".join(m.group(0) for m in RE_SOZCUK.finditer(govde_metni)
                                if m.group(0).startswith(("/*", "//")))
            son_yorum_metin_tanimlayici |= set(RE_TANIMLAYICI.findall(yorumlar))
    for k, v in sg.items():
        if k.startswith("DAT_"):
            sayac["veri_esleme"] += 1
            if k not in ham_tanimlayici:
                sayac["veri_anahtari_ham_kodda_yok"] += 1
            if k in son_tanimlayici:
                sayac["veri_eski_ad_kodda_kalan"] += 1
                ornek_ekle(ornek["veri_eski_ad_kodda_kalan"], f"{k} -> {v}")
            if v not in son_tanimlayici and k in ham_tanimlayici:
                sayac["veri_yeni_ad_kodda_yok"] += 1
                ornek_ekle(ornek["veri_yeni_ad_kodda_yok"], f"{k} -> {v}")
        elif k.startswith("FUN_"):
            sayac["fonksiyon_esleme"] += 1
            if k not in ad_adres:
                sayac["fonksiyon_anahtari_ghidrada_yok"] += 1
                ornek_ekle(ornek["fonksiyon_anahtari_ghidrada_yok"], f"{k} -> {v}")
                continue
            if k in son_tanimlayici:
                sayac["eski_fonksiyon_adi_kodda_kalan"] += 1
                ornek_ekle(ornek["eski_fonksiyon_adi_kodda_kalan"], f"{k} -> {v}")
            if k in son_yorum_metin_tanimlayici:
                sayac["eski_fonksiyon_adi_yorumda_kalan"] += 1
                ornek_ekle(ornek["eski_fonksiyon_adi_yorumda_kalan"], f"{k} -> {v}")

    # Yerel adlar: ilk tur ve son tur haritası ↔ çıktı
    def yerel_denetle(h, etiket):
        c = collections.Counter()
        for fad, yer in h.get("per_function", {}).items():
            adresler = ad_adres.get(fad)
            if not adresler:
                c["fonksiyon_anahtari_yok"] += 1
                continue
            uygun = [a for a in adresler
                     if a in ham["fonk"] and a in son_fonk
                     and any(o in ham["fonk"][a][0]["tanimlayicilar"] for o in yer)]
            if not uygun:
                c["anahtar_ham_kodda_yok"] += 1
                continue
            en_iyi = None
            for a in uygun:
                ht = ham["fonk"][a][0]["tanimlayicilar"]
                st_ = son_fonk[a][0]["tanimlayicilar"]
                eski_kalan = [o for o in yer if o in ht and o in st_]
                yeni_yok = [(o, n) for o, n in yer.items() if o in ht and n not in st_]
                puan = (len(eski_kalan), len(yeni_yok))
                if en_iyi is None or puan < en_iyi[0]:
                    en_iyi = (puan, a, eski_kalan, yeni_yok)
            _p, a, eski_kalan, yeni_yok = en_iyi
            c["fonksiyon"] += 1
            c["esleme"] += len(yer)
            # eski ad gitmiş ama haritadaki yeni ad da yok: çıktıda başka ad var
            baska = [(o, n) for o, n in yeni_yok if o not in eski_kalan]
            if baska:
                c["baska_adla_fonksiyon"] += 1
                c["baska_adla_esleme"] += len(baska)
                ornek_ekle(ornek[f"yerel_baska_adla:{etiket}"], f"{fad}@{a}: {baska[:3]}")
            if eski_kalan:
                c["eski_ad_kalan_fonksiyon"] += 1
                c["eski_ad_kalan_esleme"] += len(eski_kalan)
                ornek_ekle(ornek[f"yerel_eski_ad_kalan:{etiket}"], f"{fad}@{a}: {eski_kalan[:3]}")
            if yeni_yok:
                c["yeni_ad_yok_fonksiyon"] += 1
                c["yeni_ad_yok_esleme"] += len(yeni_yok)
                ornek_ekle(ornek[f"yerel_yeni_ad_yok:{etiket}"], f"{fad}@{a}: {yeni_yok[:3]}")
        return dict(c)

    k3["yerel_ilk_tur"] = yerel_denetle(ilk, "ilk_tur")
    k3["yerel_son_tur"] = (yerel_denetle(sonh, "son_tur")
                           if len(tur_haritalari) > 1 else dict(k3["yerel_ilk_tur"]))
    # ilk tur haritası: eski ad çıktıda duruyor -> harita "değişti" diyor, çıktı değişmemiş
    sayac["yerel_ad_uygulanmamis_fonksiyon"] = k3["yerel_ilk_tur"].get("eski_ad_kalan_fonksiyon", 0)
    sayac["yerel_ad_uygulanmamis_esleme"] = k3["yerel_ilk_tur"].get("eski_ad_kalan_esleme", 0)
    sayac["yerel_ilk_tur_baska_adla_fonksiyon"] = k3["yerel_ilk_tur"].get("baska_adla_fonksiyon", 0)
    sayac["yerel_ilk_tur_baska_adla_esleme"] = k3["yerel_ilk_tur"].get("baska_adla_esleme", 0)
    # son tur haritası (raporun saydığı ve artifacts.named_sources'ın gösterdiği):
    # çıktıdaki ad haritadakinden farklı
    sayac["yerel_son_tur_baska_adla_fonksiyon"] = k3["yerel_son_tur"].get("baska_adla_fonksiyon", 0)
    sayac["yerel_son_tur_baska_adla_esleme"] = k3["yerel_son_tur"].get("baska_adla_esleme", 0)

    # Köken ↔ harita; güven
    def koken_ozeti(h, kk):
        if not kk:
            return None
        g = kk.get("global", {}) or {}
        guven = [v.get("confidence") for v in g.values() if isinstance(v.get("confidence"), (int, float))]
        fn = [v.get("confidence") for k, v in g.items()
              if k.startswith("FUN_") and isinstance(v.get("confidence"), (int, float))]
        return {
            "global_esleme": len(g),
            "harita_anahtar_esit": set(g) == set(h.get("global", {})),
            "ad_esit": all(g[k].get("new_name") == v for k, v in h.get("global", {}).items() if k in g),
            "guven_1den_dusuk": sum(1 for x in guven if x < 1.0),
            "guven_esik_alti": sum(1 for x in guven if x < GUVEN_ESIGI),
            "fonksiyon_adi": len(fn),
            "fonksiyon_adi_esik_alti": sum(1 for x in fn if x < GUVEN_ESIGI),
            "fonksiyon_adi_en_dusuk_guven": min(fn) if fn else None,
            "guven_dagilimi": dict(collections.Counter(str(round(x, 2)) for x in guven)),
        }
    k3["koken_son_tur"] = koken_ozeti(sonh, son_koken)
    k3["koken_ilk_tur"] = koken_ozeti(ilk, ilk_koken)
    out_cn_guven = [v.get("confidence") for v in out_harita.values() if v.get("source") == "c_namer"]
    k3["out_cnamer_esleme"] = len(out_cn_guven)
    k3["out_cnamer_guven_1"] = sum(1 for x in out_cn_guven if x == 1.0)
    if k3["koken_son_tur"]:
        if not k3["koken_son_tur"]["harita_anahtar_esit"] or not k3["koken_son_tur"]["ad_esit"]:
            kusur["koken_harita_uyusmuyor"] = 1
        if k3["out_cnamer_guven_1"]:
            sayac["guven_1_yazilan_koken_dusuk"] = k3["koken_son_tur"]["guven_1den_dusuk"]
            sayac["guven_1_yazilan_koken_esik_alti"] = k3["koken_son_tur"]["guven_esik_alti"]
    else:
        kusur["koken_dosyasi_yok"] = 1
    k3["sayac"] = dict(sayac)
    for ad in ("haritasiz_degisim", "degisim_haritadan_farkli", "harita_uygulanmayan",
               "baslik_tanim_farkli", "belge_adres_farkli",
               "karadul_yarattigi_cift_ad_grup", "harita_ayni_ad_iki_anahtar",
               "yeni_ad_var_olan_fonksiyonla_cakisiyor", "gecersiz_c_adi",
               "gecersiz_c_adi:anahtar_sozcuk", "gecersiz_c_adi:tip_adi",
               "gecersiz_c_adi:gecersiz_karakter",
               "yetim_anahtar", "veri_eski_ad_kodda_kalan", "veri_yeni_ad_kodda_yok",
               "fonksiyon_anahtari_ghidrada_yok", "eski_fonksiyon_adi_kodda_kalan",
               "eski_fonksiyon_adi_yorumda_kalan",
               "yerel_ad_uygulanmamis_fonksiyon", "yerel_ilk_tur_baska_adla_fonksiyon",
               "yerel_son_tur_baska_adla_fonksiyon", "out_harita_ozdes_esleme",
               "guven_1_yazilan_koken_dusuk", "guven_1_yazilan_koken_esik_alti"):
        if sayac.get(ad):
            kusur[ad] = sayac[ad]

    # ---------------- K2: boş ya da eksik çıktı -------------------------
    k2["out_var"] = os.path.isdir(out)
    k2["out_dosya"] = out_n
    k2["out_bayt"] = out_b
    k2["out_c_dosya"] = son["dosya"]
    k2["out_sifir_bayt"] = len(out_sifir)
    eksik_zorunlu = [z for z in OUT_ZORUNLU if not os.path.exists(os.path.join(out, z))]
    k2["out_eksik_zorunlu"] = eksik_zorunlu
    if not k2["out_var"]:
        kusur["out_yok"] = 1
    if eksik_zorunlu:
        kusur["out_eksik_zorunlu"] = len(eksik_zorunlu)
    if son["dosya"] == 0:
        kusur["out_kaynak_yok"] = 1
    if out_sifir:
        kusur["out_sifir_bayt_dosya"] = len(out_sifir)
        for p in out_sifir[:ORNEK_SINIRI]:
            ornek_ekle(ornek["out_sifir_bayt_dosya"], os.path.relpath(p, kok))
    ws_sifir = []
    for alt in ("static", "deobfuscated", "reconstructed", "reports"):
        _n, _b, sf = dizin_boyutu(os.path.join(ws, alt))
        ws_sifir.extend(sf)
        k6[f"ws_{alt}_bayt"] = _b
    k2["ws_sifir_bayt"] = len(ws_sifir)
    if ws_sifir:
        kusur["ws_sifir_bayt_dosya"] = len(ws_sifir)
        for p in ws_sifir[:ORNEK_SINIRI]:
            ornek_ekle(ornek["ws_sifir_bayt_dosya"], os.path.relpath(p, kok))
    # out/src ↔ reconstructed/project
    yerlesim = "yok"
    if os.path.isdir(os.path.join(out, "src", "src")):
        yerlesim = "proje (src/src/subsystem_*)"
    elif os.path.isdir(os.path.join(out, "src")):
        yerlesim = "düz (src/*.c)"
    k2["out_yerlesim"] = yerlesim
    proje_esit = None
    if os.path.isdir(proje) and os.path.isdir(os.path.join(out, "src")):
        def agac(d):
            a = {}
            for dp, _dn, fs in os.walk(d):
                for f in fs:
                    p = os.path.join(dp, f)
                    with open(p, "rb") as fh:
                        a[os.path.relpath(p, d)] = hashlib.sha1(fh.read()).hexdigest()
            return a
        pa, oa = agac(proje), agac(os.path.join(out, "src"))
        proje_esit = pa == oa
        k2["out_proje_yalniz_out"] = len(set(oa) - set(pa))
        k2["out_proje_yalniz_proje"] = len(set(pa) - set(oa))
        k2["out_proje_icerik_farkli"] = sum(1 for k in set(pa) & set(oa) if pa[k] != oa[k])
    k2["out_proje_ile_ayni"] = proje_esit
    if proje_esit is False:
        kusur["out_proje_agacindan_farkli"] = 1
    # README
    readme = ""
    rp = os.path.join(out, "README.md")
    if os.path.isfile(rp):
        readme = open(rp, encoding="utf-8", errors="replace").read()
    rd = k1["readme"] = {}
    for anahtar, etiket in (("durum", "Status"), ("kaynak_dosya", "Source Files"),
                            ("kurtarilan_ad", "Names Recovered"), ("dil", "Language")):
        m = re.search(r"\|\s*" + re.escape(etiket) + r"\s*\|\s*([^|]+?)\s*\|", readme)
        if m:
            rd[anahtar] = m.group(1)
    try:
        karsilastir("readme_kaynak_dosya", readme=int(rd.get("kaynak_dosya", "x")), out_src_disk=src_n)
    except ValueError:
        pass
    k1["ad_degisen_fonksiyon"] = sayac.get("ad_degisen_fonksiyon", 0)
    k1["readme_kurtarilan_ad"] = rd.get("kurtarilan_ad")
    yapi_var = all(os.path.exists(os.path.join(out, "src", p)) for p in ("main.c", "modules", "types"))
    k2["readme_yapisi_diskte"] = yapi_var
    if readme and not yapi_var:
        kusur["readme_yapi_uyusmuyor"] = 1
    if rd.get("durum") == "SUCCESS" and (son["dosya"] == 0 or eksik):
        kusur["basarili_ama_eksik_cikti"] = 1

    # ---------------- K4: biçimsel sağlamlık ve kod kaybı ---------------
    ham_d, son_d = k4["asama_durumu"]["ham"], k4["asama_durumu"]["son"]
    k4["ham_bozuk"] = ham_d.get("fonksiyon", 0) - ham_d.get("tam", 0)
    if k4["ham_bozuk"]:
        kusur["ham_bozuk_govde"] = k4["ham_bozuk"]
    bozuk_son = []
    ilk_bozulan = collections.Counter()
    kayip = collections.Counter()
    for adres in adres_kayit:
        hk = ham["fonk"].get(adres)
        sk = son_kayit(adres)
        if not hk or not sk:
            continue
        hk = hk[0]
        soz_bozuk = sk["durum"] != "tam" or sk["parantez"] != 0
        if soz_bozuk:
            bozuk_son.append(adres)
            kayip["bozuk:" + (sk["durum"] if sk["durum"] != "tam" else "parantez")] += 1
            for kisa, _g in ASAMALAR:
                ak = coz[kisa]["fonk"].get(adres)
                if ak and (ak[0]["durum"] != "tam" or ak[0]["parantez"] != 0):
                    ilk_bozulan[kisa] += 1
                    break
            else:
                ilk_bozulan["son"] += 1
            ornek_ekle(ornek["bozuk_govde"],
                       f"{os.path.relpath(sk['yol'], kok)} ({sk['durum']}, parantez {sk['parantez']:+d}; "
                       f"ham kod satırı {hk['kod_satir']} → son {sk['kod_satir']})")
        if sk["bos_govde"] and not hk["bos_govde"]:
            kayip["govde_bosalan"] += 1
        dc = sk["cagri"] - hk["cagri"]
        dn = (sk["noktali"] - sk["goto"]) - (hk["noktali"] - hk["goto"])
        if dc < 0:
            kayip["cagri_azalan_fonksiyon"] += 1
            kayip["cagri_azalan_toplam"] += -dc
            if not soz_bozuk:
                kayip["cagri_azalan_sozdizimi_saglam"] += 1
                ornek_ekle(ornek["cagri_azalan_sozdizimi_saglam"],
                           f"{os.path.relpath(sk['yol'], kok)}: çağrı {hk['cagri']} → {sk['cagri']}")
        if dn < 0:
            kayip["deyim_azalan_fonksiyon"] += 1
            if not soz_bozuk:
                kayip["deyim_azalan_sozdizimi_saglam"] += 1
        eksik_dizgi = hk["dizgiler"] - sk["dizgiler"]
        if eksik_dizgi:
            kayip["dizgi_kaybeden_fonksiyon"] += 1
            kayip["kaybolan_dizgi"] += sum(eksik_dizgi.values())
            if any("undefined" in x for x in eksik_dizgi):
                kayip["dizgi_ici_undefined_degisen_fonksiyon"] += 1
                ornek_ekle(ornek["dizgi_ici_undefined_degisen_fonksiyon"],
                           f"{os.path.relpath(sk['yol'], kok)}: {[x for x in eksik_dizgi if 'undefined' in x][:2]}")
            if not soz_bozuk:
                kayip["dizgi_kaybeden_sozdizimi_saglam"] += 1
                ornek_ekle(ornek["dizgi_kaybeden_sozdizimi_saglam"],
                           f"{os.path.relpath(sk['yol'], kok)}: {list(eksik_dizgi)[:2]}")
        kayip["ham_kod_satiri"] += hk["kod_satir"]
        if hk["goto"]:
            kayip["ham_goto_iceren_fonksiyon"] += 1   # akış sadeleştirmenin dokunabileceği küme
        kayip["son_kod_satiri"] += sk["kod_satir"]
        if sk["kod_satir"] < hk["kod_satir"]:
            kayip["satiri_azalan_fonksiyon"] += 1
            kayip["azalan_satir"] += hk["kod_satir"] - sk["kod_satir"]
        if sk["dis_bildirilen"] is not None and hk["dis_satir"] is not None \
                and sk["dis_satir"] != hk["dis_satir"]:
            kayip["disasm_satiri_degisen"] += 1
        # Akış sadeleştirme (c_flow_simplifier) izleri. Çıktıdaki
        # "inlined from LAB_x" yorumu, o etiketin bloğunun goto yerine
        # kopyalandığını ve etiketin silindiğini gösterir. İki anlam hatası
        # ham koddan mekanik olarak sınanır:
        #  (a) düşerek ulaşılan etiket: etiketten önceki deyim atlama değilse
        #      blok o yol için de gerekliydi; silinince o yol bloğu kaybeder;
        #  (b) ayraçsız koşul: "if (k) goto L;" tek deyimdi; yerine çok deyimli
        #      blok ayraçsız konunca yalnız ilk deyim koşullu kalır.
        anlam_bozuk = False
        anlam_ihtiyatli = False   # yalnız en az tartışmalı kanıtla
        for etiket in set(RE_SATIR_ICI.findall(sk["metin"])):
            kayip["satir_icine_alinan_etiket"] += 1
            hs = hk["kod"].split("\n")
            etiket_satiri = None
            for i, satir in enumerate(hs):
                if re.match(r"^\s*" + re.escape(etiket) + r"\s*:", satir):
                    etiket_satiri = i
                    break
            if etiket_satiri is None:
                continue
            # bloğun deyim satırı sayısı (simplifier'ın kuralıyla: ilk
            # return/break/goto satırına kadar boş olmayan satırlar)
            blok_satirlari = []
            for satir in hs[etiket_satiri + 1:]:
                b = satir.strip()
                if not b:
                    continue
                blok_satirlari.append(b)
                if b.startswith(("return ", "break;", "goto ")) or b == "return;":
                    break
            blok_satir = ust_duzey_deyim(" ".join(blok_satirlari))
            j = etiket_satiri - 1
            while j >= 0 and not hs[j].strip():
                j -= 1
            onceki = hs[j].strip() if j >= 0 else ""
            atlama = re.match(r"^(goto\s+\w+|return\b[^;]*|break|continue)\s*;$", onceki)
            donmez = any(onceki.startswith(d + "(") for d in DONMEYEN)
            if not atlama and not donmez:
                kayip["dusmeli_etiket_satir_icine_alindi"] += 1
                if etiket + ":" not in sk["kod"]:
                    kayip["dusmeli_etiket_silindi"] += 1
                    anlam_bozuk = True
                    # ihtiyatlı alt küme: etiketten hemen önce düz bir deyim
                    # (';' ile biten) ya da blok başı ('{') var; '}' ile biten
                    # durumlar (iki kolu da dönen if/else olabilir) sayılmaz
                    if onceki.endswith((";", "{")):
                        kayip["dusmeli_etiket_silindi_ihtiyatli"] += 1
                        anlam_ihtiyatli = True
                    ornek_ekle(ornek["dusmeli_etiket_silindi"],
                               f"{os.path.relpath(sk['yol'], kok)}: {etiket} (önceki satır: {onceki[:60]!r})")
            if blok_satir >= 2:
                # son çıktıda da görülüyor mu: gömülen bloğun yorumundan hemen
                # önce (araya yalnız yorum satırı girebilir) koşulun ')' ya da
                # 'else' geliyor, '{' gelmiyor
                sonda = re.search(
                    r"(?:\)|\belse)[ \t]*\n(?:[ \t]*(?:/\*[^\n]*\*/|//[^\n]*)[ \t]*\n)*?"
                    r"[ \t]*/\* (?:error )?cleanup \(inlined from " + re.escape(etiket) + r"\) \*/",
                    sk["metin"])
                if sonda:
                    kayip["ayracsiz_kosula_blok_sonda_gorulen"] += 1
                    anlam_ihtiyatli = True
                for satir in hs:
                    b = satir.strip()
                    if re.search(r"\bgoto\s+" + re.escape(etiket) + r"\s*;", b) and not b.startswith("goto"):
                        kayip["ayracsiz_kosula_blok_gomuldu"] += 1
                        anlam_bozuk = True
                        ornek_ekle(ornek["ayracsiz_kosula_blok_gomuldu"],
                                   f"{os.path.relpath(sk['yol'], kok)}: {etiket} (ham: {b[:70]!r}; blok {blok_satir} deyim)")
        if anlam_bozuk:
            kayip["akis_anlami_bozulan_fonksiyon"] += 1
        if anlam_ihtiyatli:
            kayip["akis_anlami_bozulan_fonksiyon_ihtiyatli"] += 1
        if anlam_bozuk or soz_bozuk:
            kayip["akis_sadelestirmenin_bozdugu_fonksiyon"] += 1
        if anlam_ihtiyatli or soz_bozuk:
            kayip["akis_sadelestirmenin_bozdugu_fonksiyon_ihtiyatli"] += 1
    k4["son_bozuk"] = len(bozuk_son)
    k4["ilk_bozulan_asama"] = dict(ilk_bozulan)
    k4["kayip"] = dict(kayip)
    if bozuk_son:
        kusur["bozuk_govde"] = len(bozuk_son)
    for ad in ("govde_bosalan", "cagri_azalan_fonksiyon", "cagri_azalan_sozdizimi_saglam",
               "dizgi_kaybeden_fonksiyon", "dizgi_kaybeden_sozdizimi_saglam",
               "dizgi_ici_undefined_degisen_fonksiyon",
               "deyim_azalan_sozdizimi_saglam", "dusmeli_etiket_silindi",
               "ayracsiz_kosula_blok_gomuldu", "ayracsiz_kosula_blok_sonda_gorulen",
               "dusmeli_etiket_silindi_ihtiyatli", "akis_anlami_bozulan_fonksiyon",
               "akis_anlami_bozulan_fonksiyon_ihtiyatli",
               "akis_sadelestirmenin_bozdugu_fonksiyon",
               "akis_sadelestirmenin_bozdugu_fonksiyon_ihtiyatli", "disasm_satiri_degisen"):
        if kayip.get(ad):
            kusur[ad] = kayip[ad]
    k4["son_ic_ice_yorum"] = son_d.get("belge_ic_ice", 0)
    # alt küme: bloğun kalanında "@etiket" satırı da koda sızıyor
    k4["son_ic_ice_yorum_etiket_sizan"] = son_d.get("belge_sizinti", 0)
    if k4["son_ic_ice_yorum"]:
        kusur["ic_ice_yorum"] = k4["son_ic_ice_yorum"]
        for _a, v in son_fonk.items():
            if v[0]["belge_ic_ice"]:
                ornek_ekle(ornek["ic_ice_yorum"], os.path.relpath(v[0]["yol"], kok))
    k4["son_bos_govde"] = sum(1 for v in son_fonk.values() if v[0]["bos_govde"])
    k4["ham_bos_govde"] = sum(1 for v in ham["fonk"].values() if v[0]["bos_govde"])
    k4["son_basliksiz_c"] = len(son["basliksiz"])
    k4["son_cok_fonksiyonlu_dosya"] = son["cok_fonksiyonlu"]
    for kisa, c in coz.items():
        if c["utf8_bozuk"] or c["nul"]:
            kusur[f"kodlama_bozuk:{kisa}"] = c["utf8_bozuk"] + c["nul"]
    k4["kodlama"] = {kisa: {"utf8_bozuk": c["utf8_bozuk"], "nul": c["nul"],
                            "yerine_koyma_karakterli": c["yerine_koyma"]}
                     for kisa, c in coz.items()}
    if son["basliksiz"]:
        kusur["basliksiz_c_dosyasi"] = len(son["basliksiz"])
        for p in son["basliksiz"][:ORNEK_SINIRI]:
            ornek_ekle(ornek["basliksiz_c_dosyasi"], os.path.relpath(p, kok))

    # Ghidra uyarıları: ham ↔ son (gizlenen uyarı), kripto etiketleri
    def uyari_say(coz_):
        c = collections.Counter()
        fn = 0
        for _a, v in coz_["fonk"].items():
            metin = v[0]["metin"]
            dis = RE_DISASM.search(metin)
            bul = RE_UYARI.findall(metin[:dis.start()] if dis else metin)
            if bul:
                fn += 1
            for u in bul:
                u = " ".join(u.split())
                u = re.sub(r"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{6,}\b|\d+", "N", u)
                c[u[:70]] += 1
        return c, fn
    hu, hu_fn = uyari_say(ham)
    su, su_fn = uyari_say(son)
    k5["ghidra_uyari_ham"] = sum(hu.values())
    k5["ghidra_uyari_son"] = sum(su.values())
    k5["ghidra_uyarili_fonksiyon_ham"] = hu_fn
    k5["ghidra_uyarili_fonksiyon_son"] = su_fn
    k5["ghidra_uyari_turleri_ham"] = dict(hu.most_common(12))
    k5["ghidra_uyari_turleri_son"] = dict(su.most_common(12))
    if hu_fn > su_fn:
        kusur["ghidra_uyarisi_gizlenen_fonksiyon"] = hu_fn - su_fn
    kritik_ham = sum(v for u, v in hu.items() if RE_KRITIK_UYARI.search(u))
    kritik_son = sum(v for u, v in su.items() if RE_KRITIK_UYARI.search(u))
    k5["ghidra_kritik_uyari_ham"] = kritik_ham
    k5["ghidra_kritik_uyari_son"] = kritik_son
    k5["ghidra_uyari_turleri_ham_tam"] = dict(hu)
    if kritik_ham > kritik_son:
        kusur["ghidra_kritik_uyarisi_gizlenen"] = kritik_ham - kritik_son
    k5["halt_baddata_ham"] = sum(1 for v in ham["fonk"].values() if "halt_baddata" in v[0]["tanimlayicilar"])
    k5["halt_baddata_son"] = sum(1 for v in son_fonk.values() if "halt_baddata" in v[0]["tanimlayicilar"])
    algo = collections.Counter()
    algo_fn = 0
    for _a, v in son_fonk.items():
        bul = RE_ALGORITMA.findall(v[0]["metin"])
        if bul:
            algo_fn += 1
        for x in bul:
            algo[x.strip()] += 1
    k5["algoritma_etiketi"] = sum(algo.values())
    k5["algoritma_etiketli_fonksiyon"] = algo_fn
    k5["algoritma_etiketi_turleri"] = dict(algo.most_common(8))
    k5["rapor_algoritma"] = rc.get("algorithms_detected")
    k5["rapor_algoritma_kategori"] = rc.get("algorithms_by_category")

    # ---------------- K5: günlük ve rapor ------------------------------
    kalip = collections.Counter()
    ileti = collections.Counter()
    try:
        a = next(i for i, l in enumerate(log_satir) if "Pipeline" in l and "──" in l)
        b = next(i for i, l in enumerate(log_satir) if l.strip() == "Results")
        govde_log = [l for l in log_satir[a + 1:b] if l.strip()]
    except StopIteration:
        govde_log = []
        kusur["log_yapisi_beklenmedik"] = 1
    for l in log_satir:
        for ad, desen in LOG_KALIPLARI.items():
            if re.search(desen, l, re.I):
                kalip[ad] += 1
    for l in govde_log:
        ileti[re.sub(r"\d+(\.\d+)*", "N", l.strip())[:160]] += 1
    k5["log_kalip"] = dict(kalip)
    k5["log_ileti"] = dict(ileti)
    k5["bsim_yedege_dustu"] = any("BSim native ingest basarisiz" in l for l in govde_log)
    k5["ag_denemesi"] = any("ReferencePopulator" in l or "Auto-populate" in l for l in govde_log)
    if k5["ag_denemesi"]:
        kusur["ag_indirme_denemesi"] = 1
    if k5["bsim_yedege_dustu"]:
        kusur["bsim_yedege_dustu"] = 1
    k5["durum_alanlari"] = {k: v for k, v in rc.items() if k.endswith("_status")}
    k5["refdiff"] = rc.get("refdiff_detections")
    k5["refdiff_sure_s"] = rc.get("timing_reference_differ_iter0")
    k5["yara"] = st.get("detected_tech")
    k5["anti_debug_toplam"] = rc.get("anti_debug_total")
    k5["anti_debug_ust_teknik"] = rc.get("anti_debug_top_technique")
    k5["packer_toplam"] = rc.get("packer_total")
    ir = json_oku(os.path.join(ws, "static", "intelligence_report.json")) or {}
    mim = ir.get("architecture", {}) or {}
    k5["zeka_algoritma"] = [x.get("name") for x in mim.get("algorithms", []) or []]
    k5["zeka_protokol"] = [x.get("name") for x in mim.get("protocols", []) or []]

    # ---------------- K6: ölçek ----------------------------------------
    k6["fonksiyon"] = len(fonksiyonlar)
    k6["ikili_bayt"] = rapor.get("target", {}).get("size")
    k6["ham_c_bayt"] = sum(len(v[0]["metin"]) for v in ham["fonk"].values())
    k6["ham_kod_satiri"] = kayip.get("ham_kod_satiri", 0)
    k6["toplam_sure_s"] = hat.get("total_duration")
    k6["asama_sure_s"] = {a: v.get("duration") for a, v in asama.items()}
    k6["ghidra_sure_s"] = st.get("ghidra_duration")
    k6["geri_besleme_sure_s"] = rc.get("feedback_loop_duration_s")
    k6["adim_sure_s"] = {k: v for k, v in rc.items()
                         if k.endswith("_duration_s") and isinstance(v, (int, float))}
    k6["out_bayt"] = out_b
    k6["out_dosya"] = out_n
    tur_sure = {}
    for t in turlar:
        tur_sure[t] = round(sum(v for k, v in rc.items()
                                if k.startswith("timing_") and k.endswith(f"_iter{t}")
                                and isinstance(v, (int, float))), 1)
    k6["tur_sure_s"] = tur_sure
    if tur_sure and max(tur_sure.values()) > TUR_ZAMAN_ASIMI_S * ZAMAN_ASIMI_YAKINLIK:
        kusur["tur_zaman_asimina_yaklasan"] = 1
    if (asama.get("static", {}).get("duration") or 0) > GHIDRA_ZAMAN_ASIMI_S * ZAMAN_ASIMI_YAKINLIK:
        kusur["ghidra_zaman_asimina_yaklasan"] = 1

    # ---------------- Parmak izi (çift karşılaştırmaları için) ----------
    iz_fonk = {}
    for adres, v in son_fonk.items():
        k = v[0]
        metin = k["metin"]
        iz_fonk[adres] = (k["tanim"], sha1(metin), sha1(RE_ALGO_SATIR.sub("", metin)),
                          os.path.relpath(k["yol"], out),
                          sha1(k["kod_dizgili"]),                       # yorumsuz kod
                          sha1(RE_SONEK.sub("_N", k["kod_dizgili"])))   # + çakışma soneki hariç
    iz.update({
        "fonk": iz_fonk,
        "ham": {a: sha1(v[0]["metin"]) for a, v in ham["fonk"].items()},
        "out_harita": {k: (v.get("new_name"), v.get("source"), v.get("confidence"))
                       for k, v in out_harita.items()},
        "ilk_tur_global": dict(ig),
        "ilk_tur_yerel": {f"{f}::{o}": n for (f, o), n in duz(ilk).items()},
        "out_dosyalar": sorted(os.path.relpath(os.path.join(dp, f), out)
                               for dp, _dn, fs in os.walk(out) for f in fs),
        "rapor_sayac": {f"{a}.{k}": v for a, d in (("static", st), ("deobfuscate", de), ("reconstruct", rc))
                        for k, v in d.items()
                        if not (k.startswith("timing_") or k.endswith("_duration_s")
                                or k.endswith("_seconds") or k.endswith("_ms")
                                or k in ("ghidra_duration", "flirt_signature_sources",
                                         "pipeline_iteration_details"))},
        "hedef_hash": k1["hedef_hash"],
    })
    s["denetim_suresi_s"] = round(time.time() - t0, 1)
    s["kusur"] = dict(kusur)
    s["ornek"] = {k: v for k, v in ornek.items()}
    return s, iz


def kosu_denetle_guvenli(kosu):
    try:
        return kosu_denetle(kosu)
    except Exception as exc:  # denetçinin kendi hatası: gizleme, kaydet
        import traceback
        return ({"kimlik": kosu["kimlik"], "kume": kosu["kume"], "program": kosu["program"],
                 "elf": kosu["elf"], "tabaka": kosu["tabaka"], "ana_kume": kosu["ana_kume"],
                 "etiket": kosu["etiket"], "platform": kosu["platform"],
                 "denetci_hatasi": f"{type(exc).__name__}: {exc}",
                 "iz": traceback.format_exc()[-1500:], "kusur": {"denetci_hatasi": 1},
                 "ornek": {}}, {"kimlik": kosu["kimlik"]})


# ---------------------------------------------------------------------------
# Çift karşılaştırması (belirlenimcilik)
# ---------------------------------------------------------------------------
def cift_karsilastir(a: dict, b: dict) -> dict:
    """Aynı girdinin iki koşusu: adlar, fonksiyon metinleri, yerleşim."""
    s = {"a": a.get("kimlik"), "b": b.get("kimlik")}
    if "fonk" not in a or "fonk" not in b:
        s["hata"] = "parmak izi yok"
        return s
    s["girdi_hash_esit"] = a.get("hedef_hash") == b.get("hedef_hash")
    fa, fb = a["fonk"], b["fonk"]
    ortak = sorted(set(fa) & set(fb))
    s["fonksiyon_a"], s["fonksiyon_b"], s["ortak"] = len(fa), len(fb), len(ortak)
    s["yalniz_a"], s["yalniz_b"] = len(set(fa) - set(fb)), len(set(fb) - set(fa))
    s["ham_ghidra_ayni"] = sum(1 for x in set(a["ham"]) & set(b["ham"]) if a["ham"][x] == b["ham"][x])
    s["ham_ghidra_ortak"] = len(set(a["ham"]) & set(b["ham"]))
    s["tanim_adi_ayni"] = sum(1 for x in ortak if fa[x][0] == fb[x][0])
    s["metin_ayni"] = sum(1 for x in ortak if fa[x][1] == fb[x][1])
    s["metin_ayni_algoritma_satirlari_haric"] = sum(1 for x in ortak if fa[x][2] == fb[x][2])
    s["kod_ayni_yorumlar_haric"] = sum(1 for x in ortak if fa[x][4] == fb[x][4])
    s["kod_ayni_yorum_ve_sonek_haric"] = sum(1 for x in ortak if fa[x][5] == fb[x][5])
    s["kod_farki_ornek"] = [f"{x}: {fa[x][3]}" for x in ortak if fa[x][5] != fb[x][5]][:ORNEK_SINIRI]
    s["yol_ayni"] = sum(1 for x in ortak if fa[x][3] == fb[x][3])
    s["dosya_adi_ayni"] = sum(1 for x in ortak
                              if os.path.basename(fa[x][3]) == os.path.basename(fb[x][3]))
    s["ad_farki_ornek"] = [f"{x}: {fa[x][0]} / {fb[x][0]}" for x in ortak if fa[x][0] != fb[x][0]][:ORNEK_SINIRI]
    s["metin_farki_ornek"] = [f"{x}: {fa[x][3]}" for x in ortak if fa[x][2] != fb[x][2]][:ORNEK_SINIRI]
    ha, hb = a["out_harita"], b["out_harita"]
    s["out_harita_ayni"] = ha == hb
    s["out_harita_fark"] = len(set(ha.items()) ^ set(hb.items()))
    s["out_harita_ad_farki"] = sum(1 for k in set(ha) | set(hb)
                                   if (ha.get(k) or (None,))[0] != (hb.get(k) or (None,))[0])
    s["ilk_tur_global_fark"] = len(set(a["ilk_tur_global"].items()) ^ set(b["ilk_tur_global"].items()))
    s["ilk_tur_fonksiyon_adi_farki"] = sum(
        1 for k in set(a["ilk_tur_global"]) | set(b["ilk_tur_global"])
        if k.startswith("FUN_") and a["ilk_tur_global"].get(k) != b["ilk_tur_global"].get(k))
    ya, yb = a["ilk_tur_yerel"], b["ilk_tur_yerel"]
    s["ilk_tur_yerel_esleme_a"] = len(ya)
    s["ilk_tur_yerel_fark"] = sum(1 for k in set(ya) | set(yb) if ya.get(k) != yb.get(k))
    da, db = set(a["out_dosyalar"]), set(b["out_dosyalar"])
    s["out_dosya_a"], s["out_dosya_b"] = len(da), len(db)
    s["out_yalniz_a_yol"], s["out_yalniz_b_yol"] = len(da - db), len(db - da)
    ra, rb = a["rapor_sayac"], b["rapor_sayac"]
    farkli = sorted(k for k in set(ra) | set(rb) if ra.get(k) != rb.get(k))
    s["rapor_sayac_farki"] = len(farkli)
    s["rapor_sayac_farki_ornek"] = [f"{k}: {str(ra.get(k))[:60]} / {str(rb.get(k))[:60]}" for k in farkli[:12]]
    return s


# ---------------------------------------------------------------------------
# Özet tabloları
# ---------------------------------------------------------------------------
def egim(xs, ys):
    """log-log en küçük kareler eğimi ve R²."""
    nok = [(math.log(x), math.log(y)) for x, y in zip(xs, ys)
           if isinstance(x, (int, float)) and isinstance(y, (int, float)) and x > 0 and y > 0]
    n = len(nok)
    if n < 3:
        return None
    mx = sum(p[0] for p in nok) / n
    my = sum(p[1] for p in nok) / n
    sxx = sum((p[0] - mx) ** 2 for p in nok)
    sxy = sum((p[0] - mx) * (p[1] - my) for p in nok)
    syy = sum((p[1] - my) ** 2 for p in nok)
    if sxx == 0 or syy == 0:
        return None
    b = sxy / sxx
    return {"egim": round(b, 3), "r2": round(sxy * sxy / (sxx * syy), 3), "n": n}


def ozetle(sonuclar: list[dict]) -> dict:
    ana = [s for s in sonuclar if s.get("ana_kume")]
    oz: dict = {"ana_kume_ikili": len(ana),
                "debian_elf": sum(1 for s in ana if s["kume"] == "debian"),
                "mac_ikili": sum(1 for s in ana if s["kume"] == "mac")}
    # Kusur × (program, tabaka)
    grup = collections.defaultdict(list)
    for s in ana:
        grup[(s["platform"], s["program"], s["tabaka"])].append(s)
    oz["gruplar"] = [{"platform": p, "program": g, "tabaka": t, "ikili": len(v),
                      "fonksiyon": sum((x.get("k6") or {}).get("fonksiyon", 0) for x in v)}
                     for (p, g, t), v in sorted(grup.items())]
    kusurlar = collections.defaultdict(lambda: {"ikili": 0, "toplam": 0, "gruplar": {}, "ornek": []})
    for s in ana:
        for k, v in (s.get("kusur") or {}).items():
            d = kusurlar[k]
            d["ikili"] += 1
            d["toplam"] += v
            ga = f"{s['platform']}/{s['program']} ({s['tabaka']})"
            g = d["gruplar"].setdefault(ga, {"ikili": 0, "toplam": 0})
            g["ikili"] += 1
            g["toplam"] += v
            taban = k.split(":")[0]
            for o in (s.get("ornek") or {}).get(k, (s.get("ornek") or {}).get(taban, []))[:1]:
                if len(d["ornek"]) < ORNEK_SINIRI:
                    d["ornek"].append(f"{s['kimlik']}: {o}")
    oz["kusurlar"] = {k: dict(v) for k, v in sorted(kusurlar.items())}
    # Tabaka başına toplamlar
    tab = collections.defaultdict(lambda: collections.Counter())
    for s in ana:
        t = tab[s["tabaka"]]
        k4, k6 = s.get("k4") or {}, s.get("k6") or {}
        t["ikili"] += 1
        t["fonksiyon"] += k6.get("fonksiyon", 0)
        t["bozuk_govde"] += k4.get("son_bozuk", 0)
        t["ic_ice_yorum"] += k4.get("son_ic_ice_yorum", 0)
    oz["tabaka"] = {str(k): dict(v) for k, v in tab.items()}
    # Ghidra uyarı türleri (ham) ve son çıktıda kalan
    uy = collections.Counter()
    uy_ikili = collections.Counter()
    bozulma = collections.Counter()
    algo = collections.Counter()
    yara = collections.Counter()
    antidbg = collections.Counter()
    zeka_a, zeka_p = collections.Counter(), collections.Counter()
    for s in ana:
        k5, k4 = s.get("k5") or {}, s.get("k4") or {}
        for u, n in (k5.get("ghidra_uyari_turleri_ham_tam") or {}).items():
            uy[u] += n
            uy_ikili[u] += 1
        for a, n in (k4.get("ilk_bozulan_asama") or {}).items():
            bozulma[a] += n
        for a, n in (k5.get("algoritma_etiketi_turleri") or {}).items():
            algo[a] += n
        for y in k5.get("yara") or []:
            yara[y] += 1
        if k5.get("anti_debug_ust_teknik"):
            antidbg[k5["anti_debug_ust_teknik"]] += 1
        for a in k5.get("zeka_algoritma") or []:
            zeka_a[a] += 1
        for a in k5.get("zeka_protokol") or []:
            zeka_p[a] += 1
    oz["ghidra_uyari_turleri"] = {u: {"adet": n, "ikili": uy_ikili[u],
                                      "kritik": bool(RE_KRITIK_UYARI.search(u))}
                                  for u, n in uy.most_common(40)}
    oz["ghidra_uyari_ham_toplam"] = sum(uy.values())
    oz["ghidra_uyari_son_toplam"] = sum((s.get("k5") or {}).get("ghidra_uyari_son", 0) for s in ana)
    oz["ilk_bozulan_asama"] = dict(bozulma)
    oz["etiketler"] = {
        "algoritma_etiketi_turleri": dict(algo.most_common(15)),
        "algoritma_etiketi_toplam": sum((s.get("k5") or {}).get("algoritma_etiketi", 0) for s in ana),
        "yara_ikili": dict(yara.most_common(15)),
        "anti_debug_ust_teknik_ikili": dict(antidbg),
        "zeka_algoritma_ikili": dict(zeka_a.most_common(15)),
        "zeka_protokol_ikili": dict(zeka_p.most_common(15)),
    }
    # Ölçek: yalnız Debian (aynı koşullar: paralel 3)
    deb = [s for s in ana if s["kume"] == "debian" and s.get("k6")]
    fx = [s["k6"]["fonksiyon"] for s in deb]
    bx = [s["k6"].get("ham_c_bayt") for s in deb]
    olcek = {}
    for ad, al in (("toplam", lambda s: s["k6"]["toplam_sure_s"]),
                   ("static", lambda s: s["k6"]["asama_sure_s"].get("static")),
                   ("reconstruct", lambda s: s["k6"]["asama_sure_s"].get("reconstruct")),
                   ("out_bayt", lambda s: s["k6"]["out_bayt"])):
        ys = [al(s) for s in deb]
        olcek[ad] = {"fonksiyona_gore": egim(fx, ys), "ham_c_bayta_gore": egim(bx, ys)}
    adimlar = collections.defaultdict(list)
    for s in deb:
        for k, v in s["k6"]["adim_sure_s"].items():
            adimlar[k].append((s["k6"]["fonksiyon"], v))
    adim_egim = {}
    for k, v in adimlar.items():
        e = egim([x for x, _ in v], [y for _, y in v])
        en = max(v, key=lambda t: t[1])
        adim_egim[k] = {"egim": e, "en_uzun_s": en[1], "en_uzun_fonksiyon": en[0],
                        "toplam_s": round(sum(y for _, y in v), 1)}
    olcek["adimlar"] = adim_egim
    oz["olcek"] = olcek
    # Günlük iletileri: hepsinde mi, yalnız büyüklerde mi
    ileti = collections.defaultdict(list)
    for s in ana:
        for m in (s.get("k5") or {}).get("log_ileti", {}):
            ileti[m].append(s)
    oz["log_iletileri"] = {
        m: {"ikili": len(v),
            "en_kucuk_fonksiyon": min((x.get("k6") or {}).get("fonksiyon", 0) for x in v),
            "ortanca_fonksiyon": sorted((x.get("k6") or {}).get("fonksiyon", 0) for x in v)[len(v) // 2],
            "ornek": v[0]["kimlik"]}
        for m, v in ileti.items()}
    return oz


def depo_durumu(kunye_commit) -> dict:
    """Saklı koşuların commit'inden bugünkü ağaca ürün kodunda ne değişti
    (yalnız okur: git rev-parse / diff / status)."""
    import subprocess

    def git(*a):
        try:
            return subprocess.run(["git", "-C", DEPO, *a], capture_output=True,
                                  text=True, timeout=30).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None
    d = {"head": git("rev-parse", "HEAD"), "kunye_commit": kunye_commit}
    if kunye_commit:
        ad = git("diff", "--name-only", kunye_commit, "HEAD", "--", "karadul/")
        d["kunyeden_beri_degisen_urun_dosyalari"] = ad.split("\n") if ad else []
    kirli = git("status", "--short", "--", "karadul/")
    d["urun_agaci_kirli"] = kirli.split("\n") if kirli else []
    return d


# ---------------------------------------------------------------------------
# Ana
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--is", dest="isci", type=int, default=VARSAYILAN_IS)
    ap.add_argument("--yalniz", default=None, help="yalnız bu önekle başlayan kimlikler")
    ap.add_argument("--json", default=CIKTI_JSON)
    a = ap.parse_args(argv)

    kosular = kosulari_bul()
    if a.yalniz:
        kosular = [k for k in kosular if k["kimlik"].startswith(a.yalniz)]
    print(f"{len(kosular)} koşu denetlenecek ({a.isci} işçi)", file=sys.stderr)
    t0 = time.time()
    sonuclar, izler = [], {}
    with multiprocessing.Pool(a.isci) as havuz:
        for i, (s, iz) in enumerate(havuz.imap_unordered(kosu_denetle_guvenli, kosular), 1):
            sonuclar.append(s)
            izler[s["kimlik"]] = iz
            if i % 10 == 0 or i == len(kosular):
                print(f"  {i}/{len(kosular)}  {time.time() - t0:.0f} s", file=sys.stderr)
    sonuclar.sort(key=lambda s: s["kimlik"])

    ciftler = []
    for x, y in DOGAL_CIFTLER:
        if x in izler and y in izler:
            c = cift_karsilastir(izler[x], izler[y])
            c["tur"] = "dogal_yineleme"
            ciftler.append(c)
    for ad, esas in YENIDEN_ESLESME.items():
        x, y = esas, f"yeniden/{ad}"
        if x in izler and y in izler:
            c = cift_karsilastir(izler[x], izler[y])
            c["tur"] = "yeniden_kosu"
            ciftler.append(c)

    ana = [s for s in sonuclar if s.get("ana_kume")]
    cikti = {
        "sema": "karadul-cikti-saglamligi/1",
        "uretim": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "sabitler": {
            "DEBIAN_KOK": DEBIAN_KOK, "MAC_KOK": MAC_KOK, "MAC_ANA_ETIKET": MAC_ANA_ETIKET,
            "YENIDEN_KOK": YENIDEN_KOK, "BEKLENEN_IKILI": BEKLENEN_IKILI,
            "GUVEN_ESIGI": GUVEN_ESIGI, "DECOMPILED_JSON_SINIRI": DECOMPILED_JSON_SINIRI,
            "GHIDRA_ZAMAN_ASIMI_S": GHIDRA_ZAMAN_ASIMI_S, "TUR_ZAMAN_ASIMI_S": TUR_ZAMAN_ASIMI_S,
            "ZAMAN_ASIMI_YAKINLIK": ZAMAN_ASIMI_YAKINLIK,
        },
        "debian_kunye": json_oku(DEBIAN_KUNYE),
        "depo_durumu": depo_durumu((json_oku(DEBIAN_KUNYE) or {}).get("commit")),
        "kosu_sayisi": len(sonuclar),
        "ana_kume_ikili": len(ana),
        "ana_kume_beklenen": BEKLENEN_IKILI,
        "ozet": ozetle(sonuclar) if not a.yalniz else None,
        "ciftler": ciftler,
        "kosular": sonuclar,
    }
    with open(a.json, "w", encoding="utf-8") as f:
        json.dump(cikti, f, ensure_ascii=False, indent=1, sort_keys=True, default=str)
    print(f"yazıldı: {a.json}  ({len(sonuclar)} koşu, {time.time() - t0:.0f} s)", file=sys.stderr)
    if not a.yalniz and len(ana) != BEKLENEN_IKILI:
        print(f"UYARI: ana kümede {len(ana)} ikili var, beklenen {BEKLENEN_IKILI}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
