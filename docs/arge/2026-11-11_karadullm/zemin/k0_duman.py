#!/usr/bin/env python3
"""KaradulLM K0 duman betiği: saklı bir çalışma alanında "ad öner" iş akışını uçtan uca koşturur.

İki kip:

``--kuru``  Model YOK. Betikli sahte arka uçla (her fonksiyona aynı hazır çekimser cevap) çalışma
            alanındaki bütün program fonksiyonlarında paketi kurar, üç okuyan aracı çalıştırır ve
            sayar: paket kurulabilen fonksiyon, istem jeton kestirimi, bağlama sığmayan fonksiyon,
            boyut sınırına takılan araç sonucu. Sunucu başlatmaz, ağ isteği atmaz.

(öntanım)   GERÇEK yerel ``llama-server``'ı başlatır, en çok N fonksiyonda K0 "ad öner" koşturur,
            sunucuyu ``finally`` içinde kapatır. Ölçtükleri: görev durumları, bitiş nedeni (yeni
            ``kanit`` şeması üretimi sınırlıyor mu), jeton kestirimi ile gerçek ``usage`` farkı,
            süre, bellek tepesi. Makinede başka bir ``llama-server`` çalışıyorsa başlamaz.

Çalışma alanı SALT OKUNUR kullanılır. Çıktı dizinine sonuç JSON'u ve denetim günlüğü yazılır.
Gerçek kipte modelin önerdiği adlar çıktıya girer; gerçek ad (GT) hiçbir yerden okunmaz.

Kullanım::

    python docs/arge/2026-11-11_karadullm/zemin/k0_duman.py <çalışma alanı> --kuru [--cikti DİZİN]
    python docs/arge/2026-11-11_karadullm/zemin/k0_duman.py <çalışma alanı> --en-cok 5 --cikti DİZİN [--kor]

``<çalışma alanı>``: ``…/ws/workspaces/<ad>/<zaman>/`` (içinde ``static/`` olan dizin).
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[4]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import karadul  # noqa: E402
from karadul.lm import CONTEXT_TOKENS, context, memory_guard  # noqa: E402
from karadul.lm.agent import Agent  # noqa: E402
from karadul.lm.audit import AuditLog  # noqa: E402
from karadul.lm.backend import FakeBackend, FakeReply, LlamaServerBackend  # noqa: E402
from karadul.lm.tools import ToolContext, Workspace, default_registry  # noqa: E402

# Pilotun ve lm_duman.py'nin kullandığı ikili ve model (zemin_olcumu.md).
_IKILI = Path.home() / ".lmstudio/extensions/backends/llama.cpp-mac-arm64-apple-metal-advsimd-2.60.0/llama-server"
_MODEL = Path.home() / ".lmstudio/models/lmstudio-community/Qwen3.8-27B-GGUF/Qwen3.8-27B-Q4_K_M.gguf"
_HAZIR_CEKIMSER = json.dumps({"isim": None, "gerekce": "kuru koşu: model yok", "cekimser": True, "kanit": []},
                             ensure_ascii=False)


def _dagilim(degerler: list[float]) -> dict:
    """Sayı listesinin özeti; boş listede uydurma değer yok."""
    if not degerler:
        return {"n": 0}
    return {"n": len(degerler), "en_kucuk": min(degerler), "ortanca": statistics.median(degerler),
            "en_buyuk": max(degerler)}


def _sec(adresler: list[str], n: int) -> list[str]:
    """Adrese göre sıralı listeden eşit aralıklı en çok ``n`` adres (belirlenimci)."""
    if n <= 0 or n >= len(adresler):
        return list(adresler)
    if n == 1:
        return [adresler[len(adresler) // 2]]
    return [adresler[round(i * (len(adresler) - 1) / (n - 1))] for i in range(n)]


def kuru(alan: Workspace, adresler: list[str], kor: bool) -> dict:
    """Model olmadan: paket kurulumu ve araç sonuçlarının sayımı."""
    t0 = time.monotonic()
    paket_sayisi = len(alan.packs)
    paket_sn = round(time.monotonic() - t0, 3)
    arka = FakeBackend([], audit=None)
    ajan = Agent(arka, alan, blind_target=kor)
    kayit = default_registry()
    durumlar: Counter = Counter()
    hatalar: Counter = Counter()
    kestirim: list[int] = []
    kanit_bayt: list[int] = []
    kod_bayt: list[int] = []
    sayac: Counter = Counter()
    ham_kod = kacisli_kod = isaret = 0
    t1 = time.monotonic()
    for a in adresler:
        arka.replies.append(FakeReply(content=_HAZIR_CEKIMSER))
        r = ajan.suggest_name(f"FUN_{a}")
        durumlar[r.status] += 1
        if r.error:
            hatalar[r.error] += 1
        if r.status != "tamam":
            arka.replies.clear()
        if r.est_prompt_tokens is not None:
            kestirim.append(r.est_prompt_tokens)
        sayac["kod_kirpildi_tek_atis"] += r.code_clipped
        sayac["icerik_adsiz"] += r.empty_content
        if r.counters.model_calls == 1 and r.status == "tamam":
            kanit, kod = context.unwrap_results(arka.calls[-1]["messages"][1]["content"])
            sayac["kanit_kirpildi"] += "truncated" in kanit
            kanit_bayt.append(len(context.escape_json(kanit).encode("utf-8")))
            kod_bayt.append(len(context.escape_json(kod).encode("utf-8")))
            metin = kod["data"]["code"]
            ham_kod += len(metin.encode("utf-8"))
            kacisli_kod += len(context.escape_json(metin).encode("utf-8")) - 2
            isaret += sum(metin.count(c) for c in "<>&")
            sayac["ghidra_uyarili"] += bool(kod["data"]["ghidra_warnings"])
        # döngü kipinin araçları (model çağırmadan, doğrudan): boyut sınırına takılma sayımı
        for ad, args, anahtar in (
                ("get_decompiled", {"addr": f"FUN_{a}", "part": "bas"}, "kod_kirpildi_dongu"),
                ("get_xrefs", {"addr": f"FUN_{a}", "direction": "callers"}, "xrefs_callers_kirpildi"),
                ("get_xrefs", {"addr": f"FUN_{a}", "direction": "callees"}, "xrefs_callees_kirpildi"),
                ("get_xrefs", {"addr": f"FUN_{a}", "direction": "address_refs"}, "xrefs_address_refs_kirpildi")):
            s = kayit.call(alan, ad, args, result_id="r0", ctx=ToolContext(blind_target=a if kor else None))
            sayac[anahtar] += s.truncated is not None
            if not s.ok:
                sayac[f"{ad}_hata_{s.error}"] += 1
            sayac["arac_cagrisi"] += 1
    return {
        "kip": "kuru", "kor": kor, "program_fonksiyonu": len(alan.program_addresses()), "denenen": len(adresler),
        "toplam_fonksiyon": alan.function_count(), "kanit_paketi": paket_sayisi, "kanit_kurma_sn": paket_sn,
        "dongu_sn": round(time.monotonic() - t1, 3), "durumlar": dict(durumlar), "hatalar": dict(hatalar),
        "baglam_jetonu": CONTEXT_TOKENS, "istem_jeton_kestirimi": _dagilim(kestirim),
        "baglama_sigmayan": durumlar.get("baglam_asimi", 0),
        "kanit_sonucu_bayt": _dagilim(kanit_bayt), "kod_sonucu_bayt": _dagilim(kod_bayt),
        "sayimlar": {k: int(v) for k, v in sorted(sayac.items())},
        "kacislama": {"ham_kod_bayt": ham_kod, "kacisli_kod_bayt": kacisli_kod, "kacislanan_isaret": isaret,
                      "sisme_orani": round(kacisli_kod / ham_kod, 4) if ham_kod else None},
        "sabit_onek": {"bayt": len(ajan.prefix("K0").encode("utf-8")), "sha256": ajan.prefix_sha256("K0"),
                       "jeton_kestirimi": context.estimate_text_tokens(ajan.prefix("K0"))},
    }


def _pgrep() -> str:
    try:
        return subprocess.run(["pgrep", "-fl", "llama-server"], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"pgrep çalışmadı: {type(e).__name__}"


def gercek(alan: Workspace, adresler: list[str], args: argparse.Namespace, cikti: Path) -> dict:
    """Gerçek yerel sunucuyla K0. Sunucu her yolda ``finally`` içinde kapatılır."""
    gunluk = AuditLog(cikti / "denetim.jsonl", keep_in_memory=True)
    arka = LlamaServerBackend(Path(args.ikili), Path(args.model), cikti / "durum", audit=gunluk,
                              template_path=Path(args.sablon) if args.sablon else None,
                              ready_timeout=args.hazir_zaman_asimi)
    bekci = memory_guard.MemoryGuard(lambda: arka.pid, lambda s: arka.stop("bellek"), audit=gunluk)
    ajan = Agent(arka, alan, audit=gunluk, memory_guard=bekci, blind_target=args.kor)
    sonuc: dict = {"kip": "gercek", "kor": args.kor, "gorevler": [], "ikili": str(args.ikili), "model": str(args.model)}
    try:
        t0 = time.monotonic()
        arka.start()
        sonuc["baslatma_sn"] = round(time.monotonic() - t0, 1)
        sonuc["yetenek"] = arka.capabilities().level
        for a in adresler:
            r = ajan.suggest_name(f"FUN_{a}")
            kayit = r.as_dict()
            istek = [k for k in gunluk.records if k["olay"] == "model_istegi"]
            kayit["timings"] = istek[-1].get("timings") if istek else None
            sonuc["gorevler"].append(kayit)
            print(f"FUN_{a}: {r.status} / {r.name_status} / bitiş {r.finish_reason} / kestirim "
                  f"{r.est_prompt_tokens} gerçek {r.prompt_tokens} / {r.duration_sec} sn", flush=True)
            if r.status in ("bellek_durdu", "arka_uc_hatasi"):
                break
    except Exception as e:  # noqa: BLE001 — duman betiği: hata kayda geçer, sunucu yine kapanır
        sonuc["hata"] = f"{type(e).__name__}: {e}"[:500]
    finally:
        try:
            arka.stop("istek")
        except Exception as e:  # noqa: BLE001
            sonuc["durdurma_hatasi"] = f"{type(e).__name__}: {e}"[:300]
        sonuc["sonra_pgrep"] = _pgrep()
    g = sonuc["gorevler"]
    oran = [x["prompt_tokens"] / x["est_prompt_tokens"] for x in g if x["prompt_tokens"] and x["est_prompt_tokens"]]
    sonuc["ozet"] = {
        "gorev": len(g), "durumlar": dict(Counter(x["status"] for x in g)),
        "ad_durumlari": dict(Counter(str(x["name_status"]) for x in g)),
        "bitis_nedenleri": dict(Counter(str(x["finish_reason"]) for x in g)),
        "kanit_uzunlugu_en_buyuk": max((len(x["answer"]["kanit"]) for x in g if x["answer"]), default=None),
        "gercek_bolu_kestirim": _dagilim([round(o, 3) for o in oran]),
        "sure_sn": _dagilim([x["duration_sec"] for x in g]),
        "uretim_jetonu": _dagilim([x["completion_tokens"] for x in g if x["completion_tokens"] is not None]),
        "bellek_tepe": bekci.peak.as_dict() if bekci.peak else None,
        "bellek_durdurdu": bekci.tripped is not None,
    }
    return sonuc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="KaradulLM K0 duman betiği")
    ap.add_argument("calisma_alani", type=Path, help="…/ws/workspaces/<ad>/<zaman>/ (içinde static/ olan dizin)")
    ap.add_argument("--en-cok", type=int, default=None,
                    help="en çok N fonksiyon, adrese göre eşit aralıklı (öntanım: gerçek kipte 5, kuru kipte hepsi)")
    ap.add_argument("--adres", action="append", default=[], help="yalnız bu FUN_<adres> (yinelenebilir)")
    ap.add_argument("--cikti", type=Path, help="çıktı dizini (gerçek kipte zorunlu)")
    ap.add_argument("--kuru", action="store_true", help="model yok: sahte arka uçla paket ve araç sayımı")
    ap.add_argument("--kor", action="store_true", help="körlük kipi (hedefin Karadul adı isteme girmez)")
    ap.add_argument("--ikili", default=str(_IKILI), help="llama-server ikilisi")
    ap.add_argument("--model", default=str(_MODEL), help="GGUF model dosyası")
    ap.add_argument("--sablon", default=None, help="sohbet şablonu dosyası (isteğe bağlı)")
    ap.add_argument("--hazir-zaman-asimi", type=float, default=300.0, help="sunucunun hazır olma beklemesi (sn)")
    args = ap.parse_args(argv)

    if not str(Path(karadul.__file__).resolve()).startswith(str(_ROOT)):
        print(f"HATA: karadul başka ağaçtan yüklendi: {karadul.__file__}", file=sys.stderr)
        return 2
    alan = Workspace(args.calisma_alani)
    program = alan.program_addresses()
    if args.adres:
        adresler = []
        for x in args.adres:
            a = alan.resolve(x)
            if a is None:
                print(f"HATA: adres çalışma alanında yok: {x}", file=sys.stderr)
                return 2
            adresler.append(a)
    else:
        adresler = _sec(program, args.en_cok if args.en_cok is not None else (0 if args.kuru else 5))
    if args.kuru:
        sonuc = kuru(alan, adresler, args.kor)
    else:
        if args.cikti is None:
            ap.error("gerçek kipte --cikti zorunlu")
        calisan = _pgrep()
        if calisan:
            print(f"HATA: çalışan bir llama-server var; başlatılmadı:\n{calisan}", file=sys.stderr)
            return 2
        args.cikti.mkdir(parents=True, exist_ok=True)
        sonuc = gercek(alan, adresler, args, args.cikti)
    sonuc["calisma_alani"] = str(args.calisma_alani)
    sonuc["zaman"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    metin = json.dumps(sonuc, ensure_ascii=False, indent=1, default=str)
    if args.cikti is not None:
        args.cikti.mkdir(parents=True, exist_ok=True)
        (args.cikti / ("k0_kuru_sonuc.json" if args.kuru else "k0_duman_sonuc.json")).write_text(metin + "\n",
                                                                                                encoding="utf-8")
    print(json.dumps({k: v for k, v in sonuc.items() if k != "gorevler"}, ensure_ascii=False, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
