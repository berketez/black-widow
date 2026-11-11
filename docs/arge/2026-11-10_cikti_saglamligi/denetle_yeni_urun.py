"""Dünkü sağlamlık denetimini yeni ürün koşusuna yönelten sarmalayıcı (betik değişmeden)."""
import importlib.util, os, sys
YOL = "/Users/apple/Black_Widow/docs/arge/2026-11-10_cikti_saglamligi/denetle.py"
spec = importlib.util.spec_from_file_location("denetle", YOL)
d = importlib.util.module_from_spec(spec); sys.modules["denetle"] = d; spec.loader.exec_module(d)
KOK = os.path.expanduser("~/karadul_olcum/runs/urun-yeni-93a2956")
d.DEBIAN_KOK = os.path.join(KOK, "debian")
d.DEBIAN_KUNYE = os.path.join(KOK, "kosu_kunyesi.json")
d.MAC_KOK = KOK
d.MAC_ETIKETLER = ("mac",)
d.MAC_ANA_ETIKET = "mac"
d.YENIDEN_KOK = os.path.join(KOK, "yok")
d.YENIDEN_ESLESME = {}
d.DOGAL_CIFTLER = (("debian/redis-tools/redis-check-aof", "debian/redis-tools/redis-check-rdb"),)
if __name__ == "__main__":
    sys.exit(d.main(["--is", "3", "--json", sys.argv[1]]))
