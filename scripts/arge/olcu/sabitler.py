"""ÖLÇÜ hattının ortak sabitleri (tek yerde; öbür betikler buradan içe aktarır)."""
OLCU_TOHUM = 20261119                 # önyükleme tohumu (DEFTER §4)
OLCU_ONYUKLEME = 2000                 # önyükleme tekrar sayısı
OLCU_HEDEFLERI = {"yakin": ("tam", "dogru_tarif"), "yaniltmaz": ("tam", "dogru_tarif", "yalniz_alan")}
OLCU_ASIMETRIK_ADAYLAR = ("P", "Ps", "Pic", "Pz", "as0", "as5")
OLCU_SIRALI_ETIKET = {"yanlis": 0, "yalniz_alan": 1, "dogru_tarif": 2, "tam": 3}
OLCU_AYAR_KESINLIK = 0.90             # Ö3: ayar kümesinde kabulün ``yakin`` kesinliği en az
OLCU_O3 = {"nokta": 0.85, "wilson_alt": 0.70, "en_az_kabul": 20}
OLCU_O4 = {"nokta": 0.85, "wilson_alt": 0.80}
