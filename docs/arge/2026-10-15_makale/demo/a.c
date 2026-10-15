/* Okunaklı sürüm */
int toplam_fiyat(int *fiyatlar, int adet) {
    int toplam = 0;
    for (int i = 0; i < adet; i++)
        toplam += fiyatlar[i];
    return toplam;
}
