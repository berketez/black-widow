/* Üretilmiş: N vakalı switch, her vaka farklı dış fonksiyon. */
extern int g8_0(int); extern int g8_1(int); extern int g8_2(int); extern int g8_3(int); extern int g8_4(int); extern int g8_5(int); extern int g8_6(int); extern int g8_7(int);
int dispatch8(int op, int v) {
  switch (op) {
  case 0: return g8_0(v);
  case 1: return g8_1(v);
  case 2: return g8_2(v);
  case 3: return g8_3(v);
  case 4: return g8_4(v);
  case 5: return g8_5(v);
  case 6: return g8_6(v);
  case 7: return g8_7(v);
  default: return -1;
  }
}
extern int g12_0(int); extern int g12_1(int); extern int g12_2(int); extern int g12_3(int); extern int g12_4(int); extern int g12_5(int); extern int g12_6(int); extern int g12_7(int); extern int g12_8(int); extern int g12_9(int); extern int g12_10(int); extern int g12_11(int);
int dispatch12(int op, int v) {
  switch (op) {
  case 0: return g12_0(v);
  case 1: return g12_1(v);
  case 2: return g12_2(v);
  case 3: return g12_3(v);
  case 4: return g12_4(v);
  case 5: return g12_5(v);
  case 6: return g12_6(v);
  case 7: return g12_7(v);
  case 8: return g12_8(v);
  case 9: return g12_9(v);
  case 10: return g12_10(v);
  case 11: return g12_11(v);
  default: return -1;
  }
}
extern int g16_0(int); extern int g16_1(int); extern int g16_2(int); extern int g16_3(int); extern int g16_4(int); extern int g16_5(int); extern int g16_6(int); extern int g16_7(int); extern int g16_8(int); extern int g16_9(int); extern int g16_10(int); extern int g16_11(int); extern int g16_12(int); extern int g16_13(int); extern int g16_14(int); extern int g16_15(int);
int dispatch16(int op, int v) {
  switch (op) {
  case 0: return g16_0(v);
  case 1: return g16_1(v);
  case 2: return g16_2(v);
  case 3: return g16_3(v);
  case 4: return g16_4(v);
  case 5: return g16_5(v);
  case 6: return g16_6(v);
  case 7: return g16_7(v);
  case 8: return g16_8(v);
  case 9: return g16_9(v);
  case 10: return g16_10(v);
  case 11: return g16_11(v);
  case 12: return g16_12(v);
  case 13: return g16_13(v);
  case 14: return g16_14(v);
  case 15: return g16_15(v);
  default: return -1;
  }
}
