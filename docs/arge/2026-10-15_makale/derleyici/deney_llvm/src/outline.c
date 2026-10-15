extern void sink(int, int, int, int);
void a1(int x) { sink(1, 2, 3, x); sink(4, 5, 6, x); sink(7, 8, 9, x); }
void a2(int x) { sink(1, 2, 3, x); sink(4, 5, 6, x); sink(7, 8, 9, x); x++; sink(x, x, x, x); }
void a3(int y) { sink(10, 2, 3, y); sink(4, 5, 6, y); sink(7, 8, 9, y); }
void a4(int y) { sink(11, 2, 3, y); sink(4, 5, 6, y); sink(7, 8, 9, y); }
