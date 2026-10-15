extern int h0(int); extern int h1(int); extern int h2(int); extern int h3(int); extern int h4(int); extern int h5(int); extern int h6(int); extern int h7(int);
int d(int op,int v){switch(op){
case 0: return h0(v);
case 1: return h1(v);
case 2: return h2(v);
case 3: return h3(v);
case 4: return h4(v);
case 5: return h5(v);
case 6: return h6(v);
case 7: return h7(v);
default: return -1;}}
