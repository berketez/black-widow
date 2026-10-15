int sum(const int *a, int n) { int s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
void saxpy(float *restrict y, const float *restrict x, float k, int n) { for (int i = 0; i < n; i++) y[i] += k * x[i]; }
int fixed4(const int *a) { int s = 0; for (int i = 0; i < 4; i++) s += a[i] * (i + 1); return s; }
