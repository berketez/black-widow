/* fixture.c — Karadul Linux ELF stripped benchmark fixture
 * Kaynak: karadul v1.11.0 Dalga 5
 * Derleme: gcc -g -O1 fixture.c -o sample_elf
 */
#include <stdio.h>
#include <string.h>

int parse_config(const char *path) { return (int)strlen(path); }
int send_packet(const char *data, int len) { return len * 2; }
int encrypt_buffer(char *buf, int len) {
    for (int i = 0; i < len; i++) buf[i] ^= 0x42;
    return len;
}
int init_context(void *ctx) { return ctx ? 1 : 0; }
void cleanup_session(void *s) { (void)s; }

int main(int argc, char **argv) {
    char buf[64] = {0};
    init_context(buf);
    parse_config(argv[0]);
    send_packet(buf, 16);
    encrypt_buffer(buf, 16);
    cleanup_session(buf);
    return 0;
}
