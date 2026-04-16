/*
 * fast_scan.c — High-speed pattern search over binary files.
 * Usage: ./fast_scan <file> <pattern>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE (1 << 20)  /* 1 MB read chunks */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <file> <pattern>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    const char *pat = argv[2];
    size_t plen = strlen(pat);
    char *buf = malloc(BUFSIZE + plen);
    if (!buf) { perror("malloc"); return 1; }

    size_t offset = 0, carry = 0, n;
    int found = 0;

    while ((n = fread(buf + carry, 1, BUFSIZE, f)) > 0) {
        size_t total = carry + n;
        for (size_t i = 0; i + plen <= total; i++) {
            if (memcmp(buf + i, pat, plen) == 0) {
                printf("[+] Match at offset 0x%zx (%zu)\n", offset + i, offset + i);
                found++;
            }
        }
        /* carry last (plen-1) bytes into next iteration to catch boundary matches */
        carry = (total >= plen - 1) ? plen - 1 : total;
        memcpy(buf, buf + total - carry, carry);
        offset += total - carry;
    }

    if (!found) printf("[-] Pattern not found.\n");
    else printf("[*] Total matches: %d\n", found);

    free(buf);
    fclose(f);
    return 0;
}
