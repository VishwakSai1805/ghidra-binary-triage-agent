/*
 * cve_sim_off_by_one.c
 *
 * Simulated CVE class: CWE-193 Off-by-One Error
 * Pattern: a loop or copy writes `sizeof(buf)` bytes (or uses `<=`
 * instead of `<`) into a fixed buffer, overwriting one byte beyond its
 * end -- the classic off-by-one that corrupts an adjacent saved
 * register/canary byte, as seen in many historical CVEs and CTF
 * "babyoverflow" challenges.
 *
 * Intentionally vulnerable benchmark target for static analysis and
 * ASan-based dynamic verification only.
 */
#include <stdio.h>
#include <string.h>

void copy_label(const char *src) {
    char label[32];
    size_t len = strlen(src);
    /* sink: off-by-one bound check (<=) copies len+1 bytes (including the
     * terminator) into a 32-byte buffer; src of length >= 32 overflows
     * label by one or more bytes. */
    for (size_t i = 0; i <= len; i++) {
        label[i] = src[i];
    }
    printf("label=%s\n", label);
}

int main(int argc, char **argv) {
    const char *src = argc > 1 ? argv[1] : "demo";
    copy_label(src);
    return 0;
}
