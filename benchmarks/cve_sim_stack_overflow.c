/*
 * cve_sim_stack_overflow.c
 *
 * Simulated CVE class: CWE-121 Stack-based Buffer Overflow
 * Pattern: classic unchecked strcpy() into a fixed-size stack buffer,
 * the same shape as historical bugs such as CVE-1999-0046-style gets()/strcpy()
 * overflows taught in every stack-smashing course.
 *
 * This program is intentionally vulnerable and is used ONLY as a benchmark
 * target for the static CFG/sink analyzer and the ASan-based crash harness
 * in this repository. It is never deployed or network-exposed.
 */
#include <stdio.h>
#include <string.h>

void vulnerable_copy(const char *input) {
    char buffer[64];
    strcpy(buffer, input); /* sink: strcpy, no bounds check -> stack smash */
    printf("buffer=%s\n", buffer);
}

int process_record(const char *name) {
    char record[128];
    snprintf(record, sizeof(record), "record:%s", name);
    vulnerable_copy(record);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input>\n", argv[0]);
        return 1;
    }
    return process_record(argv[1]);
}
