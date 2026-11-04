/*
 * cve_sim_integer_overflow.c
 *
 * Simulated CVE class: CWE-190 Integer Overflow leading to undersized
 * heap allocation (classic "count * size" overflow pattern), the same
 * shape as numerous historical image/archive-parser CVEs.
 *
 * Intentionally vulnerable benchmark target for static analysis and
 * ASan-based dynamic verification only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* sink: unchecked multiplication feeding malloc() can wrap around on
 * 32-bit int, producing a tiny allocation that the caller then
 * overflows while writing `count` elements. */
int *alloc_records(int count, int record_size) {
    int total = count * record_size; /* integer overflow sink */
    int *buf = malloc(total);
    return buf;
}

int main(int argc, char **argv) {
    int count = argc > 1 ? atoi(argv[1]) : 16;
    int record_size = 64;

    int *records = alloc_records(count, record_size);
    if (!records) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    /* writes `count` records assuming the allocation matches; if the
     * multiplication overflowed, this writes far past the real buffer */
    for (int i = 0; i < count; i++) {
        records[i] = i;
    }

    printf("wrote %d records\n", count);
    free(records);
    return 0;
}
