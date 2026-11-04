/*
 * cve_sim_heap_uaf.c
 *
 * Simulated CVE class: CWE-416 Use-After-Free
 * Pattern: a pointer is freed and then either read or written again,
 * the same shape as widely-documented browser/OS UAF bugs used in
 * CTF "heap exploitation 101" challenges.
 *
 * Intentionally vulnerable benchmark target for static analysis and
 * ASan-based dynamic verification only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];
    int  priority;
} task_t;

task_t *g_last_task = NULL;

task_t *create_task(const char *name, int priority) {
    task_t *t = malloc(sizeof(task_t));
    if (!t) return NULL;
    strncpy(t->name, name, sizeof(t->name) - 1);
    t->name[sizeof(t->name) - 1] = '\0';
    t->priority = priority;
    g_last_task = t;
    return t;
}

void retire_task(task_t *t) {
    free(t); /* freed here */
}

void print_task(task_t *t) {
    /* sink: use-after-free if called with an already-retired task */
    printf("task=%s priority=%d\n", t->name, t->priority);
}

int main(int argc, char **argv) {
    const char *name = argc > 1 ? argv[1] : "default";
    task_t *t = create_task(name, 5);
    retire_task(t);
    print_task(g_last_task); /* UAF: g_last_task points to freed memory */
    return 0;
}
