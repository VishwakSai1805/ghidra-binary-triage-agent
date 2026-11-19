/*
 * cve_sim_format_string.c
 *
 * Simulated CVE class: CWE-134 Uncontrolled Format String
 * Pattern: user-controlled data passed directly as the format argument
 * to printf(), the textbook bug behind many historical format-string CVEs
 * (e.g. wu-ftpd CVE-2000-0573 era, and countless CTF "fmtstr" challenges).
 *
 * Intentionally vulnerable benchmark target for static analysis and
 * ASan-based dynamic verification only.
 */
#include <stdio.h>
#include <string.h>

void log_message(const char *user_input) {
    /* sink: format string is attacker-controlled, not a constant */
    printf(user_input);
    printf("\n");
}

int main(int argc, char **argv) {
    char line[256];
    if (argc > 1) {
        strncpy(line, argv[1], sizeof(line) - 1);
        line[sizeof(line) - 1] = '\0';
    } else {
        if (!fgets(line, sizeof(line), stdin)) {
            return 1;
        }
    }
    log_message(line);
    return 0;
}
