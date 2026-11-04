/*
 * cve_sim_command_injection.c
 *
 * Simulated CVE class: CWE-78 OS Command Injection
 * Pattern: user-controlled string concatenated into a shell command and
 * passed to system(), the textbook bug behind countless router/CGI CVEs
 * and the standard "command injection 101" CTF challenge shape.
 *
 * Intentionally vulnerable benchmark target for static analysis only.
 * The analyzer flags the system() sink; this harness never actually
 * executes attacker-chosen commands during automated testing (callers
 * run it with benign, hard-coded demo arguments only).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_lookup(const char *hostname) {
    char cmd[256];
    /* sink: unsanitized user input concatenated into a shell command */
    snprintf(cmd, sizeof(cmd), "echo lookup:%s", hostname);
    system(cmd);
}

int main(int argc, char **argv) {
    const char *hostname = argc > 1 ? argv[1] : "localhost";
    run_lookup(hostname);
    return 0;
}
