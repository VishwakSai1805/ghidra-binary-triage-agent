#!/usr/bin/env python3
"""
reports/patch_advisor.py

Milestone 3, part 1: a small rule-based "patch advisor" that maps each
vulnerability class this toolkit detects to a concrete, standard
remediation -- the kind of actionable guidance a human triager would
write into a finding, generated automatically instead.

Each entry is deliberately specific (a real replacement API / coding
pattern, plus the CWE it addresses) rather than generic "validate your
input" advice.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PatchAdvice:
    cwe: str
    title: str
    summary: str
    recommendation: str
    references: tuple


_ADVICE = {
    "stack-buffer-overflow": PatchAdvice(
        cwe="CWE-121",
        title="Stack-based Buffer Overflow",
        summary="An unbounded copy (strcpy/strcat/gets) writes attacker-"
                "controlled data into a fixed-size stack buffer with no "
                "length check, allowing the saved return address and "
                "stack canary to be overwritten.",
        recommendation=(
            "Replace strcpy()/strcat()/gets() with a bounded equivalent: "
            "snprintf(buf, sizeof(buf), \"%s\", src) or strlcpy(buf, src, "
            "sizeof(buf)) (or strncpy + explicit NUL-termination). Size "
            "every destination buffer check against sizeof(dst), never a "
            "value derived from the untrusted input itself, and compile "
            "with -fstack-protector-strong and -D_FORTIFY_SOURCE=2."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/121.html",
            "https://owasp.org/www-community/attacks/Buffer_overflow_attack",
        ),
    ),
    "off-by-one-overflow": PatchAdvice(
        cwe="CWE-193",
        title="Off-by-One Error",
        summary="A copy loop uses an inclusive bound (`i <= len`) against "
                "a fixed-size buffer, writing one byte past its end on "
                "inputs whose length equals the buffer's capacity.",
        recommendation=(
            "Use a strict `<` bound against `sizeof(dst) - 1`, reserving "
            "the final byte for the NUL terminator, e.g. "
            "`for (i = 0; i < sizeof(dst) - 1 && i < len; i++)` followed "
            "by `dst[i] = '\\0';`. Prefer strlcpy()/snprintf() over a "
            "hand-rolled loop wherever possible."
        ),
        references=("https://cwe.mitre.org/data/definitions/193.html",),
    ),
    "use-after-free": PatchAdvice(
        cwe="CWE-416",
        title="Use After Free",
        summary="A pointer is dereferenced after the memory it refers to "
                "has been freed, because a second (global/aliased) "
                "reference to the same allocation was never cleared.",
        recommendation=(
            "Set every pointer to NULL immediately after free() (`free(t); "
            "t = NULL;`), and audit for aliasing: if more than one "
            "variable can reference the same allocation, clear all of "
            "them or refactor to a single owning pointer. Consider a "
            "pool/arena allocator or reference counting for objects with "
            "shared lifetime, and build with -fsanitize=address in CI so "
            "any remaining UAF fails the test suite immediately."
        ),
        references=("https://cwe.mitre.org/data/definitions/416.html",),
    ),
    "format-string": PatchAdvice(
        cwe="CWE-134",
        title="Uncontrolled Format String",
        summary="Attacker-controlled data is passed as the *format* "
                "argument to a printf-family function, letting %n/%s/%x "
                "specifiers read or write arbitrary stack memory.",
        recommendation=(
            "Never pass a variable directly as a format string. Always "
            "use a constant format and pass the data as an argument: "
            "`printf(\"%s\", user_input);` instead of `printf(user_input);`. "
            "Enable `-Wformat -Wformat-security -Werror=format-security` "
            "so the compiler rejects non-literal format arguments."
        ),
        references=("https://cwe.mitre.org/data/definitions/134.html",),
    ),
    "integer-overflow-undersized-alloc": PatchAdvice(
        cwe="CWE-190",
        title="Integer Overflow to Buffer Overflow",
        summary="A multiplication feeding an allocation size (count * "
                "element_size) can wrap a fixed-width integer, producing "
                "an undersized allocation that a subsequent write-loop "
                "then overflows.",
        recommendation=(
            "Validate the multiplication before allocating: use "
            "__builtin_mul_overflow(count, size, &total) (or calloc(count, "
            "size), which performs this check internally) and reject the "
            "request if it overflows, rather than calling malloc(count * "
            "size) directly. Use size_t consistently and reject negative "
            "or absurdly large counts from untrusted input up front."
        ),
        references=("https://cwe.mitre.org/data/definitions/190.html",),
    ),
    "command-injection": PatchAdvice(
        cwe="CWE-78",
        title="OS Command Injection",
        summary="Untrusted input is concatenated into a shell command "
                "string passed to system()/popen(), letting shell "
                "metacharacters (`;`, `|`, `` ` ``, `$()`) inject "
                "arbitrary additional commands.",
        recommendation=(
            "Avoid invoking a shell at all: use execve()/posix_spawn() "
            "with an explicit argv array so arguments are never "
            "re-interpreted by a shell. If a shell is unavoidable, strictly "
            "allow-list the permitted characters/values for the untrusted "
            "field and reject anything else -- do not attempt to blocklist "
            "or escape shell metacharacters, which is error-prone."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ),
    ),
}

_SINK_TO_VULN_TYPE = {
    "strcpy": "stack-buffer-overflow",
    "strcat": "stack-buffer-overflow",
    "sprintf": "stack-buffer-overflow",
    "gets": "stack-buffer-overflow",
    "printf-nonconstant-fmt": "format-string",
    "system": "command-injection",
    "popen": "command-injection",
}


def advice_for_vuln_type(vuln_type: str) -> PatchAdvice:
    if vuln_type in _ADVICE:
        return _ADVICE[vuln_type]
    mapped = _SINK_TO_VULN_TYPE.get(vuln_type)
    if mapped:
        return _ADVICE[mapped]
    if vuln_type.startswith("unchecked-arith"):
        return _ADVICE["integer-overflow-undersized-alloc"]
    raise KeyError(f"No patch advice registered for vuln_type/sink_type '{vuln_type}'")
