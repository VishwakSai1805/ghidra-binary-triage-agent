# Automated ELF Binary Security Audit Report

**Generated:** 2026-11-04 18:13 UTC  
**Targets analyzed:** 6  
**Exploits automatically confirmed:** 6/6

This report was produced end-to-end by this repository's pipeline: static CFG/sink extraction (`analyzer/cfg_extractor.py`) finds the candidate bug, a heuristic generator (`triage/poc_generator.py`) synthesizes an input designed to trigger it, and an AddressSanitizer harness (`triage/asan_runner.py`) actually runs that input under a 5-second timeout to prove exploitability -- no finding below is a guess; every one is backed by a captured crash or an observed injected-command marker.

## Summary

| Benchmark | CWE | Vulnerability | Severity | Dynamic Verdict | Exploit Confirmed |
|---|---|---|---|---|---|
| `cve_sim_stack_overflow` | CWE-121 | Stack-based Buffer Overflow | high | CRASHED (stack-buffer-overflow) | ✅ |
| `cve_sim_heap_uaf` | CWE-416 | Use After Free | high | CRASHED (heap-use-after-free) | ✅ |
| `cve_sim_format_string` | CWE-134 | Uncontrolled Format String | high | CRASHED (SEGV) | ✅ |
| `cve_sim_integer_overflow` | CWE-190 | Integer Overflow to Buffer Overflow | high | CRASHED (heap-buffer-overflow) | ✅ |
| `cve_sim_command_injection` | CWE-78 | OS Command Injection | high | NO_CRASH | ✅ |
| `cve_sim_off_by_one` | CWE-193 | Off-by-One Error | high | CRASHED (stack-buffer-overflow) | ✅ |

## Findings

### 1. Stack-based Buffer Overflow (CWE-121) — `cve_sim_stack_overflow`

- **Location:** `benchmarks/cve_sim_stack_overflow.c:18`
- **Severity:** high
- **Dynamic verdict:** `CRASHED (stack-buffer-overflow)`
- **Exploit confirmed:** Yes ✅
- **ASan summary:** `stack-buffer-overflow ../../../../src/libsanitizer/asan/asan_interceptors.cpp:563 in strcpy`
- **Backtrace:** strcpy → vulnerable_copy → process_record → main → __libc_start_call_main → __libc_start_main_impl

**Description:** An unbounded copy (strcpy/strcat/gets) writes attacker-controlled data into a fixed-size stack buffer with no length check, allowing the saved return address and stack canary to be overwritten.

**Proof-of-concept:** 300-byte argv[1] overflowing a 64-byte stack buffer via strcpy()

  ```
  argv: ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA']
  ```

**Recommended fix:**

> Replace strcpy()/strcat()/gets() with a bounded equivalent: snprintf(buf, sizeof(buf), "%s", src) or strlcpy(buf, src, sizeof(buf)) (or strncpy + explicit NUL-termination). Size every destination buffer check against sizeof(dst), never a value derived from the untrusted input itself, and compile with -fstack-protector-strong and -D_FORTIFY_SOURCE=2.

**References:** <https://cwe.mitre.org/data/definitions/121.html>, <https://owasp.org/www-community/attacks/Buffer_overflow_attack>

### 2. Use After Free (CWE-416) — `cve_sim_heap_uaf`

- **Location:** `benchmarks/cve_sim_heap_uaf.c:37`
- **Severity:** high
- **Dynamic verdict:** `CRASHED (heap-use-after-free)`
- **Exploit confirmed:** Yes ✅
- **ASan summary:** `heap-use-after-free benchmarks/cve_sim_heap_uaf.c:39 in print_task`
- **Backtrace:** print_task → main → __libc_start_call_main → __libc_start_main_impl → free → retire_task

**Description:** A pointer is dereferenced after the memory it refers to has been freed, because a second (global/aliased) reference to the same allocation was never cleared.

**Proof-of-concept:** Deterministic UAF: task is freed then printed via the dangling g_last_task pointer regardless of input

  ```
  argv: ['poc-task-name']
  ```

**Recommended fix:**

> Set every pointer to NULL immediately after free() (`free(t); t = NULL;`), and audit for aliasing: if more than one variable can reference the same allocation, clear all of them or refactor to a single owning pointer. Consider a pool/arena allocator or reference counting for objects with shared lifetime, and build with -fsanitize=address in CI so any remaining UAF fails the test suite immediately.

**References:** <https://cwe.mitre.org/data/definitions/416.html>

### 3. Uncontrolled Format String (CWE-134) — `cve_sim_format_string`

- **Location:** `benchmarks/cve_sim_format_string.c:17`
- **Severity:** high
- **Dynamic verdict:** `CRASHED (SEGV)`
- **Exploit confirmed:** Yes ✅
- **ASan summary:** `SEGV ../../../../src/libsanitizer/asan/asan_interceptors_memintrinsics.h:37 in QuickCheckForUnpoisonedRegion`
- **Backtrace:** QuickCheckForUnpoisonedRegion → printf_common → vprintf → printf → log_message → main

**Description:** Attacker-controlled data is passed as the *format* argument to a printf-family function, letting %n/%s/%x specifiers read or write arbitrary stack memory.

**Proof-of-concept:** argv[1] used directly as printf()'s format string; %n/%s walk off the (empty) varargs list

  ```
  argv: ['%p %p %p %p %n %s %s']
  ```

**Recommended fix:**

> Never pass a variable directly as a format string. Always use a constant format and pass the data as an argument: `printf("%s", user_input);` instead of `printf(user_input);`. Enable `-Wformat -Wformat-security -Werror=format-security` so the compiler rejects non-literal format arguments.

**References:** <https://cwe.mitre.org/data/definitions/134.html>

### 4. Integer Overflow to Buffer Overflow (CWE-190) — `cve_sim_integer_overflow`

- **Location:** `benchmarks/cve_sim_integer_overflow.c:20`
- **Severity:** high
- **Dynamic verdict:** `CRASHED (heap-buffer-overflow)`
- **Exploit confirmed:** Yes ✅
- **ASan summary:** `heap-buffer-overflow benchmarks/cve_sim_integer_overflow.c:37 in main`
- **Backtrace:** main → __libc_start_call_main → __libc_start_main_impl → malloc → alloc_records → main

**Description:** A multiplication feeding an allocation size (count * element_size) can wrap a fixed-width integer, producing an undersized allocation that a subsequent write-loop then overflows.

**Proof-of-concept:** argv[1]=67108864 makes count*record_size wrap a 32-bit int to a near-zero allocation, which the loop then overflows while writing 67108864 elements

  ```
  argv: ['67108864']
  ```

**Recommended fix:**

> Validate the multiplication before allocating: use __builtin_mul_overflow(count, size, &total) (or calloc(count, size), which performs this check internally) and reject the request if it overflows, rather than calling malloc(count * size) directly. Use size_t consistently and reject negative or absurdly large counts from untrusted input up front.

**References:** <https://cwe.mitre.org/data/definitions/190.html>

### 5. OS Command Injection (CWE-78) — `cve_sim_command_injection`

- **Location:** `benchmarks/cve_sim_command_injection.c:22`
- **Severity:** high
- **Dynamic verdict:** `NO_CRASH`
- **Exploit confirmed:** Yes ✅

**Description:** Untrusted input is concatenated into a shell command string passed to system()/popen(), letting shell metacharacters (`;`, `|`, `` ` ``, `$()`) inject arbitrary additional commands.

**Proof-of-concept:** argv[1] breaks out of the intended command with ';' and appends a harmless marker echo to prove injection, rather than any destructive action

  ```
  argv: ['localhost; echo POC-MARKER-80f023c9 #']
  ```

**Recommended fix:**

> Avoid invoking a shell at all: use execve()/posix_spawn() with an explicit argv array so arguments are never re-interpreted by a shell. If a shell is unavoidable, strictly allow-list the permitted characters/values for the untrusted field and reject anything else -- do not attempt to blocklist or escape shell metacharacters, which is error-prone.

**References:** <https://cwe.mitre.org/data/definitions/78.html>, <https://owasp.org/www-community/attacks/Command_Injection>

### 6. Off-by-One Error (CWE-193) — `cve_sim_off_by_one`

- **Location:** `benchmarks/cve_sim_off_by_one.c:17`
- **Severity:** high
- **Dynamic verdict:** `CRASHED (stack-buffer-overflow)`
- **Exploit confirmed:** Yes ✅
- **ASan summary:** `stack-buffer-overflow benchmarks/cve_sim_off_by_one.c:24 in copy_label`
- **Backtrace:** copy_label → main → __libc_start_call_main → __libc_start_main_impl → copy_label

**Description:** A copy loop uses an inclusive bound (`i <= len`) against a fixed-size buffer, writing one byte past its end on inputs whose length equals the buffer's capacity.

**Proof-of-concept:** 40-byte argv[1] triggers the `i <= len` off-by-one bound check, overflowing a 32-byte stack buffer

  ```
  argv: ['BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB']
  ```

**Recommended fix:**

> Use a strict `<` bound against `sizeof(dst) - 1`, reserving the final byte for the NUL terminator, e.g. `for (i = 0; i < sizeof(dst) - 1 && i < len; i++)` followed by `dst[i] = '\0';`. Prefer strlcpy()/snprintf() over a hand-rolled loop wherever possible.

**References:** <https://cwe.mitre.org/data/definitions/193.html>
