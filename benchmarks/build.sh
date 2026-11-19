#!/usr/bin/env bash
# Builds every cve_sim_*.c benchmark in three flavors into ../build/:
#   <name>.elf           - stripped, no debug symbols, -O0, no sanitizer
#                            (realistic "found in the wild" triage target)
#   <name>_dbg.elf       - with -g debug symbols, no sanitizer
#                            (used by the CFG extractor's symbol-aware mode)
#   <name>_asan.elf      - with -fsanitize=address -g, used by the
#                            ASan crash-verification harness (triage/asan_runner.py)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"
mkdir -p "${BUILD_DIR}"

CFLAGS_COMMON="-fno-stack-protector -no-pie -w"

for src in "${SCRIPT_DIR}"/cve_sim_*.c; do
    name="$(basename "${src}" .c)"
    echo "== building ${name} =="

    # 1. stripped release build, no symbols
    gcc ${CFLAGS_COMMON} -O0 -o "${BUILD_DIR}/${name}.elf" "${src}"
    strip --strip-all "${BUILD_DIR}/${name}.elf"

    # 2. debug build with symbols (same vulnerability, easier to validate
    #    the CFG extractor's function/line attribution against)
    gcc ${CFLAGS_COMMON} -O0 -g -o "${BUILD_DIR}/${name}_dbg.elf" "${src}"

    # 3. ASan build used purely for dynamic PoC verification
    gcc ${CFLAGS_COMMON} -O0 -g -fsanitize=address -fno-omit-frame-pointer \
        -o "${BUILD_DIR}/${name}_asan.elf" "${src}"
done

echo "Built $(ls "${BUILD_DIR}"/*.elf | wc -l) binaries into ${BUILD_DIR}"
