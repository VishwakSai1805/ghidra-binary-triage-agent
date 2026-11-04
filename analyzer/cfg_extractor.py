#!/usr/bin/env python3
"""
analyzer/cfg_extractor.py

Static ELF binary analyzer for Milestone 1 of the ELF Binary Vulnerability
Triage toolkit.

Given a (possibly stripped) x86-64 ELF binary, this module:

  1. Parses the ELF with pyelftools (sections, symbol table, PLT relocations).
  2. Disassembles .text with Capstone.
  3. Recovers function boundaries -- from the symbol table when present,
     or via an `endbr64` / prologue heuristic when the binary is stripped.
  4. Builds a per-function Control Flow Graph (CFG) with networkx, where
     nodes are basic blocks and edges are fallthrough/branch/call-return
     control transfers.
  5. Flags "dangerous sink" calls (strcpy, sprintf, system, gets, strcat,
     memcpy, unchecked malloc-size arithmetic) and reports the CFG path
     from the function entry to each sink.

This is intentionally a lightweight, dependency-minimal static analyzer
(no full data-flow/taint analysis) -- it is a triage aid, not a proof of
exploitability. Proof of exploitability is established dynamically in
Milestone 2 (triage/asan_runner.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import networkx as nx
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

# Call targets considered dangerous "sinks" for memory-safety / injection bugs.
DANGEROUS_SINKS = {
    "strcpy": "stack/heap overflow (unbounded copy)",
    "strcat": "stack/heap overflow (unbounded concat)",
    "sprintf": "stack/heap overflow (unbounded format write)",
    "gets": "stack overflow (unbounded stdin read)",
    "system": "command injection (shell invocation)",
    "popen": "command injection (shell invocation)",
    "exec": "command injection (exec family)",
    "memcpy": "potential overflow if size is attacker-influenced",
    "vsprintf": "stack/heap overflow (unbounded format write)",
    "printf": "format-string vulnerability if fmt is non-constant",
}

# Allocation functions used for the "unchecked malloc arithmetic" heuristic.
ALLOC_FUNCS = {"malloc", "calloc", "realloc"}

# x86-64 conditional/unconditional jump mnemonics used for CFG edges.
JUMP_MNEMONICS = {
    "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge",
    "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp", "jcxz", "jecxz",
    "jrcxz",
}
COND_JUMP_MNEMONICS = JUMP_MNEMONICS - {"jmp"}


@dataclass
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    call_target: Optional[int] = None


@dataclass
class BasicBlock:
    start: int
    end: int  # address just past the last instruction
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


@dataclass
class Sink:
    address: int
    function: str
    call_target_name: str
    sink_type: str
    severity: str
    path_from_entry: List[int]


@dataclass
class FunctionCFG:
    name: str
    address: int
    size: int
    blocks: Dict[int, BasicBlock]
    graph: nx.DiGraph
    sinks: List[Sink]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "address": hex(self.address),
            "size": self.size,
            "num_basic_blocks": self.graph.number_of_nodes(),
            "num_edges": self.graph.number_of_edges(),
            "sinks": [
                {
                    "address": hex(s.address),
                    "call_target": s.call_target_name,
                    "sink_type": s.sink_type,
                    "severity": s.severity,
                    "path_from_entry": [hex(a) for a in s.path_from_entry],
                }
                for s in self.sinks
            ],
        }


class ELFBinary:
    """Thin wrapper around pyelftools exposing what the CFG extractor needs:
    the raw .text bytes, defined-function symbols, and a PLT-address ->
    imported-symbol-name map (so calls to libc sinks resolve by name even
    though the real implementation lives in a separate shared object).
    """

    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "rb")
        self.elf = ELFFile(self._fh)
        self.text_addr, self.text_bytes = self._read_text()
        self.functions = self._read_function_symbols()
        self.plt_map = self._read_plt_map()

    def close(self):
        self._fh.close()

    def _read_text(self) -> Tuple[int, bytes]:
        sec = self.elf.get_section_by_name(".text")
        if sec is None:
            raise ValueError(f"No .text section in {self.path}")
        return sec["sh_addr"], sec.data()

    def _read_function_symbols(self) -> Dict[int, Tuple[str, int]]:
        """address -> (name, size) for STT_FUNC symbols with code, from
        .symtab. Empty dict for a stripped binary (no .symtab)."""
        funcs: Dict[int, Tuple[str, int]] = {}
        symtab = self.elf.get_section_by_name(".symtab")
        if symtab is None:
            return funcs
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC":
                continue
            addr = sym["st_value"]
            size = sym["st_size"] or 0
            if addr == 0:
                continue
            if addr < self.text_addr or addr >= self.text_addr + len(self.text_bytes):
                continue
            funcs[addr] = (sym.name, size)
        return funcs

    def _read_plt_map(self) -> Dict[int, str]:
        """Resolve PLT stub addresses to imported symbol names via
        .rela.plt + .dynsym, so `call 0x401030` in the disassembly can be
        reported as `call strcpy@plt` even for a stripped binary."""
        plt_map: Dict[int, str] = {}
        dynsym = self.elf.get_section_by_name(".dynsym")
        if dynsym is None:
            return plt_map

        got_plt = self.elf.get_section_by_name(".got.plt")
        plt_sections = [
            s for s in (self.elf.get_section_by_name(".plt"),
                        self.elf.get_section_by_name(".plt.sec"))
            if s is not None
        ]

        for sec_name in (".rela.plt", ".rela.dyn"):
            rela = self.elf.get_section_by_name(sec_name)
            if rela is None or not isinstance(rela, RelocationSection):
                continue
            for reloc in rela.iter_relocations():
                sym_idx = reloc["r_info_sym"]
                if sym_idx == 0:
                    continue
                sym = dynsym.get_symbol(sym_idx)
                if not sym or not sym.name:
                    continue
                plt_map[reloc["r_offset"]] = sym.name  # GOT slot -> name

        # Map each PLT stub (in both the legacy .plt and the IBT-hardened
        # .plt.sec gcc/ld emit on modern toolchains) to the GOT slot -- and
        # thus the imported symbol name -- it jumps through, by
        # disassembling the stub itself and resolving its RIP-relative
        # memory operand.
        if got_plt is not None:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            for plt_sec in plt_sections:
                data = plt_sec.data()
                base = plt_sec["sh_addr"]
                stub_start = base
                for insn in md.disasm(data, base):
                    if insn.mnemonic == "endbr64":
                        stub_start = insn.address  # start of this PLT stub
                    if insn.mnemonic == "jmp" and insn.operands:
                        op = insn.operands[0]
                        if op.type == 3:  # X86_OP_MEM via RIP-relative
                            target = insn.address + insn.size + op.mem.disp
                            name = plt_map.get(target)
                            if name:
                                # call instructions target the stub's first
                                # byte (its endbr64), not this jmp
                                plt_map[stub_start] = name
        return plt_map

    def resolve_call_target_name(self, target: int) -> str:
        if target in self.plt_map:
            return self.plt_map[target]
        if target in self.functions:
            return self.functions[target][0]
        return hex(target)


def _discover_function_starts(binary: ELFBinary) -> List[Tuple[int, str, int]]:
    """Return sorted (address, name, size) tuples for every function to
    analyze. Uses .symtab if present; otherwise falls back to scanning
    .text for the `endbr64` CET prologue marker gcc emits at the start of
    every function it compiles with -fcf-protection (the default on
    modern Ubuntu/Debian toolchains), which also happens to be exactly
    what's needed to recover function boundaries in a stripped binary.
    """
    if binary.functions:
        funcs = sorted(
            (addr, name, size) for addr, (name, size) in binary.functions.items()
        )
        return funcs

    ENDBR64 = b"\xf3\x0f\x1e\xfa"
    starts = []
    data = binary.text_bytes
    offset = 0
    idx = 0
    while True:
        idx = data.find(ENDBR64, offset)
        if idx == -1:
            break
        starts.append(binary.text_addr + idx)
        offset = idx + 4
    starts = sorted(set(starts))
    funcs = []
    for i, addr in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else binary.text_addr + len(data)
        funcs.append((addr, f"sub_{addr:x}", end - addr))
    return funcs


def _disassemble_range(binary: ELFBinary, start: int, size: int) -> List[Instruction]:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    offset = start - binary.text_addr
    code = binary.text_bytes[offset:offset + size]
    out = []
    for insn in md.disasm(code, start):
        call_target = None
        if insn.mnemonic == "call" and insn.operands:
            op = insn.operands[0]
            if op.type == X86_OP_IMM:
                call_target = op.imm
        out.append(Instruction(insn.address, insn.size, insn.mnemonic, insn.op_str, call_target))
    return out


def _parse_branch_target(op_str: str) -> Optional[int]:
    try:
        return int(op_str, 16)
    except ValueError:
        return None


def _build_cfg(func_start: int, func_end: int, instructions: List[Instruction]) -> Tuple[Dict[int, BasicBlock], nx.DiGraph]:
    """Split a linear instruction stream into basic blocks at branch/call/
    ret boundaries and at incoming branch targets, then wire up edges."""
    if not instructions:
        return {}, nx.DiGraph()

    leaders = {instructions[0].address}
    by_addr = {insn.address: insn for insn in instructions}

    for insn in instructions:
        next_addr = insn.address + insn.size
        if insn.mnemonic in JUMP_MNEMONICS:
            target = _parse_branch_target(insn.op_str)
            if target is not None and func_start <= target < func_end:
                leaders.add(target)
            if next_addr in by_addr:
                leaders.add(next_addr)  # fallthrough target of a conditional jump
        elif insn.mnemonic == "ret":
            if next_addr in by_addr:
                leaders.add(next_addr)

    sorted_leaders = sorted(leaders)
    blocks: Dict[int, BasicBlock] = {}
    for i, leader in enumerate(sorted_leaders):
        block_end = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else func_end
        insns = [insn for insn in instructions if leader <= insn.address < block_end]
        if not insns:
            continue
        blocks[leader] = BasicBlock(start=leader, end=block_end, instructions=insns)

    graph = nx.DiGraph()
    for leader, block in blocks.items():
        graph.add_node(leader)

    sorted_block_starts = sorted(blocks.keys())
    for i, leader in enumerate(sorted_block_starts):
        block = blocks[leader]
        last = block.instructions[-1]
        next_block_start = sorted_block_starts[i + 1] if i + 1 < len(sorted_block_starts) else None

        if last.mnemonic == "jmp":
            target = _parse_branch_target(last.op_str)
            if target is not None and target in blocks:
                graph.add_edge(leader, target)
                block.successors.append(target)
        elif last.mnemonic in COND_JUMP_MNEMONICS:
            target = _parse_branch_target(last.op_str)
            if target is not None and target in blocks:
                graph.add_edge(leader, target)
                block.successors.append(target)
            if next_block_start is not None:
                graph.add_edge(leader, next_block_start)
                block.successors.append(next_block_start)
        elif last.mnemonic == "ret":
            pass  # terminal node, no intraprocedural successor
        else:
            if next_block_start is not None:
                graph.add_edge(leader, next_block_start)
                block.successors.append(next_block_start)

    return blocks, graph


_REG_ALIAS_GROUPS = [
    {"rax", "eax", "ax", "al"}, {"rbx", "ebx", "bx", "bl"},
    {"rcx", "ecx", "cx", "cl"}, {"rdx", "edx", "dx", "dl"},
    {"rsi", "esi", "si"}, {"rdi", "edi", "di"},
    {"rbp", "ebp"}, {"rsp", "esp"},
]
_REG_ALIAS_LOOKUP = {r: g for g in _REG_ALIAS_GROUPS for r in g}


def _reg_last_set_is_rip_lea(preceding: List[Instruction], reg: str, _depth: int = 0) -> bool:
    """Scan backward through `preceding` for the most recent instruction
    that writes to `reg` (or a sub-register alias of it). Returns True iff
    that write is, directly or through a simple `mov dst, src` chain,
    `lea <reg>, [rip + disp]` -- i.e. the register ultimately holds the
    address of a compile-time-constant string/data literal rather than a
    value derived from a variable (parameter, heap/stack read, etc.).
    """
    if _depth > 4:
        return False  # bound the chase through register-to-register moves
    aliases = _REG_ALIAS_LOOKUP.get(reg, {reg})
    for i, insn in enumerate(reversed(preceding)):
        dest = insn.op_str.split(",")[0].strip()
        if dest not in aliases:
            continue
        if insn.mnemonic == "lea" and "rip" in insn.op_str:
            return True
        if insn.mnemonic == "mov" and "," in insn.op_str:
            src = insn.op_str.split(",", 1)[1].strip()
            if src in _REG_ALIAS_LOOKUP:
                remaining = preceding[: len(preceding) - 1 - i]
                return _reg_last_set_is_rip_lea(remaining, src, _depth + 1)
        return False  # written by something else (memory load, arith, call result...)
    return False  # no write found; be conservative and treat as non-constant


def _detect_sinks(binary: ELFBinary, func_name: str, func_start: int,
                   blocks: Dict[int, BasicBlock], graph: nx.DiGraph) -> List[Sink]:
    sinks: List[Sink] = []
    sorted_leaders = sorted(blocks.keys())

    # Track which blocks contain an imul/mul feeding an allocation call,
    # for the "unchecked malloc arithmetic" heuristic.
    arithmetic_blocks = set()
    for leader in sorted_leaders:
        for insn in blocks[leader].instructions:
            if insn.mnemonic in ("imul", "mul"):
                arithmetic_blocks.add(leader)

    for leader in sorted_leaders:
        block = blocks[leader]
        for call_idx, insn in enumerate(block.instructions):
            if insn.mnemonic != "call" or insn.call_target is None:
                continue
            name = binary.resolve_call_target_name(insn.call_target)
            base_name = name.split("@")[0]

            sink_type = None
            severity = "high"
            if base_name == "printf":
                # printf's format pointer is argument 1 (rdi). If the last
                # write to rdi before this call is `lea reg, [rip+disp]`
                # (a string-literal address), the format is a compile-time
                # constant and this call is safe; otherwise rdi was loaded
                # from a variable/parameter and the format string -- and
                # therefore the whole call -- is attacker-influenced.
                fmt_is_constant = _reg_last_set_is_rip_lea(
                    block.instructions[:call_idx], "rdi"
                )
                if not fmt_is_constant:
                    sink_type = "printf-nonconstant-fmt"
                    severity = "high"
            elif base_name in DANGEROUS_SINKS:
                sink_type = base_name
                severity = "high" if base_name in (
                    "strcpy", "strcat", "sprintf", "gets", "system", "popen", "exec", "vsprintf",
                ) else "medium"
            elif base_name in ALLOC_FUNCS:
                # flag only if an integer multiply happened earlier in this
                # block or a predecessor block (simple same-function reach check)
                reachable_arith = arithmetic_blocks & (
                    set(nx.ancestors(graph, leader)) | {leader}
                )
                if reachable_arith:
                    sink_type = f"unchecked-arith-{base_name}"
                    severity = "medium"

            if sink_type is None:
                continue

            try:
                path = nx.shortest_path(graph, func_start, leader)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                path = [leader]

            sinks.append(
                Sink(
                    address=insn.address,
                    function=func_name,
                    call_target_name=name,
                    sink_type=sink_type,
                    severity=severity,
                    path_from_entry=path,
                )
            )
    return sinks


def analyze_binary(path: str) -> List[FunctionCFG]:
    binary = ELFBinary(path)
    try:
        results = []
        for addr, name, size in _discover_function_starts(binary):
            if size <= 0:
                continue
            instructions = _disassemble_range(binary, addr, size)
            blocks, graph = _build_cfg(addr, addr + size, instructions)
            sinks = _detect_sinks(binary, name, addr, blocks, graph)
            results.append(FunctionCFG(name=name, address=addr, size=size,
                                        blocks=blocks, graph=graph, sinks=sinks))
        return results
    finally:
        binary.close()


def analyze_to_report(path: str) -> dict:
    functions = analyze_binary(path)
    all_sinks = [s for f in functions for s in f.sinks]
    return {
        "binary": path,
        "num_functions": len(functions),
        "num_sinks": len(all_sinks),
        "functions": [f.to_dict() for f in functions],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Static ELF CFG extractor and sink detector")
    parser.add_argument("binary", help="path to the ELF binary to analyze")
    parser.add_argument("-o", "--output", help="write JSON report to this path")
    args = parser.parse_args(argv)

    report = analyze_to_report(args.binary)
    text = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
