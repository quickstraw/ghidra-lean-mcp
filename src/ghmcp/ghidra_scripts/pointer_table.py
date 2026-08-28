# ghidra_scripts — pointer-table harvest (run via `run_script`).
#
#   run_script(kind="ghidra_script", path="ghidra_scripts/pointer_table.py",
#              args=["0x08840000", "0x08840100"], program=<pid>, write=false)
#
# Reads a memory region as a table of little-endian 32-bit pointers and prints a
# JSON line with each entry address and its target (resolved to a symbol when the
# target is a function/label). Use for localization/string-table hunting.
# ruff: noqa: F821  # Ghidra script API names come from the script engine.

import json

args = list(getScriptArgs())  # supplied by the runner's args list
start = int(args[0], 0) if len(args) > 0 else int(currentProgram.getImageBase().getOffset())
end = int(args[1], 0) if len(args) > 1 else start + 0x4000

memory = currentProgram.getMemory()
space = currentProgram.getAddressFactory().getDefaultAddressSpace()
symtab = currentProgram.getSymbolTable()

out = []
size = 4
for addr in range(start, end - size + 1, size):
    try:
        raw = memory.getInt(space.getAddress(addr))
    except BaseException:
        continue
    target = raw & 0xFFFFFFFF
    label = None
    sym = symtab.getPrimarySymbol(space.getAddress(target)) if hasattr(symtab, "getPrimarySymbol") else None
    if sym is None and hasattr(symtab, "getSymbol"):
        sym = symtab.getSymbol(space.getAddress(target))
    if sym is not None:
        label = str(sym.getName())
    out.append({"addr": addr, "pointer": target, "symbol": label})

print("PTR_TABLE_JSON:" + json.dumps({"count": len(out), "entries": out}))
