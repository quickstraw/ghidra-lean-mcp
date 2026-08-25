# ghidra_scripts — MIPS-style HI16/LO16 pair harvesting (run via `run_script`).
#
#   run_script(kind="ghidra_script", path="ghidra_scripts/lui_pair_harvest.py",
#              program=<pid>, write=false)
#
# Scans MIPS `lui reg, HI16` -> (next) `ori/addiu reg, reg, LO16` pairings and
# prints a JSON line with each synthetic address (HI16<<16 | LO16). Run as one
# call so the whole sweep crosses into Java once. Requires a MIPS/PSP program.
# ruff: noqa: F821  # `currentProgram`, `listing`, `fm` come from the Ghidra engine.

import json

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

out = []
count = 0
for fn in fm.getFunctions(True):
    if fn.getBody() is None:
        continue
    body = fn.getBody()
    insn = listing.getInstructionAt(body.getMinAddress())
    while insn is not None and body.contains(insn.getAddress()):
        if str(insn.getMnemonicString()).lower() == "lui":
            try:
                hi = insn.getScalar(1)
            except BaseException:
                hi = None
            if hi is not None:
                nxt = listing.getInstructionAfter(insn.getAddress())
                if nxt is not None and body.contains(nxt.getAddress()):
                    nm = str(nxt.getMnemonicString()).lower()
                    if nm in ("ori", "addiu", "addi"):
                        try:
                            lo = nxt.getScalar(1)
                        except BaseException:
                            lo = None
                        if lo is not None:
                            address = ((int(hi.getValue()) & 0xFFFF) << 16) | (
                                int(lo.getValue()) & 0xFFFF
                            )
                            out.append(
                                {
                                    "lui_addr": int(insn.getAddress().getOffset()),
                                    "use_addr": int(nxt.getAddress().getOffset()),
                                    "use_mnemonic": nm,
                                    "address": address,
                                }
                            )
                            count += 1
        insn = listing.getInstructionAfter(insn.getAddress())
        if count >= 512:
            break
    if count >= 512:
        break

print("LUI_PAIRS_JSON:" + json.dumps({"count": count, "pairs": out}))
