# ghmcp architecture

This document is steady-state design context. It follows the implementation
plan's §4 and §5; the module map and step-by-step history live there.

## Layers and the dependency rule

```
tools/      MCP surface: params model -> service call -> CallToolResult
services/   use-case logic; plain models only; no Ghidra types in signatures
ghidra/     adapters: the only place Ghidra program/listing/decompiler APIs are touched
runtime/    JVM launch, executor, sessions, project cache, transactions, decompiler pool
platform    config, errors, targets, format, telemetry, registry
```

Enforced by import-linter: `tools -> services -> ghidra -> runtime -> platform`,
never upward. **Ghidra/JPype imports are allowed in `ghidra/` and `runtime/`
only** and are forbidden in `tools/`, `services/` and the platform modules.
That is what keeps the whole tool + service layer testable with no Ghidra
install: `fake/` implements the same adapter protocol and the contract test
asserts method-set parity between the real and fake adapters.

## The adapter protocol

`ghidra/protocols.py` declares `GhidraAdapter` — lifecycle, read, write and
game-special methods with plain-model signatures. `ghidra/backend.py` (real)
and `fake/adapter.py` (CI) implement it; `services/` consume it. Adding a
backend capability means extending the protocol, implementing it in `ghidra/`,
stubbing it in `fake/`, and letting the parity test catch drift.

## The response contract

Every tool returns a `CallToolResult` with exactly one `TextContent` summary
block plus `structured_content` that validates against a published
`output_schema`. This is the §0.4 split: a compact summary for the prompt and
the full structured payload for tooling. The wrapper is built by the registry
from a declarative `ToolSpec`; the real service runs on a JVM worker.

Because `func_metadata.convert_result` passes a returned `CallToolResult`
through unchanged, the registry sets the wrapper's return annotation to the
result model (so `output_schema` is published) while the body returns
`CallToolResult`. Result models therefore must not define field aliases.

Pagination is uniform: `offset`/`limit` in, `truncated` + `next_offset` out,
handled by the shared `platform.format.page` collector (which reads one row
past the page so `more` is exact, including the boundary case of exactly
`limit + 1` rows).

## The task policy

Only `open_program(analyze="full")` and `analysis(action="run")` are
asynchronous — they return a task id and are polled by `analysis(action="status")`.
Every other tool is synchronous with a per-spec timeout and returns partial
results plus `notes[]` on timeout. There is no open-ended socket and no hidden
task.

## Performance design

- One process, one JVM, started once in the MCP lifespan (`warm_jvm=True`,
  the default). With `warm_jvm=False` the boot is deferred to the first
  adapter call (`_bootstrap`); `JvmManager.start()` is thread-safe and
  idempotent, so the boot can happen on a worker thread.
- Ghidra work runs on a long-lived JVM worker pool.
- `DecompInterface` methods are `synchronized` and each instance owns a native
  decompiler, so the decompiler pool is a requirement for concurrency, not an
  optimisation. The pool caches formatted results keyed by
  `(pid, entry, modification_number)`; any mutation bumps the modification
  number and invalidates naturally.
- JPype crossing discipline: never element-by-element for large sets — use
  `Memory.getBytes(addr, byte[])` then `bytes(...)`, `Memory.findBytes(..., masks)`
  for byte search, and Ghidra's own filtered iterators pushed to the limit.
- The escape valve: if a sweep is still Python-bound, ship it as a Ghidra script
  in `ghidra/ghidra_scripts/` and run it through `run_script` (Java-side loop,
  one crossing for the JSON result).

## Where the write paths live

Every program access is serialized by the per-session RWLock
(`runtime/session.py`): read tools (`decompile`, `disassemble`, xrefs,
symbols, search, memory reads, snapshots, diffs) acquire it shared; mutations,
`save` and `close` acquire it exclusively, with a timeout
(`program_lock_timeout`, default 30s) that raises `BusyError` instead of
hanging a worker. Lock order is always program-lock → decompiler lease, and a
two-program diff locks both pids in pid order — both rules make deadlocks
impossible. `decompile` holds the read lock per function (wave members), so a
write can interleave between functions of a large batch, and the analysis task
deliberately takes no lock — analysis is incremental under Ghidra's own locks
and stalling all reads for minutes is worse; `close()` drains analysis tasks
first in `shutdown()`.

`run_script` always takes the exclusive lock: a script body can mutate via the
flat API (it may open its own transaction), so a possible mutator must never
race concurrent readers; a writable session additionally wraps each script
call in a transaction, and `write=true` is gated at the service layer.
`read_memory` and `diff_bytes` share one read helper (`game.read_bytes`), so a
read failure surfaces as the same `GhmcpError` with the same hint from both
tools.

Writes (`rename`, `set_prototype`, `types`, `set_comment`, `memory_map
create/rebase`) run inside exactly one transaction (`runtime/txn.py`) and roll
back on error — the txn shim supports both Ghidra 11.x int handles and the
12.x `DomainObjectTransaction` objects. They are gated on a writable session
(`open_program(writable=true)`); a write to a read-only session is a
`ReadOnly` error. `analysis(action="run")` is the exception — it runs without
the writable gate because open_program auto-analyses read-only sessions too.
