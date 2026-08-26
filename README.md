# ghidra-headless-mcp

A lean, headless Ghidra MCP server for reverse engineering video games.
It exposes a small, purpose-built tool catalog (19 tools + a `health` diagnostic)
that covers tools that are used extensively for modding or reverse engineering games.

## Why

After using Ghidra in several projects, I noticed that only a few tools
were being used consistently. The other servers I used were too general
and gave access to too many tools. Having >200 tools that were never used was
bloating the context for no reason, so these tools were culled.

## Install

Needs Python 3.13+ and a Ghidra install (`GHIDRA_INSTALL_DIR`, or the
`lastrun` file, or `install_dir=`).

```bash
pip install .            # or: uv sync
export GHIDRA_INSTALL_DIR=/path/to/ghidra
ghmcp serve              # stdio transport (default)
ghmcp serve --transport http --port 8080
```

`ghmcp serve --fake` runs against the in-memory fake backend (no JVM, no
Ghidra) — useful for smoke-testing a client without a Ghidra install.

## Tool catalog (19)

Read core: `open_program`, `program_session`, `decompile`, `disassemble`,
`read_memory` · Anchoring/nav: `xrefs`, `find_symbols`, `find_strings`,
`call_graph` · Search/escape: `search_binary`, `run_script` · Annotation
(writable sessions): `rename`, `set_prototype`, `types`, `set_comment` ·
Game specials: `memory_map`, `diff_programs`, `analysis`. Plus `health`.

Full schemas are generated into [`docs/tools.md`](docs/tools.md) with
`ghmcp docs`.

## Architecture

```
tools/      MCP surface: params model -> service call -> result (summary + structured)
services/   use-case logic; plain models only; no Ghidra types in signatures
ghidra/     adapters: the only place Ghidra program/listing/decompiler APIs are touched
runtime/    JVM launch, executor, sessions, project cache, transactions, decompiler pool
platform    config, errors, targets, format, telemetry, registry
```

Enforced by import-linter: `tools -> services -> ghidra -> runtime -> platform`,
never upward. Ghidra/JPype imports are legal only in `ghidra/` and `runtime/`,
so the whole tool + service layer is testable without a Ghidra install.

See [`docs/architecture.md`](docs/architecture.md) for the response contract,
task policy and performance design, and
[`docs/consoles.md`](docs/consoles.md) for per-console presets.

## Consoles

Loader/processor extensions are managed out-of-band through `ghmcp ext`:

```bash
ghmcp ext list
ghmcp ext install allegrex       # PSP (offline by default; --allow-download)
ghmcp ext verify
ghmcp doctor
```

Then `open_program(path=…, preset="psp")`. Extensions enter the classpath at
launch, so install/uninstall prints `restart required`.

## Testing

```bash
uv run ruff check src tests
uv run import-linter --config pyproject.toml
uv run pytest tests/unit tests/contract          # no Ghidra needed (fake backend)
uv run pytest -m live tests/live                 # needs GHIDRA_INSTALL_DIR
uv run pytest -m perf tests/perf                 # §5.5 perf gates
```

## License

MIT. See [LICENSE](LICENSE).
