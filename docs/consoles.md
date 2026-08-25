# Console presets

Console-specific loaders and processors are community Ghidra extensions,
managed out-of-band through `ghmcp ext` and referenced by preset in
`open_program(path=…, preset="psp")`. Extensions enter the classpath at launch,
so install/uninstall prints `restart required`.

## Flow for a new console

1. `ghmcp ext list` — inspect the registry.
2. `ghmcp ext install <id>` (offline by default; `--allow-download` fetches a
   release asset). Use `--allow-build` when no matching prebuilt zip exists
   (e.g. the Switch loader).
3. `ghmcp ext verify` / `ghmcp doctor` — prove the loader/language registered.
4. `open_program(path=…, preset="<console>")`.

The presets live in `src/ghmcp/extensions/presets.toml` (data only). A preset
names its `requires` extensions, a `loader_name` (resolved by class via
`LoaderService.getLoaderClassByName`), `loader_args`, `language`, `compiler`,
optional `image_base` (applied post-load via `Program.setImageBase`) and
`analysis` option overrides.

## Per-console notes

### PSP (Allegrex) — `preset="psp"`

Requires `kotcrab/ghidra-allegrex` (`ghmcp ext install allegrex`). Typical for
EBOOT.BIN / PRX. Set `preset="psp"` and the loader + Allegrex language are
applied; `image_base` defaults to `0x08804000`. Raw dumps: pass `language` and
`image_base` explicitly.

### Switch (NSO/NRO/KIP) — `preset="switch"`

Requires building `Adubbz/Ghidra-Switch-Loader` from source (`--allow-build`,
JDK 21). Loader picks the NSO/NRO/KIP format; language is AARCH64 v8A.

### PS2 (EE R5900) — `preset="ps2"`

Requires `chaoticgd/ghidra-emotionengine-reloaded` (`ghmcp ext install ee-reloaded`).
Loader `PS2 ELF`, language `MIPS:LE:32:R5900`.

### PS1 (psyq) — `preset="ps1"`

Requires `lab313ru/ghidra_psx_ldr`. Use for PSX-EXE / psyq builds.

### GameCube/Wii (DOL/REL) — `preset="gamecube"`

Requires `Cuyler36/Ghidra-GameCube-Loader`.

### N64 — `preset="n64"`

Requires `zeroKilo/N64LoaderWV`.

### Unity IL2CPP

Not an extension. Use `Il2CppDumper` output and apply it via `run_script`
(see `docs/architecture.md` escape-valve note) — `ghidra_scripts/` holds
helpers for common sweeps.

## Restart semantics

Because extension jars are appended to the classpath at launch, a running
server detects on-disk drift at the next `program_session(action="env")`/
`ghmcp doctor` and reports it. Always restart after an install or uninstall.
