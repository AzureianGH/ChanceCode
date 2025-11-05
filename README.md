# ChanceCode

ChanceCode is the backend toolkit that powers the CHance language toolchain. It consumes textual Chance bytecode (`.ccb`) produced by [`chancec`](https://github.com/AzureianGH/CEnhanced) and emits backend-specific artifacts such as assembly listings, object files, or binary modules (`.ccbin`) that can be embedded into `.cclib` libraries.

The project ships both a reusable library (headers under `include/cc`) and a command-line driver (`chancecodec`). Backends are pluggable and can be registered at runtime.

## Highlights
- Textual bytecode loader (`cc_load_file`) with structural validation, constant folding, and rich diagnostics.
- In-memory IR (`CCModule`) that separates globals, functions, instructions, and metadata for easy analysis.
- Optimisation hooks (`cc_module_optimize`) used by both the CLI and external tools.
- Backend registry with discovery helpers (`cc_backend_register`, `cc_backend_find`, `cc_backend_at`).
- Reference x86-64 backend supporting NASM-style and GAS/`.intel_syntax` assembly flavours, configurable ABI (Windows vs System V), and `--option` overrides.
- Binary serializer (`cc_module_write_binary`) that produces compact `.ccbin` blobs suitable for bundling inside `.cclib` archives.

## Repository Layout
- `include/cc/` — public headers for consumers (`backend.h`, `bytecode.h`, `diagnostics.h`, `loader.h`).
- `src/` — backend registry, IR utilities, diagnostics plumbing, textual loader, and CLI entrypoint.
- `backends/` — built-in backend implementations (currently `backend_x86.c`).
- `tests/` — sample `.ccb` inputs plus expected backend outputs wired into CTest.
- `docs/` — detailed architecture notes and design guides.

## Building
ChanceCode uses the same CMake preset workflow as the front-end:

```
# Configure + build (MinGW)
cmake --preset mingw-release
cmake --build --preset mingw-release

# Configure + build (Visual Studio 2022)
cmake --preset vs2022-release
cmake --build --preset vs2022-release

# Run the regression suite
ctest --preset mingw-release
```

`chancecodec` appears in the preset-specific build directory, for example `build/mingw-release/chancecodec.exe` on Windows. The helper scripts `build.bat` and `build.sh` mirror the preset flow.

## `chancecodec` CLI

```
chancecodec input.ccb \
	--backend x86 \
	--output output.asm \
	--option target-os=windows \
	--emit-ccbin output.ccbin
```

Important flags:
- `--backend <name>` — select a registered backend. Defaults to the first backend (`x86`) when omitted.
- `--list-backends` — enumerate available backends and exit.
- `--output <path>` — direct backend output to a file (stdout by default).
- `--emit-ccbin <path>` — write the binary module to disk; the backend run is optional when only this flag is provided.
- `--option key=value` — forward backend-specific switches (e.g. `target-os=linux`).
- `-O0|-O1|-O2` — enable IR optimisation passes before emission.

The bundled x86 backends recognise:
- `target-os=windows|linux` — choose between Win64 and System V ABIs.
- Select NASM syntax with `--backend x86` (default) or GAS `.intel_syntax` with `--backend x86-gas`.

Backends may expose additional keys via `--option`; the CLI simply forwards them.

## Integrating with `chancec`
`chancec` locates `chancecodec` automatically when both repositories sit side-by-side. You can also expose the executable via:
- `CHANCECODEC_CMD` or `CHANCECODEC` environment variables.
- `CHANCECODE_HOME` pointing at a directory that contains `chancecodec` or `build/.../chancecodec`.

When rolling your own tools, link against `chance_core` (from [`CEnhanced`](../CEnhanced)) or use the headers here directly to load modules and invoke backends.

## Writing a New Backend
1. Define a `CCBackend` struct with a unique `name`, `description`, and `emit` callback.
2. Implement the callback: it receives the `CCModule`, backend options, a diagnostic sink, and optional userdata. Emit your target artifact there.
3. Register the backend during startup (e.g. in `cc_register_builtin_backends`).
4. Add regression tests under `tests/` to cover the instructions and metadata you rely on. Update `tests/CMakeLists.txt` if new golden files are needed.

See `backends/backend_x86.c` for a complete reference that covers integers, floats, pointers, control flow, extern resolution, and string literal pooling.

## Testing
Run the suite with:

```
ctest --preset mingw-release --output-on-failure
```

The tests validate loader diagnostics, backend outputs (diffed against `tests/expected`), and `.ccbin` serialization.

## Contributing
Contributions that extend the bytecode format, add optimisation passes, or implement new backends are welcome. Please accompany changes with documentation updates in `docs/` and regression coverage in `tests/`.
