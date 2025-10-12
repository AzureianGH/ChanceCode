# ChanceCode

ChanceCode is an intermediate compiler that translates ChanceCode bytecode (CC bytecode) into backend-specific artifacts. It is designed to sit between the front-end in `CEnhanced` and multiple code generation backends.

## Features

- Textual CC bytecode loader with validation.
- Pluggable backend architecture via `cc_backend_register`.
- Reference x86-64 backend that emits NASM-style assembly.
- Command-line driver `chancecodec` with backend discovery.

## Building

Use CMake to configure and build the project. Example (Windows, with Ninja):

```
cmake -S ChanceCode -B ChanceCode/build -G "Ninja"
cmake --build ChanceCode/build --config Release
ctest --test-dir ChanceCode/build --output-on-failure
```

The generated binary `chancecodec` lives under the configured build directory (e.g. `ChanceCode/build/Release/chancecodec.exe`).

## Usage

```
chancecodec <input.ccb> --backend x86 --output output.asm
```

Flags:

- `--backend <name>` – selects a backend (defaults to the first registered backend).
- `--output <path>` – writes backend output to the given path. When omitted, output is printed to stdout.
- `--option key=value` – forwards arbitrary key/value options to the backend.
- `--list-backends` – enumerates available backends.

## Adding a Backend

1. Implement an emitter function matching `CCBackendEmitFn`. The function receives a `CCModule`, `CCBackendOptions`, and a diagnostic sink.
2. Call `cc_backend_register` with a `CCBackend` instance (typically in a file under `backends/`).
3. Export the registration routine via `cc_register_builtin_backends` so the CLI discovers it.
4. Optionally add tests under `tests/` to exercise the new backend.

Refer to `backends/backend_x86.c` for a concrete implementation covering arithmetic, local storage, branching, and zero-argument calls.
