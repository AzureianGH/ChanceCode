# ChanceCode

ChanceCode is the backend toolkit for the CHance toolchain. It loads textual Chance bytecode (`.ccb`), applies optimizations over an in-memory IR (`CCModule`), and emits assembly, objects, or binary modules (`.ccbin`) through pluggable backends.

The command-line driver is `chancecodec` (often referred to as the ChanceCode compiler). It shares the same backend registry used by library consumers.

## Highlights
- Loader with structural validation, constant folding, and diagnostics.
- In-memory IR for globals, externs, functions, and instructions.
- Binary serializer for `.ccbin` modules.
- Pluggable backends with a reference x86-64 and ARM64 implementation.

## Repository Layout
- `include/cc/` public headers (`backend.h`, `bytecode.h`, `diagnostics.h`, `loader.h`).
- `src/` core loader, IR utilities, and CLI.
- `backends/` built-in backend implementations.
- `tests/` `.ccb` samples and regression cases.

## Building
```
cmake --preset mingw-release
cmake --build --preset mingw-release

ctest --preset mingw-release
```

The helper scripts `build.sh` and `build.bat` mirror the preset workflow.

## chancecodec CLI
```
chancecodec input.ccb \
  --backend arm64-macos \
  --output output.s \
  --option target-os=macos \
  --emit-ccbin output.ccbin
```

Key flags:
- `--backend <name>` selects a backend (default: first registered backend).
- `--list-backends` lists available backends.
- `--output <path>` writes backend output to a file.
- `--emit-ccbin <path>` writes a `.ccbin` module.
- `--option key=value` passes backend-specific options.
- `-O0|-O1|-O2|-O3` enables IR optimization passes.

## Specs
See the full bytecode specification in [SPEC.md](SPEC.md).

## Contact
- Discord: Azureian
- Email: me@nhornby.com
### 4.1 File Header
- Magic: `CCBIN` (5 bytes)
- Format version: `u16` (current writer emits `4`)
- Module version: `u32` (matches `ccbytecode` version)

### 4.2 Strings and Arrays
- Strings are stored as `u32 length` followed by raw bytes.
- Type arrays are sequences of 32-bit `CCValueType` values.

### 4.3 Globals
For each global:
1. Name (string)
2. Type (`i32`)
3. `is_const` (`u8`)
4. `is_extern` (`u8`, format >=2)
5. `is_hidden` (`u8`, format >=3)
6. Alignment (`u32`)
7. Section (string, nullable)
8. Init kind (`u8`): `none|int|float|string|bytes|ptrs`
9. Init payload:
   - `int`: `u64`
   - `float`: `u64` bits
   - `string`: `u32 length` + bytes
   - `bytes`: `u32 length` + bytes
   - `ptrs`: `u32 count` + string table

### 4.4 Externs
For each extern:
1. Name (string)
2. Return type (`i32`)
3. `is_varargs` (`u8`)
4. `is_noreturn` (`u8`)
5. Param count (`u32`)
6. Param types array

### 4.5 Functions
For each function:
1. Name (string)
2. Return type (`i32`)
3. `is_varargs` (`u8`)
4. `is_noreturn` (`u8`)
5. Section (string, nullable)
6. Param count (`u32`) + param types array
7. Local count (`u32`) + local types array
8. Instruction count (`u32`) + instruction table

### 4.6 Instruction Encoding
Each instruction:
- Kind (`u8`)
- Line (`u32`)
- Payload by kind (mirrors the textual form)

Notable payloads:
- `const`: type, unsigned flag, null flag, then value (u32/u64)
- `const_string`: length + bytes + label hint string
- `call`/`call_indirect`: symbol string (empty allowed for indirect), return type, arg count, arg types, varargs flag

### 4.7 Format Version Notes
- **Format 1**: globals do not include `is_extern` or `is_hidden`.
- **Format 2**: adds `is_extern` for globals.
- **Format 3**: adds `is_hidden` for globals.
- **Format 4**: current writer version; payload layout matches v3.

## CC1
Status and support:
- Legacy textual format; the current loader rejects `ccbytecode 1`.
- If support is reintroduced, treat CC1 as a strict subset of CC2.

Textual (`.ccb`) rules:
- Header: `ccbytecode 1`.
- No `.file` or `.loc` directives.
- Same instruction set and directives as CC2 minus debug directives.

Binary (`.ccbin`) expectations:
- CC1-era modules correspond to earlier `.ccbin` format versions where globals do not carry `is_extern` or `is_hidden` flags (format version 1).

## CC2
Status and support:
- Supported by the current loader.
- Widely used in tests and samples.

Textual (`.ccb`) rules:
- Header: `ccbytecode 2`.
- `.file` and `.loc` directives are accepted but optional.
- All directives and instructions in this document are valid.

Binary (`.ccbin`) expectations:
- Modules may use format version 2, which adds `is_extern` on globals.

## CC3
Status and support:
- Supported by the current loader.
- Emitted by current `chancec`.

Textual (`.ccb`) rules:
- Header: `ccbytecode 3`.
- `.file` and `.loc` are supported and used when debug info is emitted.
- Otherwise identical to CC2.

Binary (`.ccbin`) expectations:
- Modules typically use format version 3 or 4, which adds `is_hidden` on globals.
