# ChanceCode Architecture

## Goals

ChanceCode is an intermediate compiler that translates ChanceCode bytecode (CC bytecode) into concrete backend outputs. The design emphasizes:

- **Backend modularity:** new backends are registered dynamically through a minimal vtable without touching core code.
- **Deterministic, inspectable bytecode:** the loader parses a portable textual representation that mirrors a low-level virtual machine capable of modeling the constructs produced by the `chancec` frontend.
- **Rich IR representation:** the in-memory model separates modules, globals, functions, and instructions with a strongly typed instruction set that supports integers, floats, pointers, control flow, and calls.
- **Tooling friendly:** the command-line driver exposes discovery of available backends and surfaces diagnostics hooks for IDE integration.

## High-Level Pipeline

```
           +---------------+       +---------------------+       +--------------------+
           |  CC Bytecode  |  -->  |    Bytecode IR      |  -->  |   Selected Backend  |
           |   (.ccb file) |       | (module/function)   |       | (e.g. x86, wasm)    |
           +---------------+       +---------------------+       +--------------------+
```

1. **Loader** reads a `.ccb` textual file and builds an in-memory `CCModule`.
2. **Validation** performs structural checks (version, type/operand validation, label resolution).
3. **Backend selection** resolves a requested backend name to a registered implementation.
4. **Emission** hands the validated module to the backend which emits the final artifact (assembly, object code, etc.).

## Module Layout

```
ChanceCode/
├── CMakeLists.txt
├── include/cc/
│   ├── backend.h       # Backend interface (registration & vtable)
├── include/cc/bytecode.h      # IR types, enums, helper APIs
│   ├── diagnostics.h   # Diagnostic category definitions
│   └── loader.h        # Textual loader entry point
├── src/
│   ├── backend.c       # Registry implementation
│   ├── bytecode.c      # Module/IR utilities and memory management
│   ├── diagnostics.c   # Default diagnostic sink
│   ├── loader.c        # Parser for textual CC bytecode (v2+)
│   ├── cli.c           # CLI driver (chancecodec)
│   └── support/        # Shared helpers
├── backends/
│   ├── backend_x86.c   # Reference x86-64 backend
│   └── ...
├── tests/
│   ├── *.ccb           # Sample bytecode inputs
│   ├── expected/       # Golden backend outputs
│   └── CMakeLists.txt
└── docs/
    └── architecture.md (this file)
```

## Bytecode Version 2

Version `2` of the textual format upgrades the language so every construct emitted by `chancec` can be modeled faithfully.

### File Header

Each `.ccb` file begins with the header:

```
ccbytecode 2
```

### Globals (optional)

Global definitions precede functions:

```
.global <name> type=<type> [align=<pow2>] [const] init=<initializer>
```

- `<type>` is a value type token (`i8`, `u16`, `i32`, `u64`, `f32`, `f64`, `ptr`, ...).
- `align=` is optional (defaults to the natural alignment of `<type>`).
- `const` marks read-only data.
- `init=` accepts a literal (`0`, `42.0`, `null`) or a quoted string (`"hello"`). Future revisions will allow aggregate initialisers.

### Functions

Functions use explicit typing metadata followed by instruction bodies:

```
.func <name> ret=<type> params=<count> locals=<count> [varargs]
.params <type> <type> ...
.locals <type> <type> ...
  <instruction>
  ...
.endfunc
```

- Parameter and local counts must match the type lists.
- Functions may be marked `varargs` once the frontend emits them (currently rejected by the loader).

### Value Types

| Token | Description | Size |
|-------|-------------|------|
| `i1`  | 1-bit integer/bool (stored as 1 byte) | 1 |
| `i8`/`u8` | Signed/unsigned 8-bit integer | 1 |
| `i16`/`u16` | Signed/unsigned 16-bit integer | 2 |
| `i32`/`u32` | Signed/unsigned 32-bit integer | 4 |
| `i64`/`u64` | Signed/unsigned 64-bit integer | 8 |
| `f32` | IEEE-754 single precision | 4 |
| `f64` | IEEE-754 double precision | 8 |
| `ptr` | Machine pointer (64-bit today) | 8 |
| `void` | Only valid as a function return type | 0 |

### Instruction Set (stack machine)

All instructions operate on an implicit evaluation stack. Unless specified, operands are popped in reverse order (right-most first) and the result is pushed.

| Instruction | Operands | Description |
|-------------|----------|-------------|
| `const <type> <literal>` | number/`null` | Push an immediate. Integers accept decimal or `0x` hex, floats accept decimal or `nan/inf`. `ptr null` pushes a null pointer. |
| `const_str "..."` | quoted string | Interns a string literal and pushes a pointer to it. Escapes support `\n`, `\t`, `\"`, `\\`. |
| `load_param <index>` | | Pushes parameter `<index>` (0-based). |
| `addr_param <index>` | | Pushes the address of parameter `<index>`. |
| `load_local <index>` | | Pushes local `<index>`. |
| `store_local <index>` | | Pops a value and stores into local `<index>`. |
| `addr_local <index>` | | Pushes the address of local `<index>`. |
| `load_global <symbol>` | | Pushes the contents of global `<symbol>`. |
| `store_global <symbol>` | | Pops and writes to global `<symbol>`. |
| `addr_global <symbol>` | | Pushes the address of global `<symbol>`. |
| `load_indirect <type>` | | Pops a pointer, loads `<type>` from memory, pushes value. |
| `store_indirect <type>` | | Pops value then pointer, stores `<type>`. |
| `binop <op> <type> [unsigned]` | | Binary arithmetic/bit op. `<op>` ∈ {`add`,`sub`,`mul`,`div`,`mod`,`and`,`or`,`xor`,`shl`,`shr`}. Optional `unsigned` forces unsigned semantics. |
| `unop <op> <type>` | | Unary operator (`neg`, `not`, `bitnot`). |
| `compare <cond> <type> [unsigned]` | | Pops RHS then LHS, compares, pushes `i1`. `<cond>` ∈ {`eq`,`ne`,`lt`,`le`,`gt`,`ge`}. |
| `convert <kind> <from> <to>` | | Type conversion. `<kind>` ∈ {`trunc`, `sext`, `zext`, `f2i`, `i2f`, `bitcast`}. |
| `stack_alloc <bytes> <align>` | | Reserves runtime stack space (like `alloca`) and pushes a pointer. |
| `label <name>` | | Defines a label (branch target). |
| `jump <name>` | | Unconditional branch. |
| `branch <true> <false>` | | Pops condition; jumps to `<true>` when non-zero, else `<false>`. |
| `call <symbol> <rettype> (<arg_types...>)` | | Expects arguments are already evaluated (last arg pushed last). Emits a call following the active ABI. |
| `ret [void]` | | Returns. If the function return type is non-void, the top of stack carries the return value. `ret void` is required for `void` functions. |
| `comment <text>` | | Metadata only; ignored by code generators. |

The loader validates instruction operands against function metadata (e.g., `load_local` index bounds, type expectations for stores).

### Control Flow

Labels are plain identifiers. Branch instructions enforce that referenced labels exist in the current function and that stack types are balanced at function exits.

### Extensibility

- The instruction enum leaves gaps for future vector/SIMD operations.
- Operands use bespoke parsers so new instructions can store complex payloads (e.g., `switch`, PHI nodes) without touching unrelated code.
- The loader version-gates features; v1 bytecode remains backwards compatible.

## Backend Interface

`backends/backend_x86.c` registers the built-in x86-64 backend:

```c
typedef struct {
    const char *name;        // "x86"
    const char *description; // Short description
    CCBackendEmitFn emit;    // Emits the module
    void *userdata;          // Optional backend state
} CCBackend;
```

- **Registration:** `cc_backend_register(&backend)` exposes a backend globally.
- **Lookup:** `cc_backend_find("x86")` returns the backend implementation or `NULL`.
- **Options:** The CLI forwards parsed options (output path, optimisation level, target triple, etc.) via `CCBackendOptions`.

## Diagnostics

Diagnostics flow through `CCDiagnosticSink`. The loader/backends emit structured errors and warnings; the default sink prints to stderr in `severity: line:col: message` format. IDEs can install a custom sink to collect diagnostics programmatically.

## Command-Line Tool

`chancecodec` is the reference driver.

### Usage

```
chancecodec <input.ccb> --backend <name> [--output <path>] [--option key=value] [--list-backends]
```

- `--list-backends` prints registered backends and exits.
- `--backend` selects a backend; defaults to `x86`.
- `--output` writes backend output to the specified path (stdout when omitted).
- `--option key=value` forwards backend-specific switches.

## Future Work

- Expand the backend surface to support additional targets (WASM, LLVM IR, ARM64).
- Accept binary `.ccb` containers for faster loading.
- Integrate directly with the `chancec` frontend so it can emit CC bytecode instead of target-specific assembly.
- Flesh out aggregate initialisers and varargs support once the frontend produces them.
