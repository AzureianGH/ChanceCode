# ChanceC → CCB Porting Plan

## Goals
- Re-implement the ChanceC compiler components using the `ccbytecode` instruction set so they can be assembled through the new backend pipeline.
- Maintain feature parity with the existing C implementation while taking advantage of the typed stack semantics (`drop`, `const_str`, structured calls).
- Keep the project buildable throughout the migration by porting in thin, testable slices.

## Phase Breakdown

### Phase 0 – Runtime Foundations *(in progress)*
- Provide bytecode implementations for the allocator helpers (`xmalloc`, `xcalloc`, `xstrdup`) and shared diagnostics glue.
- Surface these helpers as a small runtime module (`ccb/runtime.ccb`) that can be assembled independently and linked with either legacy C objects or future bytecode modules.
- Define extern signatures for libc functions (`malloc`, `calloc`, `strlen`, `memcpy`, `puts`, `exit`) and validate the typed `drop` instruction with real control-flow.

### Phase 1 – Diagnostics & Utilities
- Port `diag_*` helpers using the runtime module; rely on `printf`/`fprintf` externs until we have a bytecode-native formatting routine.
- Introduce a tiny `report_and_exit` bytecode helper to centralize fatal-error paths.
- Add tests that assemble the runtime module, link it into a trivial driver, and exercise allocation failures under `LD_PRELOAD`-style shims.

### Phase 2 – Lexer
- Translate the tokenization logic into bytecode: buffering, character classification, and keyword tables.
- Structure the lexer as a state machine with explicit stack management for lookahead and string building.
- Verify by reusing the current `.ce` sample programs and checking their token streams against the C implementation.

### Phase 3 – Parser & AST Construction
- Port the recursive-descent parser, starting from expression parsing and expanding outward to statements and functions.
- Model heap-allocated AST nodes through the runtime allocator helpers.
- Maintain parity with `ast.h` layouts to simplify interop while the semantic analyzer is still in C.

### Phase 4 – Semantic Analysis & Code Generation
- Gradually replace semantic passes with bytecode equivalents, keeping the C implementation as an oracle during the transition.
- Eventually stage the new bytecode-based code generator to emit `.cc` objects through the existing backend.

## Build & Testing Strategy
- Maintain a `CMake` target that assembles `.ccb` files using `chancecodec` and links them into executable artifacts.
- Mirror the current test matrix by adding bytecode-backed variants (e.g., `tests/ccb/*.ccb` → assembly → native executables).
- Keep nightly builds compiling both the legacy C and emerging bytecode implementations to catch regressions early.

## Next Steps
1. Flesh out the runtime module with diagnostics helpers and validate via a small driver program.
2. Scaffold a build rule in `ChanceCode/CMakeLists.txt` that assembles `ccb/runtime.ccb` into an object file.
3. Start porting the lexer, focusing on identifier and numeric-literal scanning as the first milestone.
