# ChanceCode Specifications (CC1, CC2, CC3)

This document describes the ChanceCode bytecode formats as implemented by the ChanceCode loader and the CHance front-end.
It is derived from the current ChanceCode sources and the CHance `chancec` code generator.

## 1. Artifacts
- **Textual bytecode:** `.ccb` (ChanceCode source)
- **Binary module:** `.ccbin` (serialized `CCModule`)

## 2. Common Concepts
### 2.1 Value Types
Text tokens map to `CCValueType`:
- `i1`, `i8`, `u8`, `i16`, `u16`, `i32`, `u32`, `i64`, `u64`, `f32`, `f64`, `ptr`, `void`

Sizes (bytes): `i1/i8/u8=1`, `i16/u16=2`, `i32/u32/f32=4`, `i64/u64/f64/ptr=8`, `void=0`.

### 2.2 Module Sections
A module contains:
- Globals
- Externs
- Functions
- Optional debug file table (textual form only)

### 2.3 Stack Semantics (Execution Model)
Instructions operate on an implicit evaluation stack:
- `const*`, `load_*`, `addr_*`, `binop`, `unop`, `compare`, `convert`, `stack_alloc` push values.
- `store_*`, `store_indirect`, `drop`, `ret` consume values.
- Branch/jump instructions use labels.

## 3. Textual Format (.ccb)
### 3.1 Header
The first non-empty, non-comment line must be:
```
ccbytecode <version>
```
Supported versions in the current loader: `2` and `3`.

### 3.2 Comments and Whitespace
- Blank lines are ignored.
- Lines starting with `#` are ignored.
- Tokens are separated by spaces or tabs.

### 3.3 Directives
#### 3.3.1 `.file` (debug file table)
```
.file <id> "path"
```
- `id` is a positive integer.
- `path` is a quoted string literal.

#### 3.3.2 `.loc` (debug location)
```
.loc <file-id> <line> <column>
```
Sets the debug location for subsequent instructions.

#### 3.3.3 `.global`
```
.global <name> <attrs...>
```
Attributes (order independent):
- `type=<type>` (required)
- `size=<bytes>`
- `align=<bytes>`
- `section="..."`
- `const`
- `extern`
- `hidden`
- `init=<literal|"string"|null>`
- `data="..."` (raw bytes)
- `ptrs=[sym1,sym2,null,...]`

Rules:
- Extern globals cannot specify an initializer.
- If `size` is omitted, it defaults to the type size.
- If `align` is omitted, it defaults to the type size.
- `data=` sets a byte array initializer; if `size` is provided, it must match the data length.
- `ptrs=` sets a pointer table; `size` must match `count * 8` if provided; alignment defaults to 8.

#### 3.3.4 `.extern`
```
.extern <name> <attrs...>
```
Attributes:
- `params=(type,type,...)` or `params=<count>`
- `returns=<type>`
- `varargs`
- `no-return` or `noreturn`

#### 3.3.5 `.no-return`
```
.no-return <symbol>
```
Marks an extern or function as no-return, even if declared later.

#### 3.3.6 `.preserve`
```
.preserve <function>
```
Marks a function as preserved (do not drop during optimisation).

#### 3.3.7 `.force-inline-literal`
```
.force-inline-literal <function>
```
Marks a literal function as forced-inline.

#### 3.3.8 `.func` / `.endfunc`
```
.func <name> <attrs...>
  .params <types...>
  .locals <types...>
  <instructions>
.endfunc
```
Attributes:
- `ret=<type>`
- `params=<count>`
- `locals=<count>`
- `varargs`
- `no-return` or `noreturn`
- `preserve`
- `hidden`
- `force-inline-literal`
- `section="..."`

Rules:
- Varargs functions must have at least one explicit parameter.
- If `params>0`, a `.params` line must appear before instructions.
- If `locals>0`, a `.locals` line must appear before instructions.
- `.params` and `.locals` must list exactly the declared count of types.

#### 3.3.9 `.literal` / `.endliteral`
```
.literal
  <raw lines>
.endliteral
```
- The literal block belongs to the current function and makes it a literal function.
- Literal functions cannot contain bytecode instructions.
- The block must contain at least one line.

### 3.4 String Literals
Quoted string literals are parsed with these escapes:
- `\n`, `\r`, `\t`, `\\`, `\"`, `\0`, `\xNN`

### 3.5 Instructions
Each instruction is one line.

#### 3.5.1 Constants
- `const <type> <literal>`
  - `ptr` literals allow `null` or an integer address.
- `const_str "..."`

#### 3.5.2 Parameters and Locals
- `load_param <index>`
- `addr_param <index>`
- `load_local <index>`
- `store_local <index>`
- `addr_local <index>`

#### 3.5.3 Globals
- `load_global <symbol>`
- `store_global <symbol>`
- `addr_global <symbol>` (symbol may refer to globals, functions, or externs)

#### 3.5.4 Indirect Memory
- `load_indirect <type>`
- `store_indirect <type>`

#### 3.5.5 Arithmetic and Logic
- `binop <op> <type> [unsigned]`
  - `op`: `add`, `sub`, `mul`, `div`, `mod`, `and`, `or`, `xor`, `shl`, `shr`
- `unop <op> <type>`
  - `op`: `neg`, `not`, `bitnot`
- `compare <op> <type> [unsigned]`
  - `op`: `eq`, `ne`, `lt`, `le`, `gt`, `ge`

#### 3.5.6 Conversions
- `convert <kind> <from> <to>`
  - `kind`: `trunc`, `sext`, `zext`, `f2i`, `i2f`, `bitcast`

#### 3.5.7 Control Flow
- `label <name>`
- `jump <label>`
- `branch <true_label> <false_label>`

#### 3.5.8 Calls
- `call <symbol> <ret> (<args>) [varargs]`
- `call_indirect <ret> (<args>) [varargs]`

#### 3.5.9 Stack and Return
- `stack_alloc <bytes> <align>`
- `drop <type>`
- `ret [void]`

#### 3.5.10 Misc
- `comment <text...>`

## 4. Binary Format (.ccbin)
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
