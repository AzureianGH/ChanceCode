# Chance Code Highlighter

Developer tooling for ChanceCode `.ccb` bytecode modules. The extension ships syntax highlighting plus a lightweight language server.

## Features

- Syntax highlighting for directives, instructions, numeric literals, and types.
- Diagnostics for missing headers, unbalanced `.func`/`.endfunc`, invalid type lists, and unknown directives or instructions.
- Completions that surface known directives at directive positions and instruction mnemonics inside function bodies.

## Getting Started

1. Run `npm install` inside `vscode-ext/chance-code-highlighter` to restore dependencies.
2. Use `npm run watch` for live TypeScript compilation while developing.
3. Launch the extension host (F5) to try the ChanceCode tooling against `.ccb` files.

## Known Limitations

- The validator only checks structural issues; it does not perform full stack-type analysis yet.
- The instruction catalogue mirrors the current ChanceCode backend and must be kept in sync manually.

## Release Notes

### 0.0.1

- Initial syntax highlighter and language server with structural diagnostics and completions.
