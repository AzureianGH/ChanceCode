import {
	CompletionItem,
	CompletionItemKind,
	CompletionParams,
	Diagnostic,
	DiagnosticSeverity,
	Hover,
	HoverParams,
	InitializeParams,
	InitializeResult,
	MarkupKind,
	Position,
	ProposedFeatures,
	Range,
	TextDocumentChangeEvent,
	TextEdit,
	TextDocumentSyncKind,
	TextDocuments,
	createConnection,
} from 'vscode-languageserver/node';
import { TextDocument } from 'vscode-languageserver-textdocument';

const connection = createConnection(ProposedFeatures.all);
const documents: TextDocuments<TextDocument> = new TextDocuments(TextDocument);

type FunctionFrame = {
	name: string;
	line: number;
	expectedParams: number;
	expectedLocals: number;
	paramsSeen: boolean;
	localsSeen: boolean;
};

type InstructionGroup = 'data' | 'memory' | 'control' | 'compute' | 'meta';

type DirectiveInfo = {
	label: string;
	detail: string;
	documentation: string;
};

type InstructionInfo = {
	label: string;
	detail: string;
	documentation: string;
	group: InstructionGroup;
};

const directiveInfos: DirectiveInfo[] = [
	{
		label: '.extern',
		detail: 'Declare external symbol',
		documentation: 'Declares an external symbol with parameter and return type metadata so the loader can resolve calls.'
	},
	{
		label: '.global',
		detail: 'Define global',
		documentation: 'Defines a global variable, including its type, constness, and initialiser.'
	},
	{
		label: '.func',
		detail: 'Begin function',
		documentation: 'Begins a function definition and records metadata such as return type, parameter count, and local count.'
	},
	{
		label: '.params',
		detail: 'Parameter types',
		documentation: 'Lists the parameter value types for the active function, matching the count declared on .func.'
	},
	{
		label: '.locals',
		detail: 'Local types',
		documentation: 'Lists the local value types for the active function, matching the count declared on .func.'
	},
	{
		label: '.endfunc',
		detail: 'End function',
		documentation: 'Terminates the current function definition.'
	},
	{
		label: '.comment',
		detail: 'Directive comment',
		documentation: 'Attaches a comment block to the current section; emitted as metadata only.'
	}
];

const directiveTokens = directiveInfos.map((info) => info.label);

const instructionInfos: InstructionInfo[] = [
	{
		label: 'const',
		detail: 'Push immediate',
		documentation: 'Pushes an immediate literal of the given type onto the evaluation stack.',
		group: 'data'
	},
	{
		label: 'const_str',
		detail: 'Intern string literal',
		documentation: 'Interns a UTF-8 string literal, returning its pointer on the evaluation stack.',
		group: 'data'
	},
	{
		label: 'drop',
		detail: 'Pop value',
		documentation: 'Discards the top-of-stack value, asserting it matches the expected type.',
		group: 'data'
	},
	{
		label: 'load_param',
		detail: 'Load parameter',
		documentation: 'Loads a parameter by index and pushes it onto the evaluation stack.',
		group: 'memory'
	},
	{
		label: 'addr_param',
		detail: 'Address of parameter',
		documentation: 'Pushes the address of the given parameter index.',
		group: 'memory'
	},
	{
		label: 'load_local',
		detail: 'Load local',
		documentation: 'Loads a local slot by index onto the evaluation stack.',
		group: 'memory'
	},
	{
		label: 'store_local',
		detail: 'Store local',
		documentation: 'Stores the top-of-stack value into the specified local slot.',
		group: 'memory'
	},
	{
		label: 'addr_local',
		detail: 'Address of local',
		documentation: 'Pushes the address of a local slot for indirect access.',
		group: 'memory'
	},
	{
		label: 'load_global',
		detail: 'Load global',
		documentation: 'Loads the value of a global symbol onto the stack.',
		group: 'memory'
	},
	{
		label: 'store_global',
		detail: 'Store global',
		documentation: 'Stores the top-of-stack value into a global symbol.',
		group: 'memory'
	},
	{
		label: 'addr_global',
		detail: 'Address of global',
		documentation: 'Pushes the address of a global symbol.',
		group: 'memory'
	},
	{
		label: 'load_indirect',
		detail: 'Indirect load',
		documentation: 'Loads a value of the given type from the address sitting on the stack.',
		group: 'memory'
	},
	{
		label: 'store_indirect',
		detail: 'Indirect store',
		documentation: 'Stores a value through the pointer sitting on the stack.',
		group: 'memory'
	},
	{
		label: 'binop',
		detail: 'Binary operator',
		documentation: 'Performs an arithmetic or bitwise binary operation on the top two stack values.',
		group: 'compute'
	},
	{
		label: 'unop',
		detail: 'Unary operator',
		documentation: 'Applies a unary arithmetic or bitwise operator to the top-of-stack value.',
		group: 'compute'
	},
	{
		label: 'compare',
		detail: 'Comparison',
		documentation: 'Compares the top two stack values and pushes an i1 result.',
		group: 'compute'
	},
	{
		label: 'convert',
		detail: 'Type conversion',
		documentation: 'Converts the top-of-stack value between primitive types.',
		group: 'compute'
	},
	{
		label: 'stack_alloc',
		detail: 'Alloca',
		documentation: 'Reserves stack storage of the given size and alignment, returning a pointer.',
		group: 'memory'
	},
	{
		label: 'label',
		detail: 'Define label',
		documentation: 'Defines a label that can be targeted by jumps and branches.',
		group: 'control'
	},
	{
		label: 'jump',
		detail: 'Unconditional branch',
		documentation: 'Jumps unconditionally to the specified label.',
		group: 'control'
	},
	{
		label: 'branch',
		detail: 'Conditional branch',
		documentation: 'Branches to either a true or false label based on the top-of-stack condition.',
		group: 'control'
	},
	{
		label: 'call',
		detail: 'Call function',
		documentation: 'Invokes a function or extern symbol with explicit type metadata.',
		group: 'control'
	},
	{
		label: 'ret',
		detail: 'Return',
		documentation: 'Returns from the current function, optionally marking void returns explicitly.',
		group: 'control'
	},
	{
		label: 'comment',
		detail: 'Inline comment',
		documentation: 'Attaches a comment instruction that backends typically ignore.',
		group: 'meta'
	}
];

const instructionTokens = instructionInfos.map((info) => info.label);
const instructionInfoMap = new Map(instructionInfos.map((info) => [info.label, info]));

const valueTypes = new Set([
	'i1', 'i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64',
	'f32', 'f64', 'ptr', 'void'
]);

const binaryOps = new Set(['add', 'sub', 'mul', 'div', 'mod', 'and', 'or', 'xor', 'shl', 'shr']);
const unaryOps = new Set(['neg', 'not', 'bitnot']);
const compareOps = new Set(['eq', 'ne', 'lt', 'le', 'gt', 'ge']);
const convertKinds = new Set(['trunc', 'sext', 'zext', 'f2i', 'i2f', 'bitcast']);

const instructionCompletionKind: Record<InstructionGroup, CompletionItemKind> = {
	data: CompletionItemKind.Value,
	memory: CompletionItemKind.Reference,
	control: CompletionItemKind.Event,
	compute: CompletionItemKind.Operator,
	meta: CompletionItemKind.Text
};

function completionKindForGroup(group: InstructionGroup): CompletionItemKind {
	return instructionCompletionKind[group] ?? CompletionItemKind.Function;
}

connection.onInitialize((_params: InitializeParams): InitializeResult => ({
	capabilities: {
		textDocumentSync: TextDocumentSyncKind.Incremental,
		completionProvider: {
			resolveProvider: false
		}
	}
}));

connection.onInitialized(() => {
	connection.console.log('ChanceCode language server initialised.');
});

documents.onDidChangeContent((change: TextDocumentChangeEvent<TextDocument>) => {
	void validateTextDocument(change.document);
});

documents.onDidClose((event: TextDocumentChangeEvent<TextDocument>) => {
	connection.sendDiagnostics({ uri: event.document.uri, diagnostics: [] });
});

connection.onCompletion((params: CompletionParams) => {
	const document = documents.get(params.textDocument.uri);
	if (!document) {
		return [];
	}
	const linePrefix = document.getText({
		start: { line: params.position.line, character: 0 },
		end: params.position
	});
	const trimmed = linePrefix.trimStart();
	const lastWordMatch = linePrefix.match(/([^\s]*)$/);
	const lastWord = lastWordMatch?.[1] ?? '';
	const replaceStart = Math.max(0, params.position.character - lastWord.length);
	const replacementRange = Range.create(
		params.position.line,
		replaceStart,
		params.position.line,
		params.position.character
	);

	const completions: CompletionItem[] = [];
	const showDirectives = trimmed.length === 0 || lastWord.startsWith('.');
	if (showDirectives) {
		for (const info of directiveInfos) {
			completions.push({
				label: info.label,
				kind: CompletionItemKind.Keyword,
				detail: info.detail,
				documentation: {
					kind: MarkupKind.Markdown,
					value: info.documentation
				},
				textEdit: TextEdit.replace(replacementRange, info.label)
			});
		}
	}

	if (!lastWord.startsWith('.')) {
		for (const info of instructionInfos) {
			completions.push({
				label: info.label,
				kind: completionKindForGroup(info.group),
				detail: info.detail,
				documentation: {
					kind: MarkupKind.Markdown,
					value: info.documentation
				},
				textEdit: TextEdit.replace(replacementRange, info.label)
			});
		}
	}

	return completions;
});

connection.onHover((params: HoverParams): Hover | null => {
	const document = documents.get(params.textDocument.uri);
	if (!document) {
		return null;
	}
	const fullText = document.getText();
	const offset = document.offsetAt(params.position);
	if (offset < 0 || offset > fullText.length) {
		return null;
	}
	let start = offset;
	while (start > 0 && /[A-Za-z_.]/.test(fullText.charAt(start - 1))) {
		start -= 1;
	}
	let end = offset;
	while (end < fullText.length && /[A-Za-z_.]/.test(fullText.charAt(end))) {
		end += 1;
	}
	if (start === end) {
		return null;
	}
	const token = fullText.slice(start, end);
	const info = instructionInfoMap.get(token);
	if (!info) {
		return null;
	}
	return {
		contents: {
			kind: MarkupKind.Markdown,
			value: `**${info.label}**\n\n${info.documentation}`
		},
		range: Range.create(document.positionAt(start), document.positionAt(end))
	};
});

function lineRange(line: number, text: string): Range {
	return {
		start: Position.create(line, 0),
		end: Position.create(line, text.length)
	};
}

function tokenRange(line: number, text: string, token: string): Range {
	const rawIndex = text.indexOf(token);
	if (rawIndex === -1) {
		return lineRange(line, text);
	}
	return {
		start: Position.create(line, rawIndex),
		end: Position.create(line, rawIndex + token.length)
	};
}

function parseIntegerFromAttribute(line: string, key: string): number | undefined {
	const match = line.match(new RegExp(`${key}=(-?\\d+)`));
	if (!match) {
		return undefined;
	}
	const value = Number.parseInt(match[1], 10);
	return Number.isNaN(value) ? undefined : value;
}

function readTypesFromParamsList(paramList: string): string[] {
	if (paramList.trim() === '') {
		return [];
	}
	return paramList.split(',').map((type) => type.trim()).filter(Boolean);
}

function isIdentifier(token: string): boolean {
	return /^[A-Za-z_][A-Za-z0-9_]*$/.test(token);
}

function isIntegerLiteral(token: string, allowNegative: boolean): boolean {
	const pattern = allowNegative ? /^-?(0x[0-9A-Fa-f]+|[0-9]+)$/ : /^(0x[0-9A-Fa-f]+|[0-9]+)$/;
	return pattern.test(token);
}

function isNumericLiteral(token: string): boolean {
	return /^-?(0x[0-9A-Fa-f]+|[0-9]+(?:\.[0-9]+)?|\.[0-9]+|inf|nan)$/i.test(token);
}

function isValidValueTypeToken(token: string, allowVoid = true): boolean {
	if (!valueTypes.has(token)) {
		return false;
	}
	if (!allowVoid && token === 'void') {
		return false;
	}
	return true;
}

function splitArgsPreservingLiterals(segment: string): string[] {
	const parts: string[] = [];
	let current = '';
	let depth = 0;
	let inString = false;

	for (let i = 0; i < segment.length; ++i) {
		const ch = segment[i];
		if (inString) {
			current += ch;
			if (ch === '"' && segment[i - 1] !== '\\') {
				inString = false;
			}
			continue;
		}
		if (depth === 0) {
			if (ch === ';' || ch === '#') {
				break;
			}
			if (ch === '/' && segment[i + 1] === '/') {
				break;
			}
		}
		if (ch === '"') {
			inString = true;
			current += ch;
			continue;
		}
		if (ch === '(') {
			depth += 1;
			current += ch;
			continue;
		}
		if (ch === ')') {
			depth = Math.max(0, depth - 1);
			current += ch;
			continue;
		}
		if (/\s/.test(ch) && depth === 0) {
			if (current.length > 0) {
				parts.push(current.trim());
				current = '';
			}
			continue;
		}
		current += ch;
	}

	if (current.length > 0) {
		parts.push(current.trim());
	}

	return parts.filter(Boolean);
}

function tokenMatchInput(line: string, index: number): string | undefined {
	const parts = line.split(/\s+/);
	return parts[index];
}

async function validateTextDocument(textDocument: TextDocument): Promise<void> {
	const diagnostics: Diagnostic[] = [];
	const text = textDocument.getText();
	const lines = text.split(/\r?\n/);
	let headerHandled = false;
	const funcStack: FunctionFrame[] = [];

	for (let lineIndex = 0; lineIndex < lines.length; ++lineIndex) {
		const lineText = lines[lineIndex];
		const trimmed = lineText.trim();

		if (trimmed.length === 0 || trimmed.startsWith(';') || trimmed.startsWith('#') || trimmed.startsWith('//')) {
			continue;
		}

		if (!headerHandled) {
			headerHandled = true;
			if (/^ccbytecode\s+\d+$/i.test(trimmed)) {
				continue;
			}
			diagnostics.push({
				severity: DiagnosticSeverity.Error,
				range: lineRange(lineIndex, lineText),
				message: 'Missing ccbytecode header (expected `ccbytecode <version>`).',
				source: 'chancecode'
			});
			// fall through so the line is validated normally below
		}

		const tokenMatch = trimmed.match(/^(\S+)/);
		if (!tokenMatch) {
			continue;
		}

		const token = tokenMatch[1];

		if (token.startsWith('.')) {
			if (!directiveTokens.includes(token)) {
				diagnostics.push({
					severity: DiagnosticSeverity.Warning,
					range: tokenRange(lineIndex, lineText, token),
					message: `Unknown directive ${token}.`,
					source: 'chancecode'
				});
				continue;
			}

			switch (token) {
				case '.func': {
					const funcName = tokenMatchInput(trimmed, 1);
					const retMatch = trimmed.match(/ret=([^\s]+)/);
					const paramsVal = parseIntegerFromAttribute(trimmed, 'params');
					const localsVal = parseIntegerFromAttribute(trimmed, 'locals');

					if (!funcName) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: 'Function directive requires a name.',
							source: 'chancecode'
						});
					}

					if (!retMatch || !valueTypes.has(retMatch[1])) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: 'Function must declare a valid ret=<type>.',
							source: 'chancecode'
						});
					}

					if (paramsVal === undefined || paramsVal < 0) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: 'Function must declare params=<non-negative integer>.',
							source: 'chancecode'
						});
					}
					if (localsVal === undefined || localsVal < 0) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: 'Function must declare locals=<non-negative integer>.',
							source: 'chancecode'
						});
					}

					funcStack.push({
						name: funcName ?? '<anonymous>',
						line: lineIndex,
						expectedParams: Math.max(0, paramsVal ?? 0),
						expectedLocals: Math.max(0, localsVal ?? 0),
						paramsSeen: paramsVal === 0 && paramsVal !== undefined,
						localsSeen: localsVal === 0 && localsVal !== undefined
					});
					break;
				}
				case '.params': {
					const current = funcStack.at(-1);
					if (!current) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: '.params is only valid inside a function.',
							source: 'chancecode'
						});
						break;
					}
					const types = trimmed.split(/\s+/).slice(1);
					if (types.length !== current.expectedParams) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: `.params expects ${current.expectedParams} entr${current.expectedParams === 1 ? 'y' : 'ies'}, found ${types.length}.`,
							source: 'chancecode'
						});
					}
					validateTypeList(types, lineIndex, lineText, diagnostics);
					current.paramsSeen = types.length === current.expectedParams;
					break;
				}
				case '.locals': {
					const current = funcStack.at(-1);
					if (!current) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: '.locals is only valid inside a function.',
							source: 'chancecode'
						});
						break;
					}
					const types = trimmed.split(/\s+/).slice(1);
					if (types.length !== current.expectedLocals) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: `.locals expects ${current.expectedLocals} entr${current.expectedLocals === 1 ? 'y' : 'ies'}, found ${types.length}.`,
							source: 'chancecode'
						});
					}
					validateTypeList(types, lineIndex, lineText, diagnostics);
					current.localsSeen = types.length === current.expectedLocals;
					break;
				}
				case '.endfunc': {
					const current = funcStack.pop();
					if (!current) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: 'Unexpected .endfunc without matching .func.',
							source: 'chancecode'
						});
						break;
					}
					if (!current.paramsSeen) {
						diagnostics.push({
							severity: DiagnosticSeverity.Warning,
							range: lineRange(current.line, lines[current.line] ?? ''),
							message: `Function ${current.name} declares params=${current.expectedParams} but no .params block was found.`,
							source: 'chancecode'
						});
					}
					if (!current.localsSeen) {
						diagnostics.push({
							severity: DiagnosticSeverity.Warning,
							range: lineRange(current.line, lines[current.line] ?? ''),
							message: `Function ${current.name} declares locals=${current.expectedLocals} but no .locals block was found.`,
							source: 'chancecode'
						});
					}
					break;
				}
				case '.extern': {
					const paramsMatch = trimmed.match(/params=\(([^)]*)\)/);
					const returnsMatch = trimmed.match(/returns=([^\s]+)/);
					if (!paramsMatch) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: '.extern requires params=(...).',
							source: 'chancecode'
						});
					} else {
						validateTypeList(readTypesFromParamsList(paramsMatch[1]), lineIndex, lineText, diagnostics);
					}
					if (!returnsMatch || !valueTypes.has(returnsMatch[1])) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: '.extern requires returns=<type>.',
							source: 'chancecode'
						});
					}
					break;
				}
				case '.global': {
					const typeMatch = trimmed.match(/type=([^\s]+)/);
					if (!typeMatch || !valueTypes.has(typeMatch[1])) {
						diagnostics.push({
							severity: DiagnosticSeverity.Error,
							range: lineRange(lineIndex, lineText),
							message: '.global requires type=<valid type>.',
							source: 'chancecode'
						});
					}
					if (!/init=/.test(trimmed)) {
						diagnostics.push({
							severity: DiagnosticSeverity.Warning,
							range: lineRange(lineIndex, lineText),
							message: '.global should specify init=<value>.',
							source: 'chancecode'
						});
					}
					break;
				}
				default:
					break;
			}
			continue;
		}

		if (funcStack.length === 0) {
			diagnostics.push({
				severity: DiagnosticSeverity.Error,
				range: lineRange(lineIndex, lineText),
				message: 'Instructions must appear inside a function body.',
				source: 'chancecode'
			});
			continue;
		}

		if (!instructionTokens.includes(token)) {
			diagnostics.push({
				severity: DiagnosticSeverity.Warning,
				range: tokenRange(lineIndex, lineText, token),
				message: `Unknown instruction ${token}.`,
				source: 'chancecode'
			});
		} else {
			validateInstructionSyntax(token, trimmed, lineIndex, lineText, diagnostics);
		}
	}

		if (!headerHandled) {
			diagnostics.push({
				severity: DiagnosticSeverity.Error,
				range: lineRange(0, lines.at(0) ?? ''),
				message: 'ChanceCode bytecode files must start with `ccbytecode <version>`.',
				source: 'chancecode'
			});
		}

		for (const frame of funcStack) {
			diagnostics.push({
				severity: DiagnosticSeverity.Error,
				range: lineRange(frame.line, lines[frame.line] ?? ''),
				message: `Function ${frame.name} is missing a closing .endfunc.`,
				source: 'chancecode'
			});
		}

	connection.sendDiagnostics({ uri: textDocument.uri, diagnostics });
}

	function validateInstructionSyntax(token: string, trimmedLine: string, lineIndex: number, lineText: string, diagnostics: Diagnostic[]): void {
		const remainder = trimmedLine.slice(token.length).trim();
		const args = splitArgsPreservingLiterals(remainder);
		const report = (message: string, target?: string) => {
			diagnostics.push({
				severity: DiagnosticSeverity.Error,
				range: target ? tokenRange(lineIndex, lineText, target) : lineRange(lineIndex, lineText),
				message,
				source: 'chancecode'
			});
		};

		switch (token) {
			case 'const': {
				if (args.length < 2) {
					report('const expects a type and a literal.');
					return;
				}
				const typeToken = args[0];
				const literalToken = args.slice(1).join(' ');
				if (!isValidValueTypeToken(typeToken, false)) {
					report('const requires a non-void value type.', typeToken);
				}
				if (typeToken === 'ptr') {
					if (literalToken !== 'null' && !isIntegerLiteral(literalToken, true)) {
						report('Pointer constants must use `null` or an integer literal.', args[1] ?? literalToken);
					}
				} else if (!isNumericLiteral(literalToken)) {
					report('const literal must be numeric.', args[1] ?? literalToken);
				}
				break;
			}
			case 'const_str': {
				if (remainder.length === 0) {
					report('const_str requires a quoted string literal.');
					return;
				}
				const stringToken = args[0];
				const stringPattern = /^"([^"\\]|\\.)*"$/;
				if (!stringToken || !stringPattern.test(stringToken)) {
					report('const_str requires a quoted string literal.', stringToken ?? remainder);
				}
				break;
			}
			case 'drop': {
				if (args.length !== 1) {
					report('drop expects exactly one value type operand.');
					return;
				}
				if (!isValidValueTypeToken(args[0], false)) {
					report('drop requires a non-void value type.', args[0]);
				}
				break;
			}
			case 'load_param':
			case 'addr_param':
			case 'load_local':
			case 'store_local':
			case 'addr_local': {
				if (args.length !== 1) {
					report(`${token} expects exactly one index operand.`);
					return;
				}
				if (!isIntegerLiteral(args[0], false)) {
					report(`${token} index must be a non-negative integer.`, args[0]);
				}
				break;
			}
			case 'load_global':
			case 'store_global':
			case 'addr_global': {
				if (args.length !== 1) {
					report(`${token} expects exactly one symbol operand.`);
					return;
				}
				if (!isIdentifier(args[0])) {
					report('Global symbols must be valid identifiers.', args[0]);
				}
				break;
			}
			case 'load_indirect':
			case 'store_indirect': {
				if (args.length !== 1) {
					report(`${token} expects exactly one value type operand.`);
					return;
				}
				if (!isValidValueTypeToken(args[0], false)) {
					report(`${token} requires a non-void value type.`, args[0]);
				}
				break;
			}
			case 'binop': {
				if (args.length < 2) {
					report('binop expects <op> <type> [unsigned].');
					return;
				}
				const opToken = args[0];
				const typeToken = args[1];
				if (!binaryOps.has(opToken)) {
					report(`Unknown binary operator ${opToken}.`, opToken);
				}
				if (!isValidValueTypeToken(typeToken, false)) {
					report('binop requires a non-void value type.', typeToken);
				}
				if (args.length >= 3 && args[2] !== 'unsigned') {
					report('binop optional third operand must be `unsigned`.', args[2]);
				}
				if (args.length > 3) {
					report('binop accepts at most three operands.');
				}
				break;
			}
			case 'unop': {
				if (args.length !== 2) {
					report('unop expects exactly <op> <type>.');
					return;
				}
				if (!unaryOps.has(args[0])) {
					report(`Unknown unary operator ${args[0]}.`, args[0]);
				}
				if (!isValidValueTypeToken(args[1], false)) {
					report('unop requires a non-void value type.', args[1]);
				}
				break;
			}
			case 'compare': {
				if (args.length < 2) {
					report('compare expects <cond> <type> [unsigned].');
					return;
				}
				if (!compareOps.has(args[0])) {
					report(`Unknown comparison predicate ${args[0]}.`, args[0]);
				}
				if (!isValidValueTypeToken(args[1], false)) {
					report('compare requires a non-void value type.', args[1]);
				}
				if (args.length >= 3 && args[2] !== 'unsigned') {
					report('compare optional third operand must be `unsigned`.', args[2]);
				}
				if (args.length > 3) {
					report('compare accepts at most three operands.');
				}
				break;
			}
			case 'convert': {
				if (args.length !== 3) {
					report('convert expects <kind> <from> <to>.');
					return;
				}
				if (!convertKinds.has(args[0])) {
					report(`Unknown conversion kind ${args[0]}.`, args[0]);
				}
				if (!isValidValueTypeToken(args[1], false)) {
					report('convert requires a non-void source type.', args[1]);
				}
				if (!isValidValueTypeToken(args[2], false)) {
					report('convert requires a non-void destination type.', args[2]);
				}
				break;
			}
			case 'stack_alloc': {
				if (args.length !== 2) {
					report('stack_alloc expects <bytes> <align>.');
					return;
				}
				if (!isIntegerLiteral(args[0], false)) {
					report('stack_alloc size must be a non-negative integer.', args[0]);
				}
				if (!isIntegerLiteral(args[1], false)) {
					report('stack_alloc alignment must be a non-negative integer.', args[1]);
				}
				break;
			}
			case 'label': {
				if (args.length !== 1) {
					report('label expects exactly one identifier.');
					return;
				}
				if (!isIdentifier(args[0])) {
					report('Labels must be valid identifiers.', args[0]);
				}
				break;
			}
			case 'jump': {
				if (args.length !== 1) {
					report('jump expects exactly one label target.');
					return;
				}
				if (!isIdentifier(args[0])) {
					report('jump target must be a valid label.', args[0]);
				}
				break;
			}
			case 'branch': {
				if (args.length !== 2) {
					report('branch expects <true_label> <false_label>.');
					return;
				}
				if (!isIdentifier(args[0])) {
					report('branch true target must be a valid label.', args[0]);
				}
				if (!isIdentifier(args[1])) {
					report('branch false target must be a valid label.', args[1]);
				}
				break;
			}
			case 'call': {
				if (args.length < 3) {
					report('call expects <symbol> <ret_type> (<arg_types>).');
					return;
				}
				const symbol = args[0];
				const retType = args[1];
				const proto = args[2];
				if (!isIdentifier(symbol)) {
					report('call symbol must be a valid identifier.', symbol);
				}
				if (!isValidValueTypeToken(retType, true)) {
					report('call return type must be a valid value type.', retType);
				}
				if (!/^\([^()]*\)$/.test(proto)) {
					report('call argument types must be enclosed in parentheses.', proto);
				} else {
					const inner = proto.slice(1, -1).trim();
					if (inner.length > 0) {
						const typeTokens = inner.split(',').map((type) => type.trim()).filter(Boolean);
						for (const typeToken of typeTokens) {
							if (!isValidValueTypeToken(typeToken, false)) {
								report('call argument types must be valid non-void value types.', typeToken);
							}
						}
					}
				}
				for (const extra of args.slice(3)) {
					if (extra !== 'tail' && extra !== 'tailcall') {
						report('Unexpected extra token in call instruction.', extra);
					}
				}
				break;
			}
			case 'ret': {
				if (args.length > 1) {
					report('ret accepts at most one operand.');
					return;
				}
				if (args.length === 1 && args[0] !== 'void') {
					report('ret operand must be `void` when present.', args[0]);
				}
				break;
			}
			case 'comment': {
				// comment instructions may carry arbitrary payload
				break;
			}
			default:
				break;
		}
	}

function validateTypeList(types: string[], lineIndex: number, lineText: string, diagnostics: Diagnostic[]): void {
	for (const typeToken of types) {
		if (!isValidValueTypeToken(typeToken, false)) {
			diagnostics.push({
				severity: DiagnosticSeverity.Error,
				range: tokenRange(lineIndex, lineText, typeToken),
				message: `Unknown or invalid value type ${typeToken}.`,
				source: 'chancecode'
			});
		}
	}
}

documents.listen(connection);
connection.listen();
