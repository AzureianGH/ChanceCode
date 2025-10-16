import * as path from 'path';
import * as vscode from 'vscode';
import {
	LanguageClient,
	LanguageClientOptions,
	ServerOptions,
	TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;

export function activate(context: vscode.ExtensionContext): void {
	const serverModule = context.asAbsolutePath(path.join('out', 'server', 'server.js'));
	const debugOptions = { execArgv: ['--nolazy', '--inspect=6009'] };

	const serverOptions: ServerOptions = {
		run: { module: serverModule, transport: TransportKind.ipc },
		debug: { module: serverModule, transport: TransportKind.ipc, options: debugOptions }
	};

	const clientOptions: LanguageClientOptions = {
		documentSelector: [
			{ scheme: 'file', language: 'chancecode' },
			{ scheme: 'untitled', language: 'chancecode' }
		],
		synchronize: {
			fileEvents: vscode.workspace.createFileSystemWatcher('**/*.ccb')
		}
	};

	client = new LanguageClient(
		'chanceCodeLanguageServer',
		'ChanceCode Language Server',
		serverOptions,
		clientOptions
	);

	void client.start();
	context.subscriptions.push({ dispose: () => { void client?.stop(); } });
}

export function deactivate(): Thenable<void> | undefined {
	if (!client) {
		return undefined;
	}
	return client.stop();
}
