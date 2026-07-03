import * as vscode from "vscode";
import { loginViaBrowser as coreLoginViaBrowser } from "../core/browser-login";
import { BrowserCookie, findBrowser } from "../core/browser-cdp";

// Re-export the vscode-free pieces so existing extension imports keep working.
export { BrowserCookie, findBrowser } from "../core/browser-cdp";

/**
 * VSCode adapter over the core browser login: bridges the extension's
 * CancellationToken/Progress to the core's plain callbacks.
 */
export function loginViaBrowser(
	token: vscode.CancellationToken,
	progress?: vscode.Progress<{ message?: string }>,
): Promise<BrowserCookie[]> {
	return coreLoginViaBrowser({
		onProgress: (message) => progress?.report({ message }),
		isCancelled: () => token.isCancellationRequested,
	});
}
