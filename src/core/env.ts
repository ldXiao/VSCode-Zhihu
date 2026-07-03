/**
 * Dependency-injection seam that lets the vscode-free `src/core` run in two
 * hosts: the VSCode extension and the standalone MCP server.
 *
 * The core only needs three things from its host:
 *   - `dataDir`   : a writable directory for cookie.json and the browser profile
 *   - `log`       : logging (and, in the extension, user-facing notifications)
 *   - `getSetting`: configuration values (zhihu.* settings)
 *
 * The host calls {@link setEnv} once at startup; core modules read it via
 * {@link getEnv}. A console-backed default is used if a core module runs before
 * the host configures anything (e.g. in tests).
 */
export interface ZhihuEnv {
	/** Writable directory for cookie.json, the browser login profile, etc. */
	dataDir: string;
	/** Log a message; `level` ("info"|"warn"|"error") may surface a notification in the extension. */
	log(message: string, level?: string): void;
	/** Read a `zhihu.<key>` setting (extension: workspace config; MCP: config file/env). */
	getSetting<T = any>(key: string): T | undefined;
}

let current: ZhihuEnv = {
	dataDir: process.cwd(),
	log: (message: string, level?: string) => {
		if (level === "error") console.error(message);
		else console.error(message); // MCP uses stdout for protocol; log to stderr
	},
	getSetting: () => undefined,
};

export function setEnv(env: ZhihuEnv): void {
	current = env;
}

export function getEnv(): ZhihuEnv {
	return current;
}
