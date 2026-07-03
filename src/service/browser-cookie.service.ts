import * as vscode from "vscode";
import * as cp from "child_process";
import * as http from "http";
import * as net from "net";
import * as path from "path";
import WebSocket = require("ws");
import { getExtensionPath } from "../global/globa-var";
import { Output } from "../global/logger";

export interface BrowserCookie {
	name: string;
	value: string;
	domain: string;
	path: string;
	secure: boolean;
	httpOnly: boolean;
	expires?: number;
}

const CHROME_CANDIDATES = [
	`${process.env["ProgramFiles"]}\\Google\\Chrome\\Application\\chrome.exe`,
	`${process.env["ProgramFiles(x86)"]}\\Google\\Chrome\\Application\\chrome.exe`,
	`${process.env["LocalAppData"]}\\Google\\Chrome\\Application\\chrome.exe`,
];

const EDGE_CANDIDATES = [
	`${process.env["ProgramFiles"]}\\Microsoft\\Edge\\Application\\msedge.exe`,
	`${process.env["ProgramFiles(x86)"]}\\Microsoft\\Edge\\Application\\msedge.exe`,
];

/** Locate an installed Chromium-based browser to drive for login. */
export function findBrowser(): { path: string; name: string } | null {
	const fs = require("fs");
	for (const p of CHROME_CANDIDATES) {
		if (p && fs.existsSync(p)) return { path: p, name: "Chrome" };
	}
	for (const p of EDGE_CANDIDATES) {
		if (p && fs.existsSync(p)) return { path: p, name: "Edge" };
	}
	return null;
}

export function getFreePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const srv = net.createServer();
		srv.unref();
		srv.on("error", reject);
		srv.listen(0, "127.0.0.1", () => {
			const port = (srv.address() as net.AddressInfo).port;
			srv.close(() => resolve(port));
		});
	});
}

export function httpGetJson(url: string): Promise<any> {
	return new Promise((resolve, reject) => {
		http.get(url, (res) => {
			let data = "";
			res.on("data", (c) => (data += c));
			res.on("end", () => {
				try {
					resolve(JSON.parse(data));
				} catch (e) {
					reject(e);
				}
			});
		}).on("error", reject);
	});
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Minimal Chrome DevTools Protocol client over a single WebSocket. */
export class CDPClient {
	private ws: WebSocket;
	private id = 0;
	private pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();

	private constructor(ws: WebSocket) {
		this.ws = ws;
		this.ws.on("message", (raw: WebSocket.RawData) => {
			let msg: any;
			try {
				msg = JSON.parse(raw.toString());
			} catch {
				return;
			}
			if (msg.id && this.pending.has(msg.id)) {
				const { resolve, reject } = this.pending.get(msg.id)!;
				this.pending.delete(msg.id);
				if (msg.error) reject(new Error(msg.error.message || "CDP error"));
				else resolve(msg.result);
			}
		});
	}

	static connect(wsUrl: string): Promise<CDPClient> {
		return new Promise((resolve, reject) => {
			const ws = new WebSocket(wsUrl, { perMessageDeflate: false, maxPayload: 256 * 1024 * 1024 });
			ws.on("open", () => resolve(new CDPClient(ws)));
			ws.on("error", reject);
		});
	}

	send(method: string, params: any = {}): Promise<any> {
		const id = ++this.id;
		return new Promise((resolve, reject) => {
			this.pending.set(id, { resolve, reject });
			this.ws.send(JSON.stringify({ id, method, params }), (err) => {
				if (err) {
					this.pending.delete(id);
					reject(err);
				}
			});
		});
	}

	close() {
		try {
			this.ws.close();
		} catch {
			/* noop */
		}
	}
}

/**
 * Launch a real browser pointed at Zhihu's login page, let the user sign in
 * (e.g. by scanning the QR with the Zhihu app), then read the resulting session
 * cookies over the DevTools Protocol.
 *
 * This mirrors what a browser extension would do: cookies are read live from the
 * browser (already decrypted), so it is unaffected by Chrome's on-disk
 * App-Bound cookie encryption. A dedicated user-data-dir is used so this never
 * touches the user's main browser profile; the login persists there for reuse.
 */
export async function loginViaBrowser(
	token: vscode.CancellationToken,
	progress?: vscode.Progress<{ message?: string }>,
): Promise<BrowserCookie[]> {
	const browser = findBrowser();
	if (!browser) {
		throw new Error("未找到 Chrome 或 Edge 浏览器，请改用手动粘贴 Cookie 登录。");
	}

	const port = await getFreePort();
	const userDataDir = path.join(getExtensionPath(), ".browser-login-profile");
	const args = [
		`--remote-debugging-port=${port}`,
		`--user-data-dir=${userDataDir}`,
		"--no-first-run",
		"--no-default-browser-check",
		"--remote-allow-origins=*",
		"https://www.zhihu.com/signin",
	];

	Output(`启动 ${browser.name} 进行登录 (端口 ${port})...`, "info");
	progress?.report({ message: `已启动 ${browser.name}，请在浏览器中登录知乎...` });

	const child = cp.spawn(browser.path, args, { stdio: "ignore", detached: false });
	let closed = false;
	const cleanup = () => {
		if (closed) return;
		closed = true;
		try {
			child.kill();
		} catch {
			/* noop */
		}
	};

	try {
		// Wait for the DevTools endpoint to come up.
		let versionInfo: any;
		for (let i = 0; i < 60; i++) {
			if (token.isCancellationRequested) throw new Error("用户取消登录");
			try {
				versionInfo = await httpGetJson(`http://127.0.0.1:${port}/json/version`);
				if (versionInfo && versionInfo.webSocketDebuggerUrl) break;
			} catch {
				/* not ready yet */
			}
			await sleep(500);
		}
		if (!versionInfo || !versionInfo.webSocketDebuggerUrl) {
			throw new Error("无法连接到浏览器调试端口");
		}

		const cdp = await CDPClient.connect(versionInfo.webSocketDebuggerUrl);
		try {
			Output("已连接浏览器调试协议，等待登录 (最长 3 分钟)...", "info");

			const deadline = Date.now() + 180000;
			let mintedZseCk = false;
			while (Date.now() < deadline) {
				if (token.isCancellationRequested) throw new Error("用户取消登录");

				const result = await cdp.send("Storage.getCookies", {});
				const all: any[] = (result && result.cookies) || [];
				const zhihu = all.filter((c) => String(c.domain || "").includes("zhihu.com"));
				const hasAuth = zhihu.some((c) => c.name === "z_c0" && c.value);
				const hasZseCk = zhihu.some((c) => c.name === "__zse_ck" && c.value);

				if (hasAuth && hasZseCk) {
					Output(`登录成功，提取到 ${zhihu.length} 个 Cookie`, "info");
					return zhihu.map((c) => ({
						name: c.name,
						value: c.value,
						domain: c.domain,
						path: c.path || "/",
						secure: !!c.secure,
						httpOnly: !!c.httpOnly,
						expires: c.expires,
					}));
				}

				// Logged in but the anti-bot cookie hasn't been minted yet: open a
				// content page once to force Zhihu's JS to set __zse_ck.
				if (hasAuth && !hasZseCk && !mintedZseCk) {
					mintedZseCk = true;
					progress?.report({ message: "登录成功，正在获取访问令牌..." });
					try {
						await cdp.send("Target.createTarget", {
							url: "https://www.zhihu.com/question/19550225",
						});
					} catch {
						/* best effort */
					}
				}

				await sleep(1500);
			}
			throw new Error("登录超时，请重试或改用手动粘贴 Cookie。");
		} finally {
			cdp.close();
		}
	} finally {
		cleanup();
	}
}
