import * as cp from "child_process";
import * as path from "path";
import { getEnv } from "./env";
import { BrowserCookie, findBrowser, getFreePort, httpGetJson, CDPClient } from "./browser-cdp";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface LoginOptions {
	/** Report progress (e.g. to a VSCode notification). */
	onProgress?: (message: string) => void;
	/** Return true to abort the login early. */
	isCancelled?: () => boolean;
	/** Overall timeout in ms (default 180000). */
	timeoutMs?: number;
}

/**
 * Launch a real browser at Zhihu's login page, let the user sign in (QR scan),
 * then read the resulting session cookies live over the DevTools Protocol.
 *
 * Reads cookies from the running browser (already decrypted), so it is unaffected
 * by Chrome's on-disk App-Bound cookie encryption. A dedicated user-data-dir
 * (under the host's dataDir) keeps this separate from the user's main profile and
 * persists the login for reuse.
 */
export async function loginViaBrowser(opts: LoginOptions = {}): Promise<BrowserCookie[]> {
	const env = getEnv();
	const browser = findBrowser();
	if (!browser) {
		throw new Error("未找到 Chrome 或 Edge 浏览器，请改用手动粘贴 Cookie 登录。");
	}

	const port = await getFreePort();
	const userDataDir = path.join(env.dataDir, ".browser-login-profile");
	const args = [
		`--remote-debugging-port=${port}`,
		`--user-data-dir=${userDataDir}`,
		"--no-first-run",
		"--no-default-browser-check",
		"--remote-allow-origins=*",
		"https://www.zhihu.com/signin",
	];

	env.log(`启动 ${browser.name} 进行登录 (端口 ${port})...`, "info");
	opts.onProgress?.(`已启动 ${browser.name}，请在浏览器中登录知乎...`);

	const child = cp.spawn(browser.path, args, { stdio: "ignore", detached: false });
	const cancelled = () => !!opts.isCancelled?.();
	let closed = false;
	const cleanup = () => {
		if (closed) return;
		closed = true;
		try { child.kill(); } catch { /* noop */ }
	};

	try {
		let versionInfo: any;
		for (let i = 0; i < 60; i++) {
			if (cancelled()) throw new Error("用户取消登录");
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
			env.log("已连接浏览器调试协议，等待登录 (最长 3 分钟)...", "info");
			const deadline = Date.now() + (opts.timeoutMs || 180000);
			let mintedZseCk = false;
			while (Date.now() < deadline) {
				if (cancelled()) throw new Error("用户取消登录");

				const result = await cdp.send("Storage.getCookies", {});
				const all: any[] = (result && result.cookies) || [];
				const zhihu = all.filter((c) => String(c.domain || "").includes("zhihu.com"));
				const hasAuth = zhihu.some((c) => c.name === "z_c0" && c.value);
				const hasZseCk = zhihu.some((c) => c.name === "__zse_ck" && c.value);

				if (hasAuth && hasZseCk) {
					env.log(`登录成功，提取到 ${zhihu.length} 个 Cookie`, "info");
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

				if (hasAuth && !hasZseCk && !mintedZseCk) {
					mintedZseCk = true;
					opts.onProgress?.("登录成功，正在获取访问令牌...");
					try {
						await cdp.send("Target.createTarget", { url: "https://www.zhihu.com/question/19550225" });
					} catch { /* best effort */ }
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
