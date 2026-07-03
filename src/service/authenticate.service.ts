import * as vscode from "vscode";
import { FeedTreeViewProvider } from "../treeview/feed-treeview-provider";
import { AccountService } from "./account.service";
import { clearCookie } from "./http.service";
import { ProfileService } from "./profile.service";
import { WebviewService } from "./webview.service";
import { Output } from "../global/logger";
import { getCookieJar } from "../global/cookie";
import { loginViaBrowser, findBrowser, BrowserCookie } from "./browser-cookie.service";

/**
 * Authentication for the Zhihu extension.
 *
 * Zhihu gates its native login APIs (QR code / password / SMS / WeChat) behind
 * anti-bot request signatures that a non-browser client cannot produce, so those
 * flows no longer work. The only reliable approach — the same one the Obsidian
 * Zhihu plugin uses — is to reuse a real browser session: sign in through an
 * actual browser and hand the resulting cookies to the extension.
 *
 * There is therefore a single login path:
 *   login() -> browserImportLogin() which drives a real Chrome/Edge and reads
 *   the session cookies over the DevTools Protocol, falling back to manual
 *   cookie paste (cookieLogin) when no supported browser is available.
 */
export class AuthenticateService {
	constructor(
		protected profileService: ProfileService,
		protected accountService: AccountService,
		protected feedTreeViewProvider: FeedTreeViewProvider,
		protected webviewService: WebviewService) {
	}

	public logout() {
		try {
			clearCookie();
			this.feedTreeViewProvider.refresh();
		} catch (error) {
			Output(`注销失败: ${error}`, "error");
		}
		vscode.window.showInformationMessage("注销成功！");
	}

	/**
	 * Entry point for the `zhihu.login` command.
	 */
	public async login(): Promise<boolean> {
		try {
			if (await this.accountService.isAuthenticated()) {
				await this.profileService.fetchProfile();
				const name = this.profileService.name;
				if (name && name.trim() !== "") {
					vscode.window.showInformationMessage(`你已经登录了哦~ ${name}`);
					this.feedTreeViewProvider.refresh();
					return true;
				}
			}
		} catch (error) {
			Output(`认证检查失败，继续登录流程: ${error}`, "warn");
		}
		return this.browserImportLogin();
	}

	/**
	 * Primary login path: drive a real Chrome/Edge to Zhihu's login page, let the
	 * user sign in (e.g. QR scan), then read the live session cookies over the
	 * DevTools Protocol and import them. Falls back to manual cookie paste when no
	 * supported browser is found or the browser flow fails.
	 */
	public async browserImportLogin(): Promise<boolean> {
		if (!findBrowser()) {
			vscode.window.showWarningMessage(
				"未检测到 Chrome/Edge 浏览器，请改用手动粘贴 Cookie 登录。",
			);
			return this.cookieLogin();
		}

		let cookies: BrowserCookie[] | undefined;
		try {
			cookies = await vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Notification,
					title: "知乎浏览器登录",
					cancellable: true,
				},
				(progress, token) => loginViaBrowser(token, progress),
			);
		} catch (error) {
			Output(`浏览器登录失败: ${error.message || error}`, "error");
			const choice = await vscode.window.showWarningMessage(
				`浏览器登录未完成：${error.message || error}`,
				"手动粘贴 Cookie",
			);
			if (choice === "手动粘贴 Cookie") {
				return this.cookieLogin();
			}
			return false;
		}

		if (!cookies || cookies.length === 0) {
			return false;
		}

		this.loadCookiesIntoJar(cookies);
		return this.finishLogin();
	}

	/**
	 * Fallback login path: import the browser session by pasting the Cookie header
	 * copied from the browser's developer tools.
	 */
	public async cookieLogin(): Promise<boolean> {
		const cookieString = await this.promptForCookies();
		if (!cookieString) {
			return false;
		}

		const cleaned = cookieString.replace(/^Cookie:\s*/i, "").trim();
		const cookieJar = getCookieJar();
		let count = 0;
		for (const pair of cleaned.split(";")) {
			const trimmed = pair.trim();
			const eq = trimmed.indexOf("=");
			if (eq === -1) continue;
			const name = trimmed.substring(0, eq).trim();
			const value = trimmed.substring(eq + 1).trim();
			if (!name || !value) continue;
			try {
				cookieJar.setCookieSync(
					`${name}=${value}; Domain=.zhihu.com; Path=/; Secure`,
					"https://www.zhihu.com",
				);
				count++;
			} catch (error) {
				Output(`跳过无效 cookie ${name}: ${error}`, "warn");
			}
		}
		Output(`导入了 ${count} 个 cookie`, "info");
		return this.finishLogin();
	}

	/** Load DevTools cookies into the tough-cookie jar used by the HTTP layer. */
	private loadCookiesIntoJar(cookies: BrowserCookie[]) {
		const cookieJar = getCookieJar();
		for (const c of cookies) {
			try {
				const domain = c.domain.replace(/^\./, "");
				const attrs = [
					`${c.name}=${c.value}`,
					`Domain=${c.domain}`,
					`Path=${c.path || "/"}`,
				];
				if (c.secure) attrs.push("Secure");
				const url = `${c.secure ? "https" : "http"}://${domain}/`;
				cookieJar.setCookieSync(attrs.join("; "), url);
			} catch (error) {
				Output(`跳过无效 cookie ${c.name}: ${error}`, "warn");
			}
		}
	}

	/** Verify the imported cookies, greet the user and refresh the UI. */
	private async finishLogin(): Promise<boolean> {
		const isAuth = await this.accountService.isAuthenticated();
		if (isAuth) {
			await this.profileService.fetchProfile();
			const username = this.profileService.name || "用户";
			vscode.window.showInformationMessage(`登录成功！欢迎 ${username}`);
			Output(`登录成功，欢迎 ${username}`, "info");
			this.feedTreeViewProvider.refresh();
			return true;
		}
		vscode.window.showWarningMessage(
			"已导入 Cookie，但认证校验未通过。Cookie 可能已过期，请重试。",
		);
		return false;
	}

	/** Prompt the user to paste the Cookie header copied from their browser. */
	private async promptForCookies(): Promise<string | null> {
		const action = await vscode.window.showInformationMessage(
			"请从浏览器导入 Cookie 完成登录：\n\n" +
			"1. 在浏览器中打开知乎并确保已登录\n" +
			"2. 按 F12 打开开发者工具，切到 Network 面板并刷新页面\n" +
			"3. 点击任意请求，在请求头中找到 Cookie 字段并复制其完整值",
			{ modal: true },
			"我已复制 Cookie",
		);
		if (action !== "我已复制 Cookie") {
			return null;
		}
		const cookieString = await vscode.window.showInputBox({
			prompt: "粘贴从浏览器复制的 Cookie 字符串",
			placeHolder: "_zap=...; d_c0=...; z_c0=...; __zse_ck=...",
			password: true,
			ignoreFocusOut: true,
		});
		return cookieString || null;
	}
}
