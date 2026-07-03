import { getCookieJar, saveCookieJar } from "../global/cookie";
import { BrowserCookie } from "./browser-cdp";
import { loginViaBrowser, LoginOptions } from "./browser-login";

/**
 * Session/cookie helpers shared by the extension and the MCP server.
 */

/** Load DevTools-extracted cookies into the persistent jar and save them. */
export function importBrowserCookies(cookies: BrowserCookie[]): void {
	const jar = getCookieJar();
	for (const c of cookies) {
		try {
			const domain = c.domain.replace(/^\./, "");
			const attrs = [`${c.name}=${c.value}`, `Domain=${c.domain}`, `Path=${c.path || "/"}`];
			if (c.secure) attrs.push("Secure");
			jar.setCookieSync(attrs.join("; "), `${c.secure ? "https" : "http"}://${domain}/`);
		} catch {
			/* skip invalid cookie */
		}
	}
	saveCookieJar();
}

/** Import a raw `Cookie:` header string (from browser devtools) into the jar. */
export function importCookieString(cookieString: string): number {
	const cleaned = cookieString.replace(/^Cookie:\s*/i, "").trim();
	const jar = getCookieJar();
	let count = 0;
	for (const pair of cleaned.split(";")) {
		const trimmed = pair.trim();
		const eq = trimmed.indexOf("=");
		if (eq === -1) continue;
		const name = trimmed.substring(0, eq).trim();
		const value = trimmed.substring(eq + 1).trim();
		if (!name || !value) continue;
		try {
			jar.setCookieSync(`${name}=${value}; Domain=.zhihu.com; Path=/; Secure`, "https://www.zhihu.com");
			count++;
		} catch {
			/* skip */
		}
	}
	saveCookieJar();
	return count;
}

/** Drive a browser login (QR) and persist the resulting session. */
export async function loginAndSave(opts: LoginOptions = {}): Promise<BrowserCookie[]> {
	const cookies = await loginViaBrowser(opts);
	if (cookies && cookies.length) importBrowserCookies(cookies);
	return cookies;
}
