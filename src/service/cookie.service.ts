import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import * as toughCookie from "tough-cookie";

export class CookieService {
	
	constructor(protected context: vscode.ExtensionContext,
		protected cookieJar: any) {
	}
	/**
	 * getCookieString
	 */
	public getCookieString(currentUrl): string {
		return this.cookieJar.getCookieStringSync(currentUrl);
	}

	public putCookie(_cookies: string[], currentUrl: string) {
		_cookies.map(c => {
			return toughCookie.Cookie?.parse(c);
		}).forEach(c => {
			this.cookieJar.setCookieSync(c, currentUrl);
		});
	}

}