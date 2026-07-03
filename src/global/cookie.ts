import { getEnv } from "../core/env";
import * as path from "path";
import * as toughCookie from "tough-cookie";
const { CookieJar, MemoryCookieStore } = toughCookie;
import { writeFileSync, readFileSync, existsSync } from "fs";

/**
 * Cookie persistence for the extension.
 *
 * The session cookies (z_c0, d_c0, __zse_ck, ...) obtained at login must survive
 * VSCode restarts, otherwise the user is logged out every session. We keep a
 * single in-memory CookieJar and persist the whole jar to `cookie.json` via
 * tough-cookie's own serialization. Call {@link saveCookieJar} after mutating
 * cookies (login import, response Set-Cookie) to write them to disk.
 *
 * This replaces the previous tough-cookie-file-store setup, whose fragile
 * fallback store silently failed to persist inside the webpack bundle.
 */

let cookieJar: any;

function cookieFilePath(): string {
	return path.join(getEnv().dataDir, "./cookie.json");
}

function loadCookie() {
	if (cookieJar) return;
	const filePath = cookieFilePath();
	try {
		if (existsSync(filePath)) {
			const raw = readFileSync(filePath, "utf8").trim();
			if (raw && raw !== "[]" && raw !== "{}") {
				cookieJar = CookieJar.deserializeSync(JSON.parse(raw), new MemoryCookieStore());
				return;
			}
		}
	} catch (error) {
		console.log("加载 cookie 失败，将重新开始:", error && error.message);
	}
	cookieJar = new CookieJar(new MemoryCookieStore());
}

export function getCookieJar() {
	loadCookie();
	return cookieJar;
}

/** The underlying cookie store (used for xsrf/token lookups and removal). */
export function getCookieStore() {
	loadCookie();
	return cookieJar.store;
}

/** Persist the current jar to cookie.json. Safe to call frequently. */
export function saveCookieJar() {
	loadCookie();
	try {
		writeFileSync(cookieFilePath(), JSON.stringify(cookieJar.serializeSync()));
	} catch (error) {
		console.log("保存 cookie 失败:", error && error.message);
	}
}

/** Drop all cookies, in memory and on disk. */
export function clearCookieStore() {
	cookieJar = new CookieJar(new MemoryCookieStore());
	try {
		writeFileSync(cookieFilePath(), "{}");
	} catch (error) {
		console.log("清除 cookie 失败:", error && error.message);
	}
}
