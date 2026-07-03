import * as http from "http";
import * as net from "net";
import WebSocket = require("ws");

/**
 * VSCode-free browser + Chrome DevTools Protocol helpers shared by login
 * (browser-login) and content reading (browser-session).
 */

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

/** Locate an installed Chromium-based browser to drive. */
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
