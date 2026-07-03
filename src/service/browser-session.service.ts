import * as cp from "child_process";
import * as path from "path";
import { getExtensionPath } from "../global/globa-var";
import { Output } from "../global/logger";
import { ZhihuUserAgent } from "../const/HTTP";
import { findBrowser, getFreePort, httpGetJson, CDPClient } from "./browser-cookie.service";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface ZhihuAuthored {
	id: string;
	content: string;
	voteup_count: number;
	author: { name: string; headline: string; url_token: string; avatar_url: string };
}
export interface QuestionData {
	title: string;
	detail: string;
	answers: ZhihuAuthored[];
}

/**
 * Reads Zhihu content by driving a headless browser.
 *
 * Zhihu's content APIs are gated behind anti-bot request signatures (x-zse-96)
 * that only its own page JavaScript produces, so instead of calling the API we
 * load the real page in a browser (which runs that JS) and read the data Zhihu
 * embeds in the page's `js-initialData` script tag over the DevTools Protocol.
 *
 * The browser runs fully headless (no visible window). Two tweaks are required
 * to get past Zhihu's automation detection — the same ones the community
 * zhihu-fisher extension uses:
 *   - override the User-Agent (the default headless UA contains "HeadlessChrome")
 *   - spoof `navigator.webdriver` to undefined
 *
 * One browser is launched lazily and reused; each read opens a throwaway tab,
 * navigates, extracts, and closes. Reads are serialized. The browser reuses the
 * `.browser-login-profile` so it shares the signed-in session (public content
 * also works when logged out).
 */

const WEBDRIVER_SPOOF = 'Object.defineProperty(navigator,"webdriver",{get:()=>undefined});';

class BrowserSession {
	private child: cp.ChildProcess | null = null;
	private browserCdp: CDPClient | null = null;
	private port = 0;
	private starting: Promise<void> | null = null;
	private queue: Promise<any> = Promise.resolve();

	private profileDir(): string {
		return path.join(getExtensionPath(), ".browser-login-profile");
	}

	private async start(): Promise<void> {
		const browser = findBrowser();
		if (!browser) {
			throw new Error("未找到 Chrome/Edge 浏览器，无法加载知乎内容。请先安装 Chrome 或 Edge。");
		}
		this.port = await getFreePort();
		const args = [
			`--remote-debugging-port=${this.port}`,
			`--user-data-dir=${this.profileDir()}`,
			"--no-first-run",
			"--no-default-browser-check",
			"--remote-allow-origins=*",
			`--user-agent=${ZhihuUserAgent}`,
			"--headless=new",
			"--disable-features=UseEcoQoSForBackgroundProcess",
			"about:blank",
		];
		Output(`启动后台浏览器加载知乎内容 (${browser.name})...`, "info");
		this.child = cp.spawn(browser.path, args, { stdio: "ignore", detached: false });
		this.child.on("exit", () => {
			this.child = null;
			this.browserCdp = null;
		});

		let version: any;
		for (let i = 0; i < 60; i++) {
			try {
				version = await httpGetJson(`http://127.0.0.1:${this.port}/json/version`);
				if (version && version.webSocketDebuggerUrl) break;
			} catch {
				/* not ready */
			}
			await sleep(300);
		}
		if (!version || !version.webSocketDebuggerUrl) {
			throw new Error("无法连接后台浏览器调试端口");
		}
		this.browserCdp = await CDPClient.connect(version.webSocketDebuggerUrl);
	}

	private async ensureStarted(): Promise<void> {
		if (this.browserCdp && this.child) return;
		if (!this.starting) {
			this.starting = this.start().finally(() => {
				this.starting = null;
			});
		}
		await this.starting;
	}

	private async doFetch(url: string, extractorExpr: string): Promise<any> {
		await this.ensureStarted();
		if (!this.browserCdp) throw new Error("后台浏览器不可用");

		const created = await this.browserCdp.send("Target.createTarget", { url: "about:blank" });
		const targetId = created && created.targetId;
		if (!targetId) throw new Error("无法创建后台标签页");

		// Find the new tab's page debugger endpoint.
		let pageWsUrl: string | undefined;
		for (let i = 0; i < 40; i++) {
			try {
				const list: any[] = await httpGetJson(`http://127.0.0.1:${this.port}/json/list`);
				const page = list.find((t) => t.id === targetId && t.webSocketDebuggerUrl);
				if (page) {
					pageWsUrl = page.webSocketDebuggerUrl;
					break;
				}
			} catch {
				/* retry */
			}
			await sleep(200);
		}
		if (!pageWsUrl) {
			await this.browserCdp.send("Target.closeTarget", { targetId }).catch(() => undefined);
			throw new Error("无法打开后台标签页");
		}

		const page = await CDPClient.connect(pageWsUrl);
		try {
			await page.send("Page.enable");
			await page.send("Runtime.enable");
			await page.send("Network.enable");
			// Anti-automation-detection: normal UA + hide navigator.webdriver.
			await page.send("Network.setUserAgentOverride", { userAgent: ZhihuUserAgent });
			await page.send("Page.addScriptToEvaluateOnNewDocument", { source: WEBDRIVER_SPOOF });
			await page.send("Page.navigate", { url });

			const deadline = Date.now() + 25000;
			while (Date.now() < deadline) {
				await sleep(700);
				let value: string | null = null;
				try {
					const res = await page.send("Runtime.evaluate", {
						expression: extractorExpr,
						returnByValue: true,
					});
					value = res && res.result ? res.result.value : null;
				} catch {
					continue;
				}
				if (!value) continue;
				let parsed: any;
				try {
					parsed = JSON.parse(value);
				} catch {
					continue;
				}
				if (parsed && parsed.__blocked) {
					throw new Error("知乎反爬拦截了后台浏览器，请稍后重试，或重新登录。");
				}
				return parsed;
			}
			throw new Error("加载知乎内容超时，请重试。");
		} finally {
			page.close();
			await this.browserCdp.send("Target.closeTarget", { targetId }).catch(() => undefined);
		}
	}

	/** Serialize reads so tabs don't pile up and overwhelm the browser. */
	public fetch(url: string, extractorExpr: string): Promise<any> {
		const task = this.queue.then(() => this.doFetch(url, extractorExpr));
		this.queue = task.catch(() => undefined);
		return task;
	}

	public dispose() {
		try {
			this.browserCdp?.close();
		} catch {
			/* noop */
		}
		const child = this.child;
		if (child && child.pid && process.platform === "win32") {
			try {
				cp.execSync(`taskkill /PID ${child.pid} /T /F`, { stdio: "ignore" });
			} catch {
				try { child.kill(); } catch { /* noop */ }
			}
		} else {
			try { child?.kill(); } catch { /* noop */ }
		}
		this.browserCdp = null;
		this.child = null;
		this.starting = null;
	}
}

let session: BrowserSession | null = null;
function getSession(): BrowserSession {
	if (!session) session = new BrowserSession();
	return session;
}

// In-page mapper from Zhihu's camelCase entity to the pug template shape.
const MAP_AUTHORED = `function(a){var au=a.author||{};return{id:a.id,content:a.content||"",voteup_count:a.voteupCount!=null?a.voteupCount:(a.voteup_count||0),author:{name:au.name||"\\u77e5\\u4e4e\\u7528\\u6237",headline:au.headline||"",url_token:au.urlToken||au.url_token||"",avatar_url:au.avatarUrl||au.avatar_url||""}}}`;

const BLOCK_CHECK = `if(!s){var t=document.body?document.body.innerText.slice(0,200):"";if(t.indexOf("40362")!==-1||t.indexOf("\\u5b58\\u5728\\u5f02\\u5e38")!==-1)return JSON.stringify({__blocked:1});return null;}`;

function entitiesExpr(body: string): string {
	return `(function(){var s=document.getElementById("js-initialData");${BLOCK_CHECK}var j;try{j=JSON.parse(s.textContent)}catch(e){return null}var e=(j.initialState&&j.initialState.entities)||{};var map=${MAP_AUTHORED};${body}})()`;
}

export function fetchQuestion(id: string): Promise<QuestionData> {
	const expr = entitiesExpr(`
		var qid=Object.keys(e.questions||{})[0];
		var q=qid?e.questions[qid]:{};
		var answers=Object.keys(e.answers||{}).map(function(k){return map(e.answers[k])});
		if(answers.length===0)return null;
		return JSON.stringify({title:q.title||"",detail:q.detail||"",answers:answers});
	`);
	return getSession().fetch(`https://www.zhihu.com/question/${id}`, expr);
}

export function fetchAnswer(id: string): Promise<{ title: string; answer: ZhihuAuthored }> {
	const expr = entitiesExpr(`
		var a=(e.answers&&(e.answers["${id}"]||e.answers[Object.keys(e.answers)[0]]));
		if(!a)return null;
		var qid=Object.keys(e.questions||{})[0];
		var q=qid?e.questions[qid]:{};
		return JSON.stringify({title:(a.question&&a.question.title)||q.title||"\\u77e5\\u4e4e\\u56de\\u7b54",answer:map(a)});
	`);
	return getSession().fetch(`https://www.zhihu.com/answer/${id}`, expr);
}

export function fetchArticle(id: string): Promise<ZhihuAuthored & { title: string }> {
	const expr = entitiesExpr(`
		var a=(e.articles&&(e.articles["${id}"]||e.articles[Object.keys(e.articles)[0]]));
		if(!a)return null;
		var m=map(a);m.title=a.title||"\\u77e5\\u4e4e\\u6587\\u7ae0";
		return JSON.stringify(m);
	`);
	return getSession().fetch(`https://zhuanlan.zhihu.com/p/${id}`, expr);
}

/** Shut down the background browser (call on extension deactivate, and before login). */
export function disposeBrowserSession() {
	session?.dispose();
	session = null;
}
