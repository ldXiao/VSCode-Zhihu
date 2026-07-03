import * as cp from "child_process";
import * as path from "path";
import { getExtensionPath } from "../global/globa-var";
import { Output } from "../global/logger";
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
 * Reads Zhihu content by driving a real (off-screen) browser.
 *
 * Zhihu's content APIs are gated behind anti-bot request signatures (x-zse-96)
 * that only its own page JavaScript produces; headless browsers and
 * CDP-initiated navigations are detected and blocked. Empirically, the only
 * thing Zhihu serves is a normal top-level navigation started from the browser
 * command line. So for each read we launch the browser with the target URL as a
 * startup argument, let it render (running Zhihu's JS, passing anti-bot), then
 * read the data Zhihu embeds in the page's `js-initialData` script tag over the
 * DevTools Protocol, and shut the browser down.
 *
 * Reuses the `.browser-login-profile` from login so it shares the signed-in
 * session. Reads are serialized and the browser process tree is fully killed
 * between reads to avoid same-profile launch contention (a second launch on a
 * live profile just forwards to the first instance and exits).
 */

let queue: Promise<any> = Promise.resolve();

function profileDir(): string {
	return path.join(getExtensionPath(), ".browser-login-profile");
}

function killTree(pid: number | undefined, child: cp.ChildProcess) {
	if (pid && process.platform === "win32") {
		try {
			cp.execSync(`taskkill /PID ${pid} /T /F`, { stdio: "ignore" });
			return;
		} catch {
			/* fall through to child.kill */
		}
	}
	try {
		child.kill();
	} catch {
		/* noop */
	}
}

/**
 * Launch the browser at `url`, evaluate `extractorExpr` in the page until it
 * returns a non-null JSON string (or a {__blocked:1} marker), and return the
 * parsed value. `extractorExpr` is a JS expression string evaluated in the page.
 */
async function launchAndExtract(url: string, extractorExpr: string): Promise<any> {
	const browser = findBrowser();
	if (!browser) {
		throw new Error("未找到 Chrome/Edge 浏览器，无法加载知乎内容。请先安装 Chrome 或 Edge。");
	}
	const port = await getFreePort();
	const args = [
		`--remote-debugging-port=${port}`,
		`--user-data-dir=${profileDir()}`,
		"--no-first-run",
		"--no-default-browser-check",
		"--remote-allow-origins=*",
		// A real (non-headless) window positioned off-screen: Zhihu's anti-bot
		// accepts it, but the user never sees it.
		"--window-position=-2400,-2400",
		url,
	];
	Output(`加载知乎内容: ${url}`, "info");
	const child = cp.spawn(browser.path, args, { stdio: "ignore", detached: false });
	const exited = new Promise<void>((r) => child.on("exit", () => r()));

	try {
		// Find the page target for our URL.
		let pageWsUrl: string | undefined;
		for (let i = 0; i < 50; i++) {
			try {
				const list: any[] = await httpGetJson(`http://127.0.0.1:${port}/json/list`);
				const page = list.find(
					(t) => t.type === "page" && t.webSocketDebuggerUrl && /zhihu\.com/.test(t.url),
				);
				if (page) {
					pageWsUrl = page.webSocketDebuggerUrl;
					break;
				}
			} catch {
				/* browser not ready */
			}
			await sleep(300);
		}
		if (!pageWsUrl) {
			throw new Error("无法连接后台浏览器页面，请重试。");
		}

		const cdp = await CDPClient.connect(pageWsUrl);
		try {
			await cdp.send("Runtime.enable");
			const deadline = Date.now() + 25000;
			while (Date.now() < deadline) {
				await sleep(700);
				let value: string | null = null;
				try {
					const res = await cdp.send("Runtime.evaluate", {
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
			cdp.close();
		}
	} finally {
		killTree(child.pid, child);
		// Wait for the process (and its children) to release the profile lock
		// before the next queued read launches on the same profile.
		await Promise.race([exited, sleep(3000)]);
		await sleep(1200);
	}
}

/** Serialize reads so only one browser uses the profile at a time. */
function enqueue<T>(fn: () => Promise<T>): Promise<T> {
	const task = queue.then(fn);
	queue = task.catch(() => undefined);
	return task;
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
	return enqueue(() => launchAndExtract(`https://www.zhihu.com/question/${id}`, expr));
}

export function fetchAnswer(id: string): Promise<{ title: string; answer: ZhihuAuthored }> {
	const expr = entitiesExpr(`
		var a=(e.answers&&(e.answers["${id}"]||e.answers[Object.keys(e.answers)[0]]));
		if(!a)return null;
		var qid=Object.keys(e.questions||{})[0];
		var q=qid?e.questions[qid]:{};
		return JSON.stringify({title:(a.question&&a.question.title)||q.title||"\\u77e5\\u4e4e\\u56de\\u7b54",answer:map(a)});
	`);
	return enqueue(() => launchAndExtract(`https://www.zhihu.com/answer/${id}`, expr));
}

export function fetchArticle(id: string): Promise<ZhihuAuthored & { title: string }> {
	const expr = entitiesExpr(`
		var a=(e.articles&&(e.articles["${id}"]||e.articles[Object.keys(e.articles)[0]]));
		if(!a)return null;
		var m=map(a);m.title=a.title||"\\u77e5\\u4e4e\\u6587\\u7ae0";
		return JSON.stringify(m);
	`);
	return enqueue(() => launchAndExtract(`https://zhuanlan.zhihu.com/p/${id}`, expr));
}

/** No persistent browser is kept; nothing to dispose. Kept for API stability. */
export function disposeBrowserSession() {
	/* no-op: browsers are launched per-read and killed immediately */
}
