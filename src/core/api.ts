import { sendRequest } from "../service/http.service";
import {
	QuestionAPI,
	AnswerAPI,
	AnswerURL,
	ZhuanlanAPI,
	ZhuanlanURL,
	SelfProfileAPI,
} from "../const/URL";
import { PostAnswer } from "../model/publish/answer.model";
import { renderZhihuHtml } from "./markdown";
import {
	fetchQuestion,
	fetchAnswer,
	fetchArticle,
	QuestionData,
	ZhihuAuthored,
} from "../service/browser-session.service";

/**
 * Host-agnostic Zhihu operations shared by the VSCode extension and the MCP
 * server. Reads go through the headless browser (content APIs are signature
 * gated); writes go through the plain HTTP API (verified to need only cookies +
 * x-xsrftoken, no x-zse-96).
 */

export interface WriteResult {
	success: boolean;
	status?: number;
	url?: string;
	id?: string;
	error?: string;
}

const ZHUANLAN_WRITE_HEADERS = {
	authority: "zhuanlan.zhihu.com",
	origin: "https://zhuanlan.zhihu.com",
	referer: "https://zhuanlan.zhihu.com/write",
	"x-requested-with": "fetch",
	"content-type": "application/json",
};

// ---------- reads (browser-backed) ----------

export function getQuestion(id: string): Promise<QuestionData> {
	return fetchQuestion(id);
}
export function getAnswer(id: string): Promise<{ title: string; answer: ZhihuAuthored }> {
	return fetchAnswer(id);
}
export function getArticle(id: string): Promise<ZhihuAuthored & { title: string }> {
	return fetchArticle(id);
}

/** The logged-in user, or null if not authenticated. */
export async function getMe(): Promise<any | null> {
	try {
		const resp = await sendRequest({
			uri: `${SelfProfileAPI}?include=is_realname`,
			json: true,
			simple: false,
			resolveWithFullResponse: true,
		});
		if (resp && resp.statusCode === 200 && resp.body && (resp.body.id || resp.body.name)) {
			return resp.body;
		}
		return null;
	} catch {
		return null;
	}
}

// ---------- writes (HTTP API) ----------

/** Post a new answer to a question. `markdown` is rendered to Zhihu HTML. */
export async function publishAnswer(questionId: string, markdown: string): Promise<WriteResult> {
	const html = renderZhihuHtml(markdown);
	const resp = await sendRequest({
		uri: `${QuestionAPI}/${questionId}/answers`,
		method: "post",
		body: new PostAnswer(html),
		json: true,
		simple: false,
		resolveWithFullResponse: true,
		headers: {},
	});
	if (resp && resp.statusCode === 200 && resp.body && resp.body.id) {
		return { success: true, status: 200, id: String(resp.body.id), url: `${AnswerURL}/${resp.body.id}` };
	}
	return {
		success: false,
		status: resp && resp.statusCode,
		error: describeError(resp),
	};
}

/** Update the content of an existing answer. */
export async function updateAnswer(answerId: string, markdown: string): Promise<WriteResult> {
	const html = renderZhihuHtml(markdown);
	const resp = await sendRequest({
		uri: `${AnswerAPI}/${answerId}`,
		method: "put",
		body: { content: html, reward_setting: { can_reward: false, tagline: "" } },
		json: true,
		simple: false,
		resolveWithFullResponse: true,
		headers: {},
	});
	if (resp && resp.statusCode === 200) {
		return { success: true, status: 200, id: answerId, url: `${AnswerURL}/${answerId}` };
	}
	return { success: false, status: resp && resp.statusCode, error: describeError(resp) };
}

// ---------- drafts (private, HTTP API) ----------

export interface DraftResult extends WriteResult {
	/** URL to view/edit the draft in the browser. */
	editUrl?: string;
}

/**
 * Create a NEW private draft article from Markdown (create + patch content).
 * The draft is NOT published; it lives in the user's 草稿箱 until published or
 * deleted. Returns the draft id and its browser edit URL.
 */
export async function createDraft(title: string, markdown: string): Promise<DraftResult> {
	const draft = await sendRequest({
		uri: `${ZhuanlanAPI}/drafts`,
		method: "post",
		body: { title, delta_time: 0 },
		json: true,
		simple: false,
		resolveWithFullResponse: true,
		headers: ZHUANLAN_WRITE_HEADERS,
	});
	const id = draft && draft.body && draft.body.id;
	if (!id) {
		return { success: false, status: draft && draft.statusCode, error: describeError(draft) };
	}
	const patch = await patchDraft(String(id), title, markdown);
	if (!patch.success) return patch;
	return { success: true, status: 200, id: String(id), editUrl: `${ZhuanlanURL}${id}/edit` };
}

/** Update an existing draft's title and/or content (Markdown). */
export async function updateDraft(id: string, opts: { title?: string; markdown?: string }): Promise<DraftResult> {
	return patchDraft(id, opts.title, opts.markdown);
}

async function patchDraft(id: string, title?: string, markdown?: string): Promise<DraftResult> {
	const body: any = {};
	if (title != null) body.title = title;
	if (markdown != null) body.content = renderZhihuHtml(markdown);
	const patch = await sendRequest({
		uri: `${ZhuanlanAPI}/${id}/draft`,
		method: "patch",
		body,
		json: true,
		simple: false,
		resolveWithFullResponse: true,
		headers: ZHUANLAN_WRITE_HEADERS,
	});
	if (patch && patch.statusCode < 300) {
		return { success: true, status: patch.statusCode, id, editUrl: `${ZhuanlanURL}${id}/edit` };
	}
	return { success: false, status: patch && patch.statusCode, id, error: describeError(patch) };
}

/** Read back a draft's current title and (HTML) content. */
export async function getDraft(id: string): Promise<{ title: string; content: string } | null> {
	const resp = await sendRequest({
		uri: `${ZhuanlanAPI}/${id}/draft`,
		method: "get",
		json: true,
		simple: false,
		resolveWithFullResponse: true,
		headers: ZHUANLAN_WRITE_HEADERS,
	});
	if (resp && resp.statusCode === 200 && resp.body) {
		return { title: resp.body.title || "", content: resp.body.content || "" };
	}
	return null;
}

/** Delete a draft (never published). */
export async function deleteDraft(id: string): Promise<WriteResult> {
	const resp = await sendRequest({
		uri: `${ZhuanlanAPI}/${id}/draft`,
		method: "delete",
		json: true,
		simple: false,
		resolveWithFullResponse: true,
		headers: ZHUANLAN_WRITE_HEADERS,
	});
	if (resp && resp.statusCode < 300) return { success: true, status: resp.statusCode, id };
	return { success: false, status: resp && resp.statusCode, id, error: describeError(resp) };
}

/** Publish an existing draft (makes the article PUBLIC). */
export async function publishDraft(id: string, column?: any): Promise<WriteResult> {
	const pub = await sendRequest({
		uri: `${ZhuanlanAPI}/${id}/publish`,
		method: "put",
		body: { column: column || null, commentPermission: "anyone" },
		json: true,
		simple: false,
		resolveWithFullResponse: true,
		headers: ZHUANLAN_WRITE_HEADERS,
	});
	if (pub && pub.statusCode < 300) {
		return { success: true, status: pub.statusCode, id, url: `${ZhuanlanURL}${id}` };
	}
	return { success: false, status: pub && pub.statusCode, id, error: describeError(pub) };
}

/** Publish a new article in one shot: create draft -> publish (PUBLIC). */
export async function publishArticle(
	title: string,
	markdown: string,
	column?: any,
): Promise<WriteResult> {
	const draft = await createDraft(title, markdown);
	if (!draft.success || !draft.id) return draft;
	return publishDraft(draft.id, column);
}

function describeError(resp: any): string {
	if (!resp) return "无响应";
	const b = resp.body;
	if (b && b.error && b.error.message) return b.error.message;
	if (typeof b === "string") return b.slice(0, 200);
	try { return JSON.stringify(b).slice(0, 200); } catch { return `HTTP ${resp.statusCode}`; }
}
