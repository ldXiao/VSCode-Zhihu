#!/usr/bin/env node
import * as os from "os";
import * as path from "path";
import * as fs from "fs";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { setEnv } from "../core/env";
import {
	getMe,
	getQuestion,
	getAnswer,
	getArticle,
	publishAnswer,
	updateAnswer,
	publishArticle,
	createDraft,
	updateDraft,
	getDraft,
	deleteDraft,
	publishDraft,
} from "../core/api";
import { loginAndSave, importCookieString } from "../core/session";
import { disposeBrowserSession } from "../service/browser-session.service";

// ---- host wiring: point the vscode-free core at a config dir + stderr logging ----
const dataDir = process.env.ZHIHU_MCP_DATA_DIR || path.join(os.homedir(), ".zhihu-mcp");
try { fs.mkdirSync(dataDir, { recursive: true }); } catch { /* exists */ }

setEnv({
	dataDir,
	log: (message: string) => process.stderr.write(`[zhihu-mcp] ${message}\n`),
	getSetting: () => undefined,
});

// Optional: seed the session from a pasted cookie string via env.
if (process.env.ZHIHU_COOKIE) {
	try {
		const n = importCookieString(process.env.ZHIHU_COOKIE);
		process.stderr.write(`[zhihu-mcp] imported ${n} cookies from ZHIHU_COOKIE\n`);
	} catch { /* ignore */ }
}

function text(s: string) {
	return { content: [{ type: "text" as const, text: s }] };
}
function errText(s: string) {
	return { content: [{ type: "text" as const, text: s }], isError: true };
}
function htmlToText(html: string): string {
	return (html || "")
		.replace(/<\/(p|div|h[1-6]|li|blockquote)>/gi, "\n\n")
		.replace(/<br\s*\/?>/gi, "\n")
		.replace(/<[^>]+>/g, "")
		.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
		.replace(/\n{3,}/g, "\n\n").trim();
}

const server = new McpServer({ name: "zhihu-mcp", version: "0.1.0" });

server.registerTool("zhihu_whoami", {
	description: "Return the currently logged-in Zhihu user, or indicate that login is required.",
	inputSchema: {},
}, async () => {
	const me = await getMe();
	if (!me) return text("Not logged in. Run zhihu_login (opens a browser to scan the QR), or set ZHIHU_COOKIE.");
	return text(`Logged in as ${me.name}${me.headline ? " — " + me.headline : ""} (id: ${me.id}).`);
});

server.registerTool("zhihu_login", {
	description: "Log in to Zhihu by launching a browser to scan the QR code with the Zhihu app. Blocks until login completes (up to ~3 minutes). Persists the session for future calls.",
	inputSchema: {},
}, async () => {
	try {
		const cookies = await loginAndSave({
			onProgress: (m) => process.stderr.write(`[zhihu-mcp] ${m}\n`),
			timeoutMs: 170000,
		});
		if (!cookies || !cookies.length) return errText("Login did not complete.");
		const me = await getMe();
		return text(me ? `Login successful. Welcome ${me.name}.` : "Login cookies saved, but verification failed; try zhihu_whoami.");
	} catch (e: any) {
		return errText(`Login failed: ${e?.message || e}`);
	}
});

server.registerTool("zhihu_get_question", {
	description: "Fetch a Zhihu question and its top answers by question id. Returns the question title, detail, and answers as text.",
	inputSchema: { id: z.string().describe("Zhihu question id, e.g. 19550225") },
}, async ({ id }) => {
	try {
		const q = await getQuestion(String(id));
		if (!q || !q.answers?.length) return errText("No answers found (may require login or the question is empty).");
		const parts = [`# ${q.title}`, q.detail ? htmlToText(q.detail) : "", `\n## ${q.answers.length} answers\n`];
		for (const a of q.answers) {
			parts.push(`### ${a.author?.name || "匿名"} · ${a.voteup_count} 赞\n${htmlToText(a.content)}\n`);
		}
		return text(parts.filter(Boolean).join("\n"));
	} catch (e: any) {
		return errText(`Failed: ${e?.message || e}`);
	}
});

server.registerTool("zhihu_get_answer", {
	description: "Fetch a single Zhihu answer by answer id.",
	inputSchema: { id: z.string().describe("Zhihu answer id") },
}, async ({ id }) => {
	try {
		const r = await getAnswer(String(id));
		if (!r?.answer?.content) return errText("Answer not found.");
		return text(`# ${r.title}\n\n### ${r.answer.author?.name || "匿名"} · ${r.answer.voteup_count} 赞\n\n${htmlToText(r.answer.content)}`);
	} catch (e: any) {
		return errText(`Failed: ${e?.message || e}`);
	}
});

server.registerTool("zhihu_get_article", {
	description: "Fetch a Zhihu column article (zhuanlan) by article id.",
	inputSchema: { id: z.string().describe("Zhihu article id, e.g. from zhuanlan.zhihu.com/p/<id>") },
}, async ({ id }) => {
	try {
		const a = await getArticle(String(id));
		if (!a?.content) return errText("Article not found.");
		return text(`# ${a.title}\n\n### ${a.author?.name || "匿名"} · ${a.voteup_count} 赞\n\n${htmlToText(a.content)}`);
	} catch (e: any) {
		return errText(`Failed: ${e?.message || e}`);
	}
});

server.registerTool("zhihu_publish_answer", {
	description: "Post a NEW answer to a question. Content is Markdown, rendered to Zhihu HTML. Publishes publicly under the logged-in account.",
	inputSchema: {
		question_id: z.string().describe("Zhihu question id to answer"),
		markdown: z.string().describe("Answer content in Markdown"),
	},
}, async ({ question_id, markdown }) => {
	const r = await publishAnswer(String(question_id), markdown);
	return r.success ? text(`Answer published: ${r.url}`) : errText(`Publish failed (${r.status}): ${r.error}`);
});

server.registerTool("zhihu_update_answer", {
	description: "Update the content of an existing answer you authored. Content is Markdown.",
	inputSchema: {
		answer_id: z.string().describe("Zhihu answer id to update"),
		markdown: z.string().describe("New answer content in Markdown"),
	},
}, async ({ answer_id, markdown }) => {
	const r = await updateAnswer(String(answer_id), markdown);
	return r.success ? text(`Answer updated: ${r.url}`) : errText(`Update failed (${r.status}): ${r.error}`);
});

server.registerTool("zhihu_publish_article", {
	description: "Publish a NEW column article (zhuanlan). Content is Markdown, rendered to Zhihu HTML. Publishes publicly under the logged-in account.",
	inputSchema: {
		title: z.string().describe("Article title"),
		markdown: z.string().describe("Article body in Markdown"),
	},
}, async ({ title, markdown }) => {
	const r = await publishArticle(String(title), markdown);
	return r.success ? text(`Article published: ${r.url}`) : errText(`Publish failed (${r.status}): ${r.error}`);
});

// ---- draft lifecycle (private until published) ----

server.registerTool("zhihu_create_draft", {
	description: "Create a NEW PRIVATE draft article from Markdown (not published). Returns the draft id and its browser edit URL. Use zhihu_publish_draft later to make it public.",
	inputSchema: {
		title: z.string().describe("Draft title"),
		markdown: z.string().describe("Draft body in Markdown"),
	},
}, async ({ title, markdown }) => {
	const r = await createDraft(String(title), markdown);
	return r.success
		? text(`Draft created (private). id: ${r.id}\nEdit: ${r.editUrl}\n草稿箱: https://zhuanlan.zhihu.com/write`)
		: errText(`Create draft failed (${r.status}): ${r.error}`);
});

server.registerTool("zhihu_get_draft", {
	description: "Read back an existing draft's title and content by draft id.",
	inputSchema: { id: z.string().describe("Draft/article id") },
}, async ({ id }) => {
	const d = await getDraft(String(id));
	if (!d) return errText("Draft not found.");
	return text(`# ${d.title}\n\n${htmlToText(d.content)}`);
});

server.registerTool("zhihu_update_draft", {
	description: "Update an existing draft's title and/or content (Markdown). The draft stays private.",
	inputSchema: {
		id: z.string().describe("Draft/article id"),
		title: z.string().optional().describe("New title (optional)"),
		markdown: z.string().optional().describe("New body in Markdown (optional)"),
	},
}, async ({ id, title, markdown }) => {
	const r = await updateDraft(String(id), { title, markdown });
	return r.success ? text(`Draft updated. Edit: ${r.editUrl}`) : errText(`Update failed (${r.status}): ${r.error}`);
});

server.registerTool("zhihu_publish_draft", {
	description: "Publish an existing draft, making the article PUBLIC under the logged-in account.",
	inputSchema: { id: z.string().describe("Draft/article id to publish") },
}, async ({ id }) => {
	const r = await publishDraft(String(id));
	return r.success ? text(`Published: ${r.url}`) : errText(`Publish failed (${r.status}): ${r.error}`);
});

server.registerTool("zhihu_delete_draft", {
	description: "Delete a draft (that has not been published).",
	inputSchema: { id: z.string().describe("Draft/article id to delete") },
}, async ({ id }) => {
	const r = await deleteDraft(String(id));
	return r.success ? text(`Draft ${id} deleted.`) : errText(`Delete failed (${r.status}): ${r.error}`);
});

async function main() {
	const transport = new StdioServerTransport();
	await server.connect(transport);
	process.stderr.write(`[zhihu-mcp] ready (dataDir: ${dataDir})\n`);
}

process.on("SIGINT", () => { disposeBrowserSession(); process.exit(0); });
process.on("SIGTERM", () => { disposeBrowserSession(); process.exit(0); });

main().catch((e) => {
	process.stderr.write(`[zhihu-mcp] fatal: ${e?.message || e}\n`);
	process.exit(1);
});
