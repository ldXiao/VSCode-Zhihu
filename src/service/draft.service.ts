import * as vscode from "vscode";
import { createDraft, updateDraft, publishDraft } from "../core/api";
import { Output } from "../global/logger";

/**
 * Draft authoring commands for the VSCode extension, backed by the shared core
 * draft lifecycle. Lets the user save the current Markdown file as a PRIVATE
 * Zhihu draft, refine it, and publish when ready — mirroring the MCP draft tools.
 *
 * The draft id is tracked with a shebang line at the top of the file:
 *   #! https://zhuanlan.zhihu.com/p/<id>
 * so a second "Save as Draft" updates the same draft, and "Publish Draft" knows
 * which draft to publish.
 */
const SHEBANG_REG = /^#!\s*(?:https?:\/\/zhuanlan\.zhihu\.com\/p\/)?(\d+)/i;

export class DraftService {
	/** Create a new draft from the current editor, or update the existing one. */
	public async saveDraft() {
		const editor = vscode.window.activeTextEditor;
		if (!editor || editor.document.languageId !== "markdown") {
			vscode.window.showWarningMessage("请在 Markdown 文件中使用此命令。");
			return;
		}
		const full = editor.document.getText();
		const existingId = this.parseDraftId(full);
		const body = this.stripShebang(full);
		const { title, content } = await this.splitTitle(body);
		if (!title) return;

		await vscode.window.withProgress(
			{ location: vscode.ProgressLocation.Notification, title: existingId ? "更新草稿中..." : "保存草稿中..." },
			async () => {
				if (existingId) {
					const r = await updateDraft(existingId, { title, markdown: content });
					if (r.success) {
						this.showDone("草稿已更新", r.editUrl);
					} else {
						vscode.window.showErrorMessage(`更新草稿失败 (${r.status}): ${r.error}`);
					}
					return;
				}
				const r = await createDraft(title, content);
				if (r.success && r.id) {
					await this.insertShebang(editor, `https://zhuanlan.zhihu.com/p/${r.id}`);
					this.showDone("草稿已创建（私密，未公开）", r.editUrl);
					Output(`草稿已创建: ${r.id}`, "info");
				} else {
					vscode.window.showErrorMessage(`创建草稿失败 (${r.status}): ${r.error}`);
				}
			},
		);
	}

	/** Publish the draft referenced by the current file's shebang (makes it public). */
	public async publishDraft() {
		const editor = vscode.window.activeTextEditor;
		if (!editor || editor.document.languageId !== "markdown") {
			vscode.window.showWarningMessage("请在 Markdown 文件中使用此命令。");
			return;
		}
		const id = this.parseDraftId(editor.document.getText());
		if (!id) {
			vscode.window.showWarningMessage("未找到草稿，请先执行 “Zhihu: Save as Draft”。");
			return;
		}
		const confirm = await vscode.window.showWarningMessage(
			"确认将该草稿公开发布到你的知乎账号？", { modal: true }, "发布",
		);
		if (confirm !== "发布") return;

		await vscode.window.withProgress(
			{ location: vscode.ProgressLocation.Notification, title: "发布中..." },
			async () => {
				const r = await publishDraft(id);
				if (r.success) {
					this.showDone("发布成功！", r.url, "打开文章");
				} else {
					vscode.window.showErrorMessage(`发布失败 (${r.status}): ${r.error}`);
				}
			},
		);
	}

	private parseDraftId(text: string): string | undefined {
		const firstLine = text.split(/\r?\n/, 1)[0] || "";
		const m = SHEBANG_REG.exec(firstLine.trim());
		return m ? m[1] : undefined;
	}

	private stripShebang(text: string): string {
		return SHEBANG_REG.test(text.split(/\r?\n/, 1)[0] || "")
			? text.slice(text.indexOf("\n") + 1)
			: text;
	}

	/** Use the first H1 as the title (removed from the body), else prompt. */
	private async splitTitle(body: string): Promise<{ title?: string; content: string }> {
		const lines = body.split(/\r?\n/);
		const idx = lines.findIndex((l) => /^#\s+\S/.test(l));
		if (idx >= 0) {
			const title = lines[idx].replace(/^#\s+/, "").trim();
			lines.splice(idx, 1);
			return { title, content: lines.join("\n").trim() };
		}
		const title = await vscode.window.showInputBox({
			ignoreFocusOut: true,
			prompt: "输入草稿标题（或在正文首行用 # 一级标题）",
		});
		return { title: title || undefined, content: body };
	}

	private async insertShebang(editor: vscode.TextEditor, url: string) {
		await editor.edit((e) => e.insert(new vscode.Position(0, 0), `#! ${url}\n`));
	}

	private showDone(message: string, url?: string, openLabel = "打开草稿") {
		if (!url) {
			vscode.window.showInformationMessage(message);
			return;
		}
		vscode.window.showInformationMessage(message, openLabel).then((c) => {
			if (c === openLabel) vscode.env.openExternal(vscode.Uri.parse(url));
		});
	}
}
