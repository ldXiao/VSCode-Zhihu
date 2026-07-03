
import * as path from "path";
import { compileFile } from "pug";
import * as vscode from "vscode";
import { MediaTypes, SettingEnum, WebviewEvents } from "../const/ENUM";
import { TemplatePath, ZhihuIconPath } from "../const/PATH";
import { AnswerAPI, AnswerURL, QuestionAPI, QuestionURL, ZhuanlanURL, ArticleAPI } from "../const/URL";
import { IArticle } from "../model/article/article-detail";
import { IQuestionAnswerTarget, IQuestionTarget, ITarget } from "../model/target/target";
import { CollectionTreeviewProvider } from "../treeview/collection-treeview-provider";
import { CollectionService, ICollectionItem } from "./collection.service";
import { HttpService, sendRequest } from "./http.service";
import { fetchQuestion, fetchAnswer, fetchArticle } from "./browser-session.service";
import { getExtensionPath, getSubscriptions } from "../global/globa-var";

export interface IWebviewPugRender {
	viewType?: string,
	title?: string,
	showOptions?: vscode.ViewColumn | { viewColumn: vscode.ViewColumn, preserveFocus?: boolean },
	options?: vscode.WebviewOptions & vscode.WebviewPanelOptions,
	pugTemplatePath: string,
	pugObjects?: any,
	iconPath?: any
}

export class WebviewService {

	constructor(
		protected collectService: CollectionService,
		protected collectionTreeviewProvider: CollectionTreeviewProvider
	) {
	}

	/**
	 * Create and show a webview provided by pug
	 */
	public renderHtml(w: IWebviewPugRender, panel?: vscode.WebviewPanel): vscode.WebviewPanel {
		if (panel == undefined) {
			panel = vscode.window.createWebviewPanel(
				w.viewType ? w.viewType : 'zhihu',
				w.title ? w.title : '知乎',
				w.showOptions ? w.showOptions : vscode.ViewColumn.One,
				w.options ? w.options : { enableScripts: true }
			);
		}
		const compiledFunction = compileFile(
			w.pugTemplatePath
		);
		panel.iconPath = vscode.Uri.file(w.iconPath ? w.iconPath : path.join(
			getExtensionPath(),
			ZhihuIconPath));
		panel.webview.html = compiledFunction(w.pugObjects);
		return panel;
	}

	public async openWebview(object: ITarget & any) {
		if (!object) {
			vscode.window.showErrorMessage('无效的对象，无法打开网页视图');
			return;
		}

		const useVSTheme = vscode.workspace.getConfiguration('zhihu').get(SettingEnum.useVSTheme);

		try {
			if (object.type == MediaTypes.question) {
				const data = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: "加载知乎问题..." },
					() => fetchQuestion(String(object.id)),
				);
				if (!data || !data.answers || data.answers.length === 0) {
					vscode.window.showWarningMessage('未获取到回答，可能需要登录或稍后重试。');
					return;
				}
				data.answers.forEach((a) => (a.content = this.actualSrcNormalize(a.content)));
				const panel = this.renderHtml({
					title: "知乎问题",
					pugTemplatePath: path.join(getExtensionPath(), TemplatePath, "questions-answers.pug"),
					pugObjects: {
						answers: data.answers,
						title: data.title || object.title || "知乎问题",
						subTitle: data.detail || "",
						useVSTheme,
					},
				});
				this.registerEvent(panel, { type: MediaTypes.question, id: object.id }, `${QuestionURL}/${object.id}`);
			} else if (object.type == MediaTypes.answer) {
				const data = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: "加载知乎回答..." },
					() => fetchAnswer(String(object.id)),
				);
				if (!data || !data.answer || data.answer.content == undefined) {
					vscode.window.showWarningMessage('未获取到回答内容，可能需要登录或稍后重试。');
					return;
				}
				data.answer.content = this.actualSrcNormalize(data.answer.content);
				const panel = this.renderHtml({
					title: "知乎回答",
					pugTemplatePath: path.join(getExtensionPath(), TemplatePath, "questions-answers.pug"),
					pugObjects: { answers: [data.answer], title: data.title, useVSTheme },
				});
				this.registerEvent(panel, { type: MediaTypes.answer, id: object.id }, `${AnswerURL}/${object.id}`);
			} else if (object.type == MediaTypes.article) {
				const articleId = object.id || (object.url ? String(object.url).split('/').pop() : undefined);
				if (!articleId) {
					vscode.window.showErrorMessage('文章缺少ID信息');
					return;
				}
				const article = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: "加载知乎文章..." },
					() => fetchArticle(String(articleId)),
				);
				if (!article || article.content == undefined) {
					vscode.window.showWarningMessage('未获取到文章内容，可能需要登录或稍后重试。');
					return;
				}
				article.content = this.actualSrcNormalize(article.content);
				const panel = this.renderHtml({
					title: "知乎文章",
					pugTemplatePath: path.join(getExtensionPath(), TemplatePath, "article.pug"),
					pugObjects: { article, title: article.title || "知乎文章", useVSTheme },
				});
				this.registerEvent(panel, { type: MediaTypes.article, id: articleId }, `${ZhuanlanURL}${articleId}`);
			}
		} catch (error) {
			vscode.window.showErrorMessage(`加载失败：${error.message || error}`);
		}
	}

	private registerEvent(panel: vscode.WebviewPanel, c: ICollectionItem, link?: string) {
		panel.webview.onDidReceiveMessage(e => {
			if (e.command == WebviewEvents.collect) {
				if (this.collectService.addItem(c)) {
					vscode.window.showInformationMessage('收藏成功！');
				} else {
					vscode.window.showWarningMessage('你已经收藏了它！');
				}
				this.collectionTreeviewProvider.refresh()
			} else if (e.command == WebviewEvents.open) {
				vscode.env.openExternal(vscode.Uri.parse(link));
			} else if (e.command == WebviewEvents.share) {
				vscode.env.clipboard.writeText(link).then(() => {
					vscode.window.showInformationMessage('链接已复制至粘贴板。');
				})
			} else if (e.command == WebviewEvents.upvoteAnswer) {
				sendRequest({
					uri: `${AnswerAPI}/${e.id}/voters`,
					method: 'post',
					headers: {},
					json: true,
					body: { type: "up" },
					resolveWithFullResponse: true
				}).then(r => {if(r.statusCode == 200) vscode.window.showInformationMessage('点赞成功！')
				else if(r.statusCode == 403) vscode.window.showWarningMessage('你已经投过票了！')})
			} else if (e.command == WebviewEvents.upvoteArticle) {
				sendRequest({
					uri: `${ArticleAPI}/${e.id}/voters`,
					method: 'post',
					headers: {},
					json: true,
					body: { voting: 1 },
					resolveWithFullResponse: true
				}).then(r => { if(r.statusCode == 200) vscode.window.showInformationMessage('点赞成功！')
					else if(r.statusCode == 403) vscode.window.showWarningMessage('你已经投过票了！');
				})
			}
		}, undefined, getSubscriptions())
	}

	private actualSrcNormalize(html: string): string {
		return html.replace(/<\/?noscript>/g, '');
	}
}