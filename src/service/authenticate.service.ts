import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import * as zhihuEncrypt from "zhihu-encrypt";
import * as cheerio from "cheerio";
import { DefaultHTTPHeader, LoginPostHeader, QRCodeOptionHeader, WeixinLoginHeader } from "../const/HTTP";
import { TemplatePath } from "../const/PATH";
import { CaptchaAPI, LoginAPI, SMSAPI, QRCodeAPI, UDIDAPI, WeixinLoginPageAPI, WeixinLoginQRCodeAPI, WeixinState, WeixinLoginRedirectAPI, JianshuWeixinLoginRedirectAPI } from "../const/URL";
import { ILogin, ISmsData } from "../model/login.model";
import { FeedTreeViewProvider } from "../treeview/feed-treeview-provider";
import { LoginEnum, LoginTypes, SettingEnum, JianshuLoginTypes } from "../const/ENUM";
import { AccountService } from "./account.service";
import { HttpService, clearCookie, sendRequest } from "./http.service";
import { ProfileService } from "./profile.service";
import { WebviewService } from "./webview.service";
import { getExtensionPath } from "../global/globa-var";
import { Output } from "../global/logger";

var formurlencoded = require('form-urlencoded').default;

export class AuthenticateService {
	constructor(
		protected profileService: ProfileService,
		protected accountService: AccountService,
		protected feedTreeViewProvider: FeedTreeViewProvider,
		protected webviewService: WebviewService) {
	}
	public logout() {
		try {
			clearCookie();
			this.feedTreeViewProvider.refresh();
			// fs.writeFileSync(path.join(getExtensionPath(), 'cookie.txt'), '');
		} catch (error) {
			console.log(error);
		}
		vscode.window.showInformationMessage('注销成功！');
	}

	public async login() {
		try {
			Output('开始登录流程...', 'info');
			
			try {
				const isAuth = await this.accountService.isAuthenticated();
				Output(`认证检查结果: ${isAuth}`, 'info');
				
				if (isAuth) {
					vscode.window.showInformationMessage(`你已经登录了哦~ ${this.profileService.name}`);
					return;
				}
			} catch (authError) {
				Output(`认证检查失败: ${authError}`, 'error');
				// Continue with login flow even if auth check fails
			}
			
			Output('清除cookie...', 'info');
			try {
				clearCookie();
				Output('cookie清除成功', 'info');
			} catch (cookieError) {
				Output(`清除cookie失败: ${cookieError}`, 'error');
			}
			
			Output('显示登录方式选择...', 'info');
			try {
				Output(`LoginTypes: ${JSON.stringify(LoginTypes)}`, 'info');
				
				const mappedTypes = LoginTypes.map(type => ({ 
					value: type.value, 
					label: type.ch, 
					description: '' 
				}));
				Output(`映射后的类型: ${JSON.stringify(mappedTypes)}`, 'info');
				
				const selectedItem = await vscode.window.showQuickPick<vscode.QuickPickItem & { value: LoginEnum }>(
					mappedTypes,
					{ placeHolder: "选择登录方式: " }
				);

				if (!selectedItem) {
					// User cancelled the selection
					Output('用户取消了登录选择', 'info');
					return;
				}

				const selectedLoginType: LoginEnum = selectedItem.value;
				Output(`用户选择登录方式: ${selectedLoginType}`, 'info');

				if (selectedLoginType == LoginEnum.password) {
					this.passwordLogin();
				} else if (selectedLoginType == LoginEnum.sms) {
					this.smsLogin();
				} else if (selectedLoginType == LoginEnum.qrcode) {
					this.qrcodeLogin();
				} else if (selectedLoginType == LoginEnum.weixin) {
					this.weixinLogin();
				}
			} catch (quickPickError) {
				Output(`快速选择失败: ${quickPickError}`, 'error');
				throw quickPickError;
			}
		} catch (error) {
			Output(`登录过程出错: ${error}`, 'error');
			Output(`错误堆栈: ${error.stack}`, 'error');
			vscode.window.showErrorMessage(`登录失败: ${error.message || error}`);
		}
	}

	public async jianshuLogin() {
		const selectedItem = await vscode.window.showQuickPick<vscode.QuickPickItem & { value: LoginEnum }>(
			JianshuLoginTypes.map(type => ({ value: type.value, label: type.ch, description: '' })),
			{ placeHolder: "选择登录方式: " }
		);

		if (!selectedItem) {
			// User cancelled the selection
			return;
		}

		const selectedLoginType: LoginEnum = selectedItem.value;

		if (selectedLoginType == LoginEnum.weixin) {
			this.jianshuWeixinLogin();
		}
	}

	public async passwordLogin() {
		let resp = await sendRequest({
			uri: CaptchaAPI,
			method: 'get',
			gzip: true,
			json: true
		});

		if (resp.show_captcha) {
			let captchaImg = await sendRequest({
				uri: CaptchaAPI,
				method: 'put',
				json: true,
				gzip: true
			});
			let base64Image = captchaImg['img_base64'].replace('\n', '');
			fs.writeFileSync(path.join(getExtensionPath(), './captcha.jpg'), base64Image, 'base64');
			const panel = vscode.window.createWebviewPanel("zhihu", "验证码", { viewColumn: vscode.ViewColumn.One, preserveFocus: true });
			const imgSrc = vscode.Uri.file(
				path.join(getExtensionPath(), './captcha.jpg')
			).with({ scheme: 'vscode-resource' });

			this.webviewService.renderHtml({
				title: '验证码',
				showOptions: {
					viewColumn: vscode.ViewColumn.One,
					preserveFocus: true
				},
				pugTemplatePath: path.join(
					getExtensionPath(),
					TemplatePath,
					'captcha.pug'
				),
				pugObjects: {
					title: '验证码',
					captchaSrc: imgSrc.toString(),
					useVSTheme: vscode.workspace.getConfiguration('zhihu').get(SettingEnum.useVSTheme)
				}
			}, panel)

			do {
				var captcha: string | undefined = await vscode.window.showInputBox({
					prompt: "输入验证码",
					placeHolder: "",
					ignoreFocusOut: true
				});
				if (!captcha) return
				let headers = DefaultHTTPHeader;
				headers['cookie'] = fs.readFileSync
				resp = await sendRequest({
					method: 'POST',
					uri: CaptchaAPI,
					form: {
						input_text: captcha
					},
					json: true,
					simple: false,
					gzip: true,
					resolveWithFullResponse: true,
				});
				if (resp.statusCode != 201) {
					vscode.window.showWarningMessage('请输入正确的验证码')
				}
			} while (resp.statusCode != 201);
			Output('验证码正确。', 'info')
			panel.dispose()
		}

		const phoneNumber: string | undefined = await vscode.window.showInputBox({
			ignoreFocusOut: true,
			prompt: "输入手机号或邮箱",
			placeHolder: "",
		});
		if (!phoneNumber) return;

		const password: string | undefined = await vscode.window.showInputBox({
			ignoreFocusOut: true,
			prompt: "输入密码",
			placeHolder: "",
			password: true
		});
		if (!password) return

		let loginData: ILogin = {
			'client_id': 'c3cef7c66a1843f8b3a9e6a1e3160e20',
			'grant_type': 'password',
			'source': 'com.zhihu.web',
			'username': '+86' + phoneNumber,
			'password': password,
			'lang': 'en',
			'ref_source': 'homepage',
			'utm_source': '',
			'captcha': captcha,
			'timestamp': Math.round(new Date().getTime()),
			'signature': ''
		};

		loginData.signature = crypto.createHmac('sha1', 'd1b964811afb40118a12068ff74a12f4')
			// .update(loginData.grant_type + loginData.client_id + loginData.source + loginData.timestamp.toString())
			.update("password" + loginData.client_id + loginData.source + loginData.timestamp.toString())
			.digest('hex');

		let encryptedFormData = zhihuEncrypt.loginEncrypt(formurlencoded(loginData));

		var loginResp = await sendRequest(
			{
				uri: LoginAPI,
				method: 'post',
				body: encryptedFormData,
				gzip: true,
				resolveWithFullResponse: true,
				simple: false,
				headers: LoginPostHeader
			});

		this.profileService.fetchProfile().then(() => {
			if (loginResp.statusCode == '201') {
				Output(`你好，${this.profileService.name}`, 'info');
				this.feedTreeViewProvider.refresh();
			} else if (loginResp.statusCode == '401') {
				Output('密码错误！' + loginResp.statusCode, 'warn');
			} else {
				Output('登录失败！错误代码' + loginResp.statusCode, 'warn');
			}
		})
	}

	public async smsLogin() {
		await sendRequest({
			uri: 'https://www.zhihu.com/signin'
		})
		const phoneNumber: string | undefined = await vscode.window.showInputBox({
			ignoreFocusOut: true,
			prompt: "输入手机号或邮箱",
			placeHolder: "",
		});
		if (!phoneNumber) {
			return;
		}
		let smsData: ISmsData = {
			phone_no: '+86' + phoneNumber,
			sms_type: 'text'
		};

		let encryptedFormData = zhihuEncrypt.smsEncrypt(formurlencoded(smsData));

		// phone_no%3D%252B8618324748963%26sms_type%3Dtext
		var loginResp = await sendRequest(
			{
				uri: SMSAPI,
				method: 'post',
				body: encryptedFormData,
				gzip: true,
				resolveWithFullResponse: true,
				simple: false,
				json: true
			});
		console.log(loginResp);
		const smsCaptcha: string | undefined = await vscode.window.showInputBox({
			ignoreFocusOut: true,
			prompt: "输入短信验证码：",
			placeHolder: "",
		});
	}

	public async qrcodeLogin() {
		// Use the improved legacy QR code method with better error handling
		await this.improvedQrcodeLogin();
	}

	/**
	 * Improved QR code login with better headers and error handling
	 */
	private async improvedQrcodeLogin() {
		try {
			Output('初始化QR码登录...', 'info');
			
			// Get UDID first
			await sendRequest({
				uri: UDIDAPI,
				method: 'post'
			});
			
			// Get QR code token with improved headers
			let resp = await sendRequest({
				uri: QRCodeAPI,
				method: 'post',
				json: true,
				gzip: true,
				headers: {
					'accept': '*/*',
					'accept-language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6',
					'sec-fetch-dest': 'empty',
					'sec-fetch-mode': 'cors',
					'sec-fetch-site': 'same-origin',
					'x-requested-with': 'fetch',
					'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
					'referer': 'https://www.zhihu.com/signin?next=%2F'
				}
			});
			
			if (!resp || !resp.token) {
				vscode.window.showErrorMessage('获取QR码失败');
				Output(`QR码响应: ${JSON.stringify(resp)}`, 'error');
				return;
			}
			
			Output(`获取到QR码token: ${resp.token}`, 'info');
			
			// Get QR code image
			let qrcode = await sendRequest({
				uri: `${QRCodeAPI}/${resp.token}/image`,
				encoding: null
			});
			
			fs.writeFileSync(path.join(getExtensionPath(), 'qrcode.png'), qrcode);
			
			const panel = vscode.window.createWebviewPanel("zhihu", "扫码登录", { viewColumn: vscode.ViewColumn.One, preserveFocus: true });
			const imgSrc = vscode.Uri.file(
				path.join(getExtensionPath(), './qrcode.png')
			).with({ scheme: 'vscode-resource' });

			this.webviewService.renderHtml(
				{
					title: '二维码',
					showOptions: {
						viewColumn: vscode.ViewColumn.One,
						preserveFocus: true
					},
					pugTemplatePath: path.join(
						getExtensionPath(),
						TemplatePath,
						'qrcode.pug'
					),
					pugObjects: {
						title: '请使用知乎APP扫一扫',
						qrcodeSrc: imgSrc.toString(),
						useVSTheme: vscode.workspace.getConfiguration('zhihu').get(SettingEnum.useVSTheme)
					}
				},
				panel
			);

			// Poll for QR code scan status with improved polling
			await this.pollQrcodeStatus(resp.token, panel);

		} catch (error) {
			Output(`QR码登录失败: ${error}`, 'error');
			vscode.window.showErrorMessage('QR码登录失败，请重试');
		}
	}

	/**
	 * Test method to check the QR code API response
	 */
	public async testModernQrcodeAPI() {
		try {
			Output('开始测试QR码API...', 'info');
			
			// First get UDID
			Output('获取UDID...', 'info');
			await sendRequest({
				uri: UDIDAPI,
				method: 'post'
			});

			Output('调用QR码API...', 'info');
			
			// Get QR code token
			let resp = await sendRequest({
				uri: QRCodeAPI,
				method: 'post',
				json: true,
				resolveWithFullResponse: true,
				headers: {
					'accept': '*/*',
					'accept-language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6',
					'sec-fetch-dest': 'empty',
					'sec-fetch-mode': 'cors',
					'sec-fetch-site': 'same-origin',
					'x-requested-with': 'fetch',
					'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
					'referer': 'https://www.zhihu.com/signin?next=%2F'
				}
			});

			Output(`状态码: ${resp.statusCode}`, 'info');
			Output(`响应头: ${JSON.stringify(resp.headers, null, 2)}`, 'info');
			Output(`响应体: ${JSON.stringify(resp.body, null, 2)}`, 'info');

			if (resp.body && resp.body.token) {
				Output(`获取到token: ${resp.body.token}`, 'info');
				
				// Try to get the QR code image
				try {
					let qrcode = await sendRequest({
						uri: `${QRCodeAPI}/${resp.body.token}/image`,
						encoding: null
					});
					Output(`QR码图片大小: ${qrcode.length} bytes`, 'info');
				} catch (imgError) {
					Output(`获取QR码图片失败: ${imgError}`, 'error');
				}
			}

			return resp;

		} catch (error) {
			Output(`测试QR码API失败: ${error}`, 'error');
			return null;
		}
	}

	/**
	 * Modern QR code login using the browser-like API (deprecated - keeping for reference)
	 */
	private async modernQrcodeLogin() {
		Output('现代QR码API暂时不可用，使用传统方法', 'warn');
		return await this.improvedQrcodeLogin();
	}

	/**
	 * Legacy QR code login for backward compatibility
	 */
	private async legacyQrcodeLogin() {
		return await this.improvedQrcodeLogin();
	}

	/**
	 * Poll QR code scan status with improved feedback
	 */
	private async pollQrcodeStatus(token: string, panel: vscode.WebviewPanel) {
		let intervalId = setInterval(async () => {
			try {
				let statusResp = await sendRequest({
					uri: `${QRCodeAPI}/${token}/scan_info`,
					method: 'get',
					json: true,
					gzip: true,
					headers: {
						'accept': '*/*',
						'accept-language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6',
						'sec-fetch-dest': 'empty',
						'sec-fetch-mode': 'cors',
						'sec-fetch-site': 'same-origin',
						'x-requested-with': 'fetch',
						'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
					}
				});

				Output(`轮询状态: ${JSON.stringify(statusResp)}`, 'info');

				if (statusResp) {
					if (statusResp.status === 0 || statusResp.status === 'waiting') {
						// Still waiting for scan
						// Output('等待扫码...', 'info');
					} else if (statusResp.status === 1 || statusResp.status === 'scanned') {
						vscode.window.showInformationMessage('请在手机上确认登录！');
						Output('已扫码，等待确认...', 'info');
					} else if (statusResp.user_id || statusResp.status === 'confirmed' || statusResp.status === 2) {
						clearInterval(intervalId);
						panel.dispose();
						Output('登录成功！', 'info');
						this.profileService.fetchProfile().then(() => {
							vscode.window.showInformationMessage(`你好，${this.profileService.name}`);
							this.feedTreeViewProvider.refresh();
						})
					} else if (statusResp.status === 'expired' || statusResp.status === -1) {
						clearInterval(intervalId);
						panel.dispose();
						vscode.window.showWarningMessage('QR码已过期，请重新登录');
						Output('QR码已过期', 'warn');
					} else {
						Output(`未知状态: ${JSON.stringify(statusResp)}`, 'warn');
					}
				}
			} catch (error) {
				Output(`轮询状态失败: ${error}`, 'warn');
				// Don't clear interval on network errors, keep trying
			}
		}, 2000);

		panel.onDidDispose(() => {
			Output('QR码窗口已关闭', 'info');
			clearInterval(intervalId)
		})
	}

	public async weixinLogin() {
		await sendRequest({
			uri: 'https://www.zhihu.com/signin?next=%2F',
		});
		let uri = WeixinLoginRedirectAPI();
		let prefetch = await sendRequest({
			uri,
			gzip: true,
			followRedirect: false,
			followAllRedirects: false,
			resolveWithFullResponse: true
		})
		uri = prefetch.headers['location'];
		let html = await sendRequest({
			uri,
			gzip: true
		})
		var reg = /state=(\w+)/g;
		const state = uri.match(reg)[0].replace(reg, '$1');
		const $ = cheerio.load(html)
		const panel = vscode.window.createWebviewPanel("zhihu", "微信登录", { viewColumn: vscode.ViewColumn.One, preserveFocus: true });
		const imgSrc = WeixinLoginQRCodeAPI($('img').attr('src'));
		const uuid = imgSrc.match(/\/connect\/qrcode\/([\w\d]*)/)[1];
		this.webviewService.renderHtml(
			{
				title: '二维码',
				showOptions: {
					viewColumn: vscode.ViewColumn.One,
					preserveFocus: true
				},
				pugTemplatePath: path.join(
					getExtensionPath(),
					TemplatePath,
					'qrcode.pug'
				),
				pugObjects: {
					title: '打开微信 APP 扫一扫',
					qrcodeSrc: imgSrc,
					useVSTheme: vscode.workspace.getConfiguration('zhihu').get(SettingEnum.useVSTheme)
				}
			},
			panel
		);

		var p = "https://lp.open.weixin.qq.com";
		
		var intervalId = setInterval(() => {
			this.weixinPolling(p, uuid, panel, state).then(r => {
				if (r == true) {
					clearInterval(intervalId);
					panel.dispose()
				}
			})

		}, 1000)

		panel.onDidDispose(l => {
			clearInterval(intervalId);
		})
		
		// this.weixinPolling(p, uuid, panel, state);
	}

	public async jianshuWeixinLogin() {
		let uri = JianshuWeixinLoginRedirectAPI();
		let prefetch = await sendRequest({
			uri,
			gzip: true,
			followRedirect: false,
			followAllRedirects: false,
			resolveWithFullResponse: true
		})
		uri = prefetch.headers['location'];
		let html = await sendRequest({
			uri,
			gzip: true
		})
		var reg = /state=([\w%]+)/g;
		const state = uri.match(reg)[0].replace(reg, '$1');
		const $ = cheerio.load(html)
		const panel = vscode.window.createWebviewPanel("zhihu", "微信登录", { viewColumn: vscode.ViewColumn.One, preserveFocus: true });
		const imgSrc = WeixinLoginQRCodeAPI($('img').attr('src'));
		const uuid = imgSrc.match(/\/connect\/qrcode\/([\w\d]*)/)[1];
		this.webviewService.renderHtml(
			{
				title: '二维码',
				showOptions: {
					viewColumn: vscode.ViewColumn.One,
					preserveFocus: true
				},
				pugTemplatePath: path.join(
					getExtensionPath(),
					TemplatePath,
					'qrcode.pug'
				),
				pugObjects: {
					title: '打开微信 APP 扫一扫',
					qrcodeSrc: imgSrc,
					useVSTheme: vscode.workspace.getConfiguration('zhihu').get(SettingEnum.useVSTheme)
				}
			},
			panel
		);

		var p = "https://lp.open.weixin.qq.com";
		
		var intervalId = setInterval(() => {
			this.jianshuWeixinPolling(p, uuid, panel, state).then(r => {
				if (r == true) {
					clearInterval(intervalId);
					panel.dispose()
				}
			})

		}, 1000)

		panel.onDidDispose(l => {
			clearInterval(intervalId)
			panel.dispose()
		})

	}

	private async weixinPolling(p: string, uuid: string, panel: vscode.WebviewPanel, state: string): Promise<boolean> {
		let weixinResp = await sendRequest({
			uri: p + `/connect/l/qrconnect?uuid=${uuid}`,
			timeout: 6e4,
			resolveWithFullResponse: true,
			headers: WeixinLoginHeader(WeixinLoginPageAPI())
		});
		let wx_errcode = ""
		let wx_code = ""

		// if (weixinResp.body && weixinResp.body.length > 0) {
			wx_errcode = weixinResp.body.match(/window\.wx_errcode=(\d+)/)[1];
			wx_code = weixinResp.body.match(/window\.wx_code='(.*)'/)[1];	
		// }
		var g = parseInt(wx_errcode);
		switch (g) {
			case 405:
				var h = "https://www.zhihu.com/oauth/callback/wechat?action=login&amp;from=";
				h = h.replace(/&amp;/g, "&"),
					h += (h.indexOf("?") > -1 ? "&" : "?") + "code=" + wx_code + `&state=${state}`;
				let r = await sendRequest({
					uri: h,
					resolveWithFullResponse: true,
					// gzip: true,
					headers: WeixinLoginHeader(WeixinLoginPageAPI())
				})
				this.profileService.fetchProfile().then(() => {
					Output(`你好，${this.profileService.name}`, 'info');
					this.feedTreeViewProvider.refresh();
				});
				panel.onDidDispose(() => {
					console.log('Window is disposed');
				});
				return Promise.resolve(true);
			case undefined:
				this.weixinPolling(p, uuid, panel, state)
				return Promise.resolve(false);
			default:
				Output('请在微信上扫码， 点击确认！', 'info');
					return Promise.resolve(false);
				// this.weixinPolling(p, uuid, panel, state)
		}
	}

	private async jianshuWeixinPolling(p: string, uuid: string, panel: vscode.WebviewPanel, state: string): Promise<boolean> {
		let weixinResp = await sendRequest({
			uri: p + `/connect/l/qrconnect?uuid=${uuid}`,
			timeout: 6e4,
			resolveWithFullResponse: true,
			headers: WeixinLoginHeader(WeixinLoginPageAPI())
		});
		let wx_code = ""
		let wx_errcode = ""
		if (weixinResp.body && weixinResp.body.length > 0) {
			wx_errcode = weixinResp.body.match(/window\.wx_errcode=(\d+)/)[1];
			wx_code = weixinResp.body.match(/window\.wx_code='(.*)'/)[1];	
		}
		var g = parseInt(wx_errcode);
		switch (g) {
			// "https://open.weixin.qq.com/connect/qrconnect?appid=wxe9199d568fe57fdd&client_id=wxe9199d568fe57fdd&redirect_uri=http%3A%2F%2Fwww.jianshu.com%2Fusers%2Fauth%2Fwechat%2Fcallback&response_type=code&scope=snsapi_login&state=%257B%257D"
			case 405:
				var h = "http://www.jianshu.com/users/auth/wechat/callback";
				// "http://www.jianshu.com/users/auth/wechat/callback?code=021jPsAa1isZkM1Z5zza1turAa1jPsAi&state=%7B%7D"
				h = h.replace(/&amp;/g, "&"),
					h += (h.indexOf("?") > -1 ? "&" : "?") + "code=" + wx_code + `&state=${state}`;
				let r = await sendRequest({
					uri: h,
					resolveWithFullResponse: true,
					gzip: true,
					// headers: WeixinLoginHeader(WeixinLoginPageAPI())
				})
				// request twice, don't know why, but jianshu does this way.
				r = await sendRequest({
					uri: h,
					resolveWithFullResponse: true,
					gzip: true,
					// headers: WeixinLoginHeader(WeixinLoginPageAPI())
				})
				this.profileService.fetchProfile().then(() => {
					Output(`你好，简书登录成功`, 'info');
					this.feedTreeViewProvider.refresh();
				});
				panel.onDidDispose(() => {
					console.log('Window is disposed');
				});
				return Promise.resolve(true);
			case undefined:
				// this.weixinPolling(p, uuid, panel, state)
				return Promise.resolve(false);
			default:
				Output('请在微信上扫码， 点击确认！', 'info');
					return Promise.resolve(false);
				// this.weixinPolling(p, uuid, panel, state)
		}		
	}
}
