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

	/**
	 * Generate or retrieve device fingerprint for x-du-bid header
	 */
	private generateDeviceId(): string {
		// Check if we have a stored device ID
		const storedId = vscode.workspace.getConfiguration().get('zhihu.deviceId') as string;
		if (storedId) {
			return storedId;
		}
		
		// Generate new device ID (placeholder format based on browser example)
		const deviceId = 'D2ivMfdbW7AYf9t67Cdh8SfhoPL+8n5vSV1M871gTLHy0X06';
		
		// Store it for future use
		vscode.workspace.getConfiguration().update('zhihu.deviceId', deviceId, vscode.ConfigurationTarget.Global);
		
		return deviceId;
	}

	/**
	 * Get stored device ID
	 */
	private getStoredDeviceId(): string {
		return vscode.workspace.getConfiguration().get('zhihu.deviceId') as string || this.generateDeviceId();
	}

	/**
	 * Calculate x-zse-96 header (anti-bot protection for API requests)
	 * TODO: Replace with actual calculation algorithm when reverse-engineered
	 */
	private calculateZse96(requestData?: any): string {
		// This is where your reverse-engineered calculation goes
		// The value changes based on request data, timestamp, etc.
		// For now, using a placeholder value from browser example
		return '2.0_//FSnjFiqIKbqZWVsFFIZtzGf3UoY0BNF7Zse=KuraJ2HGM1xFh7ZnxvMwCJcbcK';
	}

	/**
	 * Calculate x-zse-96 header specifically for polling requests
	 * TODO: Replace with actual calculation algorithm when reverse-engineered
	 */
	private calculateZse96ForPolling(token: string): string {
		// Different calculation for polling requests
		// For now, using examples from browser logs
		return '2.0_aY9bPq34pxP/4t36LhVeJXykhu7QFzgv5ZwWGnqb7r6xnz9q3+qYQBOs4AnCvHBo';
	}

	/**
	 * Calculate x-zst-81 header (complex anti-bot protection for polling)
	 * TODO: Replace with actual calculation algorithm when reverse-engineered
	 */
	private calculateZst81(token: string, pollCount?: number): string {
		// This is the most complex one, changes with each polling request
		// It's based on token, timestamp, request count, etc.
		// For now, using a placeholder value from browser example
		return '3_2.0aR_sn77yn6O92wOB8hPZn490EXtucRFqwHNMUrL8YunxE8Y0w6SmDggMgBgPD4S1hCS974e1DrNPAQLYlUefii_qr6kxELt0M4PGDwN8gGcYAupMWufIoLVqr4gxrRPOI0cY7HL8qun9g93mFukyigcmebS_FwOYPRP0E4rZUrN9DDom3hnynAUMnAVPF_PhaueTFQNBnBCYXGxBWGNYAro_QwHYeDe8sLeYxve9EwoL99VLM9N8XgwLDqSKnu2TV0omthxyyDxp09H8Uwe8PJ98NDcxcCg90g2LBDUYcck8h9oM88XyxJ3KFBxxoMVMHbeBQ0V1EuYsIwxB19xywggGWvNMUqXBPvwLXvU0j9F9eLL_dJxmCg_zBuFxWhoq2GXfbgOy9C2MhGg11ix1XCV_PGc16X29phN1zrVCJ9LmCUVMwucVzgpLtwwssqY8MM2fwgcBICeYS0xO6wYycrH1ciXxIcxGicSVWgxC6QSs';
	}

	/**
	 * Get anti-bot headers for QR code token request
	 */
	private getAntiBotHeaders(baseHeaders: {[key: string]: string}): {[key: string]: string} {
		return {
			...baseHeaders,
			'x-zse-93': '101_3_3.0', // Static value
			'x-zse-96': this.calculateZse96(),
			'x-du-bid': this.getStoredDeviceId()
		};
	}

	/**
	 * Get anti-bot headers for polling requests
	 */
	private getPollingAntiBotHeaders(baseHeaders: {[key: string]: string}, token: string, pollCount: number): {[key: string]: string} {
		return {
			...baseHeaders,
			'x-zse-93': '101_3_3.0', // Static value
			'x-zse-96': this.calculateZse96ForPolling(token),
			'x-zst-81': this.calculateZst81(token, pollCount),
			'x-du-bid': this.getStoredDeviceId()
		};
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

	public async forceLogin() {
		try {
			Output('强制重新登录...', 'info');
			
			// Clear all cookies and authentication state
			Output('清除所有认证状态...', 'info');
			try {
				clearCookie();
				Output('cookie清除成功', 'info');
			} catch (cookieError) {
				Output(`清除cookie失败: ${cookieError}`, 'error');
			}
			
			// Skip authentication check and go straight to login options
			Output('显示登录方式选择...', 'info');
			try {
				const mappedTypes = LoginTypes.map(type => ({ 
					value: type.value, 
					label: type.ch, 
					description: '' 
				}));
				
				const selectedItem = await vscode.window.showQuickPick<vscode.QuickPickItem & { value: LoginEnum }>(
					mappedTypes,
					{ placeHolder: "选择登录方式: " }
				);

				if (!selectedItem) {
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
			Output(`强制登录过程出错: ${error}`, 'error');
			Output(`错误堆栈: ${error.stack}`, 'error');
			vscode.window.showErrorMessage(`登录失败: ${error.message || error}`);
		}
	}

	public async login() {
		try {
			Output('开始登录流程...', 'info');
			
			try {
				const isAuth = await this.accountService.isAuthenticated();
				Output(`认证检查结果: ${isAuth}`, 'info');
				
				if (isAuth) {
					// Fetch profile first to get the name
					try {
						await this.profileService.fetchProfile();
						if (this.profileService.name && this.profileService.name.trim() !== '') {
							vscode.window.showInformationMessage(`你已经登录了哦~ ${this.profileService.name}`);
							return;
						} else {
							// Profile fetch failed or returned empty name - authentication might be invalid
							Output('认证检查通过但无法获取用户信息，可能需要重新登录', 'warn');
							vscode.window.showWarningMessage('检测到登录状态异常，将重新登录');
							// Continue with login flow
						}
					} catch (profileError) {
						Output(`获取用户信息失败: ${profileError}`, 'error');
						// Profile fetch failed - authentication is likely invalid
						Output('无法获取用户信息，继续登录流程', 'warn');
						vscode.window.showWarningMessage('登录状态验证失败，将重新登录');
						// Continue with login flow
					}
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
		// First test the API to see what's happening
		const testResult = await this.testQrcodeAPI();
		if (!testResult) {
			vscode.window.showErrorMessage('QR码API测试失败，请检查网络连接');
			return;
		}
		
		// Use the improved QR code method with better error handling
		await this.improvedQrcodeLogin();
	}

	/**
	 * Test method to check the QR code API response and debug issues
	 */
	public async testQrcodeAPI() {
		try {
			Output('开始测试QR码API...', 'info');
			
			// Test 1: Check basic connectivity
			try {
				Output('测试基础连接...', 'info');
				const basicTest = await sendRequest({
					uri: 'https://www.zhihu.com',
					method: 'get',
					timeout: 10000,
					resolveWithFullResponse: true,
					simple: false
				});
				Output(`知乎主页连接测试: ${basicTest.statusCode}`, 'info');
			} catch (connError) {
				Output(`基础连接测试失败: ${connError.message}`, 'error');
				return false;
			}

			// Test 2: Try UDID request
			try {
				Output('测试UDID请求...', 'info');
				const udidResp = await sendRequest({
					uri: UDIDAPI,
					method: 'post',
					resolveWithFullResponse: true,
					simple: false,
					timeout: 10000,
					headers: {
						'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
						'Referer': 'https://www.zhihu.com/signin?next=%2F'
					}
				});
				Output(`UDID响应: 状态码=${udidResp.statusCode}`, 'info');
			} catch (udidError) {
				Output(`UDID测试失败: ${udidError.message}`, 'warn');
				// Continue anyway
			}

			// Test 3: Try QR code API
			Output('测试QR码API...', 'info');
			const resp = await sendRequest({
				uri: QRCodeAPI,
				method: 'post',
				json: true,
				resolveWithFullResponse: true,
				simple: false,
				timeout: 15000,
				headers: {
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
					'Referer': 'https://www.zhihu.com/signin?next=%2F',
					'Accept': 'application/json, text/plain, */*',
					'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest'
				}
			});

			Output(`QR码API测试结果:`, 'info');
			Output(`- 状态码: ${resp.statusCode}`, 'info');
			Output(`- 响应头: ${JSON.stringify(resp.headers, null, 2)}`, 'info');
			Output(`- 响应体: ${JSON.stringify(resp.body, null, 2)}`, 'info');

			if (resp.statusCode === 200 && resp.body && resp.body.token) {
				Output(`✓ QR码API测试成功，token: ${resp.body.token}`, 'info');
				
				// Test 4: Try to get QR code image
				try {
					Output('测试QR码图片下载...', 'info');
					
					// Try multiple image request methods
					const imageUrls = [
						`${QRCodeAPI}/${resp.body.token}/scan_info`,
						`https://www.zhihu.com/api/v3/account/api/login/qrcode/${resp.body.token}/scan_info`,
						resp.body.link // Try the link from the response
					];
					
					let imageSuccess = false;
					let lastError = null;
					
					for (const imageUrl of imageUrls) {
						try {
							Output(`尝试图片URL: ${imageUrl}`, 'info');
							
							const imgResp = await sendRequest({
								uri: imageUrl,
								encoding: null,
								resolveWithFullResponse: true,
								simple: false,
								timeout: 10000,
								headers: {
									'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
									'Referer': 'https://www.zhihu.com/signin?next=%2F',
									'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
									'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
									'Accept-Encoding': 'gzip, deflate, br',
									'Connection': 'keep-alive',
									'Sec-Fetch-Dest': 'image',
									'Sec-Fetch-Mode': 'no-cors',
									'Sec-Fetch-Site': 'same-origin'
								}
							});
							
							Output(`图片请求状态: ${imgResp.statusCode}`, 'info');
							
							if (imgResp.statusCode === 200 && imgResp.body && imgResp.body.length > 0) {
								Output(`✓ QR码图片获取成功，大小: ${imgResp.body.length} bytes`, 'info');
								imageSuccess = true;
								break;
							} else {
								Output(`图片请求失败: ${imgResp.statusCode}, 响应头: ${JSON.stringify(imgResp.headers)}`, 'info');
								lastError = `HTTP ${imgResp.statusCode}`;
							}
						} catch (imgError) {
							Output(`图片请求异常: ${imgError.message}`, 'info');
							lastError = imgError.message;
							continue;
						}
					}
					
					if (imageSuccess) {
						return true;
					} else {
						Output(`✗ 所有图片URL都失败了，最后错误: ${lastError}`, 'error');
						
						// Try alternative approach - use the link directly in browser
						if (resp.body.link) {
							Output(`尝试使用浏览器链接: ${resp.body.link}`, 'info');
							Output(`✓ 可以尝试使用浏览器打开: ${resp.body.link}`, 'info');
							return 'browser_link';
						}
						return false;
					}
				} catch (imgError) {
					Output(`✗ QR码图片请求失败: ${imgError.message}`, 'error');
					return false;
				}
			} else {
				Output(`✗ QR码API测试失败`, 'error');
				if (resp.statusCode !== 200) {
					vscode.window.showErrorMessage(`QR码API返回错误状态: ${resp.statusCode}`);
				} else {
					vscode.window.showErrorMessage('QR码API响应格式异常');
				}
				return false;
			}

		} catch (error) {
			Output(`QR码API测试出现异常: ${error.message || error}`, 'error');
			Output(`错误详情: ${error.stack}`, 'error');
			vscode.window.showErrorMessage(`API测试失败: ${error.message || error}`);
			return false;
		}
	}

	/**
	 * Get CSRF token and other required headers from the login page
	 */
	private async getZhihuHeaders(): Promise<{[key: string]: string}> {
		try {
			Output('获取知乎登录页面headers...', 'info');
			
			// First, visit the signin page to get cookies and tokens
			const signinResp = await sendRequest({
				uri: 'https://www.zhihu.com/signin?next=%2F',
				method: 'get',
				resolveWithFullResponse: true,
				simple: false,
				headers: {
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
					'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
					'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6',
					'Accept-Encoding': 'gzip, deflate, br',
					'Connection': 'keep-alive',
					'Upgrade-Insecure-Requests': '1',
					'Sec-Fetch-Dest': 'document',
					'Sec-Fetch-Mode': 'navigate',
					'Sec-Fetch-Site': 'none'
				}
			});
			
			// Extract XSRF token from cookies or HTML
			let xsrfToken = '';
			if (signinResp.headers && signinResp.headers['set-cookie']) {
				const cookies = Array.isArray(signinResp.headers['set-cookie']) 
					? signinResp.headers['set-cookie'] 
					: [signinResp.headers['set-cookie']];
				
				for (const cookie of cookies) {
					const xsrfMatch = cookie.match(/XSRF-TOKEN=([^;]+)/);
					if (xsrfMatch) {
						xsrfToken = decodeURIComponent(xsrfMatch[1]);
						break;
					}
				}
			}
			
			// If not found in cookies, try to extract from HTML
			if (!xsrfToken && signinResp.body) {
				const htmlContent = signinResp.body.toString();
				const xsrfMatch = htmlContent.match(/name="csrf[_-]?token"\s+content="([^"]+)"/i) ||
								  htmlContent.match(/"xsrfToken"\s*:\s*"([^"]+)"/i) ||
								  htmlContent.match(/window\.XSRF_TOKEN\s*=\s*["']([^"']+)["']/i);
				if (xsrfMatch) {
					xsrfToken = xsrfMatch[1];
				}
			}
			
			Output(`XSRF Token: ${xsrfToken ? 'Found' : 'Not found'}`, 'info');
			
			// Generate basic headers (the zse headers are complex anti-bot measures)
			const headers: {[key: string]: string} = {
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
				'Accept': '*/*',
				'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6',
				'Referer': 'https://www.zhihu.com/signin?next=%2F',
				'Sec-Fetch-Dest': 'empty',
				'Sec-Fetch-Mode': 'cors',
				'Sec-Fetch-Site': 'same-origin',
				'X-Requested-With': 'fetch',
				'Priority': 'u=1, i'
			};
			
			if (xsrfToken) {
				headers['X-Xsrftoken'] = xsrfToken;
			}
			
			// Note: x-zse-93, x-zse-96, x-zst-81, x-du-bid are complex anti-bot headers
			// that require JavaScript execution to generate properly
			// For now, we'll try without them and implement fallback methods
			
			return headers;
			
		} catch (error) {
			Output(`获取headers失败: ${error.message}`, 'error');
			// Return basic headers as fallback
			return {
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
				'Accept': '*/*',
				'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6',
				'Referer': 'https://www.zhihu.com/signin?next=%2F'
			};
		}
	}

	/**
	 * Improved QR code login with proper headers
	 */
	private async improvedQrcodeLogin() {
		try {
			Output('初始化QR码登录...', 'info');
			
			// Step 1: Get proper headers including XSRF token
			const headers = await this.getZhihuHeaders();
			Output('获取到登录headers', 'info');
			
			// Step 2: Initialize session with UDID (optional but helps)
			try {
				Output('发送UDID请求...', 'info');
				const udidResp = await sendRequest({
					uri: UDIDAPI,
					method: 'post',
					resolveWithFullResponse: true,
					simple: false,
					headers
				});
				Output(`UDID响应状态: ${udidResp.statusCode}`, 'info');
			} catch (udidError) {
				Output(`UDID请求失败: ${udidError.message}`, 'warn');
				// Continue anyway
			}
			
			// Step 3: Get QR code token with anti-bot headers
			let resp;
			try {
				Output('获取QR码令牌...', 'info');
				
				// Get headers with anti-bot protection
				const antiBotHeaders = this.getAntiBotHeaders({
					...headers,
					'Content-Type': 'application/json'
				});
				
				Output(`使用anti-bot headers: ${JSON.stringify(antiBotHeaders, null, 2)}`, 'info');
				
				resp = await sendRequest({
					uri: QRCodeAPI,
					method: 'post',
					json: true,
					gzip: true,
					resolveWithFullResponse: true,
					simple: false,
					headers: antiBotHeaders
				});
				
				Output(`QR码API状态码: ${resp.statusCode}`, 'info');
				Output(`QR码API响应体: ${JSON.stringify(resp.body)}`, 'info');
				
				if (resp.statusCode !== 200) {
					// If we get 403, it means our anti-bot headers might be wrong
					if (resp.statusCode === 403) {
						Output('检测到反爬虫保护，anti-bot headers可能需要重新计算，尝试备用方案...', 'warn');
						return await this.fallbackQrcodeLogin();
					}
					throw new Error(`QR code API failed with status ${resp.statusCode}: ${JSON.stringify(resp.body)}`);
				}
				
			} catch (qrError) {
				Output(`QR码API请求失败: ${qrError.message}`, 'error');
				
				// Try fallback method
				Output('尝试备用QR码方案...', 'warn');
				return await this.fallbackQrcodeLogin();
			}
			
			// Continue with the rest of the QR code flow...
			const qrData = resp.body || resp;
			if (!qrData || !qrData.token) {
				throw new Error(`获取QR码失败 - 无效响应: ${JSON.stringify(qrData)}`);
			}
			
			const token = qrData.token;
			Output(`获取到QR码token: ${token}`, 'info');
			
			// For image download, use the link from response if available
			if (qrData.link) {
				Output(`使用浏览器QR码链接: ${qrData.link}`, 'info');
				const choice = await vscode.window.showInformationMessage(
					'QR码已准备就绪，请选择登录方式：', 
					'在浏览器中打开', 
					'取消'
				);
				
				if (choice === '在浏览器中打开') {
					vscode.env.openExternal(vscode.Uri.parse(qrData.link));
					// Start polling with the proper headers
					await this.pollQrcodeStatusWithHeaders(token, headers, null);
				}
			} else {
				// Try to download image as before
				// ... (keep existing image download logic)
			}
			
		} catch (error) {
			Output(`QR码登录失败: ${error.message}`, 'error');
			vscode.window.showErrorMessage(`登录失败: ${error.message}`);
		}
	}

	/**
	 * Fallback QR code login when anti-bot protection is detected
	 */
	private async fallbackQrcodeLogin() {
		Output('启动备用QR码登录方案...', 'info');
		
		try {
			// Method 1: Try to use the web interface directly
			const qrcodePageUrl = 'https://www.zhihu.com/signin?next=%2F';
			
			const choice = await vscode.window.showInformationMessage(
				'检测到知乎防护机制，需要使用浏览器登录。\n登录后VS Code将自动检测登录状态。', 
				'打开浏览器登录', 
				'取消'
			);
			
			if (choice === '打开浏览器登录') {
				// Open the login page in browser
				vscode.env.openExternal(vscode.Uri.parse(qrcodePageUrl));
				
				// Start checking authentication status periodically
				vscode.window.showInformationMessage('请在浏览器中完成登录，VS Code将自动检测...');
				
				let pollCount = 0;
				const maxPolls = 60; // 5 minutes
				
				const authCheckInterval = setInterval(async () => {
					try {
						pollCount++;
						
						if (pollCount > maxPolls) {
							clearInterval(authCheckInterval);
							vscode.window.showWarningMessage('登录检测超时，请手动刷新');
							return;
						}
						
						if (pollCount % 6 === 0) { // Every 30 seconds
							Output(`检测登录状态... (${Math.floor(pollCount/6)}/5分钟)`, 'info');
						}
						
						// Check if user is now authenticated
						const isAuth = await this.accountService.isAuthenticated();
						if (isAuth) {
							clearInterval(authCheckInterval);
							
							try {
								await this.profileService.fetchProfile();
								const username = this.profileService.name || '用户';
								vscode.window.showInformationMessage(`登录成功！欢迎 ${username}`);
								Output(`浏览器登录成功，欢迎 ${username}`, 'info');
								this.feedTreeViewProvider.refresh();
							} catch (profileError) {
								vscode.window.showInformationMessage('登录成功！');
								this.feedTreeViewProvider.refresh();
							}
						}
						
					} catch (checkError) {
						// Continue checking even if there are errors
						Output(`认证检查失败: ${checkError.message}`, 'warn');
					}
				}, 5000); // Check every 5 seconds
				
				// Provide a way to cancel
				vscode.window.showInformationMessage('正在检测登录状态...', '停止检测').then(selection => {
					if (selection === '停止检测') {
						clearInterval(authCheckInterval);
						Output('用户停止了登录检测', 'info');
					}
				});
			}
			
		} catch (error) {
			Output(`备用登录方案失败: ${error.message}`, 'error');
			vscode.window.showErrorMessage('登录失败，请稍后重试');
		}
	}

	/**
	 * Poll QR code status with proper headers
	 */
	private async pollQrcodeStatusWithHeaders(token: string, headers: {[key: string]: string}, panel: vscode.WebviewPanel | null) {
		let pollCount = 0;
		const maxPolls = 150;
		
		Output('开始轮询登录状态（使用正确headers）...', 'info');
		
		const intervalId = setInterval(async () => {
			try {
				pollCount++;
				
				if (pollCount > maxPolls) {
					clearInterval(intervalId);
					if (panel) panel.dispose();
					vscode.window.showWarningMessage('QR码已超时，请重新登录');
					return;
				}
				
				// Use proper anti-bot headers for polling
				const pollHeaders = this.getPollingAntiBotHeaders(headers, token, pollCount);
				// Remove content-type for GET requests
				delete pollHeaders['Content-Type'];
				
				Output(`轮询 ${pollCount} 使用headers: ${JSON.stringify(pollHeaders, null, 2)}`, 'info');
				
				const statusResp = await sendRequest({
					uri: `${QRCodeAPI}/${token}/scan_info`,
					method: 'get',
					json: true,
					gzip: true,
					simple: false,
					resolveWithFullResponse: true,
					headers: pollHeaders
				});
				
				if (statusResp.statusCode === 200) {
					const statusData = statusResp.body;
					Output(`轮询状态 ${pollCount}: ${JSON.stringify(statusData)}`, 'info');
					
					// Handle the response as before
					if (statusData) {
						const status = statusData.status || statusData.state;
						
						if (status === 0 || status === 'waiting') {
							// Still waiting
						} else if (status === 1 || status === 'scanned') {
							vscode.window.showInformationMessage('请在手机上确认登录！');
						} else if (status === 2 || status === 'confirmed' || statusData.user_id) {
							clearInterval(intervalId);
							if (panel) panel.dispose();
							
							try {
								await this.profileService.fetchProfile();
								const username = this.profileService.name || '用户';
								vscode.window.showInformationMessage(`登录成功！欢迎 ${username}`);
								this.feedTreeViewProvider.refresh();
							} catch (profileError) {
								vscode.window.showInformationMessage('登录成功！');
								this.feedTreeViewProvider.refresh();
							}
						}
					}
				} else if (statusResp.statusCode === 403) {
					// Anti-bot protection triggered, fall back to authentication checking
					Output('轮询遇到403，切换到认证检查模式...', 'warn');
					
					const isAuth = await this.accountService.isAuthenticated();
					if (isAuth) {
						clearInterval(intervalId);
						if (panel) panel.dispose();
						
						try {
							await this.profileService.fetchProfile();
							const username = this.profileService.name || '用户';
							vscode.window.showInformationMessage(`登录成功！欢迎 ${username}`);
							this.feedTreeViewProvider.refresh();
						} catch (profileError) {
							vscode.window.showInformationMessage('登录成功！');
							this.feedTreeViewProvider.refresh();
						}
					}
				}
				
			} catch (error) {
				Output(`轮询失败: ${error.message}`, 'warn');
				// Continue polling
			}
		}, 2000);
		
		if (panel) {
			panel.onDidDispose(() => {
				clearInterval(intervalId);
			});
		}
	}

	/**
	 * Debug method to test anti-bot header generation
	 */
	public async debugAntiBotHeaders(): Promise<string> {
		try {
			Output('开始调试anti-bot headers...', 'info');
			
			// Generate a test device ID
			const deviceId = this.generateDeviceId();
			Output(`生成的设备ID: ${deviceId}`, 'info');
			
			// Test headers for QR code request
			const baseHeaders = {
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
				'Referer': 'https://www.zhihu.com/signin?next=%2F',
				'Accept': 'application/json, text/plain, */*',
				'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
				'Content-Type': 'application/json'
			};
			
			const qrcodeHeaders = this.getAntiBotHeaders(baseHeaders);
			Output(`QR码请求headers: ${JSON.stringify(qrcodeHeaders, null, 2)}`, 'info');
			
			// Test headers for polling
			const testToken = 'test-token-12345';
			const pollingHeaders = this.getPollingAntiBotHeaders(baseHeaders, testToken, 1);
			Output(`轮询请求headers: ${JSON.stringify(pollingHeaders, null, 2)}`, 'info');
			
			Output('anti-bot headers调试完成', 'info');
			return 'Headers generated successfully';
		} catch (error) {
			Output(`Headers调试失败: ${error.message}`, 'error');
			throw error;
		}
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
