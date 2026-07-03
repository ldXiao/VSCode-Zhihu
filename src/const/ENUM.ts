export enum MediaTypes {
	answer = 'answer',
	question = 'question',
	article = 'article'
}

export enum SearchTypes {
	general = 'general',
	question = 'question',
	answer = 'answer',
	article = 'article'
}

export enum Weekdays {
	Mon = 'Mon',
	Tue = 'Tue',
	Wed = 'Wed',
	Tur = 'Tur',
	Fri = 'Fri',
	Sat = 'Sat',
	Sun = 'Sun'
}

export const WeekdaysDict = {
	Mon: 1,
	Tue: 2,
	Wed: 3,
	Tur: 4,
	Fri: 5,
	Sat: 6,
	Sun: 7
}

export const LegalImageExt = [ '.jpg', '.jpeg', '.gif', '.png' ]; 

export enum LoginEnum {
	sms,
	password,
	qrcode,
	weixin,
	cookie,
	browser
}

export const LoginTypes = [
	{ value: LoginEnum.browser, ch: '从浏览器导入登录 (推荐)' },
	{ value: LoginEnum.cookie, ch: '手动粘贴 Cookie 登录' },
	// The flows below rely on zhihu login APIs that are gated behind anti-bot
	// signatures and no longer work from a non-browser client.
	// { value: LoginEnum.qrcode, ch: '二维码'},
	// { value: LoginEnum.sms, ch: '短信验证码' },
	// { value: LoginEnum.weixin, ch: '微信'},
	// { value: LoginEnum.password, ch: '密码' },
];

export const JianshuLoginTypes = [
	{ value: LoginEnum.weixin, ch: '微信'  }
]

export enum SettingEnum {
	useVSTheme = 'useVSTheme',
	isTitleImageFullScreen = 'isTitleImageFullScreen'
}

export enum WebviewEvents {
	collect = 'collect',
	share = 'share',
	open = 'open',
	upvoteAnswer = 'upvoteAnswer',
	upvoteArticle = 'upvoteArticle'
}