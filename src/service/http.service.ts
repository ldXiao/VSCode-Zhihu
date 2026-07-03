import * as httpClient from "request-promise";
import * as toughCookie from "tough-cookie";
const { Cookie, CookieJar } = toughCookie;
import { DefaultHTTPHeader, ZhihuApiHeader } from "../const/HTTP";
import { ZhihuDomain } from "../const/URL";
import {
    getCookieJar,
    getCookieStore,
    clearCookieStore,
    saveCookieJar,
} from "../global/cookie";
import { getEnv } from "../core/env";
import { IProfile } from "../model/target/target";

interface CacheItem {
    url: string;
    data: any;
}

export class HttpService {
    public profile: IProfile;
    public xsrfToken: string;
    public cache = {};

    constructor() {}

    public async sendRequest(options): Promise<any> {
        const isZhihuApi = typeof options.uri === "string" &&
            /(^https?:\/\/(www\.|api\.)?zhihu\.com)|zhuanlan\.zhihu\.com/.test(options.uri);

        // Merge caller headers on top of a browser-like default set. For zhihu
        // API calls we include the headers the web app sends (referer,
        // x-requested-with, x-zse-93) so requests are accepted with plain
        // cookies and no reverse-engineered signature.
        const baseHeaders = isZhihuApi
            ? { ...DefaultHTTPHeader, ...ZhihuApiHeader }
            : { ...DefaultHTTPHeader };
        options.headers = { ...baseHeaders, ...(options.headers || {}) };

        let cookieStr = "";
        try {
            cookieStr = getCookieJar().getCookieStringSync(options.uri);
            options.headers["cookie"] = cookieStr;
        } catch (error) {
            console.log(error);
        }

        // Write endpoints (POST/PUT/PATCH/DELETE) require the XSRF token. Prefer
        // one captured from a response, else read `_xsrf` straight from the jar
        // (the persisted session has it, so the very first write still works).
        const xsrfMatch = /(?:^|;\s*)_xsrf=([^;]+)/.exec(cookieStr);
        const xsrf = this.xsrfToken || (xsrfMatch ? decodeURIComponent(xsrfMatch[1]) : "");
        if (xsrf) {
            options.headers["x-xsrftoken"] = xsrf;
        }

        // `x-zse-93` (an unsigned client-version tag) is fine for GET reads but
        // makes write endpoints reject with "请升级客户端" — drop it for writes.
        const method = String(options.method || "get").toLowerCase();
        if (method !== "get" && options.headers["x-zse-93"]) {
            delete options.headers["x-zse-93"];
        }
        // Let request/request-promise transparently decode gzip/deflate so JSON
        // bodies are not returned as garbled compressed bytes.
        options.gzip = true;
        var returnBody;
        if (
            options.resolveWithFullResponse == undefined ||
            options.resolveWithFullResponse == false
        ) {
            returnBody = true;
        } else {
            returnBody = false;
        }
        options.resolveWithFullResponse = true;

        options.simple = false;

        var resp;
        if (!this.cache) this.cache = {};
        try {
            if (this.cache[options.uri]) {
                // cache hit
                resp = this.cache[options.uri];
            } else {
                // cache miss
                resp = await httpClient(options);
                if (resp.headers["set-cookie"]) {
                    resp.headers["set-cookie"]
                        .map((c) => Cookie.parse(c))
                        .forEach((c) => {
                            // delete c.domain
                            getCookieJar().setCookieSync(c, options.uri);
                            getCookieStore().findCookie(
                                ZhihuDomain,
                                "/",
                                "_xsrf",
                                (err, c) => {
                                    if (c) {
                                        this.xsrfToken = c.value;
                                    }
                                }
                            );
                        });
                    saveCookieJar();
                }
                if (options.enableCache) {
                    this.cache[options.uri] = resp;
                }
            }
        } catch (error) {
            // vscode.window.showInformationMessage('请求错误');
            getEnv().log(String(error));
            return Promise.resolve(null);
        }
        if (returnBody) {
            return Promise.resolve(resp.body);
        } else {
            return Promise.resolve(resp);
        }
    }

    public clearCookie(domain?: string) {
        if (domain == undefined) {
            getCookieStore().removeCookies(ZhihuDomain, null, (err) =>
                console.log(err)
            );
            clearCookieStore();
        }
        this.xsrfToken = undefined;
    }

    public clearCache() {
        this.cache = {};
    }
}

var httpService = new HttpService();

export const sendRequest = httpService.sendRequest.bind(httpService);
export const clearCookie = httpService.clearCookie.bind(httpService);
export const clearCache = httpService.clearCache.bind(httpService);
