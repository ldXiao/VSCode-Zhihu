import { getExtensionPath } from "./globa-var";
import * as path from "path"
import * as toughCookie from "tough-cookie";
const { CookieJar } = toughCookie;
import { writeFileSync, readFileSync, existsSync } from "fs";

// Simple fallback cookie store implementation
class SimpleCookieStore {
    private filePath: string;

    constructor(filePath: string) {
        this.filePath = filePath;
    }

    findCookie(domain: string, path: string, key: string, cb: (err: any, cookie: any) => void) {
        try {
            const cookies = this.loadCookies();
            const cookie = cookies.find((c: any) => c.key === key);
            cb(null, cookie);
        } catch (err) {
            cb(err, null);
        }
    }

    removeCookies(domain: string, path: string, cb: (err: any) => void) {
        try {
            writeFileSync(this.filePath, JSON.stringify([]));
            cb(null);
        } catch (err) {
            cb(err);
        }
    }

    private loadCookies() {
        try {
            if (existsSync(this.filePath)) {
                const data = readFileSync(this.filePath, 'utf8');
                return JSON.parse(data || '[]');
            }
            return [];
        } catch {
            return [];
        }
    }
}

var store: any;
var cookieJar: any;

export function getCookieStore() {
    loadCookie()
    return store
}

export function clearCookieStore() {
    writeFileSync(path.join(getExtensionPath(), './cookie.json'), '[]');
}

export function getCookieJar() {
    loadCookie()
    return cookieJar
}

function loadCookie() {
    if (!store) {
        try {
            // Try to use tough-cookie-file-store if available
            const FileCookieStore = require('tough-cookie-file-store').FileCookieStore;
            store = new FileCookieStore(path.join(getExtensionPath(), './cookie.json'));
        } catch (error) {
            // Fallback to simple store if tough-cookie-file-store fails
            console.log('Using fallback cookie store:', error.message);
            store = new SimpleCookieStore(path.join(getExtensionPath(), './cookie.json'));
        }
    }
    if (!cookieJar) {
        cookieJar = new CookieJar(store);
    }
}