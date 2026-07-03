
import { SelfProfileAPI } from "../const/URL";
import { IProfile } from "../model/target/target";
import { sendRequest } from "./http.service";


export class AccountService {
	public profile: IProfile;

	constructor () {}

	/**
	 * Fetch the logged-in user via /api/v4/me. Returns the parsed response body
	 * (with a truthy `id`/`name` when authenticated) or null on failure.
	 */
	private async fetchMe(): Promise<any> {
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
		} catch (err) {
			console.error('fetchMe failed', err);
			return null;
		}
	}

	async fetchProfile() {
		this.profile = await this.fetchMe();
	}

	async isAuthenticated(): Promise<boolean> {
		const me = await this.fetchMe();
		if (me) {
			this.profile = me;
			return true;
		}
		return false;
	}

}