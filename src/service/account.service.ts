
import { SelfProfileAPI, SignUpRedirectPage } from "../const/URL";
import { IProfile } from "../model/target/target";
import { sendRequest } from "./http.service";


export class AccountService {
	public profile: IProfile;

	constructor () {}

	async fetchProfile() {
		this.profile  = await sendRequest({
			uri: SelfProfileAPI,
			json: true
		});
	}

	async isAuthenticated(): Promise<boolean> {

		let checkIfSignedIn;
		try {
			checkIfSignedIn = await sendRequest({
				uri: SignUpRedirectPage,
				followRedirect: false,
				followAllRedirects: false,
				resolveWithFullResponse: true,
				gzip: true,
				simple: false
			});
		} catch (err) {
			console.error('Http error', err);
			return false;
		}
		
		// Check if we got a 302 redirect
		const is302Redirect = checkIfSignedIn ? checkIfSignedIn.statusCode == 302 : false;
		
		if (is302Redirect) {
			// Double-check by trying to fetch profile
			try {
				const profileCheck = await sendRequest({
					uri: SelfProfileAPI,
					json: true,
					simple: false,
					resolveWithFullResponse: true
				});
				
				// If we can successfully get profile data, we're truly authenticated
				if (profileCheck.statusCode === 200 && profileCheck.body && profileCheck.body.name) {
					return true;
				} else {
					// 302 redirect but no valid profile - likely not authenticated
					console.log('302 redirect but invalid profile response:', profileCheck.statusCode);
					return false;
				}
			} catch (profileErr) {
				console.error('Profile check failed:', profileErr);
				return false;
			}
		}
		
		return false;
	}

}