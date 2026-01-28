(() => {
	const btn = document.getElementById('passkey_login');
	const errEl = document.getElementById('passkey_error');
	const usernameInput = document.getElementById('username');
	const adminPath = document.body && document.body.dataset ? document.body.dataset.adminPath : '';

	function showError(msg) {
		if (!errEl) return;
		errEl.textContent = msg || '';
		errEl.classList.toggle('d-none', !msg);
	}

	function supportsPasskeys() {
		return window.PublicKeyCredential && typeof PublicKeyCredential === 'function';
	}

	function base64urlToBuffer(baseurl) {
		const padding = '='.repeat((4 - baseurl.length % 4) % 4);
		const base64 = (baseurl + padding).replace(/-/g, '+').replace(/_/g, '/');
		const raw = atob(base64);
		const arr = new Uint8Array(raw.length);
		for (let i = 0; i < raw.length; ++i) arr[i] = raw.charCodeAt(i);
		return arr.buffer;
	}

	function bufferToBase64url(buf) {
		const bytes = new Uint8Array(buf);
		let str = '';
		for (let i = 0; i < bytes.byteLength; i++) str += String.fromCharCode(bytes[i]);
		return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
	}

	function credentialToJSON(cred) {
		if (!cred) return null;
		const out = {
			id: cred.id,
			rawId: bufferToBase64url(cred.rawId),
			type: cred.type,
			authenticatorAttachment: cred.authenticatorAttachment,
			response: {}
		};
		if (cred.response) {
			out.response.clientDataJSON = bufferToBase64url(cred.response.clientDataJSON);
			if (cred.response.authenticatorData) {
				out.response.authenticatorData = bufferToBase64url(cred.response.authenticatorData);
			}
			if (cred.response.signature) {
				out.response.signature = bufferToBase64url(cred.response.signature);
			}
			if (cred.response.userHandle) {
				out.response.userHandle = bufferToBase64url(cred.response.userHandle);
			}
		}
		if (cred.getClientExtensionResults) {
			out.clientExtensionResults = cred.getClientExtensionResults();
		}
		return out;
	}

	if (!btn) return;

	btn.addEventListener('click', async () => {
		showError('');
		if (!supportsPasskeys()) {
			showError('Passkeys are not supported in this browser.');
			return;
		}
		if (!adminPath) {
			showError('Admin path missing.');
			return;
		}

		const username = usernameInput ? usernameInput.value.trim() : '';
		try {
			const start = await fetch(adminPath + '/passkeys/login/start', {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ username })
			});
			if (!start.ok) {
				showError('Passkey login not available.');
				return;
			}
			const startData = await start.json();
			const opts = startData && startData.options ? startData.options.publicKey : null;
			if (!opts) {
				showError('Invalid passkey options.');
				return;
			}
			opts.challenge = base64urlToBuffer(opts.challenge);
			if (opts.allowCredentials) {
				opts.allowCredentials.forEach(c => { c.id = base64urlToBuffer(c.id); });
			}
			const assertion = await navigator.credentials.get({ publicKey: opts });
			if (!assertion) {
				showError('No assertion returned.');
				return;
			}
			const finish = await fetch(adminPath + '/passkeys/login/finish', {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json', 'X-WA-Session': startData.session_id || '' },
				body: JSON.stringify(credentialToJSON(assertion))
			});
			if (!finish.ok) {
				showError('Passkey login failed.');
				return;
			}
			const finishData = await finish.json();
			const redirect = finishData && finishData.redirect ? finishData.redirect : (adminPath + '/');
			window.location.assign(redirect);
		} catch (_) {
			showError('Passkey login cancelled or failed.');
		}
	});
})();