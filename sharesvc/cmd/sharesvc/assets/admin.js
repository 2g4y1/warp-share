(() => {
		function pad2(n) { return String(n).padStart(2, '0'); }

		function copyText(text) {
			if (!text) return;
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
				return;
			}
			fallbackCopy(text);
		}

		function fallbackCopy(text) {
			const ta = document.createElement('textarea');
			ta.value = text;
			ta.setAttribute('readonly', '');
			ta.style.position = 'fixed';
			ta.style.left = '-9999px';
			document.body.appendChild(ta);
			ta.select();
			try { document.execCommand('copy'); } catch (_) {}
			document.body.removeChild(ta);
		}

		async function shareLink(url) {
			if (!url) return;
			if (navigator.share) {
				try {
					await navigator.share({ url: url });
					return;
				} catch (_) {}
			}
			copyText(url);
		}

		function getAdminPath() {
			const ap = document.body && document.body.dataset ? document.body.dataset.adminPath : '';
			return ap || '';
		}

		function openPicker() {
			const ap = getAdminPath();
			if (!ap) return;
			window.open(ap + '/browse?pick=1', 'warp_pick', 'width=1100,height=800');
		}

		function setExpiryHours(hours) {
			const el = document.querySelector('input[name="expires_at"]');
			if (!el) return;
			const h = Number(hours);
			if (!Number.isFinite(h)) return;
			const d = new Date(Date.now() + h * 3600 * 1000);
			el.value = d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + 'T' +
				pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
		}

		function clearExpiry() {
			const el = document.querySelector('input[name="expires_at"]');
			if (el) el.value = '';
		}

		function isPickMode() {
			const v = document.body && document.body.dataset ? document.body.dataset.pick : '';
			return v === '1';
		}

		window.addEventListener('message', (ev) => {
			if (!ev || !ev.data || !ev.data.relpath) return;
			const inp = document.querySelector('input[name="relpath"]');
			if (inp) { inp.value = ev.data.relpath; inp.focus(); }
		});

		document.addEventListener('click', (ev) => {
			const target = ev.target;
			if (!(target instanceof Element)) return;

			const copyEl = target.closest('[data-copy]');
			if (copyEl) {
				ev.preventDefault();
				copyText(copyEl.getAttribute('data-copy'));
				return;
			}

			const shareEl = target.closest('[data-share]');
			if (shareEl) {
				ev.preventDefault();
				void shareLink(shareEl.getAttribute('data-share'));
				return;
			}

			const actionEl = target.closest('[data-action]');
		if (actionEl) {
			const action = actionEl.getAttribute('data-action');
			if (action === 'open-picker') {
				ev.preventDefault();
				openPicker();
				return;
			}
			if (action === 'trigger-upload') {
				ev.preventDefault();
				const uploadInput = document.getElementById('upload_file');
				if (uploadInput) uploadInput.click();
				return;
			}
		}

		const expEl = target.closest('[data-expiry-hours]');
		if (expEl) {
				ev.preventDefault();
				setExpiryHours(expEl.getAttribute('data-expiry-hours'));
				return;
			}

			const expClearEl = target.closest('[data-expiry-clear]');
			if (expClearEl) {
				ev.preventDefault();
				clearExpiry();
				return;
			}

			if (isPickMode()) {
				const pickEl = target.closest('.js-pick[data-rel]');
				if (pickEl) {
					ev.preventDefault();
					const rel = pickEl.getAttribute('data-rel') || '';
					try {
						if (window.opener) window.opener.postMessage({ relpath: rel }, '*');
					} catch (_) {}
					try { window.close(); } catch (_) {}
					return;
				}
			}

				const qcEl = target.closest('[data-action="quick-copy"][data-slug]');
				if (qcEl) {
					ev.preventDefault();
					const ap = getAdminPath();
					const slug = qcEl.getAttribute('data-slug') || '';
					// CSRF-Token aus verstecktem Input-Feld holen
					const csrfInput = document.querySelector('input[name="_csrf"]');
					const csrf = csrfInput ? csrfInput.value : '';
					if (!ap || !slug) return;
					const oldText = qcEl.textContent;
					qcEl.textContent = '…';
					fetch(ap + '/quick_create', {
						method: 'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: 'slug=' + encodeURIComponent(slug) + '&_csrf=' + encodeURIComponent(csrf),
						credentials: 'same-origin',
					}).then((res) => res.json())
					  .then((data) => {
						if (data && data.url) {
							copyText(data.url);
							qcEl.textContent = 'Copied!';
						} else {
							qcEl.textContent = oldText || 'Copy link';
						}
					  })
					  .catch(() => { qcEl.textContent = oldText || 'Copy link'; })
					  .finally(() => { setTimeout(() => { qcEl.textContent = oldText || 'Copy link'; }, 1500); });
					return;
				}
		});

		document.addEventListener('submit', (ev) => {
			const target = ev.target;
			if (!(target instanceof HTMLFormElement)) return;
			const msg = target.getAttribute('data-confirm');
			if (msg) {
				if (!window.confirm(msg)) ev.preventDefault();
			}
		});

		// ========== Upload Queue System ==========
		const uploadInput = document.getElementById('upload_file');
		const uploadStatus = document.getElementById('upload_status');

		// Upload queue state
		const uploadQueue = [];
		let currentUpload = null;
		let uploadProcessing = false;

		// Format file size
		function formatSize(bytes) {
			if (bytes < 1024) return bytes + ' B';
			if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
			if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
			return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
		}

		// Check if any upload is active
		function isUploadActive() {
			return uploadProcessing || uploadQueue.length > 0;
		}

		// Warn user if they try to leave during upload
		window.addEventListener('beforeunload', (e) => {
			if (isUploadActive()) {
				e.preventDefault();
				e.returnValue = 'Uploads still in progress. Really leave?';
				return e.returnValue;
			}
		});

		// Intercept tab clicks during upload
		document.querySelectorAll('.tab').forEach((tab) => {
			tab.addEventListener('click', (e) => {
				if (isUploadActive()) {
					const count = uploadQueue.length + (currentUpload ? 1 : 0);
					if (!confirm(count === 1 ? '1 upload still in progress.' : count + ' uploads still in progress.' + '\n\nSwitching tabs will cancel all uploads. Continue?')) {
						e.preventDefault();
						return false;
					}
				}
			});
		});

		// Render the upload status UI
		function renderUploadStatus() {
			if (!uploadStatus) return;

			if (!currentUpload && uploadQueue.length === 0) {
				uploadStatus.style.display = 'none';
				return;
			}

			uploadStatus.style.display = 'block';
			uploadStatus.replaceChildren();

			const uploadBox = document.createElement('div');
			uploadBox.className = 'upload-box';

			// Current upload
			if (currentUpload) {
				const u = currentUpload;
				const uploadItem = document.createElement('div');
				uploadItem.className = 'upload-item';

				const uploadHeader = document.createElement('div');
				uploadHeader.className = 'upload-header';

				const uploadName = document.createElement('span');
				uploadName.className = 'upload-name';
				uploadName.textContent = '📤 ' + u.file.name;

				const uploadSize = document.createElement('span');
				uploadSize.className = 'upload-size';
				uploadSize.textContent = formatSize(u.file.size);

				uploadHeader.appendChild(uploadName);
				uploadHeader.appendChild(uploadSize);

				const progress = document.createElement('progress');
				progress.className = 'upload-progress';
				progress.value = u.percent || 0;
				progress.max = 100;

				const uploadDetail = document.createElement('div');
				uploadDetail.className = 'upload-detail';
				uploadDetail.textContent = u.status || 'Starting...';

			const cancelBtn = document.createElement('button');
			cancelBtn.className = 'btn2';
			cancelBtn.type = 'button';
			cancelBtn.textContent = '✕ Cancel';
			cancelBtn.style.marginTop = '8px';
			cancelBtn.onclick = () => {
				if (confirm('Cancel this upload?')) {
					cancelCurrentUpload();
				}
			};

			uploadItem.appendChild(uploadHeader);
			uploadItem.appendChild(progress);
			uploadItem.appendChild(uploadDetail);
			uploadItem.appendChild(cancelBtn);
				uploadBox.appendChild(uploadItem);
			}

			// Queued uploads
			if (uploadQueue.length > 0) {
				const queueTitle = document.createElement('div');
				queueTitle.className = 'upload-queue-title';
				queueTitle.textContent = 'Queue (' + uploadQueue.length + ')';
				uploadBox.appendChild(queueTitle);

				const queueList = document.createElement('div');
				queueList.className = 'upload-queue-list';

				uploadQueue.forEach((u, i) => {
					const queueItem = document.createElement('div');
					queueItem.className = 'upload-queue-item';

					const indexText = document.createTextNode((i + 1) + '. ');
					const fileNameText = document.createTextNode(u.file.name);

					const sizeSpan = document.createElement('span');
					sizeSpan.style.opacity = '0.6';
					sizeSpan.textContent = ' (' + formatSize(u.file.size) + ')';

					queueItem.appendChild(indexText);
					queueItem.appendChild(fileNameText);
					queueItem.appendChild(sizeSpan);
					queueList.appendChild(queueItem);
				});

				uploadBox.appendChild(queueList);
			}

			uploadStatus.appendChild(uploadBox);
		}

	// Cancel current upload
	function cancelCurrentUpload() {
		if (!currentUpload) return;

		if (currentUpload.xhr) {
			currentUpload.xhr.abort();
		}

		currentUpload.status = '✗ Cancelled by user';
		currentUpload.success = false;
		currentUpload.cancelled = true;

		// Show cancellation immediately
		renderUploadStatus();

		// Clear and move to next
		const cancelledUpload = currentUpload;
		currentUpload = null;
		uploadProcessing = false;

		if (uploadQueue.length > 0) {
			setTimeout(processQueue, 300);
		} else {
			// Show final cancelled status
			if (uploadStatus) {
				const statusSpan = document.createElement('span');
				statusSpan.style.color = '#f88';
				statusSpan.textContent = cancelledUpload.status;
				uploadStatus.replaceChildren(statusSpan);
			}
		}
	}

	// Process upload queue
	async function processQueue() {
		if (uploadProcessing || uploadQueue.length === 0) return;
		uploadProcessing = true;

		currentUpload = uploadQueue.shift();
		const u = currentUpload;

		const ap = getAdminPath();
		const csrfInput = document.querySelector('input[name="_csrf"]');
		const csrfToken = csrfInput ? csrfInput.value : '';
		const relpathInput = document.getElementById('relpath');

		const formData = new FormData();
		formData.append('file', u.file);

		// Get target directory
		if (relpathInput && relpathInput.value) {
			const parts = relpathInput.value.split('/');
			parts.pop();
			if (parts.length > 0) {
				formData.append('dir', parts.join('/'));
			}
		}

		u.status = 'Starting upload...';
		u.percent = 0;
		renderUploadStatus();

		try {
			await new Promise((resolve, reject) => {
				const xhr = new XMLHttpRequest();
				u.xhr = xhr;
				const startTime = Date.now();

				xhr.upload.addEventListener('progress', (e) => {
					if (e.lengthComputable) {
						u.percent = Math.round((e.loaded / e.total) * 100);
						const elapsed = (Date.now() - startTime) / 1000;
						const speed = e.loaded / elapsed;
						const remaining = (e.total - e.loaded) / speed;

						let text = u.percent + '% — ' + formatSize(e.loaded) + ' / ' + formatSize(e.total);
						if (elapsed > 1 && u.percent < 100) {
							text += ' — ' + formatSize(speed) + '/s';
							if (remaining > 0 && remaining < 86400) {
								const mins = Math.floor(remaining / 60);
								const secs = Math.floor(remaining % 60);
								text += ' — ~' + (mins > 0 ? mins + 'm ' : '') + secs + 's';
							}
						}
						u.status = text;
						renderUploadStatus();
					}
				});

				xhr.onload = () => {
					if (xhr.status >= 200 && xhr.status < 300) {
						try {
							const data = JSON.parse(xhr.responseText);
							if (data.success && data.relpath) {
								u.status = '✓ ' + data.relpath;
								u.success = true;
								if (relpathInput) {
									relpathInput.value = data.relpath;
								}
							} else {
								u.status = '✗ ' + (data.message || 'Failed');
								u.success = false;
							}
						} catch (e) {
							u.status = '✗ Invalid response';
							u.success = false;
						}
						resolve();
					} else {
						try {
							const data = JSON.parse(xhr.responseText);
							// Server returns {error: "type", message: "description"}
							let errorMsg = data.message || 'Unknown error';

							// Special handling for common errors
							if (data.error === 'exists') {
								errorMsg = 'File already exists';
							} else if (xhr.status === 409) {
							errorMsg = 'File already exists';
						}

						u.status = '✗ ' + errorMsg;
						resolve(); // Continue with next file even on error
					} catch (e) {
						u.status = '✗ Error ' + xhr.status;
						resolve();
					}
				}
			};

			xhr.onerror = () => {
				u.status = '✗ Network error';
				resolve(); // Continue with next file
			};

			xhr.onabort = () => {
				if (!u.cancelled) {
					u.status = '✗ Upload cancelled';
				}
				resolve(); // Continue with next file
			};

			xhr.open('POST', ap + '/upload');
			xhr.setRequestHeader('X-CSRF-Token', csrfToken);
			xhr.withCredentials = true;
			xhr.send(formData);
		});
	} catch (err) {
		u.status = '✗ ' + err.message;
		u.success = false;
	}

	// Show result briefly
	u.completed = true;
	renderUploadStatus();

	// Clear current and process next
	const lastUpload = currentUpload;
	currentUpload = null;
	uploadProcessing = false;

	if (uploadQueue.length > 0) {
		// Small delay before next upload
		setTimeout(processQueue, 300);
	} else {
		// All done - show final status
		if (uploadStatus && lastUpload) {
			const color = lastUpload.success ? '#8f8' : '#f88';
			const statusSpan = document.createElement('span');
			statusSpan.style.color = color;
			statusSpan.textContent = lastUpload.status;
			uploadStatus.replaceChildren(statusSpan);
		}
	}
}

	// Handle file selection
	if (uploadInput) {
		// Enable multiple file selection
		uploadInput.setAttribute('multiple', 'multiple');

		uploadInput.addEventListener('change', (ev) => {
			const files = ev.target.files;
			if (!files || files.length === 0) return;

			// Add all files to queue
			for (let i = 0; i < files.length; i++) {
					uploadQueue.push({
						file: files[i],
						percent: 0,
						status: 'Waiting...',
						success: null,
						completed: false,
						xhr: null
					});
				}

				// Clear input immediately so same files can be selected again
				uploadInput.value = '';

				// Start processing if not already
				renderUploadStatus();
				processQueue();
			});
		}

		try {
			if (!navigator.share) {
				const style = document.createElement('style');
				style.textContent = '[data-share] { display: none !important; }';
				document.head.appendChild(style);
			}
		} catch (_) {}

		// Initialize stars background
		const starsContainer = document.getElementById('stars');
		if (starsContainer) {
			for (let i = 0; i < 80; i++) {
				const star = document.createElement('div');
				star.className = 'star';
				star.style.left = Math.random() * 100 + '%';
				star.style.top = Math.random() * 100 + '%';
				star.style.animationDelay = Math.random() * 2 + 's';
				star.style.opacity = Math.random() * 0.5 + 0.3;
				starsContainer.appendChild(star);
			}
		}

		// History table live search
		const historySearch = document.getElementById('history-search');
		const historyTable = document.getElementById('history-table');
		if (historySearch && historyTable) {
			historySearch.addEventListener('input', () => {
				const q = historySearch.value.toLowerCase().trim();
				const rows = historyTable.querySelectorAll('tbody tr');
				rows.forEach(row => {
					const text = row.textContent.toLowerCase();
					row.style.display = q === '' || text.includes(q) ? '' : 'none';
				});
			});
		}

		// Passkeys (WebAuthn)
		const passkeyList = document.getElementById('passkey_list');
		const passkeyAdd = document.getElementById('passkey_add');
		const passkeyLabel = document.getElementById('passkey_label');
		const passkeyMsg = document.getElementById('passkey_msg');
		const csrfInput = document.querySelector('input[name="_csrf"]');

		function showPasskeyMsg(text, isError) {
			if (!passkeyMsg) return;
			passkeyMsg.textContent = text || '';
			passkeyMsg.style.color = isError ? '#ffb0b0' : '#bfefff';
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
				if (cred.response.attestationObject) {
					out.response.attestationObject = bufferToBase64url(cred.response.attestationObject);
				}
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

		async function refreshPasskeys() {
			if (!passkeyList) return;
			const ap = getAdminPath();
			if (!ap) return;
			try {
				const res = await fetch(ap + '/passkeys', { credentials: 'same-origin' });
				if (!res.ok) return;
				const data = await res.json();
				const items = (data && data.items) ? data.items : [];
				passkeyList.replaceChildren();
				if (!items.length) {
					const empty = document.createElement('div');
					empty.className = 'passkey-empty';
					empty.textContent = passkeyList.getAttribute('data-empty') || 'No passkeys';
					passkeyList.appendChild(empty);
					return;
				}
				items.forEach((item) => {
					const row = document.createElement('div');
					row.className = 'passkey-item';

					const meta = document.createElement('div');
					meta.className = 'passkey-meta';
					const name = document.createElement('div');
					name.className = 'passkey-name';
					name.textContent = item.name || 'Passkey';
					const dates = document.createElement('div');
					dates.className = 'passkey-date';
					dates.textContent = 'Created: ' + (item.created_at || '-') + (item.last_used_at ? ' • Last used: ' + item.last_used_at : '');
					meta.appendChild(name);
					meta.appendChild(dates);

					const del = document.createElement('button');
					del.type = 'button';
					del.className = 'btn2';
					del.textContent = 'Remove';
					del.onclick = async () => {
						if (!confirm('Remove this passkey?')) return;
						const csrf = csrfInput ? csrfInput.value : '';
						const resp = await fetch(ap + '/passkeys/delete', {
							method: 'POST',
							credentials: 'same-origin',
							headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
							body: JSON.stringify({ id: item.id })
						});
						if (!resp.ok) {
							showPasskeyMsg('Could not remove passkey', true);
							return;
						}
						showPasskeyMsg('Passkey removed', false);
						refreshPasskeys();
					};

					row.appendChild(meta);
					row.appendChild(del);
					passkeyList.appendChild(row);
				});
			} catch (_) {}
		}

		if (passkeyList) {
			refreshPasskeys();
		}

		if (passkeyAdd) {
			passkeyAdd.addEventListener('click', async () => {
				showPasskeyMsg('', false);
				if (!supportsPasskeys()) {
					showPasskeyMsg('Passkeys not supported on this device/browser.', true);
					return;
				}
				const ap = getAdminPath();
				const csrf = csrfInput ? csrfInput.value : '';
				const label = passkeyLabel ? passkeyLabel.value.trim() : '';
				try {
					const start = await fetch(ap + '/passkeys/register/start', {
						method: 'POST',
						credentials: 'same-origin',
						headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
						body: JSON.stringify({ name: label })
					});
					if (!start.ok) {
						showPasskeyMsg('Could not start passkey registration.', true);
						return;
					}
					const startData = await start.json();
					const opts = startData && startData.options ? startData.options.publicKey : null;
					if (!opts) {
						showPasskeyMsg('Invalid registration options.', true);
						return;
					}
					opts.challenge = base64urlToBuffer(opts.challenge);
					opts.user.id = base64urlToBuffer(opts.user.id);
					if (opts.excludeCredentials) {
						opts.excludeCredentials.forEach(c => { c.id = base64urlToBuffer(c.id); });
					}
					const credential = await navigator.credentials.create({ publicKey: opts });
					if (!credential) {
						showPasskeyMsg('No credential returned.', true);
						return;
					}
					const finish = await fetch(ap + '/passkeys/register/finish', {
						method: 'POST',
						credentials: 'same-origin',
						headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'X-WA-Session': startData.session_id || '' },
						body: JSON.stringify(credentialToJSON(credential))
					});
					if (!finish.ok) {
						showPasskeyMsg('Passkey registration failed.', true);
						return;
					}
					showPasskeyMsg('Passkey registered.', false);
					if (passkeyLabel) passkeyLabel.value = '';
					refreshPasskeys();
				} catch (e) {
					showPasskeyMsg('Passkey registration cancelled or failed.', true);
				}
			});
		}
	})();