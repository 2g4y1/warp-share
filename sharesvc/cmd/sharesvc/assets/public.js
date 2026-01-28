(() => {
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

		async function copyLink() {
			const url = window.location.href;
			if (navigator.clipboard && navigator.clipboard.writeText) {
				try { await navigator.clipboard.writeText(url); return; } catch (_) {}
			}
			fallbackCopy(url);
		}

		async function shareLink() {
			const url = window.location.href;
			const fileName = (document.body && document.body.dataset && document.body.dataset.fileName) ? document.body.dataset.fileName : '';
			if (navigator.share) {
				try {
					await navigator.share({
						title: fileName ? ('Download: ' + fileName) : 'Download',
						text: fileName || 'Download link',
						url,
					});
					return;
				} catch (e) {
					// user cancelled or share failed -> fall back to copy
				}
			}
			await copyLink();
		}

		function startDownloadAndRedirect(el) {
			// Let the browser start the download in background
			const href = el.getAttribute('href');
			if (!href) return;

			// Show notification
			showNotification('Download started', 'Redirecting shortly…');

			// Open download in hidden iframe (so page is not blocked)
			const iframe = document.createElement('iframe');
			iframe.style.display = 'none';
			iframe.src = href;
			document.body.appendChild(iframe);

			// After short delay redirect to homepage
			const homeUrl = document.body.dataset.homeUrl || '/';
			setTimeout(() => {
				window.location.href = homeUrl;
			}, 2000);
		}

		function showNotification(title, message) {
			// Entferne vorherige Notification falls vorhanden
			const existing = document.getElementById('warp-notification');
			if (existing) existing.remove();

			const notification = document.createElement('div');
			notification.id = 'warp-notification';
			notification.className = 'notif';

			const icon = document.createElement('div');
			icon.className = 'notif-icon';
			icon.innerHTML = '<svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';

			const content = document.createElement('div');
			content.className = 'notif-content';

			const titleDiv = document.createElement('div');
			titleDiv.className = 'notif-title';
			titleDiv.textContent = title;

			const msgDiv = document.createElement('div');
			msgDiv.className = 'notif-msg';
			msgDiv.textContent = message;

			content.appendChild(titleDiv);
			content.appendChild(msgDiv);
			notification.appendChild(icon);
			notification.appendChild(content);

			document.body.appendChild(notification);
		}

		document.addEventListener('click', (ev) => {
			const target = ev.target;
			if (!(target instanceof Element)) return;
			const actionEl = target.closest('[data-action]');
			if (!actionEl) return;
			const action = actionEl.getAttribute('data-action');
			if (action === 'share') { ev.preventDefault(); void shareLink(); }
			if (action === 'copy') { ev.preventDefault(); void copyLink(); }
			if (action === 'download') {
				ev.preventDefault();
				startDownloadAndRedirect(actionEl);
			}
		});

		// Hide the share button on platforms without Web Share API
		try {
			if (!navigator.share) {
				const btn = document.querySelector('[data-action="share"]');
				if (btn) btn.remove();
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
	})();