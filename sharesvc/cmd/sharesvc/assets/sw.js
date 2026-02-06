// Service Worker for WARP SHARE
// Only intercepts GET requests for caching

const CACHE_VERSION = 'warp-share-v1';
const CACHE_ASSETS = [
	'/warp-share.css',
	'/warp-share.js',
];

// Install event - cache essential assets
self.addEventListener('install', (event) => {
	event.waitUntil(
		caches.open(CACHE_VERSION).then((cache) => {
			return cache.addAll(CACHE_ASSETS);
		})
	);
	// Activate immediately
	self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
	event.waitUntil(
		caches.keys().then((cacheNames) => {
			return Promise.all(
				cacheNames
					.filter((name) => name !== CACHE_VERSION)
					.map((name) => caches.delete(name))
			);
		})
	);
	// Take control of all pages immediately
	return self.clients.claim();
});

// Fetch event - only intercept GET requests
self.addEventListener('fetch', (event) => {
	// Only handle GET requests - non-GET requests are NOT intercepted
	if (event.request.method !== 'GET') {
		return;
	}

	// Don't cache admin routes
	if (event.request.url.includes('/admin/') || event.request.url.includes('/a/')) {
		return;
	}

	// Don't cache download requests
	if (event.request.url.includes('?download=1')) {
		return;
	}

	event.respondWith(
		caches.match(event.request).then((response) => {
			// Return cached response if found
			if (response) {
				return response;
			}

			// Otherwise fetch from network
			return fetch(event.request).then((response) => {
				// Don't cache if not a successful response
				if (!response || response.status !== 200 || response.type === 'error') {
					return response;
				}

				// Clone the response
				const responseToCache = response.clone();

				// Cache static assets only
				if (
					event.request.url.includes('/warp-share.css') ||
					event.request.url.includes('/warp-share.js')
				) {
					caches.open(CACHE_VERSION).then((cache) => {
						cache.put(event.request, responseToCache);
					});
				}

				return response;
			});
		})
	);
});
