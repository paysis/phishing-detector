import { BloomFilter } from 'bloom-filters';
import { simhash } from '@biu/simhash';
import { openDB } from 'idb';

// DATABASE CONFIG
const DB_NAME = 'phishingDB';
const DB_VERSION = 1;
const URL_STORE = 'phishingUrls';
const HTML_STORE = 'htmlFingerprints';

const initDB = () => openDB(DB_NAME, DB_VERSION, {
	upgrade(db) {
		if (!db.objectStoreNames.contains(URL_STORE)) {
			db.createObjectStore(URL_STORE, { keyPath: 'url' });
		}
		if (!db.objectStoreNames.contains(HTML_STORE)) {
			db.createObjectStore(HTML_STORE, { keyPath: 'simhash' });
		}
	}
});

// BLOOMFILTER
let bloomFilter;

async function initBloomFilter() {
	const db = await initDB();
	const urls = await db.getAll(URL_STORE);
	const phishingUrls = urls.filter(u => u.result === 1).map(u => u.url);

	// bloomfilter with false positive rate of 0.001 (80k rows at hand)
	// NEVER returns false negative!
	bloomFilter = BloomFilter.from(phishingUrls, 0.001);
	console.log("Initialized bloom filter");
}

// SIMHASH
function generateSimHash(html) {
	// clean html before hashing
	const cleanHtml = html
		.replace(/<script[^>]*>.*?<\/script>/gis, '')
		.replace(/<style[^>]*>.*?<\/style>/gis, '')
		.replace(/<[^>]+>/g, ' ');

	const generatedHash = simhash([{ text: cleanHtml, weight: 1 }]);
	console.log("Generated simhash: " + generatedHash);
	return generatedHash; // returns 64 bit hash
}

async function checkSimHash(hostname, html) {
	const db = await initDB();
	const hash = generateSimHash(html);
	const entry = await db.get(HTML_STORE, hash);
	if (!entry) {
		console.log("No entry");
		return false;
	}

	if(entry.result === 0 && entry.url === hostname) {
		console.log("result=0 & url=hostname");
		return false;
	}

	if (entry.result === 1 && entry.url !== hostname) {
		console.log("result=1 & url != hostname");
		return false;
	}

	// result == 1 && url == hostname
	// result == 0 && url != hostname
	console.log(`entry: otherwise: ${entry.result} ${entry.url}`);
	return true;
}

// CSV IMPORT (One-time operation during installation of extension)
async function importCSV() {
	// TODO: use bundled csv instead
	const mockData = [
		{ url: "phishingsite.com", html: "<html>fake</html>", result: 1 },
		{ url: "google.com", html: "<html>real</html>", result: 0 },
		{ url: "duckduckgo.com", html: "<html>fake malicious</html>", result: 1 }
		// ...
	];

	const db = await initDB();
	const tx = db.transaction([URL_STORE, HTML_STORE], 'readwrite');

	await Promise.all([
		...mockData.map(item => tx.objectStore(URL_STORE).put(item)),
		...mockData
			//.filter(item => item.result === 1)
			.map(item => tx.objectStore(HTML_STORE)
				.put({ simhash: generateSimHash(item.html), url: item.url }))
	]);

	await tx.done;
}

// Phishing detection
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
	if (request.type === "CHECK_URL") {
		detectPhishing(request.url, request.html).then(sendResponse);
		return true;
	}
});

async function detectPhishing(url, html) {
	// bloom filter check
	const hostname = new URL(url).hostname;
	if (bloomFilter.has(hostname)) {
		console.log("Entered bloom filter check");
		const db = await initDB();
		const exists = await db.get(URL_STORE, hostname);
		if (exists?.result === 1) {
			return { isPhishing: true, method: 'bloom' };
		}
	}

	// SimHash check
	if (html && await checkSimHash(hostname, html)) {
		console.log("Entered simhash check, currently seeks 100% hash match");
		return { isPhishing: true, method: 'simhash' };
	}

	// TODO: add fine-tuned LLM check
	console.log("No phishing detected!");
	return { isPhishing: false };
}

// NOTIFICATION EVENT
chrome.runtime.onMessage.addListener((request) => {
	if (request.action === "show-notification") {
		chrome.notifications.create("reminder", {
			type: "basic",
			iconUrl: chrome.runtime.getURL("assets/icon48.png"),
			title: "Phishing Hunter",
			message: "WARNING: Phishing website is detected! Please check the authenticity of this website.",
			priority: 1
		});
	}	
});

// INSTALLATION
chrome.runtime.onInstalled.addListener(async () => {
	console.log("Installing...");
	await initDB();
	await importCSV();
	await initBloomFilter();
	console.log("Installation complete!");
})
