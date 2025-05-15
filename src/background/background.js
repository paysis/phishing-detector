// Store phishing URLs in memory for now for development (TODO: use IndexedDB for large datasets)
const phishingUrls = new Set([
	"phishingsite.com",
	"fake-login.example",
	"malicious-page.com"
])

// listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
	if (request.type === "CHECK_URL") {
		try {
			const urlObj = new URL(request.url);
			const isPhishing = phishingUrls.has(urlObj.hostname);
			sendResponse({ isPhishing });
		} catch (e) {
			console.error("Error parsing URL:", e);
			sendResponse({ isPhishing: false });
		}
		return true;
	}
});
