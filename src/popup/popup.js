document.getElementById('checkCurrentPage').addEventListener('click', async () => {
	try {
		const [tab] = await chrome.tabs.query({ active: true, currentWindow: true, status: 'complete' });
		const statusElement = document.getElementById('status');

		if (!tab?.url || tab.url.startsWith('chrome://')) {
			document.getElementById('status').textContent = "Cannot analyze this page";
			return;
		}
		
		// requires scripting permission
		console.log("Tab ID:", tab.id)
		const [htmlResult] = await chrome.scripting.executeScript({
			target: { tabId: tab.id },
			func: () => document.documentElement.outerHTML
		});


		const response = await chrome.runtime.sendMessage({
			type: "CHECK_URL",
			url: tab.url,
			html: htmlResult?.result
		});

		updateUI(response);
	} catch (error) {
		console.error("Analysis failed: ", error);
		document.getElementById("status").textContent = "Analysis failed";
	}
});

function updateUI(response) {
	const status = document.getElementById('status');
	
	if (response?.isPhishing) {
    	status.textContent = `\u26A0\uFE0F Phishing detected (${response.method})`;
    	status.className = "warning";
    } else {
    	status.textContent = "\uD83C\uDF89 Page appears safe";
		status.className = "safe";
    }
}
