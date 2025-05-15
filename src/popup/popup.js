document.getElementById('checkCurrentPage').addEventListener('click', async () => {
	const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
	const statusElement = document.getElementById('status');

	const response = await chrome.runtime.sendMessage({
		type: "CHECK_URL",
		url: tab.url
	});

	if (response?.isPhishing) {
    	statusElement.textContent = "\u26A0\uFE0F Phishing detected";
    	statusElement.className = "warning";
    } else {
    	statusElement.textContent = "\uD83C\uDF89 Page appears safe";
    }
});
