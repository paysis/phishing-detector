//  Runs immediately when injected into the page

// ========================
// 1. DOM Injection Utilities
// ========================

/**
 * Injects a warning banner at the top of the page
 */
function injectWarningBanner() {
  // Check if warning already exists
  if (document.getElementById('phishing-hunter-warning')) return;

  // Create warning element
  const warning = document.createElement('div');
  warning.id = 'phishing-hunter-warning';
  warning.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background: linear-gradient(to right, #d32f2f, #b71c1c);
    color: white;
    padding: 12px 0;
    text-align: center;
    font-size: 16px;
    font-weight: bold;
    z-index: 999999;
    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 15px;
  `;

  warning.innerHTML = `
    <span>⚠️ WARNING: Potential Phishing Website Detected!</span>
  `;

  // Add to page
  if (document.body) {
    document.body.prepend(warning);
  } else {
    document.documentElement.prepend(warning);
  }

}

// ========================
// 2. Phishing Detection
// ========================

/**
 * Gets page content for analysis
 */
function getPageContent() {
  return {
    url: window.location.href,
    html: document.documentElement.outerHTML
  };
}

/**
 * Main detection function
 */
async function detectPhishing() {
  try {
    const { url, html } = getPageContent();
    const response = await chrome.runtime.sendMessage({
      type: "CHECK_URL",
      url,
      html
    });

    if (response?.isPhishing) {
      injectWarningBanner();
      chrome.runtime.sendMessage({action: "show-notification"});
    }
  } catch (error) {
    console.error('Phishing detection error:', error);
  }
}

// ========================
// 3. Execution Strategies
// ========================

// Strategy 1: Run immediately if DOM is already loaded
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  detectPhishing();
} 
// Strategy 2: Wait for DOM if needed
else {
  document.addEventListener('DOMContentLoaded', detectPhishing);
}

// Strategy 3: Fallback - check again after 1s delay
setTimeout(detectPhishing, 1000);
