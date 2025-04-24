// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getCredentials') {
        chrome.storage.sync.get('passwords', (data) => {
            const { passwords = {} } = data;
            const url = new URL(sender.tab.url).hostname;
            const credentials = passwords[url] || null;
            sendResponse({ credentials });
        });
        return true; // Required for async response
    }
}); 