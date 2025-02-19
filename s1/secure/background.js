chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension installed.");

  chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [1, 2], // Remove existing rules with IDs 1 and 2
    addRules: [
      {
        id: 1,
        priority: 1,
        action: { type: "block" },
        condition: {
          urlFilter: "*",
          resourceTypes: ["main_frame", "sub_frame"]
        }
      },
      {
        id: 2,
        priority: 1,
        action: { type: "allow" },
        condition: {
          urlFilter: "http://127.0.0.1:5000/*",
          resourceTypes: ["main_frame", "sub_frame"]
        }
      },
      {
        id: 3,
        priority: 1,
        action: { type: "allow" },
        condition: {
          urlFilter: "chrome-extension://*",
          resourceTypes: ["main_frame", "sub_frame"]
        }
      }
    ]
  }, () => {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
    } else {
      console.log("Dynamic rules updated successfully.");
    }
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkNow') {
    console.log("Check Now button clicked.");
    // Add more logic here if needed
    sendResponse({ status: "Security check complete." });
  }
});
