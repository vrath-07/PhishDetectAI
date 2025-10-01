chrome.runtime.onInstalled.addListener(() => {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon.png",
    title: "PhishDetectAI Installed 🎉",
    message: "Click the extension icon to start scanning suspicious emails."
  });
});
