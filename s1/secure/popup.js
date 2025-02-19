document.addEventListener('DOMContentLoaded', function () {
  document.getElementById('runExtension').addEventListener('click', function () {
    chrome.tabs.create({ url: 'http://127.0.0.1:5000' });
  });

  document.getElementById('viewDetails').addEventListener('click', function () {
    chrome.tabs.create({ url: 'chrome://extensions/?id=' + chrome.runtime.id });
  });

  document.getElementById('description').addEventListener('click', function () {
    chrome.tabs.create({ url: 'description.html' });
  });
});
