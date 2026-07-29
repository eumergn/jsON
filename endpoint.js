const scanBtn = document.getElementById("crawler-scan-btn");
const urlInput = document.getElementById("crawler-url-input");
const results = document.getElementById("crawler-results");
const status = document.getElementById("crawler-status");
const exportActions = document.getElementById("crawler-export-actions");
const exportTxt = document.getElementById("crawler-export-txt");
const exportJson = document.getElementById("crawler-export-json");

const scannedJs = new Set(); // avoid duplicate scans across sources
console.log("%cjsON initialized", "color: #171717; font-weight: bold; font-size: 1.1rem;");

const normalizeUrl = (url) => {
  // will normalize a URL to origin + path + query, dropping the fragment, so the same
  // page reached through different links/anchors is not scanned twice
};

const directoryfyUrl = (url) => {
  // will treat a URL as a directory when it has no file extension, so relative links
  // found on that page resolve correctly
};

function escapeHtml(str) {
  // will escape untrusted text before it gets inserted into innerHTML
}

async function proxyFetch(url, options = {}, large = false) {
  // will fetch a target URL through a rotating list of CORS proxies, falling back to the
  // next one in the list on failure or on a proxy serving its own error page
}

