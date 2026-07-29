const scanBtn = document.getElementById("crawler-scan-btn");
const urlInput = document.getElementById("crawler-url-input");
const results = document.getElementById("crawler-results");
const status = document.getElementById("crawler-status");
const exportActions = document.getElementById("crawler-export-actions");
const exportTxt = document.getElementById("crawler-export-txt");
const exportJson = document.getElementById("crawler-export-json");

const scannedJs = new Set(); // avoid duplicate scans across sources
console.log("%cjsON initialized", "color: #171717; font-weight: bold; font-size: 1.1rem;");

// Normalizes a URL (origin + path + query, no fragment)
const normalizeUrl = (url) => {
  try {
    const u = new URL(url);
    return u.origin + u.pathname + u.search;
  } catch { return url; }
};

// Treats a URL as a directory, for resolving relative links
const directoryfyUrl = (url) => {
  if (url.endsWith('/')) return url;
  try {
    const urlObj = new URL(url);
    const lastPart = urlObj.pathname.split('/').pop() || "";
    if (!lastPart.includes('.')) {
      return url + '/';
    }
  } catch { }
  return url;
};

// Escapes untrusted data before it's inserted into innerHTML
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Tries each CORS proxy in turn, returns the first response that actually looks like it
// came from the target instead of the proxy's own error page.
// TODO: large will pick a reordered proxy list once that list gets its own commit.
async function proxyFetch(url, options = {}, large = false) {
  const list = [
    (u) => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
    (u) => `https://cors.eu.org/${u}`,
    (u) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
    (u) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
    (u) => `https://thingproxy.freeboard.io/fetch/${u}`,
  ];
  let lastError;
  for (const buildUrl of list) {
    try {
      const proxied = buildUrl(url);
      const res = await fetch(proxied, {
        ...options,
        signal: AbortSignal.timeout(20000)
      });
      if (res.status >= 500 || res.status === 413) {
        lastError = new Error(`Proxy ${res.status}`);
        continue;
      }
      return res;
    } catch (e) {
      lastError = e;
      continue;
    }
  }
  throw lastError;
}

