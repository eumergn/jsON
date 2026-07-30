const scanBtn = document.getElementById("crawler-scan-btn");
const urlInput = document.getElementById("crawler-url-input");
const results = document.getElementById("crawler-results");
const status = document.getElementById("crawler-status");
const exportActions = document.getElementById("crawler-export-actions");
const exportTxt = document.getElementById("crawler-export-txt");
const exportJson = document.getElementById("crawler-export-json");

const scannedJs = new Set(); // avoid duplicate scans across sources
console.log("%cjsON initialized", "color: #171717; font-weight: bold; font-size: 1.1rem;");

// Sensitive path wordlist for the prober (loaded from data/sensitive-paths.txt)
let sensitivePaths = [];

// Loads every data/*.txt wordlist once, in parallel, before first use. Both entry points
// (startScan, the prober) await this so the extraction/probing logic itself can stay
// synchronous and doesn't need to change.
async function loadTextList(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to load ${path}: HTTP ${res.status}`);
  const text = await res.text();
  return text.split('\n').map(line => line.trim()).filter(Boolean);
}

let dataReadyPromise = null;
function ensureDataLoaded() {
  if (!dataReadyPromise) {
    dataReadyPromise = Promise.all([
      loadTextList('data/sensitive-paths.txt').then(v => { sensitivePaths = v; }),
      loadTextList('data/blocked-secret-keywords.txt').then(v => { blockedSecretKeywords = v; }),
      loadTextList('data/excluded-extensions.txt').then(v => { excludedExtensions = v; }),
      loadTextList('data/ignored-domains.txt').then(v => { externalDomainsToIgnore = v; }),
      loadTextList('data/disallowed-prefixes.txt').then(v => { disallowedPrefixes = v; }),
    ]);
  }
  return dataReadyPromise;
}

// False-positive keywords for secret detection (loaded from data/blocked-secret-keywords.txt)
let blockedSecretKeywords = [];

// File extensions to ignore (loaded from data/excluded-extensions.txt)
let excludedExtensions = [];

// Third-party/tracker domains to ignore (loaded from data/ignored-domains.txt)
let externalDomainsToIgnore = [];

// URL prefixes to ignore (loaded from data/disallowed-prefixes.txt)
let disallowedPrefixes = [];

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

// Public CORS proxies, tried in order until one works
const PROXY_LIST = [
    (url) => `https://corsproxy.io/?url=${encodeURIComponent(url)}`,
    (url) => `https://cors.eu.org/${url}`,
    (url) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
    (url) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`,
    (url) => `https://thingproxy.freeboard.io/fetch/${url}`,
];

// Same list, reordered for large responses (corsproxy.io caps payload size)
const PROXY_LIST_LARGE = [
    (url) => `https://cors.eu.org/${url}`,
    (url) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
    (url) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`,
    (url) => `https://thingproxy.freeboard.io/fetch/${url}`,
    (url) => `https://corsproxy.io/?url=${encodeURIComponent(url)}`,
];

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

// Builds an index of where each line starts in a text blob, so a match offset from a
// regex can be turned into a line number without rescanning the whole string each time
function computeLineOffsets(content) {
  const offsets = [0];
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) offsets.push(i + 1);
  }
  return offsets;
}

// Binary-searches lineOffsets for the line containing index
function getLineNumber(lineOffsets, index) {
  let lo = 0, hi = lineOffsets.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineOffsets[mid] <= index) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

// Detects file-looking URLs (absolute or quoted relative)
function extractFilesWithLines(content, lineOffsets) {
  const fileRegex = /((?:https?:\/\/|(?<=["']))[^"'\s<>]*\.(?:json|xml|config|env|yaml|yml|sql|db|bak|zip|tar|gz|7z|pdf|doc|docx|js|html|php|asp|aspx|jsp|txt)(?:\?[^"'\s]*)?)(?:["'\s]|$)/gi;
  const matches = [...content.matchAll(fileRegex)];

  return matches.map(m => ({
    value: m[1],
    line: getLineNumber(lineOffsets, m.index)
  })).filter(f => {
    if (!f.value || f.value.startsWith(".")) return false;
    // Length check to avoid massive false positives
    if (f.value.length < 4 || f.value.length > 250) return false;
    return true;
  });
}

// Finds same-site <a href> links to crawl next
function extractInternalLinks(html, baseUrl) {
  const directoryBase = directoryfyUrl(baseUrl);
  const currentUrlObj = new URL(directoryBase);
  const targetHost = currentUrlObj.hostname.replace(/^www\./, "");

  // raw HTML href="..." plus markdown [text](url), needed because the jina.ai fallback
  // returns markdown instead of HTML, so links show up in that form instead
  const patterns = [/href=["']([^"']+)["']/gi, /\]\(([^)\s]+)\)/g];
  const links = [];
  for (const re of patterns) {
    let match;
    while ((match = re.exec(html)) !== null) {
      try {
        const url = new URL(match[1], directoryBase);
        const linkHost = url.hostname.replace(/^www\./, "");

        // allow subdomains and www variants
        if ((linkHost === targetHost || url.hostname.endsWith("." + targetHost)) &&
          !url.pathname.endsWith(".js") && !url.pathname.endsWith(".css")) {
          links.push(normalizeUrl(url.href.split("#")[0]));
        }
      } catch { }
    }
  }
  return [...new Set(links)];
}

// Finds same-site <script src> URLs to crawl next
function extractScriptUrls(html, baseUrl) {
  const directoryBase = directoryfyUrl(baseUrl);
  const currentUrlObj = new URL(directoryBase);
  const targetHost = currentUrlObj.hostname.replace(/^www\./, "");

  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  const scripts = [];
  let match;
  while ((match = re.exec(html)) !== null) {
    try {
      const url = new URL(match[1], directoryBase);
      const scriptHost = url.hostname.replace(/^www\./, "");

      // allow subdomains and www variants
      if (scriptHost === targetHost || url.hostname.endsWith("." + targetHost) || !url.hostname) {
        scripts.push(normalizeUrl(url.href));
      }
    } catch { }
  }
  return [...new Set(scripts)];
}

function isInterestingFile(url) {
  if (!url) return false;
  const cleaned = url.split("?")[0].toLowerCase();
  const interestingExtensions = [
    ".json", ".xml", ".config", ".env", ".yaml", ".yml", ".sql", ".db", ".bak",
    ".zip", ".tar", ".gz", ".7z", ".pdf", ".doc", ".docx", ".js", ".html",
    ".php", ".asp", ".aspx", ".jsp", ".txt", ".xls", ".xlsx", ".csv", ".log"
  ];
  return interestingExtensions.some(ext => cleaned.endsWith(ext));
}

// Randomizes a delay by +/-30% so requests aren't perfectly periodic (an easy pattern
// for a simple rate-limiter to key on).
function jitter(ms) {
  return ms * (0.7 + Math.random() * 0.6);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Crawler throttle: delay between requests + a hard page cap
const CRAWL_REQUEST_DELAY_MS = 150;
const CRAWL_DELAY_MAX_MS = 5000;
const CRAWL_MAX_PAGES = 500;
let crawlerAdaptiveDelay = CRAWL_REQUEST_DELAY_MS; // backs off on 429s, eases back down otherwise

// Same throttle idea, applied to the sensitive-path prober
const PROBE_DELAY_MS = 75;
const PROBE_DELAY_MAX_MS = 4000;
const PROBE_CONCURRENCY = 6; // parallel workers pulling from the path queue

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    URL.revokeObjectURL(link.href);
    document.body.removeChild(link);
  }, 0);
}

