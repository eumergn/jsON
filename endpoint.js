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

// Signatures of a proxy serving its own error/rate-limit page instead of relaying the target.
// A real page from the target should never contain the proxy's own hostname.
const PROXY_ERROR_SIGNATURES = ['corsproxy.io', 'cors.eu.org', 'allorigins.win', 'codetabs.com', 'thingproxy.freeboard.io'];
const deadProxies = new Set(); // proxies skipped for the rest of this session after repeated failures

function looksLikeProxyError(text) {
    if (!text) return false;
    return PROXY_ERROR_SIGNATURES.some(sig => text.includes(sig));
}

// A proxy that fails twice in a session (timeout, 5xx, or a faked response) gets skipped for
// the rest of the run instead of eating a fresh 20s timeout on every single later request.
const proxyFailCounts = new Map();
const PROXY_FAIL_THRESHOLD = 2;
function markProxyFailure(buildUrl) {
    const n = (proxyFailCounts.get(buildUrl) || 0) + 1;
    proxyFailCounts.set(buildUrl, n);
    if (n >= PROXY_FAIL_THRESHOLD) deadProxies.add(buildUrl);
}

// Last-resort fallback: r.jina.ai renders the target page and returns it as markdown text.
// Its own HTTP status is always 200 — the target's real status shows up as a text line
// ("Warning: Target URL returned error 404: Not Found") inside the body, so it has to be
// parsed out and used to build a normal-shaped Response for callers.
// Note: unlike the raw CORS proxies, jina.ai renders the page itself server-side and does
// NOT forward custom request headers (Cookie/Authorization/X-HackerOne-Research) to the
// target — anything relying on those headers won't be authenticated when this path is used.
async function jinaFetch(url) {
    const res = await fetch('https://r.jina.ai/' + url, { signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error(`jina.ai ${res.status}`);
    const text = await res.text();
    const errMatch = text.match(/Target URL returned error (\d{3})/i);
    const status = errMatch ? parseInt(errMatch[1], 10) : 200;
    return new Response(text, { status, statusText: String(status) });
}

// useJina: jina.ai renders the full page (often via headless browser) before returning
// markdown, which can take several seconds per request. Fine for the crawler fetching a
// handful of pages; far too slow to wait on for a bulk sweep of hundreds of paths, so the
// prober disables it and just accepts "no data" once the raw proxies are exhausted.
async function proxyFetch(url, options = {}, large = false, useJina = true) {
    const list = large ? PROXY_LIST_LARGE : PROXY_LIST;
    let lastError;
    for (const buildUrl of list) {
        if (deadProxies.has(buildUrl)) continue;
        try {
            const proxied = buildUrl(url);
            const res = await fetch(proxied, {
                ...options,
                signal: AbortSignal.timeout(20000)
            });
            if (res.status >= 500 || res.status === 413) {
                markProxyFailure(buildUrl);
                lastError = new Error(`Proxy ${res.status}`);
                continue;
            }
            // Some proxies return 200/403/429 while quietly serving their own error/rate-limit
            // page instead of the target's real response. Catch that instead of returning it
            // as if it were genuine target data.
            const peek = await res.clone().text().catch(() => '');
            if (looksLikeProxyError(peek)) {
                markProxyFailure(buildUrl);
                lastError = new Error('Proxy returned its own error page instead of the target');
                continue;
            }
            return res;
        } catch (e) {
            markProxyFailure(buildUrl);
            lastError = e;
            continue;
        }
    }
    if (useJina) {
        try {
            return await jinaFetch(url);
        } catch (e) {
            lastError = e;
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

const endpointRegex = new RegExp(
  `(?:"|')((?:[a-zA-Z]{1,10}:\\/\\/|\\/\\/)[^"']*?|(?:\\/|\\.\\/|\\.\\.\\/)[^"'\\s<>]+|[a-zA-Z0-9_\\-/]+\\.[a-z]{1,5}(?:\\?[^"'\\s]*)?)(?:"|')`,
  "g"
);

// Regex patterns for common API keys/secrets
const secretPatterns = {
  "AWS Key": /AKIA[0-9A-Z]{16}/g,
  "Google API": /AIza[0-9A-Za-z\-_]{35}/g,
  "Stripe Live": /sk_live_[0-9a-zA-Z]{24,}/g,
  "GitHub PAT": /ghp_[0-9a-zA-Z]{36}/g,
  "GitHub Fine-Grained PAT": /github_pat_[0-9a-zA-Z_]{82}/g,
  "GitHub OAuth Access Token": /gho_[0-9a-zA-Z]{36}/g,
  "GitHub Refresh Token": /ghr_[0-9a-zA-Z]{36}/g,
  "Slack Token": /xox[baprs]-[0-9a-zA-Z\-]{10,48}/g,
  "JWT": /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g,
  "Private Key": /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
  "MongoDB": /mongodb(?:\+srv)?:\/\/[^\s"\'<>]+/g,
  "PostgreSQL": /postgres(?:ql)?:\/\/[^\s"\'<>]+/g,
  "Algolia Admin API Key": /algolia.{0,32}([a-z0-9]{32})\b/gi,
  "Algolia Application ID": /algolia.{0,16}([A-Z0-9]{10})\b/gi,
  "Cloudflare API Token": /cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b/gi,
  "Cloudflare Service Key": /(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b/gi,
  "MySQL URI with Credentials": /mysql:\/\/[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:\/[^\s"\'?:]+)?(?:\?[^\s"\']*)?/g,
  "Segment Public API Token": /\bsgp_[A-Z0-9_-]{60,70}\b/g,
  "Segment API Key": /(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})/gi,
  "Facebook Access Token": /EAACEdEose0cBA[A-Z0-9]{20,}\b/g,
  "Google OAuth2 Access Token": /\bya29\.[a-z0-9_-]{30,}\b/g,
  "Slack Webhook": /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/g,
  "Discord Webhook": /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
  "Azure Storage Key": /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/g,
  "Digital Ocean Token": /dop_v1_[a-f0-9]{64}/g,
  "GitLab PAT": /glpat-[0-9a-zA-Z\-_]{20}/g,
  "GitHub App Token": /ghs_[0-9a-zA-Z]{36}/g,
  "Stripe Test Key": /sk_test_[0-9a-zA-Z]{24,}/g,
  "Square Access Token": /sq0atp-[0-9A-Za-z\-_]{22}/g,
  "Telegram Bot Token": /\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b/g,
  "SendGrid API Key": /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
  "Twilio Account SID": /\bAC[a-f0-9]{32}\b/g,
  "Twilio API Key": /\bSK[a-f0-9]{32}\b/g,
  "Heroku API Key": /[hH][eE][rR][oO][kK][uU].{0,16}(?:api|key|token).{0,16}([A-Za-z0-9-]{36})\b/gi,
  "Redis URI": /redis(?:s)?:\/\/[^\s"'<>]+/g,
  "Supabase Key": /sbp_[a-z0-9]{40}/g,
  "NPM Token": /npm_[a-zA-Z0-9]{36}/g,
  "Firebase DB URL": /https:\/\/[a-z0-9\-]+\.firebaseio\.com/g
};

// Skip the full secret-regex pass unless a likely keyword is present
const secretTrigger = /AKIA|AIza|sk_live|ghp_|github_pat_|gh[or]_|xox[baprs]|eyJ|-----BEGIN|mongodb|postgres|postgresql|algolia|cloudflare|mysql|sgp_|segment|sgmt|facebook|fb|ya29|hooks\.slack\.com|discord\.com\/api\/webhooks|DefaultEndpointsProtocol|dop_v1_|glpat-|ghs_|sk_test_|sq0atp-|[0-9]{8,10}:|SG\.|AC[a-f0-9]{32}|heroku|redis|sbp_|npm_|firebaseio/i;

// Extracts URL-like strings from JS/HTML content
function extractEndpointsWithLines(content, lineOffsets) {
  const matches = [...content.matchAll(endpointRegex)];
  return matches.map(m => ({
    value: m[1],
    line: getLineNumber(lineOffsets, m.index)
  })).filter(e => {
    // webhooks are shown as secrets instead, not endpoints
    if (e.value.includes("hooks.slack.com") || e.value.includes("discord.com/api/webhooks")) return false;
    return filterUrl(e.value);
  });
}

// Runs the secret-pattern regexes against page content
function extractSecretsWithLines(content, lineOffsets) {
  if (!secretTrigger.test(content)) return [];

  const found = [];
  for (const [name, regex] of Object.entries(secretPatterns)) {
    const matches = [...content.matchAll(regex)];
    matches.forEach(m => {
      // prefer the capture group if present, else the whole match
      let val = (m[1] || m[0]).trim();

      // skip long paths that aren't actually URIs (false positives)
      if (val.includes("/") && val.split("/").length > 3 && !val.includes("://")) return;
      if (blockedSecretKeywords.some(bk => val.includes(bk))) return;
      if (val.length < 8 || val.length > 500) return;

      found.push({
        value: `${name}: ${val}`,
        line: getLineNumber(lineOffsets, m.index)
      });
    });
  }
  return found;
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

// Decides whether an extracted URL is worth keeping: not an ignored extension/domain/prefix,
// not a base64 blob, and not absurdly long (a common false-positive shape)
function filterUrl(url) {
  const lowered = (url || "").toLowerCase();
  return (
    lowered &&
    !excludedExtensions.some(ext => lowered.endsWith(ext)) &&
    !externalDomainsToIgnore.some(domain => lowered.includes(domain)) &&
    !disallowedPrefixes.some(prefix => lowered.startsWith(prefix)) &&
    !lowered.includes("base64") &&
    lowered.length < 300
  );
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

const stopScanBtn = document.getElementById("crawler-stop-btn");

// Crawler state
const state = {
  scanned: 0,
  endpoints: new Set(),
  secrets: new Set(),
  files: new Set(),
  parameters: new Set(),
  allData: [], // { source, type, value, line }
  scannedUrls: new Set(),
  probedDomains: new Set(),
  isScanning: false,
  isCrawlerStopped: false
};

const updateStats = () => {
  document.getElementById("crawler-stat-scanned").innerText = state.scanned;
  document.getElementById("crawler-stat-endpoints").innerText = state.endpoints.size;
  document.getElementById("crawler-stat-secrets").innerText = state.secrets.size;
  document.getElementById("crawler-stat-files").innerText = state.files.size;
  document.getElementById("crawler-stat-parameters").innerText = state.parameters.size;
};

const addResult = (source, type, value, line = 0) => {
  // skip if this exact result was already recorded
  if (state.allData.some(d => d.source === source && d.value === value && d.line === line && d.type === type)) return;

  state.allData.push({ source, type, value, line });
  if (type === "endpoint") state.endpoints.add(value);
  if (type === "secret") state.secrets.add(value);
  if (type === "file") state.files.add(value);
  if (type === "parameter") state.parameters.add(value);
  updateStats();
};

const setProgress = (percent) => {
  const p = Math.round(percent);
  document.getElementById("crawler-progress-bar").style.width = `${p}%`;
  const textEl = document.getElementById("crawler-progress-percent");
  if (textEl) textEl.innerText = `${p}%`;
};

// Runs the crawler starting from the entered URL
const startScan = async (maxDepth) => {
  let siteUrl = urlInput.value.trim();
  if (!siteUrl) return alert("Enter a valid URL");
  if (!/^https?:\/\//i.test(siteUrl)) siteUrl = "https://" + siteUrl;
  siteUrl = normalizeUrl(siteUrl);
  await ensureDataLoaded();

  state.scanned = 0;
  state.endpoints.clear();
  state.secrets.clear();
  state.files.clear();
  state.parameters.clear();
  state.allData = [];
  state.scannedUrls.clear();
  scannedJs.clear(); // Reset JS scan cache
  crawlerAdaptiveDelay = CRAWL_REQUEST_DELAY_MS;
  updateStats();

  results.innerHTML = "";
  scanBtn.style.display = "none";
  document.getElementById("crawler-full-btn").style.display = "none";
  stopScanBtn.style.display = "inline-block";
  stopScanBtn.disabled = false;
  state.isCrawlerStopped = false;

  document.getElementById("crawler-progress-container").style.display = "block";
  document.getElementById("crawler-filter-section").style.display = "none";
  exportActions.style.display = "none";
  status.innerText = maxDepth === 0 ? "Scanning single page..." : "Starting full recursive scan...";
  setProgress(5);

  try {
    await recursiveScan(siteUrl, maxDepth);
    if (!state.isCrawlerStopped) {
      status.innerText = "Scan complete!";
    } else {
      status.innerText = "Scan stopped manually.";
    }
    setProgress(100);
    document.getElementById("crawler-filter-section").style.display = "block";
    exportActions.style.display = "flex";
    renderResults();
  } catch (e) {
    console.error(e);
    if (!state.isCrawlerStopped) {
      status.innerText = "Scan failed. Check console.";
    }
  }
  scanBtn.style.display = "inline-block";
  scanBtn.disabled = false;
  document.getElementById("crawler-full-btn").style.display = "inline-block";
  document.getElementById("crawler-full-btn").disabled = false;
  stopScanBtn.style.display = "none";
};

stopScanBtn.addEventListener("click", () => {
  state.isCrawlerStopped = true;
  stopScanBtn.disabled = true;
  status.innerText = "Stopping scan... Finishing current requests.";
});

scanBtn.addEventListener("click", () => startScan(0));
document.getElementById("crawler-full-btn").addEventListener("click", () => startScan(1));

// Recursively crawls pages + scripts, extracting endpoints/secrets/files
async function recursiveScan(url, maxDepth, currentDepth = 0, targetHost = null) {
  if (state.isCrawlerStopped) return;
  const normUrl = normalizeUrl(url);
  try {
    const currentUrlObj = new URL(normUrl);
    if (!targetHost) targetHost = currentUrlObj.hostname;

    if (currentUrlObj.hostname !== targetHost && !currentUrlObj.hostname.endsWith("." + targetHost)) {
      return;
    }

    if (currentDepth > maxDepth || state.scannedUrls.has(normUrl)) return;
    if (state.scanned >= CRAWL_MAX_PAGES) return; // hard cap — avoid an uncontrolled crawl on large sites
    state.scannedUrls.add(normUrl);
    state.scanned++;
    updateStats();

    status.innerText = `Scanning: ${normUrl}`;
    setProgress(Math.min(95, (state.scanned / CRAWL_MAX_PAGES) * 100));

    await sleep(jitter(crawlerAdaptiveDelay)); // throttle between requests

    const headersObj = {};
    const crawlerCookie = document.getElementById("crawler-cookie-input")?.value.trim();
    const crawlerAuth = document.getElementById("crawler-auth-input")?.value.trim();
    const crawlerH1 = document.getElementById("crawler-h1-input")?.value.trim();

    if (crawlerCookie) {
      headersObj["X-JSpider-Cookie"] = crawlerCookie;
    }
    if (crawlerAuth) {
      headersObj["X-JSpider-Auth"] = crawlerAuth;
    }
    if (crawlerH1) {
      headersObj["X-HackerOne-Research"] = crawlerH1;
    }

    const res = await proxyFetch(normUrl, { headers: headersObj }, true);
    if (res.status === 429) {
      crawlerAdaptiveDelay = Math.min(crawlerAdaptiveDelay * 2, CRAWL_DELAY_MAX_MS);
    } else {
      crawlerAdaptiveDelay = Math.max(CRAWL_REQUEST_DELAY_MS, crawlerAdaptiveDelay * 0.9);
    }
    if (!res.ok) return;
    const content = await res.text();

    // pull endpoints/secrets/files out of the page content
    const lineOffsets = computeLineOffsets(content);
    const foundEndpoints = extractEndpointsWithLines(content, lineOffsets);
    const foundSecrets = extractSecretsWithLines(content, lineOffsets);
    const foundFiles = extractFilesWithLines(content, lineOffsets);

    foundEndpoints.forEach(e => {
      addResult(normUrl, "endpoint", e.value, e.line);
      if (isInterestingFile(e.value)) {
        addResult(normUrl, "file", e.value, e.line); // also list it under Files
      }
      if (e.value.includes("?")) {
        addResult(normUrl, "parameter", e.value, e.line); // also list it under Parameters
      }
    });

    foundSecrets.forEach(s => addResult(normUrl, "secret", s.value, s.line));

    foundFiles.forEach(f => {
      addResult(normUrl, "file", f.value, f.line);
    });

    // crawl further into discovered links/scripts
    const links = extractInternalLinks(content, normUrl);
    const scripts = extractScriptUrls(content, normUrl);

    for (const script of scripts) {
      if (state.isCrawlerStopped) break;
      await recursiveScan(script, maxDepth, currentDepth, targetHost);
    }

    if (currentDepth < maxDepth) {
      for (const link of links) {
        if (state.isCrawlerStopped) break;
        await recursiveScan(link, maxDepth, currentDepth + 1, targetHost);
      }
    }
  } catch (e) {
    console.warn(`Failed to scan ${normUrl}:`, e);
  }
}

// Crawler/Prober tab switching
const navCrawler = document.getElementById("nav-crawler");
const navProber = document.getElementById("nav-prober");
const crawlerSection = document.getElementById("crawler-section");
const proberSection = document.getElementById("prober-section");

navCrawler.onclick = () => {
  navCrawler.classList.add("active");
  navProber.classList.remove("active");
  crawlerSection.style.display = "block";
  proberSection.style.display = "none";
};

navProber.onclick = () => {
  navProber.classList.add("active");
  navCrawler.classList.remove("active");
  proberSection.style.display = "block";
  crawlerSection.style.display = "none";
};

// Sensitive-path prober
const probeBtn = document.getElementById("prober-scan-btn");
const stopProbeBtn = document.getElementById("prober-stop-btn");
const proberResults = document.getElementById("prober-results");
const proberUrlInput = document.getElementById("prober-url-input");
const proberProgressBar = document.getElementById("prober-progress-bar");
const proberProgressContainer = document.getElementById("prober-progress-container");
const proberStatus = document.getElementById("prober-status");

// 200/403/404 stat counters
const proberStat200 = document.getElementById("prober-stat-200");
const proberStat403 = document.getElementById("prober-stat-403");
const proberStat404 = document.getElementById("prober-stat-404");
const proberFilterSection = document.getElementById("prober-filter-section");

// response-length include/exclude filters
const proberLengthFilters = document.getElementById("prober-length-filters");
const proberIncludeLength = document.getElementById("prober-include-length");
const proberExcludeLength = document.getElementById("prober-exclude-length");

let proberData = []; // stores all probe results for later filtering
let activeProberFilter = "all";
let isProberStopped = false;

probeBtn.onclick = async () => {
  let url = proberUrlInput.value.trim();
  if (!url) return alert("Enter a URL to probe");
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  await ensureDataLoaded();

  try {
    const origin = new URL(url).origin.replace(/\/+$/, ""); // avoid a double // when joining paths
    const proberH1 = document.getElementById("prober-h1-input")?.value.trim();
    const proberHeaders = proberH1 ? { "X-HackerOne-Research": proberH1 } : {};
    proberResults.innerHTML = "";
    proberResults.style.display = "block";
    proberProgressContainer.style.display = "block";
    proberFilterSection.style.display = "flex";
    proberLengthFilters.style.display = "flex";
    proberProgressBar.style.width = "0%";
    const probPercentEl = document.getElementById("prober-progress-percent");
    if (probPercentEl) probPercentEl.innerText = "0%";

    proberData = [];
    let stats = { 200: 0, 403: 0, 404: 0 };
    let adaptiveProbeDelay = PROBE_DELAY_MS;
    proberStat200.innerText = "0";
    proberStat403.innerText = "0";
    proberStat404.innerText = "0";

    probeBtn.style.display = "none";
    stopProbeBtn.style.display = "inline-block";
    stopProbeBtn.disabled = false;
    isProberStopped = false;

    let completed = 0;
    const total = sensitivePaths.length;

    async function probeOnePath(path) {
      const cleanPath = path.startsWith("/") ? path : "/" + path;
      const fullUrl = origin + cleanPath;
      try {
        // useJina: true — worth the wait since PROBE_CONCURRENCY overlaps requests instead
        // of paying jina's per-request delay serially for all ~600 paths
        const res = await proxyFetch(fullUrl, { method: 'GET', headers: proberHeaders }, false, true);
        const status = res.status;
        const text = await res.text();
        const length = text.length;

        // back off on a real rate-limit signal, ease back toward baseline once things are clean
        if (status === 429) {
          adaptiveProbeDelay = Math.min(adaptiveProbeDelay * 2, PROBE_DELAY_MAX_MS);
        } else {
          adaptiveProbeDelay = Math.max(PROBE_DELAY_MS, adaptiveProbeDelay * 0.9);
        }

        // bucket 429 with 401/403, not with "confirmed absent" 404s
        if (status === 200) stats[200]++;
        else if (status === 403 || status === 401 || status === 429) stats[403]++;
        else stats[404]++;

        proberStat200.innerText = stats[200];
        proberStat403.innerText = stats[403];
        proberStat404.innerText = stats[404];

        const resultItem = { path, status, fullUrl, length };
        proberData.push(resultItem);

        if (doesItemMatchFilters(resultItem)) {
          renderProberLine(path, status, fullUrl, length);
        }
      } catch (e) {
        stats[404]++;
        proberStat404.innerText = stats[404];
        const resultItem = { path, status: "ERROR", fullUrl, length: 0 };
        proberData.push(resultItem);

        if (doesItemMatchFilters(resultItem)) {
          renderProberLine(path, "ERROR", fullUrl, 0);
        }
      }
      completed++;
      const percent = Math.round((completed / total) * 100);
      proberProgressBar.style.width = percent + "%";
      const probPercentEl = document.getElementById("prober-progress-percent");
      if (probPercentEl) probPercentEl.innerText = percent + "%";
      proberStatus.innerText = `Probing: ${path} (${completed}/${total})`;
      await sleep(jitter(adaptiveProbeDelay)); // throttle each worker's own request pace
    }

    // A handful of workers pull from the shared queue concurrently, so a slow fallback
    // (like jina.ai) doesn't force the whole ~600-path sweep to run one request at a time.
    let nextIndex = 0;
    async function worker() {
      while (nextIndex < sensitivePaths.length) {
        if (isProberStopped) return;
        const path = sensitivePaths[nextIndex++];
        await probeOnePath(path);
      }
    }
    await Promise.all(Array.from({ length: PROBE_CONCURRENCY }, worker));

    if (isProberStopped) {
      proberStatus.innerText = `Probing stopped manually.`;
    } else {
      proberStatus.innerText = `Probing complete! ${total} paths checked.`;
    }
    proberFilterSection.style.display = "flex";
  } catch (e) {
    alert("Invalid URL");
  } finally {
    probeBtn.style.display = "inline-block";
    stopProbeBtn.style.display = "none";
  }
};

stopProbeBtn.onclick = () => {
  isProberStopped = true;
  stopProbeBtn.disabled = true;
  proberStatus.innerText = "Stopping prober... Finishing current request.";
};

const filterProberResults = (filter) => {
  if (filter) activeProberFilter = filter;
  proberResults.innerHTML = "";

  proberData.forEach(item => {
    if (doesItemMatchFilters(item)) {
      renderProberLine(item.path, item.status, item.fullUrl, item.length);
    }
  });

  document.querySelectorAll("[data-prober-filter]").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-prober-filter") === activeProberFilter);
  });
};

// Checks a probe result against the active status + length filters
function doesItemMatchFilters(item) {
  const statusNum = parseInt(item.status);
  let statusMatch = false;

  if (activeProberFilter === "all") statusMatch = true;
  else if (activeProberFilter === "200" && statusNum === 200) statusMatch = true;
  else if (activeProberFilter === "403" && (statusNum === 403 || statusNum === 401 || statusNum === 429)) statusMatch = true;
  else if (activeProberFilter === "404" && (statusNum === 404 || item.status === "ERROR")) statusMatch = true;

  if (!statusMatch) return false;

  const incStrings = proberIncludeLength.value.split(',').map(s => s.trim()).filter(s => s !== "");
  const excStrings = proberExcludeLength.value.split(',').map(s => s.trim()).filter(s => s !== "");
  const itemLenStr = String(item.length);

  if (incStrings.length > 0 && !incStrings.includes(itemLenStr)) return false;
  if (excStrings.length > 0 && excStrings.includes(itemLenStr)) return false;

  return true;
}

proberIncludeLength.addEventListener('input', () => filterProberResults());
proberExcludeLength.addEventListener('input', () => filterProberResults());

document.querySelectorAll("#prober-filter-section .tab-btn").forEach(btn => {
  btn.onclick = () => filterProberResults(btn.getAttribute("data-prober-filter"));
});

// Renders one row in the prober results list
function renderProberLine(path, status, fullUrl, length) {
  const line = document.createElement("div");
  line.className = "prober-line";

  let statusClass = "status-error";
  if (status === 200) statusClass = "status-200";
  else if (status === 403) statusClass = "status-403";
  else if (status === 401) statusClass = "status-401";
  else if (status === 429) statusClass = "status-403"; // rate-limited — styled like blocked, not "not found"
  else if (status === 404) statusClass = "status-404";

  const lengthDisplay = length !== undefined ? `<span class="prober-length" style="color:var(--text-dim); font-size:0.85em; font-family: monospace;">[${length}]</span>` : '';

  const safeUrl = escapeHtml(fullUrl);
  let openBtnHtml = "";
  if (status === 200) {
    openBtnHtml = `<a href="${safeUrl}" target="_blank" class="prober-open-btn-200" style="margin-left: 0;">Open</a>`;
  } else if (status === 403 || status === 401) {
    openBtnHtml = `<a href="${safeUrl}" target="_blank" class="prober-open-btn-403" style="margin-left: 0;">Open</a>`;
  }

  line.innerHTML = `
    <span class="prober-path" style="flex: 1; word-break: break-all; padding-right: 15px;">${escapeHtml(path)}</span>
    <div style="display: flex; align-items: center; justify-content: flex-end; flex-shrink: 0;">
      <span class="prober-status ${statusClass}" style="width: 50px; text-align: center;">${escapeHtml(String(status))}</span>
      <div style="width: 75px; text-align: center; margin-left: 5px;">${openBtnHtml}</div>
      <div style="width: 75px; text-align: right; margin-left: 5px;">${lengthDisplay}</div>
    </div>
  `;

  if (proberResults.querySelector(".status")) proberResults.innerHTML = ""; // clear "loading" placeholder
  proberResults.appendChild(line);
}

