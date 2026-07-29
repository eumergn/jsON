const scanBtn = document.getElementById("crawler-scan-btn");
const urlInput = document.getElementById("crawler-url-input");
const results = document.getElementById("crawler-results");
const status = document.getElementById("crawler-status");
const exportActions = document.getElementById("crawler-export-actions");
const exportTxt = document.getElementById("crawler-export-txt");
const exportJson = document.getElementById("crawler-export-json");

const scannedJs = new Set(); // avoid duplicate scans across sources
console.log("%cjsON initialized", "color: #171717; font-weight: bold; font-size: 1.1rem;");

