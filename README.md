# jsON

A browser-based recon toolkit for bug bounty / web pentesting work.

## Goal

A single-page tool with two parts:

- **Crawler**: point it at a target URL, it crawls linked pages and JS files, and flags
  interesting stuff along the way, including exposed sensitive paths (`.well-known/*`, `.git/*`,
  backup files, admin panels, etc.), leaked secrets/API keys in JS, and endpoint paths worth
  testing further. Exportable results (txt/json).
- **Prober**: a sensitive-path brute-forcer. Feed it a target, it checks a curated wordlist of
  common sensitive/interesting paths and reports what's actually there (with status-code
  filtering).

Everything runs client-side in the browser.

## Status

Early build, in progress. Committing incrementally as pieces come together.

## Disclaimer

For use only against targets you're authorized to test (bug bounty programs in scope, or your own
infrastructure). Not for unauthorized access.
