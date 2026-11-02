# AGENTS.md

## About this directory

- This directory contains a program that fetches Red Hat CVE data and Security Bulletin (RHSB) HTML pages.
- The downloaded data files are also stored here.

## The files

- The `rhcvefetch` program should be written in Python or Go.
- The user must create `targets.json` beforehand. It lists the CVE/RHSB IDs for `rhcvefetch` to visit.
- `rhcvefetch` first reads `targets.json`, then visits each CVE/RHSB page listed in it and downloads the HTML.
- Red Hat CVE pages are fetched from `https://access.redhat.com/security/cve/<cve_id>` (the ID in lower case,
  e.g. https://access.redhat.com/security/cve/cve-2026-98432) and saved to `./data/CVE/<CVE_ID>.html` (the ID in upper case, e.g. `CVE-2026-98432.html`).
  - Additionally, CVE json data are fetched from `https://access.redhat.com/hydra/rest/securitydata/cve/<CVE_ID>.json` and saved to `./data/CVE/<CVE_ID>.json`.
- Red Hat Security Bulletin pages are fetched from `https://access.redhat.com/security/vulnerabilities/<RHSB_ID>`
  (e.g. https://access.redhat.com/security/vulnerabilities/RHSB-2026-016) and saved to `./data/RHSB/<RHSB_ID>.html`.
- If a page is rendered dynamically (e.g. by JavaScript), `rhcvefetch` should save the fully rendered HTML (the DOM after scripts have run), not the raw server response. Use a headless browser (e.g. Playwright for Python, chromedp for Go) when necessary.
  - <CVE_ID>.html should be downloaded with a headless browser.
  - <CVE_ID>.json and <RHSB_ID>.html should be saved as server response (without a headless browser).

## Options

- By default, `rhcvefetch` downloads every file again and overwrites existing ones.
  - Exception: if a re-downloaded `<CVE_ID>.html` has the same visible text as the existing file (ignoring `<script>`, `<style>`, `<iframe>` and `<noscript>`), the existing file is kept as is. Rendered pages contain random IDs, timestamps and injected third-party scripts that change on every fetch, and these differences are meaningless in git.
- `--skip-existing`: skip files that already exist.
- `-i, --input <path>`: input file (default: `targets.json`).
- `-o, --data-dir <path>`: output directory (default: `data`).
- `--delay <seconds>`: wait between requests (default: 2).
- `--timeout <seconds>`: per-request timeout (default: 60).

## Code

- Comments in source files should be written in English.

## Schema

`targets.json` has the following structure:

```json
{
  "targets": [
    {
      "type": "CVE",
      "description": "Use-after-free - kernel IPv4",
      "id": "CVE-2026-98432"
    },
    {
      "type": "RHSB",
      "description": "RHSB-2026-016 Use-after-free - kernel IPv4 (CVE-2026-98432)",
      "id": "RHSB-2026-016"
    }
  ]
}
```

- `targets`: array of target objects, required
- `type`: `"CVE"` or `"RHSB"` (upper case only), required
- `id`: CVE or RHSB ID in upper case (e.g. `CVE-2026-98432`), required. Output file names use the same upper-case ID.
- `description`: free-form note for humans, optional. `rhcvefetch` ignores it.
- Validation: If `type` and `id` do not match (e.g. `type` is `"CVE"` but `id` starts with `RHSB-`), `rhcvefetch` should report an error and skip that target.
