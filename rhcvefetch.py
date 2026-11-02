"""Fetch Red Hat CVE data and Security Bulletin (RHSB) pages."""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

CVE_HTML_URL = "https://access.redhat.com/security/cve/{}"
CVE_JSON_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json"
RHSB_HTML_URL = "https://access.redhat.com/security/vulnerabilities/{}"

USER_AGENT = "rhcvefetch/0.1"

ID_PATTERNS = {
    "CVE": re.compile(r"^CVE-\d{4}-\d{4,}$"),
    "RHSB": re.compile(r"^RHSB-\d{4}-\d+$"),
}


@dataclass(frozen=True)
class Target:
    type: str
    id: str
    description: str | None = None


@dataclass(frozen=True)
class Job:
    """One file to download for a target."""

    target: Target
    url: str
    dest: Path
    headless: bool  # True: save the rendered DOM; False: save the raw server response


def parse_target(entry: object) -> Target:
    """Validate one entry of `targets`. Raises ValueError on invalid input."""
    if not isinstance(entry, dict):
        raise ValueError("target must be an object")

    type_ = entry.get("type")
    id_ = entry.get("id")
    if not isinstance(type_, str) or not type_:
        raise ValueError("'type' is required")
    if not isinstance(id_, str) or not id_:
        raise ValueError("'id' is required")
    if type_ not in ID_PATTERNS:
        raise ValueError(f"'type' must be \"CVE\" or \"RHSB\" (upper case): {type_!r}")
    if not ID_PATTERNS[type_].match(id_):
        raise ValueError(f"'id' {id_!r} does not match type {type_!r} (IDs must be upper case)")

    description = entry.get("description")
    if description is not None and not isinstance(description, str):
        raise ValueError("'description' must be a string")

    return Target(type=type_, id=id_, description=description)


def load_targets(path: Path) -> tuple[list[Target], int]:
    """Read targets.json. Returns (valid targets, number of skipped entries)."""
    with path.open(encoding="utf-8") as f:
        doc = json.load(f)
    entries = doc.get("targets") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'targets' must be an array")

    targets: list[Target] = []
    skipped = 0
    for i, entry in enumerate(entries):
        try:
            targets.append(parse_target(entry))
        except ValueError as e:
            print(f"skip targets[{i}]: {e}", file=sys.stderr)
            skipped += 1
    return targets, skipped


def jobs_for(target: Target, data_dir: Path) -> list[Job]:
    """List the files to download for a target (output names use the upper-case ID)."""
    out_dir = data_dir / target.type
    if target.type == "CVE":
        return [
            # The CVE page is rendered by JavaScript, so it needs a headless browser.
            Job(target, CVE_HTML_URL.format(target.id.lower()), out_dir / f"{target.id}.html", headless=True),
            Job(target, CVE_JSON_URL.format(target.id), out_dir / f"{target.id}.json", headless=False),
        ]
    return [Job(target, RHSB_HTML_URL.format(target.id), out_dir / f"{target.id}.html", headless=False)]


def save_atomic(path: Path, content: str | bytes) -> None:
    """Write via a temporary file so an interrupted run never leaves a partial file."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(content)
    tmp.replace(path)


def fetch_raw(url: str, *, timeout: float) -> bytes:
    """GET `url` and return the server response body as is. Raises OSError on HTTP/network errors."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def wait_for_stable(page, *, timeout: float, interval: float = 1.0, stable_checks: int = 3) -> str:
    """Poll the DOM until it is unchanged for `stable_checks` polls, then return it.

    `networkidle` never fires on access.redhat.com (background traffic), and the
    page keeps growing for a few seconds after `load`, so wait for the HTML to settle.
    """
    deadline = time.monotonic() + timeout
    html = page.content()
    stable = 0
    while stable < stable_checks:
        if time.monotonic() >= deadline:
            raise RuntimeError(f"page did not settle within {timeout:g}s")
        time.sleep(interval)
        current = page.content()
        stable = stable + 1 if current == html else 0
        html = current
    return html


def fetch_rendered(page, url: str, *, timeout: float) -> str:
    """Load `url` in the headless browser and return the settled DOM as HTML."""
    resp = page.goto(url, wait_until="load")
    if resp is None or resp.status != 200:
        raise RuntimeError("no response" if resp is None else f"HTTP {resp.status}")
    return wait_for_stable(page, timeout=timeout)


def fetch_all(
    targets: list[Target],
    data_dir: Path,
    *,
    delay: float,
    timeout: float,
    skip_existing: bool,
) -> tuple[int, int, int]:
    """Download every file of every target. Returns (saved, existing, failed)."""
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    todo: list[Job] = []
    existing = 0
    for t in targets:
        for job in jobs_for(t, data_dir):
            if skip_existing and job.dest.exists():
                print(f"exists  {job.dest}")
                existing += 1
            else:
                todo.append(job)

    saved = failed = 0
    page = None
    with contextlib.ExitStack() as stack:
        for n, job in enumerate(todo):
            if n:
                time.sleep(delay)
            try:
                if job.headless:
                    if page is None:  # start the browser only when a rendered page is needed
                        pw = stack.enter_context(sync_playwright())
                        browser = pw.chromium.launch()
                        stack.callback(browser.close)
                        page = browser.new_page()
                        page.set_default_timeout(timeout * 1000)
                    content: str | bytes = fetch_rendered(page, job.url, timeout=timeout)
                else:
                    content = fetch_raw(job.url, timeout=timeout)
                    if job.dest.suffix == ".json":
                        json.loads(content)  # do not store an error page as JSON data
                save_atomic(job.dest, content)
            except (PlaywrightError, RuntimeError, OSError, ValueError) as e:
                print(f"failed  {job.target.type} {job.target.id} ({job.url}): {e}", file=sys.stderr)
                failed += 1
            else:
                print(f"saved   {job.dest}")
                saved += 1
    return saved, existing, failed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rhcvefetch", description=__doc__)
    ap.add_argument("-i", "--input", type=Path, default=Path("targets.json"))
    ap.add_argument("-o", "--data-dir", type=Path, default=Path("data"))
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between requests")
    ap.add_argument("--timeout", type=float, default=60.0, help="per-request timeout in seconds")
    ap.add_argument(
        "--skip-existing",
        action="store_true",
        help="skip files that already exist (default: download again and overwrite)",
    )
    args = ap.parse_args(argv)

    try:
        targets, skipped = load_targets(args.input)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    saved, existing, failed = fetch_all(
        targets, args.data_dir, delay=args.delay, timeout=args.timeout, skip_existing=args.skip_existing
    )
    print(f"done: {saved} saved, {existing} already existed, {failed} failed, {skipped} invalid entries skipped")
    return 1 if failed or skipped else 0


if __name__ == "__main__":
    sys.exit(main())
