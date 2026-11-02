import json
from pathlib import Path

import pytest

from rhcvefetch import Target, jobs_for, load_targets, parse_target, save_atomic, wait_for_stable


def test_parse_valid_cve_and_rhsb():
    assert parse_target({"type": "CVE", "id": "CVE-2026-98432"}) == Target("CVE", "CVE-2026-98432")
    assert parse_target({"type": "RHSB", "id": "RHSB-2026-016"}).id == "RHSB-2026-016"


@pytest.mark.parametrize(
    "entry",
    [
        "not an object",
        {"id": "CVE-2026-98432"},
        {"type": "CVE"},
        {"type": "cve", "id": "CVE-2026-98432"},
        {"type": "CVE", "id": "cve-2026-98432"},
        {"type": "CVE", "id": "RHSB-2026-016"},
        {"type": "RHSB", "id": "CVE-2026-98432"},
        {"type": "CVE", "id": "CVE-2026-98432", "description": 1},
    ],
)
def test_parse_invalid(entry):
    with pytest.raises(ValueError):
        parse_target(entry)


def test_jobs_for_cve_html_is_headless_and_json_is_raw():
    html, js = jobs_for(Target("CVE", "CVE-2026-98432"), Path("data"))
    assert html.url == "https://access.redhat.com/security/cve/cve-2026-98432"  # lower-case path
    assert html.dest == Path("data/CVE/CVE-2026-98432.html")  # upper-case file name
    assert html.headless is True
    assert js.url == "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-98432.json"
    assert js.dest == Path("data/CVE/CVE-2026-98432.json")
    assert js.headless is False


def test_jobs_for_rhsb_is_raw_html():
    (job,) = jobs_for(Target("RHSB", "RHSB-2026-016"), Path("data"))
    assert job.url == "https://access.redhat.com/security/vulnerabilities/RHSB-2026-016"
    assert job.dest == Path("data/RHSB/RHSB-2026-016.html")
    assert job.headless is False


def test_load_targets_skips_invalid(tmp_path, capsys):
    f = tmp_path / "targets.json"
    f.write_text(
        json.dumps(
            {
                "targets": [
                    {"type": "CVE", "id": "CVE-2026-98432"},
                    {"type": "CVE", "id": "RHSB-2026-016"},
                ]
            }
        )
    )
    targets, skipped = load_targets(f)
    assert [t.id for t in targets] == ["CVE-2026-98432"]
    assert skipped == 1
    assert "targets[1]" in capsys.readouterr().err


def test_load_targets_requires_array(tmp_path):
    f = tmp_path / "targets.json"
    f.write_text("{}")
    with pytest.raises(ValueError):
        load_targets(f)


def test_save_atomic_leaves_no_tmp(tmp_path):
    dest = tmp_path / "CVE" / "x.html"
    save_atomic(dest, "<html></html>")
    assert dest.read_text() == "<html></html>"
    assert list(dest.parent.glob("*.tmp")) == []


class FakePage:
    def __init__(self, snapshots):
        self.snapshots = list(snapshots)

    def content(self):
        return self.snapshots.pop(0) if len(self.snapshots) > 1 else self.snapshots[0]


def test_wait_for_stable_returns_settled_html():
    page = FakePage(["a", "ab", "abc", "abc", "abc", "abc"])
    assert wait_for_stable(page, timeout=5, interval=0) == "abc"


def test_wait_for_stable_times_out_if_always_changing():
    class Growing:
        n = 0

        def content(self):
            self.n += 1
            return "x" * self.n

    with pytest.raises(RuntimeError):
        wait_for_stable(Growing(), timeout=0.05, interval=0.01)
