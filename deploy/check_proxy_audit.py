"""Report existing proxy advisories and fail on new findings or overdue review."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
from typing import Any


def findings(report: dict[str, Any]) -> list[tuple[str, str, set[str]]]:
    if "dependencies" in report:
        return [
            (package["name"].lower(), package["version"], {v["id"], *v.get("aliases", [])})
            for package in report["dependencies"]
            for v in package.get("vulns", [])
        ]
    if "Results" in report:
        return [
            (v["PkgName"].lower(), v["InstalledVersion"], {v["VulnerabilityID"]})
            for result in report["Results"]
            for v in result.get("Vulnerabilities", [])
            if v.get("FixedVersion") and v["Severity"] in {"HIGH", "CRITICAL"}
        ]
    raise ValueError("Unrecognized audit report; refusing to treat it as clean")


def check(report: dict[str, Any], baseline: dict[str, Any], today: dt.date) -> list[str]:
    errors: list[str] = []
    for name, version, ids in findings(report):
        known = baseline["packages"].get(name, {})
        label = f"{name} {version}: {', '.join(sorted(ids))}"
        if version != known.get("version") or not ids.intersection(known.get("ids", [])):
            errors.append("New or changed finding: " + label)
        elif today >= dt.date.fromisoformat(baseline["review_by"]):
            errors.append("Upstream exception needs review: " + label)
        else:
            print("Known upstream finding: " + label)
    return errors


if __name__ == "__main__":
    baseline = json.loads(Path(__file__).with_name("mitmproxy").joinpath("audit-baseline.json").read_text())
    report = json.loads(Path(sys.argv[1]).read_text())
    errors = check(report, baseline, dt.datetime.now(dt.timezone.utc).date())
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(bool(errors))
