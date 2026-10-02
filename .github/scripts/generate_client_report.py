# Generate an html summary from client conformance results

import argparse
import html
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class Result:
    name: str
    results_found: bool = False
    total: int = -1
    passed: int = -1
    failed: int = -1
    xfailed: int = -1
    skipped: int = -1
    xfailed_tests: list[str] = field(default_factory=list)
    conformance_version: str = ""
    repository_url: str = ""
    run_url: str = ""

    def __init__(self, report_path: Path) -> None:
        with report_path.open() as f:
            data = json.load(f)

        self.name = report_path.name.replace(".json", "")
        self.xfailed_tests = []

        if data == {}:
            return  # no results found
        self.results_found = True

        env = data.get("environment", {})
        self.conformance_version = env.get("tuf_conformance_version", "")
        self.repository_url = env.get("repository_url", "")
        self.run_url = env.get("run_url", "")

        summary = data["summary"]
        self.total = summary["total"]
        self.passed = summary.get("passed", 0) + summary.get("subtests passed", 0)
        self.failed = summary.get("failed", 0) + summary.get("subtests failed", 0)
        self.xfailed = summary.get("xfailed", 0) + summary.get("subtests xfailed", 0)
        self.skipped = summary.get("skipped", 0) + summary.get("subtests skipped", 0)

        self.xfailed_tests = [  
            test["nodeid"].split("::")[-1]
            for test in data.get("tests", [])
            if test.get("outcome") == "xfailed"
        ]

        # TODO: parse data["tests"] and add feature checks like
        # self.supports_delegated_targets


def _render_row(res: Result) -> str:
    if not res.results_found:
        return (
            f'<tr class="not-found"><td><strong>{res.name}</strong></td>'
            f"{6 * '<td></td>'}</tr>"
        )

    status = "passed" if res.failed == 0 else "failed"
    passrate = round(100 * res.passed / res.total) if res.total > 0 else 0

    client = (
        f'<a href="{res.repository_url}">{res.name}</a>'
        if res.repository_url
        else res.name
    )
    run = f' (<a href="{res.run_url}">run</a>)' if res.run_url else ""

    if res.xfailed_tests:
        items = "".join(f"<li>{html.escape(t)}</li>" for t in res.xfailed_tests)
        xfailed = f"<details><summary>{res.xfailed}</summary><ul>{items}</ul></details>"
    else:
        xfailed = str(res.xfailed)

    return f"""
                <tr class="{status}">
                    <td><strong>{client}</strong>{run}</td>
                    <td>{res.conformance_version}</td>
                    <td>{passrate}%</td>
                    <td>{res.passed}</td>
                    <td>{res.failed}</td>
                    <td>{res.skipped}</td>
                    <td>{xfailed}</td>
                </tr>"""


def _generate_html(results: list[Result]) -> str:
    rows = "\n".join(_render_row(res) for res in results)
    return f"""
    <html>
    <head>
        <title>TUF Client Conformance Results</title>
        <style>
            body {{ font-family: sans-serif; margin: 2em; }}
            table {{ border-collapse: collapse; }}
            th, td {{ border: 1px solid #ccc; padding: 8px 12px; vertical-align: top; }}
            th {{ background-color: #f4f4f4; }}
            .failed {{ background-color: #ffe0e0; }}
            .passed {{ background-color: #e0ffe0; }}
            .not-found {{ background-color: #eeeeee; }}
            details summary {{ cursor: pointer; }}
            details ul {{
                margin: 4px 0 0 0; padding-left: 20px; font-family: monospace;
            }}
        </style>
    </head>
    <body>
        <h1>TUF Client Conformance Results</h1>
        <p>Last updated: {datetime.now(UTC).isoformat(timespec="minutes")}Z</p>
        <table>
            <thead>
                <tr>
                    <th>Client</th>
                    <th>tuf-conformance</th>
                    <th>Pass Rate</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Skipped</th>
                    <th>Xfailed</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        <p><i>
            If you would like another client to be included in this table, please
            <a href="https://github.com/theupdateframework/tuf-conformance/issues/new">
            file an issue</a>.
        </i></p>
    </body>
    </html>
    """


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    # Read all client results
    results: list[Result] = []
    for report_path in Path(args.reports_dir).glob("**/*.json"):
        results.append(Result(report_path))
    results.sort(key=lambda result: result.name)

    # Write summary HTML
    output_file = Path(args.output)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w") as f:
        f.write(_generate_html(results))
