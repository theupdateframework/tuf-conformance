# Generate an html summary from client conformance results

import argparse
import json
from dataclasses import dataclass
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

    def __init__(self, report_path: Path) -> None:
        with report_path.open() as f:
            data = json.load(f)

        self.name = report_path.name.replace(".json", "")

        if data == {}:
            return  # no results found
        self.results_found = True

        summary = data["summary"]
        self.total = summary["total"]
        self.passed = summary.get("passed", 0) + summary.get("subtests passed", 0)
        self.failed = summary.get("failed", 0) + summary.get("subtests failed", 0)
        self.xfailed = summary.get("xfailed", 0) + summary.get("subtests xfailed", 0)
        self.skipped = summary.get("skipped", 0) + summary.get("subtests skipped", 0)

        # TODO: parse data["tests"] and add feature checks like
        # self.supports_delegated_targets


def _generate_html(results: list[Result]) -> str:
    html = f"""
    <html>
    <head>
        <title>TUF Client Conformance Results</title>
        <style>
            body {{ font-family: sans-serif; margin: 2em; }}
            table {{ border-collapse: collapse; }}
            th, td {{ border: 1px solid #ccc; padding: 8px 12px; }}
            th {{ background-color: #f4f4f4; }}
            .failed {{ background-color: #ffe0e0; }}
            .passed {{ background-color: #e0ffe0; }}
            .not-found {{ background-color: #eeeeee; }}
        </style>
    </head>
    <body>
        <h1>TUF Client Conformance Results</h1>
        <p>Last updated: {datetime.now(UTC).isoformat(timespec="minutes")}Z</p>
        <table>
            <thead>
                <tr>
                    <th>Client</th>
                    <th>Pass Rate</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Skipped</th>
                    <th>Xfailed</th>
                </tr>
            </thead>
            <tbody>
    """
    for res in results:
        if not res.results_found:
            status_class = "not-found"
        elif res.failed == 0:
            status_class = "passed"
        else:
            status_class = "failed"
        passrate = round(100 * res.passed / res.total) if res.total > 0 else 0
        html += f"""
                <tr class="{status_class}">
                    <td><strong>{res.name}</strong></td>
                    <td>{f"{passrate}%" if res.results_found else ""}</td>
                    <td>{res.passed if res.results_found else ""}</td>
                    <td>{res.failed if res.results_found else ""}</td>
                    <td>{res.skipped if res.results_found else ""}</td>
                    <td>{res.xfailed if res.results_found else ""}</td>
                </tr>
        """
    html += """
            </tbody>
        </table>
    </body>
    </html>
    """
    return html


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
