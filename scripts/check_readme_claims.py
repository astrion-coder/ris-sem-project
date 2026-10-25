"""Check every row of README.md's "Numeric claims" table against its notebook cell.

Usage: .venv/bin/python scripts/check_readme_claims.py

Table shape:  | Claim | Value | Notebook | Cell |
Cell k is the k-th code cell, i.e. execution count [k] after a fresh Run All.

An exact Value (backticks stripped) must appear verbatim in that cell's saved output.
A Value written `~<number> <unit>` is a measurement that changes between runs (a timing,
an observed noise maximum): it passes when the output contains a number followed by the
same unit that is within a factor of 2 of the stated number.
Run scripts/run_notebooks.py first so outputs are current.
"""

import re
import sys
from pathlib import Path

import nbformat

ROOT = Path(__file__).resolve().parent.parent
HEADING = "## Numeric claims"
NUMBER = r"[-+]?\d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?"
TOLERANCE = 2.0


def claim_rows(readme: str) -> list[list[str]]:
    lines = readme.splitlines()
    start = lines.index(HEADING)
    rows = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells[0] == "Claim" or set("".join(cells)) <= set("-: "):
            continue
        rows.append(cells)
    return rows


def cell_output(notebook: Path, k: int) -> str:
    nb = nbformat.read(notebook, as_version=4)
    code = [c for c in nb.cells if c.cell_type == "code"]
    cell = code[k - 1]
    parts = []
    for out in cell.get("outputs", []):
        if out.output_type == "stream":
            parts.append(out.text)
        elif "data" in out:
            parts.append(out.data.get("text/plain", ""))
    return "".join(parts)


def approx_found(value: str, output: str) -> bool:
    match = re.fullmatch(rf"~\s*({NUMBER})\s*(\S.*)?", value)
    if match is None:
        raise ValueError(f"malformed approximate value {value!r}")
    stated = float(match.group(1).replace(",", ""))
    unit = re.escape(match.group(2) or "")
    for found in re.finditer(rf"({NUMBER})\s*{unit}(?![A-Za-z])", output):
        measured = float(found.group(1).replace(",", ""))
        if stated == measured == 0 or (stated * measured > 0 and max(stated, measured) / min(stated, measured) <= TOLERANCE):
            return True
    return False


def main() -> int:
    rows = claim_rows((ROOT / "README.md").read_text())
    failures = 0
    for claim, value, notebook, cell in rows:
        value = value.strip("`")
        output = cell_output(ROOT / notebook, int(cell))
        ok = approx_found(value, output) if value.startswith("~") else value in output
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {notebook} [{cell}] {value!r}  {claim}")
    print(f"{len(rows) - failures}/{len(rows)} claims found in their cells")
    return 1 if failures or not rows else 0


if __name__ == "__main__":
    sys.exit(main())
