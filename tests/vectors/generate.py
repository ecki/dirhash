"""Regenerate shared logical-tree vectors using the independent Python oracles."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from conformance import DIGESTS, expected  # noqa: E402


def main():
    cases = {"empty": {}}
    for line in (HERE / "trees.tsv").read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        case, path, kind, mode, payload = line.split("\t")
        cases.setdefault(case, {})[path] = (kind, bytes.fromhex(payload), int(mode, 8))
    lines = ["# case\tscheme\tdigest\tvalue"]
    for case, entries in cases.items():
        for scheme in ("h1", "gittree", "swhid", "nar"):
            for algorithm in DIGESTS:
                if algorithm == "blake3":
                    continue
                lines.append("\t".join((case, scheme, algorithm, expected(entries, scheme, algorithm))))
    (HERE / "hashes.tsv").write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")


if __name__ == "__main__":
    main()
