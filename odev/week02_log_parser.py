from pathlib import Path
from collections import Counter
import sys

# Default path: one level up from this file, in datasets/auth.log
LOG = Path(__file__).parents[1] / "datasets" / "auth.log"


def parse_line(line: str) -> dict:
    line = line.strip()
    if not line:
        return {}
    parts = line.split()
    # first token is timestamp if it looks like ISO format
    data = {}
    if parts:
        first = parts[0]
        if "T" in first and ("-" in first or ":" in first):
            data["timestamp"] = first
            kv_parts = parts[1:]
        else:
            # no explicit timestamp, treat whole line as kv pairs
            kv_parts = parts
    else:
        kv_parts = []

    for token in kv_parts:
        if "=" in token:
            k, v = token.split("=", 1)
            data[k] = v
    return data


def main():
    # allow path override from argv[1]
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else LOG
    if not path.exists():
        print(f"Log file not found: {path}")
        return

    status_counts = Counter()
    failed_ips = Counter()

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            item = parse_line(line)
            if not item:
                continue
            status = item.get("status")
            if status:
                status_counts[status] += 1
                if status.upper() == "FAILED":
                    ip = item.get("src_ip") or item.get("src") or item.get("ip")
                    if ip:
                        failed_ips[ip] += 1

    top_failed = failed_ips.most_common(1)
    top_failed_entry = tuple(top_failed[0]) if top_failed else (None, 0)

    print("Status counts:", dict(status_counts))
    print("Top failed IP:", top_failed_entry)


if __name__ == "__main__":
    main()
