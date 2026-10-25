"""Compare Angelia's process walk with Volatility 3 windows.pslist on one dump.

Use the same x64 PAGEDU64 image for both tools. This script does not infer
hidden processes from a separate live snapshot.
"""

import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def image_name(value):
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def address(value):
    if value is None:
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        return None


def volatility_rows(node):
    if isinstance(node, list):
        for item in node:
            yield from volatility_rows(item)
    elif isinstance(node, dict):
        if "PID" in node and "ImageFileName" in node:
            yield node
        for child in node.get("__children", []):
            yield from volatility_rows(child)


def compare(angelia, volatility):
    if angelia.get("dump_format") != "PAGEDU64":
        raise ValueError("Angelia result is not from a PAGEDU64 image")
    if angelia.get("walk_complete") is not True:
        raise ValueError("Angelia process walk was partial or lacks completion metadata")
    a_rows = [entry for entry in angelia.get("entries", []) if entry.get("seen_in_raw_walk")]
    v_rows = list(volatility_rows(volatility))
    if not a_rows or not v_rows:
        raise ValueError("both process lists must be nonempty")
    a_by_pid = {int(row["pid"]): row for row in a_rows}
    v_by_pid = {int(row["PID"]): row for row in v_rows}
    if len(a_by_pid) != len(a_rows) or len(v_by_pid) != len(v_rows):
        raise ValueError("duplicate PIDs in a process list; manual review required")

    missing = sorted(set(v_by_pid) - set(a_by_pid))
    extra = sorted(set(a_by_pid) - set(v_by_pid))
    image_differences = []
    offset_differences = []
    for pid in sorted(set(a_by_pid) & set(v_by_pid)):
        a, v = a_by_pid[pid], v_by_pid[pid]
        if image_name(a.get("image_raw")) != image_name(v.get("ImageFileName")):
            image_differences.append({"pid": pid, "angelia": a.get("image_raw"),
                                      "volatility": v.get("ImageFileName")})
        a_offset, v_offset = address(a.get("eprocess_va")), address(v.get("Offset(V)"))
        if a_offset is not None and v_offset is not None and a_offset != v_offset:
            offset_differences.append({"pid": pid, "angelia": a.get("eprocess_va"),
                                       "volatility": v.get("Offset(V)")})
    return {
        "angelia_count": len(a_rows), "volatility_count": len(v_rows),
        "missing_in_angelia": missing, "extra_in_angelia": extra,
        "image_differences": image_differences,
        "eprocess_offset_differences": offset_differences,
        "matched": not (missing or extra or image_differences or offset_differences),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", type=Path, required=True)
    parser.add_argument("--angelia", type=Path, required=True)
    parser.add_argument("--volatility", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    with args.dump.open("rb") as stream:
        magic = stream.read(8)
    if magic != b"PAGEDU64":
        parser.error("only a genuine x64 PAGEDU64 image is supported by this comparison")
    a = json.loads(args.angelia.read_text(encoding="utf-8-sig"))
    v = json.loads(args.volatility.read_text(encoding="utf-8-sig"))
    if Path(a.get("dump_path", "")).resolve() != args.dump.resolve():
        parser.error("Angelia inventory points to a different dump path")
    try:
        result = compare(a, v)
    except ValueError as error:
        parser.error(str(error))
    result["dump_path"] = str(args.dump.resolve())
    result["dump_sha256"] = digest(args.dump)
    result["angelia_inventory_sha256"] = digest(args.angelia)
    result["volatility_output_sha256"] = digest(args.volatility)
    result["dump_time_100ns"] = a.get("dump_time_100ns")
    result["snapshot_time_utc"] = a.get("snapshot_time_utc")
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"{args.out}: {'MATCH' if result['matched'] else 'DIFFERENCES'} "
          f"({result['angelia_count']} Angelia / {result['volatility_count']} Volatility)")
    return 0 if result["matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
