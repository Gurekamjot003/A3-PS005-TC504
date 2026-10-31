import csv
from pathlib import Path


def _resolve_data_path(path):
    p = Path(path)
    if p.is_absolute():
        return p
    src_dir = Path(__file__).resolve().parent
    candidate = src_dir / p
    if candidate.exists():
        return candidate
    return src_dir / "data" / p.name if p.parts and p.parts[0] == "data" else candidate


def load_roa_tuples(path="data/roa/roas-aligned.csv"):
    """List of (asn, max_len, prefix) tuples for the radix trie."""
    roas = []
    with _resolve_data_path(path).open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            roas.append((int(r["asn"]), int(r["maxlen"]), r["prefix"]))
    return roas


def load_update_tuples(path="data/updates.csv"):
    """(ts, prefix, origin_asn) one row at a time"""
    with _resolve_data_path(path).open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            yield int(r["ts"]), r["prefix"], int(r["origin_asn"])

