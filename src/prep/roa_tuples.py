import csv

def load_roa_tuples(path="data/roa/roas-aligned.csv"):
    """List of (asn, max_len, prefix) tuples for the radix trie."""
    roas = []
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            roas.append((int(r["asn"]), int(r["maxlen"]), r["prefix"]))
    return roas

def load_update_tuples(path="data/updates.csv"):
    """(ts, prefix, origin_asn) one row at a time"""
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            yield int(r["ts"]), r["prefix"], int(r["origin_asn"])

if __name__ == "__main__":
    roas = load_roa_tuples()
    print("ROAs loaded:", len(roas))
    print(roas[:3])