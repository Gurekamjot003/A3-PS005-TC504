import csv, glob, json, lzma, os
from datetime import datetime, timezone
from mrtparse import Reader

MRT_GLOB = "data/mrt/updates.*"
ROA_GLOB = "data/roa/*.csv.xz"


def get_origin(as_path_attr):
    segs = as_path_attr["value"]
    if not segs:
        return None                                   # empty path
    last = segs[-1]
    if 1 in last["type"] or not last["value"]:        # AS_SET at the end: skip
        return None
    return int(last["value"][-1])


def parse_updates():
    rows = []
    for path in sorted(glob.glob(MRT_GLOB)):
        for entry in Reader(path):
            d = entry.data
            msg = d.get("bgp_message")
            if not msg or 2 not in msg["type"]:       # UPDATE only
                continue
            as_path = next((a for a in msg.get("path_attributes", []) if 2 in a["type"]), None)
            if as_path is None:                       # pure withdrawal
                continue
            origin = get_origin(as_path)
            if origin is None:
                continue
            ts = int(next(iter(d["timestamp"])))      # epoch seconds (UTC)
            peer = int(d["peer_as"])
            for n in msg.get("nlri", []):             # IPv4 prefixes only
                rows.append((ts, f'{n["prefix"]}/{n["length"]}', origin, peer))
    rows.sort(key=lambda r: r[0])
    with open("data/updates.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "prefix", "origin_asn", "peer_asn"])
        w.writerows(rows)
    return rows


def to_epoch(s):
    s = s.strip().replace("T", " ").replace("Z", "")
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            pass
    raise ValueError(f"unrecognised date format: {s!r}")


def align_roas(t_min, t_max):
    kept = dropped_time = dropped_v6 = 0
    with open("data/roa/roas-aligned.csv", "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(["asn", "prefix", "maxlen", "not_before", "not_after", "tal"])
        for path in glob.glob(ROA_GLOB):
            tal = os.path.basename(path).split("-")[0]
            with lzma.open(path, "rt", encoding="utf-8") as f:
                try:
                    next(f)                           # skip header
                except StopIteration:
                    continue                          # empty file
                for line in f:
                    p = line.strip().split(",")
                    if len(p) < 6:
                        continue
                    _, asn, prefix, maxlen, nb_raw, na_raw = p[:6]
                    if ":" in prefix:                 # IPv4 only
                        dropped_v6 += 1
                        continue
                    nb, na = to_epoch(nb_raw), to_epoch(na_raw)
                    if (nb is not None and nb > t_min) or (na is not None and na < t_max):
                        dropped_time += 1
                        continue
                    w.writerow([asn.replace("AS", ""), prefix, maxlen, nb_raw, na_raw, tal])
                    kept += 1
    return kept, dropped_time, dropped_v6


def run():
    rows = parse_updates()
    if not rows:
        raise SystemExit("No IPv4 updates parsed. Check data/mrt/ and the file names.")
    t_min, t_max = rows[0][0], rows[-1][0]
    fmt = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"Updates: {len(rows)} | window {fmt(t_min)} -> {fmt(t_max)}")

    with open("data/window.json", "w") as f:
        json.dump({"t_min": t_min, "t_max": t_max}, f)

    kept, dropped, v6 = align_roas(t_min, t_max)
    print(f"ROAs kept: {kept} | dropped (not valid in window): {dropped} | dropped (IPv6): {v6}")


if __name__ == "__main__":
    run()