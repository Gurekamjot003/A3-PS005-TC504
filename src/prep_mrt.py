import glob
from mrtparse import Reader

out = open("data/updates.csv", "w", encoding="utf-8")
out.write("ts,prefix,origin_asn\n")

for path in sorted(glob.glob("data/mrt/updates.*")):
    for entry in Reader(path):
        d = entry.data
        if "bgp_message" not in d:
            continue
        msg = d["bgp_message"]
        if 2 not in msg.get("type", {}):        # 2 = UPDATE
            continue
        ts = list(d["timestamp"].keys())[0]
        path_attr = [a for a in msg.get("path_attributes", []) if 2 in a["type"]]  # 2 = AS_PATH
        if not path_attr or not msg.get("nlri"):
            continue                              # withdrawals or no path
        segs = path_attr[0]["value"]
        last = segs[-1]
        if 1 in last["type"]:                     # AS_SET at the end: skip
            continue
        origin = last["value"][-1]
        for n in msg["nlri"]:
            out.write(f'{ts},{n["prefix"]}/{n["length"]},{origin}\n')
out.close()