import csv, random
from collections import Counter
from pathlib import Path
import sys

from roa_tuples import load_roa_tuples, load_update_tuples
from rule_engine import rule_engine, status

USE_STEP4 = False      
BOGUS_ASN = 64500      
POOL = 2000            
N_ORACLE = 300         
N_INJECT = 200         
N_EXPORT = 20         
random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 1)


def pref_int(prefix):
    base, plen = prefix.split("/")
    a, b, c, d = map(int, base.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d, int(plen)


def make_oracle(roas):
    parsed = []
    for asn, maxlen, pfx in roas:
        n, l = pref_int(pfx)
        parsed.append((asn, maxlen, l, n >> (32 - l) if l else 0))

    def oracle(asn, prefix):
        n, plen = pref_int(prefix)
        cov = [(a, m, l) for a, m, l, top in parsed
               if l <= plen and (n >> (32 - l) if l else 0) == top]
        if not cov:
            return status.UNKNOWN
        if any(a == asn and plen <= m for a, m, _ in cov):
            return status.VALID
        if any(a == asn for a, _, _ in cov):
            return status.SUBPREFIX_ANOMALY
        if USE_STEP4 and any(plen > l for _, _, l in cov):
            return status.SUBPREFIX_ANOMALY
        return status.ORIGIN_ANOMALY
    return oracle


def reservoir(stream, k):
    pool = []
    for i, row in enumerate(stream):
        if i < k:
            pool.append(row)
        else:
            j = random.randint(0, i)
            if j < k:
                pool[j] = row
    return pool


def main():
    roas = load_roa_tuples()
    engine = rule_engine(roas)
    oracle = make_oracle(roas)
    pool = reservoir(load_update_tuples(), POOL)
    print(f"ROAs: {len(roas)} | random pool of updates: {len(pool)}")

    sample = random.sample(pool, min(N_ORACLE, len(pool)))
    bad = 0
    for ts, prefix, asn in sample:
        a, b = engine.rule_baseline(asn, prefix), oracle(asn, prefix)
        if a != b:
            bad += 1
            if bad <= 10:
                print("MISMATCH", prefix, asn, "engine:", a.name, "oracle:", b.name)
    print(f"\n[1] trie vs oracle: {bad} mismatches out of {len(sample)}")

    valid = [r for r in pool if engine.rule_baseline(r[2], r[1]) == status.VALID]
    valid = valid[:N_INJECT]
    inj = {"origin_hijack": [0, 0], "subprefix_hijack": [0, 0], "maxlen_violation": [0, 0]}
    for ts, prefix, asn in valid:
        base, plen = prefix.split("/")
        plen = int(plen)
        r = engine.rule_baseline(BOGUS_ASN, prefix)
        inj["origin_hijack"][1] += 1
        inj["origin_hijack"][0] += r in (status.ORIGIN_ANOMALY, status.SUBPREFIX_ANOMALY)
        if plen < 32:
            r = engine.rule_baseline(BOGUS_ASN, f"{base}/{plen+1}")
            inj["subprefix_hijack"][1] += 1
            inj["subprefix_hijack"][0] += r in (status.ORIGIN_ANOMALY, status.SUBPREFIX_ANOMALY)
            r = engine.rule_baseline(asn, f"{base}/32")
            inj["maxlen_violation"][1] += 1
            inj["maxlen_violation"][0] += r != status.VALID
    print(f"\n[2] injected attacks on {len(valid)} valid routes (detected / total):")
    for k, (hit, tot) in inj.items():
        print(f"    {k}: {hit}/{tot} = {hit / max(tot, 1):.1%}")
    print("    (maxlen_violation below 100% is fine where a ROA allows /32)")

    results = {(p, a): engine.rule_baseline(a, p) for _, p, a in pool}
    counts = Counter(s.name for s in results.values())
    total = sum(counts.values())
    print(f"\n[3] label distribution (random pool of {len(pool)}):")
    for k, v in counts.most_common():
        print(f"    {k}: {v} ({v / total:.2%})")

    inv = [(p, a) for (p, a), s in results.items()
           if s in (status.ORIGIN_ANOMALY, status.SUBPREFIX_ANOMALY)]
    ok = [(p, a) for (p, a), s in results.items() if s == status.VALID]
    pick = random.sample(inv, min(N_EXPORT, len(inv))) + random.sample(ok, min(N_EXPORT, len(ok)))
    out = Path(__file__).resolve().parent / "data" / "validation_sample.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["prefix", "origin_asn", "engine_label"])
        for p, a in pick:
            w.writerow([p, a, results[(p, a)].name])
    print(f"\n[4] wrote {len(pick)} rows to {out}")


if __name__ == "__main__":
    main()