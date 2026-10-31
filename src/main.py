
if __package__ in (None, ""):
    from roa_tuples import load_roa_tuples
    from roa_tuples import load_update_tuples
    from rule_engine import rule_engine
else:
    from .roa_tuples import load_roa_tuples
    from roa_tuples import load_update_tuples
    from .rule_engine import rule_engine


if __name__ == "__main__":
    roas = load_roa_tuples()
    print("ROAs loaded:", len(roas))
    print(roas[:3])
    engine = rule_engine(roas)
    print("Rule engine initialized.")
    print("Processing updates...")
    for ts, prefix, origin_asn in load_update_tuples():
        result = engine.rule_baseline(origin_asn, prefix)
        print(f"Timestamp: {ts}, Prefix: {prefix}, Origin ASN: {origin_asn}, Result: {result.name}")