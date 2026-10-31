
if __package__ in (None, ""):
    from roa_tuples import load_roa_tuples
    from rule_engine import rule_engine
else:
    from .roa_tuples import load_roa_tuples
    from .rule_engine import rule_engine


if __name__ == "__main__":
    roas = load_roa_tuples()
    print("ROAs loaded:", len(roas))
    print(roas[:3])
    engine = rule_engine(roas)
    print("Rule engine initialized.")
    