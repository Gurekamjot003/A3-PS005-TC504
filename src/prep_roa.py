import lzma, glob

out = open("data/roa/roas-merged.csv", "w", encoding="utf-8")
out.write("asn,prefix,maxlen,not_before,not_after,tal\n")
for path in glob.glob("data/roa/*.csv.xz"):
    tal = path.split("\\")[-1].split("-")[0]
    with lzma.open(path, "rt", encoding="utf-8") as f:
        next(f)
        for line in f:
            p = line.strip().split(",")
            out.write(f"{p[1].replace('AS','')},{p[2]},{p[3]},{p[4]},{p[5]},{tal}\n")
out.close()