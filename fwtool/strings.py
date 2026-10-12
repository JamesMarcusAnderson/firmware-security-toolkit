import re

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")

def extract(path, min_len=4):
    out = []
    with open(path, "rb") as f:
        for m in PRINTABLE.finditer(f.read()):
            s = m.group().decode("ascii", errors="ignore")
            if len(s) >= min_len:
                out.append({"offset": m.start(), "string": s})
    return out
