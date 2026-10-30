# Tier 3 detection per sample: a sample is detected when any of its files (by
# hash, so shared files count for every sample) raises a warning or error.
import json, sys, collections
acq = json.load(open("tiers/tier3-acquisition.json"))
def levels(path):
    out = {}
    for line in open(path):
        r = json.loads(line)
        out[r["sha256"]] = max([{"warning": 2, "error": 3}.get(f["severity"], 0) for f in r.get("findings") or []], default=0)
    return out
for path in sys.argv[1:]:
    lv = levels(path)
    table = collections.defaultdict(collections.Counter)
    for s in acq:
        key = s["ecosystem"] if s["ecosystem"] == "ide_extensions" else "npm/" + s["category"]
        top = max([lv.get(f["sha256"], 0) for f in s.get("files", []) if "sha256" in f], default=-1)
        table[key]["error" if top == 3 else "warning" if top == 2 else "none" if top >= 0 else "no-js"] += 1
    total = sum(t["warning"] + t["error"] for t in table.values())
    print(path.split("/")[-1], total, {k: dict(v) for k, v in sorted(table.items())})
