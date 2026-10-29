#!/bin/sh
# Run every tool on the generated samples, 6 processes at a time. The scanner
# engines take all samples, 50 per process. The baseline deobfuscators take a
# stratified subset (every configuration, the first 10 inputs in inputs.json),
# one process per sample with a 60 s limit, so a hang or crash affects only
# that sample.
cd ~/rot-exp
NODE=/home/ik/.local/share/mise/installs/node/22.22.2/bin/node
python3 - "$@" <<'PY'
import json, sys
first = {c['sha256'] for c in json.load(open('inputs.json'))['chosen'][:10]}
with open('ids.txt', 'w') as all_ids, open('ids-subset.txt', 'w') as subset:
    for label in sys.argv[1:]:
        for s in json.load(open(f'samples-{label}.json'))['samples']:
            if 'error' in s:
                continue
            print(s['id'], file=all_ids)
            if s['input'] in first:
                print(s['id'], file=subset)
PY
for tool in scanner-frozen scanner-hardened; do
  xargs -P 6 -n 50 timeout 900 $NODE measure.mjs $tool < ids.txt > results-$tool.jsonl 2>/dev/null
done
for tool in webcrack synchrony obfuscator-io-deobfuscator; do
  xargs -P 6 -I{} sh -c "timeout 60 $NODE measure.mjs $tool {} 2>/dev/null | tail -1 | grep . || echo '{\"tool\":\"$tool\",\"id\":\"{}\",\"error\":\"timeout or crash\"}'" < ids-subset.txt > results-$tool.jsonl
done
echo done > run.done
