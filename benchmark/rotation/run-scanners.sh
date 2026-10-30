#!/bin/sh
# All three scanner engines on the main and held-out sets, 50 samples per process.
cd ~/rot-exp
NODE=/home/ik/.local/share/mise/installs/node/22.22.2/bin/node
for tool in scanner-frozen scanner-hardened scanner-revised; do
  xargs -P 6 -n 50 timeout 900 $NODE measure.mjs $tool < ids-scanner.txt > results-$tool.jsonl 2>/dev/null
done
$NODE validate-alignment.mjs > validate-alignment.out
echo done > run-scanners.done
