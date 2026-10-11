"""Run: python tests/evaluate.py   (dev set + held-out set; held-out was written after tuning)."""
import os, sys, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, os.path.dirname(__file__))
logging.disable(logging.CRITICAL)
from pifw import Firewall
import corpus
fw = Firewall()
def run(name, attacks, benign):
    miss = [a for a in attacks if fw.scan(a[-1], a[-2] if len(a) == 3 else a[0]).verdict == "ALLOW"]
    fp = [b for b in benign if fw.scan(b[1], b[0]).verdict != "ALLOW"]
    print(f"{name:10s} attacks caught {len(attacks)-len(miss)}/{len(attacks)} = {100*(len(attacks)-len(miss))/len(attacks):.1f}%   false positives {len(fp)}/{len(benign)} = {100*len(fp)/len(benign):.1f}%")
    for m in miss: print("   MISSED:", m[-1][:80].replace("\n", " "))
    for f in fp: print("   FALSE POSITIVE:", f[1][:80].replace("\n", " "))
run("dev", corpus.ATTACKS, corpus.BENIGN)
run("held-out", [(s, t) for s, t in corpus.HOLDOUT_ATTACKS], corpus.HOLDOUT_BENIGN)
run("blind", [(s_, t) for s_, t in corpus.BLIND_ATTACKS], corpus.BLIND_BENIGN)
