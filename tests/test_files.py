"""Scan every sample file: attacks must not be ALLOW; benign must be ALLOW. (Images need tesseract-ocr.)"""
import os, sys, logging
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, R); logging.disable(logging.CRITICAL)
from pifw import Firewall
fw = Firewall(); ok = 0; total = 0
for kind, want_allow in (("attacks", False), ("benign", True)):
    d = os.path.join(R, "samples", kind)
    for fn in sorted(os.listdir(d)):
        r = fw.scan(open(os.path.join(d, fn), "rb").read(), filename=fn); total += 1
        good = (r.verdict == "ALLOW") == want_allow; ok += good
        print(f"{'PASS' if good else 'FAIL'}  {kind:8s} {fn:28s} {r.verdict:8s} {r.risk}")
print(f"{ok}/{total} correct")
