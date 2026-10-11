# Evaluation

Run `python tests/evaluate.py` and `python tests/test_files.py`. Latest output:
```
dev        attacks caught 20/20 = 100.0%   false positives 0/13 = 0.0%
held-out   attacks caught 12/12 = 100.0%   false positives 0/8 = 0.0%
blind      attacks caught 12/12 = 100.0%   false positives 0/10 = 0.0%
13/13 correct
```

**Caveat:** dev rules were tuned on the dev set; held-out and blind sets were written by the developers (not independent red-teamers) and are small, so they are optimistic. Known weaknesses: non-English attacks, novel obfuscation (rot13, hex, leetspeak), long multi-turn setups, and images when Tesseract is missing or text is stylised.
