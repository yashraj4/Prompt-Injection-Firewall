# Prompt Injection Firewall (PIFW)

Scans any content before it reaches an AI agent and returns **ALLOW / SANITIZE / BLOCK** with per-category risk, rule-level evidence and a sanitized copy.

**Inputs:** user messages, web pages/HTML, PDF (text + metadata), Word (.docx, hidden runs), email (.eml), Markdown (comments, link titles), JSON API responses, source code, images (OCR via Tesseract).
**Attack types (9):** instruction override, role change, secret extraction, tool abuse, credential theft, context poisoning, multi-step jailbreak, encoded instructions, indirect injection.

## Quick start
```
pip install -r requirements.txt
python tools/make_samples.py
python -m pifw serve                      # web UI + POST /api/scan
python -m pifw scan samples/attacks/web_hidden_div.html
python tests/evaluate.py && python tests/test_files.py
```
```python
from pifw import Firewall
r = Firewall().scan("Ignore all previous instructions", "user_message")
print(r.verdict, r.risk, r.categories)
```

## Pipeline
1. **Extract** per format, keeping hidden content (CSS-hidden elements, comments, alt text, PDF metadata, hidden Word runs) as separate segments.
2. **Normalise**: Unicode NFKC, zero-width stripping, homoglyph folding, de-spacing ("i g n o r e").
3. **Detect**: regex rules per category, base64 decode-and-rescan, negation guard ("staff must never share passwords"), discussion discount (quoted examples in security text).
4. **Score**: noisy-OR per category; overlapping hits in one category collapse to the strongest.
5. **Decide**: risk >= 0.75 BLOCK, >= 0.40 SANITIZE, else ALLOW. Untrusted sources with any strong finding also raise indirect injection. Multi-turn sessions are re-scanned jointly.
6. **Sanitise**: whole malicious sentences are replaced with `[REMOVED: ...]`; hidden segments with injections are dropped; output is wrapped in an `UNTRUSTED_DATA` envelope.

## Server hardening
Binds 127.0.0.1 by default; strict CSP, `nosniff`, no-store; same-origin check; body-size and per-IP rate limits; optional `PIFW_API_TOKEN` (header `X-API-Key`) for non-browser clients; audit log holds verdict/risk only, never content.

## Honest limits
- Detection is rules + a semantic concept layer, so unseen paraphrases can still slip through; see EVALUATION.md for dev, held-out and blind figures and known weaknesses.
- Image OCR needs `tesseract-ocr` installed; without it images yield an "ocr-unavailable" segment and are not scanned.
- English only. No semantic/ML classifier yet (see roadmap).
