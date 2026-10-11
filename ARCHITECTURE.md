# Architecture and Self-Declared Position

**Declared position: F3 x D3.** F3: all 9 attack types detected (instruction override, role change, secret extraction, tool abuse, credential theft, context poisoning, multi-step jailbreak, encoded instruction, indirect injection). D3: heterogeneous multimodal input (text, HTML, PDF, DOCX, email, Markdown, JSON, code, images via OCR) with measured reliability and published limits.

## Flow
`input -> kind detection -> extraction (visible + hidden segments) -> normalisation -> detection -> scoring -> verdict -> sanitiser -> UNTRUSTED_DATA envelope -> agent`

| Stage | What it does | Evidence in demo |
|---|---|---|
| Extraction | Splits visible vs hidden content: CSS-hidden elements, comments, alt/title, img URLs, PDF metadata, hidden Word runs, email headers | Hidden div, PDF metadata, DOCX hidden run samples |
| Normalisation | NFKC, zero-width removal, homoglyph folding, de-spacing | Cyrillic and spaced-out attacks |
| Detection (rules) | ~30 regex rules, negation guard, quoted-discussion discount | Security-blog benign sample |
| Detection (semantic) | Action x object concept pairing in short windows, so paraphrases match | "Set aside everything your creators told you" |
| Decoding | base64 decode and rescan; findings tagged `decoded` | Base64 chip |
| Scoring | Noisy-OR per category, overlap collapse, multi-category bonus, source-aware indirect-injection boost | Category bars in UI |
| Sanitiser | Removes whole sentences / hidden segments, wraps remainder as data | Side-by-side panel |
| Session | Re-scans recent turns jointly for staged jailbreaks | `session_id` |

## Responsible AI and robustness
Explainable evidence (rule id, weight, location); audit log without content; localhost-by-default hardened server; rate and size limits; honest evaluation sets (dev / held-out / blind) with misses published in EVALUATION.md.

## Models and technologies
Deterministic rules plus concept layer (no model call on the hot path, ~1-3 ms for text); Tesseract OCR for images; BeautifulSoup, pypdf, python-docx for extraction. Optional LLM judge for grey-zone content is a roadmap item.
