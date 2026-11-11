#!/usr/bin/env python3
"""Independent validation of the PDF report signatures with pyHanko (an implementation other than this tool's).

Usage: python tests/validate_pdf_signature.py <file.pdf | folder> [...]

For every PDF: the signature must be present, cover the document (intact: the digest over /ByteRange
matches) and be cryptographically valid (the CMS signature verifies with the signer's public key).
The trust chain is reported but not required: the test certificates come from a test CA.
Prints one JSON line per PDF; exit 0 when every PDF passes, 3 otherwise, 2 on usage errors.
Needs: pip install pyhanko
"""

import io
import json
import sys
from pathlib import Path


def check(pdf: Path) -> dict:
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    out = {"file": str(pdf), "signed": False, "intact": False, "valid": False, "trusted": False, "signer": ""}
    sigs = PdfFileReader(io.BytesIO(pdf.read_bytes())).embedded_signatures
    if not sigs:
        return out
    st = validate_pdf_signature(sigs[0])
    out.update(
        signed=True,
        intact=bool(st.intact),
        valid=bool(st.valid),
        trusted=bool(st.trusted),
        signer=st.signing_cert.subject.human_friendly,
        coverage=str(st.coverage),
    )
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    pdfs: list[Path] = []
    for a in map(Path, sys.argv[1:]):
        pdfs += sorted(a.rglob("*.pdf")) if a.is_dir() else [a]
    if not pdfs:
        print("no PDF found")
        return 3
    ok = True
    for p in pdfs:
        r = check(p)
        print(json.dumps(r, ensure_ascii=False))
        ok &= r["signed"] and r["intact"] and r["valid"]
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
