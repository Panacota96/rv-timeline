"""Unpacks a golden case archive stored as base64 text (case-by-<profile>.zip.b64) into a folder.

Stored as text, not as a .zip, so the archive survives packaging steps that refuse nested zip files (skill bundles)
and git line-ending normalisation. Standard library only. Usage: python tests/golden/unpack.py <archive.zip.b64> <dest>
"""

import base64
import io
import sys
import zipfile


def unpack(archive: str, dest: str) -> None:
    with open(archive, encoding="ascii") as fh:
        data = base64.b64decode("".join(fh.read().split()))
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(dest)


if __name__ == "__main__":
    unpack(sys.argv[1], sys.argv[2])
