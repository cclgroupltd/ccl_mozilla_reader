"""
Copyright 2024, CCL Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import json
import pathlib
import struct
import lz4.block

MAGIC = b"mozLz40\x00"


def decompress(compressed: bytes) -> bytes:
    if len(compressed) < len(MAGIC) + 4:
        raise ValueError("Data not long enough to contain header")

    if compressed[0:len(MAGIC)] != MAGIC:
        raise ValueError(f"Magic doesn't match. Expected: {MAGIC.hex(" ", 1)}; got: {compressed[0:len(MAGIC)].hex(" ", 1)}")

    length_offset = len(MAGIC)
    decompressed_length, = struct.unpack("<I", compressed[length_offset: length_offset + 4])

    data_start_offset = length_offset + 4
    decompressed = lz4.block.decompress(compressed[data_start_offset:], decompressed_length)

    return decompressed


def load_jsonlz4(path: pathlib.Path):
    with path.open("rb") as f:
        data = f.read()

    return json.loads(decompress(data))

# if __name__ == '__main__':
#     with open(sys.argv[1], "rb") as f:
#         data = f.read()
#     print(decompress(data))
