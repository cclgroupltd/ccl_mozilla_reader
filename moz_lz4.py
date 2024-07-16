import json
import pathlib
import sys
import typing
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
