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

import dataclasses
import pathlib
import datetime
import struct
import typing

EPOCH = datetime.datetime(1970, 1, 1)


def parse_unix_microseconds(microseconds: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(microseconds=microseconds)


def read_unix_microseconds(stream: typing.BinaryIO) -> datetime.datetime:
    timestamp_raw = stream.read(8)
    if len(timestamp_raw) != 8:
        raise ValueError("Couldn't get enough data to read the timestamp")
    return parse_unix_microseconds(struct.unpack(">Q", timestamp_raw)[0])


def read_cstring(stream: typing.BinaryIO):
    length_raw = stream.read(4)
    if len(length_raw) != 4:
        raise ValueError("Couldn't get enough data to read the string length")
    length, = struct.unpack(">I", length_raw)
    string_raw = stream.read(length)
    if len(string_raw) != length:
        raise ValueError("Couldn't get enough data to read the string data")
    return string_raw.decode("utf-8")


@dataclasses.dataclass(frozen=True)
class MetadataV2:
    # dom/quota/ActorsParent.cpp - StorageOperationBase::GetDirectoryMetadata2
    # Strings are 32bit length, followed by the string - /xpcom/io/nsBinaryStream.cpp - ReadCString
    timestamp: datetime.datetime
    persisted: bool
    suffix: typing.Optional[str]
    group: typing.Optional[str]
    origin: typing.Optional[str]
    is_app: bool

    @classmethod
    def from_file(cls, path: pathlib.Path):
        with path.open("rb") as f:
            timestamp = read_unix_microseconds(f)
            persisted = f.read(1)[0] != 0
            reserved_1_and_2 = f.read(8)
            suffix = read_cstring(f)
            group = read_cstring(f)
            origin = read_cstring(f)
            is_app = f.read(1)[0] != 0

        return cls(timestamp, persisted, suffix, group, origin, is_app)