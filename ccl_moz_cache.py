import dataclasses
import datetime
import enum
import os
import pathlib
import sys
import typing
import struct
import collections.abc
import io


EPOCH = datetime.datetime(1970, 1, 1)

def decode_unix_time(seconds: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(seconds=seconds)


class BinaryReader:
    """
    Utility class which wraps a BinaryIO and provides reading for a bunch of data types we need to do the cache stuff
    """
    def __init__(self, stream: typing.BinaryIO):
        self._stream = stream
        self._closed = False

    @classmethod
    def from_bytes(cls, buffer: bytes):
        return cls(io.BytesIO(buffer))

    def close(self):
        self._stream.close()
        self._closed = True

    def __enter__(self) -> "BinaryReader":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, offset: int, whence: int) -> int:
        return self._stream.seek(offset, whence)

    def read_raw(self, count: int) -> bytes:
        start_offset = self._stream.tell()
        result = self._stream.read(count)
        if len(result) != count:
            raise ValueError(
                f"Could not read all of the data starting at {start_offset}. Expected: {count}; got {len(result)}")
        return result

    def read_utf8(self, count: int) -> str:
        return self.read_raw(count).decode("utf-8")

    def read_int16(self) -> int:
        raw = self.read_raw(2)
        return struct.unpack(">h", raw)[0]

    def read_int32(self) -> int:
        raw = self.read_raw(4)
        return struct.unpack(">i", raw)[0]

    def read_int64(self) -> int:
        raw = self.read_raw(8)
        return struct.unpack(">q", raw)[0]

    def read_uint16(self) -> int:
        raw = self.read_raw(2)
        return struct.unpack(">H", raw)[0]

    def read_uint32(self) -> int:
        raw = self.read_raw(4)
        return struct.unpack(">I", raw)[0]

    def read_uint64(self) -> int:
        raw = self.read_raw(8)
        return struct.unpack(">Q", raw)[0]

    def read_single(self) -> float:
        raw = self.read_raw(4)
        return struct.unpack(">f", raw)[0]

    def read_double(self) -> float:
        raw = self.read_raw(8)
        return struct.unpack(">d", raw)[0]

    def read_datetime(self) -> datetime.datetime:
        return decode_unix_time(self.read_uint32())

    def can_read(self, count) -> bool:
        tmp = self._stream.read(count)
        self._stream.seek(-len(tmp), os.SEEK_CUR)
        if len(tmp) != count:
            return False
        return True

    @property
    def is_closed(self) -> bool:
        return self._closed


class CacheEntryContentType(enum.IntEnum):
    # netwerk/cache2/nsICacheEntry.idl
    UNKNOWN = 0
    OTHER = 1
    JAVASCRIPT = 2
    IMAGE = 3
    MEDIA = 4
    STYLESHEET = 5
    WASM = 6


@dataclasses.dataclass(frozen=True)
class CacheIndexHeader:
    # /netwerk/cache2/CacheIndex.h
    version: int
    last_write_timestamp: datetime.datetime
    is_dirty: int
    kb_written: int

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        version = reader.read_uint32()
        last_write = reader.read_datetime()
        is_dirty = reader.read_uint32()
        kb_written = reader.read_uint32()

        return CacheIndexHeader(version, last_write, is_dirty, kb_written)


@dataclasses.dataclass(frozen=True)
class CacheIndexRecord:
    SIZE = 41

    # /netwerk/cache2/CacheIndex.h
    sha1_hash: str
    frecency: float  # I think float even though source says int - it's a float in other databases
    origin_attrs_hash: int
    onStartTime: int
    onStopTime: int
    content_type: CacheEntryContentType  # todo: resolve this enum
    flags: int

    @property
    def file_size_kb(self):
        return self.flags & 0x00ffffff

    @property
    def is_initialized(self) -> bool:
        return self.flags & 0x80000000 != 0

    @property
    def is_anonymous(self) -> bool:
        return self.flags & 0x40000000 != 0

    @property
    def is_removed(self) -> bool:
        return self.flags & 0x20000000 != 0

    @property
    def is_dirty(self) -> bool:
        return self.flags & 0x10000000 != 0

    @property
    def is_fresh(self) -> bool:
        return self.flags & 0x08000000 != 0

    @property
    def is_pinned(self) -> bool:
        return self.flags & 0x04000000 != 0

    @property
    def has_alt_data(self) -> bool:
        return self.flags & 0x02000000 != 0

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        sha1 = reader.read_raw(20).hex()
        frecency = reader.read_single()
        origin_attrs_hash = reader.read_int64()
        on_start = reader.read_uint16()
        on_stop = reader.read_uint16()
        content_type = CacheEntryContentType(reader.read_raw(1)[0])
        flags = reader.read_uint32()

        return cls(sha1, frecency, origin_attrs_hash, on_start, on_stop, content_type, flags)


class CacheIndexFile:
    # /netwerk/cache2/CacheIndex.h
    def __init__(self, header: CacheIndexHeader, records: collections.abc.Iterable[CacheIndexRecord]):
        self._header = header
        self._records = tuple(records)

    @classmethod
    def from_file(cls, path: pathlib.Path):
        with BinaryReader(path.open("rb")) as reader:
            header = CacheIndexHeader.from_reader(reader)
            records = []
            while True:
                if not reader.can_read(CacheIndexRecord.SIZE):
                    break
                records.append(CacheIndexRecord.from_reader(reader))

        return CacheIndexFile(header, records)

    @property
    def header(self):
        return self._header

    @property
    def records(self):
        yield from self._records


if __name__ == '__main__':
    index = CacheIndexFile.from_file(pathlib.Path(sys.argv[1]))

    print(index.header)
    for rec in index.records:
        print(rec)