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
import datetime
import enum
import math
import os
import pathlib
import re
import types
import typing
import struct
import collections.abc
import io
import email
import collections.abc as col_abc

from .common import KeySearch, is_keysearch_hit


__version__ = "0.2"
__description__ = "Library for reading Mozilla Firefox Cache (v2 Entries version)"
__contact__ = "Alex Caithness"


EPOCH = datetime.datetime(1970, 1, 1)


def decode_unix_time(seconds: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(seconds=seconds)


def parse_http_headers(raw_headers: str):
    if not raw_headers:
        return "", "", {}
    split = raw_headers.splitlines(keepends=False)
    version, status = split[0].strip().split(None, 1)
    remains = "\r\n".join(split[1:])
    message = email.message_from_string(remains)
    headers = types.MappingProxyType(dict(message.items()))

    return version, status, headers


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

    def read_until_end(self) -> bytes:
        return self._stream.read()

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


class CacheKey:
    # netwerk/cache2/CacheFileUtils.cpp
    def __init__(self, raw_key: str):
        self._raw_key = raw_key
        self._is_anon = False
        self._url = None
        self._sync_attributes_with_private_browsing = False
        self._id_enhance = None
        self._origin_suffix = None
        self._read_tags()

    def __repr__(self):
        return f"<CacheKey {self._raw_key}>"

    def __eq__(self, other):
        if not isinstance(other, CacheKey):
            raise TypeError("Can only compare with another CacheKey")
        return self._raw_key == other.raw_key

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return self._raw_key.__hash__()

    @property
    def url(self):
        return self._url

    @property
    def raw_key(self):
        return self._raw_key

    @staticmethod
    def _read_value(s: io.BytesIO) -> str:
        out = io.BytesIO()
        while True:
            c = s.read(1)
            if not c:
                raise ValueError("unexpected end of key while reading a value")
            if c == b",":
                comma_check = s.read(1)
                if not comma_check:
                    raise ValueError("unexpected end of key while reading a value")
                elif comma_check == b",":  # escaped comma
                    out.write(c)
                else:
                    # back past the check and the original comma as the consumer expects it
                    s.seek(-2, os.SEEK_CUR)
                    break
            else:
                out.write(c)

        result = out.getvalue()
        out.close()
        return result.decode("ascii")

    def _read_tags(self):
        key = io.BytesIO(self._raw_key.encode("ascii"))  # need to do negative seeks
        while True:
            tag = key.read(1)
            if not tag:
                break
            elif tag == b":":  # Final tag URL follows
                self._url = key.read().decode("ascii")
                break
            elif tag == b"O":  # origin attributes
                self._origin_suffix = self._read_value(key)
            elif tag == b"p":
                self._sync_attributes_with_private_browsing = True
            elif tag == b"a":
                self._is_anon = True
            elif tag == b"~":
                self._id_enhance = self._read_value(key)
            else:
                raise ValueError(f"Unexpected tag in cache key: {tag}")

            comma = key.read(1)
            if comma != b",":
                raise ValueError(f"Expected a comma after a tag in a cache key")

            # tags b and i are related to an old format which for now we count as invalid


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
    content_type: CacheEntryContentType
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


@dataclasses.dataclass(frozen=True)
class CacheFileMetadata:
    # /netwerk/cache2/CacheFileMetadata.cpp - CacheFileMetadata::CalcMetadataSize gives a good
    # overview of the metadata format, plus the CacheFileMetadataHeader class in the same source
    # file

    # I'm not going to have a separate CacheFileMetadataHeader class as it's just an extra level
    # for the caller to navigate with no obvious benefit that I can see.

    # This is kCacheEntryVersion 3 which is current at this point.

    metadata_hash: int
    chunk_hashes: tuple[int, ...]
    version: int
    fetch_count: int
    last_fetched: datetime.datetime
    last_modified: datetime.datetime
    frecency: float
    expiration: datetime.datetime
    key_size: int
    flags: int  # only flag is at 0x1 which is "pinned"
    key: CacheKey
    offset: int
    elements: typing.Mapping  # provide an overlay for the stuff in here within the class

    @classmethod
    def from_reader(cls, reader: BinaryReader, chunk_count: int):
        metadata_hash = reader.read_uint32()
        chunk_hashes = tuple(reader.read_uint16() for _ in range(chunk_count))  # currently I believe there can only be 1 or 0
        version = reader.read_uint32()

        if version != 3:
            raise ValueError(f"Unsupported CacheFileMetadata version. Expected: 3; got: {version}")

        fetch_count = reader.read_uint32()
        last_fetched = reader.read_datetime()
        last_modified = reader.read_datetime()
        frecency = reader.read_single()
        expiration_time = reader.read_datetime()
        key_size = reader.read_uint32()
        flags = reader.read_uint32()

        key = reader.read_utf8(key_size + 1)  # + 1 as it should end with \0 which we can check
        if key.endswith("\0"):
            key = key[0:-1]
        else:
            raise ValueError("Invalid metadata format (key does not end with \\0)")

        elements_raw = reader.read_until_end()
        offset, = struct.unpack(">I", elements_raw[-4:])
        elements_raw = elements_raw[0:-4]
        if elements_raw.endswith(b"\x00"):
            elements_raw = elements_raw[0:-1]  # check the final delimiting 0x00 is there and remove it
        else:
            raise ValueError("Invalid metadata format (missing final delimiting 0x00)")

        elements_raw_split = elements_raw.split(b"\x00")
        if len(elements_raw_split) % 2 != 0:
            raise ValueError("Invalid metadata format (odd number of elements)")

        elements = types.MappingProxyType({
            elements_raw_split[i].decode("ascii").lower(): elements_raw_split[i + 1].decode("ascii")
            for i in range(0, len(elements_raw_split), 2)
        })

        return cls(
            metadata_hash, chunk_hashes, version, fetch_count,
            last_fetched, last_modified, frecency, expiration_time,
            key_size, flags, CacheKey(key), offset, elements
        )


class CacheFile:
    # Data followed by metadata. Metadata ends with an offset to the start of the metadata which we can
    # treat as the length of the cached resource
    # /netwerk/cache2/CacheFileMetadata.cpp - CacheFileMetadata::CalcMetadataSize gives a good
    # overview of the metadata format, plus the CacheFileMetadataHeader class in the same source
    # file

    _CHUNK_SIZE = 256 * 1024  # /netwerk/cache2/CacheFileChunk.h

    def __init__(self, path: pathlib.Path, metadata, cached_resource_data: bytes):
        self._path = path
        self._metadata = metadata
        self._data = cached_resource_data
        self._process_headers()

    def _process_headers(self):
        header = self.metadata.elements.get("original-response-headers") or self.metadata.elements.get("response-head")
        if header:
            version, status, fields = parse_http_headers(header)
            self._header = fields
        else:
            self._header = types.MappingProxyType({})

    @property
    def header_attributes(self) -> col_abc.Iterable[tuple[str, str]]:
        #yield from self._header.keys()
        yield from self._header.items()

    def has_header_attribute(self, attribute: str):
        return attribute.lower() in self._header

    def get_header_attribute(self, attribute: str):
        return self._header.get(attribute.lower())

    @classmethod
    def from_file(cls, path: pathlib.Path):
        with BinaryReader(path.open("rb")) as reader:
            # read offset for metadata, and implicitly the data length
            reader.seek(-4, os.SEEK_END)
            offset = reader.read_uint32()
            reader.seek(offset, os.SEEK_SET)
            chunk_count = math.ceil(offset / CacheFile._CHUNK_SIZE)
            metadata = CacheFileMetadata.from_reader(reader, chunk_count)

            reader.seek(0, os.SEEK_SET)
            data = reader.read_raw(offset)

        return cls(path, metadata, data)

    @staticmethod
    def read_metadata(path: pathlib.Path) -> CacheFileMetadata:
        with BinaryReader(path.open("rb")) as reader:
            # read offset for metadata, and implicitly the data length
            reader.seek(-4, os.SEEK_END)
            offset = reader.read_uint32()
            reader.seek(offset, os.SEEK_SET)
            chunk_count = math.ceil(offset / CacheFile._CHUNK_SIZE)
            metadata = CacheFileMetadata.from_reader(reader, chunk_count)

        return metadata

    @property
    def path(self) -> pathlib.Path:
        return self._path

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def metadata(self) -> CacheFileMetadata:
        return self._metadata


class MozillaCache:
    _ENTRIES_FOLDER_NAME = "entries"

    def __init__(self, cache_folder: pathlib.Path):
        if not cache_folder.is_dir():
            raise NotADirectoryError("cache_folder does not exist or it not a directory")
        self._cache_folder = cache_folder
        self._precached_metadata: typing.Optional[dict[CacheKey, tuple[pathlib.Path, CacheFileMetadata]]] = None
        self._url_key_lookup: typing.Optional[dict[str, list[CacheKey]]] = None

    def _make_url_key_lookup(self):
        if self._precached_metadata is None:
            raise ValueError("_precached_metadata not set")
        # We make a URL lookup as cache keys are unique based on the whole key, but with partitioning etc.
        # it is possible for the same *URL* to be duplicated, and that's what consumers will want to use
        # almost every time.
        self._url_key_lookup = {}
        for key in self._precached_metadata.keys():
            self._url_key_lookup.setdefault(key.url, [])
            self._url_key_lookup[key.url].append(key)

    def _precache_metadata(self):
        if self._precached_metadata is not None:
            raise ValueError("Precached metadata is already set")
        self._precached_metadata = {}
        for file in (self._cache_folder / MozillaCache._ENTRIES_FOLDER_NAME).iterdir():
            if not file.is_file():
                continue

            metadata = CacheFile.read_metadata(file)
            if metadata.key in self._precached_metadata:
                raise KeyError("Duplicate key (shouldn't be possible)")

            self._precached_metadata[metadata.key] = file, metadata

    def iter_metadata(self, *, url: typing.Optional[KeySearch]=None):
        self._precache_metadata()
        self._make_url_key_lookup()

        for file, metadata in self._precached_metadata.values():
            yield metadata

    @staticmethod
    def _check_attributes(cache_file: CacheFile, **kwargs):
        for att_name, test_value in kwargs.items():
            att_name = att_name.replace("_", "-").lower()
            has_att = cache_file.has_header_attribute(att_name)

            if isinstance(test_value, bool):
                return not (test_value ^ has_att)

            if not has_att:
                return False

            if not is_keysearch_hit(test_value, cache_file.get_header_attribute(att_name)):
                return False

        return True

    def _iter_cache_all(self, **kwargs):
        for file in (self._cache_folder / MozillaCache._ENTRIES_FOLDER_NAME).iterdir():
            if not file.is_file():
                continue
            cache_file = CacheFile.from_file(file)
            if kwargs and not self._check_attributes(cache_file, **kwargs):
                continue

            yield cache_file

    def _iter_cache_filtered(self, search_url: KeySearch, **kwargs):
        if self._precached_metadata is None:
            self._precache_metadata()
            self._make_url_key_lookup()

        if isinstance(search_url, str):
            for key in self._url_key_lookup.get(search_url, []):
                file, meta = self._precached_metadata[key]
                cache_file = CacheFile.from_file(file)
                if kwargs and not self._check_attributes(cache_file, **kwargs):
                    continue
                yield cache_file
        elif isinstance(search_url, col_abc.Collection):
            for url in search_url:
                for key in self._url_key_lookup.get(url, []):
                    file, meta = self._precached_metadata[key]
                    cache_file = CacheFile.from_file(file)
                    if kwargs and not self._check_attributes(cache_file, **kwargs):
                        continue
                    yield cache_file
        elif isinstance(search_url, re.Pattern):
            for url, keys in self._url_key_lookup.items():
                if search_url.search(url) is not None:
                    for key in keys:
                        file, meta = self._precached_metadata[key]
                        cache_file = CacheFile.from_file(file)
                        if kwargs and not self._check_attributes(cache_file, **kwargs):
                            continue
                        yield cache_file
        elif isinstance(search_url, col_abc.Callable):
            for url, keys in self._url_key_lookup.items():
                if search_url(url):
                    for key in keys:
                        file, meta = self._precached_metadata[key]
                        cache_file = CacheFile.from_file(file)
                        if kwargs and not self._check_attributes(cache_file, **kwargs):
                            continue
                        yield cache_file
        else:
            raise TypeError(f"Unexpected type: {type(search_url)} (expects: {KeySearch})")

    def iter_cache(self, *, url: typing.Optional[KeySearch]=None, **kwargs):
        """
        Iterates cache records for this cache.

        :param url: a URL to search for. This can be one of: a single string; a collection of strings;
        a regex pattern; a function that takes a string (each host) and returns a bool; or None (the
        default) in which case all records are considered.
        :param kwargs: further keyword arguments are used to search based upon header fields. The
        keyword should be the header field name, with underscores replacing hyphens (e.g.,
        content-encoding, becomes content_encoding). The value should be one of: a Boolean (in which
        case only records with this field present will be included if True, and vice versa); a single
        string; a collection of strings; a regex pattern; a function that takes a string (the value)
        and returns a bool.
        """

        if url is None:
            yield from self._iter_cache_all(**kwargs)
        else:
            yield from self._iter_cache_filtered(url, **kwargs)


