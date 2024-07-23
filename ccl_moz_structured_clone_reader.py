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
import os
import re
import struct
import sys
import types
import typing

__version__ = "0.1"
__description__ = "Library for reading Mozilla Firefox Structured Clone data (used to store objects in IndexedDB)"
__contact__ = "Alex Caithness"


# /js/src/vm/StructuredClone.cpp and in particular JSStructuredCloneWriter::startWrite(HandleValue v)
# also: dom/base/StructuredCloneHolder.cpp and in particular: StructuredCloneHolder::CustomWriteHandler
# also: dom/indexedDB/IndexedDatabase.cpp


class EndOfKeysException(Exception):
    ...  # thrown when an end of keys tag is encountered to be handled by the collection readers


class StructuredCloneReaderError(Exception):
    ...

# This causes issues when repr'ing
# class JsArray:
#     """
#     A wrapper around a dict to act like sparse JavaScript array
#     """
#     def __init__(self, initial_contents: dict[int, typing.Any], default):
#         if any(not isinstance(x, int) for x in initial_contents.keys()):
#             raise TypeError("All keys in a JsArray must be of type int")
#         self._backing = dict(initial_contents)
#         self._max_index = -1
#         if self._backing:
#             self._max_index = max(self._backing.keys())
#         self._default = default
#         self._frozen = False
#
#     def freeze(self):
#         self._frozen = True
#
#     def __len__(self):
#         return self._max_index + 1
#
#     def __iter__(self):
#         for i in range(len(self)):
#             yield self._backing[i] if i in self._backing else self._default
#
#     def __getitem__(self, item: int):
#         self._backing.get(item, self._default)
#
#     def __setitem__(self, key: int, value: typing.Any):
#         if self._frozen:
#             raise ValueError("Array is frozen")
#         if not isinstance(key, int):
#             raise TypeError("All keys in a JsArray must be of type int")
#         if key > self._max_index:
#             self._max_index = key
#
#         self._backing[key] = value
#
#     def __repr__(self):
#         item_strings = ", ".join(repr(x) if x is not self else "[...]" for x in self)
#         return f"[{item_strings}]"


class ScalarType(enum.IntEnum):
    Int8 = 0
    Uint8 = enum.auto()
    Int16 = enum.auto()
    Uint16 = enum.auto()
    Int32 = enum.auto()
    Uint32 = enum.auto()
    Float32 = enum.auto()
    Float64 = enum.auto()

    # Special type that is a uint8_t, but assignments are clamped to [0, 256).
    # Treat the raw data type as a uint8_t.
    Uint8Clamped = enum.auto()
    BigInt64 = enum.auto()
    BigUint64 = enum.auto()

    # Types that don't have their own TypedArray equivalent, for now. E.g. DataView
    MaxTypedArrayViewType = enum.auto()
    Int64 = enum.auto()
    Simd128 = enum.auto()

    def data_to_array(self, data: bytes, element_count: int, start_offset: int):
        if len(data) == 0:
            return []
        element_size = _SCALAR_TYPE_ELEMENT_LENGTH[self]
        if (len(data) - start_offset) / element_size < element_count:
            raise ValueError(
                f"Invalid length for data to be converted to a typed array of {self.name} of length {element_count}")

        # special case for Uint8Clamped as it's usually just a byte array
        if self == self.Uint8Clamped:
            return data[start_offset:start_offset + element_count]

        struct_fmt = f"<{element_count}{_SCALAR_TYPE_STRUCT_CODE[self]}"
        return struct.unpack(struct_fmt, data[start_offset:(element_count * element_size) + start_offset])


_SCALAR_TYPE_ELEMENT_LENGTH = {
    ScalarType.Int8: 1,
    ScalarType.Uint8: 1,
    ScalarType.Int16: 2,
    ScalarType.Uint16: 2,
    ScalarType.Int32: 4,
    ScalarType.Uint32: 4,
    ScalarType.Float32: 4,
    ScalarType.Float64: 8,
    ScalarType.Uint8Clamped: 1,
    ScalarType.BigInt64: 8,
    ScalarType.BigUint64: 8,
}

_SCALAR_TYPE_STRUCT_CODE = {
    ScalarType.Int8: "b",
    ScalarType.Uint8: "B",
    ScalarType.Int16: "h",
    ScalarType.Uint16: "H",
    ScalarType.Int32: "i",
    ScalarType.Uint32: "I",
    ScalarType.Float32: "f",
    ScalarType.Float64: "d",
    #ScalarType.Uint8Clamped: 1,  just return bytes
    ScalarType.BigInt64: "q",
    ScalarType.BigUint64: "Q",
}


class StructuredDataType(enum.IntEnum):
    # For values before END_OF_BUILTIN_TYPES:
    # js/src/vm/StructuredClone.cpp
    # After that:
    # dom/base/StructuredCloneTags.h

    FLOAT_MAX = 0xFFF00000
    HEADER = 0xFFF10000
    NULL = 0xFFFF0000
    UNDEFINED = enum.auto()
    BOOLEAN = enum.auto()
    INT32 = enum.auto()
    STRING = enum.auto()
    DATE_OBJECT = enum.auto()
    REGEXP_OBJECT = enum.auto()
    ARRAY_OBJECT = enum.auto()
    OBJECT_OBJECT = enum.auto()
    ARRAY_BUFFER_OBJECT_V2 = enum.auto(),  # Old version, for backwards compatibility.
    BOOLEAN_OBJECT = enum.auto()
    STRING_OBJECT = enum.auto()
    NUMBER_OBJECT = enum.auto()
    BACK_REFERENCE_OBJECT = enum.auto()
    DO_NOT_USE_1 = enum.auto(),  # Required for backwards compatibility
    DO_NOT_USE_2 = enum.auto(),  # Required for backwards compatibility
    TYPED_ARRAY_OBJECT_V2 = enum.auto(),  # Old version, for backwards compatibility.
    MAP_OBJECT = enum.auto()
    SET_OBJECT = enum.auto()
    END_OF_KEYS = enum.auto()
    DO_NOT_USE_3 = enum.auto(),  # Required for backwards compatibility
    DATA_VIEW_OBJECT_V2 = enum.auto(),  # Old version, for backwards compatibility.
    SAVED_FRAME_OBJECT = enum.auto()

    # No new tags before principals.
    JSPRINCIPALS = enum.auto()
    NULL_JSPRINCIPALS = enum.auto()
    RECONSTRUCTED_SAVED_FRAME_PRINCIPALS_IS_SYSTEM = enum.auto()
    RECONSTRUCTED_SAVED_FRAME_PRINCIPALS_IS_NOT_SYSTEM = enum.auto()

    SHARED_ARRAY_BUFFER_OBJECT = enum.auto()
    SHARED_WASM_MEMORY_OBJECT = enum.auto()

    BIGINT = enum.auto()
    BIGINT_OBJECT = enum.auto()

    ARRAY_BUFFER_OBJECT = enum.auto()
    TYPED_ARRAY_OBJECT = enum.auto()
    DATA_VIEW_OBJECT = enum.auto()

    ERROR_OBJECT = enum.auto()

    RESIZABLE_ARRAY_BUFFER_OBJECT = enum.auto()
    GROWABLE_SHARED_ARRAY_BUFFER_OBJECT = enum.auto()

    TYPED_ARRAY_V1_MIN = 0xFFFF0100
    TYPED_ARRAY_V1_INT8 = TYPED_ARRAY_V1_MIN + ScalarType.Int8
    TYPED_ARRAY_V1_UINT8 = TYPED_ARRAY_V1_MIN + ScalarType.Uint8
    TYPED_ARRAY_V1_INT16 = TYPED_ARRAY_V1_MIN + ScalarType.Int16
    TYPED_ARRAY_V1_UINT16 = TYPED_ARRAY_V1_MIN + ScalarType.Uint16
    TYPED_ARRAY_V1_INT32 = TYPED_ARRAY_V1_MIN + ScalarType.Int32
    TYPED_ARRAY_V1_UINT32 = TYPED_ARRAY_V1_MIN + ScalarType.Uint32
    TYPED_ARRAY_V1_FLOAT32 = TYPED_ARRAY_V1_MIN + ScalarType.Float32
    TYPED_ARRAY_V1_FLOAT64 = TYPED_ARRAY_V1_MIN + ScalarType.Float64
    # BigInt64 and BigUint64 are not supported in the v1 format.
    TYPED_ARRAY_V1_UINT8_CLAMPED = TYPED_ARRAY_V1_MIN + ScalarType.Uint8Clamped
    # BigInt64 and BigUint64 are not supported in the v1 format.

    # Define a separate range of numbers for Transferable-only tags, since
    # they are not used for persistent clone buffers and therefore do not
    # require bumping JS_STRUCTURED_CLONE_VERSION.
    TRANSFER_MAP_HEADER = 0xFFFF0200
    TRANSFER_MAP_PENDING_ENTRY = enum.auto()
    TRANSFER_MAP_ARRAY_BUFFER = enum.auto()
    TRANSFER_MAP_STORED_ARRAY_BUFFER = enum.auto()
    TRANSFER_MAP_END_OF_BUILTIN_TYPES = enum.auto()

    END_OF_BUILTIN_TYPES = enum.auto()  # Any new builtin types must be added before this

    DOM_BASE = 0xFFFF8000  # JS_SCTAG_USER_MIN defined in js/public/StructuredClone.h
    DOM_BLOB = enum.auto()
    # This tag is obsolete and exists only for backwards compatibility with existing IndexedDB databases.
    DOM_FILE_WITHOUT_LASTMODIFIEDDATE = enum.auto()
    DOM_FILELIST = enum.auto()
    DOM_MUTABLEFILE = enum.auto()
    DOM_FILE = enum.auto()
    DOM_WASM_MODULE = enum.auto()
    DOM_IMAGEDATA = enum.auto()
    DOM_DOMPOINT = enum.auto()
    DOM_DOMPOINTREADONLY = enum.auto()
    DOM_CRYPTOKEY = enum.auto()
    DOM_NULL_PRINCIPAL = enum.auto()
    DOM_SYSTEM_PRINCIPAL = enum.auto()
    DOM_CONTENT_PRINCIPAL = enum.auto()
    DOM_DOMQUAD = enum.auto()
    DOM_RTCCERTIFICATE = enum.auto()
    DOM_DOMRECT = enum.auto()
    DOM_DOMRECTREADONLY = enum.auto()
    DOM_EXPANDED_PRINCIPAL = enum.auto()
    DOM_DOMMATRIX = enum.auto()
    DOM_URLSEARCHPARAMS = enum.auto()
    DOM_DOMMATRIXREADONLY = enum.auto()
    DOM_DOMEXCEPTION = enum.auto()
    EMPTY_SLOT_9 = enum.auto()
    DOM_STRUCTUREDCLONETESTER = enum.auto()
    DOM_FILESYSTEMHANDLE = enum.auto()
    DOM_FILESYSTEMFILEHANDLE = enum.auto()
    DOM_FILESYSTEMDIRECTORYHANDLE = enum.auto()

    # --------------------------------------------------------------------------
    # All the following tags are not written to disk and they are not used by
    # IndexedDB directly or via
    # StructuredCloneHolder::{Read,Write}FullySerializableObjects. In theory they
    # can be 'less' stable.
    DOM_IMAGEBITMAP = enum.auto()
    DOM_MAP_MESSAGEPORT = enum.auto()
    DOM_FORMDATA = enum.auto()
    DOM_CANVAS = enum.auto()
    DOM_DIRECTORY = enum.auto()
    DOM_INPUTSTREAM = enum.auto()
    DOM_STRUCTURED_CLONE_HOLDER = enum.auto()
    DOM_BROWSING_CONTEXT = enum.auto()
    DOM_CLONED_ERROR_OBJECT = enum.auto()
    DOM_READABLESTREAM = enum.auto()
    DOM_WRITABLESTREAM = enum.auto()
    DOM_TRANSFORMSTREAM = enum.auto()
    DOM_VIDEOFRAME = enum.auto()
    DOM_ENCODEDVIDEOCHUNK = enum.auto()
    DOM_AUDIODATA = enum.auto()
    DOM_ENCODEDAUDIOCHUNK = enum.auto()


class CryptoType(enum.IntEnum):
    AES = 0
    HMAC = enum.auto()
    RSA = enum.auto()
    EC = enum.auto()
    KDF = enum.auto()
    ED = enum.auto()


@dataclasses.dataclass(frozen=True)
class Pair:
    data: int
    tag: StructuredDataType | int

    def __post_init__(self):
        if self.data < 0 or self.tag < 0 or self.data > 0xffffffff or self.tag > 0xffffffff:
            raise ValueError("data and tag must be in the range of 0-0xffffffff")

    def to_double(self):
        int64_value = (self.tag << 32) | self.data
        buff = struct.pack(">Q", int64_value)
        return struct.unpack(">d", buff)[0]


class _Undefined:
    def __bool__(self):
        return False

    def __eq__(self, other):
        if isinstance(other, _Undefined):
            return True
        return False

    def __repr__(self):
        return "<Undefined>"

    def __str__(self):
        return "<Undefined>"


# @dataclasses.dataclass
# class BackReference:
#     index: int


@dataclasses.dataclass(frozen=True)
class Blob:
    index: int
    size: int
    mimetype: str


@dataclasses.dataclass
class File:
    index: int
    size: int
    mimetype: str
    last_modified: typing.Optional[datetime.datetime]
    name: str


@dataclasses.dataclass(frozen=True)
class CryptoKey:
    sym: typing.Optional[bytes]
    priv: typing.Optional[bytes]
    pub: typing.Optional[bytes]
    parameters: typing.Mapping


def unsparse_array(result: list, length: int, sparse_dict: dict[int, typing.Any], default) -> list:
    if len(sparse_dict) == 0:
        return []

    if any(not isinstance(x, int) or x < 0 for x in sparse_dict.keys()):
        raise ValueError("all dict keys must be positive ints for a sparse array")

    if max(sparse_dict.keys()) >= length:
        raise ValueError("length is too low for the maximum key")

    result.clear()
    result.extend(default for _ in range(length))
    for k, v in sparse_dict.items():
        result[k] = v

    return result


class StructuredCloneReader:
    UNDEFINED = _Undefined()

    def __init__(self, stream: typing.BinaryIO):
        self._f = stream

        header_pair = self._read_pair()
        if header_pair.tag != StructuredDataType.HEADER:
            raise StructuredCloneReaderError("Structured clone data does not start with HEADER")

        self._scope = header_pair.data
        self._flattened_objects = []

    def _read_raw(self, length):
        """
        It's a read but checks for the right number of bytes read before returning.
        Prefer this over a basic call to the stream's read function in most cases.
        It also returns the starting offset of the read in case we need that.

        :param length:
        :return: a tuple of the start offset for the read and the data read
        """
        start_offset = self._f.tell()
        data = self._f.read(length)
        if len(data) != length:
            raise StructuredCloneReaderError(
                f"Could not read enough data at {start_offset} (wanted: {length}; got: {len(data)}")
        return start_offset, data

    def _read_pair(self) -> Pair:
        _, buff = self._read_raw(8)
        data, tag = struct.unpack("<2I", buff)
        if tag < StructuredDataType.FLOAT_MAX:
            return Pair(data, tag)
        else:
            return Pair(data, StructuredDataType(tag))

    def _read_int(self) -> int:
        _, buff = self._read_raw(4)
        val, = struct.unpack("<i", buff)
        return val

    def _read_uint(self) -> int:
        _, buff = self._read_raw(4)
        val, = struct.unpack("<I", buff)
        return val

    def _read_long(self) -> int:
        _, buff = self._read_raw(8)
        val, = struct.unpack("<q", buff)
        return val

    def _read_ulong(self) -> int:
        _, buff = self._read_raw(8)
        val, = struct.unpack("<Q", buff)
        return val

    def _read_double(self) -> float:
        _, buff = self._read_raw(8)
        val, = struct.unpack("<d", buff)
        return val

    def read_structuredclonereader_string(self):
        # from dom/indexedDB/IndexedDatabase.cpp used by some of the non-builtin types
        string_length = self._read_uint()
        self._align()
        _, raw = self._read_raw(string_length)
        self._align()
        return raw.decode("utf-8")

    def _read_string_internal(self, pair: Pair) -> str:
        if pair.tag not in (StructuredDataType.STRING, StructuredDataType.STRING_OBJECT):
            raise StructuredCloneReaderError(f"Unexpected tag in pair when reading string ({pair.tag})")

        # pair data contains the encoding and length
        if pair.data & 0x80000000 == 0:
            # encoding is utf-16, length is codepoints so must be doubled
            length = 2 * (pair.data & 0x7fffffff)
            _, buff = self._read_raw(length)
            return buff.decode("utf-16-le")
        else:
            # encoding is latin-1
            length = pair.data & 0x7fffffff
            _, buff = self._read_raw(length)
            return buff.decode("latin-1")

    def _read_string(self) -> str:
        pair = self._read_pair()
        return self._read_string_internal(pair)

    def _read_bigint(self, pair: Pair):
        if pair.tag not in (StructuredDataType.BIGINT, StructuredDataType.BIGINT_OBJECT):
            raise ValueError(f"Unexpected tag in pair when reading bigint ({pair.tag})")

        # length is expressed as a count of 64-bit allocations
        length = 8 * (pair.data & 0x7fffffff)
        is_negative = pair.data & 0x80000000 != 0
        _, raw = self._read_raw(length)
        # TODO: format into a bigint actually
        result = int.from_bytes(raw, "little", signed=False)
        if is_negative:
            result = -result
        return result

    def _read_array(self, pair: Pair) -> list:
        if pair.tag != StructuredDataType.ARRAY_OBJECT:
            raise ValueError("Pair tag isn't ARRAY_OBJECT")

        array_length = pair.data

        result = []
        sparse_dict = {}
        self._flattened_objects.append(result)  # must be added before population
        while True:
            try:
                key = self._read(StructuredDataType.INT32, StructuredDataType.END_OF_KEYS)
            except EndOfKeysException:
                break

            value = self._read()

            sparse_dict[key] = value
        return unsparse_array(result, array_length, sparse_dict, self.UNDEFINED)

    def _read_set(self, pair: Pair) -> set:
        if pair.tag != StructuredDataType.SET_OBJECT:
            raise ValueError("Pair tag isn't SET_OBJECT")

        result = set()
        self._flattened_objects.append(result)
        while True:
            try:
                value = self._read()
            except EndOfKeysException:
                break

            result.add(value)

        return result

    def _read_object(self, pair: Pair) -> dict[str, typing.Any]:
        if pair.tag != StructuredDataType.OBJECT_OBJECT:
            raise ValueError("Pair tag isn't OBJECT_OBJECT")

        result = {}
        self._flattened_objects.append(result)
        while True:
            try:
                key = self._read(
                    StructuredDataType.STRING,
                    StructuredDataType.STRING_OBJECT,
                    StructuredDataType.END_OF_KEYS)
            except EndOfKeysException:
                break

            value = self._read()
            result[key] = value

        return result

    def _read_map(self, pair: Pair):
        if pair.tag != StructuredDataType.MAP_OBJECT:
            raise ValueError("Pair tag isn't MAP_OBJECT")

        result = {}
        self._flattened_objects.append(result)
        while True:
            try:
                key = self._read()
            except EndOfKeysException:
                break

            value = self._read()
            result[key] = value

        return result

    def _read_typed_array(self, pair: Pair, is_v1_format: bool):
        if is_v1_format:
            raise ValueError("v1 typed arrays not implemented")

        if pair.tag == StructuredDataType.TYPED_ARRAY_OBJECT:
            # Array type is in the pair, length follows
            array_type = ScalarType(pair.data)
            element_count = self._read_ulong()
        elif pair.tag == StructuredDataType.TYPED_ARRAY_OBJECT_V2:
            # Length in the pair data, array type follows
            element_count = pair.data
            array_type = ScalarType(self._read_ulong())
        else:
            raise ValueError("Pair tag isn't TYPED_ARRAY_OBJECT or TYPED_ARRAY_OBJECT_V2")

        backing_buffer = self._read(
            StructuredDataType.BACK_REFERENCE_OBJECT,
            StructuredDataType.ARRAY_BUFFER_OBJECT,
            StructuredDataType.ARRAY_BUFFER_OBJECT_V2
        )

        if not isinstance(backing_buffer, bytes):
            # have to do this test in case it was a backreference that we got
            raise TypeError("typed array must be backed by a bytes object")

        start_offset = self._read_ulong()

        return array_type.data_to_array(backing_buffer, element_count,start_offset)

    def _read_blob(self, pair: Pair) -> Blob:
        # dom/indexedDB/IndexedDatabase.cpp - ReadBlobOrFile
        if pair.tag != StructuredDataType.DOM_BLOB:
            raise ValueError("Pair tag isn't DOM_BLOB")
        # the following reads are aligned:
        size = self._read_ulong()
        self._align()  # should be redundant really
        mime_type = self.read_structuredclonereader_string()

        # TODO: does this get backreferenced should it go into flattened objects?
        return Blob(pair.data, size, mime_type)

    def _read_file(self, pair: Pair):
        if pair.tag not in (StructuredDataType.DOM_FILE, StructuredDataType.DOM_FILE_WITHOUT_LASTMODIFIEDDATE):
            raise ValueError("Pair tag isn't DOM_FILE or DOM_FILE_WITHOUT_LASTMODIFIEDDATE")

        # the following reads are aligned:
        size = self._read_ulong()
        self._align()  # should be redundant really
        mime_type = self.read_structuredclonereader_string()

        if pair.tag == StructuredDataType.DOM_FILE:
            last_modified = self._read_double()
            last_modified = datetime.datetime(
                1970, 1, 1) + datetime.timedelta(milliseconds=last_modified)
        else:
            last_modified = None
        self._align()
        name = self.read_structuredclonereader_string()

        return File(pair.data, size, mime_type, last_modified, name)

    def read_cryptokey(self, pair: Pair):
        if pair.tag != StructuredDataType.DOM_CRYPTOKEY:
            raise ValueError("Pair tag isn't DOM_CRYPTOKEY")
        # dom/crypto/CryptoKey.cpp - CryptoKey::ReadStructuredClone
        version = self._read_uint()
        attributes = self._read_uint()  # todo: parse flags

        if version != 1:
            raise StructuredCloneReaderError(f"Invalid cryptokey version - expected: 1; got: {version}")

        # reads beyond this point should be aligned
        _, sym_key_length = self._read_uint(), self._read_uint()
        _, sym_key = self._read_raw(sym_key_length)
        self._align()

        _, priv_key_length = self._read_uint(), self._read_uint()
        _, priv_key = self._read_raw(priv_key_length)
        self._align()

        _, pub_key_length = self._read_uint(), self._read_uint()
        _, pub_key = self._read_raw(pub_key_length)
        self._align()

        # dom/crypto/KeyAlgorithmProxy.cpp - KeyAlgorithmProxy::ReadStructuredClone
        _, name_length = self._read_uint(), self._read_uint()
        _, name = self._read_raw(name_length * 2)  # UTF-16, length is codepoints
        name = name.decode("utf-16-le")
        self._align()

        proxy_version, algo = self._read_uint(), CryptoType(self._read_uint())
        if proxy_version != 1:
            raise StructuredCloneReaderError(f"Invalid cryptokey version - expected: 1; got: {version}")

        parameters = {}
        match algo:
            case CryptoType.AES:
                _, length = self._read_uint(), self._read_uint()
                parameters["length"] = length
            case CryptoType.KDF:
                pass
            case CryptoType.HMAC:
                _, length = self._read_uint(), self._read_uint()
                _, hashname_length = self._read_uint(), self._read_uint()
                _, hash_name = self._read_raw(hashname_length * 2)  # utf-16
                self._align()
                parameters["length"] = length
                parameters["hash"] = hash_name.decode("utf-16-le")
            case CryptoType.RSA:
                _, modulus_length = self._read_uint(), self._read_uint()
                _, public_exponent_length = self._read_uint(), self._read_uint()
                _, public_exponent = self._read_raw(public_exponent_length)
                self._align()
                _, hashname_length = self._read_uint(), self._read_uint()
                _, hash_name = self._read_raw(hashname_length * 2)  # utf-16
                self._align()
                parameters["modulus_length"] = modulus_length
                parameters["public_exponent"] = public_exponent
                parameters["hash"] = hash_name.decode("utf-16-le")
            case CryptoType.EC:
                _, named_curve_length = self._read_uint(), self._read_uint()
                _, named_curve = self._read_raw(named_curve_length * 2)  # utf-16
                self._align()
                parameters["named_curve"] = named_curve
            case CryptoType.ED:
                pass
            case _:
                raise ValueError(f"Unexpected CryptoType: {CryptoType.name}")

        return CryptoKey(sym_key or None, priv_key or None, pub_key or None, types.MappingProxyType(parameters))

    def _align(self):
        alignment = self._f.tell() % 8
        if alignment != 0:
            self._f.seek(8 - alignment, os.SEEK_CUR)

    def _read(self, *expected_tags):
        # Align to int64 before reading each pair
        self._align()
        start_offset = self._f.tell()
        # print(f"reading new pair at {start_offset}")
        pair = self._read_pair()
        # print(f"pair is {pair}")

        if expected_tags and pair.tag not in expected_tags:
            raise StructuredCloneReaderError(f"Expected a pair with one of: {', '.join(expected_tags)}, but got {pair.tag}")

        if pair.tag < StructuredDataType.FLOAT_MAX:
            return pair.to_double()

        # todo: v1 typed arrays?

        match pair.tag:
            case StructuredDataType.NULL:
                return None
            case StructuredDataType.UNDEFINED:
                return self.UNDEFINED
            case StructuredDataType.BOOLEAN | StructuredDataType.BOOLEAN_OBJECT:
                result = pair.data != 0
                if pair.tag == StructuredDataType.BOOLEAN_OBJECT:
                    self._flattened_objects.append(result)
                return result
            case StructuredDataType.INT32:
                result = pair.data
                if result & 0x80000000 != 0:  # hack twos-compliment
                    result -= 0x100000000
                return result
            case StructuredDataType.STRING | StructuredDataType.STRING_OBJECT:
                result = self._read_string_internal(pair)
                if pair.tag == StructuredDataType.STRING_OBJECT:
                    self._flattened_objects.append(result)
                return result
            case StructuredDataType.DATE_OBJECT:
                value = self._read_double()
                result = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=value)
                self._flattened_objects.append(result)
                return result
            case StructuredDataType.REGEXP_OBJECT:
                pattern = self._read_string()
                result = re.compile(pattern)
                self._flattened_objects.append(result)
                return result
            case StructuredDataType.BIGINT | StructuredDataType.BIGINT_OBJECT:
                result = self._read_bigint(pair)
                if pair.tag == StructuredDataType.BIGINT_OBJECT:
                    self._flattened_objects.append(result)
                return result
            case StructuredDataType.NUMBER_OBJECT:
                result = self._read_double()
                self._flattened_objects.append(result)
                return result
            case StructuredDataType.BACK_REFERENCE_OBJECT:
                return self._flattened_objects[pair.data]
            case StructuredDataType.ARRAY_OBJECT:
                return self._read_array(pair)  # added to flattened_objects in the method
            case StructuredDataType.OBJECT_OBJECT:
                return self._read_object(pair)  # added to flattened_objects in the method
            case StructuredDataType.TYPED_ARRAY_OBJECT | StructuredDataType.TYPED_ARRAY_OBJECT_V2:
                # have to add a dummy object for this type and replace at the end:
                self._flattened_objects.append(self.UNDEFINED)
                dummy_object_index = len(self._flattened_objects) - 1
                result = self._read_typed_array(pair, False)
                self._flattened_objects[dummy_object_index] = result
                return result
            case StructuredDataType.MAP_OBJECT:
                return self._read_map(pair)
            case StructuredDataType.SET_OBJECT:
                return self._read_set(pair)  # added to flattened_objects in the method
            case StructuredDataType.ARRAY_BUFFER_OBJECT:
                array_length = self._read_ulong()
                _, result = self._read_raw(array_length)
                self._flattened_objects.append(result)
                return result
            case StructuredDataType.ARRAY_BUFFER_OBJECT_V2:
                array_length = pair.data
                _, result = self._read_raw(array_length)
                self._flattened_objects.append(result)
                return result
            case StructuredDataType.DOM_BLOB:
                return self._read_blob(pair)
            case StructuredDataType.DOM_FILE | StructuredDataType.DOM_FILE_WITHOUT_LASTMODIFIEDDATE:
                result = self._read_file(pair)
                self._flattened_objects.append(result)
                return result
            case StructuredDataType.DOM_FILELIST:
                raise NotImplementedError()
            case StructuredDataType.DOM_CRYPTOKEY:
                return self.read_cryptokey(pair)
            case StructuredDataType.END_OF_KEYS:
                raise EndOfKeysException()
            case _:
                raise NotImplementedError(f"datatype not supported: {pair.tag.name}")

    def read_root(self):
        return self._read()


if __name__ == '__main__':
    with open(sys.argv[1], "rb") as f:
        reader = StructuredCloneReader(f)

        print(reader.read_root())

