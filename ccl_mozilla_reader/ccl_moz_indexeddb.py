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
import io
import sys
import pathlib
import sqlite3
import typing
import datetime
import os

from . import ccl_moz_indexeddb_key
from .serialization_formats import ccl_moz_structured_clone_reader
from .storage_formats import ccl_simplesnappy

__version__ = "0.1"
__description__ = "Library for reading Mozilla Firefox IndexedDB"
__contact__ = "Alex Caithness"


UNIX_EPOCH = datetime.datetime(1970, 1, 1)


def decode_unix_microseconds(ms):
    return UNIX_EPOCH + datetime.timedelta(microseconds=ms)


@dataclasses.dataclass(frozen=True)
class ObjectStoreMetadata:
    id_number: int
    auto_increment: bool
    name: str
    key_path: str


@dataclasses.dataclass(frozen=True)
class MozillaIndexedDbRecord:
    owner: "MozillaIndexedDbDatabase"
    object_store_meta: ObjectStoreMetadata
    key: ccl_moz_indexeddb_key.MozillaIdbKey
    value: typing.Any
    file_ids: tuple[str, ...]
    external_value_path: typing.Optional[str] = None

    def open_external_data(
            self,
            file_or_blob: typing.Optional[typing.Union[ccl_moz_structured_clone_reader.File, ccl_moz_structured_clone_reader.Blob]]):
        if file_or_blob.index >= len(self.file_ids):
            raise IndexError(f"index for the file or blob is too large for this record "
                             f"(index: {file_or_blob.index}); file ids length: {len(self.file_ids)}")
        return self.owner.owner.get_external_data_stream(self.owner, self.file_ids[file_or_blob.index])

    @property
    def origin_file(self) -> os.PathLike:
        return self.owner.db_path

    @property
    def database_name(self) -> str:
        return self.owner.name

    @property
    def database_origin(self) -> str:
        return self.owner.origin

    @property
    def object_store_name(self) -> str:
        return self.object_store_meta.name

    @property
    def obj_store_id(self) -> int:
        return self.object_store_meta.id_number


class MozillaIndexedDbDatabase:
    METADATA_QUERY = """
        SELECT "name", "origin", "version", "last_vacuum_time", "last_analyze_time", "last_vacuum_size" 
        FROM database;
        """

    OBJ_STORE_QUERY = """
        SELECT id, auto_increment, name, key_path
        FROM object_store;
    """

    RECORD_BY_OBJECT_STORE_QUERY = """
        SELECT
            "object_data"."key",
            "object_data"."data",
            "object_data"."file_ids"
        FROM "object_data"
        WHERE "object_data"."object_store_id" = ?;
    """

    def __init__(
            self, db_path: pathlib.Path,
            owner: "MozillaIndexedDb"):
        self._db_path = db_path
        if not db_path.is_file():
            raise FileNotFoundError(db_path)
        self._db = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
        self._db.row_factory = sqlite3.Row
        #self._external_data_callback = external_data_callback
        self._owner = owner

        cur = self._db.execute(MozillaIndexedDbDatabase.METADATA_QUERY)
        meta_row = cur.fetchone()

        self._name = meta_row["name"]
        self._origin = meta_row["origin"]
        self._version = meta_row["version"]
        self._last_vacuum_time = decode_unix_microseconds(meta_row["last_vacuum_time"])
        self._last_analyze_time = decode_unix_microseconds(meta_row["last_analyze_time"])
        self._last_vacuum_size = meta_row["last_vacuum_size"]

        self._object_store_metas: list[ObjectStoreMetadata] = []

        cur.execute(MozillaIndexedDbDatabase.OBJ_STORE_QUERY)
        for row in cur:
            self._object_store_metas.append(ObjectStoreMetadata(
                row["id"], bool(row["auto_increment"]), row["name"], row["key_path"]
            ))

        cur.close()

        self._id_number_to_object_store = {x.id_number: x for x in self._object_store_metas}
        self._name_to_object_store = {x.name: x for x in self._object_store_metas}

    def iter_records_for_object_store(self, object_store: typing.Union[int, str, ObjectStoreMetadata]):
        if isinstance(object_store, int):
            object_store_meta = self._id_number_to_object_store[object_store]
        elif isinstance(object_store, str):
            object_store_meta = self._name_to_object_store[object_store]
        elif isinstance(object_store, ObjectStoreMetadata):
            if object_store not in self._object_store_metas:
                raise ValueError("object_store does not belong to this database")
            object_store_meta = object_store
        else:
            raise TypeError(f"Unexpected type for object_store: {type(object_store)}")

        cur = self._db.cursor()
        cur.execute(MozillaIndexedDbDatabase.RECORD_BY_OBJECT_STORE_QUERY, (object_store_meta.id_number,))

        for row in cur:
            key = ccl_moz_indexeddb_key.MozillaIdbKey.from_bytes(row["key"])
            file_ids = (row["file_ids"] or "").split()
            data_compressed = row["data"]
            external_data_location = None
            if isinstance(data_compressed, bytes):
                with io.BytesIO(data_compressed) as d:
                    data_decompressed = ccl_simplesnappy.decompress(d)
                with io.BytesIO(data_decompressed) as d:
                    value_reader = ccl_moz_structured_clone_reader.StructuredCloneReader(d)
                    value = value_reader.read_root()
            elif isinstance(data_compressed, int):
                # externally held data, value is an int64 containing a 32-bit file index into file_ids and a flag in
                # the 33rd bit indicating whether it's compressed
                # see: /dom/indexedDB/ActorsParent.cpp ObjectStoreAddOrPutRequestOp::DoDatabaseWork
                file_index = data_compressed & 0xffffffff
                external_data_compressed = data_compressed & 0x100000000 != 0
                if file_index >= len(file_ids):
                    raise ValueError(f"External file index too large for record with key {key.raw_key.hex()}")
                if not file_ids[file_index].startswith("."):
                    raise ValueError(
                        f"External record data file id does not start with '.' in record with key {key.raw_key.hex()}")
                external_data_location = self._owner.get_external_data_file_details(
                    self, file_ids[file_index].lstrip("."))
                raw_external_data_stream = self._owner.get_external_data_stream(self, file_ids[file_index].lstrip("."))
                if external_data_compressed:
                    with io.BytesIO() as external_data_decompressed:
                        ccl_simplesnappy.decompress_framed(
                            raw_external_data_stream, external_data_decompressed, mozilla_mode=True)
                        external_data_decompressed.seek(0)
                        value_reader = ccl_moz_structured_clone_reader.StructuredCloneReader(external_data_decompressed)
                        value = value_reader.read_root()
                else:
                    value_reader = ccl_moz_structured_clone_reader.StructuredCloneReader(raw_external_data_stream)
                    value = value_reader.read_root()

            yield MozillaIndexedDbRecord(self, object_store_meta, key, value, tuple(file_ids), external_data_location)

        cur.close()

    @property
    def owner(self):
        return self._owner

    @property
    def db_path(self):
        return self._db_path

    @property
    def name(self):
        return self._name

    @property
    def origin(self):
        return self._origin

    @property
    def version(self):
        return self._version

    @property
    def last_vacuum_time(self):
        return self._last_vacuum_time

    @property
    def last_analyze_time(self):
        return self._last_analyze_time

    @property
    def last_vacuum_size(self):
        return self._last_vacuum_size

    def close(self):
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __repr__(self):
        return f"<MozillaIndexedDbDatabase: \"{self.name}\" @ \"{self.db_path}\">"


class MozillaIndexedDb:
    """
    This class represents a whole "idb" folder, brokers access to each database and external files
    """

    def __init__(self, idb_folder_path: pathlib.Path):
        self._path = idb_folder_path
        self._databases = [
            MozillaIndexedDbDatabase(db_path, self) for db_path in self._path.glob("*.sqlite")
        ]
        self._external_file_lookup = {}  # {db_path: {file_id: file_path}}
        for db in self._databases:
            this_db_file_lookup = {}
            self._external_file_lookup[db.db_path] = this_db_file_lookup
            files_folder_path = db.db_path.with_suffix(".files")
            if files_folder_path.is_dir():
                for ext_file in files_folder_path.iterdir():
                    if ext_file.is_file():
                        this_db_file_lookup[ext_file.name] = ext_file

    def get_external_data_stream(self, database: MozillaIndexedDbDatabase, ext_id: str) -> typing.Optional[typing.BinaryIO]:
        if ext_id in self._external_file_lookup[database.db_path]:
            return self._external_file_lookup[database.db_path][ext_id].open("rb")

    def get_external_data_file_details(self, database: MozillaIndexedDbDatabase, ext_id: str):
        if ext_id in self._external_file_lookup[database.db_path]:
            return self._external_file_lookup[database.db_path][ext_id]

    @property
    def databases(self):
        yield from self._databases

    @property
    def path(self):
        return self._path

    def close(self):
        for db in self._databases:
            db.close()

    def __enter__(self) -> "MozillaIndexedDb":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# if __name__ == '__main__':
#     idb = MozillaIndexedDb(pathlib.Path(sys.argv[1]))
#     for db in idb.databases:
#         for rec in db.iter_records_for_object_store(1):
#             print(rec.key)
#             print(rec.value)
#             print("=" * 72)
