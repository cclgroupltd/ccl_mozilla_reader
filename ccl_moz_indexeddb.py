import dataclasses
import io
import sys
import pathlib
import sqlite3
import typing
import datetime
import os
import collections.abc as col_abc

import ccl_moz_indexeddb_key
import ccl_moz_structured_clone_reader
import ccl_simplesnappy

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
    owner: "MozillaIndexedDbDatabase"  # might switch to a class a level up
    object_store_meta: ObjectStoreMetadata
    key: ccl_moz_indexeddb_key.MozillaIdbKey
    value: typing.Any
    #external_value_path: typing.Optional[str] = None

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

    # def resolve_blob_index(self, blob_index: ccl_blink_value_deserializer.BlobIndex) -> IndexedDBExternalObject:
    #     """Resolve a ccl_blink_value_deserializer.BlobIndex to its IndexedDBExternalObject
    #      to get metadata (file name, timestamps, etc)"""
    #     return self.owner.get_blob_info(self.db_id, self.obj_store_id, self.key.raw_key, blob_index.index_id)
    #
    # def get_blob_stream(self, blob_index: ccl_blink_value_deserializer.BlobIndex) -> typing.BinaryIO:
    #     """Resolve a ccl_blink_value_deserializer.BlobIndex to a stream of its content"""
    #     return self.owner.get_blob(self.db_id, self.obj_store_id, self.key.raw_key, blob_index.index_id)


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

    def __init__(self, db_path: pathlib.Path):
        self._db_path = db_path
        if not db_path.is_file():
            raise FileNotFoundError(db_path)
        self._db = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
        self._db.row_factory = sqlite3.Row

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
            data_compressed = row["data"]
            if isinstance(data_compressed, bytes):
                with io.BytesIO(data_compressed) as d:
                    data_decompressed = ccl_simplesnappy.decompress(d)
                with io.BytesIO(data_decompressed) as d:
                    value_reader = ccl_moz_structured_clone_reader.StructuredCloneReader(d)
                    value = value_reader.read_root()
            else:
                continue  # TODO: externally held records

            yield MozillaIndexedDbRecord(self, object_store_meta, key, value)

        cur.close()

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


if __name__ == '__main__':
    idb = MozillaIndexedDbDatabase(pathlib.Path(sys.argv[1]))

    for rec in idb.iter_records_for_object_store(1):
        print(rec)
