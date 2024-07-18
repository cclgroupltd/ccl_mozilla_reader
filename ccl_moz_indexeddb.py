import dataclasses
import sys
import pathlib
import sqlite3
import typing
import datetime
import collections.abc as col_abc


UNIX_EPOCH = datetime.datetime(1970, 1, 1)


def decode_unix_microseconds(ms):
    return UNIX_EPOCH + datetime.timedelta(microseconds=ms)


@dataclasses.dataclass
class ObjectStoreMetadata:
    id_number: int
    auto_increment: bool
    name: str
    key_path: str


class MozIndexedDbSqlite:
    METADATA_QUERY = """
        SELECT "name", "origin", "version", "last_vacuum_time", "last_analyze_time", "last_vacuum_size" 
        FROM database;
        """

    OBJ_STORE_QUERY = """
        SELECT id, auto_increment, name, key_path
        FROM object_store;
    """

    def __init__(self, db_path: pathlib.Path):
        if not db_path.is_file():
            raise FileNotFoundError(db_path)
        self._db = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
        self._db.row_factory = sqlite3.Row

        cur = self._db.execute(MozIndexedDbSqlite.METADATA_QUERY)
        meta_row = cur.fetchone()

        self._name = meta_row["name"]
        self._origin = meta_row["origin"]
        self._version = meta_row["version"]
        self._last_vacuum_time = decode_unix_microseconds(meta_row["last_vacuum_time"])
        self._last_analyze_time = decode_unix_microseconds(meta_row["last_analyze_time"])
        self._last_vacuum_size = meta_row["last_vacuum_size"]

        self._object_store_metas: list[ObjectStoreMetadata] = []

        cur.execute(MozIndexedDbSqlite.OBJ_STORE_QUERY)
        for row in cur:
            self._object_store_metas.append(ObjectStoreMetadata(
                row["id"], bool(row["auto_increment"]), row["name"], row["key_path"]
            ))

        cur.close()

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


if __name__ == '__main__':
    MozIndexedDbSqlite(pathlib.Path(sys.argv[1]))