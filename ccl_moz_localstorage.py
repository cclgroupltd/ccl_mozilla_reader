import enum
import io
import pathlib
import re
import sqlite3
import dataclasses
import sys
import types
import collections.abc as col_abc
import typing

import ccl_simplesnappy
from storage_common import MetadataV2
from common import KeySearch, is_keysearch_hit


__version__ = "0.1"
__description__ = "Library for reading Mozilla Firefox local storage"
__contact__ = "Alex Caithness"


class ConversionType(enum.IntEnum):
    # localstorage/LSValue.h
    utf_16 = 0  # called "NONE" in the original enum, but I wanted to make explicit what the default actually was
    utf_8 = 1  # called "UTF16_UTF8" in the original enum, but it's not clear what that name actually means


class CompressionType(enum.IntEnum):
    # localstorage/LSValue.h
    uncompressed = 0
    snappy = 1


@dataclasses.dataclass(frozen=True)
class LocalStorageRecord:
    storage_key: str
    script_key: str
    value: str
    database_path: pathlib.Path
    sqlite_rowid: int
    value_raw: bytes
    conversion_type: ConversionType
    compression_type: CompressionType


class LocalStoreDb:
    """
    A class managing access to this profile's localstorage. We treat all of the underlying
    sqlite databases together to mirror the way that it's done in the corresponding Chromium
    module, and to make searching filtering easier for the user of the class.
    """

    LS_QUERY = """
        SELECT
            rowid, 
            "data"."key",
            "data"."utf16_length",
            "data"."conversion_type",
            "data"."compression_type",
            "data"."last_access_time",
            "data"."value"
        FROM "data";"""

    def __init__(self, path: pathlib.Path):
        """

        :param path: the storage/default folder
        """
        if not path.is_dir():
            raise ValueError(f"path does not exist or is not a directory")
        self._host_lookup= {}  # origin to database path
        self._metadata_lookup = {}  # origin to metadatav2
        self._collect_hosts(path)
        self._host_lookup = types.MappingProxyType(self._host_lookup)
        self._metadata_lookup = types.MappingProxyType(self._metadata_lookup)

        # we lazy load the databases
        self._databases: dict[str, typing.Optional[sqlite3.Connection]] = {x: None for x in self._host_lookup.keys()}

    def _collect_hosts(self, storage_default_folder: pathlib.Path):
        for domain_folder in storage_default_folder.iterdir():
            if not domain_folder.is_dir():
                continue
            ls_db = domain_folder / "ls" / "data.sqlite"
            if not ls_db.is_file():
                continue

            metadata_path = domain_folder / ".metadata-v2"
            if not metadata_path.is_file():
                raise ValueError(f".metadata-v2 file missing from {domain_folder}")

            metadata = MetadataV2.from_file(metadata_path)
            self._host_lookup[metadata.origin] = ls_db
            self._metadata_lookup[metadata.origin] = metadata

    def _lazy_load_database(self, storage_key: str):
        if storage_key not in self._databases:
            raise KeyError(storage_key)

        if self._databases[storage_key] is None:
            self._databases[storage_key] = sqlite3.connect(
                self._host_lookup[storage_key].as_uri() + "?mode=ro", uri=True)
            self._databases[storage_key].row_factory = sqlite3.Row

    def iter_storage_keys(self) -> col_abc.Iterable[str]:
        yield from self._host_lookup.keys()

    def contains_storage_key(self, storage_key: str) -> bool:
        return storage_key in self._host_lookup

    def _prepare_hosts_for_iteration(self, storage_key: typing.Optional[KeySearch], *, raise_on_no_result=True):
        yielded = False
        if storage_key is None:
            yielded = True
            yield from self._host_lookup.keys()
        elif isinstance(storage_key, str):
            if storage_key in self._host_lookup:
                yielded = True
                yield storage_key
        elif isinstance(storage_key, col_abc.Collection):
            hits = set(storage_key) & self._host_lookup.keys()
            if hits:
                yielded = True
                yield from hits
        elif isinstance(storage_key, re.Pattern):
            hits = [h for h in self._host_lookup.keys() if storage_key.search(h) is not None]
            if hits:
                yielded = True
                yield from hits
        elif isinstance(storage_key, col_abc.Callable):
            hits = [h for h in self._host_lookup.keys() if storage_key(h)]
            if hits:
                yielded = True
                yield from hits
        else:
            raise TypeError(f"Unexpected type: {type(storage_key)} (expects: {KeySearch})")

        if not yielded and raise_on_no_result:
            raise KeyError(storage_key)

    @staticmethod
    def _record_from_row(database_path: pathlib.Path, storage_key, row: sqlite3.Row) -> LocalStorageRecord:
        conv_type = ConversionType(row["conversion_type"])
        compr_type = CompressionType(row["compression_type"])
        value_raw = row["value"]
        if compr_type == CompressionType.snappy:
            with io.BytesIO(value_raw) as value_raw_stream:
                value_raw = ccl_simplesnappy.decompress(value_raw_stream)
        elif compr_type == CompressionType.uncompressed:
            pass
        else:
            raise ValueError(f"Unexpected compression type: {compr_type}")

        if not value_raw:
            value = value_raw  # empty values are bound to a string due to column type, which doesn't have a decode func
        elif conv_type == ConversionType.utf_16:
            value = value_raw.decode("utf-16-be")
        elif conv_type == ConversionType.utf_8:
            value = value_raw.decode("utf-8")
        else:
            raise ValueError(f"Unexpected conversion type: {conv_type}")

        return LocalStorageRecord(
            storage_key,
            row["key"],
            value,
            database_path,
            row["rowid"],
            row["value"],
            conv_type,
            compr_type
        )

    def iter_records(
            self, storage_key: typing.Optional[KeySearch], script_key: typing.Optional[KeySearch], *,
            raise_on_no_result=True) -> col_abc.Iterable[LocalStorageRecord]:

        hosts = self._prepare_hosts_for_iteration(storage_key, raise_on_no_result=raise_on_no_result)
        if not hosts and raise_on_no_result:
            raise KeyError(storage_key)

        yielded = False
        for host in hosts:
            self._lazy_load_database(host)
            cur = self._databases[host].cursor()
            cur.execute(LocalStoreDb.LS_QUERY)
            for row in cur:
                if script_key is None or is_keysearch_hit(script_key, row["key"]):
                    rec = LocalStoreDb._record_from_row(self._host_lookup[host], host, row)
                    yield rec
                    yielded = True

        if not yielded and raise_on_no_result:
            raise KeyError((storage_key, script_key))

    def iter_records_for_storage_key(self, storage_key: KeySearch, *, raise_on_no_result=True):
        yield from self.iter_records(storage_key, script_key=None, raise_on_no_result=raise_on_no_result)

    def iter_all_records(self):
        yield from self.iter_records(None, None, raise_on_no_result=False)

    def close(self):
        for database in self._databases.values():
            if database is not None:
                database.close()

    def __enter__(self) -> "LocalStoreDb":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()



if __name__ == '__main__':
    db = LocalStoreDb(pathlib.Path(sys.argv[1]))
    for rec in db.iter_records_for_storage_key(re.compile(r"bbc.co.uk")):
        print(rec)