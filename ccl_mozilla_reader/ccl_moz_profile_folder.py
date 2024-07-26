import datetime
import pathlib
import typing
import collections.abc as col_abc
import dataclasses
import gzip
import zlib
import brotli

from . import ccl_moz_places
from . import ccl_moz_cache
from . import ccl_moz_indexeddb
from . import ccl_moz_localstorage
from . import ccl_moz_sessionstorage

from .common import KeySearch, is_keysearch_hit


class CacheResultMetadataProxy:
    # used to align with what goes on in the Chromium module
    def __init__(self, cache_file: ccl_moz_cache.CacheFile):
        self._cache_file = cache_file

    @property
    def request_time(self) -> datetime.datetime:
        return self._cache_file.metadata.last_fetched

    @property
    def http_header_attributes(self) -> typing.Iterable[tuple[str, str]]:
        yield from self._cache_file.header_attributes

    def has_declaration(self, declaration: str) -> bool:
        raise NotImplementedError()  # TODO
        #return declaration in self._declarations

    def get_attribute(self, attribute: str) -> list[str]:
        return self._cache_file.get_header_attribute(attribute.lower()) or []

    def __getattr__(self, item):
        return getattr(self._cache_file.metadata, item)


class CacheResult:
    # this Wrapper around a CacheFile object is designed to ducktype with the version in the Chromium module
    def __init__(self, cache_file: ccl_moz_cache.CacheFile, *, decompress_data=True):
        self._cache_file = cache_file
        self._metadata_proxy = CacheResultMetadataProxy(cache_file)
        if decompress_data:
            self._data_processed = None  # do the decompression only if required
            self._was_compressed = None
        else:
            self._data_processed = self._cache_file.data
            self._was_compressed = False

    def _set_data(self):
        if self._data_processed is not None:
            return

        content_encoding = self._cache_file.get_header_attribute("content-encoding")
        if content_encoding.strip() == "gzip":
            self._data_processed = gzip.decompress(self._cache_file.data)
            self._was_compressed = True
        elif content_encoding.strip() == "br":
            self._data_processed = brotli.decompress(self._cache_file.data)
            self._was_compressed = True
        elif content_encoding.strip() == "deflate":
            self._data_processed = zlib.decompress(self._cache_file.data, -zlib.MAX_WBITS)  # suppress trying to read a header
            self._was_compressed = True
        else:
            self._data_processed = self._cache_file.data
            self._was_compressed = False

    @property
    def key(self) -> ccl_moz_cache.CacheKey:
        return self._cache_file.metadata.key

    @property
    def metadata(self) -> CacheResultMetadataProxy:
        return self._metadata_proxy

    @property
    def data_location(self):  # do we need to wrap this up like the CacheFileLocation in the Chromium version?
        return self._cache_file.path

    @property
    def metadata_location(self):
        return self._cache_file.path

    @property
    def data(self) -> bytes:
        if self._data_processed is None:
            self._set_data()

        return self._data_processed


class MozillaProfileFolder:  # TODO: inherit AbstractBrowserProfile
    _PLACES_DB_NAME = "places.sqlite"
    _STORAGE_FOLDER_NAME = "storage"
    _DEFAULT_FOLDER_NAME = "default"

    def __init__(self, main_profile_path: pathlib.Path, cache_path: pathlib.Path):
        if not main_profile_path.is_dir():
            raise NotADirectoryError("main_profile_path doesn't exist or is not a directory")

        if not cache_path.is_dir():
            raise NotADirectoryError("cache_path doesn't exist or is not a directory")

        self._profile_folder = main_profile_path
        self._cache_folder = cache_path

        # Cache operates lazily so no problem setting it up now
        self._cache: ccl_moz_cache.MozillaCache = ccl_moz_cache.MozillaCache(cache_path)
        self._places: typing.Optional[ccl_moz_places.MozillaPlacesDatabase] = None
        self._localstorage: typing.Optional[ccl_moz_localstorage.LocalStoreDb] = None
        self._sessionstorage: typing.Optional[ccl_moz_sessionstorage.SessionStorage] = None
        self._indexeddb: typing.Optional[ccl_moz_indexeddb.MozillaIndexedDbBag] = None

    def close(self):
        if self._places is not None:
            self._places.close()

    def _lazy_load_places(self):
        if self._places is None:
            self._places = ccl_moz_places.MozillaPlacesDatabase(
                self._profile_folder / MozillaProfileFolder._PLACES_DB_NAME)

    def _lazy_load_local_storage(self):
        if self._localstorage is None:
            ls_path = (
                    self._profile_folder /
                    MozillaProfileFolder._STORAGE_FOLDER_NAME /
                    MozillaProfileFolder._DEFAULT_FOLDER_NAME)
            self._localstorage = ccl_moz_localstorage.LocalStoreDb(ls_path)

    def _lazy_load_session_storage(self):
        if self._sessionstorage is None:
            self._sessionstorage = ccl_moz_sessionstorage.SessionStorage(self._profile_folder)

    def _lazy_load_indexeddb(self):
        if self._indexeddb is None:
            storage_default_path = (
                    self._profile_folder /
                    MozillaProfileFolder._STORAGE_FOLDER_NAME /
                    MozillaProfileFolder._DEFAULT_FOLDER_NAME)
            self._indexeddb = ccl_moz_indexeddb.MozillaIndexedDbBag(storage_default_path)

    def iter_local_storage_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates the hosts in this profile's local storage
        """
        self._lazy_load_local_storage()
        yield from self._localstorage.iter_storage_keys()

    def iter_local_storage(
            self, storage_key: typing.Optional[KeySearch] = None,
            script_key: typing.Optional[KeySearch] = None, *,
            include_deletions=False,
            raise_on_no_result=False) -> col_abc.Iterable[ccl_moz_localstorage.LocalStorageRecord]:
        """
        Iterates this profile's local storage records

        :param storage_key: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool.
        :param script_key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool.
        :param include_deletions: Has no effect in Mozilla currently
        :param raise_on_no_result: if True (the default) if no matching storage keys are found, raise a KeyError
        (these will have None as values).
        :return: TODO
        """
        self._lazy_load_local_storage()
        yield from self._localstorage.iter_records(
            storage_key=storage_key, script_key=script_key, raise_on_no_result=raise_on_no_result)

    def iter_session_storage_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates this profile's session storage hosts
        """
        self._lazy_load_session_storage()
        yield from self._sessionstorage.iter_hosts()

    def iter_session_storage(
            self,
            host: typing.Optional[KeySearch] = None,
            key: typing.Optional[KeySearch] = None, *,
            include_deletions=False,
            raise_on_no_result=False) -> col_abc.Iterable[ccl_moz_sessionstorage.SessionStoreRecord]:
        """
        Iterates this profile's session storage records

        :param host: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string (each host) and
        returns a bool; or None (the default) in which case all hosts are considered.
        :param key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool; or
        None (the default) in which case all keys are considered.
        :param include_deletions: has no effect in Mozilla
        :param raise_on_no_result: if True, if no matching storage keys are found, raise a KeyError

        :return: iterable of SessionStoreRecords
        """
        self._lazy_load_session_storage()
        yield from self._sessionstorage.iter_records(host=host, key=key, raise_on_no_results=raise_on_no_result)

    def iter_indexeddb_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates the hosts present in the Indexed DB folder. These values are what should be used to load the databases
        directly.
        """
        self._lazy_load_indexeddb()
        yield from self._indexeddb.iter_origins()

    def get_indexeddb(self, host: str) -> ccl_moz_indexeddb.MozillaIndexedDb:
        """
        Returns the database with the host provided. Should be one of the values returned by
        :func:`~iter_indexeddb_hosts`. The database will be opened on-demand if it hasn't previously been opened.

        :param host: the host to get
        """
        self._lazy_load_indexeddb()
        return self._indexeddb.get_idb(host)

    def iter_indexeddb_records(
            self, host_id: typing.Optional[KeySearch], database_name: typing.Optional[KeySearch] = None,
            object_store_name: typing.Optional[KeySearch] = None, *,
            raise_on_no_result=False, include_deletions=False):
        """
        Iterates indexeddb records in this profile.

        :param host_id: the host for the records, The possible values for this profile are returned by
        :func:`~iter_indexeddb_hosts`. This can be one of: a single string; a collection of strings;
        a regex pattern; a function that takes a string (each host) and returns a bool; or None in which
        case all hosts are considered. Be cautious with supplying a parameter which will lead to unnecessary
        databases being opened as this has a set-up time for the first time it is opened.
        :param database_name: the database name for the records. This can be one of: a single string; a collection
        of strings; a regex pattern; a function that takes a string (each host) and returns a bool; or None (the
        default) in which case all hosts are considered.
        :param object_store_name: the object store name of the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string (each host) and returns a bool;
        or None (the default) in which case all hosts are considered.
        :param raise_on_no_result: if True, if no matching storage keys are found, raise a KeyError
        :param include_deletions: no effect in Mozilla
        """
        self._lazy_load_indexeddb()

        yielded = False
        matched_hosts = [h for h in self._indexeddb.iter_origins() if host_id is None or is_keysearch_hit(host_id, h)]
        for host in matched_hosts:
            idb = self._indexeddb.get_idb(host)
            matched_databases = [d for d in idb.databases
                                 if database_name is None or is_keysearch_hit(database_name, d.name)]
            for db in matched_databases:
                matched_objstores = [o for o in db.object_stores
                                     if object_store_name is None or is_keysearch_hit(object_store_name, o.name)]
                for obj_store in matched_objstores:
                    for rec in db.iter_records_for_object_store(obj_store):
                        yielded = True
                        yield rec

        if raise_on_no_result and not yielded:
            raise KeyError((host_id, database_name, object_store_name))

    def iterate_history_records(
            self, url: typing.Optional[KeySearch] = None, *,
            earliest: typing.Optional[datetime.datetime] = None, latest: typing.Optional[datetime.datetime] = None):
        """
        Iterates history records for this profile.

        :param url: a URL to search for. This can be one of: a single string; a collection of strings;
        a regex pattern; a function that takes a string (each host) and returns a bool; or None (the
        default) in which case all hosts are considered.
        :param earliest: an optional datetime which will be used to exclude records before this date.
        NB the date should be UTC to match the database. If None, no lower limit will be placed on
        timestamps.
        :param latest: an optional datetime which will be used to exclude records after this date.
        NB the date should be UTC to match the database. If None, no upper limit will be placed on
        timestamps.
        """

        self._lazy_load_places()
        yield from self._places.iter_history_records(url=url, earliest=earliest, latest=latest)

    def iterate_cache(
            self,
            url: typing.Optional[KeySearch] = None, *, decompress=True, omit_cached_data=False,
            **kwargs: typing.Union[bool, KeySearch]) -> col_abc.Iterable[CacheResult]:
        """
        Iterates cache records for this profile.

        :param url: a URL to search for. This can be one of: a single string; a collection of strings;
        a regex pattern; a function that takes a string (each host) and returns a bool; or None (the
        default) in which case all records are considered.
        :param decompress: if True (the default), data from the cache which is compressed (as per the
        content-encoding header field) will be decompressed when read if the compression format is
        supported (currently deflate, gzip and brotli are supported).
        :param omit_cached_data: does not collect the cached data and omits it from each `CacheResult`
        object. Should be faster in cases when only metadata recovery is required.
        :param kwargs: further keyword arguments are used to search based upon header fields. The
        keyword should be the header field name, with underscores replacing hyphens (e.g.,
        content-encoding, becomes content_encoding). The value should be one of: a Boolean (in which
        case only records with this field present will be included if True, and vice versa); a single
        string; a collection of strings; a regex pattern; a function that takes a string (the value)
        and returns a bool.
        """

        # TODO: omit_cached_data is actually currently ignored because of how the metadata class is built
        for rec in self._cache.iter_cache(url=url, **kwargs):
            yield CacheResult(rec, decompress_data=decompress)

    def iter_downloads(
            self, *, download_url: typing.Optional[KeySearch] = None, tab_url: typing.Optional[KeySearch] = None):
        """
        Iterates download records for this profile

        :param download_url: A URL related to the downloaded resource. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string (each host) and returns a bool;
        or None (the default) in which case all records are considered.
        :param tab_url: A URL related to the page the user was accessing when this download was started.
        This can be one of: a single string; a collection of strings; a regex pattern; a function that takes
        a string (each host) and returns a bool; or None (the default) in which case all records are considered.
        """
        # TODO typehint return type once it's also abstracted
        self._lazy_load_places()
        for download in self._places.iter_downloads():
            if download_url is not None and not is_keysearch_hit(download_url, download.url):
                continue
            if tab_url is not None:
                parent = download.get_parent()
                if not parent or not is_keysearch_hit(tab_url, parent.url):
                    continue

            yield download

    @property
    def path(self):
        """The input path of this browser profile"""
        return self._profile_folder

    @property
    def local_storage(self):
        """The local storage object for this browser profile"""
        self._lazy_load_local_storage()
        return self._localstorage

    @property
    def session_storage(self):
        """The session storage object for this browser profile"""
        self._lazy_load_local_storage()
        return self._sessionstorage

    @property
    def cache(self):
        """The cache for this browser profile"""
        return self._cache

    @property
    def history(self):
        """The history for this browser profile"""
        self._lazy_load_places()
        return self._places

    def __enter__(self) -> "MozillaProfileFolder":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()