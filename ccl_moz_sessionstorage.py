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

import sys
import pathlib
import moz_lz4
import dataclasses
import typing
import re
import collections.abc as col_abc
from common import KeySearch, is_keysearch_hit

__version__ = "0.1"
__description__ = "Library for reading Mozilla Firefox session storage"
__contact__ = "Alex Caithness"


@dataclasses.dataclass(frozen=True)
class SessionStoreRecord:
    host: typing.Optional[str]
    key: str
    value: str
    is_closed_tab: bool
    origin_file: pathlib.Path


class SessionStorage:
    """
    Class which gives access to sessionstorage records recovered from the sessionstore file and the various backups
    found in the sessionstore-backups folder.
    """

    def __init__(self, profile_path: pathlib.Path):
        self._host_lookup = {}  # {host: {key: [value, ...]}}

        session_store_path = profile_path / "sessionstore.jsonlz4"
        if session_store_path.is_file():
            for rec in SessionStorage._get_records_from_file(session_store_path):
                self._host_lookup.setdefault(rec.host, {})
                self._host_lookup[rec.host].setdefault(rec.key, [])
                self._host_lookup[rec.host][rec.key].append(rec)

        session_store_backups_path = profile_path / "sessionstore-backups"
        if session_store_backups_path.is_dir():
            for ss_backup_path in session_store_backups_path.iterdir():
                if "jsonlz4" in ss_backup_path.suffix or ss_backup_path.suffix == ".baklz4":
                    for rec in SessionStorage._get_records_from_file(ss_backup_path):
                        self._host_lookup.setdefault(rec.host, {})
                        self._host_lookup[rec.host].setdefault(rec.key, [])
                        self._host_lookup[rec.host][rec.key].append(rec)

    @staticmethod
    def _get_storage_from_tab(
            tab_obj: dict, is_closed: bool, file_path: pathlib.Path) -> col_abc.Iterable[SessionStoreRecord]:
        if not isinstance(tab_obj, dict):
            raise TypeError(f"tab_obj is expected to be a dict (actually got {type(tab_obj)}")

        storage = tab_obj.get("storage", {})
        for host in storage:
            for key, value in storage[host].items():
                yield SessionStoreRecord(host, key, value, is_closed, file_path)

    @staticmethod
    def _get_records_from_file(session_store_file: pathlib.Path) -> col_abc.Iterable[SessionStoreRecord]:
        sessionstore_obj = moz_lz4.load_jsonlz4(session_store_file)
        for window in sessionstore_obj["windows"]:
            for tab in window["tabs"]:
                yield from SessionStorage._get_storage_from_tab(tab, False, session_store_file)

            for closed_tab in window.get("_closedTabs", []):
                yield from SessionStorage._get_storage_from_tab(closed_tab["state"], True, session_store_file)

    def iter_hosts(self) -> typing.Iterable[str]:
        """
        :return: yields the hosts present in this SessionStorage
        """
        yield from self._host_lookup.keys()

    def _search_host(self, host: KeySearch) -> list[str]:
        if isinstance(host, str):
            return [host] if host in self._host_lookup else []
        elif isinstance(host, re.Pattern):
            return [x for x in self._host_lookup if host.search(x)]
        elif isinstance(host, col_abc.Collection):
            return list(set(host) & self._host_lookup.keys())
        elif isinstance(host, col_abc.Callable):
            return [x for x in self._host_lookup if host(x)]
        else:
            raise TypeError(f"Unexpected type: {type(host)} (expects: {KeySearch})")

    def iter_records(
            self,
            host: typing.Optional[KeySearch],
            key: typing.Optional[KeySearch],
            *,
            raise_on_no_results=True):
        if host is None:
            host_hits = self._host_lookup.keys()
        else:
            host_hits = self._search_host(host)
            if not host_hits and raise_on_no_results:
                raise KeyError((host, key))

        yielded = False
        for host_hit in host_hits:
            if key is None:
                key_hits = self._host_lookup[host_hit].keys()
            else:
                key_hits = [k for k in self._host_lookup[host_hit].keys() if is_keysearch_hit(key, k)]

            for key_hit in key_hits:
                yielded = True
                yield from self._host_lookup[host_hit][key_hit]

        if not yielded and raise_on_no_results:
            raise KeyError((host, key))

    def iter_records_for_host(self, host: KeySearch, *, raise_on_no_results=True):
        yield from self.iter_records(host, None, raise_on_no_results=raise_on_no_results)

    def iter_all_records(self):
        yield from self.iter_records(None, None, raise_on_no_results=False)

    def close(self):
        pass  # we don't really need this, but it's included to match the Chromium version

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __contains__(self, item: typing.Union[str, typing.Tuple[str, str]]) -> bool:
        """
        :param item: either the host as a str or a tuple of the host and a key (both str)
        :return: if item is a str, returns true if that host is present, if item is a tuple of (str, str), returns True
            if that host and key pair are present
        """

        if isinstance(item, str):
            return item in self._host_lookup
        elif isinstance(item, tuple) and len(item) == 2:
            host, key = item
            return host in self._host_lookup and key in self._host_lookup[host]
        else:
            raise TypeError("item must be a string or a tuple of (str, str)")


if __name__ == '__main__':
    ss = SessionStorage(pathlib.Path(sys.argv[1]))

    for record in ss.iter_all_records():
        print(record)
