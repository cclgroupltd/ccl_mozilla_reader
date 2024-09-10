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

import enum
import math
import sys
import re
import pathlib
import sqlite3
import typing
import dataclasses
import datetime
import json
import collections.abc as col_abc

from .common import KeySearch

__version__ = "0.1"
__description__ = "Library for reading Mozilla Firefox history and downloads from the places database"
__contact__ = "Alex Caithness"

EPOCH = datetime.datetime(1970, 1, 1)


def encode_unix_microseconds(timestamp: datetime.datetime) -> typing.Union[int, float]:
    return math.floor((timestamp - EPOCH).total_seconds() * 1000000)


def parse_unix_microseconds(microseconds: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(microseconds=microseconds)


def parse_unix_milliseconds(milliseconds: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(milliseconds=milliseconds)


class VisitType(enum.IntEnum):
    # /toolkit/components/places/nsINavHistoryService.idl
    link = 1
    typed = 2
    bookmark = 3
    embed = 4
    redirect_permanent = 5
    redirect_temporary = 6
    download = 7
    framed_link = 8
    reload = 9


class DownloadState(enum.IntEnum):
    # toolkit/components/downloads/DownloadHistory.sys.mjs
    unknown = 0

    finished = 1
    failed = 2
    cancelled = 3
    paused = 4
    blocked_parental = 6
    dirty = 8


@dataclasses.dataclass(frozen=True)
class MozillaHistoryRecord:
    _owner: "MozillaPlacesDatabase" = dataclasses.field(repr=False)
    rec_id: int
    url: str
    title: str
    visit_time: datetime.datetime
    transition: VisitType
    from_visit_id: int

    @property
    def has_parent(self) -> bool:
        return self.from_visit_id != 0

    @property
    def parent_visit_id(self) -> int:
        return self.from_visit_id

    def get_parent(self) -> typing.Optional["MozillaHistoryRecord"]:
        """
        Get the parent visit for this record (based on the from_visit field in the database),
        or None if there isn't one.
        """

        return self._owner.get_parent_of(self)

    def get_children(self) -> col_abc.Iterable["MozillaHistoryRecord"]:
        """
        Get the children visits for this record (based on their from_visit field in the database).
        """
        return self._owner.get_children_of(self)

    @property
    def record_location(self) -> str:
        return f"SQLite Rowid: {self.rec_id}"


@dataclasses.dataclass(frozen=True)
class MozillaDownload(MozillaHistoryRecord):
    downloaded_location: str
    deleted: bool
    end_time: datetime.datetime
    file_size: typing.Optional[int]
    download_state: DownloadState

    @property
    def start_time(self):
        return self.visit_time

    @property
    def target_path(self):
        return self.downloaded_location


class MozillaPlacesDatabase:
    _HISTORY_QUERY = """
    SELECT 
        "moz_historyvisits"."id",
        "moz_places"."url",
        "moz_places"."title",
        "moz_places"."guid",
        "moz_places"."id" AS "place_id",
        "moz_historyvisits"."visit_date",
        "moz_historyvisits"."visit_type",
        "moz_historyvisits"."from_visit"
    FROM "moz_historyvisits"
    LEFT JOIN "moz_places" ON "moz_historyvisits"."place_id" = "moz_places"."id" """

    _WHERE_URL_EQUALS_PREDICATE = """"moz_places"."url" = ?"""

    _WHERE_URL_REGEX_PREDICATE = """"moz_places"."url" REGEXP ?"""

    _WHERE_URL_IN_PREDICATE = """"moz_places"."url" IN ({parameter_question_marks})"""

    _WHERE_VISIT_TIME_EARLIEST_PREDICATE = """"moz_historyvisits"."visit_date" >= ?"""

    _WHERE_VISIT_TIME_LATEST_PREDICATE = """"moz_historyvisits"."visit_date" <= ?"""

    _WHERE_VISIT_ID_EQUALS_PREDICATE = """"moz_historyvisits"."id" = ?"""

    _WHERE_FROM_VISIT_EQUALS_PREDICATE = """"moz_historyvisits"."from_visit" = ?"""

    _WHERE_VISIT_IS_DOWNLOAD_PREDICATE = f""""moz_historyvisits"."visit_type" = {VisitType.download.value}"""

    _DOWNLOAD_ATTRIBUTES_QUERY = """
        SELECT 
          "moz_anno_attributes"."name",
          "moz_annos"."content",
          "moz_annos"."dateAdded",
          "moz_annos"."lastModified"
        FROM "moz_annos"
        INNER JOIN "moz_anno_attributes"
        ON "moz_annos"."anno_attribute_id" = "moz_anno_attributes"."id"
        WHERE "moz_annos"."place_id" = ?;"""

    _DOWNLOAD_DESTINATION_FILE_URI_KEY = "downloads/destinationFileURI"
    _DOWNLOAD_METADATA_KEY = "downloads/metaData"

    def __init__(self, places_db_path: pathlib.Path):
        self._conn = sqlite3.connect(places_db_path.absolute().as_uri() + "?mode=ro", uri=True)
        self._conn.row_factory = sqlite3.Row
        self._conn.create_function("regexp", 2, lambda y, x: 1 if re.search(y, x) is not None else 0)

    def _row_to_record(self, row: sqlite3.Row) -> MozillaHistoryRecord:
        return MozillaHistoryRecord(
            self,
            row["id"],
            row["url"],
            row["title"],
            parse_unix_microseconds(row["visit_date"]),
            VisitType(row["visit_type"]),
            row["from_visit"]
        )

    def get_parent_of(self, record: MozillaHistoryRecord) -> typing.Optional[MozillaHistoryRecord]:
        if record.from_visit_id == 0:
            return None

        query = MozillaPlacesDatabase._HISTORY_QUERY
        query += f" WHERE {MozillaPlacesDatabase._WHERE_VISIT_ID_EQUALS_PREDICATE};"
        cur = self._conn.cursor()
        cur.execute(query, (record.from_visit_id,))
        row = cur.fetchone()
        cur.close()
        if row:
            return self._row_to_record(row)

    def get_children_of(self, record: MozillaHistoryRecord) -> col_abc.Iterable[MozillaHistoryRecord]:
        query = MozillaPlacesDatabase._HISTORY_QUERY
        predicate = MozillaPlacesDatabase._WHERE_FROM_VISIT_EQUALS_PREDICATE
        query += f" WHERE {predicate};"
        cur = self._conn.cursor()
        cur.execute(query, (record.rec_id,))
        for row in cur:
            yield self._row_to_record(row)

        cur.close()

    def get_record_with_id(self, visit_id: int) -> typing.Optional[MozillaHistoryRecord]:
        query = MozillaPlacesDatabase._HISTORY_QUERY
        query += f" WHERE {MozillaPlacesDatabase._WHERE_VISIT_ID_EQUALS_PREDICATE};"
        cur = self._conn.cursor()
        cur.execute(query, (visit_id,))
        row = cur.fetchone()
        cur.close()
        if row:
            return self._row_to_record(row)

    def iter_history_records(
            self, url: typing.Optional[KeySearch], *,
            earliest: typing.Optional[datetime.datetime]=None, latest: typing.Optional[datetime.datetime]=None
    ) -> col_abc.Iterable[MozillaHistoryRecord]:

        predicates = []
        parameters = []

        if url is None:
            pass  # no predicate
        elif isinstance(url, str):
            predicates.append(MozillaPlacesDatabase._WHERE_URL_EQUALS_PREDICATE)
            parameters.append(url)
        elif isinstance(url, re.Pattern):
            predicates.append(MozillaPlacesDatabase._WHERE_URL_REGEX_PREDICATE)
            parameters.append(url.pattern)
        elif isinstance(url, col_abc.Collection):
            predicates.append(
                MozillaPlacesDatabase._WHERE_URL_IN_PREDICATE.format(
                    parameter_question_marks=",".join("?" for _ in range(len(url)))))
            parameters.extend(url)
        elif isinstance(url, col_abc.Callable):
            pass  # we have to call this function across every
        else:
            raise TypeError(f"Unexpected type: {type(url)} (expects: {KeySearch})")

        if earliest is not None:
            predicates.append(MozillaPlacesDatabase._WHERE_VISIT_TIME_EARLIEST_PREDICATE)
            parameters.append(encode_unix_microseconds(earliest))

        if latest is not None:
            predicates.append(MozillaPlacesDatabase._WHERE_VISIT_TIME_LATEST_PREDICATE)
            parameters.append(encode_unix_microseconds(latest))

        query = MozillaPlacesDatabase._HISTORY_QUERY
        if predicates:
            query += f" WHERE {' AND '.join(predicates)}"

        query += ";"
        cur = self._conn.cursor()
        for row in cur.execute(query, parameters):
            if not isinstance(url, col_abc.Callable) or url(row["url"]):
                yield self._row_to_record(row)

        cur.close()

    def iter_downloads(self):
        cur = self._conn.cursor()
        attrib_cur = self._conn.cursor()

        cur.execute(" ".join(
            (MozillaPlacesDatabase._HISTORY_QUERY,
             "WHERE",
             MozillaPlacesDatabase._WHERE_VISIT_IS_DOWNLOAD_PREDICATE)) + ";")
        for row in cur:
            attrib_cur.execute(MozillaPlacesDatabase._DOWNLOAD_ATTRIBUTES_QUERY, (row["place_id"], ))
            attributes = {x["name"]: x["content"] for x in attrib_cur}

            metadata = json.loads(attributes.get(MozillaPlacesDatabase._DOWNLOAD_METADATA_KEY, "{}"))
            file_location = attributes.get(MozillaPlacesDatabase._DOWNLOAD_DESTINATION_FILE_URI_KEY)

            yield MozillaDownload(
                self,
                row["id"],
                row["url"],
                row["title"],
                parse_unix_microseconds(row["visit_date"]),
                VisitType(row["visit_type"]),
                row["from_visit"],
                file_location,
                metadata.get("deleted"),
                parse_unix_milliseconds(metadata.get("endTime", 0)),
                metadata.get("fileSize"),
                DownloadState(metadata.get("state"))
            )

    def close(self):
        self._conn.close()

    def __enter__(self) -> "MozillaPlacesDatabase":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# if __name__ == '__main__':
#     with MozillaPlacesDatabase(pathlib.Path(sys.argv[1])) as places:
#         for rec in places.iter_history_records(None):
#             print(rec)
#             print()
