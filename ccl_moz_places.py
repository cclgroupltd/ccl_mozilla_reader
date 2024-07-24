import enum
import math
import sys
import re
import pathlib
import sqlite3
import typing
import dataclasses
import datetime
import collections.abc as col_abc

from common import KeySearch, is_keysearch_hit

EPOCH = datetime.datetime(1970, 1, 1)


def encode_unix_microseconds(timestamp: datetime.datetime) -> typing.Union[int, float]:
    return math.floor((timestamp - EPOCH).total_seconds() * 1000000)


def parse_unix_microseconds(microseconds: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(microseconds=microseconds)


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


class MozillaPlacesDatabase:
    _HISTORY_QUERY = """
    SELECT 
        "moz_historyvisits"."id",
        "moz_places"."url",
        "moz_places"."title",
        "moz_places"."guid",
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

    def __init__(self, places_db_path: pathlib.Path):
        self._conn = sqlite3.connect(places_db_path.as_uri() + "?mode=ro", uri=True)
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

    def close(self):
        self._conn.close()

    def __enter__(self) -> "MozillaPlacesDatabase":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


if __name__ == '__main__':
    with MozillaPlacesDatabase(pathlib.Path(sys.argv[1])) as places:
        for rec in places.iter_history_records(None):
            print(rec)