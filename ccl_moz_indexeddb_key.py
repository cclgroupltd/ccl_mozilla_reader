import datetime
import enum
import io
import struct
import typing

# dom/indexedDB/Key.cpp / dom/indexedDB/Key.h


TOKEN_Terminator = 0
TOKEN_Float = 0x10
TOKEN_Date = 0x20
TOKEN_String = 0x30
TOKEN_Binary = 0x40
TOKEN_Array = 0x50


class EndOfTokens(Exception):
    pass


class TerminatorEncountered(Exception):
    pass


class _IdbKeyReader:
    def __init__(self, data: bytes):
        self._raw = data
        self._f = io.BytesIO(data)

    def _read_until_nul(self):
        buffer = []
        while True:
            b = self._f.read(1)
            if not b or b == b"\x00":
                break
            buffer.append(b[0])
        return bytes(buffer)

    def _read_float(self):
        # trailing 00 bytes in a key are truncated, so we have to add them back in if needed
        number_raw = bytearray(self._f.read(8))
        shortage = 8 - len(number_raw)
        number_raw = number_raw + (b"\x00" * shortage)
        # floats are stored weirdly, so that they sort correctly
        if number_raw[0] & 0x80 != 0:
            # a positive number
            number_raw[0] = number_raw[0] & 0x7f
            return struct.unpack(">d", number_raw)[0]
        else:
            return -struct.unpack(">d", number_raw)[0]

    def _read_string(self, is_binary=False):
        data = self._read_until_nul()
        i = 0
        chars = []
        while i < len(data):
            byte_1 = data[i]
            i += 1

            if byte_1 & 0b10000000 == 0:
                # 1 byte character, stored as codepoint + 1
                if is_binary:
                    chars.append(byte_1 - 1)
                else:
                    chars.append(chr(byte_1 - 1))
            elif byte_1 & 0b11000000 == 0b10000000:
                # 2 byte character encoded as 10xxxxxx xxxxxxxx with 7F subtracted
                byte_2 = data[i]
                i += 1
                value = (((byte_1 & 0b00111111) << 8) | byte_2) - 0x7f
                if is_binary:
                    chars.append(value)
                else:
                    chars.append(chr(value))
            elif byte_1 & 0b11000000 == 0b11000000:
                # 3 byte character encoded as 11xxxxxx xxxxxxxx xx000000
                byte_2 = data[i]
                i += 1
                byte_3 = data[i]
                i += 1

                value = (byte_1 & 0b00111111) << 16
                value |= byte_2 << 8
                value |= byte_3 & 0b11000000
                value >>= 6

                if is_binary:
                    chars.append(value)
                else:
                    chars.append(chr(value))
        if is_binary:
            return bytes(chars)
        else:
            return "".join(chars)

    def _read_token(self, token) -> typing.Union[str, bytes, float, datetime.datetime, tuple]:
        if token == TOKEN_Terminator:
            raise TerminatorEncountered()
        elif token == TOKEN_Float:
            return self._read_float()
        elif token == TOKEN_Date:
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=self._read_float())
        elif token == TOKEN_String:
            return self._read_string()
        elif token >= TOKEN_Array:
            result = []
            next_token = token - TOKEN_Array
            if next_token > TOKEN_Terminator:
                result.append(self._read_token(next_token))

            while True:
                try:
                    result.append(self.read())
                except (EndOfTokens, TerminatorEncountered):
                    return tuple(result)

    def read(self) -> typing.Union[str, bytes, float, datetime.datetime, tuple]:
        token_raw = self._f.read(1)
        if not token_raw:
            raise EndOfTokens()
        token = token_raw[0]
        return self._read_token(token)


class MozillaIdbKey:
    def __init__(self, value: typing.Union[str, bytes, float, datetime.datetime, tuple], raw_key: bytes):
        self._value = value
        self._raw_value = raw_key

    @classmethod
    def from_bytes(cls, raw_key: bytes):
        r = _IdbKeyReader(raw_key)
        value = r.read()

        return cls(value, raw_key)

    def __eq__(self, other):
        if isinstance(other, MozillaIdbKey):
            return self._raw_value == other._raw_value
        raise TypeError(f"cannot compare MozillaIdbKey with {type(other)}")

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return self._raw_value.__hash__()

    def __repr__(self):
        return f"<MozillaIdbKey {self._value}>"

    @property
    def value(self):
        return self._value

    @property
    def raw_key(self):
        return self._raw_value

