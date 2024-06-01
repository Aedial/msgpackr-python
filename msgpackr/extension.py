from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, List, Tuple, Union

from msgpackr.constants import ARRAY, SKIP, STR, UINT32_STRUCT, UNDEFINED

BytesLike = Union[bytes, bytearray, memoryview]


class MsgpackExtension(ABC):
    #: The extension type code.
    EXT_TYPE: int = 0

    @classmethod
    @abstractmethod
    def unpack(cls, unpacker, data: BytesLike, pos: int, length: int) -> Any:
        """
        Unpack the data from the given bytes.

        :param unpacker: The unpacker instance.
        :param data: The data to unpack.
        :param pos: The position in the data.
        :param length: The length from this position the extension should consume.

        :return: The unpacked data.
        """

    @classmethod
    @abstractmethod
    def pack(cls, unpacker, data: Any) -> bytes:
        """
        Pack the data into bytes.

        :param unpacker: The unpacker instance.
        :param data: The data to pack.

        :return: The packed data.
        """


class TimestampExtension(MsgpackExtension):
    EXT_TYPE = -1

    @classmethod
    def unpack(cls, _unpacker, data: BytesLike, pos: int, length: int) -> datetime:
        if length == 4:
            return datetime.fromtimestamp(int.from_bytes(data[pos : pos + length], "big"))

        if length == 8:
            e = int.from_bytes(data[pos : pos + length], "big")
            d = datetime.fromtimestamp(e & 0x3FFFFFFFF)

            return d.replace(microsecond=(e >> 34) // 1000)

        if length == 12:
            e = int.from_bytes(data[pos : pos + length], "big")
            d = datetime.fromtimestamp(e & 0xFFFFFFFFFFFFFFFF)

            return d.replace(microsecond=(e >> 64) * 1000)

        raise ValueError(f"Invalid timestamp length: {length} bytes")

    @classmethod
    def pack(cls, _unpacker, data: datetime) -> bytes:
        d = data.timestamp()
        seconds = int(d)
        nanoseconds = int((d - seconds) * 1e9)

        if nanoseconds == 0:
            return seconds.to_bytes(4, "big")

        if seconds <= 0x3FFFFFFFF:
            return (seconds | (nanoseconds << 34)).to_bytes(8, "big")

        if seconds <= 0xFFFFFFFFFFFFFFFF:
            return (seconds | (nanoseconds << 64)).to_bytes(8, "big")

        raise ValueError(f"Timestamp out of range: {data}")


class MsgpackExtensionWithPost(MsgpackExtension):
    @classmethod
    @abstractmethod
    def post_unpack(cls, unpacker, data: Any, pos: int, ret: Any) -> Tuple[int, Any]:
        """
        Post-process the data to unpack. Unlike the unpack method, this one is not bound in size.

        :param unpacker: The unpacker instance.
        :param data: The data to process.
        :param pos: The position in the data.
        :param ret: The data from the unpack method.

        :return: A tuple with the new position and the post-processed data.
        """


class UndefinedExtension(MsgpackExtension):
    EXT_TYPE = 0

    @classmethod
    def unpack(cls, _unpacker, _data: BytesLike, _pos: int, _length: int):
        return UNDEFINED

    @classmethod
    def pack(cls, _unpacker, data: None) -> bytes:
        return b"\x00"


class BigIntExtension(MsgpackExtension):
    EXT_TYPE = 66

    @classmethod
    def unpack(cls, _unpacker, data: BytesLike, pos: int, length: int) -> int:
        return int.from_bytes(data[pos : pos + length], "big")

    @classmethod
    def pack(cls, _unpacker, data: int) -> bytes:
        return data.to_bytes((data.bit_length() + 7) // 8, "big")


class BundledStrings:
    string_offset: Union[int, None]
    strings: Tuple[str, str]
    begin: int
    end: int

    positions: List[int]

    def __init__(self, offset: [int, None]):
        self.string_offset = offset
        self.strings = ("", "")
        self.positions = [0, 0]

    def __repr__(self):
        left = f"{self.positions[0]}/{len(self.strings[0])}"
        right = f"{self.positions[1]}/{len(self.strings[1])}"

        return f"{self.__class__.__name__}(left={left}, right={right}, begin={hex(self.begin)}, end={hex(self.end)})"

    def populate(self, strings: Tuple[str, str], begin: int, end: int):
        """
        Populate the bundled strings with the given strings, invalidating the offset.

        :param strings: The strings to populate.
        :param begin: The begin position of the strings in the data.
        :param end: The end position of the strings in the data.
        """

        self.strings = strings
        self.begin = begin
        self.end = end
        self.string_offset = None

    def consume_string(self, length: int, peek: bool = False) -> str:
        """
        Consume a slice of the stored strings. Lengths are in characters, relative to the current position.

        :param length: The length of the slice to consume.
            Negative length = left string, positive length = right string.
        :param peek: Whether to consume the slice or just peek at it.
        """

        if self.string_offset is not None:
            raise ValueError("Bundled strings not populated")

        sign = 0 <= length  # 0 for left, 1 for right
        string = self.strings[sign]

        start = self.positions[sign]
        end = start + abs(length)

        if len(string) == start:
            raise ValueError("BundledStrings exhausted")

        if len(string) < end:
            raise ValueError(f"String out of bounds: {len(string)} < {end}")

        if not peek:
            self.positions[sign] = end

        return string[start:end]

    def copy(self):
        obj = BundledStrings(self.string_offset)
        obj.strings = self.strings
        obj.positions = self.positions.copy()

        return obj


class BundledStringsExtension(MsgpackExtensionWithPost):
    EXT_TYPE = 98

    @classmethod
    def unpack(cls, unpacker, data: BytesLike, pos: int, length: int) -> BundledStrings:
        offset = UINT32_STRUCT.unpack_from(data, pos)[0] - length

        return BundledStrings(offset)

    @classmethod
    def post_unpack(cls, unpacker, data: BytesLike, pos: int, ret: BundledStrings) -> Tuple[int, Any]:
        assert isinstance(ret, BundledStrings)
        assert ret.string_offset is not None

        begin = pos + ret.string_offset
        offset, string1 = unpacker.step(data, begin, restrict=STR)
        end, string2 = unpacker.step(data, offset, restrict=STR)
        ret.populate((string1, string2), begin=begin, end=end)
        unpacker.bundle = ret

        return pos, SKIP

    @classmethod
    def pack(cls, _unpacker, data: Any) -> bytes:
        return data


class Error:
    type: int
    message: str
    cause: str

    ERRORS = {0: Exception, 1: TypeError, 2: ReferenceError}

    def __init__(self, extype: int, message: str, cause: str):
        self.type = extype
        self.message = message
        self.cause = cause

    def __repr__(self):
        return f"{self.type}(message={self.message!r}, cause={self.cause!r})"

    def to_values(self):
        return [self.type, self.message, self.cause]


class ErrorExtension(MsgpackExtensionWithPost):
    EXT_TYPE = 101

    @classmethod
    def unpack(cls, _unpacker, data: BytesLike, pos: int, length: int) -> None:
        return None

    @classmethod
    def post_unpack(cls, unpacker, data: BytesLike, pos: int, ret: None) -> Tuple[int, Error]:
        pos, values = unpacker.step(data, pos, restrict=ARRAY)

        if len(values) != 3:
            raise ValueError(f"Invalid error extension: {values}")

        return pos, Error(*values)

    @classmethod
    def pack(cls, unpacker, data: Error) -> bytes:
        return unpacker.pack(data.to_values())


# class StructuredCloneExtension(MsgpackExtensionWithPost):
#     EXT_TYPE = 105


# class PointerExtension(MsgpackExtensionWithPost):
#     EXT_TYPE = 106


class RecordExtension(MsgpackExtensionWithPost):
    EXT_TYPE = 114

    @classmethod
    def unpack(cls, unpacker, data: BytesLike, pos: int, length: int) -> int:
        identifier1 = data[pos]
        if not 0x40 <= identifier1 <= 0x7F:
            raise ValueError(f"Invalid record identifier: {identifier1}")

        identifier1 &= 0x3F

        if length == 1:
            print("RecordExtension", identifier1)
            return identifier1

        if length == 2:
            identifier2 = data[pos + 1]
            # TODO: do we need to check the range?
            print("RecordExtension", identifier1, identifier2, identifier2 << 5 + identifier1)

            return identifier2 << 5 + identifier1

        raise ValueError(f"Invalid record identifier length: {length} bytes")

    @classmethod
    def post_unpack(cls, unpacker, data: BytesLike, pos: int, ret: int) -> Tuple[int, Any]:
        assert isinstance(ret, int)

        records = unpacker.records
        if records is None:
            raise ValueError("Records extension is disabled")

        if ret in records:
            keys = records[ret]
        else:
            pos, keys = unpacker.step(data, pos, restrict=ARRAY)
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                raise ValueError(f"Invalid record keys: {keys!r}")

            records[ret] = keys

        record = {}
        for key in keys:
            pos, value = unpacker.step(data, pos)
            record[key] = value

        return pos, record

    @classmethod
    def pack(cls, unpacker, data: dict) -> bytes:
        keys = list(data.keys())
        values = data.values()

        return unpacker.pack(keys) + b"".join(unpacker.pack(v) for v in values)


class SetExtension(MsgpackExtensionWithPost):
    EXT_TYPE = 115

    @classmethod
    def unpack(cls, _unpacker, _data: BytesLike, _pos: int, _length: int) -> None:
        return None

    @classmethod
    def post_unpack(cls, unpacker, data: BytesLike, pos: int, ret: None) -> Tuple[int, Any]:
        return unpacker.step(data, pos, restrict=ARRAY)

    @classmethod
    def pack(cls, unpacker, data: set) -> bytes:
        return b"".join(unpacker.pack(v) for v in data)
