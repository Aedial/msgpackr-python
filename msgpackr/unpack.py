"""
Unpacker for MessagePack data.

Thanks to JasonLWalker for helping to spot the non-standard additions to the MessagePack format.
"""


from functools import partial
from typing import Any, Callable, Dict, List, Tuple, Type, Union

from msgpackr.constants import *
from msgpackr.extension import (
    BundledStrings,
    BundledStringsExtension,
    MsgpackExtension,
    MsgpackExtensionWithPost,
    RecordExtension,
    SetExtension,
    TimestampExtension,
    UndefinedExtension,
)

BytesLike = Union[bytes, bytearray, memoryview]


# noinspection PyMethodMayBeStatic
class Unpacker:
    #: The registered extensions.
    extensions: Dict[int, Type[MsgpackExtension]]
    #: Whether to enable bundled strings.
    use_bundled_strings: bool

    #: Last bundle used for bundled strings. It needs to be stored there, as the bundle can be initialized anywhere.
    bundle: Union[BundledStrings, None]
    #: List of previously unpacked records's keys.
    records: Dict[int, List[str]]

    def check_data_length(self, length: int, data: BytesLike):
        """
        Check that the data is at least the given length.

        :param length: The minimum length.
        :param data: The data.
        """

        if len(data) < length:
            # TODO: this part might be a good place to fetch more data if we are reading from a stream or something

            raise ValueError(f"Data is too short: {len(data)} bytes, expected at least {length} bytes")

    # Fixed code points
    def bundled_string(self, data: BytesLike, pos: int) -> Tuple[int, str]:
        if self.bundle is None:
            raise ValueError("No bundled strings provided")

        pos, size = self.step(data, pos, restrict=INT)
        ret = self.bundle.consume_string(size)

        return pos, ret

    def bin(self, data: BytesLike, pos: int, st: Struct, offset: int) -> Tuple[int, BytesLike]:
        begin = pos + offset
        self.check_data_length(begin, data)
        end = begin + st.unpack_from(data, pos)[0]  # pos + offset + size

        return end, data[begin:end]

    def ext(self, data: BytesLike, pos: int, st: Struct, offset: int) -> Tuple[int, Any]:
        begin = pos + offset
        self.check_data_length(begin, data)
        size = st.unpack_from(data, pos)[0]

        ext_type = INT8_STRUCT.unpack_from(data, begin)[0]
        if ext_type not in self.extensions:
            raise ValueError(f"Unknown extension type: {ext_type}")

        end = begin + size + 1  # pos + offset + size + ext_type
        extension = self.extensions[ext_type]
        ret = extension.unpack(self, data, begin + 1, size)
        if issubclass(extension, MsgpackExtensionWithPost):
            end, ret = extension.post_unpack(self, data, end, ret)

        return end, ret

    def float(self, data: BytesLike, pos: int, st: Struct, size: int) -> Tuple[int, float]:
        end = pos + size
        self.check_data_length(end, data)

        return end, st.unpack_from(data, pos)[0]

    def int(self, data: BytesLike, pos: int, st: Struct, size: int) -> Tuple[int, int]:
        end = pos + size
        self.check_data_length(end, data)

        return end, st.unpack_from(data, pos)[0]

    def fixext(self, data: BytesLike, pos: int, size: int) -> Tuple[int, Any]:
        begin = pos + 1
        end = begin + size
        self.check_data_length(end, data)
        ext_type = INT8_STRUCT.unpack_from(data, pos)[0]
        if ext_type not in self.extensions:
            raise ValueError(f"Unknown extension type: {ext_type}")

        extension = self.extensions[ext_type]
        ret = extension.unpack(self, data, begin, size)
        if issubclass(extension, MsgpackExtensionWithPost):
            end, ret = extension.post_unpack(self, data, end, ret)

        return end, ret

    def str(self, data: BytesLike, pos: int, st: Struct, offset: int) -> Tuple[int, str]:
        self.check_data_length(pos + offset, data)
        size = st.unpack_from(data, pos)[0]
        pos += offset
        end = pos + size

        self.check_data_length(end, data)
        if isinstance(data, memoryview):
            return end, data[pos:end].tobytes().decode()

        return end, data[offset:end].decode()

    def array(self, data: BytesLike, pos: int, st: Struct, offset: int) -> Tuple[int, list]:
        end = pos + offset
        self.check_data_length(end, data)
        size = st.unpack_from(data, pos)[0]

        arr = [None] * size
        for i in range(size):
            end, arr[i] = self.step(data, end)

        return end, arr

    def map(self, data: BytesLike, pos: int, st: Struct, offset: int) -> Tuple[int, dict]:
        end = pos + offset
        self.check_data_length(end, data)
        size = st.unpack_from(data, pos)[0]

        ret_map = {}
        for i in range(size):
            end, key = self.step(data, end)
            end, value = self.step(data, end)

            ret_map[key] = value

        return end, ret_map

    CODES_FIXED: Dict[int, Callable[["Unpacker", BytesLike, int], Tuple[int, Any]]] = {
        # BUNDLED_STRINGS is handled separately
        NIL: lambda self, data, pos: (pos, None),
        FALSE: lambda self, data, pos: (pos, False),
        TRUE: lambda self, data, pos: (pos, True),
        BIN8: partial(bin, st=UINT8_STRUCT, offset=UINT8_STRUCT.size),
        BIN16: partial(bin, st=UINT16_STRUCT, offset=UINT16_STRUCT.size),
        BIN32: partial(bin, st=UINT32_STRUCT, offset=UINT32_STRUCT.size),
        EXT8: partial(ext, st=UINT8_STRUCT, offset=UINT8_STRUCT.size),
        EXT16: partial(ext, st=UINT16_STRUCT, offset=UINT16_STRUCT.size),
        EXT32: partial(ext, st=UINT32_STRUCT, offset=UINT32_STRUCT.size),
        FLOAT32: partial(float, st=FLOAT32_STRUCT, size=FLOAT32_STRUCT.size),
        FLOAT64: partial(float, st=FLOAT64_STRUCT, size=FLOAT64_STRUCT.size),
        UINT8: partial(int, st=UINT8_STRUCT, size=UINT8_STRUCT.size),
        UINT16: partial(int, st=UINT16_STRUCT, size=UINT16_STRUCT.size),
        UINT32: partial(int, st=UINT32_STRUCT, size=UINT32_STRUCT.size),
        UINT64: partial(int, st=UINT64_STRUCT, size=UINT64_STRUCT.size),
        INT8: partial(int, st=INT8_STRUCT, size=INT8_STRUCT.size),
        INT16: partial(int, st=INT16_STRUCT, size=INT16_STRUCT.size),
        INT32: partial(int, st=INT32_STRUCT, size=INT32_STRUCT.size),
        INT64: partial(int, st=INT64_STRUCT, size=INT64_STRUCT.size),
        FIXEXT1: partial(fixext, size=1),
        FIXEXT2: partial(fixext, size=2),
        FIXEXT4: partial(fixext, size=4),
        FIXEXT8: partial(fixext, size=8),
        FIXEXT16: partial(fixext, size=16),
        STR8: partial(str, st=UINT8_STRUCT, offset=UINT8_STRUCT.size),
        STR16: partial(str, st=UINT16_STRUCT, offset=UINT16_STRUCT.size),
        STR32: partial(str, st=UINT32_STRUCT, offset=UINT32_STRUCT.size),
        ARRAY16: partial(array, st=UINT16_STRUCT, offset=UINT16_STRUCT.size),
        ARRAY32: partial(array, st=UINT32_STRUCT, offset=UINT32_STRUCT.size),
        MAP16: partial(map, st=UINT16_STRUCT, offset=UINT16_STRUCT.size),
        MAP32: partial(map, st=UINT32_STRUCT, offset=UINT32_STRUCT.size),
    }

    # Range code points
    def positive_fixint(self, code: int, _data: BytesLike, pos: int) -> Tuple[int, int]:
        return pos, code

    def record(self, code: int, data: BytesLike, pos: int) -> Tuple[int, Union[int, dict]]:
        # if records are not used, it's just a positive fixint
        if not self.records:
            return self.positive_fixint(code, data, pos)

        identifier1 = code & 0x3F

        # TODO: if data[pos + 1] != 0, it's an extended record?

        return RecordExtension.post_unpack(self, data, pos, identifier1)

    def fixmap(self, code: int, data: BytesLike, pos: int) -> Tuple[int, dict]:
        size = code & 0x0F

        ret_map = {}
        for i in range(size):
            pos, key = self.step(data, pos)
            pos, value = self.step(data, pos)

            ret_map[key] = value

        return pos, ret_map

    def fixarray(self, code: int, data: BytesLike, pos: int) -> Tuple[int, list]:
        size = code & 0x0F

        arr = [None] * size
        for i in range(size):
            pos, arr[i] = self.step(data, pos)

        return pos, arr

    def fixstr(self, code: int, data: BytesLike, pos: int) -> Tuple[int, str]:
        size = code & 0x1F
        end = pos + size

        self.check_data_length(end, data)
        if isinstance(data, memoryview):
            return end, data[pos:end].tobytes().decode()

        return end, data[pos:end].decode()

    def negative_fixint(self, code: int, _data: BytesLike, pos: int) -> Tuple[int, int]:
        return pos, code - 0x100

    CODES_RANGES: Dict[int, Callable[["Unpacker", int, BytesLike, int], Tuple[int, Any]]] = {
        POSITIVE_FIXINT: positive_fixint,
        RECORD: record,
        FIXMAP: fixmap,
        FIXARRAY: fixarray,
        FIXSTR: fixstr,
        NEGATIVE_FIXINT: negative_fixint,
    }

    def __init__(self, enable_bundled_strings: bool = True, enable_records: bool = True):
        """
        Initialize the unpacker.

        :param enable_bundled_strings: Whether to enable bundled strings.
        :param enable_records: Whether to enable records.
        """

        self.extensions = {}
        self.register_extensions(TimestampExtension, UndefinedExtension, RecordExtension, SetExtension)

        if enable_bundled_strings:
            self.register_extensions(BundledStringsExtension)

        self.enable_bundled_strings = enable_bundled_strings
        self.records = {} if enable_records else None

        self.bundle = None

    def register_extensions(self, *exts: Type[MsgpackExtension], replace: bool = False):
        """
        Register the given extensions.

        :param exts: The extensions to register.
        :param replace: Allow replacing existing extensions.
        """

        for ext in exts:
            ext_type = ext.EXT_TYPE
            if not replace and ext_type in self.extensions:
                raise ValueError(f"Extension type {ext_type} is already registered")

            self.extensions[ext_type] = ext

    def replace_fixed_code(self, code: int, func: Callable[["Unpacker", BytesLike, int], Tuple[int, Any]]):
        """
        Replace the code with the given function.

        :param code: The code to replace.
        :param func: The function to replace it with. The function should be of the form
            `func(unpacker: Unpacker, data: BytesLike, pos: int) -> Tuple[int, Any]`
            (returning the new position and the extracted data).
        """

        if code not in self.CODES_FIXED:
            raise ValueError(f"Code {code} is not an existing fixed code point")

        self.CODES_FIXED[code] = func

    def replace_range_code(
        self, low: int, high: int, func: Callable[["Unpacker", int, BytesLike, int], Tuple[int, Any]]
    ):
        """
        Replace the range code with the given function.

        :param low: The low end of the range.
        :param high: The high end of the range.
        :param func: The function to replace it with. The function should be of the form
            `func(unpacker: Unpacker, code: int, data: BytesLike, pos: int) -> Tuple[int, Any]`
            (returning the new position and the extracted data).
        """

        if (low, high) not in self.CODES_RANGES:
            raise ValueError(f"Code range {low}-{high} is not an existing range code point")

        self.CODES_RANGES[(low, high)] = func

    def skip_bundle(self, pos: int):
        """
        Skip the bundled strings if we are at the beginning of it.
        This will also invalidate the current bundle.

        :param pos: The current position in the data.

        :return: The new position.
        """

        if self.bundle is not None and self.bundle.begin == pos:
            pos = self.bundle.end
            self.bundle = None

        return pos

    def step(self, data: BytesLike, pos: int, restrict: Union[List[int], None] = None):
        """
        Extract one item

        :param data: The data to extract from.
        :param pos: The current position in the data.
        :param restrict: The codes to restrict to.

        :return: A tuple with the new position and the extracted data.
        """

        code: int = UINT8_STRUCT.unpack_from(data, pos)[0]
        pos += 1

        if restrict is not None and not any(
            isinstance(r, int) and r == code or isinstance(r, tuple) and r[0] <= code <= r[1] for r in restrict
        ):
            restrict_str = ", ".join(f"{r[0]:02x}-{r[1]:02x}" if isinstance(r, tuple) else f"{r:02x}" for r in restrict)

            raise ValueError(f"Invalid code: {hex(code)} at position {hex(pos)} (expected {restrict_str})")

        # fixed code points
        if code in self.CODES_FIXED:
            pos, ret = self.CODES_FIXED[code](self, data, pos)

            if ret is SKIP:
                pos, ret = self.step(data, pos)
            pos = self.skip_bundle(pos)

            return pos, ret

        # special case for bundled strings
        if code == BUNDLED_STRINGS:
            return self.bundled_string(data, pos)

        # range code points
        for (low, high), func in self.CODES_RANGES.items():
            if low <= code <= high:
                pos, ret = func(self, code, data, pos)
                pos = self.skip_bundle(pos)

                return pos, ret

        raise ValueError(f"Invalid code: 0x{code:02x} at position {hex(pos)}")

    def unpack(self, data: BytesLike, multiple: bool = False, allow_remaining: bool = False):
        """
        Unpack the data from the given bytes.

        :param data: The data to unpack.
        :param multiple: Whether to unpack multiple items.
        :param allow_remaining: Whether to allow remaining data after unpacking.

        :return: The unpacked data.
        """

        pos = 0
        data = memoryview(data)
        length = len(data)

        ret_data = []
        while pos < length:
            pos, ret = self.step(data, pos)

            if not multiple:
                if not allow_remaining and pos < length:
                    raise ValueError(f"Remaining data after unpacking: {length - pos} bytes")

                return ret

            ret_data.append(ret)

        return ret_data

    def export_state(self) -> dict:
        """
        Export the state of the unpacker. Use it to save the state for error recovery or other purposes.
        Note that only dynamic variables are exported. This includes:
        - Current bundled strings.
        - Current records.

        :return: The state of the unpacker.
        """

        return {"bundle": self.bundle.copy() if self.bundle is not None else None, "records": self.records.copy()}

    def restore_state(self, state: dict, copy: bool = False):
        """
        Restore the state of the unpacker. Note that only dynamic variables are restored. This includes:
        - Current bundled strings.
        - Current records.

        :param state: The state to restore.
        :param copy: Whether to copy the state instead of using it directly.
        """

        bundle = state["bundle"]
        self.bundle = bundle.copy() if bundle is not None and copy else bundle
        self.records = state["records"].copy() if copy else state["records"]
