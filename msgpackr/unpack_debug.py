from functools import partial
from logging import Logger
from typing import Union

from msgpackr.constants import *
from msgpackr.unpack import Unpacker as UnpackerBase

BytesLike = Union[bytes, bytearray, memoryview]


def attach_logger(
    cls=None,
    logger: Union[Logger, None] = None,
    log_pos: bool = False,
    log_func: bool = False,
    log_ext: bool = False,
    log_bundle: bool = False,
    log_return: bool = False,
):
    """
    Attach a logger to the unpacker.

    :param cls: The class to attach the logger to.
    :param logger: The logger to attach. If None, the logger will print to stdout.
    :param log_pos: Whether to log the position.
    :param log_func: Whether to log the function.
    :param log_ext: Whether to log the extension type.
    :param log_bundle: Whether to log the bundled strings.
    :param log_return: Whether to log the return value.
    """

    def inner(inner_cls):
        def print_log(msg):
            if logger is None:
                print(msg)
            else:
                logger.info(msg)

        def get_code_name(code: int) -> str:
            if code in inner_cls.CODES_FIXED:
                return inner_cls.NAMES[code] + f" (0x{code:02x})"

            for (low, high), func in inner_cls.CODES_RANGES.items():
                if low <= code <= high:
                    return inner_cls.NAMES_RANGE[(low, high)] + f" (0x{code:02x})"

            return f"<{code:02x}>"

        step_func = inner_cls.step

        def step_wrapper(self, data, pos, *args, **kwargs):
            code = UINT8_STRUCT.unpack_from(data, pos)[0]

            msg = ""
            if log_pos:
                msg = f"{hex(pos)}: "

            if log_func:
                msg += f"{get_code_name(code)}"

            if log_ext:
                if code in (FIXEXT1, FIXEXT2, FIXEXT4, FIXEXT8, FIXEXT16, EXT8, EXT16, EXT32):
                    ext_type = data[pos + 1]
                    msg += (" | " if msg else "") + f"Ext{ext_type}"

            if log_bundle:
                msg += (" | " if msg else "") + f"Bundle: {self.bundle}"

            if msg:
                print_log(msg)

            i, ret = step_func(self, data, pos, *args, **kwargs)

            if log_return:
                print_log(f"    -> {ret}")

            return i, ret

        inner_cls.step = step_wrapper

        return inner_cls

    return inner if cls is None else inner(cls)


def array(self, data: BytesLike, pos: int, st: Struct, offset: int):
    end = pos + offset
    self.check_data_length(end, data)
    size = st.unpack_from(data, pos)[0]

    arr = [None] * size
    for i in range(size):
        end, arr[i] = self.step(data, end)

        print(f"   => {i+1}/{size}: {arr[i]}")

    return end, arr


def fixarray(self, code: int, data: BytesLike, pos: int):
    size = code & 0x0F

    arr = [None] * size
    for i in range(size):
        pos, arr[i] = self.step(data, pos)

        print(f"   => {i+1}/{size}: {arr[i]}")

    return pos, arr


def fixmap(self, code: int, data: BytesLike, pos: int):
    size = code & 0x0F

    ret_map = {}
    for i in range(size):
        pos, key = self.step(data, pos)
        pos, value = self.step(data, pos)

        print(f"   => {key} ({i+1}/{size}): {value}")

        ret_map[key] = value

    return pos, ret_map


def map_func(self, data: BytesLike, pos: int, st: Struct, offset: int):
    end = pos + offset
    self.check_data_length(end, data)
    size = st.unpack_from(data, pos)[0]

    ret_map = {}
    for i in range(size):
        end, key = self.step(data, end)
        end, value = self.step(data, end)

        print(f"   => {key} ({i+1}/{size}): {value}")

        ret_map[key] = value

    return end, ret_map


@attach_logger(log_pos=True, log_func=True, log_ext=True, log_bundle=True, log_return=True)
class Unpacker(UnpackerBase):
    NAMES = {
        NIL: "None",
        BUNDLED_STRINGS: "Bundled Strings",
        FALSE: "False",
        TRUE: "True",
        BIN8: "bin8",
        BIN16: "bin16",
        BIN32: "bin32",
        EXT8: "ext8",
        EXT16: "ext16",
        EXT32: "ext32",
        FLOAT32: "float32",
        FLOAT64: "Ffloat64",
        UINT8: "uint8",
        UINT16: "uint16",
        UINT32: "uint32",
        UINT64: "uint64",
        INT8: "int8",
        INT16: "int16",
        INT32: "int32",
        INT64: "int64",
        FIXEXT1: "fixext1",
        FIXEXT2: "fixext2",
        FIXEXT4: "fixext4",
        FIXEXT8: "fixext8",
        FIXEXT16: "fixext16",
        STR8: "str8",
        STR16: "str16",
        STR32: "str32",
        ARRAY16: "array16",
        ARRAY32: "array32",
        MAP16: "map16",
        MAP32: "map32",
    }

    NAMES_RANGE = {
        POSITIVE_FIXINT: "pos fixint",
        RECORD: "record",
        FIXMAP: "fixmap",
        FIXARRAY: "fixarray",
        FIXSTR: "fixstr",
        NEGATIVE_FIXINT: "neg fixint",
    }

    def __init__(self, enable_bundled_strings: bool = True, enable_records: bool = True):
        """
        Initialize the unpacker.

        :param enable_bundled_strings: Whether to enable bundled strings.
        :param enable_records: Whether to enable records.
        """

        super().__init__(enable_bundled_strings, enable_records)

        self.replace_fixed_code(ARRAY16, partial(array, st=UINT16_STRUCT, offset=UINT16_STRUCT.size))
        self.replace_fixed_code(ARRAY32, partial(array, st=UINT32_STRUCT, offset=UINT32_STRUCT.size))
        self.replace_fixed_code(MAP16, partial(map_func, st=UINT16_STRUCT, offset=UINT16_STRUCT.size))
        self.replace_fixed_code(MAP32, partial(map_func, st=UINT32_STRUCT, offset=UINT32_STRUCT.size))

        self.replace_range_code(FIXARRAY[0], FIXARRAY[1], fixarray)  # type: ignore
        self.replace_range_code(FIXMAP[0], FIXMAP[1], fixmap)  # type: ignore
