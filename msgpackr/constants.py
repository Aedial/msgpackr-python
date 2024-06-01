from struct import Struct

#: Represents a return value that should be skipped and process the next step instead.
SKIP = object()
#: Represents an undefined value (extension 0).
UNDEFINED = object()

# MessagePack format family
POSITIVE_FIXINT = (0x00, 0x3F)
RECORD = (0x40, 0x7F)
FIXMAP = (0x80, 0x8F)
FIXARRAY = (0x90, 0x9F)
FIXSTR = (0xA0, 0xBF)
NIL = 0xC0
BUNDLED_STRINGS = 0xC1  # Non-standard
FALSE = 0xC2
TRUE = 0xC3
BIN8 = 0xC4
BIN16 = 0xC5
BIN32 = 0xC6
EXT8 = 0xC7
EXT16 = 0xC8
EXT32 = 0xC9
FLOAT32 = 0xCA
FLOAT64 = 0xCB
UINT8 = 0xCC
UINT16 = 0xCD
UINT32 = 0xCE
UINT64 = 0xCF
INT8 = 0xD0
INT16 = 0xD1
INT32 = 0xD2
INT64 = 0xD3
FIXEXT1 = 0xD4
FIXEXT2 = 0xD5
FIXEXT4 = 0xD6
FIXEXT8 = 0xD7
FIXEXT16 = 0xD8
STR8 = 0xD9
STR16 = 0xDA
STR32 = 0xDB
ARRAY16 = 0xDC
ARRAY32 = 0xDD
MAP16 = 0xDE
MAP32 = 0xDF
NEGATIVE_FIXINT = (0xE0, 0xFF)

# MessagePack format groups
UINT = (POSITIVE_FIXINT, UINT8, UINT16, UINT32, UINT64)
INT = (*UINT, NEGATIVE_FIXINT, INT8, INT16, INT32, INT64)
STR = (FIXSTR, STR8, STR16, STR32)
ARRAY = (FIXARRAY, ARRAY16, ARRAY32)
MAP = (FIXMAP, MAP16, MAP32)

# Structs
UINT8_STRUCT = Struct("B")
UINT16_STRUCT = Struct(">H")
UINT32_STRUCT = Struct(">I")
UINT64_STRUCT = Struct(">Q")
INT8_STRUCT = Struct("b")
INT16_STRUCT = Struct(">h")
INT32_STRUCT = Struct(">i")
INT64_STRUCT = Struct(">q")
FLOAT32_STRUCT = Struct(">f")
FLOAT64_STRUCT = Struct(">d")
