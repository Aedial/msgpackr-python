import json
import os
from base64 import b64decode
from pathlib import Path

import pytest

if os.environ.get("DEBUG"):
    from msgpackr.unpack_debug import Unpacker
else:
    from msgpackr.unpack import Unpacker


resources = Path(__file__).parent / "resources"
files = list(resources.glob("*.json"))


class JSONEncoder(json.JSONEncoder):
    """
    Extended JSON encoder to support bytes
    """

    def default(self, o):
        if isinstance(o, bytes):
            return o.hex()

        return super().default(o)


def dumps(e) -> str:
    """
    Shortcut to a configuration of json.dumps for consistency
    """

    return json.dumps(e, indent=4, ensure_ascii=False, cls=JSONEncoder)


def compare_lines(name: str, a: str, b: str):
    a_lines = a.splitlines()
    b_lines = b.splitlines()

    len_a = len(a_lines)
    len_b = len(b_lines)

    count = sum(a_line == b_line for a_line, b_line in zip(a_lines, b_lines))
    if len_a != len_b or count != len_a:
        raise ValueError(f"{name} mismatch: {count} on {len_a}/{len_b} lines match")
    else:
        print(f"{name} match\n")


@pytest.mark.parametrize("file", files)
def test_sanity_check(file: Path):
    print(f"Checking {file.name}")

    json_data = json.loads(file.read_text("utf-8"))
    b64_data = b64decode(file.with_suffix(".b64").read_text("utf-8"))

    unpapcker = Unpacker()
    content_doc = unpapcker.unpack(b64_data)

    json_orig = dumps(json_data)
    json_out = dumps(content_doc)
    compare_lines(file.name, json_orig, json_out)


if __name__ == "__main__":
    for f in files:
        try:
            test_sanity_check(f)
        except Exception as e:
            print(f"Error: {e}\n")
