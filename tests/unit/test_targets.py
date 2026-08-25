"""Address parser table: the single convention every tool shares."""

from __future__ import annotations

import pytest

from ghmcp.platform.errors import BadTarget
from ghmcp.platform.targets import parse_address

ADDRESS_CASES = [
    ("0x8804a1c0", 0x8804A1C0),
    ("0X8804A1C0", 0x8804A1C0),
    ("8804a1c0", 0x8804A1C0),
    ("1212", 1212),
    ("976532870", 976532870),
    (" 0x1000 ", 0x1000),
    ("0x0", 0),
    ("0", 0),
]

INVALID_CASES = [
    "",
    "   ",
    "0x",
    "0xGG",
    "not-an-addr",
    "main@0x1000",
    "0x1000-0x2000",
    "0x1000+0x200",
]


@pytest.mark.parametrize("text,value", ADDRESS_CASES)
def test_parse_address(text: str, value: int):
    assert parse_address(text) == value


@pytest.mark.parametrize("text", INVALID_CASES)
def test_parse_address_invalid(text: str):
    with pytest.raises(BadTarget):
        parse_address(text)
