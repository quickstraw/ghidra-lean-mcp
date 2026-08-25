"""Transaction wrapping for write operations (plan §5.1: writes are transactional,
roll back on error)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def txn(program: object, description: str) -> Iterator[None]:
    """Open a transaction on a Ghidra program; commit on success, roll back on error."""
    tx_id = program.openTransaction(description)
    try:
        yield
    except BaseException:
        program.rollbackTransaction(tx_id)
        raise
    else:
        program.endTransaction(tx_id, True)
