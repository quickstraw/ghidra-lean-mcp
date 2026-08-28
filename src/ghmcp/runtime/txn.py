"""Transaction wrapping for write operations (plan §5.1: writes are transactional,
roll back on error).

Ghidra 12.1 changed the transaction API: `openTransaction` returns a
`DomainObjectTransaction` object (`commit()`/`abort()`) instead of the 11.x
`int` handle, and `rollbackTransaction` was dropped. Both shapes are handled
here: the object API when present, otherwise the int handle with
`endTransaction(tx, commit)` — using `commit=False` as the rollback, which
exists in both generations.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def txn(program: object, description: str) -> Iterator[None]:
    """Open a transaction on a Ghidra program; commit on success, roll back on error."""
    handle = program.openTransaction(description)
    try:
        yield
    except BaseException:
        _abort(program, handle)
        raise
    else:
        _commit(program, handle)


def _commit(program: object, handle: object) -> None:
    if hasattr(handle, "commit"):
        handle.commit()
        return
    program.endTransaction(handle, True)


def _abort(program: object, handle: object) -> None:
    if hasattr(handle, "abort"):
        handle.abort()
        return
    program.endTransaction(handle, False)
