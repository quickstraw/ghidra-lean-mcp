"""txn() compatibility: Ghidra 12.x object handles and 11.x int handles.

Ghidra 12.1 `openTransaction` returns a DomainObjectTransaction object
(commit()/abort()); 11.x returns an int used with endTransaction(tx, commit).
Both must commit on success and roll back on error (commit=False as the
12.x-absent rollback path).
"""

from __future__ import annotations

import pytest

from ghmcp.runtime.txn import txn


class _TxObject:
    def __init__(self) -> None:
        self.committed = False
        self.aborted = False

    def commit(self) -> None:
        self.committed = True

    def abort(self) -> None:
        self.aborted = True


class _ProgramObject:
    """Ghidra 12.x shape: openTransaction returns an object; endTransaction exists."""

    def __init__(self) -> None:
        self.handle = _TxObject()
        self.end_calls: list[tuple] = []

    def openTransaction(self, desc: str) -> _TxObject:
        return self.handle

    def endTransaction(self, tx, commit: bool) -> bool:
        self.end_calls.append((tx, commit))
        return True


class _ProgramInt:
    """Ghidra 11.x shape: int handle + endTransaction(tx, commit)."""

    def __init__(self) -> None:
        self.end_calls: list[tuple] = []

    def openTransaction(self, desc: str) -> int:
        return 42

    def endTransaction(self, tx, commit: bool) -> bool:
        self.end_calls.append((tx, commit))
        return True


def test_object_flow_commits() -> None:
    p = _ProgramObject()
    with txn(p, "t"):
        pass
    assert p.handle.committed and not p.handle.aborted
    assert not p.end_calls


def test_object_flow_aborts_on_error() -> None:
    p = _ProgramObject()
    with pytest.raises(RuntimeError), txn(p, "t"):
        raise RuntimeError("boom")
    assert p.handle.aborted and not p.handle.committed


def test_int_flow_commits_and_rolls_back() -> None:
    q = _ProgramInt()
    with txn(q, "t"):
        pass
    assert q.end_calls == [(42, True)]

    q2 = _ProgramInt()
    with pytest.raises(RuntimeError), txn(q2, "t"):
        raise RuntimeError("boom")
    assert q2.end_calls == [(42, False)], "rollback via endTransaction(tx, False)"
