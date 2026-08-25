"""Pure function-name index helpers: precedence, bucketing, case behavior.

The precedence must mirror ghidra.listing.lookup_function (case-sensitive
exact → case-insensitive exact → first prefix), so disassemble and decompile
can never disagree on the same target.
"""

from __future__ import annotations

from ghmcp.ghidra.decomp import build_name_index, lookup_in_index


class _F:
    def __init__(self, name: str):
        self._name = name

    def getName(self):
        return self._name


def _index(names: list[str]):
    return build_name_index([(n, _F(n)) for n in names])


def test_exact_wins_over_ci_and_prefix():
    exact, buckets = _index(["Foo", "foo", "foobar"])
    assert lookup_in_index(exact, buckets, "foo") is exact["foo"]
    assert lookup_in_index(exact, buckets, "Foo") is exact["Foo"]


def test_ci_exact_wins_over_prefix():
    exact, buckets = _index(["Foo", "foobar"])
    # query 'foo': no case-sensitive exact → ci-exact 'Foo' (first in order)
    assert lookup_in_index(exact, buckets, "foo") is exact["Foo"]


def test_prefix_fallback_respects_program_order():
    exact, buckets = _index(["foo_bar", "foo_baz"])
    assert lookup_in_index(exact, buckets, "foo") is exact["foo_bar"]
    assert lookup_in_index(exact, buckets, "FOO_B") is exact["foo_bar"]


def test_case_duplicate_matches_listing_precedence():
    """[Foo, foo]: query 'foo' → exact 'foo' (not first-ci 'Foo')."""
    exact, buckets = _index(["Foo", "foo"])
    assert lookup_in_index(exact, buckets, "foo") is exact["foo"]
    # and query 'FOO' → no exact → first ci-exact 'Foo'
    assert lookup_in_index(exact, buckets, "FOO") is exact["Foo"]


def test_miss_returns_none():
    exact, buckets = _index(["start", "add2"])
    assert lookup_in_index(exact, buckets, "render") is None
    assert lookup_in_index(exact, buckets, "zzz") is None
    assert lookup_in_index(exact, buckets, "") is None


def test_bucket_distribution():
    exact, buckets = _index(["start", "add2", "apply", "a"])
    assert set(buckets) == {"st", "ad", "ap", "a"}
    assert buckets["ad"]["add2"] is exact["add2"]


def test_short_names_bucket_by_first_char():
    exact, buckets = _index(["a", "b"])
    assert lookup_in_index(exact, buckets, "a") is exact["a"]


def test_batch_plan_keeps_useful_per_fn_and_caps_targets():
    from ghmcp.ghidra.decomp import _batch_plan

    # Small batch: usable per-function budget, nothing capped.
    per_fn, cap = _batch_plan(8, 2)
    assert per_fn >= 8.0
    assert cap >= 8
    # A 64-target batch on the default pool = 32 waves: the 2.8s collapse is
    # replaced by a floor (8s) and a hard cap that defers the overflow.
    per_fn, cap = _batch_plan(64, 2)
    assert per_fn == 8.0, f"per_fn must not collapse below the floor, got {per_fn}"
    assert cap == 22, f"cap must fit wave(*90//per_fn), got {cap}"
    # Ordering sanity: the capped batch fits the schedule window (ceil(cap/wave) waves).
    schedule = -(-cap // 2) * per_fn
    assert schedule <= 90, f"schedule {schedule}s exceeds the 90s window"
    # Single-target edge.
    per_fn, cap = _batch_plan(1, 2)
    assert per_fn == 60.0 and cap >= 1
