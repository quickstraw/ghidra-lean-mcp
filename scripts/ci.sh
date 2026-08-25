#!/usr/bin/env bash
# ghmcp CI: lint, layering, unit + contract tests, docs staleness.
set -euo pipefail

uv sync --locked
uv run ruff check src tests
uv run import-linter lint --config pyproject.toml
uv run pytest tests/unit tests/contract

# Docs must be regenerated from the registry (CI fails if stale).
uv run ghmcp docs
if ! git diff --exit-code -- docs/tools.md; then
  echo "docs/tools.md is stale — run 'uv run ghmcp docs' and commit the result" >&2
  exit 1
fi
