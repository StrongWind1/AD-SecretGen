# Contributing

Thanks for your interest in AD-SecretGen.

## Development setup

The project uses [uv](https://docs.astral.sh/uv/). Install it, then:

```bash
uv sync                 # create the venv and install the package + dev tools
uv run pre-commit install   # optional: run ruff/format on commit
```

## Before you open a PR

```bash
make check              # ruff (lint + format), ty, pytest, and mkdocs --strict
```

All of these must pass. CI runs the same checks across Python 3.11–3.14.

- **Lint & format:** `ruff` with `select = ["ALL"]` and a 320-char line length. Run `make format` to auto-fix.
- **Types:** `ty` with `all = "error"`. Annotate everything.
- **Tests:** `pytest`. New behaviour needs a test. The suite mixes published known-answer vectors (`tests/test_kats.py`) with golden fixtures captured from real AD (`tests/fixtures/secrets/`).

## Conventions

- Every wire value, flag, and constant must trace to a spec section (e.g. `[MS-NLMP] 3.3.1`) or be documented as a deliberate, lab-confirmed deviation. The design rationale lives in `docs/design/`, and the Microsoft Open Specification references are in `specs/`.
- `ad_secretgen.py` is a single self-contained PEP 723 file (so it runs via `uv run` / a raw URL); keep the crypto/derivation logic clearly separated from the CLI/I/O sections within it.
- Conventional-commit style messages (`feat:`, `fix:`, `docs:`, `refactor:`, `ci:`, `chore:`).

## Reporting issues

Use the issue templates. Include the exact command, the full output, and what you expected.
