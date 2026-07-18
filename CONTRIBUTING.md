# Contributing

Thanks for taking a look. Bypasses and new attack patterns are especially welcome.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Before opening a pull request

- Keep changes focused. One logical change per PR, not a drive-by rewrite.
- Add or update tests for any behaviour you change. CI runs `pytest` on
  Python 3.9, 3.11, and 3.13, plus the example and benchmark, so it will
  find you.
- Run `ruff check .` and `pytest -q` locally before you push.
- Found an attack that gets through? Add it to `injectguard/corpus.py` and a
  matching signal to `injectguard/signals.py`. New signals should be named and
  weighted so the verdict stays auditable. Then run the benchmark and make sure
  precision did not fall while you were raising recall.

## Reporting bugs

Open an issue with a minimal reproduction, the expected versus actual result,
and your Python version. For security issues see [SECURITY.md](SECURITY.md).
