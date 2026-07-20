"""Module entrypoint used by the sandbox runtime contract."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
