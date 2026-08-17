"""Allow `python -m crucible` as an alias for `python -m crucible.cli`."""

from .cli import main

raise SystemExit(main())
