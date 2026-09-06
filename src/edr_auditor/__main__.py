"""Allow ``python -m edr_auditor`` to behave like the ``edr`` console script."""

import sys

from edr_auditor.cli import main

if __name__ == "__main__":
    sys.exit(main())