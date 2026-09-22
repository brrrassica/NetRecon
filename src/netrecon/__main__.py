"""Allow `python -m netrecon`."""

import sys

from .cli import main

sys.exit(main())