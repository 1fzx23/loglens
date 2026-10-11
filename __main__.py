"""允许 `python -m loglens` 方式运行。"""

import sys

from .loglens import main

if __name__ == "__main__":
    sys.exit(main())
