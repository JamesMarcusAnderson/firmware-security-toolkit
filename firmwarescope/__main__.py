"""Entry point for `python -m firmwarescope` and for the packaged binary.

Absolute import (not relative): PyInstaller runs this file as a
top-level script, where a relative import has no parent package.
"""
import sys

from firmwarescope.main import main

if __name__ == "__main__":
    sys.exit(main())
