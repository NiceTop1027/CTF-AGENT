"""Shared code/workspace path split for reusable multi-CTF runs."""
import os
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = Path(os.environ.get("CTF_WORKSPACE", str(CODE_ROOT))).expanduser().resolve()

