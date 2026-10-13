"""Run the pinned GenVM linter with all downloaded SDK artifacts kept local."""
from pathlib import Path
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from genvm_linter.validate import artifacts

artifacts.CACHE_DIR = Path(__file__).resolve().parents[1] / ".genvm-cache"
os.environ.setdefault("PYTHONUTF8", "1")
os.environ["GENVM_VERSION"] = "v0.2.16"

from genvm_linter.cli import cli  # noqa: E402

if __name__ == "__main__":
    cli()
