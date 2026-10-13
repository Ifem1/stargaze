"""Keep the pinned Direct Mode SDK/runtime artifacts inside the workspace."""
from pathlib import Path
import os
import sys
import pytest

import gltest.direct.sdk_loader as sdk_loader

ROOT = Path(__file__).resolve().parents[1]
sdk_loader.CACHE_DIR = ROOT / ".gltest-cache"
STABLE_SDK = ROOT / ".genvm-cache" / "extracted" / "v0.2.16.tar"
LOCAL_SDK = ROOT / ".genvm-cache" / "extracted" / "v0.3.0-rc7.tar"
SDK_ROOT = STABLE_SDK if STABLE_SDK.is_dir() else LOCAL_SDK
os.environ["GENVM_VERSION"] = "v0.2.16" if SDK_ROOT == STABLE_SDK else "v0.3.0-rc7"


def _setup_pinned_sdk_paths(contract_path=None, version=None):
    """Use the exact official SDK bundle already checked by genvm-linter."""
    root = SDK_ROOT
    dependencies = sdk_loader.parse_contract_header(contract_path) if contract_path else {}
    runner = root / "py-genlayer" / dependencies["py-genlayer"]
    if not runner.is_dir():
        raise FileNotFoundError(f"Pinned py-genlayer SDK not found in local cache: {runner}")
    paths = [runner]
    for name, directory in (("py-lib-genlayer-std", "py-lib-genlayer-std"), ("py-lib-protobuf", "py-lib-protobuf")):
        hashes = sdk_loader.parse_runner_manifest(runner)
        digest = hashes.get(name)
        candidate = root / directory / digest if digest else None
        if candidate is not None and candidate.is_dir():
            paths.append(candidate)
    for path in reversed(paths):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    return paths


sdk_loader.setup_sdk_paths = _setup_pinned_sdk_paths

# gltest's Direct Mode loader unlinks a temporary stdin file immediately after
# dup2. Windows refuses deletion while fd 0 still holds that file; defer only
# that cleanup until the VM fixture has restored stdin.
from gltest.direct import loader as direct_loader

_pending_stdin_files = []
_inject_original = direct_loader._inject_message_to_fd0


def _inject_windows_compatible(vm):
    original_unlink = os.unlink

    def unlink_or_defer(path, *args, **kwargs):
        try:
            return original_unlink(path, *args, **kwargs)
        except PermissionError as error:
            if getattr(error, "winerror", None) == 32:
                _pending_stdin_files.append(Path(path))
                return None
            raise

    os.unlink = unlink_or_defer
    try:
        return _inject_original(vm)
    finally:
        os.unlink = original_unlink


direct_loader._inject_message_to_fd0 = _inject_windows_compatible


@pytest.fixture(autouse=True)
def cleanup_windows_stdin_files():
    # The Direct Mode loader re-imports the contract file per deployment, while
    # this SDK bundle keeps its one-contract registration in a module global.
    contracts_module = sys.modules.get("genlayer.gl.genvm_contracts")
    if contracts_module is not None:
        contracts_module.__known_contract__ = None
    yield
    if contracts_module is not None:
        contracts_module.__known_contract__ = None
    for path in _pending_stdin_files:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    _pending_stdin_files.clear()
