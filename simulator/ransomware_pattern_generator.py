
"""
ransomware_pattern_generator.py — safe ransomware I/O pattern simulator.

Creates a backup of each file before modifying it.
Only processes files inside the specified sandbox.
"""

import argparse
import math
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from utils.event_logger import EventLogger, make_event
from utils.backup import create_backup


LABEL = 1
XOR_KEY = 0xA5


# ─── Helpers ──────────────────────────────────────────────────────────────────

def xor_transform(data: bytes, key: int = XOR_KEY) -> bytes:
    """Reversible byte-level transformation."""
    return bytes(b ^ key for b in data)


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte."""
    if not data:
        return 0.0

    freq = [0] * 256

    for b in data:
        freq[b] += 1

    n = len(data)

    return -sum(
        (f / n) * math.log2(f / n)
        for f in freq if f > 0
    )


# ─── Per-file operation ───────────────────────────────────────────────────────

def _process_file(
    fpath: Path,
    session_id: str,
    logger: EventLogger,
    delay: float,
    sandbox_root: Path,
    backup_root: Path,
) -> None:
    """
    Process one file in this order:

    1. Create a backup of the original file.
    2. Read the original content.
    3. Transform the content.
    4. Write the transformed content.
    5. Rename the file with .locked.
    """

    try:
        # STEP 1: Create backup BEFORE modifying the file.
        backup_result = create_backup(
            fpath,
            session_id,
            backup_root,
            sandbox_root
        )

        if backup_result["status"] != "success":
            print(
                f"[backup] File skipped: {fpath} "
                f"- {backup_result}"
            )
            return

        # STEP 2: Read original content.
        ext_before = fpath.suffix
        original = fpath.read_bytes()
        size = len(original)

        ent_before = shannon_entropy(original)

        # STEP 3: Transform content.
        transformed = xor_transform(original)
        ent_after = shannon_entropy(transformed)

        # STEP 4: Register WRITE event.
        logger.log(make_event(
            operation="WRITE",
            file_path=str(fpath),
            session_id=session_id,
            label=LABEL,
            file_extension_before=ext_before,
            file_extension_after=ext_before,
            file_size_bytes=size,
            extra={
                "entropy_before": round(ent_before, 4),
                "entropy_after": round(ent_after, 4),
                "entropy_delta": round(ent_after - ent_before, 4),
            },
        ))

        # Modify the file only after the backup succeeds.
        fpath.write_bytes(transformed)

        # STEP 5: Rename file with .locked extension.
        new_ext = ext_before + ".locked"
        new_path = fpath.with_suffix(new_ext)

        logger.log(make_event(
            operation="RENAME",
            file_path=str(fpath),
            session_id=session_id,
            label=LABEL,
            file_extension_before=ext_before,
            file_extension_after=new_ext,
            file_size_bytes=size,
        ))

        fpath.rename(new_path)

        time.sleep(delay)

    except (PermissionError, FileNotFoundError, OSError) as error:
        print(f"[simulator] Could not process {fpath}: {error}")


# ─── Session runner ───────────────────────────────────────────────────────────

def run_session(
    sandbox: Path,
    session_id: str,
    log_path: Path,
    speed: float,
    max_files: int,
) -> None:

    if speed <= 0:
        raise ValueError("Speed must be greater than zero.")

    # Resolve paths to avoid relative-path ambiguity.
    sandbox = sandbox.resolve()

    # Store backups in the backend version-store directory.
    project_root = Path(__file__).resolve().parents[1]
    backup_root = project_root / "backend" / "version-store"

    if not sandbox.is_dir():
        raise ValueError(f"Sandbox directory does not exist: {sandbox}")

    delay = 1.0 / speed

    # Find files inside the sandbox.
    all_files = sorted(
        (f for f in sandbox.rglob("*") if f.is_file()),
        key=lambda p: str(p),
    )

    if max_files and max_files < len(all_files):
        all_files = all_files[:max_files]

    print(f"[ransom-pattern] {session_id}")
    print(f"  Sandbox : {sandbox}")
    print(f"  Backups : {backup_root}")
    print(f"  Files   : {len(all_files)}")
    print(f"  Speed   : {speed} files/sec")
    print(f"  XOR key : 0x{XOR_KEY:02X}")

    start = time.time()

    with EventLogger(log_path) as logger:
        for i, fpath in enumerate(all_files):

            _process_file(
                fpath,
                session_id,
                logger,
                delay,
                sandbox,
                backup_root,
            )

            if (i + 1) % 25 == 0:
                elapsed = time.time() - start
                actual = (i + 1) / elapsed if elapsed > 0 else 0

                print(
                    f"  [{i + 1:>4}/{len(all_files)}] "
                    f"{actual:.1f} files/sec"
                )

    elapsed = time.time() - start
    actual = len(all_files) / elapsed if elapsed > 0 else 0

    print(
        f"[ransom-pattern] Done. "
        f"{len(all_files)} files in {elapsed:.1f}s "
        f"→ {actual:.1f} files/sec"
    )

    print(f"  Backups saved in: {backup_root / session_id}")
    print(f"  Sandbox: {sandbox}")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "Ransomware I/O pattern simulator — "
            "safe, reversible, sandbox-only"
        )
    )

    parser.add_argument("--sandbox", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--session-id", default=None, type=str)

    parser.add_argument(
        "--speed",
        default=10.0,
        type=float,
        help="Target files/sec (default 10)"
    )

    parser.add_argument(
        "--max-files",
        default=0,
        type=int,
        help="Max files to process per session (0 = all)"
    )

    args = parser.parse_args()

    if not args.sandbox.is_dir():
        print(f"Sandbox not found: {args.sandbox}")
        sys.exit(1)

    session_id = args.session_id or f"ransom-{uuid.uuid4().hex[:8]}"

    run_session(
        args.sandbox,
        session_id,
        args.log,
        args.speed,
        args.max_files,
    )

