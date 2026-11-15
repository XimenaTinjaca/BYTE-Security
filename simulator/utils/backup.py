
import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path


def calculate_sha256(file_path: Path) -> str:
    """Calcula la huella SHA-256 de un archivo."""
    sha256 = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_backup(
    file_path: Path,
    session_id: str,
    backup_root: Path,
    sandbox_root: Path
) -> dict:
    """Crea una copia únicamente si el archivo pertenece al sandbox."""

    file_path = Path(file_path).resolve()
    sandbox_root = Path(sandbox_root).resolve()
    backup_root = Path(backup_root).resolve()

    try:
        file_path.relative_to(sandbox_root)
    except ValueError:
        return {
            "status": "rejected",
            "reason": "File outside sandbox"
        }

    try:
        backup_root.relative_to(sandbox_root)
        return {
            "status": "rejected",
            "reason": "Backup cannot be inside sandbox"
        }
    except ValueError:
        pass

    if not file_path.is_file():
        return {
            "status": "skipped",
            "reason": "File not found"
        }

    if not session_id or Path(session_id).name != session_id:
        return {
            "status": "rejected",
            "reason": "Invalid session ID"
        }

    session_dir = backup_root / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%dT%H%M%S%f")
    backup_name = f"{file_path.name}_{timestamp}"

    backup_path = session_dir / backup_name
    shutil.copy2(file_path, backup_path)

    record = {
        "session_id": session_id,
        "sandbox_root": str(sandbox_root),
        "original_path": str(file_path),
        "backup_path": str(backup_path),
        "backup_at": datetime.now().isoformat(),
        "size_bytes": backup_path.stat().st_size,
        "sha256": calculate_sha256(backup_path)
    }

    record_path = session_dir / f"{backup_name}.json"
    record_path.write_text(
        json.dumps(record, indent=4),
        encoding="utf-8"
    )

    return {"status": "success", **record}
