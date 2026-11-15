
import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path

from config import VERSION_STORE_DIR


def ensure_dirs() -> None:
    VERSION_STORE_DIR.mkdir(parents=True, exist_ok=True)


def _valid_session_id(session_id: str) -> bool:
    """Evita que el identificador permita salir del almacén."""
    return (
        isinstance(session_id, str)
        and bool(session_id)
        and session_id not in {".", ".."}
        and Path(session_id).name == session_id
        and "/" not in session_id
        and "\\" not in session_id
    )


def _calculate_sha256(file_path: Path) -> str:
    """Calcula la huella SHA-256 de un archivo."""
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _is_inside(path: Path, directory: Path) -> bool:
    """Comprueba que una ruta esté dentro de un directorio."""
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def restore_session(session_id: str) -> dict:
    """
    Restaura exclusivamente los archivos respaldados
    por la sesión indicada.
    """
    ensure_dirs()

    if not _valid_session_id(session_id):
        return {
            "session_id": session_id,
            "files_restored": 0,
            "files_failed": 0,
            "status": "failed",
            "details": [{"status": "failed", "reason": "Invalid session ID"}]
        }

    store_root = VERSION_STORE_DIR.resolve()
    session_dir = (store_root / session_id).resolve()

    if not _is_inside(session_dir, store_root) or not session_dir.is_dir():
        return {
            "session_id": session_id,
            "files_restored": 0,
            "files_failed": 0,
            "status": "failed",
            "details": [{"status": "failed", "reason": "Session backups not found"}]
        }

    records = sorted(session_dir.glob("*.json"))
    results = []
    restored = 0
    failed = 0

    # Guarda las rutas que ya fueron restauradas.
    restored_paths = set()

    for record_file in records:
        try:
            record_path = record_file.resolve()

            if not _is_inside(record_path, session_dir):
                raise ValueError("Record outside session directory")

            record = json.loads(record_path.read_text(encoding="utf-8"))

            if record.get("session_id") != session_id:
                raise ValueError("Session ID mismatch")

            sandbox_root = Path(record["sandbox_root"]).resolve()
            original_path = Path(record["original_path"]).resolve()
            backup_path = Path(record["backup_path"]).resolve()

            if not _is_inside(original_path, sandbox_root):
                raise ValueError("Original file outside sandbox")

            # Ignorar respaldos de archivos que ya terminaban en .locked.
            if original_path.name.lower().endswith(".locked"):
                continue

            # Evitar restaurar dos veces el mismo archivo.
            original_key = str(original_path).casefold()

            if original_key in restored_paths:
                continue

            if not _is_inside(backup_path, session_dir):
                raise ValueError("Backup outside session directory")

            if not backup_path.is_file():
                raise FileNotFoundError("Backup file not found")

            expected_hash = record.get("sha256")

            if not expected_hash:
                raise ValueError("Backup has no SHA-256 hash")

            actual_hash = _calculate_sha256(backup_path)

            if actual_hash != expected_hash:
                raise ValueError("Backup integrity check failed")

            # Restaurar el archivo original.
            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_path, original_path)

            # Verificar la integridad del archivo restaurado.
            restored_hash = _calculate_sha256(original_path)

            if restored_hash != expected_hash:
                raise ValueError("Restored file integrity check failed")

            # Construir la ruta correspondiente al archivo .locked.
            locked_path = original_path.with_suffix(
                original_path.suffix + ".locked"
            )

            locked_file_removed = False

            # Eliminar el archivo .locked únicamente dentro del sandbox.
            if (
                _is_inside(locked_path.resolve(), sandbox_root)
                and locked_path.is_file()
            ):
                locked_path.unlink()
                locked_file_removed = True

            results.append({
                "status": "success",
                "original_path": str(original_path),
                "restored_from": str(backup_path),
                "locked_file_removed": locked_file_removed
            })

            restored_paths.add(original_key)
            restored += 1

        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            results.append({
                "status": "failed",
                "record": record_file.name,
                "reason": str(error)
            })
            failed += 1

    status = (
        "success" if restored > 0 and failed == 0
        else "partial" if restored > 0
        else "failed"
    )

    summary = {
        "session_id": session_id,
        "restored_at": datetime.now().isoformat(),
        "files_restored": restored,
        "files_failed": failed,
        "status": status,
        "details": results
    }

    print(
        f"[recovery] Session {session_id}: "
        f"{restored} restored, {failed} failed"
    )

    return summary


def get_store_stats() -> dict:
    """Resumen del almacén de respaldos."""
    ensure_dirs()

    session_dirs = [
        directory
        for directory in VERSION_STORE_DIR.iterdir()
        if directory.is_dir()
    ]

    total_backups = sum(
        len(list(directory.glob("*.json")))
        for directory in session_dirs
    )

    return {
        "tracked_sessions": len(session_dirs),
        "total_versions": total_backups,
        "store_path": str(VERSION_STORE_DIR)
    }
