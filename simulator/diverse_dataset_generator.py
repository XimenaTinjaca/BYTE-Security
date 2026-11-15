
"""
simulator/diverse_dataset_generator.py

Genera datos sinteticos balanceados para entrenar un detector
de ransomware basado en comportamiento de escritura.

IMPORTANTE:
Los datos son simulados. No representan muestras reales de malware.
"""

import argparse
import random
from pathlib import Path

import numpy as np
import pandas as pd


FEATURES = [
    "session_duration_sec",
    "files_modified_per_sec",
    "overwrite_ratio",
    "sequential_score",
    "max_files_per_10sec",
    "unique_dirs_touched",
    "write_count",
    "read_count",
    "unique_files_touched",
    "mean_entropy_delta",
]

CONTINUOUS_FEATURES = [
    "session_duration_sec",
    "files_modified_per_sec",
    "overwrite_ratio",
    "sequential_score",
    "mean_entropy_delta",
]


def random_int(rng, low, high):
    """Entero aleatorio incluyendo low y excluyendo high."""
    return int(rng.integers(low, high))


def allocate(total, variants):
    """Distribuye registros sin perder el residuo."""
    base, remainder = divmod(total, variants)
    return [
        base + (1 if i < remainder else 0)
        for i in range(variants)
    ]


# ============================================================
# BENIGN
# ============================================================

def normal_user(n, rng):
    rows = []

    for _ in range(n):
        duration = rng.uniform(60, 180)
        writes = random_int(rng, 1, 9)
        reads = random_int(rng, 5, 21)

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.0, 0.3),
            "sequential_score": rng.uniform(-0.3, 0.35),
            "max_files_per_10sec": random_int(rng, 0, 3),
            "unique_dirs_touched": random_int(rng, 1, 3),
            "write_count": writes,
            "read_count": reads,
            "unique_files_touched": writes + reads,
            "mean_entropy_delta": rng.uniform(-0.02, 0.02),
            "label": 0,
        })

    return rows


def log_writer(n, rng):
    """Aplicaciones que sobrescriben repetidamente archivos de log."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(10, 60)
        rate = rng.uniform(5, 20)
        writes = max(1, int(rate * duration))
        unique = random_int(rng, 2, 7)

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.7, 1.0),
            "sequential_score": rng.uniform(0.3, 0.9),
            "max_files_per_10sec": int(rate * 10),
            "unique_dirs_touched": random_int(rng, 1, 3),
            "write_count": writes,
            "read_count": random_int(rng, 0, 5),
            "unique_files_touched": unique,
            "mean_entropy_delta": rng.uniform(-0.02, 0.02),
            "label": 0,
        })

    return rows


def database_backup(n, rng):
    """Copias de seguridad con escrituras secuenciales intensivas."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(5, 30)
        rate = rng.uniform(8, 25)
        writes = max(1, int(rate * duration))

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.0, 0.25),
            "sequential_score": rng.uniform(0.45, 0.95),
            "max_files_per_10sec": int(rate * 10),
            "unique_dirs_touched": random_int(rng, 1, 4),
            "write_count": writes,
            "read_count": random_int(rng, 2, 11),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(0.1, 0.5),
            "label": 0,
        })

    return rows


def media_encoder(n, rng):
    """Codificacion de video y audio con pocos archivos grandes."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(30, 300)
        writes = random_int(rng, 1, 8)

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.0, 0.25),
            "sequential_score": rng.uniform(-0.2, 0.45),
            "max_files_per_10sec": random_int(rng, 0, 3),
            "unique_dirs_touched": random_int(rng, 1, 3),
            "write_count": writes,
            "read_count": random_int(rng, 1, 6),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(0.5, 1.5),
            "label": 0,
        })

    return rows


def build_system(n, rng):
    """Compiladores e instalaciones que crean muchos archivos."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(5, 60)
        rate = rng.uniform(10, 40)
        writes = max(1, int(rate * duration))

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.0, 0.2),
            "sequential_score": rng.uniform(-0.2, 0.4),
            "max_files_per_10sec": int(rate * 10),
            "unique_dirs_touched": random_int(rng, 5, 21),
            "write_count": writes,
            "read_count": random_int(rng, 5, 31),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(-0.05, 0.1),
            "label": 0,
        })

    return rows


def short_benign_burst(n, rng):
    """
    Actividad legitima breve: aplicaciones que guardan varios
    archivos rapidamente o realizan operaciones en lote.
    """
    rows = []

    for _ in range(n):
        duration = rng.uniform(0.2, 2.0)
        writes = random_int(rng, 2, 9)
        reads = random_int(rng, 0, 5)

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.3, 1.0),
            "sequential_score": rng.uniform(-0.5, 0.9),
            "max_files_per_10sec": writes,
            "unique_dirs_touched": random_int(rng, 1, 3),
            "write_count": writes,
            "read_count": reads,
            "unique_files_touched": writes + reads,
            "mean_entropy_delta": rng.uniform(-0.02, 0.08),
            "label": 0,
        })

    return rows


# ============================================================
# RANSOMWARE
# ============================================================

def fast_ransomware(n, rng):
    """Ransomware rapido con actividad intensa."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(2, 15)
        rate = rng.uniform(15, 50)
        writes = max(1, int(rate * duration))

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.7, 1.0),
            "sequential_score": rng.uniform(0.4, 1.0),
            "max_files_per_10sec": int(rate * 10),
            "unique_dirs_touched": random_int(rng, 2, 8),
            "write_count": writes,
            "read_count": random_int(rng, 0, 9),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(-0.01, 0.08),
            "label": 1,
        })

    return rows


def slow_ransomware(n, rng):
    """Ransomware que reduce su velocidad para evadir detecciones."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(30, 120)
        rate = rng.uniform(0.5, 3.0)
        writes = max(1, int(rate * duration))

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.7, 1.0),
            "sequential_score": rng.uniform(0.2, 0.98),
            "max_files_per_10sec": random_int(rng, 2, 9),
            "unique_dirs_touched": random_int(rng, 1, 8),
            "write_count": writes,
            "read_count": random_int(rng, 0, 9),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(-0.02, 0.08),
            "label": 1,
        })

    return rows


def burst_ransomware(n, rng):
    """Ransomware que alterna periodos de actividad y pausas."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(20, 60)
        burst_rate = rng.uniform(20, 60)
        active_ratio = rng.uniform(0.25, 0.45)

        actual_rate = burst_rate * active_ratio
        writes = max(1, int(actual_rate * duration))

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.7, 1.0),
            "sequential_score": rng.uniform(0.2, 0.95),
            "max_files_per_10sec": int(burst_rate * 10),
            "unique_dirs_touched": random_int(rng, 2, 8),
            "write_count": writes,
            "read_count": random_int(rng, 0, 9),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(-0.02, 0.08),
            "label": 1,
        })

    return rows


def targeted_ransomware(n, rng):
    """Ransomware que concentra su actividad en pocas carpetas."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(5, 25)
        rate = rng.uniform(5, 20)
        writes = max(1, int(rate * duration))

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.7, 1.0),
            "sequential_score": rng.uniform(0.2, 0.98),
            "max_files_per_10sec": int(rate * 10),
            "unique_dirs_touched": random_int(rng, 1, 4),
            "write_count": writes,
            "read_count": random_int(rng, 0, 9),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(-0.02, 0.08),
            "label": 1,
        })

    return rows


def partial_ransomware(n, rng):
    """Ransomware que modifica solo una parte de los archivos."""
    rows = []

    for _ in range(n):
        duration = rng.uniform(10, 60)
        base_rate = rng.uniform(1, 8)
        active_ratio = rng.uniform(0.2, 0.4)

        actual_rate = base_rate * active_ratio
        writes = max(5, int(actual_rate * duration))

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.65, 1.0),
            "sequential_score": rng.uniform(0.15, 0.95),
            "max_files_per_10sec": random_int(rng, 3, 16),
            "unique_dirs_touched": random_int(rng, 1, 8),
            "write_count": writes,
            "read_count": random_int(rng, 0, 9),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(-0.02, 0.08),
            "label": 1,
        })

    return rows


def micro_ransomware(n, rng):
    """
    Ataques pequenos que modifican pocos archivos en poco tiempo.
    Incluye comportamientos similares a sesiones de 5 archivos.
    """
    rows = []

    for _ in range(n):
        duration = rng.uniform(0.2, 2.0)
        writes = random_int(rng, 2, 9)

        rows.append({
            "session_duration_sec": duration,
            "files_modified_per_sec": writes / duration,
            "overwrite_ratio": rng.uniform(0.8, 1.0),
            "sequential_score": rng.uniform(0.3, 1.0),
            "max_files_per_10sec": writes,
            "unique_dirs_touched": random_int(rng, 1, 3),
            "write_count": writes,
            "read_count": random_int(rng, 0, 2),
            "unique_files_touched": writes,
            "mean_entropy_delta": rng.uniform(-0.02, 0.08),
            "label": 1,
        })

    return rows


# ============================================================
# GENERACION Y VALIDACION
# ============================================================

def add_noise(df, rng):
    """Anade pequenas variaciones a las caracteristicas continuas."""
    limits = {
        "session_duration_sec": (0.1, None),
        "files_modified_per_sec": (0.0, None),
        "overwrite_ratio": (0.0, 1.0),
        "sequential_score": (-1.0, 1.0),
        "mean_entropy_delta": (-1.0, 2.0),
    }

    for col in CONTINUOUS_FEATURES:
        std = float(df[col].std())

        if not np.isfinite(std) or std == 0:
            continue

        noise = rng.normal(0, std * 0.01, len(df))
        low, high = limits[col]

        df[col] = (df[col] + noise).clip(lower=low, upper=high)

    return df


def generate(n_per_class: int, out_path: Path, seed: int = 42):
    if n_per_class < 6:
        raise ValueError("n_per_class debe ser como minimo 6.")

    rng = np.random.default_rng(seed)
    py_rng = random.Random(seed)

    # Seis escenarios por cada clase.
    counts = allocate(n_per_class, 6)

    benign_rows = (
        normal_user(counts[0], rng)
        + log_writer(counts[1], rng)
        + database_backup(counts[2], rng)
        + media_encoder(counts[3], rng)
        + build_system(counts[4], rng)
        + short_benign_burst(counts[5], rng)
    )

    ransom_rows = (
        fast_ransomware(counts[0], rng)
        + slow_ransomware(counts[1], rng)
        + burst_ransomware(counts[2], rng)
        + targeted_ransomware(counts[3], rng)
        + partial_ransomware(counts[4], rng)
        + micro_ransomware(counts[5], rng)
    )

    all_rows = benign_rows + ransom_rows
    py_rng.shuffle(all_rows)

    df = pd.DataFrame(all_rows)
    df = df[FEATURES + ["label"]]

    df = add_noise(df, rng)

    count_features = [
        "max_files_per_10sec",
        "unique_dirs_touched",
        "write_count",
        "read_count",
        "unique_files_touched",
    ]

    for col in count_features:
        df[col] = df[col].round().astype(int).clip(lower=0)

    if df[FEATURES].isnull().any().any():
        raise ValueError("El dataset contiene valores nulos.")

    if not set(df["label"].unique()).issubset({0, 1}):
        raise ValueError("Se encontraron etiquetas diferentes de 0 y 1.")

    if len(df) != n_per_class * 2:
        raise ValueError("La cantidad final de registros no coincide.")

    label_counts = df["label"].value_counts().to_dict()

    if label_counts.get(0, 0) != n_per_class:
        raise ValueError("La clase benigna no tiene el total esperado.")

    if label_counts.get(1, 0) != n_per_class:
        raise ValueError("La clase ransomware no tiene el total esperado.")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    print("\n  Dataset generado correctamente")
    print(f"  Archivo       : {out_path}")
    print(f"  Semilla       : {seed}")
    print(f"  Total         : {len(df)}")
    print(f"  Benign (0)    : {label_counts.get(0, 0)}")
    print(f"  Ransomware (1): {label_counts.get(1, 0)}")

    print("\n  Promedios por clase:")
    print(df.groupby("label")[FEATURES].mean().round(3).to_string())

    print("\n  Valores nulos:")
    print(int(df[FEATURES].isnull().sum().sum()))

    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generador de dataset conductual para BYTE Security"
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Ruta del CSV de salida",
    )

    parser.add_argument(
        "--n",
        default=250,
        type=int,
        help="Cantidad de sesiones por clase",
    )

    parser.add_argument(
        "--seed",
        default=42,
        type=int,
        help="Semilla para reproducibilidad",
    )

    args = parser.parse_args()

    generate(args.n, args.out, args.seed)
