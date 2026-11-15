
"""
ml-model/train_behavioral.py

Behavioral ransomware detection — write-phase training.

Uses behavioral features only. Extension changes and rename events
are excluded because they are outcomes of an attack, not early signals.

Validation:
- Cross-validation uses original, unaugmented training data.
- Augmentation is applied only inside each training fold.
- The final test set is never augmented.
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.base import clone
from xgboost import XGBClassifier


FEATURE_COLS = [
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

COUNT_COLS = [
    "max_files_per_10sec",
    "unique_dirs_touched",
    "write_count",
    "read_count",
    "unique_files_touched",
]


def load(csv_path: Path):
    df = pd.read_csv(csv_path)

    if "label" not in df.columns:
        raise ValueError("The dataset must contain a 'label' column.")

    df = df[df["label"].isin([0, 1])].copy()

    if df.empty:
        raise ValueError("No valid rows with labels 0 or 1 were found.")

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    X = df[FEATURE_COLS].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    y = df["label"].astype(int)

    counts = y.value_counts()
    if len(counts) != 2 or counts.min() < 5:
        raise ValueError(
            "At least 5 samples per class are required for 5-fold CV."
        )

    print(
        f"  Dataset: {len(df)} rows | "
        f"benign={int(counts.get(0, 0))} | "
        f"ransomware={int(counts.get(1, 0))}"
    )

    return X, y


def augment(X: pd.DataFrame, std: float = 0.05) -> pd.DataFrame:
    """Add small relative Gaussian noise to training data only."""
    rng = np.random.default_rng(42)
    noise = rng.normal(0, std, X.shape)

    Xa = X.to_numpy(dtype=float) + X.abs().to_numpy(dtype=float) * noise
    result = pd.DataFrame(Xa, columns=X.columns, index=X.index)

    # Ratios remain inside their valid range.
    if "overwrite_ratio" in result:
        result["overwrite_ratio"] = result["overwrite_ratio"].clip(0, 1)

    # Sequential score is allowed to be negative.
    if "sequential_score" in result:
        result["sequential_score"] = result["sequential_score"].clip(-1, 1)

    # Counts cannot be negative and must remain integers.
    for col in COUNT_COLS:
        result[col] = result[col].clip(lower=0).round().astype(int)

    # Duration, rates and entropy delta are not forced to be positive
    # except duration and modification rate.
    for col in ["session_duration_sec", "files_modified_per_sec"]:
        result[col] = result[col].clip(lower=0)

    return result


def make_rf():
    return RandomForestClassifier(
        n_estimators=500,
        max_depth=6,
        min_samples_leaf=5,
        min_samples_split=10,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )


def make_xgb(spw=1.0):
    return XGBClassifier(
        n_estimators=300,
        max_depth=3,
        learning_rate=0.03,
        subsample=0.75,
        colsample_bytree=0.75,
        min_child_weight=5,
        reg_alpha=0.3,
        reg_lambda=2.0,
        scale_pos_weight=spw,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )


def make_iso(contamination):
    return IsolationForest(
        n_estimators=300,
        contamination=float(np.clip(contamination, 0.01, 0.49)),
        random_state=42,
        n_jobs=-1,
    )


def cv_eval(model, X, y, name, k=5):
    """
    Cross-validation with augmentation applied separately
    inside each training fold. Validation folds remain untouched.
    """
    cv = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)

    scores = {
        "accuracy": [],
        "precision": [],
        "recall": [],
        "f1": [],
    }

    for train_idx, val_idx in cv.split(X, y):
        X_fold_train = X.iloc[train_idx]
        X_fold_val = X.iloc[val_idx]
        y_fold_train = y.iloc[train_idx]
        y_fold_val = y.iloc[val_idx]

        X_fold_aug = augment(X_fold_train)

        fold_model = clone(model)
        fold_model.fit(X_fold_aug, y_fold_train)
        predictions = fold_model.predict(X_fold_val)

        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
        )

        scores["accuracy"].append(
            accuracy_score(y_fold_val, predictions)
        )
        scores["precision"].append(
            precision_score(y_fold_val, predictions, zero_division=0)
        )
        scores["recall"].append(
            recall_score(y_fold_val, predictions, zero_division=0)
        )
        scores["f1"].append(
            f1_score(y_fold_val, predictions, zero_division=0)
        )

    print(f"\n  {name} — {k}-fold CV:")

    summary = {}
    for metric, values in scores.items():
        values = np.asarray(values, dtype=float)
        mean = float(values.mean())
        std = float(values.std())

        print(f"    {metric:<12} {mean:.4f} ± {std:.4f}")
        summary[metric] = mean
        summary[f"{metric}_std"] = std

    return summary


def plot_cms(results, out_path: Path):
    fig, axes = plt.subplots(
        1, len(results),
        figsize=(5 * len(results), 4)
    )

    if len(results) == 1:
        axes = [axes]

    for ax, result in zip(axes, results):
        ConfusionMatrixDisplay(
            result["cm"],
            display_labels=["Benign", "Ransomware"],
        ).plot(ax=ax, colorbar=False, cmap="Blues")

        ax.set_title(
            f"{result['name']}\nCV F1={result['cv']['f1']:.3f}"
        )

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()

    print(f"  Saved: {out_path}")


def plot_importance(model, out_path: Path):
    importance = model.feature_importances_
    indices = np.argsort(importance)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(
        [FEATURE_COLS[i] for i in indices],
        [importance[i] for i in indices],
    )
    ax.axvline(
        importance.mean(),
        color="gray",
        linestyle="--",
        linewidth=1,
    )
    ax.set_title(
        "Feature Importances — Behavioral Detection\n"
        "(no extension features)"
    )

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()

    print(f"  Saved: {out_path}")


def run(csv_path: Path, out_dir: Path):
    print("\n" + "=" * 60)
    print("  Behavioral Ransomware Detection — Write-Phase Training")
    print(f"  Features: {len(FEATURE_COLS)} behavioral")
    print("=" * 60)

    X, y = load(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        stratify=y,
        random_state=42,
    )

    contamination = float((y_train == 1).mean())
    spw = float(
        (y_train == 0).sum() /
        max((y_train == 1).sum(), 1)
    )

    results = []

    print("\n-- Random Forest --")
    rf = make_rf()

    cv_rf = cv_eval(rf, X_train, y_train, "Random Forest")

    rf.fit(augment(X_train), y_train)
    rf_pred = rf.predict(X_test)

    results.append({
        "name": "Random Forest",
        "model": rf,
        "cv": cv_rf,
        "cm": confusion_matrix(y_test, rf_pred),
        "pred": rf_pred,
    })

    print("\n-- XGBoost --")
    xgb = make_xgb(spw)

    cv_xgb = cv_eval(xgb, X_train, y_train, "XGBoost")

    xgb.fit(augment(X_train), y_train)
    xgb_pred = xgb.predict(X_test)

    results.append({
        "name": "XGBoost",
        "model": xgb,
        "cv": cv_xgb,
        "cm": confusion_matrix(y_test, xgb_pred),
        "pred": xgb_pred,
    })

    print("\n-- Isolation Forest --")
    iso = make_iso(contamination)
    iso.fit(augment(X_train))

    iso_pred = (iso.predict(X_test) == -1).astype(int)
    iso_f1 = f1_score(y_test, iso_pred, zero_division=0)

    print(f"  Test F1: {iso_f1:.4f}")

    results.append({
        "name": "Isolation Forest",
        "model": iso,
        "cv": {"f1": iso_f1},
        "cm": confusion_matrix(y_test, iso_pred),
        "pred": iso_pred,
    })

    print("\n" + "=" * 60)
    print(f"{'Model':<24} {'CV F1':>8} {'F1 std':>8}")
    print("-" * 60)

    for result in results:
        f1 = result["cv"]["f1"]
        std = result["cv"].get("f1_std", 0.0)
        print(f"{result['name']:<24} {f1:>8.4f} {std:>8.4f}")

    print("=" * 60)

    best_sup = max(
        results[:2],
        key=lambda result: result["cv"]["f1"],
    )

    print(
        f"\nDetailed test report — {best_sup['name']}:"
    )
    print(
        classification_report(
            y_test,
            best_sup["pred"],
            target_names=["Benign", "Ransomware"],
            zero_division=0,
        )
    )

    plot_cms(
        results,
        out_dir / "plots" / "confusion_behavioral.png",
    )

    # Plot the feature importance of the selected model if supported.
    if hasattr(best_sup["model"], "feature_importances_"):
        plot_importance(
            best_sup["model"],
            out_dir / "plots" / "importance_behavioral.png",
        )

    models_dir = out_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        best_sup["model"],
        models_dir / "best_model.joblib",
    )

    with open(
        models_dir / "feature_columns.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(FEATURE_COLS, file, indent=2)

    print(f"\nSaved candidate model: {models_dir / 'best_model.joblib'}")
    print("The active backend model has NOT been modified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--features",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--out-dir",
        default=".",
        type=Path,
    )

    args = parser.parse_args()

    if not args.features.exists():
        print(f"Dataset not found: {args.features}")
        sys.exit(1)

    run(args.features, args.out_dir)
