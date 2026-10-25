
"""Train and evaluate a URL-only phishing detection model."""

from pathlib import Path
import json
import sys
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split, GroupShuffleSplit

from url_features import FEATURE_NAMES, extract_features, parse_url


ROOT = Path(__file__).resolve().parent
DATASET = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else ROOT / "data" / "dataset_phishing.csv"
)


def make_model():
    return RandomForestClassifier(
        n_estimators=300,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )


def evaluate_model(model, X_test, y_test):
    predictions = model.predict(X_test)

    return {
        "test_rows": int(len(y_test)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_phishing": float(
            precision_score(y_test, predictions, zero_division=0)
        ),
        "recall_phishing": float(
            recall_score(y_test, predictions, zero_division=0)
        ),
        "f1_phishing": float(
            f1_score(y_test, predictions, zero_division=0)
        ),
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            output_dict=True,
            zero_division=0,
        ),
    }


def save_misclassified_urls(X_test, y_test, predictions, urls, output_path):
    """Save incorrectly classified test URLs for error analysis."""

    results = pd.DataFrame({
        "url": urls.reset_index(drop=True),
        "actual": y_test.reset_index(drop=True).map({
            0: "legitimate",
            1: "phishing",
        }),
        "predicted": pd.Series(predictions).map({
            0: "legitimate",
            1: "phishing",
        }),
    })

    errors = results[results["actual"] != results["predicted"]].copy()

    errors["error_type"] = errors.apply(
        lambda row: (
            "false_negative"
            if row["actual"] == "phishing"
            else "false_positive"
        ),
        axis=1,
    )

    errors.to_csv(output_path, index=False)

    print(f"\nMisclassified URLs: {len(errors)}")
    print(f"Saved error analysis to: {output_path}")
    print(errors["error_type"].value_counts().to_string())

    return errors


def get_hostname(url):
    """Return a normalized hostname for grouping related URLs."""
    try:
        _, _, hostname = parse_url(url)
        return hostname.lower().rstrip(".")
    except (ValueError, TypeError, AttributeError):
        return None


def main():
    if not DATASET.exists():
        raise SystemExit(f"Dataset not found: {DATASET}")

    data = pd.read_csv(DATASET)

    if not {"url", "status"}.issubset(data.columns):
        raise SystemExit("Dataset must contain 'url' and 'status' columns.")

    data = data[["url", "status"]].dropna().copy()
    data["url"] = data["url"].astype(str).str.strip()
    data["status"] = data["status"].astype(str).str.lower().str.strip()

    label_map = {
        "legitimate": 0,
        "benign": 0,
        "phishing": 1,
        "malicious": 1,
    }

    data = data[data["status"].isin(label_map)].copy()
    data["target"] = data["status"].map(label_map)

    # Remove exact duplicate URLs, ignoring surrounding whitespace.
    data = data.drop_duplicates(subset=["url"]).reset_index(drop=True)

    rows = []
    valid_urls = []
    labels = []
    invalid = 0

    print(f"Extracting URL-only features for {len(data):,} unique URLs...")

    for url, target in zip(data["url"], data["target"]):
        try:
            rows.append(extract_features(url))
            valid_urls.append(url)
            labels.append(int(target))
        except (ValueError, TypeError, AttributeError):
            invalid += 1

    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = pd.Series(labels, name="target")
    urls = pd.Series(valid_urls, name="url")

    if len(X) < 100:
        raise SystemExit("Too few valid URLs to train.")

    if y.nunique() != 2:
        raise SystemExit("The dataset must contain both classes.")

    print(f"Valid URLs: {len(X):,}")
    print(f"Skipped invalid URLs: {invalid:,}")

    # ---------------------------------------------------------
    # Evaluation 1: standard stratified random split
    # ---------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    random_model = make_model()
    random_model.fit(X_train, y_train)

    random_results = evaluate_model(random_model, X_test, y_test)

    # ---------------------------------------------------------
    # Evaluation 2: hostname-separated split
    # ---------------------------------------------------------
    hosts = urls.map(get_hostname)

    valid_mask = hosts.notna()
    X_group = X.loc[valid_mask].reset_index(drop=True)
    y_group = y.loc[valid_mask].reset_index(drop=True)
    hosts_group = hosts.loc[valid_mask].reset_index(drop=True)

    group_results = None
    group_split_note = None

    if y_group.nunique() == 2 and hosts_group.nunique() >= 2:
        splitter = GroupShuffleSplit(
            n_splits=1,
            test_size=0.20,
            random_state=42,
        )

        train_idx, test_idx = next(
            splitter.split(X_group, y_group, groups=hosts_group)
        )

        y_train_group = y_group.iloc[train_idx]
        y_test_group = y_group.iloc[test_idx]

        # Both classes must be present in each split for meaningful metrics.
        if y_train_group.nunique() == 2 and y_test_group.nunique() == 2:
            group_model = make_model()
            group_model.fit(
                X_group.iloc[train_idx],
                y_train_group,
            )

            group_results = evaluate_model(
                group_model,
                X_group.iloc[test_idx],
                y_test_group,
            )
            
            group_predictions = group_model.predict(
                X_group.iloc[test_idx]
            )

            test_urls = urls.loc[valid_mask].reset_index(drop=True).iloc[
                test_idx
            ]

            save_misclassified_urls(
                X_group.iloc[test_idx],
                y_test_group,
                group_predictions,
                test_urls,
                ROOT / "misclassified_urls.csv",
            )


            train_hosts = set(hosts_group.iloc[train_idx])
            test_hosts = set(hosts_group.iloc[test_idx])

            group_results["train_unique_hostnames"] = len(train_hosts)
            group_results["test_unique_hostnames"] = len(test_hosts)
            group_results["hostname_overlap"] = len(
                train_hosts.intersection(test_hosts)
            )
        else:
            group_split_note = (
                "Skipped: one of the hostname-separated partitions "
                "did not contain both classes."
            )
    else:
        group_split_note = (
            "Skipped: insufficient hostname or class diversity."
        )

    # ---------------------------------------------------------
    # Print evaluation results
    # ---------------------------------------------------------
    def print_results(title, results):
        print(f"\n{title}")
        print("-" * len(title))
        print(f"Accuracy:           {results['accuracy']:.3%}")
        print(f"Phishing precision: {results['precision_phishing']:.3%}")
        print(f"Phishing recall:    {results['recall_phishing']:.3%}")
        print(f"Phishing F1:        {results['f1_phishing']:.3%}")
        print("Confusion matrix (rows=true, columns=predicted):")
        print(results["confusion_matrix"])

    print_results("Random split evaluation", random_results)

    if group_results is not None:
        print_results("Hostname-separated evaluation", group_results)
        print(
            "Hostname overlap:",
            group_results["hostname_overlap"],
        )
    else:
        print("\nHostname-separated evaluation was not completed.")
        print(group_split_note)

    # ---------------------------------------------------------
    # Train deployment model on all valid URLs
    # ---------------------------------------------------------
    final_model = make_model()
    final_model.fit(X, y)

    metrics = {
        "dataset": DATASET.name,
        "unique_valid_urls": int(len(X)),
        "invalid_or_unparseable_rows": int(invalid),
        "features": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "random_split": random_results,
        "hostname_separated_split": group_results,
        "hostname_split_note": group_split_note,
        "notes": (
            "Evaluation metrics come from held-out splits of the supplied "
            "dataset. The final saved model is trained on all valid URLs. "
            "These metrics do not guarantee performance on new or future "
            "domains. Hostname separation does not necessarily separate "
            "all related domains owned by the same organization."
        ),
    }

    joblib.dump(
        {
            "model": final_model,
            "feature_names": FEATURE_NAMES,
            "class_names": {0: "legitimate", 1: "phishing"},
            "model_version": "url-only-rf-v3",
        },
        ROOT / "model.pkl",
    )

    (ROOT / "model_metrics.json").write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    print(f"\nSaved model: {ROOT / 'model.pkl'}")
    print(f"Saved metrics: {ROOT / 'model_metrics.json'}")
    print("Final model was trained on all valid URLs.")


if __name__ == "__main__":
    main()
