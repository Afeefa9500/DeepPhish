
"""DeepPhish 2.0 — explainable URL and domain investigation dashboard."""

from pathlib import Path
from datetime import datetime, timezone
import json
import ipaddress
from urllib.parse import urlparse

import joblib
import pandas as pd
import streamlit as st
import plotly.express as px

from url_features import (
    extract_features,
    normalize_url,
    FEATURE_NAMES,
    PHISH_HINTS,
)
from intel import investigate_domain
import storage


ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "model.pkl"
METRICS_PATH = ROOT / "model_metrics.json"

st.set_page_config(
    page_title="DeepPhish 2.0",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

storage.init_db()

st.markdown("""
<style>
.block-container {
    padding-top: 1.6rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}
div[data-testid="stMetric"] {
    border: 1px solid rgba(128,128,128,.22);
    padding: 14px;
    border-radius: 12px;
}
.hero {
    padding: 1.3rem 1.5rem;
    border-radius: 16px;
    border: 1px solid rgba(128,128,128,.25);
    margin-bottom: 1rem;
}
.small-note {
    font-size: .88rem;
    opacity: .8;
}
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_bundle():
    if not MODEL_PATH.exists():
        return None

    try:
        bundle = joblib.load(MODEL_PATH)
        if (
            isinstance(bundle, dict)
            and bundle.get("feature_names") == FEATURE_NAMES
            and "model" in bundle
        ):
            return bundle
        return None
    except Exception:
        return None


bundle = load_bundle()


def signals_for(url, features):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    signals = []

    def add(name, severity, detail, points):
        signals.append({
            "signal": name,
            "severity": severity,
            "detail": detail,
            "points": points,
        })

    if parsed.scheme == "http":
        add(
            "HTTP instead of HTTPS",
            "Medium",
            "The URL does not use HTTPS. This is a risk indicator, "
            "not proof of phishing.",
            10,
        )

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        add(
            "IP address used as hostname",
            "High",
            "The destination uses a raw IP address rather than "
            "a conventional domain.",
            24,
        )

    if "@" in url:
        add(
            "At-sign in URL",
            "High",
            "The @ symbol can make the actual destination harder "
            "to recognize.",
            22,
        )

    if features["shortening_service"]:
        add(
            "URL shortening service",
            "Medium",
            "A shortening service can hide the eventual destination.",
            12,
        )

    if features["punycode"]:
        add(
            "Punycode / internationalized domain",
            "Medium",
            "Inspect the domain carefully for lookalike characters.",
            12,
        )

    if features["length_url"] >= 120:
        add(
            "Very long URL",
            "Medium",
            "Long URLs can conceal important path or parameter details.",
            9,
        )
    elif features["length_url"] >= 75:
        add(
            "Long URL",
            "Low",
            "The URL is longer than typical; length alone is a weak signal.",
            4,
        )

    if features["length_hostname"] >= 35:
        add(
            "Long hostname",
            "Low",
            "The hostname is unusually long.",
            4,
        )

    if features["nb_subdomains"] >= 4:
        add(
            "Many hostname labels",
            "Medium",
            "Check the registrable domain; subdomains can be controlled "
            "by the domain owner.",
            9,
        )

    if features["nb_hyphens"] >= 3:
        add(
            "Multiple hyphens",
            "Low",
            "Multiple hyphens can be used in deceptive domains, "
            "but are common on legitimate sites.",
            3,
        )

    if features["ratio_digits_url"] > 0.25:
        add(
            "High digit ratio",
            "Low",
            "A large proportion of the URL consists of digits.",
            3,
        )

    if features["suspecious_tld"]:
        add(
            "TLD heuristic match",
            "Low",
            "The TLD appears on a heuristic list. Many sites using it "
            "are legitimate.",
            4,
        )

    found = sorted(
        word for word in PHISH_HINTS if word in url.lower()
    )

    if found:
        add(
            "Phishing-lure vocabulary",
            "Medium",
            "Contains: " + ", ".join(found[:8]) + ".",
            min(12, 4 + 2 * len(found)),
        )

    if features["nb_qm"] >= 2 or features["nb_eq"] >= 5:
        add(
            "Complex query parameters",
            "Low",
            "Many query delimiters or assignments can make a URL "
            "harder to inspect.",
            3,
        )

    if not signals:
        signals.append({
            "signal": "No obvious URL red flags",
            "severity": "Info",
            "detail": "The URL structure has few of the indicators checked. "
                      "This does not mean the site is safe.",
            "points": 0,
        })

    return signals


def score_url(url, features, signals):
    model_score = None

    if bundle:
        frame = pd.DataFrame(
            [[features[name] for name in bundle["feature_names"]]],
            columns=bundle["feature_names"],
        )

        model = bundle["model"]
        classes = list(model.classes_)

        if 1 in classes:
            model_score = float(
                model.predict_proba(frame)[0][classes.index(1)]
            )

    # This is a heuristic blend, not a calibrated probability.
    heuristic = min(100, sum(signal["points"] for signal in signals))

    if model_score is None:
        risk = heuristic
    else:
        risk = round(
            0.65 * model_score * 100 + 0.35 * heuristic
        )

    level = (
        "High" if risk >= 65
        else "Elevated" if risk >= 40
        else "Guarded" if risk >= 20
        else "Low"
    )

    return risk, level, model_score, heuristic


def do_scan(raw, external):
    normalized = normalize_url(raw)
    features = extract_features(raw)
    signals = signals_for(normalized, features)

    risk, level, model_score, heuristic = score_url(
        normalized, features, signals
    )

    intel_data = None

    if external:
        with st.spinner(
            "Checking public DNS, domain registration and TLS metadata..."
        ):
            intel_data = investigate_domain(normalized)

    # Add intelligence-derived findings without overclaiming.
    if intel_data:
        rdap = intel_data.get("rdap") or {}
        age = rdap.get("age_days")

        if age is not None and age < 30:
            signals.append({
                "signal": "Recently registered domain",
                "severity": "High",
                "detail": (
                    f"RDAP reports a domain age of {age} days. "
                    "New domains are not automatically malicious."
                ),
                "points": 18,
            })
            risk = min(100, risk + 12)

        elif age is not None and age < 180:
            signals.append({
                "signal": "Relatively new domain",
                "severity": "Medium",
                "detail": (
                    f"RDAP reports a domain age of {age} days. "
                    "Treat this as context, not proof."
                ),
                "points": 8,
            })
            risk = min(100, risk + 5)

        if intel_data.get("dns") is None:
            signals.append({
                "signal": "No public DNS answer",
                "severity": "Medium",
                "detail": (
                    "No public A/AAAA answer was returned by the "
                    "DNS-over-HTTPS check. Temporary failures or "
                    "unsupported records are possible."
                ),
                "points": 8,
            })

        tls = intel_data.get("tls") or {}

        if (
            tls.get("days_until_expiry") is not None
            and tls["days_until_expiry"] < 0
        ):
            signals.append({
                "signal": "TLS certificate appears expired",
                "severity": "High",
                "detail": (
                    "The certificate expiry time is in the past. "
                    "Browser validation may fail."
                ),
                "points": 15,
            })
            risk = min(100, risk + 10)

    level = (
        "High" if risk >= 65
        else "Elevated" if risk >= 40
        else "Guarded" if risk >= 20
        else "Low"
    )

    result = (
        "Potential phishing" if level == "High"
        else "Review carefully" if level in {"Elevated", "Guarded"}
        else "No major indicators found"
    )

    record = {
        "scanned_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "url": normalized,
        "result": result,
        "risk_score": int(risk),
        "risk_level": level,
        "phishing_score": model_score,
        "heuristic_score": heuristic,
        "signals": signals,
        "intel": intel_data,
        "model_version": (bundle or {}).get(
            "model_version", "heuristic-only"
        ),
    }

    storage.save_scan(record)
    return record, features


def render_result(record, features):
    st.markdown("### Assessment")

    c1, c2, c3 = st.columns([1, 1, 1.4])

    c1.metric(
        "Combined risk score",
        f"{record['risk_score']}/100",
        record["risk_level"] + " risk",
    )

    phishing_score = record.get("phishing_score")

    c2.metric(
        "ML phishing score",
        f"{phishing_score:.1%}"
        if phishing_score is not None
        else "Unavailable",
    )

    c3.metric(
        "Signals identified",
        str(
            sum(
                1 for signal in record["signals"]
                if signal["severity"] != "Info"
            )
        ),
    )

    if record["risk_level"] == "High":
        st.error(
            "High risk — do not enter credentials or payment information."
        )
    elif record["risk_level"] == "Elevated":
        st.warning(
            "Review carefully — several risk indicators need investigation."
        )
    elif record["risk_level"] == "Guarded":
        st.info(
            "Some indicators were found. Check the details before "
            "trusting the URL."
        )
    else:
        st.success(
            "No major indicators found by this scan. "
            "This is not a safety guarantee."
        )

    st.code(record["url"], language=None)

    st.caption(
        "The combined risk score is a heuristic blend, not a calibrated "
        "probability. ML scores and signals can be wrong."
    )

    st.markdown("#### Why this result?")

    for signal in record["signals"]:
        icon = (
            "🔴" if signal["severity"] == "High"
            else "🟠" if signal["severity"] == "Medium"
            else "🟡" if signal["severity"] == "Low"
            else "ℹ️"
        )

        with st.expander(
            f"{icon} {signal['signal']} · {signal['severity']}"
        ):
            st.write(signal["detail"])

    with st.expander("URL feature details"):
        st.json(features)

    with st.expander("Domain intelligence"):
        if not record.get("intel"):
            st.write("External checks were not run for this scan.")
        else:
            intel = record["intel"]

            st.write("**DNS**")
            st.json(
                intel.get("dns") or {"status": "No public answer returned"}
            )

            st.write("**Registration (RDAP)**")
            rdap = intel.get("rdap")
            st.json(
                rdap or {
                    "status": "Unavailable",
                    "notes": intel.get("notes", []),
                }
            )

            if rdap and rdap.get("age_days") is not None:
                st.metric(
                    "Reported domain age",
                    f"{rdap['age_days']} days",
                )

            st.write("**TLS certificate**")
            st.json(intel.get("tls") or {"status": "Unavailable"})

            if intel.get("notes"):
                st.write("**Check notes**")
                for note in intel["notes"]:
                    st.caption("• " + note)

    st.download_button(
        "Download investigation report (JSON)",
        json.dumps(record, indent=2),
        file_name="deepphish_report.json",
        mime="application/json",
    )


# Sidebar navigation
page = st.sidebar.radio(
    "Navigate",
    ["Scan URL", "Dashboard", "Batch scan", "Model & limitations", "About"],
)

st.sidebar.markdown("---")
st.sidebar.caption("DeepPhish 2.0 · local prototype")
st.sidebar.caption(
    "External checks are optional and only query public metadata services."
)


if page == "Scan URL":
    st.markdown(
        '<div class="hero"><h1>DeepPhish 2.0</h1>'
        '<p>Explainable URL risk screening and optional domain investigation.</p>'
        '<p class="small-note">Submitted URLs are not opened and page '
        'content is never downloaded.</p></div>',
        unsafe_allow_html=True,
    )

    with st.form("scan_form"):
        url_input = st.text_input(
            "URL to investigate",
            placeholder="https://example.com/login",
        )

        external = st.toggle(
            "Run external domain checks (DNS, RDAP registration, TLS)",
            value=True,
        )

        st.caption(
            "External checks contact public metadata services. "
            "They do not visit the submitted web page."
        )

        submitted = st.form_submit_button(
            "Analyze URL",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        try:
            record, features = do_scan(url_input, external)
            st.session_state["last_record"] = record
            st.session_state["last_features"] = features
        except ValueError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"Scan could not complete: {exc}")

    if st.session_state.get("last_record"):
        render_result(
            st.session_state["last_record"],
            st.session_state["last_features"],
        )


elif page == "Dashboard":
    st.title("Security dashboard")

    scans = storage.get_scans(1000)

    if not scans:
        st.info("No saved scans yet. Run your first scan on the Scan URL page.")
    else:
        df = pd.DataFrame(scans)

        total = len(df)
        high = int((df["risk_score"] >= 65).sum())
        avg = float(df["risk_score"].mean())

        a, b, c = st.columns(3)
        a.metric("Saved scans", total)
        b.metric("High-risk scans", high)
        c.metric("Average risk score", f"{avg:.1f}/100")

        chart_df = df.copy()
        chart_df["scanned_at"] = pd.to_datetime(
            chart_df["scanned_at"], errors="coerce"
        )

        daily = (
            chart_df.dropna(subset=["scanned_at"])
            .assign(day=lambda x: x["scanned_at"].dt.date.astype(str))
            .groupby("day")
            .size()
            .reset_index(name="Scans")
        )

        if len(daily):
            st.plotly_chart(
                px.line(
                    daily,
                    x="day",
                    y="Scans",
                    markers=True,
                    title="Scans over time",
                ),
                use_container_width=True,
            )

        hist = (
            chart_df.assign(
                RiskBand=chart_df["risk_score"].apply(
                    lambda value: (
                        "High" if value >= 65
                        else "Elevated" if value >= 40
                        else "Guarded" if value >= 20
                        else "Low"
                    )
                )
            )
            .groupby("RiskBand")
            .size()
            .reset_index(name="Scans")
        )

        st.plotly_chart(
            px.bar(hist, x="RiskBand", y="Scans", title="Saved scan risk distribution"),
            use_container_width=True,
        )

        st.subheader("Recent scans")

        show = df[
            ["id", "scanned_at", "url", "result", "risk_score", "model_version"]
        ].copy()

        show["scanned_at"] = show["scanned_at"].astype(str)

        st.dataframe(show, use_container_width=True, hide_index=True)

        csv = show.to_csv(index=False).encode("utf-8")

        st.download_button(
            "Export scan history (CSV)",
            csv,
            file_name="deepphish_scan_history.csv",
            mime="text/csv",
        )

        json_data = json.dumps(scans, indent=2)

        st.download_button(
            "Export scan history (JSON)",
            json_data,
            file_name="deepphish_scan_history.json",
            mime="application/json",
        )

        with st.expander("Delete history"):
            st.warning("This permanently clears locally stored scan history.")

            if st.button("Clear all scan history", type="secondary"):
                storage.clear_scans()
                st.success("History cleared.")
                st.rerun()


elif page == "Batch scan":
    st.title("Batch URL scan")

    st.write(
        "Upload a CSV with a column named `url`, or paste one URL per line. "
        "Each URL is analyzed locally; external intelligence checks are not "
        "run for batch scans."
    )

    upload = st.file_uploader("Upload URL CSV", type=["csv"])

    pasted = st.text_area(
        "Or paste URLs (one per line)",
        height=150,
        placeholder="https://example.com\nhttps://example.org/login",
    )

    urls = []

    if upload:
        try:
            batch_df = pd.read_csv(upload)

            if "url" not in batch_df.columns:
                st.error("CSV must include a column named `url`.")
            else:
                urls = batch_df["url"].dropna().astype(str).tolist()

        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")

    elif pasted.strip():
        urls = [
            line.strip()
            for line in pasted.splitlines()
            if line.strip()
        ]

    if urls:
        st.caption(
            f"{len(urls)} URL(s) queued. A maximum of 500 is allowed per batch."
        )

        if len(urls) > 500:
            st.warning("Only the first 500 URLs will be processed.")
            urls = urls[:500]

        if st.button("Run batch scan", type="primary"):
            output = []
            progress = st.progress(0)

            for i, raw in enumerate(urls):
                try:
                    normalized = normalize_url(raw)
                    features = extract_features(raw)
                    signals = signals_for(normalized, features)

                    risk, level, probability, heuristic = score_url(
                        normalized, features, signals
                    )

                    output.append({
                        "url": normalized,
                        "risk_score": risk,
                        "risk_level": level,
                        "model_phishing_score": probability,
                        "heuristic_score": heuristic,
                        "signals": "; ".join(
                            signal["signal"] for signal in signals
                        ),
                    })

                    storage.save_scan({
                        "scanned_at": datetime.now(timezone.utc).isoformat(
                            timespec="seconds"
                        ),
                        "url": normalized,
                        "result": (
                            "Potential phishing" if level == "High"
                            else "Review carefully"
                            if level in {"Elevated", "Guarded"}
                            else "No major indicators found"
                        ),
                        "risk_score": int(risk),
                        "risk_level": level,
                        "phishing_score": probability,
                        "heuristic_score": heuristic,
                        "signals": signals,
                        "intel": None,
                        "model_version": (bundle or {}).get(
                            "model_version", "heuristic-only"
                        ),
                    })

                except Exception as exc:
                    output.append({
                        "url": raw,
                        "risk_score": None,
                        "risk_level": "Invalid URL",
                        "model_phishing_score": None,
                        "heuristic_score": None,
                        "signals": str(exc),
                    })

                progress.progress((i + 1) / len(urls))

            st.session_state["batch_results"] = output

    if st.session_state.get("batch_results"):
        results = pd.DataFrame(st.session_state["batch_results"])

        st.dataframe(results, use_container_width=True, hide_index=True)

        st.download_button(
            "Download batch results (CSV)",
            results.to_csv(index=False).encode("utf-8"),
            file_name="deepphish_batch_results.csv",
            mime="text/csv",
        )

        st.download_button(
            "Download batch results (JSON)",
            results.to_json(orient="records", indent=2),
            file_name="deepphish_batch_results.json",
            mime="application/json",
        )


elif page == "Model & limitations":
    st.title("Model performance and limitations")

    if METRICS_PATH.exists():
        try:
            metrics = json.loads(
                METRICS_PATH.read_text(encoding="utf-8")
            )

            # Support both the old flat format and the new nested format.
            random_metrics = metrics.get("random_split", metrics)

            accuracy = random_metrics.get("accuracy")
            precision = random_metrics.get("precision_phishing")
            recall = random_metrics.get("recall_phishing")
            f1 = random_metrics.get("f1_phishing")
            confusion = random_metrics.get("confusion_matrix")

            a, b, c, d = st.columns(4)

            a.metric(
                "Accuracy",
                f"{accuracy:.2%}" if accuracy is not None else "N/A",
            )
            b.metric(
                "Phishing precision",
                f"{precision:.2%}" if precision is not None else "N/A",
            )
            c.metric(
                "Phishing recall",
                f"{recall:.2%}" if recall is not None else "N/A",
            )
            d.metric(
                "Phishing F1",
                f"{f1:.2%}" if f1 is not None else "N/A",
            )

            if confusion is not None:
                st.write(
                    "Confusion matrix: rows are actual "
                    "[legitimate, phishing]; columns are predicted "
                    "[legitimate, phishing]."
                )

                st.dataframe(
                    pd.DataFrame(
                        confusion,
                        index=["Actual legitimate", "Actual phishing"],
                        columns=[
                            "Predicted legitimate",
                            "Predicted phishing",
                        ],
                    ),
                    use_container_width=True,
                )

            # Display hostname-separated metrics when the training script
            # has generated them.
            hostname_metrics = metrics.get("hostname_separated_split")

            if hostname_metrics:
                st.subheader("Hostname-separated evaluation")

                a, b, c, d = st.columns(4)

                a.metric(
                    "Accuracy",
                    f"{hostname_metrics['accuracy']:.2%}"
                    if hostname_metrics.get("accuracy") is not None
                    else "N/A",
                )
                b.metric(
                    "Phishing precision",
                    f"{hostname_metrics['precision_phishing']:.2%}"
                    if hostname_metrics.get("precision_phishing") is not None
                    else "N/A",
                )
                c.metric(
                    "Phishing recall",
                    f"{hostname_metrics['recall_phishing']:.2%}"
                    if hostname_metrics.get("recall_phishing") is not None
                    else "N/A",
                )
                d.metric(
                    "Phishing F1",
                    f"{hostname_metrics['f1_phishing']:.2%}"
                    if hostname_metrics.get("f1_phishing") is not None
                    else "N/A",
                )

                if hostname_metrics.get("confusion_matrix") is not None:
                    st.write("Hostname-separated confusion matrix:")

                    st.dataframe(
                        pd.DataFrame(
                            hostname_metrics["confusion_matrix"],
                            index=[
                                "Actual legitimate",
                                "Actual phishing",
                            ],
                            columns=[
                                "Predicted legitimate",
                                "Predicted phishing",
                            ],
                        ),
                        use_container_width=True,
                    )

                st.caption(
                    "This evaluation tests generalization to hostnames "
                    "excluded from the training partition. It does not "
                    "guarantee performance on newly collected phishing URLs."
                )

            st.caption(metrics.get("notes", ""))

        except (json.JSONDecodeError, OSError, TypeError, ValueError, KeyError) as exc:
            st.error(f"Could not read model metrics: {exc}")

    else:
        st.warning("Model metrics not found. Run `python train.py`.")

    st.subheader("How the score works")

    st.write(
        "The displayed combined score blends the model's phishing-class "
        "score with a transparent URL-heuristic score. It is a prioritization "
        "aid, not a calibrated probability. External metadata may add context "
        "and adjust the final risk band."
    )

    st.subheader("Known limitations")

    st.markdown("""
    - URL-only features cannot inspect page source, page behavior,
      redirects, forms, or brand impersonation.
    - Domain registration and TLS metadata can be missing, rate-limited,
      or privacy-redacted.
    - A valid HTTPS certificate only encrypts a connection; it does not
      prove that a site is trustworthy.
    - New domains are not necessarily malicious; old domains can be
      compromised.
    - Metrics come from the supplied dataset and may not represent
      performance on unseen or newly created phishing domains.
    - Do not enter credentials into suspicious websites based on this
      tool's result alone.
    """)


elif page == "About":
    st.title("About DeepPhish")

    st.write(
        "DeepPhish is a student security project that combines URL-derived "
        "machine-learning features, explainable heuristic signals, optional "
        "public domain metadata checks, batch scanning, local scan history, "
        "and downloadable reports."
    )

    st.subheader("Privacy by design")

    st.markdown("""
    - Submitted pages are never fetched or executed.
    - Optional checks query Cloudflare DNS-over-HTTPS and public RDAP
      endpoints; HTTPS URLs can also trigger a TLS handshake to the domain
      after public-IP validation.
    - Scan history is stored in a local SQLite file
      (`deepphish_history.db`) in this project folder.
    - Do not scan private URLs or submit secrets in query strings.
      Avoid sharing exported reports if they contain sensitive URLs.
    """)

    st.subheader("Recommended future work")

    st.write(
        "For production-grade reputation checks, integrate a "
        "threat-intelligence provider with an API key, add "
        "domain-separated and time-separated validation, and deploy behind "
        "a managed service with authentication and retention controls."
    )
