# src/scanning_detector.py

import argparse
import re
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


# ---------------------------
# Helpers
# ---------------------------

APACHE_CLF_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<endpoint>\S+)(?: HTTP/\d\.\d)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

def ensure_reports_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def parse_apache_log_to_df(log_path: Path) -> pd.DataFrame:
    """Parse a raw Apache access.log (Combined Log Format) into a DataFrame."""
    rows = []
    with log_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = APACHE_CLF_RE.search(line)
            if not m:
                continue
            d = m.groupdict()
            rows.append(
                {
                    "ip": d["ip"],
                    "endpoint": d["endpoint"],
                    "method": d["method"],
                    "status": d["status"],
                    "timestamp": d["time"],  # raw string for now
                }
            )
    df = pd.DataFrame(rows)

    # Parse Apache timestamp: 10/Oct/2000:13:55:36 -0700
    if not df.empty:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            format="%d/%b/%Y:%H:%M:%S %z",
            errors="coerce",
        )
    return df


def load_input(input_path: Path) -> pd.DataFrame:
    """Load either a CSV we already parsed or a raw .log file."""
    if input_path.suffix.lower() == ".csv":
        df = pd.read_csv(input_path)
        # Try to discover columns and normalize:
        # Need: ip, endpoint, and (optionally) a timestamp column.
        # Endpoint could be 'endpoint', 'url', 'path', or embedded in 'request'.
        cols = {c.lower(): c for c in df.columns}

        # IP column
        if "ip" not in cols:
            raise SystemExit("❌ Could not find 'ip' column in CSV.")

        # Endpoint column normalize
        endpoint_col = None
        for candidate in ("endpoint", "url", "path"):
            if candidate in cols:
                endpoint_col = cols[candidate]
                break

        if endpoint_col is None and "request" in cols:
            # Try to extract from request line, e.g. "GET /login HTTP/1.1"
            req_col = cols["request"]
            df["endpoint"] = df[req_col].astype(str).str.extract(r'^[A-Z]+\s+(\S+)')
            endpoint_col = "endpoint"

        if endpoint_col is None:
            raise SystemExit("❌ Could not find endpoint column (endpoint/url/path/request).")

        # Timestamp column normalize (optional)
        ts_col = None
        for candidate in ("timestamp", "time", "date", "datetime"):
            if candidate in cols:
                ts_col = cols[candidate]
                break

        # Build a minimal normalized frame
        out = pd.DataFrame({
            "ip": df[cols["ip"]].astype(str),
            "endpoint": df[endpoint_col].astype(str),
        })

        if ts_col:
            # Try best-effort parse. If your CSV has yearless dates, add a fixed year if needed.
            parsed = pd.to_datetime(df[ts_col], errors="coerce")
            if parsed.isna().all():
                # Try common Apache-style without year (rare in CSVs) or ssh-style "Aug 12 21:10:01"
                # Add a default year to be consistent
                parsed = pd.to_datetime(df[ts_col].astype(str) + " 2025", errors="coerce")
            out["timestamp"] = parsed
        else:
            out["timestamp"] = pd.NaT

        return out

    # If it's not a CSV, assume raw Apache log
    return parse_apache_log_to_df(input_path)


def detect_scanning(
    df: pd.DataFrame,
    threshold_total: int = 30,
    window_minutes: int = 5,
    threshold_window: int = 20,
) -> pd.DataFrame:
    """
    Flag IPs that request many *different* endpoints (scanners).
    Two signals:
      - unique_endpoints_total >= threshold_total
      - max unique endpoints in any N-minute window >= threshold_window (if timestamps available)
    """
    if df.empty:
        return pd.DataFrame(columns=[
            "ip", "unique_endpoints_total", f"max_unique_endpoints_{window_minutes}min",
            "first_seen", "last_seen", "is_scanner", "sample_endpoints"
        ])

    # Keep only rows with required fields
    df = df.dropna(subset=["ip", "endpoint"]).copy()

    # ----- Total unique endpoints per IP -----
    total_unique = (
        df.groupby("ip")["endpoint"]
        .nunique(dropna=True)
        .rename("unique_endpoints_total")
        .reset_index()
    )

    # ----- Time-window unique endpoints (approx via per-minute uniques) -----
    has_time = "timestamp" in df.columns and df["timestamp"].notna().any()
    if has_time:
        # Normalize to minute
        df_time = df.dropna(subset=["timestamp"]).copy()
        df_time["timestamp"] = pd.to_datetime(df_time["timestamp"], errors="coerce")
        df_time = df_time.dropna(subset=["timestamp"])

        # unique endpoints per ip per minute
        per_min = (
            df_time
            .groupby(["ip", pd.Grouper(key="timestamp", freq="1min")])["endpoint"]
            .nunique()
            .rename("unique_per_min")
            .reset_index()
        )

        # rolling sum over N minutes (time-based window)
        per_min = per_min.sort_values(["ip", "timestamp"])
        per_min["unique_per_window"] = (
            per_min
            .set_index("timestamp")
            .groupby("ip")["unique_per_min"]
            .rolling(f"{window_minutes}min")
            .sum()
            .reset_index(level=0, drop=True)
            .values
        )

        rolling_max = (
            per_min.groupby("ip")["unique_per_window"].max().rename(
                f"max_unique_endpoints_{window_minutes}min"
            )
        ).reset_index()
    else:
        # No timestamps → window metric not available
        rolling_max = pd.DataFrame({
            "ip": total_unique["ip"],
            f"max_unique_endpoints_{window_minutes}min": 0
        })

    # ----- Merge and compute flags -----
    summary = total_unique.merge(rolling_max, on="ip", how="left")

    # First/last seen (if time present)
    if has_time:
        seen = df.groupby("ip")["timestamp"].agg(["min", "max"]).reset_index()
        seen.columns = ["ip", "first_seen", "last_seen"]
        summary = summary.merge(seen, on="ip", how="left")
    else:
        summary["first_seen"] = pd.NaT
        summary["last_seen"] = pd.NaT

    # Flag scanners
    window_col = f"max_unique_endpoints_{window_minutes}min"
    summary["is_scanner"] = (summary["unique_endpoints_total"] >= threshold_total) | \
                            (summary[window_col] >= threshold_window)

    # Add a tiny sample of endpoints for context
    samples = (
        df.groupby("ip")["endpoint"]
          .apply(lambda s: ", ".join(s.value_counts().head(5).index.tolist()))
          .rename("sample_endpoints")
          .reset_index()
    )
    summary = summary.merge(samples, on="ip", how="left")

    # Sort by strongest signal
    summary = summary.sort_values(
        ["is_scanner", "unique_endpoints_total", window_col],
        ascending=[False, False, False]
    ).reset_index(drop=True)

    return summary


def plot_top(summary: pd.DataFrame, out_png: Path, top_n: int = 10, window_minutes: int = 5):
    if summary.empty:
        print("ℹ️ No data to plot.")
        return

    top = summary.head(top_n).copy()
    colors = ["red" if x else "gray" for x in top["is_scanner"]]

    plt.figure(figsize=(10, 6))
    plt.bar(top["ip"], top["unique_endpoints_total"], color=colors)
    plt.title("Top IPs by Unique Endpoints (scanners in red)")
    plt.xlabel("IP")
    plt.ylabel("Unique Endpoints (total)")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()


# ---------------------------
# Main
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="Detect scanning attacks (many unique URL requests per IP).")
    parser.add_argument("--input", default="reports/apache_parsed.csv",
                        help="Input file: CSV (parsed) or raw Apache log (e.g., logs/apache.log)")
    parser.add_argument("--threshold-total", type=int, default=30,
                        help="Flag if total unique endpoints per IP >= this value (default: 30)")
    parser.add_argument("--window-minutes", type=int, default=5,
                        help="Time window size for rolling unique endpoint sum (default: 5)")
    parser.add_argument("--threshold-window", type=int, default=20,
                        help="Flag if max unique endpoints in N-minute window >= this value (default: 20)")
    parser.add_argument("--output", default="reports/scanning.csv",
                        help="Where to save CSV summary (default: reports/scanning.csv)")
    parser.add_argument("--plot", default="reports/scanning_top_ips.png",
                        help="Where to save bar chart (default: reports/scanning_top_ips.png)")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_csv = Path(args.output)
    output_png = Path(args.plot)

    ensure_reports_dir(output_csv.parent)

    print(f"📥 Loading: {input_path}")
    df = load_input(input_path)
    if df.empty:
        print("❌ No records found. Check your input file.")
        return

    # Normalize missing timestamp column name
    if "timestamp" not in df.columns and "date" in df.columns:
        # Try to parse a 'date' column (yearless → add a default year)
        parsed = pd.to_datetime(df["date"], errors="coerce")
        if parsed.isna().all():
            parsed = pd.to_datetime(df["date"].astype(str) + " 2025", errors="coerce")
        df["timestamp"] = parsed

    print("🔎 Detecting scanners...")
    summary = detect_scanning(
        df,
        threshold_total=args.threshold_total,
        window_minutes=args.window_minutes,
        threshold_window=args.threshold_window,
    )

    summary.to_csv(output_csv, index=False)
    print(f"✅ Scanning summary saved to {output_csv}")

    plot_top(summary, output_png, top_n=10, window_minutes=args.window_minutes)
    print(f"✅ Top IPs chart saved to {output_png}")

    # Quick console preview
    print("\n📋 Preview:")
    print(summary.head(10).to_string(index=False))


if __name__ == "__main__":
    main()
