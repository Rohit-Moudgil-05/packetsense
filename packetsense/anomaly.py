import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler


def anomaly_scoring(features):
    if features.empty:
        return features

    df = features.copy()
    numeric_cols = [
        "num_packets",
        "avg_packet_len",
        "std_packet_len",
        "session_duration_s"
    ]

    scaler = MinMaxScaler()
    df[numeric_cols] = scaler.fit_transform(df[numeric_cols].fillna(0))

    df["risk_score"] = (
        df["num_packets"] * 0.4 +
        df["avg_packet_len"] * 0.2 +
        df["std_packet_len"] * 0.2 +
        df["session_duration_s"] * 0.2
    )

    df["risk_level"] = pd.cut(
        df["risk_score"],
        bins=[0, 0.3, 0.6, 1.0],
        labels=["Low", "Medium", "High"]
    )

    return df
