import pandas as pd
import numpy as np


def ml_feature_profiler(df):
    required = {"src_ip", "dst_ip", "timestamp"}
    if not required.issubset(df.columns):
        return pd.DataFrame()

    flows = df.groupby(["src_ip", "dst_ip"])
    feats = []

    for (src, dst), g in flows:
        feats.append({
            "src_ip": src,
            "dst_ip": dst,
            "num_packets": len(g),
            "avg_packet_len": g["packet_len"].mean(),
            "std_packet_len": g["packet_len"].std(),
            "unique_src_ports": g["src_port"].nunique() if "src_port" in g else 0,
            "unique_dst_ports": g["dst_port"].nunique() if "dst_port" in g else 0,
            "session_duration_s": (
                (g["timestamp"].max() - g["timestamp"].min()).total_seconds()
                if pd.notna(g["timestamp"].max())
                else 0
            ),
        })

    return pd.DataFrame(feats)
