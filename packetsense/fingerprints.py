import pandas as pd
from collections import defaultdict


def build_fingerprints(df):
    if "src_ip" not in df or "packet_len" not in df:
        return pd.DataFrame()

    fingerprints = defaultdict(lambda: {
        "avg_packet_size": 0,
        "unique_ports": set(),
        "packet_count": 0,
        "device_type": "Unknown"
    })

    for _, row in df.iterrows():
        ip = row["src_ip"]
        fingerprints[ip]["packet_count"] += 1
        fingerprints[ip]["avg_packet_size"] += row["packet_len"]

        if "src_port" in row:
            fingerprints[ip]["unique_ports"].add(row["src_port"])

    rows = []
    for ip, data in fingerprints.items():
        avg_size = data["avg_packet_size"] / max(data["packet_count"], 1)
        port_count = len(data["unique_ports"])

        # Simple device fingerprinting heuristics
        if port_count < 3 and avg_size < 200:
            dtype = "PLC / ICS Device"
        elif port_count > 50:
            dtype = "Workstation"
        else:
            dtype = "Generic Device"

        rows.append({
            "ip": ip,
            "packet_count": data["packet_count"],
            "avg_packet_size": avg_size,
            "unique_ports": port_count,
            "device_type": dtype
        })

    return pd.DataFrame(rows)
