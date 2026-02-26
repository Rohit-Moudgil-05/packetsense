import pandas as pd
import re
import numpy as np
import json
import hashlib
from scapy.all import rdpcap, IP, TCP, UDP


# -------------------------
# Column Normalizer (reference-integrated)
# -------------------------
def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Automatically standardizes column names to a unified network schema.
    Detects case-insensitive, underscore-free, and partial matches like:
    source_ip → src_ip, ipSource → src_ip, DestinationAddress → dst_ip, etc.
    """
    field_aliases = {
        "src_ip": ["src", "source", "ip_src", "ip_source", "sourceip", "sourceaddr", "srcaddr", "sourceaddress"],
        "dst_ip": ["dst", "destination", "ip_dst", "ip_destination", "destinationip", "dstaddr", "destinationaddr", "destaddress"],
        "src_port": ["srcport", "sport", "sourceport", "tcp_sport", "udp_sport"],
        "dst_port": ["dstport", "dport", "destinationport", "tcp_dport", "udp_dport"],
        "protocol": ["proto", "protocolname", "ip_proto", "layer4protocol"],
        "timestamp": ["time", "ts", "datetime", "capturetime", "packettime", "event_time"],
        "packet_len": ["len", "length", "pktlen", "framesize", "packetsize", "bytes", "frame_length"],
        "flags": ["flag", "tcpflags", "controlflags", "tcp_flags"],
        "session_id": ["sessionid", "flowid", "connectionid", "flow_id", "session"],
        "ttl": ["ttl", "timetolive"],
    }

    def clean(col: str) -> str:
        """Normalize for comparison: lowercase, remove spaces, hyphens, and underscores"""
        return re.sub(r'[\s_\-]', '', str(col).lower())

    df = df.copy()
    df.columns = [str(col).strip() for col in df.columns]
    rename_map = {}
    for col in df.columns:
        cleaned = clean(col)
        matched = False
        for standard_name, variants in field_aliases.items():
            for variant in variants:
                v_clean = clean(variant)
                if v_clean in cleaned or cleaned in v_clean:
                    rename_map[col] = standard_name
                    matched = True
                    break
            if matched:
                break
    if rename_map:
        df = df.rename(columns=rename_map)
    return df


# -------------------------
# PCAP -> DataFrame parser (reference-integrated)
# -------------------------
def parse_pcap_to_df(packets) -> pd.DataFrame:
    data = []
    for pkt in packets:
        pkt_info = {}
        if IP in pkt:
            try:
                pkt_info["timestamp"] = pd.to_datetime(float(pkt.time), unit="s", utc=True)
            except Exception:
                pkt_info["timestamp"] = pd.NaT
            pkt_info["src_ip"] = pkt[IP].src
            pkt_info["dst_ip"] = pkt[IP].dst
            try:
                pkt_info["protocol"] = int(pkt[IP].proto)
            except Exception:
                pkt_info["protocol"] = None
        if TCP in pkt:
            pkt_info["src_port"] = pkt[TCP].sport
            pkt_info["dst_port"] = pkt[TCP].dport
            pkt_info["flags"] = str(pkt[TCP].flags)
        elif UDP in pkt:
            pkt_info["src_port"] = pkt[UDP].sport
            pkt_info["dst_port"] = pkt[UDP].dport
        pkt_info["packet_len"] = len(pkt)
        data.append(pkt_info)
    return pd.DataFrame(data)


# -------------------------
# Robust flattening & normalization helpers
# -------------------------

def safe_flatten(value):
    """Safely flatten any nested structure into a usable, 1-D scalar value (string/int).

    Handles lists, tuples, dicts, numpy arrays, NaN, None and nested mixes.
    Prefer returning meaningful scalar (ip/address/number) when possible.
    """
    try:
        # None/NaN
        if value is None:
            return "unknown"
        if isinstance(value, float) and np.isnan(value):
            return "unknown"

        # Scalars
        if isinstance(value, (str, int, float, bool)):
            return value

        # numpy scalar
        if np.isscalar(value):
            return value

        # list/tuple/set -> try to pick first scalar-like element or join
        if isinstance(value, (list, tuple, set)):
            flat = []
            for v in value:
                fv = safe_flatten(v)
                if fv != "unknown":
                    flat.append(str(fv))
            if not flat:
                return "unknown"
            # if single element, return it as scalar
            if len(flat) == 1:
                return flat[0]
            return ", ".join(flat)

        # dict -> try common keys
        if isinstance(value, dict):
            for key in ("ip", "src", "source", "address", "addr", "host", "hostname"):
                if key in value and value[key] is not None:
                    return value[key]
            # fallback to any scalar value in dict
            for k, v in value.items():
                if isinstance(v, (str, int, float)):
                    return v
            return json.dumps(value)

        # numpy arrays
        if isinstance(value, np.ndarray):
            try:
                arr = value.tolist()
                return safe_flatten(arr)
            except Exception:
                return str(value)

        # Fallback: string representation
        return str(value)

    except Exception:
        try:
            return str(value)
        except Exception:
            return "unknown"


def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Apply safe_flatten across columns — keep numeric types where sensible.

    - For columns with mostly numeric values, coerce to numeric.
    - For columns that look like IPs / ports, coerce to strings or ints as appropriate.
    """
    if df is None:
        return df

    df = df.copy()
    for col in df.columns:
        try:
            col_vals = df[col]
            # quick heuristic: if majority of values are dict/list/array, flatten
            sample = col_vals.dropna().head(50).tolist()
            if not sample:
                df[col] = col_vals.astype(str)
                continue

            non_scalars = sum(1 for v in sample if not isinstance(v, (str, int, float, bool)))
            if non_scalars > (len(sample) * 0.2):
                # apply flattening
                df[col] = col_vals.apply(safe_flatten)
            else:
                # minor sanitization: replace NaN with 'unknown'
                df[col] = col_vals.replace({np.nan: None}).apply(lambda v: safe_flatten(v) if not isinstance(v, (str, int, float, bool)) else v)

            # coerce obvious numeric columns
            if df[col].dropna().apply(lambda x: isinstance(x, (int, float))).mean() > 0.6:
                df[col] = pd.to_numeric(df[col], errors='coerce')

        except Exception:
            df[col] = df[col].astype(str)
    return df


# -------------------------
# Auto-reconstruction helpers (Auto-Reconstruction Mode)
# -------------------------

def _gen_session_id(src, dst, sport, dport, ts):
    base = f"{src}|{dst}|{sport}|{dport}|{ts}"
    return hashlib.sha1(base.encode()).hexdigest()[:12]


def reconstruct_missing_fields(df: pd.DataFrame, mode: str = "auto") -> pd.DataFrame:
    """Ensure dataframe has required network columns. If missing, reconstruct or fill defaults.

    mode: 'auto' -> fills missing values with best-effort guesses
          'strict' -> raises ValueError if required fields missing
    """
    df = df.copy()
    required = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "packet_len"]
    missing = [c for c in required if c not in df.columns]

    if mode == "strict" and missing:
        raise ValueError(f"Missing required columns: {missing}")

    # Fill missing basic columns
    if "src_ip" not in df.columns:
        df["src_ip"] = ["unknown_src"] * len(df)
    if "dst_ip" not in df.columns:
        df["dst_ip"] = ["unknown_dst"] * len(df)
    if "src_port" not in df.columns:
        df["src_port"] = 0
    if "dst_port" not in df.columns:
        df["dst_port"] = 0
    if "protocol" not in df.columns:
        # try to guess from ports if available later — set 0 for now
        df["protocol"] = 0
    if "packet_len" not in df.columns:
        # try to estimate from length of serialized row
        df["packet_len"] = df.apply(lambda row: len(json.dumps(row.to_dict())) if hasattr(row, "to_dict") else 0, axis=1)

    # Timestamp handling: if missing or all invalid -> generate monotonic timestamps
    if "timestamp" not in df.columns or df["timestamp"].isnull().all():
        now = pd.Timestamp.utcnow()
        df["timestamp"] = [now + pd.Timedelta(seconds=i) for i in range(len(df))]
    else:
        # try to coerce to datetime
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
            if df["timestamp"].isnull().all():
                now = pd.Timestamp.utcnow()
                df["timestamp"] = [now + pd.Timedelta(seconds=i) for i in range(len(df))]
        except Exception:
            now = pd.Timestamp.utcnow()
            df["timestamp"] = [now + pd.Timedelta(seconds=i) for i in range(len(df))]

    # coerce ports to numeric
    try:
        df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").fillna(0).astype(int)
    except Exception:
        df["src_port"] = 0
    try:
        df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0).astype(int)
    except Exception:
        df["dst_port"] = 0

    # protocol guess: if protocol missing (0) and ports present, map common ports
    def guess_proto(row):
        p = int(row.get("protocol", 0) or 0)
        if p and p != 0:
            return p
        srcp = int(row.get("src_port", 0) or 0)
        dstp = int(row.get("dst_port", 0) or 0)
        # common mapping: TCP=6, UDP=17, ICMP=1 (best-effort)
        for port in (srcp, dstp):
            if port in (80, 443, 8080, 22, 25, 110, 143):
                return 6
            if port in (53, 123, 161):
                return 17
        # fallback
        return 0

    df["protocol"] = df.apply(guess_proto, axis=1)

    # generate session_id if missing
    if "session_id" not in df.columns:
        df["session_id"] = df.apply(lambda r: _gen_session_id(r.get("src_ip"), r.get("dst_ip"), r.get("src_port"), r.get("dst_port"), r.get("timestamp")), axis=1)

    # ensure packet_len numeric
    try:
        df["packet_len"] = pd.to_numeric(df["packet_len"], errors="coerce").fillna(0).astype(int)
    except Exception:
        df["packet_len"] = df["packet_len"].apply(lambda v: len(str(v)))

    return df


# -------------------------
# Main loader entrypoint
# -------------------------

def load_file(uploaded, mode: str = "auto") -> pd.DataFrame:
    """Load CSV, JSONL, or PCAP and normalize columns + flatten nested cells + reconstruct missing fields.

    mode: 'auto' (default) -> auto-reconstruction
          'strict' -> raise on missing required columns
    """
    if uploaded is None:
        return None

    name = getattr(uploaded, "name", "")
    lname = str(name).lower()

    df = None
    try:
        if lname.endswith('.csv'):
            df = pd.read_csv(uploaded)
        elif lname.endswith('.jsonl') or lname.endswith('.ndjson'):
            df = pd.read_json(uploaded, lines=True)
        elif lname.endswith('.pcap') or lname.endswith('.pcapng'):
            packets = rdpcap(uploaded)
            df = parse_pcap_to_df(packets)
        else:
            # best-effort: try CSV then JSONL
            try:
                df = pd.read_csv(uploaded)
            except Exception:
                df = pd.read_json(uploaded, lines=True)
    except Exception:
        # fallback: try JSON lines
        try:
            df = pd.read_json(uploaded, lines=True)
        except Exception:
            return None

    if df is None:
        return None

    # normalize column names
    df = normalize_columns(df)

    # flatten nested cells and sanitize types
    df = normalize_dataframe(df)

    # remove duplicate columns
    if df.columns.duplicated().any():
        df = df.loc[:, ~df.columns.duplicated()]

    # reconstruct or validate required fields
    if mode not in ("auto", "strict"):
        mode = "auto"

    df = reconstruct_missing_fields(df, mode=mode)

    return df
