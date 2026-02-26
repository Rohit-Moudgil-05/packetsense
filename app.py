"""
PacketSense – Modular Product Edition
Production-optimized Streamlit UI
"""

import os
import pandas as pd
import plotly.express as px
import streamlit as st

# Internal modules
from packetsense.loader import load_file
from packetsense.profiler import ml_feature_profiler
from packetsense.anomaly import anomaly_scoring
from packetsense.rule_engine import RuleEngine
from packetsense.realtime import start_sniffer
from packetsense.exports import write_alert
from packetsense.license import is_valid
from packetsense.eda import (
    eda_profiler,
    network_graph,
    generate_report,
    geoip_map,
    threat_intel_lookup_ui,
    flow_clustering_ui
)

st.set_page_config(page_title="PacketSense", layout="wide")
st.title("PacketSense – Modular Product Edition")

# =========================================================
# CACHING LAYER
# =========================================================

@st.cache_data(show_spinner=False)
def cached_load_file(file):
    return load_file(file)

@st.cache_data(show_spinner=False)
def cached_ml_features(df):
    return ml_feature_profiler(df)

@st.cache_data(show_spinner=False)
def cached_anomaly(df):
    return anomaly_scoring(df)

@st.cache_resource
def get_engine():
    return RuleEngine(rules_dir="rules")

# =========================================================
# SAFE DATAFRAME FOR ARROW
# =========================================================

def make_arrow_safe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in df.columns:
        if df[col].dtype == "object":
            df[col] = df[col].astype(str)
    return df

# =========================================================
# LICENSE
# =========================================================

if not is_valid():
    st.warning("⚠️ License key missing or invalid. Place a valid key in license.key.")

engine = get_engine()

# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.markdown("### Real-Time Mode")
realtime_mode = st.sidebar.checkbox("Enable real-time sniff (demo)")
iface = st.sidebar.text_input("Interface", value="eth0")
duration = st.sidebar.number_input("Duration (seconds)", min_value=0, value=30)

st.sidebar.markdown("### Rule Engine")
if st.sidebar.button("Reload rules"):
    engine.load_rules()
    st.sidebar.success("Rules reloaded")

# =========================================================
# FILE UPLOAD
# =========================================================

uploaded_file = st.file_uploader(
    "Upload PCAP, CSV, or JSONL file (Recommended < 50MB on free tier)",
    type=["pcap", "csv", "jsonl"]
)

if uploaded_file:

    if uploaded_file.name.endswith(".pcap"):
        st.info("⚠️ PCAP parsing is slower due to packet decoding.")

    progress = st.progress(0)

    with st.spinner("Processing file..."):
        df = cached_load_file(uploaded_file)
        progress.progress(30)

    if df is None or df.empty:
        st.error("Failed to load or empty dataset.")
        st.stop()

    st.success("File loaded successfully ✅")

    tabs = st.tabs([
        "Numerical",
        "Categorical",
        "Temporal",
        "Attack Profiler",
        "ML Features",
        "Network Graph",
        "EDA",
        "PDF",
        "GeoIP",
        "Threat Intel",
        "Anomaly",
        "Clustering",
        "Rule Matches"
    ])

    # =====================================================
    # NUMERICAL
    # =====================================================
    with tabs[0]:
        try:
            desc = df.describe()
            st.dataframe(make_arrow_safe(desc), use_container_width=True)
        except:
            st.info("No numerical columns found.")

    # =====================================================
    # CATEGORICAL
    # =====================================================
    with tabs[1]:
        cat_df = df.select_dtypes(include="object")
        if cat_df.empty:
            st.info("No categorical data.")
        else:
            st.dataframe(make_arrow_safe(cat_df.head(50)), use_container_width=True)

    # =====================================================
    # TEMPORAL
    # =====================================================
    with tabs[2]:
        if "timestamp" in df.columns:
            temp_df = df.copy()
            temp_df["timestamp"] = pd.to_datetime(temp_df["timestamp"], errors="coerce")
            temp_df = temp_df.dropna(subset=["timestamp"])
            ts = temp_df.groupby(pd.Grouper(key="timestamp", freq="1Min")).size()

            if ts.empty or len(ts) <= 1:
                st.warning("Not enough timestamp variation for graph.")
            else:
                fig = px.line(ts, title="Packets Over Time")
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No timestamp column available.")

    # =====================================================
    # ATTACK PROFILER
    # =====================================================
    with tabs[3]:
        if "src_ip" not in df.columns:
            st.warning("Source IP missing.")
        else:
            stats = df["src_ip"].astype(str).value_counts().reset_index()
            stats.columns = ["src_ip", "packet_count"]
            st.dataframe(make_arrow_safe(stats.head(20)), use_container_width=True)

    # =====================================================
    # ML FEATURES
    # =====================================================
    with tabs[4]:
        with st.spinner("Extracting ML features..."):
            features_df = cached_ml_features(df)
            progress.progress(60)

        if features_df.empty:
            st.warning("No ML features extracted.")
        else:
            st.session_state["features_df"] = features_df
            st.dataframe(make_arrow_safe(features_df.head(50)), use_container_width=True)

    # =====================================================
    # NETWORK GRAPH
    # =====================================================
    with tabs[5]:
        try:
            network_graph(df)
        except Exception as e:
            st.error(f"Graph error: {e}")

    # =====================================================
    # EDA
    # =====================================================
    with tabs[6]:
        try:
            eda_profiler(df)
        except Exception as e:
            st.error(f"EDA failed: {e}")

    # =====================================================
    # PDF
    # =====================================================
    with tabs[7]:
        if st.button("Generate PDF"):
            generate_report(df)
            st.success("PDF generated.")

    # =====================================================
    # GEOIP
    # =====================================================
    with tabs[8]:
        if "src_ip" in df.columns:
            st.write(f"Unique IPs: {df['src_ip'].nunique()}")
        try:
            geoip_map(df)
        except Exception as e:
            st.error(f"GeoIP failed: {e}")

    # =====================================================
    # THREAT INTEL
    # =====================================================
    with tabs[9]:
        if "src_ip" in df.columns:
            top_ips = df["src_ip"].value_counts().head(10).index.tolist()
            threat_df = threat_intel_lookup_ui(top_ips)
            if threat_df is None or threat_df.empty:
                st.warning("No threat intel data available.")

    # =====================================================
    # ANOMALY
    # =====================================================
    with tabs[10]:
        feats = st.session_state.get("features_df", pd.DataFrame())
        if feats.empty:
            st.info("No features available.")
        else:
            with st.spinner("Running anomaly detection..."):
                scored = cached_anomaly(feats)
                progress.progress(90)

            if scored.empty:
                st.warning("No anomalies detected.")
            else:
                st.dataframe(make_arrow_safe(scored.head(30)), use_container_width=True)

    # =====================================================
    # CLUSTERING
    # =====================================================
    with tabs[11]:
        feats = st.session_state.get("features_df", pd.DataFrame())
        if feats.empty:
            st.info("No data for clustering.")
        else:
            clustered = flow_clustering_ui(feats)
            if clustered is not None:
                st.dataframe(make_arrow_safe(clustered.head(30)), use_container_width=True)

    # =====================================================
    # RULE MATCHES
    # =====================================================
    with tabs[12]:
        feats = st.session_state.get("features_df", pd.DataFrame())
        if feats.empty:
            st.info("No feature flows available.")
        else:
            matches = engine.apply_to_features(feats)
            st.write(f"Matches found: {len(matches)}")
            st.json(matches)

    progress.progress(100)
    st.success("Analysis complete ✅")

# =========================================================
# REAL-TIME (unchanged)
# =========================================================

if realtime_mode:
    st.info("Starting real-time capture...")

    def handler(pkt):
        try:
            from scapy.all import IP
            if IP in pkt:
                entry = {
                    "timestamp": pd.Timestamp.utcfromtimestamp(pkt.time).isoformat(),
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "packet_len": len(pkt)
                }
                write_alert({"type": "live_packet", "entry": entry})
        except:
            pass

    start_sniffer(iface=iface, duration=duration if duration > 0 else None, handler=handler)

st.sidebar.markdown("---")
st.sidebar.write("PacketSense — Modular Product Edition")