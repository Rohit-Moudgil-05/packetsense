"""
app.py - main Streamlit UI for PacketSense modular edition
"""
import plotly.express as px

import os
import streamlit as st
import pandas as pd

# import our modules
from packetsense.loader import load_file
from packetsense.profiler import ml_feature_profiler
from packetsense.anomaly import anomaly_scoring
from packetsense.fingerprints import build_fingerprints
from packetsense.intel import threat_lookup
from packetsense.rule_engine import RuleEngine
from packetsense.realtime import start_sniffer
from packetsense.exports import write_alert, export_zip
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

# license notice
if not is_valid():
    st.warning("⚠️ License key missing or invalid. Place a valid key in license.key to unlock premium features.")

# Rule engine
engine = RuleEngine(rules_dir="rules")

# Sidebar: real-time options
realtime_mode = st.sidebar.checkbox("Enable real-time sniff (demo)")
iface = st.sidebar.text_input("Interface for sniffing", value="eth0")
duration = st.sidebar.number_input("Real-time duration (seconds, 0 for indefinite)", min_value=0, value=30)

# File upload
uploaded_file = st.file_uploader("Upload PCAP, CSV, or JSONL file", type=["pcap", "csv", "jsonl"])

# Rule editor controls
st.sidebar.markdown("### Rule Engine")
if st.sidebar.button("Reload rules"):
    engine.load_rules()
    st.sidebar.success("Rules reloaded")

# Show list of rules and enable toggles
rule_files = []
try:
    rule_files = [f for f in os.listdir("rules") if f.endswith((".yaml", ".yml"))]
except Exception:
    pass

if rule_files:
    chosen = st.sidebar.selectbox("Open rule file", ["(none)"] + rule_files)
    if chosen and chosen != "(none)":
        if st.sidebar.button("Edit selected rule file"):
            # show editor in a modal-like area
            text = open(os.path.join("rules", chosen), "r", encoding="utf-8").read()
            new_text = st.text_area(f"Edit {chosen}", text, height=400)
            if st.button("Save rule file"):
                with open(os.path.join("rules", chosen), "w", encoding="utf-8") as fh:
                    fh.write(new_text)
                engine.load_rules()
                st.success(f"Saved {chosen} and reloaded rules")

# Processing
features_df = pd.DataFrame()

if uploaded_file is not None:
    df = load_file(uploaded_file)
    if df is None:
        st.error("Failed to load file")
    else:
        st.success("✅ File loaded successfully")
        # Tabs similar to original app
        tabs = st.tabs([
            "Numerical Profiler",
            "Categorical Profiler",
            "Temporal Profiler",
            "Attack Profiler",
            "ML Feature Profiler",
            "Network Graph",
            "EDA & Profiling",
            "PDF Report",
            "GeoIP Map",
            "Threat Intel",
            "Anomaly Scoring",
            "Flow Clustering",
            "Rule Matches"
        ])

        # Numerical
        with tabs[0]:
            st.subheader("Numerical Profiler")
            try:
                st.write(df.describe())
            except Exception:
                st.write("No numerical columns")

        # Categorical
        with tabs[1]:
            st.subheader("Categorical Profiler")
            try:
                st.write(df.select_dtypes(include="object").head(50))
            except Exception:
                st.write("No categorical data")

        # Temporal
        with tabs[2]:
            st.subheader("Temporal Profiler")
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
                df = df.dropna(subset=["timestamp"])
                ts = df.groupby(pd.Grouper(key="timestamp", freq="1Min")).size()
                fig = px.line(ts, title="Packets over Time")
                st.plotly_chart(fig)
            else:
                st.info("No timestamp column")

        # Attack Profiler
        with tabs[3]:
            st.subheader("🚨 Attack Profiler – Heuristics + MITRE mapping")
            if "src_ip" not in df.columns:
                st.warning("Source IP missing")
            else:
                # build traffic_stats
                # traffic_stats = df["src_ip"].value_counts().reset_index()
                df["src_ip"] = df["src_ip"].apply(lambda x: x if isinstance(x, str) else str(x))

                traffic_stats = (
                    df["src_ip"]
                    .astype(str)
                    .value_counts()
                    .reset_index()
                    .rename(columns={"index": "src_ip", "src_ip": "count"})
                )

                traffic_stats.columns = ["src_ip", "packet_count"]
                if "dst_port" in df.columns:
                    unique_ports = df.groupby("src_ip")["dst_port"].nunique().reset_index()
                    traffic_stats = traffic_stats.merge(unique_ports, on="src_ip", how="left")
                    traffic_stats.rename(columns={"dst_port": "unique_dst_ports"}, inplace=True)
                else:
                    traffic_stats["unique_dst_ports"] = 0
                if "protocol" in df.columns:
                    proto_dist = df.groupby("src_ip")["protocol"].nunique().reset_index()
                    traffic_stats = traffic_stats.merge(proto_dist, on="src_ip", how="left")
                    traffic_stats.rename(columns={"protocol": "unique_protocols"}, inplace=True)
                else:
                    traffic_stats["unique_protocols"] = 0

                # simple adaptive MITRE mapping as in original
                ADAPTIVE_MITRE_MAP = {
                    "DDoS / Flooding": ["T1498", "T1499", "Impact"],
                    "Port Scan": ["T1046", "T1595", "Reconnaissance"],
                    "Reconnaissance": ["T1046", "ICS-T0842", "Reconnaissance"],
                    "Suspicious Activity": ["T1071", "T1070", "Defense Evasion"],
                    "Unauthorized Access": ["T1078", "T1110.001", "Credential Access"],
                    "Command Injection": ["T1059", "T1071.001", "Execution"],
                    "Data Exfiltration": ["T1041", "T1048", "Exfiltration"],
                    "Anomaly": ["T1071", "T1070", "Defense Evasion"]
                }
                MITRE_TACTIC_MAP = {
                    "T1498": "Impact", "T1499": "Impact",
                    "T1046": "Reconnaissance", "T1595": "Reconnaissance",
                    "T1071": "Command & Control", "T1070": "Defense Evasion",
                    "T1078": "Credential Access", "T1110.001": "Credential Access",
                    "T1059": "Execution", "T1041": "Exfiltration", "T1048": "Exfiltration",
                    "ICS-T0842": "Reconnaissance"
                }

                # heuristics
                reasons, types, risks, confs, mitres, tactics = [], [], [], [], [], []
                for _, row in traffic_stats.iterrows():
                    pkt = row["packet_count"]
                    ports = row.get("unique_dst_ports", 0) or 0
                    protos = row.get("unique_protocols", 0) or 0
                    reason, attack_type, risk, confidence = "Normal pattern", "Normal", "Low", 0.2
                    if pkt > 5000:
                        reason = "Unusually high packet rate — potential DDoS/flood"
                        attack_type, risk, confidence = "DDoS / Flooding", "High", 0.95
                    elif ports > 50:
                        reason = "Many destination ports targeted — likely port scan"
                        attack_type, risk, confidence = "Port Scan", "Medium", 0.75
                    elif protos > 5:
                        reason = "Multiple uncommon protocols — possible reconnaissance"
                        attack_type, risk, confidence = "Reconnaissance", "Medium", 0.7
                    elif pkt > 1000:
                        reason = "Moderate single-source packet spike"
                        attack_type, risk, confidence = "Suspicious Activity", "Medium", 0.6

                    mitre_code = ADAPTIVE_MITRE_MAP.get(attack_type, ["Unmapped"])[0]
                    tactic = MITRE_TACTIC_MAP.get(mitre_code, "Unmapped")

                    reasons.append(reason)
                    types.append(attack_type)
                    risks.append(risk)
                    confs.append(confidence)
                    mitres.append(mitre_code)
                    tactics.append(tactic)

                traffic_stats["Attack Reason"] = reasons
                traffic_stats["Probable Attack Type"] = types
                traffic_stats["Risk Level"] = risks
                traffic_stats["Confidence"] = confs
                traffic_stats["MITRE Technique"] = mitres
                traffic_stats["MITRE Tactic"] = tactics

                st.dataframe(traffic_stats.head(20))

        # ML Feature Profiler tab
        with tabs[4]:
            st.subheader("ML Feature Profiler")
            features_df = ml_feature_profiler(df)
            st.session_state["features_df"] = features_df

        # Network Graph
        with tabs[5]:
            try:
                network_graph(df)
            except Exception as e:
                st.error(f"Network graph failed: {e}")

        # EDA & Profiling
        with tabs[6]:
            try:
                eda_profiler(df)
            except Exception as e:
                st.error(f"EDA failed: {e}")

        # PDF Report
        with tabs[7]:
            if st.button("Generate PDF Summary"):
                generate_report(df)

        # GeoIP Map
        with tabs[8]:
            try:
                geoip_map(df)
            except Exception as e:
                st.error(f"GeoIP map failed: {e}")

        # Threat Intel (EDA wrapper)
        with tabs[9]:
            if "src_ip" in df.columns:
                top_ips = df["src_ip"].value_counts().head(10).index.tolist()
                # use environment keys if available
                abuse_key = os.getenv("ABUSEIPDB_KEY")
                vt_key = os.getenv("VT_API_KEY")
                threat_df = threat_intel_lookup_ui(top_ips, abuse_key=abuse_key, vt_key=vt_key)

        # Anomaly scoring
        with tabs[10]:
            try:
                if "features_df" in st.session_state and not st.session_state["features_df"].empty:
                    scored = anomaly_scoring(st.session_state["features_df"])
                    st.dataframe(scored.head(30))
                else:
                    st.info("No features available for anomaly scoring.")
            except Exception as e:
                st.error(f"Anomaly scoring failed: {e}")

        # Flow clustering
        with tabs[11]:
            try:
                if "features_df" in st.session_state and not st.session_state["features_df"].empty:
                    clustered = flow_clustering_ui(st.session_state["features_df"])
                    st.session_state["clustered"] = clustered
                else:
                    st.info("No features to cluster.")
            except Exception as e:
                st.error(f"Flow clustering failed: {e}")

        # Rule engine matches (apply rule engine to flows)
        with tabs[12]:
            st.subheader("Rule Engine Matches")
            try:
                # apply flow rules if features available
                feats = st.session_state.get("features_df", pd.DataFrame())
                if not feats.empty:
                    matches = engine.apply_to_features(feats)
                    st.write(f"Found {len(matches)} matches")
                    st.json(matches)
                    # convert to alerts
                    for m in matches:
                        write_alert({
                            "timestamp": str(pd.Timestamp.utcnow()),
                            "type": "rule_match",
                            "rule": m.get("rule"),
                            "description": m.get("description"),
                            "action": m.get("action"),
                            "confidence": m.get("confidence"),
                            "row": m.get("row")
                        })
                else:
                    st.info("No feature flows to apply rules to.")
            except Exception as e:
                st.error(f"Rule engine failed: {e}")

# Real-time sniff demo
if realtime_mode:
    st.info("Starting demo real-time capture (sniff).")
    def handler(pkt):
        try:
            if IP in pkt:
                entry = {
                    "timestamp": pd.Timestamp.utcfromtimestamp(pkt.time).isoformat(),
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "packet_len": len(pkt)
                }
                write_alert({"type": "live_packet", "entry": entry})
        except Exception:
            pass
    start_sniffer(iface=iface, duration=duration if duration > 0 else None, handler=handler)

st.sidebar.markdown("---")
st.sidebar.write("PacketSense — modular product edition")
