"""
packetsense/eda.py

Exploratory Data Analysis + network graph + PDF report + GeoIP + Threat-Intel UI
Extracted from your original file.py and adjusted to be a module.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
import tempfile
from fpdf import FPDF
import folium
from streamlit_folium import st_folium
import requests
import concurrent.futures
from ydata_profiling import ProfileReport
from scapy.all import IP, TCP, UDP
from pyvis.network import Network
import networkx as nx
import streamlit as st


def eda_profiler(df):
    """Automated EDA & Profiling UI elements (Streamlit)."""
    st.header("🧠 Automated EDA & Profiling")

    # Brief summary
    st.subheader("📝 Brief Summary")
    num_rows, num_cols = df.shape
    st.markdown(f"- **Rows:** {num_rows} | **Columns:** {num_cols}")

    if "src_ip" in df.columns:
        st.markdown(f"- **Unique Source IPs:** {df['src_ip'].nunique()}")
        top_src = df['src_ip'].value_counts().head(3)
        st.markdown(f"- **Top Source IPs:** {', '.join(top_src.index)} ({top_src.values.tolist()})")

    if "dst_ip" in df.columns:
        st.markdown(f"- **Unique Destination IPs:** {df['dst_ip'].nunique()}")
        top_dst = df['dst_ip'].value_counts().head(3)
        st.markdown(f"- **Top Destination IPs:** {', '.join(top_dst.index)} ({top_dst.values.tolist()})")

    if "protocol" in df.columns:
        top_proto = df['protocol'].value_counts().head(3)
        st.markdown(f"- **Top Protocols:** {', '.join(map(str, top_proto.index))} ({top_proto.values.tolist()})")

    st.markdown("---")

    # Dataset overview
    st.subheader("Dataset Overview")
    st.write(df.describe(include='all'))
    st.write("Data Types:", df.dtypes)
    st.write("Missing Values:", df.isnull().sum())

    # Correlation heatmap
    num_df = df.select_dtypes(include='number')
    if not num_df.empty:
        st.subheader("Correlation Heatmap")
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(num_df.corr(), annot=True, fmt=".2f", cmap="coolwarm", ax=ax)
        st.pyplot(fig)

    # Protocol vs Packet Length
    if {"protocol", "packet_len"}.issubset(df.columns):
        st.subheader("Protocol vs Packet Length Distribution")
        fig = px.violin(df, x="protocol", y="packet_len", box=True, points="all")
        st.plotly_chart(fig, use_container_width=True)

    # Full profiling (ydata_profiling)
    if st.button("🧩 Generate Full Profiling Report"):
        with st.spinner("Generating full EDA report..."):
            try:
                profile = ProfileReport(df, title="Full Data Profiling Report", explorative=True)
                profile_path = "eda_full_report.html"
                profile.to_file(profile_path)
                st.success("✅ Report Generated!")
                with open(profile_path, "r", encoding="utf-8") as f:
                    st.components.v1.html(f.read(), height=900, scrolling=True)
            except Exception as e:
                st.error(f"Failed to generate profiling report: {e}")


def parse_pcap_to_df_for_graph(packets):
    """Helper to build DataFrame from scapy packets for graphing if needed."""
    data = []
    for pkt in packets:
        pkt_info = {}
        if IP in pkt:
            pkt_info["src_ip"] = pkt[IP].src
            pkt_info["dst_ip"] = pkt[IP].dst
            pkt_info["protocol"] = pkt[IP].proto
        if TCP in pkt:
            pkt_info["src_port"] = pkt[TCP].sport
            pkt_info["dst_port"] = pkt[TCP].dport
        elif UDP in pkt:
            pkt_info["src_port"] = pkt[UDP].sport
            pkt_info["dst_port"] = pkt[UDP].dport
        pkt_info["packet_len"] = len(pkt)
        data.append(pkt_info)
    return pd.DataFrame(data)


def network_graph(df, height_px=650):
    """Build an interactive network graph (pyvis) and render in Streamlit."""
    st.subheader(" Advanced Network Graph")
    if "src_ip" not in df.columns or "dst_ip" not in df.columns:
        st.info("Source/Destination IP fields not found.")
        return

    clean_df = df.copy()
    # convert datetimes to strings for safe display
    for col in clean_df.columns:
        if pd.api.types.is_datetime64_any_dtype(clean_df[col]):
            clean_df[col] = clean_df[col].astype(str)

    edge_df = clean_df.groupby(["src_ip", "dst_ip", "protocol"]).agg(
        num_packets=("packet_len", "count"),
        avg_packet_len=("packet_len", "mean")
    ).reset_index()

    G = nx.Graph()
    protocol_colors = {6: "blue", 17: "green", 1: "orange"}
    for _, row in edge_df.iterrows():
        color = protocol_colors.get(row["protocol"], "gray")
        G.add_edge(
            row["src_ip"], row["dst_ip"],
            weight=row["num_packets"],
            title=f"Packets: {row['num_packets']}, Avg Len: {row['avg_packet_len']:.1f}",
            color=color
        )

    net = Network(height=f"{height_px}px", width="100%", bgcolor="#ffffff", font_color="black", notebook=False)
    net.from_nx(G)

    # enhance node sizes
    for node in net.nodes:
        try:
            node["size"] = max(5, G.degree(node["id"]) * 2)
        except Exception:
            node["size"] = 8

    # highlight top talkers
    try:
        top_ips = clean_df["src_ip"].value_counts().head(3).index.tolist()
        for node in net.nodes:
            if node["id"] in top_ips:
                node["color"] = "red"
    except Exception:
        pass

    # render to temp html and embed
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
        net.save_graph(tmp.name)
        html_content = open(tmp.name, "r", encoding="utf-8").read()
        st.components.v1.html(html_content, height=height_px)


def generate_report(df, filename="packet_report.pdf"):
    """Generate a simple PDF summary and offer download."""
    st.subheader(" PDF Report Generation")
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "PacketSense Analysis Report", ln=True, align="C")
        pdf.set_font("Arial", "", 12)
        pdf.ln(10)
        pdf.multi_cell(0, 8, f"Rows: {df.shape[0]} | Columns: {df.shape[1]}")
        pdf.ln(5)
        if "src_ip" in df.columns:
            pdf.multi_cell(0, 8, f"Top Source IPs: {df['src_ip'].value_counts().head(5).to_dict()}")
        if "dst_ip" in df.columns:
            pdf.multi_cell(0, 8, f"Top Destination IPs: {df['dst_ip'].value_counts().head(5).to_dict()}")
        pdf.output(filename)
        with open(filename, "rb") as f:
            st.download_button("📥 Download PDF Report", f, file_name=filename)
    except Exception as e:
        st.error(f"PDF generation failed: {e}")


def geoip_map(df, limit_top=20):
    """Show a simple GeoIP map with markers for top IPs. (Uses ip-api for coords)"""
    st.subheader("🗺️ GeoIP Mapping")
    if "src_ip" not in df.columns and "dst_ip" not in df.columns:
        st.info("Source/Destination IPs required for GeoIP mapping")
        return

    # choose top IPs from combined list
    combined = pd.concat([df.get("src_ip", pd.Series()), df.get("dst_ip", pd.Series())]).value_counts().head(limit_top).index
    folium_map = folium.Map(location=[20, 0], zoom_start=2)

    def lookup_coords(ip):
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            return float(r.get("lat")), float(r.get("lon")), r.get("country", "-")
        except:
            return None, None, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lookup_coords, combined))

    for ip, (lat, lon, country) in zip(combined, results):
        if lat is None or lon is None:
            continue
        folium.CircleMarker(location=[lat, lon], radius=6, popup=f"IP: {ip} ({country})").add_to(folium_map)

    st_folium(folium_map, width=800)


def threat_intel_lookup_ui(ip_list, abuse_key=None, vt_key=None):
    """
    Lightweight UI wrapper for threat lookups. Returns pandas DataFrame.
    Note: prefer to centralize keys via environment variables in production.
    """
    st.subheader("🛡️ Threat Intelligence Dashboard (EDA module)")

    headers_abuse = {"Key": abuse_key, "Accept": "application/json"} if abuse_key else None
    headers_vt = {"x-apikey": vt_key} if vt_key else None

    all_results = []

    def lookup_ip(ip):
        entry = {"IP": ip, "Country": "-", "ISP": "-", "Abuse Score": None, "VT Detections": None, "Risk Reason": "-", "Risk Level": "Low"}
        # GeoIP
        try:
            r_geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            entry["Country"] = r_geo.get("country", "-")
            entry["ISP"] = r_geo.get("isp", "-")
        except:
            pass

        # AbuseIPDB
        if headers_abuse:
            try:
                r_abuse = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers_abuse, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=3)
                data = r_abuse.json().get("data", {})
                entry["Abuse Score"] = data.get("abuseConfidenceScore", 0)
                categories = data.get("categories", [])
                if categories:
                    entry["Risk Reason"] = ", ".join([str(c) for c in categories])
            except:
                entry["Abuse Score"] = None

        # VirusTotal
        if headers_vt:
            try:
                vt_resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers_vt, timeout=3)
                vt_data = vt_resp.json().get("data", {}).get("attributes", {})
                entry["VT Detections"] = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
            except:
                entry["VT Detections"] = None

        abuse = entry.get("Abuse Score") or 0
        vt = entry.get("VT Detections") or 0
        combined = abuse * 0.6 + vt * 8
        if combined > 60:
            entry["Risk Level"] = "High"
        elif combined > 30:
            entry["Risk Level"] = "Medium"
        else:
            entry["Risk Level"] = "Low"
        return entry

    with st.spinner("🔍 Performing multi-source threat lookups..."):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lookup_ip, ip_list))

    results_df = pd.DataFrame(results)

    def color_risk(val):
        colors = {"High": "#ff4d4d", "Medium": "#ffcc00", "Low": "#00cc66"}
        return f"background-color: {colors.get(val, 'white')}; color: black; font-weight: bold;"

    try:
        st.dataframe(results_df.style.applymap(color_risk, subset=["Risk Level"]))
    except Exception:
        st.write(results_df)

    # small summary plot
    if not results_df.empty and "Abuse Score" in results_df.columns:
        fig = px.bar(
            results_df.sort_values("Abuse Score", ascending=False),
            x="IP",
            y="Abuse Score",
            color="Risk Level",
            text="Country",
            title="Threat Intelligence Summary – Abuse Scores by IP",
            color_discrete_map={"High": "red", "Medium": "orange", "Low": "green"}
        )
        fig.update_traces(textposition="outside")
        st.plotly_chart(fig, use_container_width=True)

    return results_df


def flow_clustering_ui(features_df):
    """Flow clustering UI using DBSCAN. Returns features_df augmented with 'cluster'."""
    st.subheader("🧩 Flow Clustering / Anomaly Detection")
    if features_df.empty:
        st.info("No features available for clustering")
        return features_df

    from sklearn.cluster import DBSCAN
    numeric_cols = ["num_packets", "avg_packet_len", "std_packet_len", "session_duration_s"]
    X = features_df[numeric_cols].fillna(0).values
    clustering = DBSCAN(eps=0.5, min_samples=2).fit(X)
    dfc = features_df.copy()
    dfc["cluster"] = clustering.labels_
    st.dataframe(dfc.sort_values("cluster").head(20))
    st.info("Cluster -1 = potential anomalies / noise")
    return dfc
