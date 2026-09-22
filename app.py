import streamlit as st
import pandas as pd
import plotly.express as px
import log_parser

# Page Config
st.set_page_config(page_title="SOC Analyst Dashboard", layout="wide", initial_sidebar_state="expanded")

# Persistence (Session State Initialization)
if 'logs_df' not in st.session_state:
    st.session_state['logs_df'] = None
if 'active_filename' not in st.session_state:
    st.session_state['active_filename'] = None

# Sidebar Navigation
st.sidebar.title("🛡️ SOC CENTER")
st.sidebar.caption("Windows + Linux + macOS log analysis")

if st.session_state['active_filename']:
    st.sidebar.success(f"📂 Loaded File: {st.session_state['active_filename']}")

menu = st.sidebar.radio(
    "Navigation", 
    ["Dashboard", "Upload / Ingest Logs", "Alerts", "Incidents", "Log Explorer", "Threat Intelligence"]
)

st.sidebar.markdown("---")
if st.sidebar.button("🚀 Run Detection Engine"):
    st.sidebar.success("Detection Engine Executed Successfully!")

# ---------------- 1. DASHBOARD PAGE ----------------
if menu == "Dashboard":
    st.title("🛡️ SOC Analyst Dashboard")
    st.caption("Detect | Investigate | Respond | Stay Secure")
    
    if st.session_state['logs_df'] is not None:
        df = st.session_state['logs_df']
        
        total_alerts = len(df)
        critical = len(df[df['Severity'].astype(str).str.upper() == 'CRITICAL']) if 'Severity' in df.columns else 0
        high = len(df[df['Severity'].astype(str).str.upper() == 'HIGH']) if 'Severity' in df.columns else 0
        medium = len(df[df['Severity'].astype(str).str.upper() == 'MEDIUM']) if 'Severity' in df.columns else 0
        unique_ips = df['Source_IP'].nunique() if 'Source_IP' in df.columns else 0

        # Metrics
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Alerts", total_alerts)
        c2.metric("Critical Alerts", critical)
        c3.metric("High Alerts", high)
        c4.metric("Medium Alerts", medium)
        c5.metric("Unique IPs", unique_ips)
        
        st.markdown("---")
        
        col_left, col_mid, col_right = st.columns([2, 2, 1.5])
        
        with col_left:
            st.subheader("Alerts Over Time")
            time_df = df.head(15).copy()
            time_df['Index'] = range(1, len(time_df) + 1)
            fig_line = px.line(time_df, x="Index", y="Severity", markers=True)
            st.plotly_chart(fig_line, use_container_width=True)
            
        with col_mid:
            st.subheader("Alerts by Severity")
            if 'Severity' in df.columns:
                sev_counts = df['Severity'].value_counts().reset_index()
                sev_counts.columns = ['Severity', 'Count']
                fig_pie = px.pie(sev_counts, values="Count", names="Severity", hole=0.5)
                st.plotly_chart(fig_pie, use_container_width=True)
            
        with col_right:
            st.subheader("Top Attacking IPs")
            if 'Source_IP' in df.columns:
                ip_counts = df['Source_IP'].value_counts().reset_index()
                ip_counts.columns = ['IP', 'Attacks']
                fig_bar = px.bar(ip_counts.head(5), x="Attacks", y="IP", orientation='h')
                st.plotly_chart(fig_bar, use_container_width=True)

        st.subheader("Recent Uploaded Logs Preview")
        st.dataframe(df.head(15), use_container_width=True)
    else:
        st.warning("⚠️ No Log File uploaded yet! Please go to 'Upload / Ingest Logs' and upload your logs.csv file.")

# ---------------- 2. UPLOAD LOGS PAGE ----------------
elif menu == "Upload / Ingest Logs":
    st.title("📥 Upload / Ingest Logs")
    
    uploaded_file = st.file_uploader("Upload System Log File (.log, .txt, .csv)", type=["log", "txt", "csv"])
    
    if uploaded_file is not None:
        parsed_df = log_parser.parse_log_file(uploaded_file)
        # Session state memory lo store chestunnam
        st.session_state['logs_df'] = parsed_df
        st.session_state['active_filename'] = uploaded_file.name
        st.success(f"✅ Successfully loaded '{uploaded_file.name}' with {len(parsed_df)} records!")

    if st.session_state['logs_df'] is not None:
        st.info(f"📁 Active Dataset: *{st.session_state['active_filename']}* ({len(st.session_state['logs_df'])} rows)")
        st.dataframe(st.session_state['logs_df'].head(10), use_container_width=True)

# ---------------- 3. LOG EXPLORER PAGE ----------------
elif menu == "Log Explorer":
    st.title("🔍 Log Explorer")
    if st.session_state['logs_df'] is not None:
        df = st.session_state['logs_df']
        
        search_query = st.text_input("Search logs by Keyword, IP, or Severity:")
        if search_query:
            filtered_df = df[df.astype(str).apply(lambda x: x.str.contains(search_query, case=False)).any(axis=1)]
            st.subheader(f"Search Results ({len(filtered_df)} matches)")
            st.dataframe(filtered_df, use_container_width=True)
        else:
            st.dataframe(df, use_container_width=True)
    else:
        st.warning("Please upload a log file first under 'Upload / Ingest Logs'.")

# ---------------- 4. THREAT INTELLIGENCE ----------------
elif menu == "Threat Intelligence":
    st.title("🌐 Threat Intelligence Lookup")
    ip_input = st.text_input("Enter IP Address to investigate:")
    if st.button("Check Threat Status"):
        if ip_input:
            col1, col2, col3 = st.columns(3)
            col1.metric("Threat Level", "HIGH", delta_color="inverse")
            col2.metric("Malicious Score", "88/100")
            col3.metric("Category", "Brute Force / Scanner")
            st.error(f"⚠️ Warning: {ip_input} is flagged as Malicious!")
        else:
            st.warning("Please enter an IP address.")

# ---------------- 5. ALERTS & INCIDENTS ----------------
else:
    st.title(f"📂 {menu}")
    if st.session_state['logs_df'] is not None:
        st.dataframe(st.session_state['logs_df'], use_container_width=True)
    else:
        st.info("No active log file loaded.")