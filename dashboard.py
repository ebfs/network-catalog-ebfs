import pandas as pd
import streamlit as st
import plotly.express as px

from datetime import datetime

from sqlalchemy import create_engine

from streamlit_autorefresh import st_autorefresh


#
# Auto Refresh
#

st_autorefresh(
    interval=5000,
    key="dashboard_refresh"
)


#
# Page Configuration
#

st.set_page_config(
    page_title="Network Catalog Dashboard",
    layout="wide"
)


#
# Database Connection
#

engine = create_engine(
    "sqlite:///network_catalog.db"
)


#
# Helpers
#

@st.cache_data(ttl=5)

def load_table(table_name):

    query = f"SELECT * FROM {table_name}"

    return pd.read_sql(query, engine)


#
# Load Data
#

try:

    devices_df = load_table("devices")

except Exception:

    devices_df = pd.DataFrame()


try:

    services_df = load_table("services")

except Exception:

    services_df = pd.DataFrame()


try:

    flows_df = load_table("flows")

except Exception:

    flows_df = pd.DataFrame()


#
# Flow Enrichment
#

ip_to_hostname = {}

if not devices_df.empty:

    for _, row in devices_df.iterrows():

        ip_to_hostname[row["ip"]] = (
            row.get("hostname")
            or row["ip"]
        )


if not flows_df.empty:

    flows_df["src_hostname"] = (
        flows_df["src_ip"]
        .map(ip_to_hostname)
        .fillna(flows_df["src_ip"])
    )

    flows_df["dst_hostname"] = (
        flows_df["dst_ip"]
        .map(ip_to_hostname)
        .fillna(flows_df["dst_ip"])
    )


#
# Header
#

st.title("Network Catalog Dashboard")

st.markdown(
    "Lightweight network inventory and telemetry observability dashboard"
)

st.caption(
    f"Last Updated: "
    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)


#
# Metrics Row
#

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Devices",
        len(devices_df)
    )

with col2:

    st.metric(
        "Services",
        len(services_df)
    )

with col3:

    st.metric(
        "Flows",
        len(flows_df)
    )

with col4:

    total_bytes = 0

    if not flows_df.empty:

        total_bytes = int(
            flows_df["byte_count"].sum()
        )

    st.metric(
        "Total Bytes",
        f"{total_bytes:,}"
    )


st.divider()


#
# Devices Section
#

st.header("Devices")

if not devices_df.empty:

    display_devices = devices_df.copy()

    st.dataframe(
        display_devices,
        width="stretch"
    )

else:

    st.warning("No device data found.")


st.divider()


#
# Services Section
#

st.header("Services")

if not services_df.empty:

    display_services = services_df.copy()

    st.dataframe(
        display_services,
        width="stretch"
    )

else:

    st.warning("No services data found.")


st.divider()


#
# Flows Section
#

st.header("Flows")

if not flows_df.empty:

    display_flows = flows_df.copy()

    st.dataframe(
        display_flows,
        width="stretch"
    )

else:

    st.warning("No flow data found.")


st.divider()


#
# Protocol Breakdown
#

st.header("Protocol Breakdown")

if not flows_df.empty and "protocol" in flows_df.columns:

    protocol_counts = (
        flows_df["protocol"]
        .value_counts()
        .reset_index()
    )

    protocol_counts.columns = [
        "Protocol",
        "Count"
    ]

    fig_protocol = px.pie(
        protocol_counts,
        names="Protocol",
        values="Count",
        title="Traffic by Protocol"
    )

    st.plotly_chart(
        fig_protocol,
        width="stretch"
    )

else:

    st.warning("No protocol data available.")


st.divider()


#
# Top Destination Ports
#

st.header("Top Destination Ports")

if not flows_df.empty and "dst_port" in flows_df.columns:

    top_ports = (
        flows_df["dst_port"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    top_ports.columns = [
        "Port",
        "Count"
    ]

    fig_ports = px.bar(
        top_ports,
        x="Port",
        y="Count",
        title="Most Observed Destination Ports"
    )

    st.plotly_chart(
        fig_ports,
        width="stretch"
    )

else:

    st.warning("No port data available.")


st.divider()


#
# Top Talkers
#

st.header("Top Talkers")

if not flows_df.empty and "src_hostname" in flows_df.columns:

    top_talkers = (
        flows_df
        .groupby("src_hostname")["byte_count"]
        .sum()
        .sort_values(ascending=False)
        .head(10)
        .reset_index()
    )

    top_talkers.columns = [
        "Hostname",
        "Total Bytes"
    ]

    fig_talkers = px.bar(
        top_talkers,
        x="Hostname",
        y="Total Bytes",
        title="Top Traffic Generators"
    )

    st.plotly_chart(
        fig_talkers,
        width="stretch"
    )

else:

    st.warning("No flow telemetry available.")


st.divider()


#
# Top External Organizations
#

st.header("Top External Organizations")

if (
    not flows_df.empty
    and "dst_org" in flows_df.columns
):

    external_orgs = flows_df[
        flows_df["dst_org"].notna()
    ]

    if not external_orgs.empty:

        top_orgs = (
            external_orgs
            .groupby("dst_org")["byte_count"]
            .sum()
            .sort_values(ascending=False)
            .head(10)
            .reset_index()
        )

        top_orgs.columns = [
            "Organization",
            "Total Bytes"
        ]

        fig_orgs = px.bar(
            top_orgs,
            x="Organization",
            y="Total Bytes",
            title="Top External Organizations"
        )

        st.plotly_chart(
            fig_orgs,
            width="stretch"
        )

        st.dataframe(
            top_orgs,
            width="stretch"
        )

    else:

        st.warning(
            "No external organization data available."
        )

else:

    st.warning(
        "No enrichment data available."
    )


st.divider()


#
# Recent Flows
#

st.header("Recent Flows")

if not flows_df.empty:

    recent_flows = flows_df.sort_values(
        by="last_seen",
        ascending=False
    )

    recent_display = recent_flows[[
        "src_hostname",
        "dst_hostname",
        "src_port",
        "dst_port",
        "protocol",
        "packet_count",
        "byte_count",
        "dst_org",
        "dst_country",
        "dst_rdns",
        "first_seen",
        "last_seen"
    ]]

    recent_display.columns = [
        "Source",
        "Destination",
        "Source Port",
        "Destination Port",
        "Protocol",
        "Packets",
        "Bytes",
        "Destination Organization",
        "Destination Country",
        "Destination RDNS",
        "First Seen",
        "Last Seen"
    ]

    st.dataframe(
        recent_display.head(25),
        width="stretch"
    )

else:

    st.warning("No recent flow data available.")


#
# Footer
#

st.divider()

st.caption(
    "Network Catalog | Active discovery + passive telemetry"
)
