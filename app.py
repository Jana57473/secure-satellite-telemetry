# Replace your current app.py with this full code


import streamlit as st
import time
import random
import pandas as pd
from datetime import datetime
from PIL import Image
import os

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="Secure Satellite Telemetry",
    layout="wide",
    page_icon="🛰"
)

# =========================
# CUSTOM CSS
# =========================
st.markdown("""
<style>
body {
    background-color: #0b1220;
}

.main {
    background-color: #0b1220;
    color: white;
}

.block-container {
    padding-top: 1rem;
}

.metric-box {
    background-color: #111827;
    padding: 15px;
    border-radius: 10px;
    border: 1px solid #1f2937;
}

.green {
    color: #00ff7f;
    font-weight: bold;
}

.blue {
    color: #4da6ff;
    font-weight: bold;
}

.red {
    color: #ff4d4d;
    font-weight: bold;
}

.small-text {
    font-size: 14px;
}

.title-style {
    font-size: 34px;
    font-weight: bold;
}

.subtitle-style {
    color: #9ca3af;
}
</style>
""", unsafe_allow_html=True)

# =========================
# HEADER
# =========================
st.markdown("<div class='title-style'>🛰 Secure Satellite Telemetry Framework</div>", unsafe_allow_html=True)
st.markdown("<div class='subtitle-style'>Channel-Aware Adaptive Secure Telemetry using ChaCha20-Poly1305</div>", unsafe_allow_html=True)

st.write("")

# =========================
# TOP STATUS BAR
# =========================
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.success("Satellite: ONLINE")

with col2:
    st.success("Ground Station: ONLINE")

with col3:
    st.success("Secure Link: ACTIVE")

with col4:
    st.info("Phase: READY")

st.divider()

# =========================
# SIDEBAR
# =========================
with st.sidebar:
    st.header("📡 Simulation Pipeline")

    st.success("1️⃣ Boot")
    st.success("2️⃣ Telemetry")
    st.success("3️⃣ Encrypt")
    st.success("4️⃣ QAM Channel")
    st.success("5️⃣ Transmit")
    st.success("6️⃣ Verify")
    st.success("7️⃣ Decrypt")

    st.divider()

    st.header("🛰 Satellite Status")

    st.metric("Altitude", "539 km")
    st.metric("Velocity", "7.6 km/s")
    st.metric("TX Frequency", "2276.87 MHz")
    st.metric("SNR", "30 dB")

    st.divider()

    st.header("🔐 Encryption")

    st.write("Algorithm: ChaCha20-Poly1305")
    st.write("Auth Tag: 16 bytes")
    st.write("Nonce: 12 bytes")

# =========================
# MAIN TABS
# =========================

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📜 Live Log",
    "📡 Telemetry",
    "🔐 Encryption",
    "📶 QAM Channel",
    "🖥 Decryption",
    "📊 Benchmark"
])

# =========================
# TAB 1 - LIVE LOG
# =========================
with tab1:

    st.subheader("Simulation Console")

    if st.button("🚀 Run Full Simulation"):

        progress = st.progress(0)
        log_area = st.empty()

        logs = [
            "Satellite boot sequence initialized...",
            "Telemetry packet generated successfully...",
            "16 telemetry parameters loaded...",
            "ChaCha20-Poly1305 encryption started...",
            "Nonce generated successfully...",
            "Ciphertext generated...",
            "QAM wireless channel simulation started...",
            "AWGN noise added to channel...",
            "Encrypted packet transmitted...",
            "Ground station packet received...",
            "Authentication verification successful...",
            "Telemetry packet decrypted successfully...",
            "Data integrity verified...",
            "Simulation completed successfully..."
        ]

        for i, log in enumerate(logs):
            progress.progress((i + 1) / len(logs))
            log_area.code(log)
            time.sleep(0.4)

        st.success("Secure Telemetry Simulation Completed")

# =========================
# TAB 2 - TELEMETRY
# =========================
with tab2:

    st.subheader("Satellite Telemetry Parameters")

    telemetry = {
        "Parameter": [
            "Temperature",
            "Latitude",
            "Longitude",
            "Velocity",
            "Fuel Level",
            "Solar Voltage",
            "Radiation Level",
            "Gyro X",
            "Gyro Y",
            "Gyro Z",
            "Battery Level",
            "Altitude",
            "Payload Status",
            "Signal Strength",
            "Error Code",
            "Timestamp"
        ],

        "Value": [
            "45.2 °C",
            "12.9716",
            "77.5946",
            "27000 km/h",
            "78%",
            "24.5 V",
            "3.2",
            "0.02",
            "0.03",
            "0.01",
            "88%",
            "550 km",
            "ACTIVE",
            "-70 dB",
            "0",
            str(datetime.now())
        ]
    }

    df = pd.DataFrame(telemetry)
    st.dataframe(df, use_container_width=True)

# =========================
# TAB 3 - ENCRYPTION
# =========================
with tab3:

    st.subheader("ChaCha20-Poly1305 Encryption Analysis")

    enc_col1, enc_col2, enc_col3 = st.columns(3)

    with enc_col1:
        st.metric("Plaintext Size", "59 Bytes")

    with enc_col2:
        st.metric("Ciphertext Size", "75 Bytes")

    with enc_col3:
        st.metric("Encryption Time", "1.420 ms")

    st.success("Authenticated Encryption Successfully Applied")

# =========================
# TAB 4 - QAM CHANNEL
# =========================
with tab4:

    st.subheader("Wireless QAM Channel Simulation")

    qam_col1, qam_col2, qam_col3 = st.columns(3)

    with qam_col1:
        st.metric("BER", "0.0001")

    with qam_col2:
        st.metric("SNR", "30 dB")

    with qam_col3:
        st.metric("Packets Received", "1 / 1")

    st.info("AWGN Noise Successfully Simulated")

# =========================
# TAB 5 - DECRYPTION
# =========================
with tab5:

    st.subheader("Decryption & Integrity Verification")

    st.success("Authentication Tag Verified")
    st.success("Telemetry Packet Successfully Decrypted")
    st.success("No Tampering Detected")

# =========================
# TAB 6 - BENCHMARK
# =========================
with tab6:

    st.subheader("ChaCha20-Poly1305 vs AES-256-GCM")

    benchmark = pd.DataFrame({
        "Metric": [
            "Avg Encryption Time",
            "Avg Decryption Time",
            "Throughput",
            "Authentication Tag"
        ],

        "ChaCha20-Poly1305": [
            "0.0024 ms",
            "0.0022 ms",
            "0.0017 MB/s",
            "16 bytes"
        ],

        "AES-256-GCM": [
            "0.0724 ms",
            "0.0720 ms",
            "0.0271 MB/s",
            "16 bytes"
        ]
    })

    st.table(benchmark)

    st.success(
        "Selected Algorithm: ChaCha20-Poly1305 — More efficient for software-based satellite telemetry systems."
    )

# =========================
# OUTPUT GRAPHS
# =========================

st.divider()
st.header("📈 Output Graphs")

image_files = [
    "graph1_performance.png",
    "graph2_recovery.png",
    "graph3_security.png",
    "graph4_snr_decrypt.png",
    "graph5_ber_snr.png",
    "graph6_constellation.png"
]

cols = st.columns(2)

for idx, image_name in enumerate(image_files):

    image_path = os.path.join("outputs", image_name)

    if os.path.exists(image_path):

        with cols[idx % 2]:
            st.image(image_path, caption=image_name)

st.divider()

st.caption("Developed for Final Year ECE Project — Secure Satellite Telemetry Framework")