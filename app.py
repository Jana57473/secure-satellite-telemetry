import streamlit as st
import subprocess
import os

st.title("🛰 Secure Satellite Telemetry Framework")

st.write("Channel-Aware Adaptive Secure Telemetry using ChaCha20-Poly1305")

if st.button("Run Full Simulation"):

    st.success("Simulation Started...")

    result = subprocess.run(
        ["python", "demo_presentation.py"],
        capture_output=True,
        text=True
    )

    st.text(result.stdout)

    st.success("Simulation Completed!")

st.header("📊 Output Graphs")

graph_folder = "outputs"

graphs = [
    "graph1_performance.png",
    "graph2_recovery.png",
    "graph3_security.png",
    "graph4_snr_decrypt.png",
    "graph5_ber_snr.png",
    "graph6_constellation.png"
]

for graph in graphs:
    path = os.path.join(graph_folder, graph)

    if os.path.exists(path):
        st.image(path, caption=graph)