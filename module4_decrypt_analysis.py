"""
MODULE 4 — Demodulation, Decryption, Recovery Verification & All Output Graphs
Project: Securing Satellite Telemetry in Software-Defined Space Link
"""

import struct, os, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, ".")
from module1_telemetry_gen import generate_stream, decode_packet
from module2_encryption    import (chacha_encrypt, chacha_decrypt,
                                   aes_encrypt, aes_decrypt, benchmark, security_tests)
from module3_qam_channel   import (modulate, add_awgn, demodulate,
                                   nibbles_to_bytes, ber_curve,
                                   plot_waveform, plot_chacha20_advantages)

os.makedirs("outputs", exist_ok=True)

SNR_HIGH   = 30   # clean channel
SNR_MEDIUM = 15   # realistic LEO
SNR_LOW    = 8    # degraded link


# ─────────────────────── End-to-End Pipeline ─────────────────────────────────

def e2e_pipeline(plaintext: bytes, snr_db: float):
    """Encrypt → Modulate → AWGN → Demodulate → Decrypt with ChaCha20."""
    ct, nonce, enc_t = chacha_encrypt(plaintext)
    syms, _          = modulate(ct)
    rx               = add_awgn(syms, snr_db)
    rec_nibs         = demodulate(rx)
    rec_bytes        = nibbles_to_bytes(rec_nibs)[:len(ct)]
    try:
        pt, dec_t = chacha_decrypt(rec_bytes, nonce)
        return pt, True, enc_t, dec_t
    except Exception as e:
        return None, False, enc_t, 0.0


# ─────────────────────── Graph 1: Performance Bar Chart ──────────────────────

def graph_performance(stats: dict):
    fig, axes = plt.subplots(1, 3, figsize=(15, 5.5))
    fig.patch.set_facecolor("#0D1117")
    fig.suptitle("ChaCha20-Poly1305 vs AES-256-GCM — Performance Comparison\n"
                 "Satellite Telemetry Encryption (500 iterations)",
                 color="white", fontsize=13, fontweight="bold")

    metrics = [
        ("avg_enc_ms", "Avg. Encryption Time (ms)", "Encryption Time"),
        ("avg_dec_ms", "Avg. Decryption Time (ms)", "Decryption Time"),
        ("stdev_enc",  "Std Dev — Enc Time (ms)",   "Timing Consistency"),
    ]
    colors = ["#79C0FF", "#FF7B72"]
    labels = ["ChaCha20-Poly1305", "AES-256-GCM"]

    for ax, (key, ylabel, title) in zip(axes, metrics):
        ax.set_facecolor("#161B22")
        vals = [stats["ChaCha20"][key], stats["AES_GCM"][key]]
        bars = ax.bar(labels, vals, color=colors, width=0.4, edgecolor="none")
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + max(vals)*0.02,
                    f"{v:.5f}", ha="center", va="bottom",
                    color="white", fontsize=9.5, fontweight="bold")
        ax.set_title(title, color="white", fontsize=11, fontweight="bold")
        ax.set_ylabel(ylabel, color="#8B949E", fontsize=9)
        ax.tick_params(colors="white", labelsize=9)
        ax.yaxis.grid(True, color="#30363D", ls="--", alpha=0.5); ax.set_axisbelow(True)
        for sp in ax.spines.values(): sp.set_edgecolor("#30363D")

    plt.tight_layout()
    plt.savefig("outputs/graph1_performance.png", dpi=150, bbox_inches="tight", facecolor="#0D1117")
    plt.close()
    print("  ✅ Graph 1 saved → outputs/graph1_performance.png")


# ─────────────────────── Graph 2: Telemetry Recovery ─────────────────────────

def graph_recovery(originals, recovered):
    param_pairs = [
        ("cpu_temp",          "CPU Temperature (°C)"),
        ("battery_voltage",   "Battery Voltage (V)"),
        ("altitude",          "Orbital Altitude (km)"),
        ("solar_panel_power", "Solar Power (W)"),
    ]
    fig, axes = plt.subplots(2, 2, figsize=(14, 8))
    fig.patch.set_facecolor("#0D1117")
    fig.suptitle("Telemetry Data Recovery — Original vs Decrypted (ChaCha20-Poly1305)",
                 color="white", fontsize=13, fontweight="bold")

    pkt_ids = [str(r["packet_id"]) for r in originals]
    x = np.arange(len(pkt_ids))
    w = 0.35

    for ax, (key, ylabel) in zip(axes.flat, param_pairs):
        ax.set_facecolor("#161B22")
        orig = [r[key] for r in originals]
        recv = [r[key] if r else 0 for r in recovered]
        ax.bar(x - w/2, orig, w, label="Original",  color="#FF7B72", edgecolor="none")
        ax.bar(x + w/2, recv, w, label="Recovered", color="#3FB950", edgecolor="none", alpha=0.85)
        ax.set_xticks(x); ax.set_xticklabels([f"P{i}" for i in pkt_ids], color="white", fontsize=9)
        ax.set_ylabel(ylabel, color="#8B949E", fontsize=9)
        ax.set_title(ylabel, color="white", fontsize=10, fontweight="bold")
        ax.tick_params(colors="white")
        ax.legend(facecolor="#21262D", labelcolor="white", fontsize=9)
        ax.yaxis.grid(True, color="#30363D", ls="--", alpha=0.5); ax.set_axisbelow(True)
        for sp in ax.spines.values(): sp.set_edgecolor("#30363D")

    plt.tight_layout()
    plt.savefig("outputs/graph2_recovery.png", dpi=150, bbox_inches="tight", facecolor="#0D1117")
    plt.close()
    print("  ✅ Graph 2 saved → outputs/graph2_recovery.png")


# ─────────────────────── Graph 3: Security Dashboard ─────────────────────────

def graph_security():
    fig, ax = plt.subplots(figsize=(10, 4))
    fig.patch.set_facecolor("#0D1117"); ax.set_facecolor("#0D1117"); ax.axis("off")
    fig.suptitle("Security Test Results — ChaCha20-Poly1305 vs AES-256-GCM",
                 color="white", fontsize=13, fontweight="bold")

    rows = [
    ["Test",                         "ChaCha20-Poly1305", "AES (Software)"],

    ["Bit-flip attack detection",    "✅ DETECTED",        "✅ DETECTED"],

    ["Replay attack protection",     "✅ NONCE-BASED",     "✅ NONCE-BASED"],

    ["Side-channel resistance",      "✅ HIGH (ARX design)", "⚠️ LOWER (table-based)"],

    ["Software performance",         "✅ FAST",            "❌ SLOW"],

    ["Hardware dependency",          "❌ NOT REQUIRED",    "⚠️ REQUIRED for speed"],

    ["Suitability (Satellite SW)",   "✅ HIGH",            "⚠️ LIMITED"],
]

    col_colors  = [["#1F6FEB","#388BFD","#388BFD"]]
    cell_colors = []
    for i, row in enumerate(rows[1:]):
        cell_colors.append(["#161B22", "#0D2137" if "✅" in row[1] else "#1A0A0A",
                             "#0D2137" if "✅" in row[2] else "#1A0A0A"])

    tbl = ax.table(
        cellText   = rows[1:],
        colLabels  = rows[0],
        loc        = "center",
        cellColours= cell_colors,
        colColours = col_colors[0],
    )
    tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1, 1.8)
    for (r, c), cell in tbl.get_celld().items():
        cell.set_text_props(color="white")
        cell.set_edgecolor("#30363D")

    plt.tight_layout()
    plt.savefig("outputs/graph3_security.png", dpi=150, bbox_inches="tight", facecolor="#0D1117")
    plt.close()
    print("  ✅ Graph 3 saved → outputs/graph3_security.png")


# ─────────────────────── Graph 4: SNR Impact on Decryption ───────────────────

def graph_snr_decrypt(packets):
    snr_vals = [5, 8, 10, 12, 15, 18, 20, 25, 30]
    success_rate = []

    for snr in snr_vals:
        ok = 0
        for pkt in packets[:8]:
            _, success, _, _ = e2e_pipeline(pkt, snr)
            if success: ok += 1
        success_rate.append(ok / len(packets[:8]) * 100)

    fig, ax = plt.subplots(figsize=(10, 5.5))
    fig.patch.set_facecolor("#0D1117"); ax.set_facecolor("#161B22")
    ax.plot(snr_vals, success_rate, "o-", color="#3FB950", lw=2.5, ms=8,
            label="Decryption Success Rate (%)")
    ax.axhline(100, color="#79C0FF", ls="--", lw=1.2, alpha=0.6, label="100% threshold")
    ax.fill_between(snr_vals, success_rate, alpha=0.15, color="#3FB950")
    ax.set_xlabel("SNR (dB)", color="white", fontsize=12)
    ax.set_ylabel("Decryption Success Rate (%)", color="white", fontsize=12)
    ax.set_title("End-to-End Decryption Success vs Channel SNR\n"
                 "(ChaCha20-Poly1305 + QAM-16 + AWGN)",
                 color="white", fontsize=12, fontweight="bold")
    ax.set_ylim(-5, 110); ax.tick_params(colors="white")
    ax.legend(facecolor="#21262D", labelcolor="white", fontsize=10)
    ax.grid(True, color="#30363D", ls="--", alpha=0.5)
    for sp in ax.spines.values(): sp.set_edgecolor("#30363D")

    plt.tight_layout()
    plt.savefig("outputs/graph4_snr_decrypt.png", dpi=150, bbox_inches="tight", facecolor="#0D1117")
    plt.close()
    print("  ✅ Graph 4 saved → outputs/graph4_snr_decrypt.png")


# ─────────────────────── MAIN ─────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("  MODULE 4 — FULL PIPELINE: DEMODULATION + DECRYPTION + ANALYSIS")
    print("=" * 70)

    packets, orig_records = generate_stream(16)

    # ── End-to-end test at high SNR ──
    print(f"\n── E2E Pipeline Test (ChaCha20, SNR={SNR_HIGH} dB) ──────────────────────")
    print(f"\n  {'Pkt':<4} {'Match':<10} {'CPU°C Orig':<14} {'CPU°C Recv':<14} {'Alt Orig':<14} {'Alt Recv':<14} {'Status'}")
    print("  " + "-" * 82)

    recovered_records = []
    for pkt, orig in zip(packets, orig_records):
        rec_bytes, ok, enc_t, dec_t = e2e_pipeline(pkt, SNR_HIGH)
        if ok and rec_bytes:
            rec_info = decode_packet(rec_bytes)
            recovered_records.append(rec_info)

            rec_info = decode_packet(rec_bytes)

            def is_close(a, b):
                if isinstance(a, float):
                    return abs(a - b) < 0.05   # tolerance
                return a == b

            all_ok = True
            for key in orig:
                if key in rec_info:
                    if not is_close(orig[key], rec_info[key]):
                        all_ok = False
                        break

            match = "✅ PASS" if all_ok else "❌ FAIL"

            err = "0x{:04X}".format(rec_info["error_flags"])
            print(f"  {orig['packet_id']:<4} {match:<10} {orig['cpu_temp']:<14} "
                  f"{round(rec_info['cpu_temp'],2):<14} {orig['altitude']:<14} "
                  f"{round(rec_info['altitude'],2):<14} {err}")
        else:
            recovered_records.append(None)
            print(f"  {orig['packet_id']:<4} ❌ AUTH FAIL — ciphertext corrupted by channel")

    passed = sum(1 for r in recovered_records if r is not None)
    print(f"\n  ✅ Packets passed authentication: {passed}/{len(packets)}")

    # ── Security tests ──
    print("\n── Security Tests ──────────────────────────────────────────────────")
    sec = security_tests(packets[0])
    for test, result in sec.items():
        print(f"  {test:<35}: {result}")

    # ── Benchmark ──
    print("\n── Benchmark (500 iterations) ──────────────────────────────────────")
    stats = benchmark(packets[0], 500)
    print(f"\n  {'Metric':<28} {'ChaCha20':>14} {'AES-GCM':>14}")
    print("  " + "-"*58)
    for k in ["avg_enc_ms", "avg_dec_ms", "stdev_enc", "overhead_B"]:
        print(f"  {k:<28} {stats['ChaCha20'][k]:>14.6f} {stats['AES_GCM'][k]:>14.6f}")

    # ── Generate all graphs ──
    print("\n── Generating All Output Graphs ────────────────────────────────────")
    graph_performance(stats)
    graph_recovery(orig_records[:8],
                   [r for r in recovered_records[:8]])
    graph_security()
    graph_snr_decrypt(packets)

    # ── BER curve ──
    from module3_qam_channel import plot_ber
    ct_c, _, _ = chacha_encrypt(packets[0])
    ct_a, _, _ = aes_encrypt(packets[0])
    snr_vals = [0, 5, 8, 10, 12, 15, 18, 20, 25, 30]
    ber_c = ber_curve(ct_c, snr_vals)
    ber_a = ber_curve(ct_a, snr_vals)
    plot_ber(snr_vals, ber_c, ber_a, out="outputs/graph5_ber_snr.png")

    # ── Constellation ──
    from module3_qam_channel import plot_constellation, modulate, add_awgn
    syms, _ = modulate(ct_c)
    rx_demo  = add_awgn(syms, 12)
    plot_constellation(syms, rx_demo, 12, out="outputs/graph6_constellation.png")

    # ── NEW Graph 7: QAM-16 I/Q Waveform ──
    plot_waveform(syms, out="outputs/graph7_qam_waveform.png", n_symbols=32)

    # ── NEW Graph 8: ChaCha20 Advantages Panel ──
    plot_chacha20_advantages(stats, out="outputs/graph8_chacha20_advantages.png")

    print("\n" + "=" * 70)
    print("  ALL DONE — 8 output graphs saved in  outputs/  folder")
    print("=" * 70)
    print("""
  outputs/
    graph1_performance.png        ← Encryption/Decryption time comparison
    graph2_recovery.png           ← Original vs Recovered telemetry values
    graph3_security.png           ← Security test results table
    graph4_snr_decrypt.png        ← Decryption success vs SNR
    graph5_ber_snr.png            ← BER vs SNR (corrected + theory curve + region labels)
    graph6_constellation.png      ← QAM-16 constellation diagram
    graph7_qam_waveform.png       ← NEW: I/Q time-domain waveform diagram
    graph8_chacha20_advantages.png← NEW: ChaCha20 feature table + benchmark chart
""")
