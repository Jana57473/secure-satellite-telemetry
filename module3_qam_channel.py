"""
MODULE 3 — QAM-16 Modulation + AWGN Satellite Channel Simulation
Project: Securing Satellite Telemetry in Software-Defined Space Link

CHANGES (v2):
  - Added plot_waveform()         → I/Q time-domain waveform diagram
  - Added plot_chacha20_advantages() → feature table + benchmark chart
  - Corrected BER vs SNR plot    → theoretical curve + region annotations
  - BER clarification: ChaCha20 & AES-GCM produce same BER (only channel matters)
"""

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os

# ── Gray-coded QAM-16 symbol map (4 bits → complex symbol) ───────────────────
QAM16_MAP = {
    0b0000:(-3+3j), 0b0001:(-1+3j), 0b0011:(1+3j),  0b0010:(3+3j),
    0b0100:(-3+1j), 0b0101:(-1+1j), 0b0111:(1+1j),  0b0110:(3+1j),
    0b1100:(-3-1j), 0b1101:(-1-1j), 0b1111:(1-1j),  0b1110:(3-1j),
    0b1000:(-3-3j), 0b1001:(-1-3j), 0b1011:(1-3j),  0b1010:(3-3j),
}
INV_MAP     = {v: k for k, v in QAM16_MAP.items()}
SYMBOL_ARR  = np.array(list(QAM16_MAP.values()))


# ── Core DSP functions ────────────────────────────────────────────────────────

def bytes_to_nibbles(data: bytes):
    nibs = []
    for b in data:
        nibs.append((b >> 4) & 0xF)
        nibs.append(b & 0xF)
    return nibs

def nibbles_to_bytes(nibs):
    out = []
    for i in range(0, len(nibs) - 1, 2):
        out.append(((nibs[i] & 0xF) << 4) | (nibs[i+1] & 0xF))
    return bytes(out)

def modulate(data: bytes):
    nibs = bytes_to_nibbles(data)
    return np.array([QAM16_MAP[n] for n in nibs], dtype=complex), nibs

def add_awgn(symbols, snr_db):
    snr   = 10 ** (snr_db / 10)
    sp    = np.mean(np.abs(symbols) ** 2)
    noise = np.sqrt(sp / snr / 2) * (
        np.random.randn(len(symbols)) + 1j * np.random.randn(len(symbols)))
    return symbols + noise

def demodulate(rx):
    nibs = []
    for s in rx:
        idx = np.argmin(np.abs(SYMBOL_ARR - s))
        nibs.append(INV_MAP[SYMBOL_ARR[idx]])
    return nibs

def ber(orig_nibs, rec_nibs):
    bits = len(orig_nibs) * 4
    errs = sum(bin(o ^ r).count('1') for o, r in zip(orig_nibs, rec_nibs))
    return errs / bits if bits else 0.0

def ber_curve(data: bytes, snr_range):
    syms, orig_nibs = modulate(data)
    bers = []
    for snr in snr_range:
        rx = add_awgn(syms, snr)
        bers.append(ber(orig_nibs, demodulate(rx)))
    return bers

def theoretical_ber_qam16(snr_db_range):
    """
    Theoretical BER for Gray-coded QAM-16 over AWGN:
      BER = (3/8) * erfc( sqrt(snr_linear / 10) )
    Both ChaCha20 and AES-GCM yield the same BER because the cipher does NOT
    alter the channel noise characteristics — only SNR matters.
    """
    try:
        from scipy.special import erfc
    except ImportError:
        return None
    bers = []
    for snr_db in snr_db_range:
        snr_lin = 10 ** (snr_db / 10)
        ber_val = (3.0 / 8.0) * erfc(np.sqrt(snr_lin / 10.0))
        bers.append(max(float(ber_val), 1e-7))
    return bers


# ── Plot 1: Constellation ─────────────────────────────────────────────────────

def plot_constellation(tx, rx, snr_db, out="outputs/constellation.png"):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))
    fig.patch.set_facecolor("#0D1117")
    fig.suptitle("QAM-16 Constellation — Satellite Channel",
                 color="white", fontsize=14, fontweight="bold")

    for ax, syms, title in [
        (axes[0], tx, "Transmitted (No Noise)"),
        (axes[1], rx, f"Received  (SNR = {snr_db} dB)"),
    ]:
        ax.set_facecolor("#161B22")
        ax.scatter(syms.real, syms.imag, s=8, alpha=0.55, color="#58A6FF", edgecolors="none")
        for sym in QAM16_MAP.values():
            ax.plot(sym.real, sym.imag, "r+", markersize=10, markeredgewidth=1.5)
        ax.axhline(0, color="#30363D", lw=0.6)
        ax.axvline(0, color="#30363D", lw=0.6)
        ax.set_title(title, color="white", fontsize=11, fontweight="bold")
        ax.set_xlabel("In-phase (I)", color="#8B949E")
        ax.set_ylabel("Quadrature (Q)", color="#8B949E")
        ax.tick_params(colors="#8B949E")
        for sp in ax.spines.values(): sp.set_edgecolor("#30363D")

    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="#0D1117")
    plt.close()
    print(f"  ✅ Constellation saved → {out}")


# ── Plot 2: BER vs SNR (corrected + annotated) ────────────────────────────────

def plot_ber(snr_vals, ber_c, ber_a, out="outputs/ber_vs_snr.png"):
    """
    Corrected BER plot with:
    - Simulated BER for ChaCha20-Poly1305 ciphertext
    - Simulated BER for AES-256-GCM ciphertext
    - Theoretical QAM-16 AWGN reference curve
    - SNR region annotations (Poor / Fair / Good / Excellent)
    - Explanatory note: both ciphers yield the same BER
    """
    os.makedirs(os.path.dirname(out), exist_ok=True)
    theory_bers = theoretical_ber_qam16(snr_vals)

    fig, ax = plt.subplots(figsize=(12, 7))
    fig.patch.set_facecolor("#0D1117")
    ax.set_facecolor("#161B22")

    ax.semilogy(snr_vals, [max(b, 1e-7) for b in ber_c],
                "o-",  color="#79C0FF", lw=2.5, ms=7,
                label="Simulated — ChaCha20-Poly1305 ciphertext")
    ax.semilogy(snr_vals, [max(b, 1e-7) for b in ber_a],
                "s--", color="#FF7B72", lw=2.5, ms=7,
                label="Simulated — AES-256-GCM ciphertext")
    if theory_bers:
        ax.semilogy(snr_vals, theory_bers,
                    "^-.", color="#3FB950", lw=2.0, ms=6,
                    label="Theoretical QAM-16 AWGN (academic reference)")

    # SNR operating regions
    regions = [
        (0,  5,  "#FF7B72", "Poor\n(BER > 0.01)"),
        (5,  12, "#F0883E", "Fair\n(BER ~0.001)"),
        (12, 20, "#79C0FF", "Good\n(LEO Typical)"),
        (20, 30, "#3FB950", "Excellent\n(BER < 1e-5)"),
    ]
    for x0, x1, color, label in regions:
        ax.axvspan(x0, x1, alpha=0.07, color=color)
        ax.text((x0 + x1) / 2, 2e-1, label, ha="center", va="top",
                color=color, fontsize=8.5, fontweight="bold",
                bbox=dict(facecolor="#0D1117", edgecolor=color,
                          boxstyle="round,pad=0.3", alpha=0.8))

    # Annotation explaining overlap
    ax.annotate(
        "⚠  ChaCha20 & AES-GCM curves overlap:\n"
        "    Cipher choice does NOT affect BER.\n"
        "    Only AWGN noise level (SNR) determines BER.",
        xy=(14, 5e-4), xytext=(17, 2e-2),
        color="#E3B341", fontsize=8.5,
        arrowprops=dict(arrowstyle="->", color="#E3B341", lw=1.2),
        bbox=dict(facecolor="#161B22", edgecolor="#E3B341",
                  boxstyle="round,pad=0.4"),
    )

    ax.set_xlabel("SNR (dB)", color="white", fontsize=12)
    ax.set_ylabel("Bit Error Rate (BER)", color="white", fontsize=12)
    ax.set_title(
        "BER vs SNR — QAM-16 over AWGN Satellite Channel\n"
        "(Simulated ciphertexts + Theoretical QAM-16 reference curve)",
        color="white", fontsize=13, fontweight="bold"
    )
    ax.legend(facecolor="#21262D", labelcolor="white", fontsize=10)
    ax.tick_params(colors="white")
    ax.grid(True, color="#30363D", ls="--", alpha=0.5)
    ax.set_xlim(min(snr_vals) - 0.5, max(snr_vals) + 0.5)
    for sp in ax.spines.values(): sp.set_edgecolor("#30363D")

    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="#0D1117")
    plt.close()
    print(f"  ✅ BER vs SNR (corrected + annotated) saved → {out}")


# ── Plot 3 (NEW): QAM-16 I/Q Waveform Diagram ────────────────────────────────

def plot_waveform(symbols, out="outputs/qam_waveform.png",
                  n_symbols=32, samples_per_symbol=20):
    """
    QAM-16 I/Q time-domain baseband waveform.

    Three panels:
      Top    — In-Phase I(t) component (stepped / zero-order hold)
      Middle — Quadrature Q(t) component
      Bottom — Signal envelope |s(t)| = sqrt(I² + Q²)

    Each step corresponds to one transmitted QAM-16 symbol.
    Dashed vertical lines mark symbol boundaries every 4 symbols.
    """
    os.makedirs(os.path.dirname(out), exist_ok=True)

    syms = symbols[:n_symbols]
    I    = syms.real
    Q    = syms.imag
    mag  = np.abs(syms)

    t        = np.arange(len(syms) * samples_per_symbol) / samples_per_symbol
    I_wave   = np.repeat(I,   samples_per_symbol)
    Q_wave   = np.repeat(Q,   samples_per_symbol)
    mag_wave = np.repeat(mag, samples_per_symbol)

    fig, axes = plt.subplots(3, 1, figsize=(16, 9), sharex=True)
    fig.patch.set_facecolor("#0D1117")
    fig.suptitle(
        f"QAM-16  I/Q  Baseband Waveform  —  First {n_symbols} Symbols\n"
        "Satellite Telemetry (ChaCha20-Poly1305 Encrypted Payload)",
        color="white", fontsize=13, fontweight="bold", y=1.01
    )

    panel_cfg = [
        (axes[0], I_wave,   "#79C0FF", "In-Phase  I(t)",      "Amplitude (I)"),
        (axes[1], Q_wave,   "#FF7B72", "Quadrature  Q(t)",    "Amplitude (Q)"),
        (axes[2], mag_wave, "#3FB950", "Envelope  |s(t)|",    "Magnitude"),
    ]
    symbol_levels = [-3, -1, 1, 3]

    for ax, wave, color, title, ylabel in panel_cfg:
        ax.set_facecolor("#161B22")
        ax.plot(t, wave, color=color, lw=1.4, alpha=0.92)
        ax.fill_between(t, 0, wave, alpha=0.13, color=color)

        if ax in (axes[0], axes[1]):
            for lvl in symbol_levels:
                ax.axhline(lvl, color="#30363D", lw=0.7, ls=":")
            ax.set_ylim(-4.5, 4.5)
            ax.set_yticks(symbol_levels)
            ax.set_yticklabels([f"{l:+d}" for l in symbol_levels],
                               color="#8B949E", fontsize=9)
        else:
            ref_levels = [np.sqrt(2), np.sqrt(10), np.sqrt(18)]
            for lvl in ref_levels:
                ax.axhline(lvl, color="#30363D", lw=0.7, ls=":")
            ax.set_ylim(0, 5.5)
            ax.set_yticks(ref_levels)
            ax.set_yticklabels(["√2  (corner)", "√10 (edge)", "√18 (corner max)"],
                               color="#8B949E", fontsize=8)

        ax.set_ylabel(ylabel, color="#8B949E", fontsize=10)
        ax.set_title(title, color=color, fontsize=11, fontweight="bold",
                     loc="left", pad=4)
        ax.axhline(0, color="#555", lw=0.8)
        ax.tick_params(colors="#8B949E")
        for sp in ax.spines.values(): sp.set_edgecolor("#30363D")

        # Symbol boundary markers every 4 symbols
        for sym_idx in range(0, n_symbols + 1, 4):
            ax.axvline(sym_idx, color="#30363D", lw=0.7, ls="--", alpha=0.7)

    # Annotate first 10 symbols with (I, Q) label on top panel
    for i in range(min(n_symbols, 10)):
        iv = I[i]; qv = Q[i]
        axes[0].annotate(
            f"({iv:+.0f},{qv:+.0f})",
            xy=(i + 0.5, iv),
            xytext=(i + 0.5, iv + (1.2 if iv >= 0 else -1.5)),
            ha="center", fontsize=6.5, color="#E3B341",
            arrowprops=dict(arrowstyle="-", color="#E3B341", lw=0.5)
        )

    axes[2].set_xlabel("Symbol Index", color="#8B949E", fontsize=11)
    axes[2].xaxis.set_major_locator(plt.MultipleLocator(4))
    axes[2].tick_params(colors="#8B949E")

    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="#0D1117")
    plt.close()
    print(f"  ✅ QAM-16 I/Q Waveform saved → {out}")


# ── Plot 4 (NEW): ChaCha20-Poly1305 Advantages Panel ─────────────────────────

def plot_chacha20_advantages(stats=None, out="outputs/chacha20_advantages.png"):
    """
    Two-panel figure:
      Left  — Feature comparison table  (ChaCha20-Poly1305 vs AES-256-GCM)
      Right — Benchmark bar chart       (from module2 benchmark stats)
    + Bottom summary text explaining why ChaCha20 is preferred for satellites.
    """
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fig = plt.figure(figsize=(16, 7.5))
    fig.patch.set_facecolor("#0D1117")
    fig.suptitle(
        "ChaCha20-Poly1305 — Why It's Chosen for Satellite Telemetry Security",
        color="white", fontsize=14, fontweight="bold"
    )

    # ── Left: feature table ──────────────────────────────────────────────────
    ax_tbl = fig.add_subplot(1, 2, 1)
    ax_tbl.set_facecolor("#0D1117")
    ax_tbl.axis("off")

    rows = [
        ["Feature",                         "ChaCha20-Poly1305",         "AES (Software)"],
        ["Hardware acceleration needed",    "❌ No",                     "⚠️ Yes for speed"],
        ["Software performance",            "✅ Fast (ARX design)",      "❌ Slower"],
        ["Side-channel resistance",         "✅ High (constant-time)",   "⚠️ Lower"],
        ["Bit-flip attack detection",       "✅ Detected",               "✅ Detected"],
        ["Replay attack protection",        "✅ Nonce-based",            "✅ Nonce-based"],
        ["Power consumption",               "✅ Low",                    "⚠️ Higher"],
        ["Suitability (Satellite SW)",      "✅ High",                   "⚠️ Limited"],
        ["BER impact",                      "❌ No effect",              "❌ No effect"],
    ]

    col_colors = ["#1A2540", "#0A2A0A", "#2A1A0A"]
    cell_colors = []
    for row in rows[1:]:
        def cell_color(txt):
            if "[YES]" in txt:   return "#0A1F0A"
            if "[NO]" in txt:    return "#1F0A0A"
            if "[WARN]" in txt:  return "#1F180A"
            return "#161B22"
        cell_colors.append([cell_color(row[0]), cell_color(row[1]), cell_color(row[2])])

    tbl = ax_tbl.table(
        cellText    = rows[1:],
        colLabels   = rows[0],
        loc         = "center",
        cellColours = cell_colors,
        colColours  = col_colors,
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8.5)
    tbl.scale(1, 1.62)
    for (r, c), cell in tbl.get_celld().items():
        cell.set_text_props(color="white")
        cell.set_edgecolor("#30363D")

    # ── Right: benchmark bar chart ────────────────────────────────────────────
    ax_bar = fig.add_subplot(1, 2, 2)
    ax_bar.set_facecolor("#161B22")

    if stats:
        metrics = ["avg_enc_ms", "avg_dec_ms", "stdev_enc"]
        labels  = ["Avg Encrypt\n(ms)", "Avg Decrypt\n(ms)", "Timing\nStd Dev (ms)"]
        x  = np.arange(len(metrics))
        w  = 0.32
        cv = [stats["ChaCha20"][m] for m in metrics]
        av = [stats["AES_GCM"][m]  for m in metrics]

        bars_c = ax_bar.bar(x - w/2, cv, w, label="ChaCha20-Poly1305",
                            color="#79C0FF", edgecolor="none")
        bars_a = ax_bar.bar(x + w/2, av, w, label="AES-256-GCM",
                            color="#FF7B72", edgecolor="none")

        top = max(max(cv), max(av))
        for bars, vals in [(bars_c, cv), (bars_a, av)]:
            for bar, v in zip(bars, vals):
                ax_bar.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + top * 0.02,
                    f"{v:.5f}", ha="center", va="bottom",
                    color="white", fontsize=8, fontweight="bold"
                )

        faster = "ChaCha20" if cv[0] <= av[0] else "AES-GCM"
        diff_pct = abs(cv[0] - av[0]) / max(av[0], 1e-9) * 100
        ax_bar.set_title(
            f"Benchmark — 500 Iterations / 59-byte Packet\n"
            f"[WINNER]  {faster} is faster  ({diff_pct:.1f}% difference)",
            color="white", fontsize=10, fontweight="bold"
        )
        ax_bar.set_xticks(x)
        ax_bar.set_xticklabels(labels, color="white", fontsize=9)
        ax_bar.set_ylabel("Time (ms)", color="#8B949E", fontsize=10)
        ax_bar.legend(facecolor="#21262D", labelcolor="white", fontsize=9)
        ax_bar.yaxis.grid(True, color="#30363D", ls="--", alpha=0.5)
        ax_bar.set_axisbelow(True)
        ax_bar.tick_params(colors="white")
        for sp in ax_bar.spines.values(): sp.set_edgecolor("#30363D")
    else:
        ax_bar.text(0.5, 0.5, "Run benchmark (Module 2)\nto populate this chart",
                    ha="center", va="center", color="#8B949E", fontsize=12,
                    transform=ax_bar.transAxes)
        ax_bar.set_title("Benchmark Comparison", color="white", fontsize=11)
        for sp in ax_bar.spines.values(): sp.set_edgecolor("#30363D")
        ax_bar.tick_params(colors="white")

    # ── Bottom summary ────────────────────────────────────────────────────────
    summary = (
        "KEY ADVANTAGES OF ChaCha20-Poly1305 (SOFTWARE-DEFINED SATELLITE SYSTEM)\n"
        "① No hardware acceleration required — efficient in pure software environments\n"
        "② ARX-based design ensures constant-time execution → strong side-channel resistance\n"
        "③ Lower computational complexity → faster encryption in software implementation\n"
        "④ Poly1305 authentication ensures tamper detection (bit-flip, replay)\n"
        "⑤ Channel BER depends only on SNR — encryption algorithm does NOT affect transmission quality"
    )
    fig.text(0.5, -0.03, summary, ha="center", va="top", color="#C9D1D9",
             fontsize=8.8, linespacing=1.7,
             bbox=dict(facecolor="#161B22", edgecolor="#30363D",
                       boxstyle="round,pad=0.7", alpha=0.95))

    plt.tight_layout(rect=[0, 0.10, 1, 1])
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="#0D1117")
    plt.close()
    print(f"  ✅ ChaCha20 Advantages panel saved → {out}")


# ── Main (Module 3 standalone run) ───────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from module1_telemetry_gen import generate_stream
    from module2_encryption    import chacha_encrypt, aes_encrypt, benchmark

    print("=" * 70)
    print("  MODULE 3 — QAM-16 MODULATION + AWGN CHANNEL  (v2)")
    print("=" * 70)

    pkts, _ = generate_stream(1)
    ct_c, _, _ = chacha_encrypt(pkts[0])
    ct_a, _, _ = aes_encrypt(pkts[0])

    syms_c, _ = modulate(ct_c)
    syms_a, _ = modulate(ct_a)

    print(f"\n  Plaintext      : {len(pkts[0])} bytes")
    print(f"  ChaCha20 CT    : {len(ct_c)} bytes → {len(syms_c)} QAM-16 symbols")
    print(f"  AES-GCM  CT    : {len(ct_a)} bytes → {len(syms_a)} QAM-16 symbols")

    SNR_DEMO = 12
    rx_demo  = add_awgn(syms_c, SNR_DEMO)
    plot_constellation(syms_c, rx_demo, SNR_DEMO)

    snr_vals = [0, 5, 8, 10, 12, 15, 18, 20, 25, 30]
    ber_c = ber_curve(ct_c, snr_vals)
    ber_a = ber_curve(ct_a, snr_vals)

    print(f"\n  {'SNR(dB)':<10} {'BER ChaCha20':<18} {'BER AES-GCM':<18} {'Observation'}")
    print("  " + "-" * 75)
    for s, bc, ba in zip(snr_vals, ber_c, ber_a):
        obs = "≈ identical (cipher≠channel)" if abs(bc - ba) < 0.01 else f"diff={abs(bc-ba):.4f}"
        print(f"  {s:<10} {bc:<18.6f} {ba:<18.6f} {obs}")

    print("\n  ★ NOTE: ChaCha20 and AES-GCM BERs are nearly identical.")
    print("    BER depends only on SNR and modulation (QAM-16), NOT the cipher.")
    print("    Theoretical curve added as academic reference.\n")

    plot_ber(snr_vals, ber_c, ber_a)

    # NEW: I/Q Waveform
    plot_waveform(syms_c, n_symbols=32)

    # NEW: ChaCha20 advantages with benchmark
    print("  Running benchmark for advantages panel (300 iter)...")
    stats = benchmark(pkts[0], 300)
    plot_chacha20_advantages(stats)

    print("\n  Outputs this run:")
    print("    outputs/constellation.png")
    print("    outputs/ber_vs_snr.png          ← corrected + theory curve + region labels")
    print("    outputs/qam_waveform.png         ← NEW I/Q time-domain waveform")
    print("    outputs/chacha20_advantages.png  ← NEW feature table + benchmark chart")
    print("\n→ Module 3 complete.\n")
