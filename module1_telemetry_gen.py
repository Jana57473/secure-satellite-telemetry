"""
MODULE 1 - Telemetry Data Generation
Project: Securing Satellite Telemetry in Software-Defined Space Link
16 Real Satellite Telemetry Parameters
"""

import struct
import time
import random

def generate_telemetry_packet(packet_id=1):
    """
    16 Real Satellite Telemetry Parameters:
    1.  packet_id          - Packet sequence number       (uint8,  1 byte)
    2.  mission_time       - Mission elapsed time (s)     (uint32, 4 bytes)
    3.  cpu_temp           - On-board CPU temp (°C)       (float,  4 bytes)
    4.  battery_voltage    - Battery voltage (V)          (float,  4 bytes)
    5.  battery_current    - Battery current (mA)         (float,  4 bytes)
    6.  solar_panel_power  - Solar panel power (W)        (float,  4 bytes)
    7.  altitude           - Orbital altitude (km)        (float,  4 bytes)
    8.  velocity           - Orbital velocity (km/s)      (float,  4 bytes)
    9.  attitude_roll      - Roll angle (°)               (float,  4 bytes)
    10. attitude_pitch     - Pitch angle (°)              (float,  4 bytes)
    11. attitude_yaw       - Yaw angle (°)                (float,  4 bytes)
    12. signal_strength    - Downlink RSSI (dBm)          (float,  4 bytes)
    13. tx_frequency       - Transmit frequency (MHz)     (float,  4 bytes)
    14. payload_temp       - Payload unit temp (°C)       (float,  4 bytes)
    15. memory_usage       - Memory used (%)              (float,  4 bytes)
    16. error_flags        - System error bitmask         (uint16, 2 bytes)

    Total: 1+4+4+4+4+4+4+4+4+4+4+4+4+4+4+2 = 59 bytes per packet
    """

    data = {
        "packet_id"        : packet_id,
        "mission_time"     : int(time.time()) - 1700000000 + packet_id * 10,
        "cpu_temp"         : round(random.uniform(35.0,  75.0), 2),
        "battery_voltage"  : round(random.uniform(11.5,  14.8), 2),
        "battery_current"  : round(random.uniform(200.0, 950.0), 2),
        "solar_panel_power": round(random.uniform(10.0,  120.0), 2),
        "altitude"         : round(random.uniform(400.0, 600.0), 2),
        "velocity"         : round(random.uniform(7.5,   7.9),   3),
        "attitude_roll"    : round(random.uniform(-5.0,  5.0),   3),
        "attitude_pitch"   : round(random.uniform(-5.0,  5.0),   3),
        "attitude_yaw"     : round(random.uniform(-5.0,  5.0),   3),
        "signal_strength"  : round(random.uniform(-110.0, -60.0), 1),
        "tx_frequency"     : round(random.uniform(2200.0, 2300.0), 2),
        "payload_temp"     : round(random.uniform(20.0,  55.0),  2),
        "memory_usage"     : round(random.uniform(20.0,  85.0),  1),
        "error_flags"      : random.choice([0x0000, 0x0000, 0x0000, 0x0001, 0x0002]),
    }

    # Pack to binary: B=uint8, I=uint32, f=float, H=uint16  (big-endian >)
    packet = struct.pack(
        ">BIfffffffffffff H",
        data["packet_id"],
        data["mission_time"],
        data["cpu_temp"],
        data["battery_voltage"],
        data["battery_current"],
        data["solar_panel_power"],
        data["altitude"],
        data["velocity"],
        data["attitude_roll"],
        data["attitude_pitch"],
        data["attitude_yaw"],
        data["signal_strength"],
        data["tx_frequency"],
        data["payload_temp"],
        data["memory_usage"],
        data["error_flags"],
    )

    return packet, data


def decode_packet(raw: bytes):
    """Unpack binary back to telemetry dict."""
    vals = struct.unpack(">BIfffffffffffff H", raw)
    keys = [
        "packet_id","mission_time","cpu_temp","battery_voltage",
        "battery_current","solar_panel_power","altitude","velocity",
        "attitude_roll","attitude_pitch","attitude_yaw","signal_strength",
        "tx_frequency","payload_temp","memory_usage","error_flags"
    ]
    return dict(zip(keys, vals))


def generate_stream(count=10):
    packets, records = [], []
    for i in range(1, count + 1):
        pkt, rec = generate_telemetry_packet(i)
        packets.append(pkt)
        records.append(rec)
    return packets, records


if __name__ == "__main__":
    print("=" * 75)
    print("  MODULE 1 — SATELLITE TELEMETRY DATA GENERATION (16 Parameters)")
    print("=" * 75)

    packets, records = generate_stream(10)

    fields = [
        ("cpu_temp",          "CPU Temp (°C)"),
        ("battery_voltage",   "Battery (V)"),
        ("altitude",          "Altitude (km)"),
        ("velocity",          "Velocity (km/s)"),
        ("signal_strength",   "RSSI (dBm)"),
        ("solar_panel_power", "Solar (W)"),
        ("memory_usage",      "RAM (%)"),
        ("error_flags",       "Errors"),
    ]

    header = f"{'ID':<4}" + "".join(f"{lbl:<16}" for _, lbl in fields)
    print("\n" + header)
    print("-" * len(header))
    for r in records:
        row = f"{r['packet_id']:<4}"
        for key, _ in fields:
            val = r[key]
            if key == "error_flags":
                row += f"{'0x{:04X}'.format(val):<16}"
            else:
                row += f"{val:<16}"
        print(row)

    print(f"\n✅ Packets generated  : {len(packets)}")
    print(f"✅ Bytes per packet   : {len(packets[0])}")
    print(f"✅ Total stream size  : {sum(len(p) for p in packets)} bytes")
    print("\n→ Packets ready for ChaCha20-Poly1305 encryption (Module 2)\n")
