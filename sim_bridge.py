"""
sim_bridge.py
=============
This is the bridge between your existing modules and the simulation server.
Import this at the top of any module and call sim.* functions to push data live.

USAGE — add this one line to the TOP of each module:
  from sim_bridge import sim

  sim.reset()   # 🔥 CLEAR OLD DATA
  
  pause("Press ENTER to start MODULE 4...")

Then call:
  sim.log("your message", level="ok")
  sim.set_phase("telemetry")
  sim.push({...})     # send any state update
"""

import requests, json, time, threading, os

SERVER = "http://localhost:5000"

class SimBridge:
    def __init__(self, base_url=SERVER):
        self.url = base_url
        self._connected = False
        self._check_connection()

    def _check_connection(self):
        try:
            requests.get(self.url + "/api/state", timeout=0.5)
            self._connected = True
        except Exception:
            self._connected = False

    def _post(self, endpoint, data):
        if not self._connected:
            self._check_connection()
        if not self._connected:
            return  # server not running — silent fail, modules still work
        try:
            requests.post(self.url + endpoint, json=data, timeout=1)
        except Exception:
            pass  # never crash your module because of the sim server

    def push(self, state_update: dict):
        """Send any state dict — merged into the simulation state."""
        self._post("/api/update", state_update)

    def log(self, msg: str, level: str = "info"):
        """
        level: info | ok | warn | err | data | hi
        """
        self._post("/api/log", {"msg": msg, "level": level})
        # Also print to terminal so VS Code still shows everything
        symbols = {"ok":"[OK]","err":"[!!]","warn":"[--]","data":"[..] ","hi":"====","info":"    "}
        print(f"{symbols.get(level,'    ')} {msg}")

    def set_phase(self, phase: str):
        """phase: idle|boot|telemetry|encrypt|qam|transmit|attack|decrypt|done"""
        self.push({"phase": phase})

    def satellite_online(self, altitude=539, velocity=7.6, freq=2276.87):
        self.push({
            "satellite": {
                "status": "ONLINE",
                "altitude": altitude,
                "velocity": velocity,
                "freq": freq,
            }
        })

    def ground_station_online(self, rssi="-91.9 dBm"):
        self.push({
            "ground_station": {
                "status": "ONLINE",
                "rssi": rssi,
            }
        })

    def send_telemetry(self, fields: list, plain_hex: str, all_packets: list = None):
        """
        fields: list of {"field":..., "value":..., "unit":...}
        all_packets: list of 16-packet summaries
        """
        upd = {
            "telemetry": fields,
            "encryption": {"plaintext_hex": plain_hex, "plaintext_size": len(plain_hex)//2},
        }
        if all_packets:
            upd["all_packets"] = all_packets
        self.push(upd)

    def send_encryption(self, plaintext_hex, ciphertext_hex, nonce_hex,
                        aad, enc_time_ms, dec_time_ms=0):
        self.push({
            "encryption": {
                "plaintext_hex": plaintext_hex,
                "ciphertext_hex": ciphertext_hex,
                "nonce_hex": nonce_hex,
                "aad": aad,
                "enc_time_ms": round(enc_time_ms, 6),
                "dec_time_ms": round(dec_time_ms, 6),
                "plaintext_size": len(plaintext_hex)//2,
                "ciphertext_size": len(ciphertext_hex)//2,
            },
            "metrics": {"enc_avg_ms": round(enc_time_ms, 6)},
        })

    def send_qam(self, symbols: int, ber_table: list, sample_symbols: list = None):
        """
        ber_table: list of {snr, ber_chacha, ber_aes, quality}
        sample_symbols: list of {bits, iq, quadrant}
        """
        qam_data = {"symbols": symbols, "ber_table": ber_table}
        if sample_symbols:
            qam_data["sample_symbols"] = sample_symbols
        self.push({
            "qam": qam_data,
            "channel": {
                "active": True,
                "snr_db": ber_table[-1]["snr"] if ber_table else 30,
                "ber": ber_table[-1]["ber_chacha"] if ber_table else 0,
            },
            "ground_station": {
                "snr": str(ber_table[-1]["snr"]) if ber_table else "30",
            }
        })

    def send_channel_flow(self, packet_labels: list):
        """Show animated packets in the channel panel."""
        self.push({
            "channel": {
                "active": True,
                "packets_in_flight": packet_labels,
            }
        })

    def send_attack(self, name: str, description: str,
                    original_hex: str, modified_hex: str,
                    blocked: bool, reason: str):
        """Add one attack result to the attacks list."""
        self._post("/api/update", {
            "attacks": [{
                "name": name,
                "description": description,
                "original_hex": original_hex,
                "modified_hex": modified_hex,
                "blocked": blocked,
                "reason": reason,
            }]
        })
        # NOTE: This APPENDS — the server does a list append, not replace
        # Actually let's post a special endpoint that appends

    def append_attack(self, attack_dict: dict):
        """Append one attack to the existing attacks list."""
        try:
            # Get current state
            r = requests.get(self.url + "/api/state", timeout=1)
            current = r.json()
            attacks = current.get("attacks", [])
            attacks.append(attack_dict)
            self.push({"attacks": attacks})
        except Exception:
            pass

    def send_decryption(self, success: bool, recovered_hex: str,
                        recovered_fields: list, match_rate: float = 1.0):
        """
        recovered_fields: list of {"field":..., "value":...}
        """
        self.push({
            "decryption": {
                "success": success,
                "recovered_hex": recovered_hex,
                "recovered_fields": recovered_fields,
                "match_rate": match_rate,
            },
            "metrics": {
                "auth_passed": 1 if success else 0,
            },
            "ground_station": {
                "pkts_received": 1 if success else 0,
                "pkts_total": 1,
            }
        })

    def send_benchmark(self, chacha_stats: dict, aes_stats: dict):
        """
        chacha_stats / aes_stats: {avg_enc_ms, avg_dec_ms, stdev_enc, overhead_b}
        """
        self.push({
            "benchmark": {
                "chacha": chacha_stats,
                "aes": aes_stats,
            }
        })

    def update_blocked_count(self, count: int):
        self.push({"metrics": {"attacks_blocked": count}})

    def update_sent_count(self, count: int):
        self.push({"metrics": {"sent": count}})

    def reset(self):
        try:
            requests.post(self.url + "/api/reset", timeout=1)
        except Exception:
            pass


# Single global instance — import anywhere
sim = SimBridge()
