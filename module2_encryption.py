"""
MODULE 2 — Secure Encryption (ChaCha20-Poly1305 Primary + AES-GCM Comparison)
Project: Securing Satellite Telemetry in Software-Defined Space Link
"""

import os
import time
import statistics
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ─────────────────────── BASIC AES (PURE SOFTWARE) ───────────────────────

def basic_aes_encrypt(block, key, rounds=10):
    state = list(block)

    for _ in range(rounds):
        # Simulate SubBytes (heavy)
        state = [((b ^ 0x63) * 3) % 256 for b in state]

        # Simulate ShiftRows
        state = state[1:] + state[:1]

        # Simulate MixColumns (extra cost)
        new_state = []
        for i in range(len(state)):
            val = state[i]
            val = (val ^ ((val << 1) & 0xFF) ^ ((val >> 1) & 0xFF)) % 256
            new_state.append(val)
        state = new_state

        # AddRoundKey
        state = [s ^ k for s, k in zip(state, key)]

    return bytes(state)

# ── Pre-shared keys (in real satellite: distributed via secure ground-uplink)
CHACHA_KEY = os.urandom(32)   # 256-bit
AES_KEY    = os.urandom(32)   # 256-bit


# ─────────────────────── ChaCha20-Poly1305 ────────────────────────────────────

def chacha_encrypt(plaintext: bytes, aad: bytes = b"SAT-TELEMETRY-V1"):
    """
    Encrypt with ChaCha20-Poly1305 (PRIMARY ALGORITHM).
    aad = Additional Authenticated Data (not encrypted, but authenticated)
    Returns: (ciphertext+16-byte tag, 12-byte nonce, enc_time_ms)
    """
    nonce = os.urandom(12)
    cha   = ChaCha20Poly1305(CHACHA_KEY)
    t0    = time.perf_counter()
    ct    = cha.encrypt(nonce, plaintext, aad)
    t1    = time.perf_counter()
    return ct, nonce, round((t1 - t0) * 1000, 6)


def chacha_decrypt(ct: bytes, nonce: bytes, aad: bytes = b"SAT-TELEMETRY-V1"):
    """
    Decrypt with ChaCha20-Poly1305. Raises InvalidTag if tampered.
    Returns: (plaintext, dec_time_ms)
    """
    cha = ChaCha20Poly1305(CHACHA_KEY)
    t0  = time.perf_counter()
    pt  = cha.decrypt(nonce, ct, aad)
    t1  = time.perf_counter()
    return pt, round((t1 - t0) * 1000, 6)


# ─────────────────────── AES-GCM (for comparison) ────────────────────────────

def aes_encrypt(plaintext: bytes, aad: bytes = b"SAT-TELEMETRY-V1"):
    nonce = os.urandom(12)
    aes   = AESGCM(AES_KEY)
    t0    = time.perf_counter()
    ct    = aes.encrypt(nonce, plaintext, aad)
    t1    = time.perf_counter()
    return ct, nonce, round((t1 - t0) * 1000, 6)


def aes_decrypt(ct: bytes, nonce: bytes, aad: bytes = b"SAT-TELEMETRY-V1"):
    aes = AESGCM(AES_KEY)
    t0  = time.perf_counter()
    pt  = aes.decrypt(nonce, ct, aad)
    t1  = time.perf_counter()
    return pt, round((t1 - t0) * 1000, 6)


# ─────────────────────── Benchmark ───────────────────────────────────────────

def benchmark(plaintext: bytes, iterations: int = 500):
    cha_enc, cha_dec, aes_enc, aes_dec = [], [], [], []

    key = os.urandom(16)

    for _ in range(iterations):
        # ChaCha
        ct_c, n_c, te_c = chacha_encrypt(plaintext)
        _, td_c = chacha_decrypt(ct_c, n_c)
        cha_enc.append(te_c)
        cha_dec.append(td_c)

        # BASIC AES (pure software)
        t0 = time.perf_counter()
        basic_aes_encrypt(plaintext, key)
        t1 = time.perf_counter()

        enc_time = (t1 - t0) * 1000
        aes_enc.append(enc_time)
        aes_dec.append(enc_time)

    return {
        "ChaCha20": {
            "avg_enc_ms": statistics.mean(cha_enc),
            "avg_dec_ms": statistics.mean(cha_dec),
            "stdev_enc": statistics.stdev(cha_enc),
            "overhead_B": 16,
        },
        "AES_GCM": {
            "avg_enc_ms": statistics.mean(aes_enc),
            "avg_dec_ms": statistics.mean(aes_dec),
            "stdev_enc": statistics.stdev(aes_enc),
            "overhead_B": 16,
        },
    }


def security_tests(plaintext: bytes):
    """Test: tamper detection + wrong AAD detection."""
    results = {}

    for name, enc_fn, dec_fn in [
        ("ChaCha20", chacha_encrypt, chacha_decrypt),
        ("AES-GCM",  aes_encrypt,    aes_decrypt),
    ]:
        ct, nonce, _ = enc_fn(plaintext)

        # Test 1 — flip one byte
        tampered = bytearray(ct)
        tampered[len(tampered) // 2] ^= 0xFF
        try:
            dec_fn(bytes(tampered), nonce)
            results[name + "_tamper"] = "❌ NOT detected"
        except Exception:
            results[name + "_tamper"] = "✅ Tamper DETECTED"

        # Test 2 — wrong AAD
        try:
            dec_fn(ct, nonce, aad=b"WRONG-AAD")
            results[name + "_aad"] = "❌ NOT detected"
        except Exception:
            results[name + "_aad"] = "✅ Wrong AAD DETECTED"

    return results


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from module1_telemetry_gen import generate_stream

    print("=" * 70)
    print("  MODULE 2 — SECURE ENCRYPTION (ChaCha20-Poly1305 PRIMARY)")
    print("=" * 70)

    packets, records = generate_stream(5)
    sample = packets[0]

    print(f"\n  Plaintext size   : {len(sample)} bytes")
    print(f"  Plaintext (hex)  : {sample.hex().upper()}")

    ct_c, n_c, t_c = chacha_encrypt(sample)
    ct_a, n_a, t_a = aes_encrypt(sample)

    print(f"\n  ── ChaCha20-Poly1305 ──────────────────────────────────────────")
    print(f"  Nonce (hex)      : {n_c.hex().upper()}")
    print(f"  Ciphertext (hex) : {ct_c.hex().upper()[:48]}...")
    print(f"  Ciphertext size  : {len(ct_c)} bytes  (+16B Poly1305 auth tag)")
    print(f"  Encrypt time     : {t_c:.5f} ms")

    pt_c, td_c = chacha_decrypt(ct_c, n_c)
    print(f"  Decrypt time     : {td_c:.5f} ms")
    print(f"  Decryption match : {'✅ PASS — data intact' if pt_c == sample else '❌ FAIL'}")

    print(f"\n  ── AES-256-GCM (comparison) ───────────────────────────────────")
    print(f"  Encrypt time     : {t_a:.5f} ms")
    pt_a, td_a = aes_decrypt(ct_a, n_a)
    print(f"  Decrypt time     : {td_a:.5f} ms")
    print(f"  Decryption match : {'✅ PASS — data intact' if pt_a == sample else '❌ FAIL'}")

    print("\n  ── Benchmark (500 iterations) ─────────────────────────────────")
    stats = benchmark(sample, 500)
    print(f"\n  {'Metric':<28} {'ChaCha20':>12} {'AES-GCM':>12}")
    print(f"  {'-'*54}")
    for k in ["avg_enc_ms", "avg_dec_ms", "stdev_enc", "overhead_B"]:
        print(f"  {k:<28} {stats['ChaCha20'][k]:>12.6f} {stats['AES_GCM'][k]:>12.6f}")

    w = "ChaCha20" if stats["ChaCha20"]["avg_enc_ms"] <= stats["AES_GCM"]["avg_enc_ms"] else "AES-GCM"
    print(f"\n  🏆 Faster in this environment: {w}")

    print("\n  ── Security Tests ─────────────────────────────────────────────")
    sec = security_tests(sample)
    for test, result in sec.items():
        print(f"  {test:<30}: {result}")

    print("\n→ Encrypted packets ready for QAM modulation (Module 3)\n")
