# Post-Quantum State Channel

**A post-quantum payment system built on Bitcoin.**

Verifiable custodial state channels with ML-DSA-44 signatures and BitVM2 bridge integration.

Trust is not assumed. It is proven mathematically.

---

## What is this

A payment system designed for daily BTC transactions, built on three principles:

- **Post-quantum security** — ML-DSA-44 (FIPS 204) signatures and CTIDH key exchange
- **Verifiable custody** — anyone can verify the system operated correctly, no one can see who paid what to whom
- **Bitcoin-native** — state root anchored on Bitcoin via OP_RETURN, bridge layer based on BitVM2

This is not a whitepaper. There is a working proof of concept with real Bitcoin testnet transactions.

---

## Live demo

[https://state-channel-pq.onrender.com](https://state-channel-pq.onrender.com)

Two publicly verifiable transactions on Bitcoin testnet (Blockstream):

- Settlement: `60ead78ae2f22530b0d5e50329117eb9ba124d409ef4956e6ed2113ad4f4f35a`
- OP_RETURN commitment: `9402ec872febb13ddc67a00f5b058483ae9e8636063403b3535292c8dfa8f73f`

---

## Contents

- `State_Channel_PQ_v3_EN.docx` — full technical document (architecture, cryptography, bridge layer, open questions)
- `core_server.py` — Flask backend, ML-DSA-44 signatures, Bitcoin testnet settlement
- `demo_web.html` — demo interface

---

## What is missing

- Real ZK proofs (LaBRADOR/Brakedown) — in the document, not yet in code
- Full SMT implementation
- BitVM2 bridge integration

This is declared openly. The document includes a full section on open vulnerabilities and unresolved questions.

---

## Looking for

A technical co-founder — Rust, cryptography, Bitcoin protocol.

Serious criticism is equally welcome. If something is architecturally wrong, I want to know.

Thank you for your time
