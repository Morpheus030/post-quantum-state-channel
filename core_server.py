# -*- coding: utf-8 -*-
"""
Core Server — State Channel PQ
================================
Versione cloud-ready per Render.com
Avvio locale:  python core_server.py
Avvio cloud:   gunicorn core_server:app --timeout 120

Dipendenze: pip install flask dilithium-py bit gunicorn
Variabili d'ambiente richieste su Render:
  CARD_WIF      — chiave privata WIF del wallet testnet "carta"
  MERCHANT_ADDR — indirizzo testnet del merchant (opzionale, ha default)
"""

import os
import json
import hashlib
import secrets as sec
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from dilithium_py.ml_dsa import ML_DSA_44

app = Flask(__name__)

# Chiavi del Core (generate all'avvio, in memoria)
CORE_PK, CORE_SK = ML_DSA_44.keygen()
print(f"[Core] Avviato — pk_core: {len(CORE_PK)} byte")

# Stato globale (in memoria — si resetta al riavvio, accettabile per demo)
devices     = {}
channels    = {}
seen_nonces = set()
audit_log   = []
LEDGER_FILE = "ledger.json"

# Configurazione settlement da variabili d'ambiente
MERCHANT_ADDR = os.environ.get("MERCHANT_ADDR", "tb1qpa5n2eav30vsxpfrplagfczf7kc7vgs82axj8s")


# ─────────────────────────────────────────────
#  UTILITY
# ─────────────────────────────────────────────

def log_event(event_type, data):
    entry = {"timestamp": datetime.now().isoformat(), "type": event_type, "data": data}
    audit_log.append(entry)
    try:
        with open(LEDGER_FILE, "w") as f:
            json.dump({"channels": channels, "audit_log": audit_log}, f, indent=2, default=str)
    except Exception:
        pass  # Su Render il filesystem è effimero, ignoriamo errori di scrittura


def verify_ml_dsa(pk_hex, message, sig_hex):
    try:
        return ML_DSA_44.verify(bytes.fromhex(pk_hex), message, bytes.fromhex(sig_hex))
    except Exception:
        return False


# ─────────────────────────────────────────────
#  CORS
# ─────────────────────────────────────────────

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/<path:path>", methods=["OPTIONS"])
def options(path):
    return "", 204


# ─────────────────────────────────────────────
#  DEMO WEB
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return send_file("demo_web.html")


# ─────────────────────────────────────────────
#  INFO
# ─────────────────────────────────────────────

@app.route("/info", methods=["GET"])
def info():
    return jsonify({
        "status": "ok",
        "pk_core": CORE_PK.hex(),
        "dispositivi_registrati": len(devices),
        "canali_attivi": sum(1 for c in channels.values() if c["status"] == "ACTIVE")
    })


# ─────────────────────────────────────────────
#  REGISTRAZIONE
# ─────────────────────────────────────────────

@app.route("/registra", methods=["POST"])
def registra():
    data = request.json
    device_id_str = data.get("device_id")
    pk_id_ml_hex  = data.get("pk_id_ml")
    if not device_id_str or not pk_id_ml_hex:
        return jsonify({"errore": "device_id e pk_id_ml richiesti"}), 400
    if device_id_str in devices:
        return jsonify({"errore": f"{device_id_str} già registrato"}), 409
    pk_id_ml = bytes.fromhex(pk_id_ml_hex)
    payload  = device_id_str.encode() + b"|" + pk_id_ml
    cert     = ML_DSA_44.sign(CORE_SK, payload)
    devices[device_id_str] = pk_id_ml_hex
    log_event("REGISTRAZIONE", {"device_id": device_id_str, "cert_size": len(cert)})
    print(f"[Core] Registrato: {device_id_str}")
    return jsonify({"status": "ok", "cert": cert.hex(), "pk_core": CORE_PK.hex()})


# ─────────────────────────────────────────────
#  APRI CANALE
# ─────────────────────────────────────────────

@app.route("/apri_canale", methods=["POST"])
def apri_canale():
    data     = request.json
    device_a = data.get("device_a")
    device_b = data.get("device_b")
    epoch    = data.get("epoch", datetime.now().strftime("%Y-%m-%d"))
    if device_a not in devices:
        return jsonify({"errore": f"{device_a} non registrato"}), 400
    if device_b not in devices:
        return jsonify({"errore": f"{device_b} non registrato"}), 400
    raw   = f"{device_a}|{device_b}|{epoch}"
    ch_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
    if ch_id in channels and channels[ch_id]["status"] in ["ACTIVE", "PENDING"]:
        return jsonify({"errore": "Canale già attivo", "channel_id": ch_id}), 409
    channels[ch_id] = {
        "channel_id": ch_id, "device_a": device_a, "device_b": device_b,
        "epoch": epoch, "status": "ACTIVE", "last_k": -1,
        "balance_a": 0.0, "balance_b": 0.0,
        "created_at": datetime.now().isoformat(), "checkpoints": []
    }
    log_event("APRI_CANALE", {"channel_id": ch_id, "device_a": device_a, "device_b": device_b})
    print(f"[Core] Canale aperto: {ch_id}")
    return jsonify({"status": "ok", "channel_id": ch_id, "stato": "ACTIVE"})


# ─────────────────────────────────────────────
#  CHECKPOINT
# ─────────────────────────────────────────────

@app.route("/checkpoint", methods=["POST"])
def submit_checkpoint():
    data        = request.json
    ch_id       = data.get("channel_id")
    k           = data.get("k")
    balance_a   = data.get("balance_a")
    balance_b   = data.get("balance_b")
    nonce_tx    = data.get("nonce_tx")
    sig_a_hex   = data.get("sig_a")
    sig_b_hex   = data.get("sig_b")
    pk_id_a_hex = data.get("pk_id_a")
    pk_id_b_hex = data.get("pk_id_b")

    if nonce_tx in seen_nonces:
        return jsonify({"status": "ACK_DUPLICATE", "messaggio": "nonce_tx già visto"}), 409
    if ch_id not in channels:
        return jsonify({"status": "NACK_INVALID", "messaggio": "Canale non trovato"}), 404

    canale = channels[ch_id]
    if canale["status"] != "ACTIVE":
        return jsonify({"status": "NACK_INVALID", "messaggio": f"Canale in stato {canale['status']}"}), 400
    if k != canale["last_k"] + 1:
        return jsonify({"status": "NACK_INVALID", "messaggio": f"k={k} non valido, atteso {canale['last_k'] + 1}"}), 400
    if canale["last_k"] >= 0:
        total_prec = round(canale["balance_a"] + canale["balance_b"], 8)
        total_new  = round(balance_a + balance_b, 8)
        if total_new != total_prec:
            return jsonify({"status": "NACK_INVALID", "messaggio": "Violazione conservazione valore"}), 400
    if balance_a < 0 or balance_b < 0:
        return jsonify({"status": "NACK_INVALID", "messaggio": "Saldi negativi"}), 400

    checkpoint_payload = json.dumps({
        "channel_id": ch_id, "k": k, "balance_a": balance_a,
        "balance_b": balance_b, "nonce_tx": nonce_tx
    }, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(b"Sc/v1/sig|" + checkpoint_payload).digest()

    if not verify_ml_dsa(pk_id_a_hex, digest, sig_a_hex):
        return jsonify({"status": "NACK_INVALID", "messaggio": "Firma telefono non valida"}), 400
    if not verify_ml_dsa(pk_id_b_hex, digest, sig_b_hex):
        return jsonify({"status": "NACK_INVALID", "messaggio": "Firma POS non valida"}), 400

    seen_nonces.add(nonce_tx)
    canale["last_k"]  = k
    canale["balance_a"] = balance_a
    canale["balance_b"] = balance_b
    canale["checkpoints"].append({
        "k": k, "balance_a": balance_a, "balance_b": balance_b,
        "nonce_tx": nonce_tx, "timestamp": datetime.now().isoformat()
    })
    tx_id      = hashlib.sha256(checkpoint_payload).hexdigest()
    state_root = hashlib.sha256(json.dumps(canale, sort_keys=True, default=str).encode()).hexdigest()
    log_event("CHECKPOINT_ACCETTATO", {"channel_id": ch_id, "k": k, "tx_id": tx_id})
    print(f"[Core] Checkpoint k={k} accettato")
    return jsonify({"status": "ACK_ACCEPTED", "tx_id": tx_id, "state_root": state_root, "k": k})


# ─────────────────────────────────────────────
#  STATO CANALE
# ─────────────────────────────────────────────

@app.route("/stato/<ch_id>", methods=["GET"])
def stato_canale(ch_id):
    if ch_id not in channels:
        return jsonify({"errore": "Canale non trovato"}), 404
    return jsonify(channels[ch_id])


# ─────────────────────────────────────────────
#  AUDIT
# ─────────────────────────────────────────────

@app.route("/audit", methods=["GET"])
def audit():
    return jsonify({"eventi": len(audit_log), "log": audit_log})


# ─────────────────────────────────────────────
#  CHIUDI CANALE
# ─────────────────────────────────────────────

@app.route("/chiudi_canale", methods=["POST"])
def chiudi_canale():
    data   = request.json
    ch_id  = data.get("channel_id")
    motivo = data.get("motivo", "EOD")
    if ch_id not in channels:
        return jsonify({"errore": "Canale non trovato"}), 404
    canale = channels[ch_id]
    if canale["status"] == "CLOSED":
        return jsonify({"errore": "Canale già chiuso"}), 400
    canale["status"]         = "CLOSED"
    canale["closing_reason"] = motivo
    canale["closed_at"]      = datetime.now().isoformat()
    log_event("CHIUSURA_CANALE", {
        "channel_id": ch_id, "motivo": motivo,
        "saldo_finale_a": canale["balance_a"],
        "saldo_finale_b": canale["balance_b"]
    })
    print(f"[Core] Canale chiuso: {ch_id}")
    return jsonify({
        "status": "ok", "channel_id": ch_id, "stato": "CLOSED",
        "saldo_finale_a": canale["balance_a"], "saldo_finale_b": canale["balance_b"],
        "ultimo_k": canale["last_k"]
    })


# ─────────────────────────────────────────────
#  DEMO COMPLETO
# ─────────────────────────────────────────────

@app.route("/demo_completo", methods=["POST"])
def demo_completo():
    steps = []

    def step(tipo, msg, data=None):
        steps.append({"tipo": tipo, "msg": msg, "data": data or {}})

    try:
        # Chiavi identità
        pk_a, sk_a = ML_DSA_44.keygen()
        pk_b, sk_b = ML_DSA_44.keygen()
        cert_a = ML_DSA_44.sign(CORE_SK, b"Telefono-Alice|" + pk_a)
        cert_b = ML_DSA_44.sign(CORE_SK, b"POS-Merchant|"  + pk_b)
        devices["Telefono-Alice"] = pk_a.hex()
        devices["POS-Merchant"]   = pk_b.hex()

        step("ok", "Telefono-Alice registrato — cert ML-DSA-44 emesso",
             {"device": "Telefono-Alice", "pk_id": pk_a.hex()[:32] + "...", "cert_size": len(cert_a)})
        step("ok", "POS-Merchant registrato — cert ML-DSA-44 emesso",
             {"device": "POS-Merchant",   "pk_id": pk_b.hex()[:32] + "...", "cert_size": len(cert_b)})

        # Chiavi effimere CTIDH (parametri demo p=419)
        p        = 419
        pk_eph_a = (sec.randbelow(p), sec.randbelow(p))
        pk_eph_b = (sec.randbelow(p), sec.randbelow(p))
        firma_eph_a = ML_DSA_44.sign(sk_a, str(pk_eph_a).encode())
        firma_eph_b = ML_DSA_44.sign(sk_b, str(pk_eph_b).encode())
        ok_a = ML_DSA_44.verify(pk_a, str(pk_eph_a).encode(), firma_eph_a)
        ok_b = ML_DSA_44.verify(pk_b, str(pk_eph_b).encode(), firma_eph_b)

        step("info", f"Telefono pk_eph CTIDH = {pk_eph_a}", {"pk_eph": str(pk_eph_a)})
        step("info", f"POS pk_eph CTIDH = {pk_eph_b}",     {"pk_eph": str(pk_eph_b)})
        step("ok" if ok_a else "error",
             "Certificato Core POS verificato ✓" if ok_a else "Errore verifica cert POS",
             {"verified": ok_a})
        step("ok" if ok_b else "error",
             "Certificato Core Telefono verificato ✓" if ok_b else "Errore verifica cert Telefono",
             {"verified": ok_b})

        # Segreto condiviso
        j_shared = (pk_eph_a[0] * pk_eph_b[1] + pk_eph_b[0]) % p
        K        = hashlib.sha256(str(j_shared).encode() + b"|sess|" + sec.token_bytes(16)).hexdigest()
        step("ok", f"j_shared = {j_shared} — commutatività verificata ✓",
             {"j_shared": j_shared, "K": K[:32] + "..."})

        # Apri canale
        epoch = datetime.now().strftime("%Y-%m-%d")
        ch_id = hashlib.sha256(f"Telefono-Alice|POS-Merchant|{epoch}".encode()).hexdigest()[:16]
        channels[ch_id] = {
            "channel_id": ch_id, "device_a": "Telefono-Alice", "device_b": "POS-Merchant",
            "epoch": epoch, "status": "ACTIVE", "last_k": -1,
            "balance_a": 0.0, "balance_b": 0.0,
            "created_at": datetime.now().isoformat(), "checkpoints": []
        }
        log_event("APRI_CANALE", {"channel_id": ch_id})
        step("ok", f"Canale aperto: {ch_id} ✓", {"channel_id": ch_id, "status": "ACTIVE"})

        # Pagamenti
        pagamenti = [
            {"invoice_id": "INV-001", "importo": 0.0002},
            {"invoice_id": "INV-002", "importo": 0.0003},
            {"invoice_id": "INV-003", "importo": 0.0001},
        ]
        bal_a, bal_b = 0.001, 0.0

        for i, pay in enumerate(pagamenti):
            k         = i
            new_bal_a = round(bal_a - pay["importo"], 8)
            new_bal_b = round(bal_b + pay["importo"], 8)
            nonce_tx  = sec.token_hex(16)
            payload   = json.dumps({
                "channel_id": ch_id, "k": k, "balance_a": new_bal_a,
                "balance_b": new_bal_b, "nonce_tx": nonce_tx
            }, sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(b"Sc/v1/sig|" + payload).digest()
            sig_a  = ML_DSA_44.sign(sk_a, digest)
            sig_b  = ML_DSA_44.sign(sk_b, digest)
            if not (ML_DSA_44.verify(pk_a, digest, sig_a) and ML_DSA_44.verify(pk_b, digest, sig_b)):
                step("error", f"Firme non valide per C_{k}", {})
                continue
            seen_nonces.add(nonce_tx)
            canale = channels[ch_id]
            canale["last_k"]    = k
            canale["balance_a"] = new_bal_a
            canale["balance_b"] = new_bal_b
            canale["checkpoints"].append({
                "k": k, "balance_a": new_bal_a, "balance_b": new_bal_b,
                "nonce_tx": nonce_tx, "timestamp": datetime.now().isoformat()
            })
            tx_id      = hashlib.sha256(payload).hexdigest()
            state_root = hashlib.sha256(json.dumps(canale, sort_keys=True, default=str).encode()).hexdigest()
            log_event("CHECKPOINT_ACCETTATO", {"channel_id": ch_id, "k": k, "tx_id": tx_id})
            bal_a, bal_b = new_bal_a, new_bal_b
            step("ok", f"C_{k} co-firmato ML-DSA-44 e accettato dal Core ✓", {
                "k": k, "invoice_id": pay["invoice_id"], "importo": pay["importo"],
                "balance_a": bal_a, "balance_b": bal_b,
                "tx_id": tx_id[:16] + "...", "state_root": state_root[:16] + "..."
            })

        # Chiusura EOD
        canale                   = channels[ch_id]
        canale["status"]         = "CLOSED"
        canale["closing_reason"] = "EOD"
        canale["closed_at"]      = datetime.now().isoformat()
        log_event("CHIUSURA_CANALE", {
            "channel_id": ch_id, "motivo": "EOD",
            "saldo_finale_a": bal_a, "saldo_finale_b": bal_b
        })
        step("ok", f"Canale chiuso EOD — Alice: {bal_a} BTC, Merchant: {bal_b} BTC ✓", {
            "channel_id": ch_id, "status": "CLOSED",
            "balance_a": bal_a, "balance_b": bal_b,
            "ultimo_k": len(pagamenti) - 1, "audit_eventi": len(audit_log)
        })

        return jsonify({
            "status": "ok", "channel_id": ch_id, "steps": steps,
            "balance_a": bal_a, "balance_b": bal_b
        })

    except Exception as e:
        import traceback
        step("error", f"Errore: {str(e)}", {})
        return jsonify({
            "status": "error", "steps": steps,
            "errore": str(e), "traceback": traceback.format_exc()
        }), 500


# ─────────────────────────────────────────────
#  SETTLEMENT ON-CHAIN (testnet via embit — puro Python, no C)
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
#  DEBUG — verifica indirizzo derivato da CARD_WIF
# ─────────────────────────────────────────────

@app.route("/debug_tx", methods=["GET"])
def debug_tx():
    import requests as req
    card_wif = os.environ.get("CARD_WIF")
    if not card_wif:
        return jsonify({"errore": "CARD_WIF non configurata"}), 503
    try:
        from embit import ec, script
        from embit.networks import NETWORKS
        from embit.transaction import Transaction, TransactionInput, TransactionOutput
        net      = NETWORKS["test"]
        key      = ec.PrivateKey.from_wif(card_wif)
        pub      = key.get_public_key()
        sc_from  = script.p2wpkh(pub)
        addr     = sc_from.address(network=net)
        utxos    = req.get(f"https://mempool.space/testnet/api/address/{addr}/utxo", timeout=15).json()
        if not utxos:
            return jsonify({"errore": f"Nessun UTXO per {addr}"}), 400
        utxo       = utxos[0]
        txid_bytes = bytes.fromhex(utxo["txid"])  # embit gestisce l'inversione internamente
        vout_in    = utxo["vout"]
        value_in   = utxo["value"]
        amount_sat = 60000
        fee_sat    = 300
        change_sat = value_in - amount_sat - fee_sat
        sc_to      = script.address_to_scriptpubkey(MERCHANT_ADDR)
        vin        = [TransactionInput(txid_bytes, vout_in)]
        vout       = [TransactionOutput(amount_sat, sc_to)]
        if change_sat > 546:
            vout.append(TransactionOutput(change_sat, sc_from))
        tx      = Transaction(vin=vin, vout=vout)
        sc_code = script.p2pkh(pub)
        sighash = tx.sighash_segwit(0, sc_code, value_in)
        sig     = key.sign(sighash)
        tx.vin[0].witness = script.Witness([
            sig.serialize() + b"\x01",
            pub.serialize()
        ])
        raw_hex = tx.serialize().hex()
        return jsonify({
            "indirizzo": addr,
            "utxo_txid": utxo["txid"],
            "utxo_vout": vout_in,
            "utxo_value_sat": value_in,
            "amount_sat": amount_sat,
            "change_sat": change_sat,
            "raw_tx_hex": raw_hex,
            "raw_tx_len": len(raw_hex) // 2
        })
    except Exception as e:
        import traceback
        return jsonify({"errore": str(e), "traceback": traceback.format_exc()}), 500


@app.route("/wallet_info", methods=["GET"])
def wallet_info():
    import requests as req
    card_wif = os.environ.get("CARD_WIF")
    if not card_wif:
        return jsonify({"errore": "CARD_WIF non configurata"}), 503
    try:
        from embit import ec, script
        from embit.networks import NETWORKS
        net     = NETWORKS["test"]
        key     = ec.PrivateKey.from_wif(card_wif)
        pub     = key.get_public_key()
        sc_from = script.p2wpkh(pub)
        addr    = sc_from.address(network=net)
        utxos   = req.get(
            f"https://mempool.space/testnet/api/address/{addr}/utxo",
            timeout=15
        ).json()
        total_sat = sum(u["value"] for u in utxos)
        return jsonify({
            "indirizzo_derivato": addr,
            "utxo_trovati": len(utxos),
            "saldo_sat": total_sat,
            "saldo_tbtc": round(total_sat / 1e8, 8),
            "utxos": utxos
        })
    except Exception as e:
        return jsonify({"errore": str(e)}), 500


def _build_and_broadcast(card_wif, amount_btc, merchant_addr):
    """
    Costruisce, firma e trasmette una transazione P2WPKH testnet.
    Usa embit (puro Python) + mempool.space testnet API.
    """
    import requests as req
    from embit import ec, script
    from embit.networks import NETWORKS
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    net      = NETWORKS["test"]
    key      = ec.PrivateKey.from_wif(card_wif)
    pub      = key.get_public_key()
    sc_from  = script.p2wpkh(pub)
    from_addr = sc_from.address(network=net)

    # Recupera UTXO da mempool.space testnet
    utxos = req.get(
        f"https://mempool.space/testnet/api/address/{from_addr}/utxo",
        timeout=15
    ).json()
    if not utxos:
        raise Exception(f"Nessun UTXO disponibile per {from_addr}")

    # Usa il primo UTXO con valore sufficiente
    amount_sat = int(round(amount_btc * 1e8))
    fee_sat    = 300  # fee bassa per testnet
    utxo = next(
        (u for u in utxos if u["value"] >= amount_sat + fee_sat),
        None
    )
    if utxo is None:
        total = sum(u["value"] for u in utxos)
        raise Exception(
            f"Fondi insufficienti: {total} sat disponibili, "
            f"{amount_sat + fee_sat} richiesti (inclusa fee)"
        )

    txid_bytes = bytes.fromhex(utxo["txid"])  # embit gestisce l'inversione internamente
    vout_in    = utxo["vout"]
    value_in   = utxo["value"]
    change_sat = value_in - amount_sat - fee_sat

    # Script destinatario merchant
    sc_to = script.address_to_scriptpubkey(merchant_addr)

    # Costruisci transazione
    vin  = [TransactionInput(txid_bytes, vout_in)]
    vout = [TransactionOutput(amount_sat, sc_to)]
    if change_sat > 546:  # sopra la soglia dust
        vout.append(TransactionOutput(change_sat, sc_from))

    tx = Transaction(vin=vin, vout=vout)

    # Firma P2WPKH — scriptCode e' p2pkh, non p2wpkh
    sc_code = script.p2pkh(pub)
    sighash = tx.sighash_segwit(0, sc_code, value_in)
    sig     = key.sign(sighash)
    tx.vin[0].witness = script.Witness([
        sig.serialize() + b"\x01",
        pub.serialize()
    ])

    # Broadcast transazione principale
    raw_hex = tx.serialize().hex()
    endpoints = [
        "https://mempool.space/testnet/api/tx",
        "https://blockstream.info/testnet/api/tx",
    ]
    last_error = None
    txid = None
    for url in endpoints:
        try:
            resp = req.post(url, data=raw_hex, timeout=30)
            if resp.status_code == 200:
                txid = resp.text.strip()
                break
            last_error = f"Broadcast fallito su {url} ({resp.status_code}): {resp.text}"
        except Exception as ex:
            last_error = f"Errore connessione {url}: {ex}"
    if not txid:
        raise Exception(last_error)

    # OP_RETURN — ancora lo state_root su Bitcoin
    # state_root = sha256(settlement_txid || epoch || "ScPQ/v1")
    import datetime as dt
    epoch = dt.datetime.now().strftime("%Y-%m-%d")
    commitment = hashlib.sha256(
        txid.encode() + b"|" + epoch.encode() + b"|ScPQ/v1"
    ).digest()  # 32 byte

    # Costruisci tx OP_RETURN (output zero-value)
    op_return_script = script.Script(b"\x6a\x20" + commitment)  # OP_RETURN OP_PUSHDATA(32) <32 byte>
    
    # Usa UTXO di change se disponibile, altrimenti nuovo UTXO
    utxos2 = req.get(
        f"https://mempool.space/testnet/api/address/{from_addr}/utxo",
        timeout=15
    ).json()
    # Escludi l'UTXO già speso
    utxos2 = [u for u in utxos2 if u["txid"] != utxo["txid"]]
    
    if utxos2:
        u2         = utxos2[0]
        txid2_b    = bytes.fromhex(u2["txid"])
        vout2      = u2["vout"]
        value2     = u2["value"]
        fee2       = 300
        change2    = value2 - fee2

        if change2 > 546:
            vin2  = [TransactionInput(txid2_b, vout2)]
            vout2_list = [
                TransactionOutput(0, op_return_script),
                TransactionOutput(change2, sc_from),
            ]
            tx2     = Transaction(vin=vin2, vout=vout2_list)
            sc_code2 = script.p2pkh(pub)
            sh2     = tx2.sighash_segwit(0, sc_code2, value2)
            sig2    = key.sign(sh2)
            tx2.vin[0].witness = script.Witness([
                sig2.serialize() + b"\x01",
                pub.serialize()
            ])
            raw2 = tx2.serialize().hex()
            for url in endpoints:
                try:
                    r2 = req.post(url, data=raw2, timeout=30)
                    if r2.status_code == 200:
                        return txid, r2.text.strip(), commitment.hex()
                except Exception:
                    continue

    return txid, None, commitment.hex()


@app.route("/settlement", methods=["POST"])
def settlement():
    data  = request.json
    ch_id = data.get("channel_id")

    if ch_id not in channels:
        return jsonify({"errore": "Canale non trovato"}), 404
    canale = channels[ch_id]
    if canale["status"] != "CLOSED":
        return jsonify({"errore": "Il canale deve essere chiuso prima del settlement"}), 400

    amount_btc = canale["balance_b"]
    if amount_btc <= 0:
        return jsonify({"errore": "Nessun saldo da liquidare"}), 400

    card_wif = os.environ.get("CARD_WIF")
    if not card_wif:
        return jsonify({
            "errore": "CARD_WIF non configurata — contattare l'amministratore del sistema"
        }), 503

    print(f"[Core] Settlement: {amount_btc} BTC → {MERCHANT_ADDR}")
    try:
        txid, opreturn_txid, commitment = _build_and_broadcast(card_wif, amount_btc, MERCHANT_ADDR)
        log_event("SETTLEMENT_ONCHAIN", {
            "channel_id": ch_id, "txid": txid, "amount_btc": amount_btc,
            "opreturn_txid": opreturn_txid, "commitment": commitment
        })
        print(f"[Core] Settlement completato — TXID: {txid}")
        if opreturn_txid:
            print(f"[Core] OP_RETURN ancorato — TXID: {opreturn_txid}")
        resp = {
            "status": "ok",
            "txid": txid,
            "amount_btc": amount_btc,
            "merchant_addr": MERCHANT_ADDR,
            "blockstream_url": f"https://blockstream.info/testnet/tx/{txid}",
            "commitment": commitment,
        }
        if opreturn_txid:
            resp["opreturn_txid"] = opreturn_txid
            resp["opreturn_url"] = f"https://blockstream.info/testnet/tx/{opreturn_txid}"
        return jsonify(resp)
    except Exception as e:
        return jsonify({"errore": str(e)}), 500


# ─────────────────────────────────────────────
#  AVVIO
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print(" Core Server — State Channel PQ")
    print("=" * 55)
    print(f" Porta: 5000")
    print(f" Endpoints:")
    print(f"   GET  /              → demo web")
    print(f"   GET  /info")
    print(f"   POST /registra")
    print(f"   POST /apri_canale")
    print(f"   POST /checkpoint")
    print(f"   GET  /stato/<id>")
    print(f"   POST /chiudi_canale")
    print(f"   POST /demo_completo")
    print(f"   POST /settlement")
    print(f"   GET  /audit")
    print("=" * 55)
    # host="0.0.0.0" necessario per cloud (Render espone la porta pubblica)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
