"""
transaction_stream.py
Continuous Live Transaction Stream — Financial Risk Engine

Runs as a persistent loop, constantly generating synthetic transactions into Neo4j.
Designed to simulate a live payment network with organic traffic PLUS
periodically injected anomalies (AML rings, glitch duplicates).

Deployment:
  - Runs inside GitHub Actions (up to 5h 50m per job, then the next cron restarts it)
  - Can also run locally: `python transaction_stream.py`

Stream composition (per cycle):
  ─ 70% → Normal everyday payments (groceries, fuel, e-commerce, transfers)
  ─ 15% → AML smurfing ring transactions
  ─ 15% → FNB/Takealot-style glitch duplicate charges
"""
from dotenv import load_dotenv
load_dotenv()
import os
import sys
import time
import random
import signal
import logging
from datetime import datetime
from faker import Faker

from db_connection  import Neo4jConnection
from data_generator import (
    ensure_schema,
    _create_customer,
    _create_account,
    _create_merchant,
    _ts,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("risk_engine.stream")

fake = Faker()

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Seconds between transaction bursts
STREAM_INTERVAL_SECONDS = int(os.environ.get("STREAM_INTERVAL_SECONDS", "15"))

# How many normal transactions to emit per cycle
NORMAL_TXN_PER_CYCLE = int(os.environ.get("NORMAL_TXN_PER_CYCLE", "5"))

# Max runtime in seconds (5h 50m keeps us inside GitHub Actions 6h limit)
MAX_RUNTIME_SECONDS = int(os.environ.get("MAX_RUNTIME_SECONDS", str(5 * 3600 + 50 * 60)))

# Probability (0–1) that a cycle injects an AML anomaly
AML_INJECT_PROBABILITY = float(os.environ.get("AML_INJECT_PROBABILITY", "0.15"))

# Probability (0–1) that a cycle injects a glitch duplicate
GLITCH_INJECT_PROBABILITY = float(os.environ.get("GLITCH_INJECT_PROBABILITY", "0.15"))

# Realistic ZA merchants for normal transactions
ZA_MERCHANTS = [
    "Checkers", "Pick n Pay", "Woolworths Food", "Spar",
    "Takealot", "Makro", "Game", "Incredible Connection",
    "Engen", "Shell", "BP", "TotalEnergies",
    "Netflix", "Showmax", "DStv",
    "Uber Eats", "Mr D Food",
    "Discovery Health", "Momentum",
]

# ─────────────────────────────────────────────────────────────────────────────
# Graceful shutdown
# ─────────────────────────────────────────────────────────────────────────────

_running = True

def _handle_sigterm(sig, frame):
    global _running
    logger.info("🛑 SIGTERM received — finishing current cycle then shutting down.")
    _running = False

signal.signal(signal.SIGTERM, _handle_sigterm)
signal.signal(signal.SIGINT,  _handle_sigterm)


# ─────────────────────────────────────────────────────────────────────────────
# Transaction emitters
# ─────────────────────────────────────────────────────────────────────────────

def emit_normal_transactions(conn: Neo4jConnection, count: int) -> int:
    """
    Emit a batch of realistic everyday ZA payment transactions.
    Customers and accounts are created on-the-fly to keep the graph growing.
    """
    emitted = 0
    for _ in range(count):
        c = _create_customer(conn)
        a = _create_account(conn, c["customer_id"],
                            account_type=random.choice(["cheque", "savings", "virtual"]))

        merchant_name = random.choice(ZA_MERCHANTS)
        m = _create_merchant(conn, name=merchant_name)

        amount  = round(random.uniform(20, 8_000), 2)
        channel = random.choice(["online", "pos", "mobile", "virtual_card", "tap_to_pay"])

        conn.query(
            """
            MATCH (a:Account {account_id: $acc_id})
            MATCH (m:Merchant {merchant_id: $merch_id})
            CREATE (t:Transaction {txn_id: $txn_id})
            SET t.amount    = $amount,
                t.currency  = 'ZAR',
                t.timestamp = $ts,
                t.txn_type  = 'purchase',
                t.status    = 'completed',
                t.channel   = $channel,
                t.aml_ring  = null,
                t.glitch_flag = false
            CREATE (a)-[:SENT]->(t)-[:TO]->(m)
            """,
            {
                "acc_id":   a["account_id"],
                "merch_id": m["merchant_id"],
                "txn_id":   f"TXN-NORM-{fake.uuid4()[:10].upper()}",
                "amount":   amount,
                "ts":       _ts(datetime.now()),
                "channel":  channel,
            },
        )
        emitted += 1

    return emitted


def emit_aml_burst(conn: Neo4jConnection) -> int:
    """
    Inject a single AML smurfing ring burst.
    Ring size and hop count are randomised for realism.
    """
    ring_size = random.randint(3, 5)
    hops      = random.randint(2, 4)
    ring_id   = f"LIVE-RING-{fake.uuid4()[:6].upper()}"

    customers = []
    accounts  = []
    for i in range(ring_size):
        c = _create_customer(conn, suffix=f"-{ring_id}-{i}")
        a = _create_account(conn, c["customer_id"], account_type="cheque")
        customers.append(c)
        accounts.append(a)

    base_time = _ts(datetime.now())
    txn_count = 0

    for hop in range(hops):
        for idx in range(ring_size):
            sender_acc   = accounts[idx]
            receiver_acc = accounts[(idx + 1) % ring_size]
            amount       = round(random.uniform(1_000, 4_999), 2)
            ts           = base_time + (hop * 300) + (idx * 20)

            conn.query(
                """
                MATCH (a:Account {account_id: $from_id})
                MATCH (b:Account {account_id: $to_id})
                CREATE (t:Transaction {txn_id: $txn_id})
                SET t.amount    = $amount,
                    t.currency  = 'ZAR',
                    t.timestamp = $ts,
                    t.txn_type  = 'smurf_transfer',
                    t.status    = 'completed',
                    t.channel   = 'online',
                    t.aml_ring  = $ring_id,
                    t.glitch_flag = false
                CREATE (a)-[:SENT]->(t)-[:TO]->(b)
                """,
                {
                    "from_id": sender_acc["account_id"],
                    "to_id":   receiver_acc["account_id"],
                    "txn_id":  f"AML-LIVE-{fake.uuid4()[:8].upper()}-H{hop}I{idx}",
                    "amount":  amount,
                    "ts":      ts,
                    "ring_id": ring_id,
                },
            )
            txn_count += 1

    logger.warning(
        "💉 AML burst injected | %s | %d participants | %d hops | %d txns",
        ring_id, ring_size, hops, txn_count,
    )
    return txn_count


def emit_glitch_burst(conn: Neo4jConnection) -> int:
    """
    Inject a single FNB/Takealot-style duplicate virtual card charge event.
    """
    c = _create_customer(conn, suffix=f"-GLIVE-{fake.uuid4()[:4].upper()}")
    a = _create_account(conn, c["customer_id"], account_type="virtual")

    takealot_results = conn.query(
        "MATCH (m:Merchant {name: 'Takealot'}) RETURN m.merchant_id AS mid LIMIT 1"
    )
    if takealot_results:
        merch_id = takealot_results[0]["mid"]
    else:
        m        = _create_merchant(conn, name="Takealot")
        merch_id = m["merchant_id"]

    amount    = round(random.uniform(150, 3_500), 2)
    base_time = _ts(datetime.now())
    dup_time  = base_time + random.randint(5, 45)

    for txn_id, ts, is_dup in [
        (f"TXN-ORIG-LIVE-{fake.uuid4()[:8].upper()}", base_time, False),
        (f"TXN-DUP-LIVE-{fake.uuid4()[:8].upper()}",  dup_time,  True),
    ]:
        conn.query(
            """
            MATCH (a:Account {account_id: $acc_id})
            MATCH (m:Merchant {merchant_id: $merch_id})
            CREATE (t:Transaction {txn_id: $txn_id})
            SET t.amount      = $amount,
                t.currency    = 'ZAR',
                t.timestamp   = $ts,
                t.txn_type    = 'virtual_card_purchase',
                t.status      = 'completed',
                t.channel     = 'virtual_card',
                t.glitch_flag = $is_dup,
                t.aml_ring    = null
            CREATE (a)-[:SENT]->(t)-[:TO]->(m)
            """,
            {
                "acc_id":   a["account_id"],
                "merch_id": merch_id,
                "txn_id":   txn_id,
                "amount":   amount,
                "ts":       ts,
                "is_dup":   is_dup,
            },
        )

    logger.warning(
        "💉 Glitch burst injected | %s | R%.2f x2 | %ds gap",
        a["account_id"], amount, dup_time - base_time,
    )
    return 2


# ─────────────────────────────────────────────────────────────────────────────
# Stream stats tracker
# ─────────────────────────────────────────────────────────────────────────────

class StreamStats:
    def __init__(self):
        self.cycles        = 0
        self.normal_txns   = 0
        self.aml_bursts    = 0
        self.glitch_bursts = 0
        self.start_time    = time.time()

    def elapsed(self) -> str:
        secs = int(time.time() - self.start_time)
        return f"{secs // 3600:02d}h {(secs % 3600) // 60:02d}m {secs % 60:02d}s"

    def log(self):
        logger.info(
            "📊 Stream stats | Elapsed: %s | Cycles: %d | Normal txns: %d | "
            "AML bursts: %d | Glitch bursts: %d",
            self.elapsed(), self.cycles,
            self.normal_txns, self.aml_bursts, self.glitch_bursts,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main stream loop
# ─────────────────────────────────────────────────────────────────────────────

def run_stream():
    logger.info("=" * 70)
    logger.info("🌊 LIVE TRANSACTION STREAM — Starting")
    logger.info("   Interval : %ds per cycle", STREAM_INTERVAL_SECONDS)
    logger.info("   Normal txns/cycle : %d", NORMAL_TXN_PER_CYCLE)
    logger.info("   AML inject prob   : %.0f%%", AML_INJECT_PROBABILITY * 100)
    logger.info("   Glitch inject prob: %.0f%%", GLITCH_INJECT_PROBABILITY * 100)
    logger.info("   Max runtime       : %ds", MAX_RUNTIME_SECONDS)
    logger.info("=" * 70)

    stats      = StreamStats()
    start_time = time.time()

    with Neo4jConnection() as conn:
        ensure_schema(conn)
        logger.info("✅ Connected to Neo4j AuraDB. Stream is live.\n")

        while _running:
            # ── Check max runtime ────────────────────────────────────────
            elapsed = time.time() - start_time
            if elapsed >= MAX_RUNTIME_SECONDS:
                logger.info("⏱️  Max runtime reached (%.0fs). Shutting down cleanly.", elapsed)
                break

            cycle_start = time.time()
            stats.cycles += 1
            logger.info("─── Cycle #%d | %s ───", stats.cycles, _now())

            # ── Normal transactions ──────────────────────────────────────
            n = emit_normal_transactions(conn, NORMAL_TXN_PER_CYCLE)
            stats.normal_txns += n
            logger.info("  ✅ %d normal transaction(s) written", n)

            # ── AML anomaly (probabilistic) ──────────────────────────────
            if random.random() < AML_INJECT_PROBABILITY:
                emit_aml_burst(conn)
                stats.aml_bursts += 1

            # ── Glitch anomaly (probabilistic) ───────────────────────────
            if random.random() < GLITCH_INJECT_PROBABILITY:
                emit_glitch_burst(conn)
                stats.glitch_bursts += 1

            # ── Log summary every 10 cycles ──────────────────────────────
            if stats.cycles % 10 == 0:
                stats.log()

            # ── Sleep until next cycle ────────────────────────────────────
            cycle_duration = time.time() - cycle_start
            sleep_for      = max(0, STREAM_INTERVAL_SECONDS - cycle_duration)
            logger.info("  💤 Sleeping %.1fs until next cycle...\n", sleep_for)
            time.sleep(sleep_for)

    stats.log()
    logger.info("🏁 Transaction stream stopped.")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    run_stream()
