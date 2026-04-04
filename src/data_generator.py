"""
data_generator.py
Generates synthetic KYC customer profiles, accounts, merchants, and transactions
and seeds them into Neo4j AuraDB.

Two injection modes:
  - inject_aml_ring()     → Simulates smurfing: closed-loop multi-hop transfers
  - inject_glitch_data()  → Simulates FNB/Takealot duplicate virtual card charges
"""

import random
import logging
from datetime import datetime, timedelta
from faker import Faker
from db_connection import Neo4jConnection

fake    = Faker()          # South African locale for ZA-realistic data
logger  = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Helper: epoch timestamp (seconds)
# ─────────────────────────────────────────────────────────────────────────────

def _ts(dt: datetime) -> int:
    return int(dt.timestamp())


# ─────────────────────────────────────────────────────────────────────────────
# Graph schema setup
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_QUERIES = [
    "CREATE CONSTRAINT customer_id IF NOT EXISTS FOR (c:Customer) REQUIRE c.customer_id IS UNIQUE",
    "CREATE CONSTRAINT account_id  IF NOT EXISTS FOR (a:Account)  REQUIRE a.account_id  IS UNIQUE",
    "CREATE CONSTRAINT txn_id      IF NOT EXISTS FOR (t:Transaction) REQUIRE t.txn_id IS UNIQUE",
    "CREATE CONSTRAINT merchant_id IF NOT EXISTS FOR (m:Merchant)  REQUIRE m.merchant_id IS UNIQUE",
]

def ensure_schema(conn: Neo4jConnection):
    for q in SCHEMA_QUERIES:
        conn.query(q)
    logger.info("📐 Schema constraints verified.")


# ─────────────────────────────────────────────────────────────────────────────
# Node factories
# ─────────────────────────────────────────────────────────────────────────────

def _create_customer(conn: Neo4jConnection, suffix: str = "") -> dict:
    customer = {
        "customer_id":  f"CUST-{fake.uuid4()[:8].upper()}{suffix}",
        "full_name":    fake.name(),
        "id_number":    fake.numerify("##############"),   # SA ID format placeholder
        "email":        fake.email(),
        "phone":        fake.phone_number(),
        "risk_score":   round(random.uniform(0.1, 0.9), 2),
        "kyc_verified": random.choice([True, False]),
        "created_at":   _ts(datetime.now()),
    }
    conn.query(
        """
        MERGE (c:Customer {customer_id: $customer_id})
        SET c += $props
        """,
        {"customer_id": customer["customer_id"], "props": customer},
    )
    return customer


def _create_account(conn: Neo4jConnection, customer_id: str,
                    account_type: str = "cheque") -> dict:
    account = {
        "account_id":   f"ACC-{fake.uuid4()[:8].upper()}",
        "account_type": account_type,
        "bank":         random.choice(["FNB", "ABSA", "Standard Bank", "Nedbank", "Capitec"]),
        "balance":      round(random.uniform(500, 50_000), 2),
        "currency":     "ZAR",
    }
    conn.query(
        """
        MERGE (a:Account {account_id: $account_id})
        SET a += $props
        WITH a
        MATCH (c:Customer {customer_id: $cid})
        MERGE (c)-[:OWNS]->(a)
        """,
        {"account_id": account["account_id"], "props": account, "cid": customer_id},
    )
    return account


def _create_merchant(conn: Neo4jConnection, name: str = None) -> dict:
    merchant_name = name or fake.company()
    merchant_id   = f"MERCH-{fake.uuid4()[:6].upper()}"

    if name:
        # Named merchants (e.g. Takealot) must always be a single node — MERGE on name
        result = conn.query(
            """
            MERGE (m:Merchant {name: $name})
            ON CREATE SET m.merchant_id   = $merchant_id,
                          m.category      = $category,
                          m.merchant_code = $merchant_code
            RETURN m.merchant_id AS mid
            """,
            {
                "name":          merchant_name,
                "merchant_id":   merchant_id,
                "category":      random.choice(["Retail", "E-Commerce", "Grocery", "Electronics"]),
                "merchant_code": fake.numerify("MCC-####"),
            },
        )
        return {"merchant_id": result[0]["mid"], "name": merchant_name}
    else:
        # Random merchants get a unique ID each time
        merchant = {
            "merchant_id":   merchant_id,
            "name":          merchant_name,
            "category":      random.choice(["Retail", "E-Commerce", "Grocery", "Electronics"]),
            "merchant_code": fake.numerify("MCC-####"),
        }
        conn.query(
            "MERGE (m:Merchant {merchant_id: $merchant_id}) SET m += $props",
            {"merchant_id": merchant["merchant_id"], "props": merchant},
        )
        return merchant


def _create_transaction(conn: Neo4jConnection, from_account_id: str,
                        to_node_id: str, to_label: str,
                        amount: float, timestamp: int,
                        txn_type: str = "transfer",
                        label_tag: str = "") -> dict:
    txn = {
        "txn_id":       f"TXN-{fake.uuid4()[:10].upper()}{label_tag}",
        "amount":       amount,
        "currency":     "ZAR",
        "timestamp":    timestamp,
        "txn_type":     txn_type,
        "status":       "completed",
        "channel":      random.choice(["online", "mobile", "virtual_card", "pos"]),
    }
    conn.query(
        f"""
        MATCH (a:Account {{account_id: $from_id}})
        MATCH (b:{to_label} {{{to_label.lower()}_id: $to_id}})
        CREATE (t:Transaction {{txn_id: $txn_id}})
        SET t += $props
        CREATE (a)-[:SENT]->(t)
        CREATE (t)-[:TO]->(b)
        """,
        {
            "from_id": from_account_id,
            "to_id":   to_node_id,
            "txn_id":  txn["txn_id"],
            "props":   txn,
        },
    )
    return txn


# ─────────────────────────────────────────────────────────────────────────────
# AML: Smurfing ring injection
# ─────────────────────────────────────────────────────────────────────────────

def inject_aml_ring(conn: Neo4jConnection, ring_size: int = 4,
                    num_rings: int = 2, hops: int = 3):
    """
    Inject synthetic smurfing rings into the graph.

    Pattern: A -> B -> C -> ... -> A  (closed loop)
    Amounts are deliberately small (<R5 000) to stay below FICA thresholds.
    """
    logger.info("💉 Injecting %d AML smurfing ring(s) of size %d ...", num_rings, ring_size)

    for ring_num in range(num_rings):
        customers = []
        accounts  = []

        # Build ring participants
        for i in range(ring_size):
            c = _create_customer(conn, suffix=f"-R{ring_num}M{i}")
            a = _create_account(conn, c["customer_id"], account_type="cheque")
            customers.append(c)
            accounts.append(a)

        # Create closed-loop transactions  A->B->C->A
        base_time = _ts(datetime.now() - timedelta(hours=random.randint(1, 48)))
        for hop in range(hops):
            for idx in range(ring_size):
                sender_acc   = accounts[idx]
                receiver_acc = accounts[(idx + 1) % ring_size]
                amount       = round(random.uniform(1_000, 4_999), 2)   # Sub-FICA threshold
                ts           = base_time + (hop * 600) + (idx * 30)

                # Direct account-to-account SENT relationship for cycle detection
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
                        t.aml_ring  = $ring_id
                    CREATE (a)-[:SENT]->(t)-[:TO]->(b)
                    """,
                    {
                        "from_id": sender_acc["account_id"],
                        "to_id":   receiver_acc["account_id"],
                        "txn_id":  f"AML-{fake.uuid4()[:8].upper()}-R{ring_num}H{hop}I{idx}",
                        "amount":  amount,
                        "ts":      ts,
                        "ring_id": f"RING-{ring_num}",
                    },
                )

        logger.info("  ✅ Ring %d injected (%d participants, %d hops)", ring_num, ring_size, hops)

    logger.info("🏁 AML ring injection complete.")


# ─────────────────────────────────────────────────────────────────────────────
# Glitch: FNB/Takealot duplicate virtual card charges
# ─────────────────────────────────────────────────────────────────────────────

def inject_glitch_data(conn: Neo4jConnection, num_affected: int = 10,
                       duplicate_window_seconds: int = 45):
    """
    Simulates the FNB virtual card processing glitch on Takealot.

    Each affected customer has a virtual card account that fires the SAME
    transaction twice within `duplicate_window_seconds`.
    """
    logger.info("💉 Injecting FNB/Takealot glitch data (%d affected customers)...", num_affected)

    takealot = _create_merchant(conn, name="Takealot")

    for i in range(num_affected):
        c = _create_customer(conn, suffix=f"-GLT{i}")
        a = _create_account(conn, c["customer_id"], account_type="virtual")   # FNB virtual card

        amount    = round(random.uniform(150, 3_500), 2)      # Realistic ZA e-commerce basket
        base_time = _ts(datetime.now() - timedelta(minutes=random.randint(5, 120)))
        dup_time  = base_time + random.randint(5, duplicate_window_seconds)

        # First (legitimate) charge
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
                t.glitch_flag = false
            CREATE (a)-[:SENT]->(t)-[:TO]->(m)
            """,
            {
                "acc_id":   a["account_id"],
                "merch_id": takealot["merchant_id"],
                "txn_id":   f"TXN-ORIG-{fake.uuid4()[:8].upper()}",
                "amount":   amount,
                "ts":       base_time,
            },
        )

        # Duplicate (ghost) charge — same account, same merchant, same amount
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
                t.glitch_flag = true
            CREATE (a)-[:SENT]->(t)-[:TO]->(m)
            """,
            {
                "acc_id":   a["account_id"],
                "merch_id": takealot["merchant_id"],
                "txn_id":   f"TXN-DUP-{fake.uuid4()[:8].upper()}",
                "amount":   amount,
                "ts":       dup_time,
            },
        )

        logger.info(
            "  👤 Customer %s | Virtual Acc %s | R%.2f charged twice (%ds apart)",
            c["customer_id"], a["account_id"], amount,
            dup_time - base_time,
        )

    logger.info("🏁 Glitch injection complete.")
