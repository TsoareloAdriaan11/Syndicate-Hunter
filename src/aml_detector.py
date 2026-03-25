"""
aml_detector.py
Anti-Money Laundering detection engine.
"""

import logging
from db_connection import Neo4jConnection

logger = logging.getLogger(__name__)

# The stream creates this exact pattern:
# (AccA)-[:SENT]->(Txn1)-[:TO]->(AccB)
# (AccB)-[:SENT]->(Txn2)-[:TO]->(AccC)
# (AccC)-[:SENT]->(Txn3)-[:TO]->(AccA)  <-- closes the loop
#
# We detect it by finding all transactions tagged with aml_ring
# which is set by emit_aml_burst() in transaction_stream.py

RING_DETECTION_QUERY = """
MATCH (t:Transaction)
WHERE t.aml_ring IS NOT NULL
WITH t.aml_ring AS ring_id,
     collect(t.txn_id) AS txn_ids,
     collect(t.amount) AS amounts,
     count(t) AS txn_count,
     sum(t.amount) AS total_laundered
MATCH (acc:Account)-[:SENT]->(tx:Transaction {aml_ring: ring_id})
WITH ring_id, txn_ids, amounts, txn_count, total_laundered,
     collect(DISTINCT acc.account_id) AS ring_accounts
WITH ring_id, txn_ids, amounts, txn_count, total_laundered,
     ring_accounts, ring_accounts[0] AS first_account
MATCH (first_acc:Account {account_id: first_account})<-[:OWNS]-(c:Customer)
RETURN
    ring_id                AS ring_id,
    first_account          AS ring_account,
    c.customer_id          AS customer_id,
    c.full_name            AS customer_name,
    c.email                AS customer_email,
    size(ring_accounts)    AS hops,
    amounts                AS transaction_amounts,
    total_laundered        AS total_laundered,
    txn_ids                AS txn_ids
ORDER BY total_laundered DESC
LIMIT 25
"""

STRUCTURING_QUERY = """
MATCH (a:Account)-[:SENT]->(t:Transaction)
WHERE t.amount >= 1000 AND t.amount < 5000
  AND t.timestamp >= (timestamp() / 1000) - 86400
WITH a, count(t) AS txn_count, collect(t.txn_id) AS txn_ids,
     sum(t.amount) AS total_amount
WHERE txn_count > 5
MATCH (a)<-[:OWNS]-(c:Customer)
RETURN
    a.account_id  AS account_id,
    c.customer_id AS customer_id,
    c.full_name   AS customer_name,
    c.email       AS customer_email,
    txn_count     AS suspicious_txn_count,
    total_amount  AS total_structured_amount,
    txn_ids       AS txn_ids
ORDER BY txn_count DESC
"""


class AMLDetector:

    def __init__(self, conn: Neo4jConnection):
        self.conn = conn

    def detect_smurfing_rings(self) -> list[dict]:
        """
        Detect AML rings by finding all transactions tagged with aml_ring.
        """
        logger.info("Scanning for AML smurfing rings...")
        results = self.conn.query(RING_DETECTION_QUERY)

        if not results:
            logger.info("No AML smurfing rings detected.")
            return []

        findings = []
        for row in results:
            finding = {
                "type":                "AML_SMURFING_RING",
                "severity":            _classify_severity(row.get("total_laundered", 0)),
                "ring_account":        row["ring_account"],
                "ring_id":             row["ring_id"],
                "customer_id":         row["customer_id"],
                "customer_name":       row["customer_name"],
                "customer_email":      row.get("customer_email", ""),
                "hops":                row["hops"],
                "transaction_amounts": row["transaction_amounts"],
                "total_laundered_zar": round(row["total_laundered"], 2),
                "txn_ids":             row["txn_ids"],
                "description": (
                    f"Closed-loop smurfing ring detected. Ring ID: {row['ring_id']}. "
                    f"{row['hops']} accounts involved. "
                    f"Total laundered: R{round(row['total_laundered'], 2):,.2f} "
                    f"across {len(row['txn_ids'])} transactions."
                ),
            }
            findings.append(finding)
            logger.warning(
                "AML Ring | %s | %d accounts | R%.2f | Customer: %s",
                row["ring_id"], row["hops"],
                row["total_laundered"], row["customer_name"],
            )

        logger.info("AML scan complete. %d ring(s) found.", len(findings))
        return findings

    def detect_structuring(self) -> list[dict]:
        """
        Detect transaction structuring: many sub-threshold transfers in 24h.
        """
        logger.info("Scanning for transaction structuring...")
        results = self.conn.query(STRUCTURING_QUERY)

        if not results:
            logger.info("No structuring patterns detected.")
            return []

        findings = []
        for row in results:
            finding = {
                "type":                    "AML_STRUCTURING",
                "severity":                "HIGH",
                "account_id":              row["account_id"],
                "customer_id":             row["customer_id"],
                "customer_name":           row["customer_name"],
                "customer_email":          row.get("customer_email", ""),
                "suspicious_txn_count":    row["suspicious_txn_count"],
                "total_structured_amount": round(row["total_structured_amount"], 2),
                "txn_ids":                 row["txn_ids"],
                "description": (
                    f"Structuring detected on account {row['account_id']}. "
                    f"{row['suspicious_txn_count']} sub-R5000 transactions totalling "
                    f"R{round(row['total_structured_amount'], 2):,.2f} in the past 24 hours."
                ),
            }
            findings.append(finding)
            logger.warning(
                "Structuring | %s | %d txns | R%.2f",
                row["account_id"], row["suspicious_txn_count"],
                row["total_structured_amount"],
            )

        logger.info("Structuring scan complete. %d finding(s).", len(findings))
        return findings

    def run_all(self) -> list[dict]:
        rings       = self.detect_smurfing_rings()
        structuring = self.detect_structuring()
        return rings + structuring


def _classify_severity(amount: float) -> str:
    if amount >= 50_000:
        return "CRITICAL"
    if amount >= 20_000:
        return "HIGH"
    if amount >= 5_000:
        return "MEDIUM"
    return "LOW"
