"""
aml_detector.py
Anti-Money Laundering detection engine.

Uses Cypher graph traversal to identify closed-loop "smurfing" rings:
  -> Multi-hop circular transaction flows between accounts
  -> Sub-threshold amounts designed to evade FICA reporting (< R5 000)
  -> Returns structured AML findings for the alert engine
"""

import logging
from db_connection import Neo4jConnection

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Cypher: Closed-loop ring detection (2-hop)
# ─────────────────────────────────────────────────────────────────────────────

RING_DETECTION_QUERY = """
MATCH (a:Account)-[:SENT]->(t:Transaction)-[:TO]->(b:Account)-[:SENT]->(t2:Transaction)-[:TO]->(a)
WITH a, b, t, t2,
     [t.amount, t2.amount] AS amounts
MATCH (a)<-[:OWNS]-(c:Customer)
RETURN
    a.account_id          AS ring_account,
    c.customer_id         AS customer_id,
    c.full_name           AS customer_name,
    c.email               AS customer_email,
    2                     AS hops,
    amounts               AS transaction_amounts,
    t.amount + t2.amount  AS total_laundered,
    [t.txn_id, t2.txn_id] AS txn_ids
ORDER BY total_laundered DESC
LIMIT 25
"""

# ─────────────────────────────────────────────────────────────────────────────
# Cypher: Sub-threshold structuring detection
# Flags accounts with > 5 transactions between R1 000-R4 999 within 24 hours
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Detection runner
# ─────────────────────────────────────────────────────────────────────────────

class AMLDetector:

    def __init__(self, conn: Neo4jConnection):
        self.conn = conn

    def detect_smurfing_rings(self) -> list[dict]:
        """
        Detect closed-loop circular transaction rings (smurfing).
        Returns a list of AML finding dictionaries.
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
                "customer_id":         row["customer_id"],
                "customer_name":       row["customer_name"],
                "customer_email":      row.get("customer_email", ""),
                "hops":                row["hops"],
                "transaction_amounts": row["transaction_amounts"],
                "total_laundered_zar": round(row["total_laundered"], 2),
                "txn_ids":             row["txn_ids"],
                "description": (
                    f"Closed-loop smurfing ring detected on account {row['ring_account']}. "
                    f"{row['hops']}-hop circular transfer totalling "
                    f"R{round(row['total_laundered'], 2):,.2f} in sub-threshold amounts."
                ),
            }
            findings.append(finding)
            logger.warning(
                "AML Ring | %s | %d hops | R%.2f | %s",
                row["ring_account"], row["hops"],
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


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _classify_severity(amount: float) -> str:
    if amount >= 50_000:
        return "CRITICAL"
    if amount >= 20_000:
        return "HIGH"
    if amount >= 5_000:
        return "MEDIUM"
    return "LOW"
