"""
aml_detector.py
Detection algorithms for Anti-Money Laundering (AML) patterns.
"""

import logging
from db_connection import Neo4jConnection

logger = logging.getLogger(__name__)

# ── TAG-BASED RING DETECTION ─────────────────────────────────────────────────
# Reverted to tag-based grouping to prevent graph permutation duplicates.
# Groups all transactions by their specific ring ID so you only get 1 alert per syndicate.
RING_DETECTION_QUERY = """
MATCH (t:Transaction)
WHERE t.aml_ring IS NOT NULL
WITH t.aml_ring AS ring_id,
     collect(DISTINCT t.txn_id) AS txn_ids,
     sum(t.amount)              AS total_laundered_zar
MATCH (a:Account)-[:SENT]->(tx:Transaction {aml_ring: ring_id})
WITH ring_id, txn_ids, total_laundered_zar,
     collect(DISTINCT a.account_id) AS accounts
MATCH (c:Customer)-[:OWNS]->(first_acc:Account {account_id: accounts[0]})
RETURN
    ring_id,
    ring_id                AS ring_account,
    c.customer_id          AS customer_id,
    c.full_name            AS customer_name,
    size(accounts)         AS hops,
    total_laundered_zar,
    txn_ids
ORDER BY total_laundered_zar DESC
"""

# ── STRUCTURING QUERY ────────────────────────────────────────────────────────
# Scans for individuals making multiple transfers just below reporting thresholds.
# Excludes known ring transactions to prevent overlap.
STRUCTURING_QUERY = """
MATCH (c:Customer)-[:OWNS]->(a:Account)-[:SENT]->(t:Transaction)
WHERE t.amount >= 1000 AND t.amount < 5000 AND t.aml_ring IS NULL
WITH a.account_id AS account_id, 
     c.full_name AS customer_name, 
     count(t) AS txn_count, 
     sum(t.amount) AS total_amount
WHERE txn_count > 5
RETURN 
    account_id,
    customer_name,
    txn_count,
    total_amount AS total_structured_amount
ORDER BY total_structured_amount DESC
LIMIT 50
"""

class AMLDetector:
    def __init__(self, conn: Neo4jConnection):
        self.conn = conn

    def detect_smurfing_rings(self) -> list:
        logger.info("Scanning for AML smurfing rings...")
        results = self.conn.query(RING_DETECTION_QUERY)
        
        findings = []
        for r in results:
            if r.get("hops", 0) == 0:
                logger.warning("Skipping ring %s — 0 accounts detected (data integrity issue)", r.get("ring_id"))
                continue
            findings.append({
                "type": "AML_SMURFING_RING",
                "severity": "CRITICAL" if r["total_laundered_zar"] > 50000 else "HIGH",
                "ring_id": r["ring_id"],
                "ring_account": r["ring_account"],
                "customer_id": r["customer_id"],
                "customer_name": r["customer_name"],
                "hops": r["hops"],
                "total_laundered_zar": r["total_laundered_zar"],
                "txn_ids": r["txn_ids"]
            })
            
            logger.warning(
                "AML Ring | %s | %d accounts | R%.2f | Customer: %s",
                r['ring_id'], r['hops'], r['total_laundered_zar'], r['customer_name']
            )
            
        logger.info("AML scan complete. %d ring(s) found.", len(findings))
        return findings

    def detect_structuring(self) -> list:
        logger.info("Scanning for transaction structuring...")
        results = self.conn.query(STRUCTURING_QUERY)
        
        findings = []
        for r in results:
            findings.append({
                "type": "AML_STRUCTURING",
                "severity": "MEDIUM",
                "account_id": r["account_id"],
                "customer_name": r["customer_name"],
                "txn_count": r["txn_count"],
                "total_structured_amount": r["total_structured_amount"]
            })
            logger.warning(
                "Structuring | %s | %d txns | R%.2f",
                r['account_id'], r['txn_count'], r['total_structured_amount']
            )
            
        logger.info("Structuring scan complete. %d finding(s).", len(findings))
        return findings

    def run_all(self) -> list:
        rings = self.detect_smurfing_rings()
        structs = self.detect_structuring()
        return rings + structs
