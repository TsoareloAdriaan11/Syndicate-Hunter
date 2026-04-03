"""
aml_detector.py
Advanced Graph Traversal for Anti-Money Laundering (AML).
"""

import logging
from db_connection import Neo4jConnection

logger = logging.getLogger(__name__)

# ── ADVANCED GRAPH TRAVERSAL QUERY ───────────────────────────────────────────
# This query hunts for topological cycles. It finds where money leaves an account,
# bounces through up to 5 other accounts, and returns to the origin.
RING_DETECTION_QUERY = """
MATCH path = (start_acc:Account)-[:SENT]->(t1:Transaction)-[:TO]->(next_acc:Account)
// Traverse outgoing transfers up to 10 relationship hops (5 transactions)
MATCH p2 = (next_acc)-[:SENT|TO*2..10]->(start_acc)
WHERE t1.amount >= 1000 
  AND start_acc <> next_acc // Prevent immediate bounce-backs
WITH start_acc, path, p2, nodes(p2) AS path_nodes
RETURN 
    start_acc.account_id AS ring_account,
    start_acc.account_id AS customer_id, 
    "Syndicate Target" AS customer_name,
    length(p2)/2 + 1 AS hops,
    reduce(total = 0, n IN path_nodes | 
        CASE WHEN 'Transaction' IN labels(n) THEN total + n.amount ELSE total END
    ) + t1.amount AS total_laundered_zar,
    [n IN path_nodes WHERE 'Transaction' IN labels(n) | n.txn_id] AS txn_ids
ORDER BY total_laundered_zar DESC
LIMIT 25
"""

STRUCTURING_QUERY = """
MATCH (a:Account)-[:SENT]->(t:Transaction)
WHERE t.amount >= 1000 AND t.amount < 5000
WITH a, count(t) AS small_txns, sum(t.amount) AS total_amount
WHERE small_txns > 5
RETURN 
    a.account_id AS account_id,
    small_txns AS txn_count,
    total_amount AS total_structured_amount
ORDER BY total_structured_amount DESC
LIMIT 50
"""

class AMLDetector:
    def __init__(self, conn: Neo4jConnection):
        self.conn = conn

    def detect_smurfing_rings(self) -> list:
        logger.info("Scanning for topological AML smurfing cycles...")
        results = self.conn.query(RING_DETECTION_QUERY)
        
        findings = []
        for r in results:
            findings.append({
                "type": "AML_SMURFING_RING",
                "severity": "CRITICAL" if r["total_laundered_zar"] > 50000 else "HIGH",
                "ring_id": r.get("ring_account", "UNKNOWN"),
                "ring_account": r["ring_account"],
                "customer_id": r["customer_id"],
                "customer_name": r["customer_name"],
                "hops": r["hops"],
                "total_laundered_zar": r["total_laundered_zar"],
                "txn_ids": r["txn_ids"]
            })
            
            logger.warning(
                "AML Cycle | %s | %d hops | R%.2f",
                r['ring_account'], r['hops'], r['total_laundered_zar']
            )
            
        logger.info("AML cycle scan complete. %d ring(s) found.", len(findings))
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
                "customer_name": "Unknown",
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
