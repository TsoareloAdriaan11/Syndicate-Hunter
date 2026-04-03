"""
glitch_detector.py
Optimized temporal detection for duplicate payment gateway charges.
"""

import logging
from db_connection import Neo4jConnection

logger = logging.getLogger(__name__)

# ── TEMPORAL OPTIMIZED QUERY ─────────────────────────────────────────────────
# Forces the database to only look at subsequent transactions within the window
# before doing the absolute math, preventing Cartesian Product slowdowns.
DUPLICATE_CHARGE_QUERY = """
MATCH (a:Account {account_type: 'virtual'})-[:SENT]->(t1:Transaction)-[:TO]->(m:Merchant)
WHERE t1.channel = 'virtual_card'
MATCH (a)-[:SENT]->(t2:Transaction)-[:TO]->(m)
WHERE t1.txn_id < t2.txn_id 
  AND t2.channel = 'virtual_card'
  AND t2.timestamp >= t1.timestamp 
  AND t2.timestamp <= t1.timestamp + $window_seconds
  AND abs(t1.amount - t2.amount) < 0.01
MATCH (a)<-[:OWNS]-(c:Customer)
RETURN 
    c.customer_id AS customer_id,
    c.full_name AS customer_name,
    a.account_id AS account_id,
    m.name AS merchant_name,
    t1.txn_id AS original_txn_id,
    t2.txn_id AS duplicate_txn_id,
    t1.amount AS overcharged_zar,
    (t2.timestamp - t1.timestamp) AS seconds_between_charges
ORDER BY t1.timestamp DESC
"""

class GlitchDetector:
    def __init__(self, conn: Neo4jConnection, window_seconds: int = 21600):
        self.conn = conn
        self.window_seconds = window_seconds
        self.findings = []

    def detect_duplicates(self) -> list:
        logger.info("🔍 Scanning for duplicate virtual card charges (temporal window: %ds)...", self.window_seconds)
        
        results = self.conn.query(DUPLICATE_CHARGE_QUERY, {"window_seconds": self.window_seconds})
        
        for r in results:
            self.findings.append({
                "type": "PAYMENT_GATEWAY_GLITCH",
                "severity": "HIGH",
                "customer_id": r["customer_id"],
                "customer_name": r["customer_name"],
                "account_id": r["account_id"],
                "merchant_name": r["merchant_name"],
                "original_txn_id": r["original_txn_id"],
                "duplicate_txn_id": r["duplicate_txn_id"],
                "overcharged_zar": r["overcharged_zar"],
                "total_debited_zar": r["overcharged_zar"] * 2,
                "seconds_between_charges": r["seconds_between_charges"]
            })
            
            logger.warning(
                "🚨 Duplicate Charge | %s | %s | R%.2f x2 | %ds gap",
                r['customer_id'], r['merchant_name'], 
                r['overcharged_zar'], r['seconds_between_charges']
            )

        logger.info("🏁 Glitch scan complete. %d duplicate(s) found.", len(self.findings))
        return self.findings

    def get_impact_summary(self) -> dict:
        summary = {}
        for f in self.findings:
            m = f["merchant_name"]
            if m not in summary:
                summary[m] = {
                    "duplicate_events": 0,
                    "total_overcharged_zar": 0.0,
                    "min_charge_zar": float('inf'),
                    "max_charge_zar": 0.0
                }
            
            summary[m]["duplicate_events"] += 1
            amt = f["overcharged_zar"]
            summary[m]["total_overcharged_zar"] += amt
            
            if amt < summary[m]["min_charge_zar"]:
                summary[m]["min_charge_zar"] = amt
            if amt > summary[m]["max_charge_zar"]:
                summary[m]["max_charge_zar"] = amt

        for m, data in summary.items():
            if data["duplicate_events"] > 0:
                data["avg_charge_zar"] = data["total_overcharged_zar"] / data["duplicate_events"]
            else:
                data["avg_charge_zar"] = 0.0

        logger.info("📊 Generating glitch impact summary...")
        for m, d in summary.items():
            logger.info("   📌 %s → %d duplicates | R%.2f overcharged", m, d['duplicate_events'], d['total_overcharged_zar'])

        return summary

    def run_all(self) -> list:
        return self.detect_duplicates()
