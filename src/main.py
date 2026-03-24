"""
main.py
Financial Risk Engine — Detection & Alert Orchestrator

NOTE: Data injection is handled by `transaction_stream.py` running as a
      persistent live service. This script is detection-only — it scans
      whatever the stream has written and fires alerts.

Execution flow:
  1. Connect to Neo4j AuraDB
  2. Run AML detection  (smurfing rings + structuring)
  3. Run glitch detection (duplicate virtual card charges)
  4. Fire real-time email alerts per finding
  5. Send end-of-run summary digest
  6. Exit cleanly

Triggered every 6 hours by GitHub Actions (risk_engine.yml).
The live stream (transaction_stream.yml) runs in parallel, continuously
writing new transactions — this script scans what it finds and reports.
"""
from dotenv import load_dotenv
load_dotenv()
import sys
import logging

from db_connection   import Neo4jConnection
from aml_detector    import AMLDetector
from glitch_detector import GlitchDetector
from alert_engine    import AlertEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("risk_engine.main")


def main():
    logger.info("=" * 70)
    logger.info("🚀 FINANCIAL RISK ENGINE — Detection Scan Starting")
    logger.info("   (Live transaction stream is running separately)")
    logger.info("=" * 70)

    alert = AlertEngine()

    with Neo4jConnection() as conn:

        # ── 1. AML Detection ───────────────────────────────────────────────
        logger.info("\n🔍 Step 1/3: Running AML detection algorithms...")
        aml_detector = AMLDetector(conn)
        aml_findings = aml_detector.run_all()

        # ── 2. Glitch Detection ────────────────────────────────────────────
        logger.info("\n⚡ Step 2/3: Running payment glitch detection...")
        glitch_detector = GlitchDetector(conn, window_seconds=21600)
        glitch_findings = glitch_detector.run_all()
        impact_summary  = glitch_detector.get_impact_summary()

        # ── 3. Alerting ────────────────────────────────────────────────────
        logger.info("\n📧 Step 3/3: Dispatching alerts...")
        total_findings = len(aml_findings) + len(glitch_findings)

        if total_findings == 0:
            logger.info("✅ No anomalies detected — sending clean-run notification.")
            alert.send_clean_run()
        else:
            for finding in aml_findings + glitch_findings:
                alert.send_finding(finding)
            alert.send_run_summary(aml_findings, glitch_findings, impact_summary)

        # ── Summary ────────────────────────────────────────────────────────
        logger.info("\n" + "=" * 70)
        logger.info("📊 SCAN COMPLETE")
        logger.info("   AML findings       : %d", len(aml_findings))
        logger.info("   Glitch findings    : %d", len(glitch_findings))
        logger.info(
            "   Total AML exposure : R%.2f",
            sum(f.get("total_laundered_zar", 0) for f in aml_findings),
        )
        logger.info(
            "   Total refunds due  : R%.2f",
            sum(f.get("overcharged_zar", 0) for f in glitch_findings),
        )
        logger.info("=" * 70)


if __name__ == "__main__":
    main()
