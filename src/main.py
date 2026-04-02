"""
main.py
Financial Risk Engine — Detection & Alert Orchestrator
"""
from dotenv import load_dotenv
load_dotenv()
import os
import sys
import logging

from db_connection    import Neo4jConnection
from aml_detector     import AMLDetector
from glitch_detector  import GlitchDetector
from alert_engine     import AlertEngine
from report_generator import generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("risk_engine.main")


def main():
    logger.info("=" * 70)
    logger.info("FINANCIAL RISK ENGINE — Detection Scan Starting")
    logger.info("   (Live transaction stream is running separately)")
    logger.info("=" * 70)

    alert  = AlertEngine()
    run_id = os.environ.get("GITHUB_RUN_ID", "local")

    with Neo4jConnection() as conn:

        # ── 1. AML Detection ───────────────────────────────────────────────
        logger.info("\nStep 1/4: Running AML detection algorithms...")
        aml_detector = AMLDetector(conn)
        aml_findings = aml_detector.run_all()

        # ── 2. Glitch Detection ────────────────────────────────────────────
        logger.info("\nStep 2/4: Running payment glitch detection...")
        glitch_detector = GlitchDetector(conn, window_seconds=21600)
        glitch_findings = glitch_detector.run_all()
        impact_summary  = glitch_detector.get_impact_summary()

        # ── 3. Generate full HTML report ───────────────────────────────────
        logger.info("\nStep 3/4: Generating full anomaly report...")
        total_findings = len(aml_findings) + len(glitch_findings)

        report_path = None
        report_name = None
        if total_findings > 0:
            report_path, report_name = generate_report(
                aml_findings, glitch_findings, impact_summary, run_id
            )
            logger.info("Report saved: %s", report_path)

        # ── 4. Alerting ────────────────────────────────────────────────────
        logger.info("\nStep 4/4: Dispatching alerts...")

        if total_findings == 0:
            logger.info("No anomalies detected — sending clean-run notification.")
            alert.send_clean_run()
        else:
            # Send top 25 AML + top 25 glitch as individual emails
            # with a small delay to avoid Gmail rate limiting
            import time
            for finding in aml_findings[:25] + glitch_findings[:25]:
                alert.send_finding(finding)
                time.sleep(1)

            # Send summary with top 50 of each + report download link
            alert.send_run_summary(
                aml_findings[:50],
                glitch_findings[:50],
                impact_summary,
                total_aml=len(aml_findings),
                total_glitch=len(glitch_findings),
                run_id=run_id,
            )

        # ── Summary log ────────────────────────────────────────────────────
        logger.info("\n" + "=" * 70)
        logger.info("SCAN COMPLETE")
        logger.info("   AML findings       : %d", len(aml_findings))
        logger.info("   Glitch findings    : %d", len(glitch_findings))
        logger.info(
            "   Total AML exposure : R%.2f",
            sum(f.get("total_laundered_zar", f.get("total_structured_amount", 0)) for f in aml_findings),
        )
        logger.info(
            "   Total refunds due  : R%.2f",
            sum(f.get("overcharged_zar", 0) for f in glitch_findings),
        )
        if report_path:
            logger.info("   Report file        : %s", report_name)
        logger.info("=" * 70)


if __name__ == "__main__":
    main()
