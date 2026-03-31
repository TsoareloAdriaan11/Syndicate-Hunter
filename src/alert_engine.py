"""
alert_engine.py
Real-time email alerting via smtplib (Gmail SMTP).

Fires structured risk alert emails to analysts the moment a finding is detected.
Credentials are injected via GitHub Actions Secrets:
  - ALERT_EMAIL_SENDER      : Gmail address sending the alert
  - ALERT_EMAIL_PASSWORD    : Gmail App Password (not account password)
  - ALERT_EMAIL_RECIPIENT   : Analyst's email address
"""

import os
import smtplib
import logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText

logger = logging.getLogger(__name__)

# SMTP config — Gmail by default (changeable for other providers)
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

# Severity → colour mapping for HTML emails
SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH":     "#FF6600",
    "MEDIUM":   "#FFA500",
    "LOW":      "#FFD700",
}


class AlertEngine:

    def __init__(self):
        self.sender    = os.environ["ALERT_EMAIL_SENDER"]
        self.password  = os.environ["ALERT_EMAIL_PASSWORD"]
        self.recipient = os.environ["ALERT_EMAIL_RECIPIENT"]

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def send_finding(self, finding: dict):
        """Send a single risk finding alert."""
        finding_type = finding.get("type", "UNKNOWN")

        if finding_type == "AML_SMURFING_RING":
            subject = self._aml_subject(finding)
            body    = self._aml_html_body(finding)
        elif finding_type == "AML_STRUCTURING":
            subject = f"[{finding['severity']}] AML Structuring Detected | {finding['customer_name']}"
            body    = self._structuring_html_body(finding)
        elif finding_type == "PAYMENT_GATEWAY_GLITCH":
            subject = self._glitch_subject(finding)
            body    = self._glitch_html_body(finding)
        else:
            subject = f"[RISK ENGINE] Unknown Finding Type: {finding_type}"
            body    = f"<pre>{finding}</pre>"

        self._send(subject, body)

    def send_run_summary(self, aml_findings: list, glitch_findings: list,
                         impact_summary: dict, total_aml: int = 0,
                         total_glitch: int = 0, run_id: str = ""):
        """Send an end-of-run digest with top 50 of each + full report link."""
        total_aml    = total_aml    or len(aml_findings)
        total_glitch = total_glitch or len(glitch_findings)
        total        = total_aml + total_glitch
        subject = f"[RISK ENGINE] Scan Complete — {total} Finding(s) | {_now()}"
        body    = self._summary_html_body(
            aml_findings, glitch_findings, impact_summary,
            total_aml, total_glitch, run_id
        )
        self._send(subject, body)

    def send_clean_run(self):
        """Send a 'all clear' notification when no findings are detected."""
        subject = f"[RISK ENGINE] ✅ All Clear — No Anomalies Detected | {_now()}"
        body    = self._clean_run_html()
        self._send(subject, body)

    # ─────────────────────────────────────────────────────────────────────────
    # SMTP sender
    # ─────────────────────────────────────────────────────────────────────────

    def _send(self, subject: str, html_body: str):
        msg                  = MIMEMultipart("alternative")
        msg["Subject"]       = subject
        msg["From"]          = self.sender
        msg["To"]            = self.recipient
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.ehlo()
                server.starttls()
                server.login(self.sender, self.password)
                server.sendmail(self.sender, self.recipient, msg.as_string())
            logger.info("📧 Alert sent → %s | %s", self.recipient, subject)
        except smtplib.SMTPAuthenticationError:
            logger.error("❌ SMTP auth failed. Check ALERT_EMAIL_SENDER / ALERT_EMAIL_PASSWORD secrets.")
            raise
        except Exception as e:
            logger.error("❌ Failed to send alert: %s", e)
            raise

    # ─────────────────────────────────────────────────────────────────────────
    # Subject builders
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _aml_subject(f: dict) -> str:
        return (
            f"[{f['severity']}] 🚨 AML Smurfing Ring | "
            f"{f['hops']}-Hop | R{f['total_laundered_zar']:,.2f} | {f['customer_name']}"
        )

    @staticmethod
    def _glitch_subject(f: dict) -> str:
        return (
            f"[{f['severity']}] ⚡ Duplicate Charge | "
            f"{f['customer_name']} | R{f['overcharged_zar']:,.2f} at {f['merchant_name']}"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # HTML email builders
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _aml_html_body(f: dict) -> str:
        color  = SEVERITY_COLORS.get(f["severity"], "#999")
        amounts = ", ".join([f"R{a:,.2f}" for a in f.get("transaction_amounts", [])])
        return f"""
        <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px">
        <div style="max-width:620px;background:#fff;border-radius:8px;overflow:hidden;margin:auto">
          <div style="background:{color};padding:16px 20px">
            <h2 style="color:#fff;margin:0">🚨 AML ALERT: Smurfing Ring Detected</h2>
            <span style="color:#ffffffcc;font-size:13px">{_now()} — Financial Risk Engine</span>
          </div>
          <div style="padding:20px">
            {_row("Severity",          f"<strong style='color:{color}'>{f['severity']}</strong>")}
            {_row("Ring Account",       f['ring_account'])}
            {_row("Customer ID",        f['customer_id'])}
            {_row("Customer Name",      f['customer_name'])}
            {_row("Hops in Ring",       str(f['hops']))}
            {_row("Transaction Amounts", amounts)}
            {_row("Total Laundered",    f"<strong>R{f['total_laundered_zar']:,.2f}</strong>")}
            {_row("Transaction IDs",    "<br>".join(f['txn_ids']))}
          </div>
          <div style="background:#fffbea;border-top:3px solid {color};padding:14px 20px">
            <strong>Description:</strong><br>{f['description']}
          </div>
          <div style="background:#f9f9f9;padding:12px 20px;font-size:12px;color:#999;text-align:center">
            Financial Risk Engine | Automated AML Detection | South Africa FICA Compliance
          </div>
        </div></body></html>
        """

    @staticmethod
    def _structuring_html_body(f: dict) -> str:
        color = SEVERITY_COLORS.get(f["severity"], "#999")
        return f"""
        <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px">
        <div style="max-width:620px;background:#fff;border-radius:8px;overflow:hidden;margin:auto">
          <div style="background:{color};padding:16px 20px">
            <h2 style="color:#fff;margin:0">🚨 AML ALERT: Transaction Structuring</h2>
            <span style="color:#ffffffcc;font-size:13px">{_now()}</span>
          </div>
          <div style="padding:20px">
            {_row("Severity",             f"<strong style='color:{color}'>{f['severity']}</strong>")}
            {_row("Account ID",            f['account_id'])}
            {_row("Customer",              f['customer_name'])}
            {_row("Suspicious Txns (24h)", str(f['suspicious_txn_count']))}
            {_row("Total Structured",      f"<strong>R{f['total_structured_amount']:,.2f}</strong>")}
          </div>
          <div style="background:#fffbea;border-top:3px solid {color};padding:14px 20px">
            {f['description']}
          </div>
        </div></body></html>
        """

    @staticmethod
    def _glitch_html_body(f: dict) -> str:
        color = SEVERITY_COLORS.get(f["severity"], "#999")
        return f"""
        <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px">
        <div style="max-width:620px;background:#fff;border-radius:8px;overflow:hidden;margin:auto">
          <div style="background:{color};padding:16px 20px">
            <h2 style="color:#fff;margin:0">⚡ GLITCH ALERT: Duplicate Virtual Card Charge</h2>
            <span style="color:#ffffffcc;font-size:13px">{_now()} — FNB Virtual Card Gateway</span>
          </div>
          <div style="padding:20px">
            {_row("Severity",              f"<strong style='color:{color}'>{f['severity']}</strong>")}
            {_row("Customer",              f['customer_name'])}
            {_row("Customer ID",           f['customer_id'])}
            {_row("Account (Virtual Card)", f['account_id'])}
            {_row("Bank",                  f.get('bank','Unknown'))}
            {_row("Merchant",              f['merchant_name'])}
            {_row("Original Txn",          f['original_txn_id'])}
            {_row("Duplicate Txn",         f['duplicate_txn_id'])}
            {_row("Amount Charged",        f"R{f['charged_amount_zar']:,.2f}")}
            {_row("Total Debited",         f"<strong>R{f['total_debited_zar']:,.2f}</strong>")}
            {_row("Refund Required",       f"<strong style='color:#e53e3e'>R{f['overcharged_zar']:,.2f}</strong>")}
            {_row("Gap Between Charges",   f"{f['seconds_between_charges']}s")}
          </div>
          <div style="background:#fff5f5;border-top:3px solid {color};padding:14px 20px">
            <strong>Recommended Action:</strong> Initiate immediate refund of R{f['overcharged_zar']:,.2f} 
            and flag virtual card gateway for audit. Notify customer within 2 hours per FSCA guidelines.
          </div>
          <div style="background:#f9f9f9;padding:12px 20px;font-size:12px;color:#999;text-align:center">
            Financial Risk Engine | FNB/Takealot Glitch Replication | FSCA Incident Response
          </div>
        </div></body></html>
        """

    @staticmethod
    def _summary_html_body(aml: list, glitch: list, impact: dict,
                           total_aml: int = 0, total_glitch: int = 0,
                           run_id: str = "") -> str:
        total_aml    = total_aml    or len(aml)
        total_glitch = total_glitch or len(glitch)
        total = total_aml + total_glitch
        total_aml_amount    = sum(f.get("total_laundered_zar", f.get("total_structured_amount", 0)) for f in aml)
        total_glitch_amount = sum(f.get("overcharged_zar", 0) for f in glitch)

        # Build report download link
        repo = "TsoareloAdriaan11/Financial-Risk-Engine"
        report_link = f"https://github.com/{repo}/actions/runs/{run_id}/artifacts" if run_id else "#"

        aml_rows = ""
        for f in aml:
            sev_color = SEVERITY_COLORS.get(f["severity"], "#999")
            name = f.get("customer_name", f.get("account_id", "Unknown"))
            amount = f.get("total_laundered_zar", f.get("total_structured_amount", 0))
            hops = f.get("hops", len(f.get("txn_ids", [])))
            aml_rows += (
                f"<tr><td style='padding:6px 10px;border-bottom:1px solid #eee'>{name}</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>{hops} accounts</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>R{amount:,.2f}</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>"
                f"<span style='color:{sev_color}'>{f['severity']}</span></td></tr>"
            )
        if not aml_rows:
            aml_rows = "<tr><td colspan='4' style='padding:10px;color:#999'>None detected</td></tr>"

        glitch_rows = ""
        for f in glitch:
            sev_color = SEVERITY_COLORS.get(f["severity"], "#999")
            glitch_rows += (
                f"<tr><td style='padding:6px 10px;border-bottom:1px solid #eee'>{f['customer_name']}</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>{f['merchant_name']}</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>R{f['overcharged_zar']:,.2f}</td>"
                f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>"
                f"<span style='color:{sev_color}'>{f['severity']}</span></td></tr>"
            )
        if not glitch_rows:
            glitch_rows = "<tr><td colspan='4' style='padding:10px;color:#999'>None detected</td></tr>"

        return f"""
        <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px">
        <div style="max-width:700px;background:#fff;border-radius:8px;overflow:hidden;margin:auto">
          <div style="background:#1a202c;padding:16px 20px">
            <h2 style="color:#fff;margin:0">📊 Risk Engine Scan Summary</h2>
            <span style="color:#ffffffcc;font-size:13px">{_now()} — {total} total finding(s)</span>
          </div>
          <div style="padding:20px;display:flex;gap:16px">
            {_stat_card("AML Rings", str(total_aml), "#FC8181")}
            {_stat_card("Glitch Duplicates", str(total_glitch), "#F6AD55")}
            {_stat_card("AML Exposure", f"R{total_aml_amount:,.0f}", "#68D391")}
            {_stat_card("Glitch Refunds", f"R{total_glitch_amount:,.0f}", "#76E4F7")}
          </div>
          <div style="background:#ebf8ff;border-left:4px solid #2b6cb0;padding:16px 20px;margin:0 20px 20px">
            <strong style="color:#2b6cb0">📎 Full Anomaly Report Available</strong><br>
            <span style="font-size:13px;color:#4a5568">
              This email shows the top 50 AML and top 50 glitch findings.<br>
              The complete report with all {total} findings and Neo4j investigation links is attached as a downloadable artifact:<br><br>
              <a href="{report_link}" target="_blank"
                 style="background:#2b6cb0;color:#fff;padding:8px 16px;border-radius:4px;text-decoration:none;font-size:13px;display:inline-block">
                 Download Full Report (HTML)
              </a>
              <br><br>
              <span style="font-size:11px;color:#718096">
                GitHub Actions → Run #{run_id} → Artifacts → risk-report
              </span>
            </span>
          </div>
          <div style="padding:0 20px 20px">
            <h3>AML Findings (Showing top {len(aml)} of {total_aml} detected)</h3>
            <table width="100%" style="border-collapse:collapse;font-size:13px">
              <tr style="background:#f7fafc">
                <th style="padding:8px 10px;text-align:left">Customer</th>
                <th style="padding:8px 10px;text-align:left">Ring Size</th>
                <th style="padding:8px 10px;text-align:left">Amount</th>
                <th style="padding:8px 10px;text-align:left">Severity</th>
              </tr>
              {aml_rows}
            </table>
            <h3>Payment Glitch Findings (Showing top {len(glitch)} of {total_glitch} detected)</h3>
            <table width="100%" style="border-collapse:collapse;font-size:13px">
              <tr style="background:#f7fafc">
                <th style="padding:8px 10px;text-align:left">Customer</th>
                <th style="padding:8px 10px;text-align:left">Merchant</th>
                <th style="padding:8px 10px;text-align:left">Refund</th>
                <th style="padding:8px 10px;text-align:left">Severity</th>
              </tr>
              {glitch_rows}
            </table>
          </div>
        </div></body></html>
        """
    @staticmethod
    def _clean_run_html() -> str:
        return f"""
        <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:40px">
        <div style="max-width:500px;background:#fff;border-radius:8px;overflow:hidden;margin:auto;text-align:center;padding:40px">
          <div style="font-size:48px">✅</div>
          <h2 style="color:#38a169">All Clear</h2>
          <p style="color:#555">No AML rings, structuring patterns, or duplicate charges detected.</p>
          <p style="color:#aaa;font-size:12px">{_now()} — Financial Risk Engine</p>
        </div></body></html>
        """


# ─────────────────────────────────────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────────────────────────────────────

def _row(label: str, value: str) -> str:
    return (
        f"<div style='display:flex;justify-content:space-between;"
        f"padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:14px'>"
        f"<span style='color:#718096;min-width:160px'>{label}</span>"
        f"<span style='color:#1a202c;text-align:right'>{value}</span></div>"
    )

def _stat_card(label: str, value: str, color: str) -> str:
    return (
        f"<div style='flex:1;background:#f7fafc;border-radius:6px;"
        f"padding:16px;text-align:center;border-top:3px solid {color}'>"
        f"<div style='font-size:22px;font-weight:bold;color:#1a202c'>{value}</div>"
        f"<div style='font-size:12px;color:#718096;margin-top:4px'>{label}</div></div>"
    )

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S SAST")
