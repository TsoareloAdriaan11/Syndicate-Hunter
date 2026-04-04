"""
alert_engine.py
Real-time email alerting via smtplib (Gmail SMTP).
"""

import os
import smtplib
import logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.mime.application import MIMEApplication

logger = logging.getLogger(__name__)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

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

    def send_finding(self, finding: dict):
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
                         total_glitch: int = 0, run_id: str = "", report_path: str = None):
        """Send an end-of-run digest with top 50 of each + attached full HTML report."""
        
        total_aml    = total_aml    or len(aml_findings)
        total_glitch = total_glitch or len(glitch_findings)
        total        = total_aml + total_glitch
        subject = f"[RISK ENGINE] Scan Complete — {total} Finding(s) | {_now()}"
        
        body    = self._summary_html_body(
            aml_findings, glitch_findings, impact_summary,
            total_aml, total_glitch, run_id
        )
        self._send(subject, body, attachment_path=report_path)

    def send_clean_run(self):
        subject = f"[RISK ENGINE] ✅ All Clear — No Anomalies Detected | {_now()}"
        body    = self._clean_run_html()
        self._send(subject, body)

    # ─────────────────────────────────────────────────────────────────────────
    # SMTP sender (Upgraded to handle direct HTML file attachments)
    # ─────────────────────────────────────────────────────────────────────────

    def _send(self, subject: str, html_body: str, attachment_path: str = None):
        msg                  = MIMEMultipart("alternative")
        msg["Subject"]       = subject
        msg["From"]          = self.sender
        msg["To"]            = self.recipient
        msg.attach(MIMEText(html_body, "html"))

        # Attach the HTML report file directly to the email
        if attachment_path and os.path.exists(attachment_path):
            filename = os.path.basename(attachment_path)
            with open(attachment_path, "rb") as f:
                part = MIMEApplication(f.read(), Name=filename)
            part['Content-Disposition'] = f'attachment; filename="{filename}"'
            msg.attach(part)

        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.ehlo()
                server.starttls()
                server.login(self.sender, self.password)
                server.sendmail(self.sender, self.recipient, msg.as_string())
            logger.info("📧 Alert sent → %s | %s", self.recipient, subject)
        except Exception as e:
            logger.error("❌ Failed to send alert: %s", e)
            raise

    # ─────────────────────────────────────────────────────────────────────────
    # HTML email builders
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _aml_subject(f: dict) -> str:
        return f"[{f['severity']}] 🚨 AML Smurfing Ring | {f['hops']}-Hop | R{f['total_laundered_zar']:,.2f} | {f['customer_name']}"

    @staticmethod
    def _glitch_subject(f: dict) -> str:
        return f"[{f['severity']}] ⚡ Duplicate Charge | {f['customer_name']} | R{f['overcharged_zar']:,.2f} at {f['merchant_name']}"

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
          </div>
          <div style="padding:20px">
            {_row("Account ID",            f['account_id'])}
            {_row("Total Structured",      f"<strong>R{f['total_structured_amount']:,.2f}</strong>")}
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
          </div>
          <div style="padding:20px">
            {_row("Customer",              f['customer_name'])}
            {_row("Merchant",              f['merchant_name'])}
            {_row("Refund Required",       f"<strong style='color:#e53e3e'>R{f['overcharged_zar']:,.2f}</strong>")}
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

        ring_rows = ""
        struct_rows = ""
        for f in aml:
            sev_color = SEVERITY_COLORS.get(f["severity"], "#999")
            name   = f.get("customer_name", f.get("account_id", "Unknown"))
            amount = f.get("total_laundered_zar", f.get("total_structured_amount", 0))
            row = (
                f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>"
                f"<span style='color:{sev_color}'>{f['severity']}</span></td></tr>"
            )
            if f.get("type") == "AML_SMURFING_RING":
                size = f"{f.get('hops', 0)} accounts"
                ring_rows += (
                    f"<tr><td style='padding:6px 10px;border-bottom:1px solid #eee'>{name}</td>"
                    f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>{size}</td>"
                    f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>R{amount:,.2f}</td>"
                    + row
                )
            else:
                size = f"{f.get('txn_count', 0)} txns"
                struct_rows += (
                    f"<tr><td style='padding:6px 10px;border-bottom:1px solid #eee'>{name}</td>"
                    f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>{size}</td>"
                    f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>R{amount:,.2f}</td>"
                    + row
                )
        if not ring_rows:
            ring_rows = "<tr><td colspan='4' style='padding:10px;color:#999'>None detected</td></tr>"
        if not struct_rows:
            struct_rows = "<tr><td colspan='4' style='padding:10px;color:#999'>None detected</td></tr>"

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
            <strong style="color:#2b6cb0">📎 Full HTML Dashboard Attached</strong><br>
            <span style="font-size:13px;color:#4a5568">
              The complete anomaly report containing all {total} findings and direct Neo4j investigation links 
              is attached to this email as an HTML file. Double-click the attachment below to view it in your browser.
            </span>
          </div>

          <div style="padding:0 20px 20px">
            <h3 style="margin-top:16px">🔴 Smurfing Rings (Showing top {len([f for f in aml if f.get('type')=='AML_SMURFING_RING'])} of {sum(1 for f in aml if f.get('type')=='AML_SMURFING_RING')} detected)</h3>
            <table width="100%" style="border-collapse:collapse;font-size:13px;margin-bottom:16px">
              <tr style="background:#f7fafc">
                <th style="padding:8px 10px;text-align:left">Customer</th>
                <th style="padding:8px 10px;text-align:left">Ring Size</th>
                <th style="padding:8px 10px;text-align:left">Amount</th>
                <th style="padding:8px 10px;text-align:left">Severity</th>
              </tr>
              {ring_rows}
            </table>
            <h3 style="margin-top:16px">🟡 Structuring Patterns (Showing top {len([f for f in aml if f.get('type')=='AML_STRUCTURING'])} detected)</h3>
            <table width="100%" style="border-collapse:collapse;font-size:13px;margin-bottom:16px">
              <tr style="background:#f7fafc">
                <th style="padding:8px 10px;text-align:left">Customer</th>
                <th style="padding:8px 10px;text-align:left">Txn Count</th>
                <th style="padding:8px 10px;text-align:left">Amount</th>
                <th style="padding:8px 10px;text-align:left">Severity</th>
              </tr>
              {struct_rows}
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

def _row(label: str, value: str) -> str:
    return f"<div style='display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:14px'><span style='color:#718096;min-width:160px'>{label}</span><span style='color:#1a202c;text-align:right'>{value}</span></div>"

def _stat_card(label: str, value: str, color: str) -> str:
    return f"<div style='flex:1;background:#f7fafc;border-radius:6px;padding:16px;text-align:center;border-top:3px solid {color}'><div style='font-size:22px;font-weight:bold;color:#1a202c'>{value}</div><div style='font-size:12px;color:#718096;margin-top:4px'>{label}</div></div>"

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S SAST")
