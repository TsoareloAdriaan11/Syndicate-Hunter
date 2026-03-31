"""
report_generator.py
Generates a full HTML anomaly report with all AML rings and duplicate charges.
Each finding includes a pre-built Cypher query link for Neo4j Browser investigation.
"""

import os
from datetime import datetime


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S SAST")


def _neo4j_link(cypher: str) -> str:
    """
    Builds a Neo4j Browser deep link that pre-fills the query editor.
    User clicks it, Neo4j Browser opens with the query ready to run.
    """
    import urllib.parse
    uri = os.environ.get("NEO4J_URI", "")
    encoded = urllib.parse.quote(cypher)
    # Neo4j Browser accepts a cmd parameter to pre-fill the editor
    return f"https://browser.neo4j.io/?dbms={uri}&cmd=edit&arg={encoded}"


def generate_report(aml_findings: list, glitch_findings: list,
                    impact_summary: dict, run_id: str = "") -> str:
    """
    Generates a full self-contained HTML report and saves it to disk.
    Returns the file path.
    """
    total_aml     = len(aml_findings)
    total_glitch  = len(glitch_findings)
    total         = total_aml + total_glitch
    aml_exposure  = sum(f.get("total_laundered_zar", f.get("total_structured_amount", 0)) for f in aml_findings)
    glitch_refunds = sum(f.get("overcharged_zar", 0) for f in glitch_findings)

    # ── AML rows ────────────────────────────────────────────────────────────
    aml_rows_html = ""
    for i, f in enumerate(aml_findings, 1):
        ring_id   = f.get("ring_id", "")
        acct      = f.get("ring_account", "")
        name      = f.get("customer_name", f.get("account_id", "Unknown"))
        hops      = f.get("hops", len(f.get("txn_ids", [])))
        amount    = f.get("total_laundered_zar", f.get("total_structured_amount", 0))
        severity  = f.get("severity", "MEDIUM")
        txn_ids   = f.get("txn_ids", [])
        ftype     = f.get("type", "")

        sev_color = {"CRITICAL": "#e53e3e", "HIGH": "#dd6b20",
                     "MEDIUM": "#d69e2e", "LOW": "#38a169"}.get(severity, "#718096")

        if ftype == "AML_SMURFING_RING":
            cypher = f"MATCH (t:Transaction) WHERE t.aml_ring = '{ring_id}' MATCH (a:Account)-[:SENT]->(t)-[:TO]->(b:Account) RETURN a, t, b LIMIT 100"
            type_label = "Smurfing Ring"
        else:
            cypher = f"MATCH (a:Account {{account_id: '{acct}'}})-[:SENT]->(t:Transaction) WHERE t.amount >= 1000 AND t.amount < 5000 RETURN a, t LIMIT 50"
            type_label = "Structuring"

        neo4j_url = _neo4j_link(cypher)
        txn_list  = "<br>".join(txn_ids[:5]) + ("..." if len(txn_ids) > 5 else "")

        aml_rows_html += f"""
        <tr>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;color:#718096;font-size:12px">{i}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0"><strong>{name}</strong></td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#4a5568">{type_label}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:11px;color:#2b6cb0">{ring_id or acct}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;text-align:center">{hops}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;font-weight:bold">R{amount:,.2f}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0">
                <span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold">{severity}</span>
            </td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:10px;color:#718096">{txn_list}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0">
                <a href="{neo4j_url}" target="_blank"
                   style="background:#2b6cb0;color:#fff;padding:4px 10px;border-radius:4px;text-decoration:none;font-size:11px;white-space:nowrap">
                   🔍 View in Neo4j
                </a>
            </td>
        </tr>"""

    # ── Glitch rows ──────────────────────────────────────────────────────────
    glitch_rows_html = ""
    for i, f in enumerate(glitch_findings, 1):
        name     = f.get("customer_name", "Unknown")
        cust_id  = f.get("customer_id", "")
        acct     = f.get("account_id", "")
        merchant = f.get("merchant_name", "Takealot")
        orig     = f.get("original_txn_id", "")
        dup      = f.get("duplicate_txn_id", "")
        amount   = f.get("overcharged_zar", 0)
        total    = f.get("total_debited_zar", 0)
        gap      = f.get("seconds_between_charges", 0)
        severity = f.get("severity", "HIGH")

        sev_color = {"CRITICAL": "#e53e3e", "HIGH": "#dd6b20",
                     "MEDIUM": "#d69e2e", "LOW": "#38a169"}.get(severity, "#718096")

        cypher    = f"MATCH (a:Account {{account_id: '{acct}'}})-[:SENT]->(t:Transaction)-[:TO]->(m:Merchant {{name: '{merchant}'}}) WHERE t.channel = 'virtual_card' RETURN a, t, m"
        neo4j_url = _neo4j_link(cypher)

        glitch_rows_html += f"""
        <tr>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;color:#718096;font-size:12px">{i}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0"><strong>{name}</strong></td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:11px;color:#718096">{acct}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0">{merchant}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:10px;color:#4a5568">{orig}<br><span style="color:#e53e3e">{dup}</span></td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;font-weight:bold;color:#e53e3e">R{amount:,.2f}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;color:#718096">{gap}s</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0">
                <span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold">{severity}</span>
            </td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0">
                <a href="{neo4j_url}" target="_blank"
                   style="background:#2b6cb0;color:#fff;padding:4px 10px;border-radius:4px;text-decoration:none;font-size:11px;white-space:nowrap">
                   🔍 View in Neo4j
                </a>
            </td>
        </tr>"""

    # ── Impact summary rows ──────────────────────────────────────────────────
    impact_rows = ""
    for merchant, data in impact_summary.items():
        impact_rows += f"""
        <tr>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0"><strong>{merchant}</strong></td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;text-align:center">{data['duplicate_events']}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0;font-weight:bold;color:#e53e3e">R{data['total_overcharged_zar']:,.2f}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0">R{data['min_charge_zar']:,.2f}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0">R{data['max_charge_zar']:,.2f}</td>
            <td style="padding:10px;border-bottom:1px solid #e2e8f0">R{data['avg_charge_zar']:,.2f}</td>
        </tr>"""

    # ── Full HTML ────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Financial Risk Engine — Full Anomaly Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: Arial, sans-serif; background: #f7fafc; color: #1a202c; }}
  .header {{ background: #1a202c; color: #fff; padding: 32px 40px; }}
  .header h1 {{ font-size: 28px; margin-bottom: 6px; }}
  .header p {{ color: #a0aec0; font-size: 14px; }}
  .stats {{ display: flex; gap: 16px; padding: 24px 40px; background: #fff; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; }}
  .stat {{ flex: 1; min-width: 150px; background: #f7fafc; border-radius: 8px; padding: 16px; text-align: center; border-top: 3px solid #2b6cb0; }}
  .stat .value {{ font-size: 28px; font-weight: bold; color: #1a202c; }}
  .stat .label {{ font-size: 12px; color: #718096; margin-top: 4px; }}
  .section {{ padding: 32px 40px; }}
  .section h2 {{ font-size: 20px; margin-bottom: 6px; color: #1a202c; padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; }}
  .section .subtitle {{ font-size: 13px; color: #718096; margin-bottom: 20px; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th {{ background: #2b6cb0; color: #fff; padding: 12px 10px; text-align: left; font-size: 12px; font-weight: bold; white-space: nowrap; }}
  tr:hover {{ background: #f7fafc; }}
  .footer {{ background: #1a202c; color: #718096; padding: 20px 40px; font-size: 12px; text-align: center; }}
</style>
</head>
<body>

<div class="header">
  <h1>🏦 Financial Risk Engine — Full Anomaly Report</h1>
  <p>Generated: {_now()} &nbsp;|&nbsp; Run ID: {run_id} &nbsp;|&nbsp; Neo4j AuraDB + GitHub Actions</p>
</div>

<div class="stats">
  <div class="stat"><div class="value">{total}</div><div class="label">Total Findings</div></div>
  <div class="stat"><div class="value">{total_aml}</div><div class="label">AML Findings</div></div>
  <div class="stat"><div class="value">{total_glitch}</div><div class="label">Glitch Duplicates</div></div>
  <div class="stat" style="border-top-color:#e53e3e"><div class="value" style="color:#e53e3e">R{aml_exposure:,.0f}</div><div class="label">AML Exposure</div></div>
  <div class="stat" style="border-top-color:#dd6b20"><div class="value" style="color:#dd6b20">R{glitch_refunds:,.0f}</div><div class="label">Refunds Due</div></div>
</div>

<!-- ── AML SECTION ── -->
<div class="section">
  <h2>🚨 AML Findings — All {total_aml} Anomalies</h2>
  <p class="subtitle">Smurfing rings and structuring patterns. Click "View in Neo4j" to open the graph for that specific ring.</p>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Customer</th>
        <th>Type</th>
        <th>Ring / Account ID</th>
        <th>Accounts</th>
        <th>Amount</th>
        <th>Severity</th>
        <th>Transaction IDs</th>
        <th>Investigate</th>
      </tr>
    </thead>
    <tbody>
      {aml_rows_html if aml_rows_html else "<tr><td colspan='9' style='padding:20px;text-align:center;color:#718096'>No AML findings</td></tr>"}
    </tbody>
  </table>
</div>

<!-- ── GLITCH IMPACT SUMMARY ── -->
<div class="section">
  <h2>📊 Glitch Impact Summary by Merchant</h2>
  <p class="subtitle">Total financial exposure per merchant from duplicate charges.</p>
  <table>
    <thead>
      <tr>
        <th>Merchant</th>
        <th>Duplicate Events</th>
        <th>Total Overcharged</th>
        <th>Min Charge</th>
        <th>Max Charge</th>
        <th>Avg Charge</th>
      </tr>
    </thead>
    <tbody>
      {impact_rows if impact_rows else "<tr><td colspan='6' style='padding:20px;text-align:center;color:#718096'>No data</td></tr>"}
    </tbody>
  </table>
</div>

<!-- ── GLITCH SECTION ── -->
<div class="section">
  <h2>⚡ Payment Glitch Findings — All {total_glitch} Duplicate Charges</h2>
  <p class="subtitle">FNB virtual card duplicate charges on Takealot. Click "View in Neo4j" to inspect the account's transaction graph.</p>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Customer</th>
        <th>Account</th>
        <th>Merchant</th>
        <th>Original / Duplicate Txn</th>
        <th>Refund Due</th>
        <th>Gap</th>
        <th>Severity</th>
        <th>Investigate</th>
      </tr>
    </thead>
    <tbody>
      {glitch_rows_html if glitch_rows_html else "<tr><td colspan='9' style='padding:20px;text-align:center;color:#718096'>No glitch findings</td></tr>"}
    </tbody>
  </table>
</div>

<div class="footer">
  Financial Risk Engine &nbsp;|&nbsp; Neo4j AuraDB &nbsp;|&nbsp; GitHub Actions &nbsp;|&nbsp;
  University of the Witwatersrand &nbsp;|&nbsp; Data Science Project
</div>

</body>
</html>"""

    # Save to disk
    filename = f"risk_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(os.path.dirname(__file__), filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath, filename
