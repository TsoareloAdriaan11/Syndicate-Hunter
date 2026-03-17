# 🏦 Financial Risk Engine
### Autonomous Graph-Based AML & Payment Glitch Detection | Neo4j AuraDB + GitHub Actions

---

## Overview

Traditional relational databases struggle to detect **multi-hop financial anomalies** in real time. This engine solves that by modelling financial networks as a **property graph** and running Cypher traversal algorithms to expose hidden risk patterns invisible to SQL.

It autonomously detects two distinct threat types:

| Threat | Type | Pattern |
|--------|------|---------|
| **Smurfing / AML** | Anti-Money Laundering | Closed-loop circular transfers between accounts |
| **FNB/Takealot Glitch** | Systemic IT Failure | Duplicate virtual card charges within a 60s window |

---

## Architecture

```
GitHub Actions (Cron / Manual)
        │
        ▼
  main.py (Orchestrator)
   ├── data_generator.py  →  Faker KYC + Graph Injection → Neo4j AuraDB
   ├── aml_detector.py    →  Cypher ring traversal (2–5 hops)
   ├── glitch_detector.py →  Duplicate charge detection (virtual cards)
   └── alert_engine.py    →  smtplib HTML email alerts → Analyst inbox
```

**Graph Model:**
```
(Customer)-[:OWNS]->(Account)-[:SENT]->(Transaction)-[:TO]->(Account | Merchant)
```

---

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/financial-risk-engine.git
cd financial-risk-engine
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure GitHub Actions Secrets

Go to **Settings → Secrets and variables → Actions** and add:

| Secret | Description | Example |
|--------|-------------|---------|
| `NEO4J_URI` | AuraDB connection URI | `neo4j+s://abc123.databases.neo4j.io` |
| `NEO4J_USERNAME` | AuraDB username | `neo4j` |
| `NEO4J_PASSWORD` | AuraDB password | `your-aura-password` |
| `ALERT_EMAIL_SENDER` | Gmail sender address | `riskengine@gmail.com` |
| `ALERT_EMAIL_PASSWORD` | Gmail **App Password** (not account password) | `xxxx xxxx xxxx xxxx` |
| `ALERT_EMAIL_RECIPIENT` | Analyst email | `analyst@company.co.za` |

> **Gmail App Password:** Go to Google Account → Security → 2-Step Verification → App Passwords → Generate one for "Mail".

### 4. Run manually (local dev)
```bash
# Create a .env file for local testing (never commit this)
cp .env.example .env
# Fill in your secrets in .env, then:
cd src
python main.py
```

---

## Detection Algorithms

### AML: Smurfing Ring Detection
```cypher
MATCH path = (start:Account)-[:SENT*2..5]->(:Transaction)-[:TO]->(start)
WHERE ALL(t IN [n IN nodes(path) WHERE n:Transaction] WHERE t.amount < 5000)
RETURN start.account_id, count(path), sum(...)
```
- Detects **closed-loop circular flows** of 2–5 hops
- Flags transactions under the **R5,000 FICA reporting threshold**
- Matches the typology used by SA AML syndicates ("smurfing")

### AML: Structuring Detection
- Flags accounts with **>5 sub-R5,000 transactions within 24 hours**
- Complements ring detection to catch solo structuring (no ring needed)

### Glitch: Duplicate Charge Detection
```cypher
MATCH (a:Account {account_type: 'virtual'})-[:SENT]->(t1)-[:TO]->(m),
      (a)-[:SENT]->(t2)-[:TO]->(m)
WHERE abs(t1.amount - t2.amount) < 0.01
  AND abs(t1.timestamp - t2.timestamp) <= 60
```
- Replicates the **FNB/Takealot virtual card processing error**
- Detects same-account, same-merchant, same-amount charges within 60 seconds
- Calculates exact refund amounts for each affected customer

---

## Commercial Context: FNB/Takealot Glitch

This engine mathematically replicates a real South African FinTech incident where FNB customers were double-charged for Takealot purchases via the virtual card gateway. FNB confirmed the issue was isolated to their virtual card processing pipeline.

This model:
1. Injects 10 synthetic affected customers with virtual card accounts
2. Creates legitimate + duplicate transaction pairs per customer
3. Runs the detection Cypher query to isolate all affected accounts in milliseconds
4. Fires individual refund alerts per customer to the analyst inbox

---

## Alert Samples

**AML Alert subject:**
```
[HIGH] 🚨 AML Smurfing Ring | 3-Hop | R12,450.00 | John Doe
```

**Glitch Alert subject:**
```
[CRITICAL] ⚡ Duplicate Charge | Jane Smith | R2,999.00 at Takealot
```

**End-of-run digest** includes a full summary table of all findings with severity colour coding.

---

## Schedule

The engine runs automatically every **6 hours** via GitHub Actions cron:
```
0 */6 * * *   →   00:00, 06:00, 12:00, 18:00 UTC
```

To trigger manually: **Actions tab → Financial Risk Engine → Run workflow**

---

## Project Structure

```
financial-risk-engine/
├── .github/
│   └── workflows/
│       └── risk_engine.yml       # GitHub Actions CI/CD
├── src/
│   ├── main.py                   # Orchestrator
│   ├── db_connection.py          # Neo4j AuraDB connection
│   ├── data_generator.py         # Faker KYC + graph injection
│   ├── aml_detector.py           # AML ring + structuring detection
│   ├── glitch_detector.py        # Duplicate charge detection
│   └── alert_engine.py           # smtplib HTML email alerts
├── requirements.txt
└── README.md
```

---

*Built for demonstrating commercial awareness of South African FinTech risk scenarios — FICA compliance, FSCA incident response, and real-time graph-based anomaly detection.*
