# 🔍 Autonomous Financial Risk & Anomaly Detection Engine 

**Author:** Tsoarelo Adriaan Rikhotso  
**Academic Profile:** BSc Mathematics & Information Systems | PGDip Data Science  
**Tech Stack:** Python, Neo4j AuraDB (Cloud), Cypher Query Language, GitHub Actions, Faker  

---

## 📖 Project Overview
Traditional relational databases (SQL) struggle to detect deep, multi-hop financial anomalies in real-time. This project is a fully autonomous, cloud-hosted Graph Database engine designed to simulate, detect, and alert on two distinct types of financial risk:

1. **Adversarial Fraud (AML):** Anti-Money Laundering syndicates executing closed-loop "smurfing" transactions.
2. **Systemic IT Failures:** Real-time payment gateway glitches resulting in duplicate consumer charges.

**Unified Economy Visualization:**
<img width="1420" height="665" alt="visualisation (1)" src="https://github.com/user-attachments/assets/32e59b95-402e-419b-a3e5-049e7b6df836" />


---

## ⚙️ Cloud Architecture & Automation
Unlike static local databases, this engine is deployed as a continuous cloud microservice.
* **Synthetic Data Generation:** Utilizes Python's `Faker` library to generate realistic Customer Identity (KYC) profiles.
* **Cloud Database:** Hosted on **Neo4j AuraDB** for real-time, remote querying.
* **Autonomous Execution:** Orchestrated via **GitHub Actions** (CI/CD) to automatically spin up a server, run the Python detection algorithms, and scan the network at scheduled intervals.
* **Live Email Alerting:** Integrates Python's `smtplib` to fire real-time email notifications to risk analysts the second a glitch or money-laundering ring is detected.

---

## 🌍 Commercial Context: The FNB & Takealot Glitch
To demonstrate commercial awareness, this model simulates a recent South African FinTech crisis. FNB customers experienced a technical processing error where virtual card payments on Takealot were duplicated. FNB confirmed the issue was isolated to their virtual card gateways.

This model mathematically replicates that scenario, injecting synthetic duplicate virtual card payments into a graph database and utilizing an automated detection algorithm to isolate affected accounts instantly.

---

## 🛠️ The Detection Algorithms

### 1. System Glitch & Duplicate Payment Detection
Identifies instances where the exact same account pays the same merchant the exact same amount multiple times within a tightly constrained 5-minute window.

```cypher
MATCH (u:Account)-[t1:PAID]->(m:Merchant)
MATCH (u)-[t2:PAID]->(m)
WHERE t1.amount = t2.amount 
  AND t1.tx_id <> t2.tx_id 
  AND t1.card_type = "Virtual"
  AND abs(t1.timestamp - t2.timestamp) < 300000 
RETURN u.id AS Victim_Account, u.first_name AS First_Name, u.last_name AS Last_Name, m.name AS Merchant, t1.amount AS Amount_Charged, count(t2) AS Total_Duplicates

2. AML Syndicate Detection (Smurfing Rings)
Uses Variable-Length Pathing to dynamically detect closed-loop money transfer rings between 3 and 10 hops long to bypass reporting thresholds.

Cypher
MATCH path = (a:Account)-[:TRANSFERRED_TO*3..10]->(a)
RETURN [node in nodes(path) | node.first_name + " " + node.last_name] AS Ring_Members, length(path) AS Hops

[neo4j_query_table_data_2026-3-11.csv](https://github.com/user-attachments/files/25896925/neo4j_query_table_data_2026-3-11.csv)
<img width="1347" height="498" alt="visualisation (2)" src="https://github.com/user-attachments/assets/378bbbd2-274b-4ae7-9366-6882b70e23e1" />

