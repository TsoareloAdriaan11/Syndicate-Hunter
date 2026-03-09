# 🔍 Financial Risk & Anomaly Detection Engine (Neo4j & Python)

**Author:** Tsoarelo Adriaan Rikhotso | BSc Mathematics & Information Systems, PGDip Data Science  
**Tech Stack:** Python, Neo4j (Graph Database), Cypher Query Language

## 📖 Project Overview
Traditional relational databases (SQL) struggle to detect deep, multi-hop financial anomalies in real-time. This project is a custom-built Graph Database engine designed to simulate and detect two distinct types of financial risk:
1. **Adversarial Fraud:** Anti-Money Laundering (AML) syndicates executing closed-loop "smurfing" transactions.
2. **Systemic IT Failures:** Real-time payment gateway glitches resulting in duplicate charges. 

## 🌍 Real-World Application: The FNB & Takealot Glitch
This model was expanded to simulate a real-world FinTech crisis. On March 4, 2026, FNB customers experienced a technical processing error where virtual card payments on Takealot were duplicated, resulting in customers being charged two or three times for a single purchase. FNB confirmed the issue was specifically limited to their virtual cards. 

This project mathematically models that exact scenario, injecting synthetic duplicate virtual card payments into a graph database and using an automated detection algorithm to isolate the affected accounts instantly.

## 🛠️ The Detection Algorithms

### 1. System Glitch & Duplicate Payment Detection
This Cypher algorithm identifies instances where the exact same account pays the same merchant the exact same amount multiple times within a 5-minute window, specifically flagging Virtual Card transactions. 

```cypher
MATCH (u:Account)-[t1:PAID]->(m:Merchant)
MATCH (u)-[t2:PAID]->(m)
WHERE t1.amount = t2.amount 
  AND t1.tx_id <> t2.tx_id 
  AND t1.card_type = "Virtual"
  AND abs(t1.timestamp - t2.timestamp) < 300000 
RETURN u.id AS Victim_Account, m.name AS Merchant, t1.amount AS Amount_Charged, count(t2) AS Total_Duplicates
<img width="900" height="465" alt="visualisation (3)" src="https://github.com/user-attachments/assets/8277180e-0148-4d6f-a5d8-edfb356d1a85" />
<img width="827" height="498" alt="visualisation (4)" src="https://github.com/user-attachments/assets/671f0711-801f-4119-b9c5-af1698827f13" />
<img width="900" height="465" alt="visualisation" src="https://github.com/user-attachments/assets/19787811-8a28-4513-a3e4-e2f7183c874a" />

2. AML Syndicate Detection (Smurfing Rings)
Money launderers often use "smurfs" to move money in a circular topology to bypass the R25,000 reporting threshold. This algorithm uses Variable-Length Pathing to dynamically detect any closed-loop money transfer ring between 3 and 10 hops long.

Cypher
MATCH path = (a:Account)-[:TRANSFERRED_TO*3..10]->(a)
RETURN [node in nodes(path) | node.id] AS Ring, length(path) AS Hops
Algorithmic Output & Visual Proof: (Drag and drop your Neo4j Smurfing Ring graph screenshot here) ---

⚙️ How to Run the Engine
Clone the repository and install dependencies: pip install neo4j

Ensure you have a local Neo4j Desktop instance running or connect to Neo4j AuraDB.

Update the URI and PASSWORD credentials in financial_risk_engine.py.

Run the data generator to populate the graph: python financial_risk_engine.py

Open your Neo4j browser and execute the Cypher queries above to catch the anomalies.

🤖 Acknowledgments
AI/LLM Assistance: Large Language Models (LLMs) were utilized during the development phase to assist in the syntactic formatting and optimization of the advanced Cypher graph queries, ensuring high-performance traversal logic and accurate algorithmic execution.
