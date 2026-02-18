# 🕵️ Syndicate Hunter: Graph-Based Anti-Money Laundering (AML)

![Neo4j](https://img.shields.io/badge/Neo4j-008CC1?style=for-the-badge&logo=neo4j&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Graph Theory](https://img.shields.io/badge/Graph_Theory-FF6C37?style=for-the-badge&logo=graph&logoColor=white)

### 🚀 Project Overview
Traditional SQL databases often struggle to detect circular money laundering schemes (e.g., A -> B -> C -> A) because they require expensive recursive joins. 

**Syndicate Hunter** is a Graph Analytics project that generates synthetic banking data, injects a hidden fraud ring, and uses **Neo4j** to mathematically detect these "closed loops" often associated with **smurfing** and **structuring** (placement stage of money laundering).

---

### 🛠️ Tech Stack & Methodology

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Data Generation** | Python (`pandas`, `faker`) | Created 1,000+ realistic banking transactions and injected a specific 5-node fraud ring. |
| **Database** | Neo4j (Graph DB) | Modeled accounts as **Nodes** (`(:Client)`) and transactions as **Relationships** (`[:SENT_MONEY]`). |
| **Analysis** | Cypher Query Language (CQL) | Wrote pattern-matching algorithms with the help of LLMs to detect cycles of length 5 with amounts > R40,000. |

---

### 📊 The Analysis (Cypher Query)

The core logic relies on finding a specific path pattern where money returns to the originator:

```cypher
// Find closed loops of 5 hops where high-value funds are moved
MATCH path = (a)-[r1]->(b)-[r2]->(c)-[r3]->(d)-[r4]->(e)-[r5]->(a)
WHERE r1.amount > 40000 
  AND r2.amount > 40000
  AND r3.amount > 40000
  AND r4.amount > 40000
  AND r5.amount > 40000
RETURN path
