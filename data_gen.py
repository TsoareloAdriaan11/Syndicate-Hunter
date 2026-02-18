#GOAL: GENERATE BANKING DATA WITH A HIDDEN MONEY LAUNDERING RING.
#TECH :PYTHON (PANDAS) FOR DATA MANIPULATION
#GRAPH THEORY (NODES = PEOPLE, EDGES = TRANSACTIONS) WAS USED
import pandas as pd
import random
from faker import Faker
from datetime import date

#INITIALIZING THE FAKE NAME GENERATOR
fake = Faker()
#1 GENERATING THE NODES "ACCOUNTS"
print("1. Generating 100 Bank Accounts...")

accounts = []
#CREATING IDs FROM 101 TO 200
for i in range(101,201):
    accounts.append({
        "client_id": i,
        "name": fake.name(),
        "risk_score": random.randint(10,30), #RANDOM LOW RISK SCORE
        "location": "Gauteng"
    })

#CONVERTING TO THE DATAFRAME(TABLE) AND SVAING IT
df_accounts = pd.DataFrame(accounts)
df_accounts.to_csv("accounts.csv", index = False)
print("-> Success! Saved 'accounts.csv' (The Nodes)")

#2 GENERATING THE EGDES "NORMAL TRANSACTIONS"
print("2. Generating 500 Legitimate Transactions...")

transactions = []

for _ in range(500):
    #PICK 2 RANDOM PEOPLE
    sender = random.choice(accounts)["client_id"]
    receiver = random.choice(accounts) ["client_id"]

    #RULE: YOU CANT SEND MONEY TO YOURSELF
    if sender != receiver:
        transactions.append({
            "from_id": sender,
            "to_id": receiver,
            "amount": round(random.uniform(50,2000),2), # RANDOM AMOUNTS R50 - R2000
            "type": "Legit",
            "date": fake.date_this_year()
               
        })
#3 NOW WE INJECT THE SYNDICATE (FRAUD)
#WE PICK 5 SPECIFIC IDs TO BE OUR CRIMINALS
#THEY WILL MOVE A LARGE SUM OF MONEY IN A PERFECT CIRCLE (LOOP)
#PATH: 105->110->115->120->125->105
print("3. Injecting the Hidden Fraud Ring...")

syndicate_members = [105, 110, 115, 120, 125]
large_amount = 50000.00 #R50,000.00

#LOOPING THROUGH THE MEMBERS AS ILLUSTRATED IN THE PATH
for i in range(len(syndicate_members)):
    sender = syndicate_members[i]
    #% ENSURES THE LAST PERSON SENDS BACK TO THE FIRST PERSON
    receiver = syndicate_members[(i+1) % len(syndicate_members)]

    #WE CHANGE THE AMOUNT SLIGHTLY SO IT LOOKS NATURAL TO SQL, e,g., R50,000->R49,500->R49,200
    cleaned_amount = large_amount - (random.uniform(0,500))

    today = date.today().isoformat()
    transactions.append({
        "from_id": sender,
        "to_id": receiver,
        "amount": round(cleaned_amount,2),
        "type": "Structuring", #MONEY LAUNDERING TERM
        "date": today
    })
#SAVING EVERYTHING
df_tx = pd.DataFrame(transactions)
df_tx.to_csv("transactions.csv", index=False)
print(f"-> Success! Saved 'transactions.csv' with {len(df_tx)} rows.")
print("-> The Hidden Ring is: 105 -> 110 -> 115 -> 120 -> 125 -> 105")
