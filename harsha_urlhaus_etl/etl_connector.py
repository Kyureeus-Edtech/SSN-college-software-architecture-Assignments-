import os
import json
from datetime import datetime
from dotenv import load_dotenv  # type: ignore
from pymongo import MongoClient  # type: ignore

# Load environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("MONGO_DB_NAME", "etl_database")
COLLECTION_NAME = os.getenv("MONGO_COLLECTION", "urlhaus_raw")

# Path to local JSON file (offline data)
SAMPLE_JSON_FILE = "sample_data.json"

def extract():
    """
    Load recent URL data from local JSON file (offline mode).
    """
    print("[*] Extracting data from local sample_data.json...")
    if not os.path.exists(SAMPLE_JSON_FILE):
        raise FileNotFoundError(f"{SAMPLE_JSON_FILE} not found in current directory.")
    with open(SAMPLE_JSON_FILE, "r") as f:
        return json.load(f)

def transform(data):
    """
    Transform raw API response into MongoDB-compatible documents.
    """
    print("[*] Transforming data...")
    transformed = []

    # Handle both 'urls' at root or inside 'data'
    urls_data = data.get("urls") or data.get("data", {}).get("urls", [])

    for item in urls_data:
        transformed.append({
            "url_id": item.get("id"),
            "url": item.get("url"),
            "threat": item.get("threat"),
            "status": item.get("url_status"),
            "date_added": item.get("date_added"),
            "tags": item.get("tags"),
            "ingested_at": datetime.utcnow()
        })

    print(f"[DEBUG] Transformed {len(transformed)} records.")
    return transformed

def load(data):
    """
    Insert transformed data into MongoDB.
    """
    print("[*] Loading data into MongoDB...")
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    if data:
        collection.insert_many(data)
        print(f"[+] Inserted {len(data)} records into {COLLECTION_NAME}")
    else:
        print("[!] No data to insert")

if __name__ == "__main__":
    try:
        raw_data = extract()
        clean_data = transform(raw_data)
        load(clean_data)
        print("[✓] ETL process completed successfully.")
    except Exception as e:
        print("[ERROR]", e)
