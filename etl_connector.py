import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv
from pymongo import MongoClient
from pathlib import Path

load_dotenv()  # Load .env file

API_URL = os.getenv("API_URL")
API_KEY = os.getenv("API_KEY")
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")
LOAD_DIR = Path("load")
LOAD_DIR.mkdir(exist_ok=True)

def ingestion_layer():
    """Fetch data from API and store raw JSON in load directory."""
    headers = {"Auth-Key": API_KEY}
    response = requests.get(API_URL, headers=headers)
    response.raise_for_status()
    
    data = response.json()
    file_path = LOAD_DIR / f"urls_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    print(f"[Ingestion] Data saved to {file_path}")
    return data

def raw_layer(data):
    """Extract only 'urls' part from the response."""
    return data.get("urls", [])

def staging_layer(urls):
    """Transform data: flatten, convert dates, booleans, lowercase tags, normalize URLs."""
    transformed = []
    for item in urls:
        # Flatten blacklists
        for k, v in item.get("blacklists", {}).items():
            item[f"blacklist_{k}"] = v
        item.pop("blacklists", None)

        # Convert date strings to datetime
        if "date_added" in item:
            try:
                item["date_added"] = datetime.strptime(item["date_added"], "%Y-%m-%d %H:%M:%S %Z")
            except ValueError:
                pass  # keep original if format unexpected

        # Convert "true"/"false" strings to boolean
        for k, v in item.items():
            if isinstance(v, str) and v.lower() in ["true", "false"]:
                item[k] = v.lower() == "true"

        # Lowercase tags
        if "tags" in item and isinstance(item["tags"], list):
            item["tags"] = [tag.lower() for tag in item["tags"]]

        # Normalize URL casing (host part lowercase)
        if "url" in item:
            try:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(item["url"])
                item["url"] = urlunparse(parsed._replace(netloc=parsed.netloc.lower()))
            except:
                pass

        transformed.append(item)

    return transformed

def load_layer(data):
    """Store final transformed data into MongoDB."""
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    if data:
        collection.insert_many(data)
        print(f"[Load] Inserted {len(data)} records into MongoDB")
    else:
        print("[Load] No data to insert")

# MAIN PIPELINE

def main():
    raw_data = ingestion_layer()
    urls_data = raw_layer(raw_data)
    staged_data = staging_layer(urls_data)
    load_layer(staged_data)

if __name__ == "__main__":
    main()


