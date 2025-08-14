import os
import logging
import time
from datetime import datetime, timezone
import requests
from pymongo import MongoClient, errors
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB", "etl_database")
COLLECTION_NAME = "spamhaus_raw"
SPAMHAUS_URL = "https://www.spamhaus.org/drop/drop.txt"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

def utcnow_iso():
    return datetime.now(timezone.utc).isoformat()

def http_get_with_retry(url, max_retries=5):
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.text
            logging.warning(f"Status {resp.status_code}, retrying...")
        except requests.RequestException as e:
            logging.warning(f"Error: {e}, retrying...")
        time.sleep(2 ** attempt)
    raise RuntimeError("Failed to fetch data after retries.")

def parse_drop_list(txt):
    indicators = []
    for line in txt.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            indicators.append(line.split(";")[0].strip())
    return indicators

def get_collection():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB][COLLECTION_NAME]

def extract():
    logging.info(f"Fetching {SPAMHAUS_URL}")
    return http_get_with_retry(SPAMHAUS_URL)

def transform(raw_txt):
    indicators = parse_drop_list(raw_txt)
    now = utcnow_iso()
    return [{"source": "spamhaus_drop", "indicator": i, "_ingested_at": now} for i in indicators]

def load(docs):
    col = get_collection()
    try:
        col.create_index("indicator", unique=True)
    except errors.PyMongoError as e:
        logging.warning(f"Index error: {e}")
    try:
        res = col.insert_many(docs, ordered=False)
        logging.info(f"Inserted {len(res.inserted_ids)} new docs.")
    except errors.BulkWriteError as bwe:
        inserted = bwe.details.get("nInserted", 0)
        logging.info(f"Inserted {inserted}, skipped duplicates.")

def main():
    raw_txt = extract()
    docs = transform(raw_txt)
    load(docs)

if __name__ == "__main__":
    main()
