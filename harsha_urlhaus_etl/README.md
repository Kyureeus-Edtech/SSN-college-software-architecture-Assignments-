URLhaus ETL Connector
📌 Overview

This project implements an ETL (Extract → Transform → Load) pipeline that retrieves the most recent malicious URLs from the URLhaus API, transforms the data into a clean format, and loads it into a MongoDB collection.

Due to API restrictions, this implementation uses a local sample_data.json file for demonstration purposes. This ensures the pipeline can run without internet connectivity issues.

🌐 API Details

Endpoint: https://urlhaus.abuse.ch/api/

Method: POST

Payload:

{
    "query": "get_recent"
}


Response Format: JSON

Official Docs: https://urlhaus.abuse.ch/api/

📂 Project Structure
harsha_urlhaus_etl/
│── etl_connector.py      # Main ETL script (Extract, Transform, Load)
│── sample_data.json      # Sample API response for offline testing
│── requirements.txt      # Python dependencies
│── README.md             # Project documentation
│── .env.example          # Example environment variables file

⚙️ Setup Instructions
1️⃣ Clone the Repository and Switch to Your Branch
git clone https://github.com/Kyureeus-Edtech/SSN-college-software-architecture-Assignments-.git
cd SSN-college-software-architecture-Assignments-
git checkout harsha_3122225001703_urlhaus

2️⃣ Navigate to the Project Folder
cd harsha_urlhaus_etl

3️⃣ Create Virtual Environment and Install Dependencies
python -m venv .venv
.\.venv\Scripts\activate     # On Windows
pip install -r requirements.txt

4️⃣ Create .env File

Create a file named .env in this folder with:

MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=etl_database
MONGO_COLLECTION=urlhaus_raw


(Do NOT commit this file to Git.)

▶️ How to Run
python etl_connector.py


Expected Output (Example):

[*] Extracting data from local sample_data.json...
[*] Transforming data...
[DEBUG] Transformed 2 records.
[*] Loading data into MongoDB...
[+] Inserted 2 records into urlhaus_raw
[✓] ETL process completed successfully.

🛠 Technologies Used

Python 3.x

requests

pymongo

python-dotenv

MongoDB

✍️ Author

Name: Harsha
Roll Number: 3122225001703
Course: B.E. CSE, SSN College of Engineering