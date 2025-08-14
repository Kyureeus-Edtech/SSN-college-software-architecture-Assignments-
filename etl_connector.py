#!/usr/bin/env python3
"""
Custom ETL Data Connector for ThreatFox JSON Feed
File: etl_connector.py
Author: [Your Name] - [Your Roll Number]
Description: ETL pipeline to extract threat intelligence data from ThreatFox JSON feed,
             transform it for MongoDB compatibility, and load into MongoDB collection.
Data Source: Entry #10 from provided connector list - ThreatFox JSON
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import requests
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, BulkWriteError
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('etl_connector.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ThreatFoxETLConnector:
    """
    ETL Connector class for extracting threat intelligence data from ThreatFox JSON feed
    and loading it into MongoDB - Based on Entry #10 from connector requirements
    """
    
    def _init_(self):
        """Initialize the ETL connector with configuration"""
        # Load environment variables
        load_dotenv()
        
        # API Configuration (ThreatFox JSON - Entry #10 from connector list)
        self.base_url = os.getenv('API_BASE_URL', 'https://threatfox.abuse.ch')
        self.endpoint = os.getenv('API_ENDPOINT', '/export/json/threatfox_abuse_ch.json')
        self.rate_limit_delay = float(os.getenv('RATE_LIMIT_DELAY', '3.0'))  # Conservative rate limiting
        
        # MongoDB Configuration
        self.mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
        self.database_name = os.getenv('MONGO_DATABASE', 'etl_database')
        self.collection_name = os.getenv('MONGO_COLLECTION', 'threatfox_raw')
        
        # Initialize MongoDB client
        self.mongo_client = None
        self.database = None
        self.collection = None
        
        # Request session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ETL-Connector/1.0 (Educational Purpose)',
            'Accept': 'application/json'
        })
    
    def connect_to_mongodb(self) -> bool:
        """
        Establish connection to MongoDB
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.mongo_client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
            # Test the connection
            self.mongo_client.admin.command('ping')
            self.database = self.mongo_client[self.database_name]
            self.collection = self.database[self.collection_name]
            logger.info(f"Successfully connected to MongoDB: {self.database_name}.{self.collection_name}")
            return True
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            return False
    
    def extract_data(self) -> List[Dict[str, Any]]:
        """
        Extract threat intelligence data from ThreatFox JSON feed (Entry #10 from connector list)
        
        Returns:
            List[Dict]: Extracted threat data or empty list on failure
        """
        try:
            # Build full URL from connector list specification
            url = f"{self.base_url}{self.endpoint}"
            
            logger.info(f"Extracting threat intelligence data from: {url}")
            
            response = self.session.get(url, timeout=60)  # Longer timeout for large JSON file
            
            # Handle rate limiting
            if response.status_code == 429:
                logger.warning("Rate limit hit, waiting...")
                time.sleep(self.rate_limit_delay * 2)
                response = self.session.get(url, timeout=60)
            
            response.raise_for_status()
            
            # ThreatFox returns a large JSON array directly
            threats = response.json()
            
            logger.info(f"Successfully extracted {len(threats)} threat intelligence records")
            
            # Add extraction metadata to each threat
            extraction_timestamp = datetime.now(timezone.utc).isoformat()
            for threat in threats:
                threat['extraction_metadata'] = {
                    'extracted_at': extraction_timestamp,
                    'source_url': url,
                    'total_records_in_batch': len(threats)
                }
            
            return threats
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON response: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during extraction: {e}")
            return []
    
    def transform_data(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Transform raw ThreatFox data for MongoDB compatibility
        
        Args:
            raw_data (List[Dict]): Raw threat data from ThreatFox API
            
        Returns:
            List[Dict]: Transformed data
        """
        transformed_data = []
        current_timestamp = datetime.now(timezone.utc)
        
        for threat_record in raw_data:
            try:
                # Extract threat details
                threat_id = threat_record.get('id', 'unknown')
                ioc_id = threat_record.get('ioc_id', 'unknown')
                ioc_value = threat_record.get('ioc_value', '')
                ioc_type = threat_record.get('ioc_type', '')
                threat_type = threat_record.get('threat_type', '')
                malware = threat_record.get('malware', '')
                malware_alias = threat_record.get('malware_alias', '')
                malware_printable = threat_record.get('malware_printable', '')
                first_seen = threat_record.get('first_seen', '')
                last_seen = threat_record.get('last_seen', '')
                confidence_level = threat_record.get('confidence_level', 0)
                reference = threat_record.get('reference', '')
                reporter = threat_record.get('reporter', '')
                tags = threat_record.get('tags', [])
                
                # Parse dates
                first_seen_parsed = self._parse_threatfox_date(first_seen)
                last_seen_parsed = self._parse_threatfox_date(last_seen)
                
                # Calculate derived fields
                is_recent = self._is_recent_threat(first_seen_parsed)
                is_active = self._is_active_threat(last_seen_parsed)
                threat_severity = self._calculate_threat_severity(confidence_level, threat_type, malware)
                ioc_category = self._categorize_ioc_type(ioc_type)
                
                # Create transformed record
                transformed_record = {
                    # Original data
                    'original_data': threat_record,
                    
                    # ETL metadata
                    'etl_metadata': {
                        'ingestion_timestamp': current_timestamp,
                        'source': 'threatfox_json',
                        'version': '1.0',
                        'record_id': threat_id,
                        'data_quality_score': self._calculate_threat_quality(threat_record)
                    },
                    
                    # Flatten and clean important fields
                    'threat_id': threat_id,
                    'ioc_id': ioc_id,
                    'ioc_value': ioc_value.strip(),
                    'ioc_type': ioc_type.strip(),
                    'threat_type': threat_type.strip(),
                    'malware': malware.strip(),
                    'malware_alias': malware_alias.strip(),
                    'malware_printable': malware_printable.strip(),
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'first_seen_parsed': first_seen_parsed,
                    'last_seen_parsed': last_seen_parsed,
                    'confidence_level': confidence_level,
                    'reference': reference.strip(),
                    'reporter': reporter.strip(),
                    'tags': tags if isinstance(tags, list) else [],
                    
                    # Derived fields
                    'is_recent_threat': is_recent,
                    'is_active_threat': is_active,
                    'threat_severity': threat_severity,
                    'ioc_category': ioc_category,
                    'tag_count': len(tags) if isinstance(tags, list) else 0,
                    'has_reference': bool(reference.strip()),
                    'malware_family_clean': self._clean_malware_name(malware_printable or malware),
                    'days_since_first_seen': self._days_since_date(first_seen_parsed),
                    'days_since_last_seen': self._days_since_date(last_seen_parsed),
                    'threat_age_category': self._categorize_threat_age(first_seen_parsed),
                    
                    # Extraction metadata
                    'extraction_timestamp': threat_record.get('extraction_metadata', {}).get('extracted_at'),
                    'source_url': threat_record.get('extraction_metadata', {}).get('source_url'),
                    'batch_size': threat_record.get('extraction_metadata', {}).get('total_records_in_batch')
                }
                
                transformed_data.append(transformed_record)
                
            except Exception as e:
                logger.warning(f"Failed to transform threat record {threat_record}: {e}")
                continue
        
        logger.info(f"Successfully transformed {len(transformed_data)} threat records")
        return transformed_data
    
    def _calculate_threat_quality(self, threat: Dict[str, Any]) -> float:
        """
        Calculate a simple data quality score for threat record (0-1)
        
        Args:
            threat (Dict): Threat data
            
        Returns:
            float: Quality score
        """
        score = 0.0
        total_checks = 7
        
        # Check for required fields
        if threat.get('id'):
            score += 1/total_checks
        if threat.get('ioc_value'):
            score += 1/total_checks
        if threat.get('ioc_type'):
            score += 1/total_checks
        if threat.get('threat_type'):
            score += 1/total_checks
        if threat.get('malware'):
            score += 1/total_checks
        if threat.get('first_seen'):
            score += 1/total_checks
        if threat.get('confidence_level', 0) > 0:
            score += 1/total_checks
        
        return round(score, 2)
    
    def _parse_threatfox_date(self, date_str: str) -> Optional[datetime]:
        """Parse ThreatFox date string to datetime object"""
        if not date_str:
            return None
        try:
            # ThreatFox uses format: "2024-01-15 12:30:45"
            return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                # Alternative format: "2024-01-15"
                return datetime.strptime(date_str, '%Y-%m-%d')
            except ValueError:
                return None
    
    def _is_recent_threat(self, first_seen: Optional[datetime]) -> bool:
        """Check if threat was first seen recently (within last 30 days)"""
        if not first_seen:
            return False
        cutoff = datetime.now() - timedelta(days=30)
        return first_seen > cutoff
    
    def _is_active_threat(self, last_seen: Optional[datetime]) -> bool:
        """Check if threat was seen recently (within last 7 days)"""
        if not last_seen:
            return False
        cutoff = datetime.now() - timedelta(days=7)
        return last_seen > cutoff
    
    def _calculate_threat_severity(self, confidence: int, threat_type: str, malware: str) -> str:
        """Calculate threat severity based on various factors"""
        if confidence >= 75:
            return 'HIGH'
        elif confidence >= 50:
            if any(keyword in threat_type.lower() for keyword in ['botnet', 'ransomware', 'trojan']):
                return 'HIGH'
            return 'MEDIUM'
        elif confidence >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _categorize_ioc_type(self, ioc_type: str) -> str:
        """Categorize IOC type into broader categories"""
        ioc_lower = ioc_type.lower()
        if 'domain' in ioc_lower or 'url' in ioc_lower:
            return 'NETWORK'
        elif 'ip' in ioc_lower:
            return 'NETWORK'
        elif 'hash' in ioc_lower or 'md5' in ioc_lower or 'sha' in ioc_lower:
            return 'FILE'
        elif 'email' in ioc_lower:
            return 'EMAIL'
        else:
            return 'OTHER'
    
    def _clean_malware_name(self, malware_name: str) -> str:
        """Clean and standardize malware name"""
        if not malware_name:
            return 'Unknown'
        # Remove common prefixes and clean up
        cleaned = malware_name.strip().replace('win32:', '').replace('trojan:', '')
        return cleaned.title() if cleaned else 'Unknown'
    
    def _days_since_date(self, date_obj: Optional[datetime]) -> Optional[int]:
        """Calculate days since a given date"""
        if not date_obj:
            return None
        return (datetime.now() - date_obj).days
    
    def _categorize_threat_age(self, first_seen: Optional[datetime]) -> str:
        """Categorize threat based on age"""
        if not first_seen:
            return 'Unknown'
        days_old = (datetime.now() - first_seen).days
        if days_old <= 7:
            return 'New'
        elif days_old <= 30:
            return 'Recent'
        elif days_old <= 90:
            return 'Moderate'
        else:
            return 'Old'
    
    def load_data(self, transformed_data: List[Dict[str, Any]]) -> bool:
        """
        Load transformed ThreatFox data into MongoDB
        
        Args:
            transformed_data (List[Dict]): Transformed data to load
            
        Returns:
            bool: True if load successful, False otherwise
        """
        if not transformed_data:
            logger.warning("No data to load")
            return True
        
        try:
            # Create indexes for better query performance
            self.collection.create_index("etl_metadata.ingestion_timestamp")
            self.collection.create_index("threat_id", unique=True)
            self.collection.create_index("ioc_type")
            self.collection.create_index("threat_severity")
            self.collection.create_index("malware_family_clean")
            self.collection.create_index("is_active_threat")
            self.collection.create_index("first_seen_parsed")
            
            # Use direct insert/update operations
            inserted_count = 0
            updated_count = 0
            
            for record in transformed_data:
                try:
                    # Try to update existing record, insert if not found
                    result = self.collection.replace_one(
                        {'threat_id': record['threat_id']},
                        record,
                        upsert=True
                    )
                    
                    if result.upserted_id:
                        inserted_count += 1
                    elif result.modified_count > 0:
                        updated_count += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to process threat {record.get('threat_id', 'unknown')}: {e}")
                    continue
            
            logger.info(f"Data load completed: {inserted_count} inserted, {updated_count} updated")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load data: {e}")
            return False
    
    def run_etl_pipeline(self) -> bool:
        """
        Execute the complete ETL pipeline for ThreatFox data
        
        Returns:
            bool: True if pipeline completed successfully
        """
        logger.info("Starting ThreatFox ETL pipeline execution")
        start_time = time.time()
        
        try:
            # Step 1: Connect to MongoDB
            if not self.connect_to_mongodb():
                return False
            
            # Step 2: Extract data from ThreatFox JSON feed
            raw_data = self.extract_data()
            if not raw_data:
                logger.error("No data extracted, stopping pipeline")
                return False
            
            # Step 3: Transform data
            transformed_data = self.transform_data(raw_data)
            if not transformed_data:
                logger.error("No data transformed, stopping pipeline")
                return False
            
            # Step 4: Load data
            if not self.load_data(transformed_data):
                logger.error("Data load failed, stopping pipeline")
                return False
            
            execution_time = time.time() - start_time
            logger.info(f"ETL pipeline completed successfully in {execution_time:.2f} seconds")
            return True
            
        except Exception as e:
            logger.error(f"ETL pipeline failed: {e}")
            return False
    
    def get_pipeline_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the ThreatFox data in MongoDB collection
        
        Returns:
            Dict: Pipeline statistics
        """
        if self.collection is None:
            return {}
        
        try:
            total_records = self.collection.count_documents({})
            
            stats = {
                'total_threats': total_records,
                'high_severity_count': self.collection.count_documents({'threat_severity': 'HIGH'}),
                'medium_severity_count': self.collection.count_documents({'threat_severity': 'MEDIUM'}),
                'active_threats': self.collection.count_documents({'is_active_threat': True}),
                'recent_threats': self.collection.count_documents({'is_recent_threat': True}),
                'network_iocs': self.collection.count_documents({'ioc_category': 'NETWORK'}),
                'file_iocs': self.collection.count_documents({'ioc_category': 'FILE'}),
                'latest_ingestion': None,
                'avg_confidence_level': 0,
                'top_malware_families': []
            }
            
            # Only get additional stats if we have records
            if total_records > 0:
                # Get latest ingestion record
                latest_record = self.collection.find_one(
                    {}, sort=[('etl_metadata.ingestion_timestamp', -1)]
                )
                if latest_record:
                    stats['latest_ingestion'] = latest_record.get('etl_metadata', {}).get('ingestion_timestamp')
                
                # Get average confidence level
                avg_result = list(self.collection.aggregate([
                    {'$match': {'confidence_level': {'$gt': 0}}},
                    {'$group': {'_id': None, 'avg_confidence': {'$avg': '$confidence_level'}}}
                ]))
                if avg_result:
                    stats['avg_confidence_level'] = round(avg_result[0].get('avg_confidence', 0), 1)
                
                # Get top malware families
                top_malware = list(self.collection.aggregate([
                    {'$match': {'malware_family_clean': {'$ne': 'Unknown'}}},
                    {'$group': {'_id': '$malware_family_clean', 'count': {'$sum': 1}}},
                    {'$sort': {'count': -1}},
                    {'$limit': 5}
                ]))
                stats['top_malware_families'] = [
                    {'family': item['_id'], 'count': item['count']} 
                    for item in top_malware
                ]
            
            return stats
        except Exception as e:
            logger.error(f"Failed to get pipeline stats: {e}")
            return {}


def main():
    """Main function to run the ThreatFox ETL connector"""
    connector = ThreatFoxETLConnector()
    
    try:
        # Run the ETL pipeline
        success = connector.run_etl_pipeline()
        
        if success:
            logger.info("ETL process completed successfully")
            
            # Display stats (before closing connections)
            stats = connector.get_pipeline_stats()
            if stats:
                logger.info(f"Pipeline Statistics: {json.dumps(stats, indent=2, default=str)}")
            
            sys.exit(0)
        else:
            logger.error("ETL process failed")
            sys.exit(1)
    
    finally:
        # Cleanup connections after everything is done
        if connector.mongo_client:
            connector.mongo_client.close()
        if connector.session:
            connector.session.close()


if __name__ == "__main__":
    main()