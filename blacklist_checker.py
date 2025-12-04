import requests
import logging
import time
import os
from functools import lru_cache
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler

# Setup dedicated logger for blacklist checker
logger = logging.getLogger('blacklist_checker')
logger.setLevel(logging.INFO)

# Create logs directory if it doesn't exist
LOGS_DIR = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)

# Add timed rotating file handler - rotates daily, keeps 14 days
log_file = os.path.join(LOGS_DIR, 'blacklist_checker.log')
file_handler = TimedRotatingFileHandler(
    log_file,
    when='midnight',
    interval=1,
    backupCount=14,
    encoding='utf-8'
)
file_handler.setLevel(logging.INFO)

# Format: timestamp - level - message
formatter = logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s', 
                             datefmt='%Y-%m-%d %H:%M:%S %Z')
file_handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(file_handler)

# Also log to console for debugging
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)  # Only warnings/errors to console
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logger.info("Blacklist checker initialized")

class IPBlacklistChecker:
    """Check IPs against free threat intelligence feeds."""
    
    def __init__(self):
        self.cache = {}
        self.cache_duration = timedelta(hours=24)
        
        # Free blacklist sources
        self.sources = {
            'abuseipdb': self._check_abuseipdb,
            'stopforumspam': self._check_stopforumspam,
            'blocklist_de': self._check_blocklist_de,
        }
        
        logger.info(f"IPBlacklistChecker initialized with sources: {', '.join(self.sources.keys())}")
    
    @lru_cache(maxsize=10000)
    def is_blacklisted(self, ip_address):
        """
        Check if IP is blacklisted (with caching).
        Returns: (is_blacklisted: bool, source: str, confidence: int)
        """
        # Check cache first
        cache_key = ip_address
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if datetime.now() - cached_time < self.cache_duration:
                logger.debug(f"IP {ip_address} found in cache: {cached_data}")
                return cached_data
        
        logger.info(f"Checking IP {ip_address} against blacklists...")
        
        # Check against multiple sources
        for source_name, check_func in self.sources.items():
            try:
                is_blocked, confidence = check_func(ip_address)
                if is_blocked:
                    result = (True, source_name, confidence)
                    self.cache[cache_key] = (result, datetime.now())
                    logger.warning(f"IP {ip_address} BLACKLISTED by {source_name} (confidence: {confidence}%)")
                    return result
                else:
                    logger.debug(f"IP {ip_address} not found in {source_name}")
            except Exception as e:
                logger.error(f"Error checking {source_name} for {ip_address}: {e}")
                continue
        
        # Not blacklisted
        result = (False, None, 0)
        self.cache[cache_key] = (result, datetime.now())
        logger.info(f"IP {ip_address} is NOT blacklisted")
        return result
    
    def _check_abuseipdb(self, ip):
        """
        Check AbuseIPDB (requires free API key from https://www.abuseipdb.com/)
        Set ABUSEIPDB_API_KEY environment variable.
        """
        api_key = os.environ.get('ABUSEIPDB_API_KEY')
        if not api_key:
            logger.debug("AbuseIPDB: No API key configured, skipping")
            return False, 0
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        
        logger.debug(f"Checking AbuseIPDB for {ip}")
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
            logger.info(f"AbuseIPDB: {ip} has abuse score {abuse_score}%")
            # Block if abuse score > 75%
            return abuse_score > 75, abuse_score
        else:
            logger.warning(f"AbuseIPDB API error: {response.status_code}")
        
        return False, 0
    
    def _check_stopforumspam(self, ip):
        """
        Check StopForumSpam (free, no API key needed).
        https://www.stopforumspam.com/
        """
        url = f'https://api.stopforumspam.org/api?ip={ip}&json'
        
        logger.debug(f"Checking StopForumSpam for {ip}")
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('ip', {}).get('appears', 0) > 0:
                frequency = data.get('ip', {}).get('frequency', 0)
                confidence = min(100, frequency * 10)  # rough confidence score
                logger.info(f"StopForumSpam: {ip} appears {frequency} times (confidence: {confidence}%)")
                return True, confidence
        else:
            logger.warning(f"StopForumSpam API error: {response.status_code}")
        
        return False, 0
    
    def _check_blocklist_de(self, ip):
        """
        Check blocklist.de (free, checks if IP is in their dataset).
        https://www.blocklist.de/
        """
        url = f'https://api.blocklist.de/api.php?ip={ip}'
        
        logger.debug(f"Checking blocklist.de for {ip}")
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            # Returns "attacks: X" if IP is listed
            text = response.text.lower()
            if 'attacks:' in text and 'attacks: 0' not in text:
                logger.info(f"blocklist.de: {ip} found with attacks")
                return True, 80  # High confidence if listed
        else:
            logger.warning(f"blocklist.de API error: {response.status_code}")
        
        return False, 0
    
    def clear_cache(self):
        """Clear the cache."""
        cache_size = len(self.cache)
        self.cache.clear()
        self.is_blacklisted.cache_clear()
        logger.info(f"Cache cleared ({cache_size} entries removed)")

# Global instance
blacklist_checker = IPBlacklistChecker()