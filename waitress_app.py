"""
Filename: waitress_app.py
Description: This script sets up and runs a Waitress WSGI server
to serve a Flask web application.
"""

from main_app import app
import os
from sys import path
import logging
import logging.handlers
from datetime import datetime

# Add current directory to path to ensure imports work
path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Get the absolute path to this script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "waitress_app.log")

THREADS = 64

# Set up logging with Mountain Time formatting
try:
    from zoneinfo import ZoneInfo
    MOUNTAIN_TZ = ZoneInfo("America/Denver")
except ImportError:
    try:
        from backports.zoneinfo import ZoneInfo
        MOUNTAIN_TZ = ZoneInfo("America/Denver")
    except ImportError:
        from datetime import timezone, timedelta
        MOUNTAIN_TZ = timezone(timedelta(hours=-6))
        logging.warning("zoneinfo not available, using fixed UTC-6 offset")

class MountainFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, MOUNTAIN_TZ)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")

# Configure TimedRotatingFileHandler for waitress_app.log
waitress_handler = logging.handlers.TimedRotatingFileHandler(
    LOG_FILE,
    when="midnight",
    interval=1,
    backupCount=14,
    encoding="utf-8"
)
waitress_handler.suffix = "%Y-%m-%d.log"  # Rotated files: waitress_app.log.2025-10-12.log
waitress_handler.setFormatter(MountainFormatter("%(asctime)s %(levelname)s %(message)s"))

# Get the waitress_app logger
logger = logging.getLogger('waitress_app')
logger.setLevel(logging.INFO)
logger.handlers.clear()  # Remove any existing handlers
logger.addHandler(waitress_handler)
logger.propagate = False  # Don't propagate to root logger

# Also configure the waitress library logger
waitress_logger = logging.getLogger("waitress")
waitress_logger.setLevel(logging.INFO)
waitress_logger.handlers.clear()
waitress_logger.addHandler(waitress_handler)
waitress_logger.propagate = False

# Test logging
logger.info("=== Waitress app logging configured with daily rotation ===")
logger.info(f"Script directory: {SCRIPT_DIR}")
logger.info(f"Current working directory: {os.getcwd()}")
logger.info(f"Log file: {LOG_FILE}")
logger.info("Flask app imported successfully")


def main():
    port = int(os.environ.get("HTTP_PLATFORM_PORT", 8080))
    host = "127.0.0.1"

    logger.info(f"Starting Waitress server on {host}:{port}")

    try:
        from waitress import serve
        serve(
            app,
            host=host,
            port=port,
            threads=THREADS,
            connection_limit=1000,
        )
    except Exception as e:
        logger.error(f"Failed to start Waitress: {e}")
        exit(1)


if __name__ == "__main__":
    logger.info("Running as main script")
    main()
else:
    logger.info("Module imported by IIS")


