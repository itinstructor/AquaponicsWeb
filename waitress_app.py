"""
Filename: waitress_app.py
Description: This script sets up and runs a Waitress WSGI server
to serve a Flask web application.
"""

import os
import sys
import logging

# Add current directory to path to ensure imports work
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# Initialize logging FIRST - force initialization for IIS
from logging_config import setup_logging
import logging_config

# configure logging for the Waitress process first
setup_logging("waitress_app.log")

# Now import the Flask app (which may also call setup_logging to add its own file)
import main_app

# Expose the Flask WSGI application object for Waitress
app = getattr(main_app, "app", None)
if app is None:
    raise RuntimeError("Flask app not found in main_app (expected variable 'app')")

# IMMEDIATELY configure all waitress loggers to use our handlers
# This must happen before waitress is imported or used
waitress_loggers = [
    "waitress",
    "waitress.queue", 
    "waitress.channel",
    "waitress.task",
]

root_logger = logging.getLogger()
for logger_name in waitress_loggers:
    wl = logging.getLogger(logger_name)
    wl.setLevel(logging.INFO)
    wl.handlers.clear()
    wl.propagate = False  # Don't propagate to root to avoid duplicates
    # Add all root handlers to waitress loggers
    for handler in root_logger.handlers:
        wl.addHandler(handler)

logger = logging.getLogger(__name__)

logger.info("=== Waitress WSGI app initializing ===")
logger.info(f"Script directory: {SCRIPT_DIR}")
logger.info(f"Current working directory: {os.getcwd()}")
logger.info(f"Python version: {sys.version}")
logger.info(f"Python executable: {sys.executable}")

# safer: use logging_config.LOG_DIR if present, otherwise fall back to ./logs
log_dir = getattr(logging_config, "LOG_DIR", os.path.join(os.path.dirname(__file__), "logs"))
logger.info(f"All logging configured to: {os.path.join(log_dir, 'waitress_app.log')}")

THREADS = 64


def main():
    """Run Waitress server directly (for testing)."""
    port = int(os.environ.get("HTTP_PLATFORM_PORT", 8080))
    host = "127.0.0.1"

    logger.info(f"Starting Waitress server on {host}:{port} with {THREADS} threads")

    try:
        from waitress import serve
        
        logger.info("Waitress serve() called - all logging to waitress_app.log")
        
        serve(
            app,
            host=host,
            port=port,
            threads=THREADS,
            connection_limit=1000,
            channel_timeout=300,
        )
    except Exception as e:
        logger.exception(f"Failed to start Waitress: {e}")
        sys.exit(1)


if __name__ == "__main__":
    logger.info("Running as main script (direct execution)")
    main()
else:
    logger.info("Module imported by IIS/wfastcgi - app object ready")


