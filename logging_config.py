"""
Centralized logging configuration for the Aquaponics Flask application.
Provides Mountain Time formatted rotating logs with consistent formatting.
"""

import os
import logging
import logging.handlers
from datetime import datetime, timezone, timedelta

# Determine log directory
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Try to import zoneinfo for proper timezone support
try:
    from zoneinfo import ZoneInfo
    MOUNTAIN_TZ = ZoneInfo("America/Denver")
except ImportError:
    try:
        from backports.zoneinfo import ZoneInfo
        MOUNTAIN_TZ = ZoneInfo("America/Denver")
    except ImportError:
        # Fallback to fixed offset if zoneinfo unavailable
        MOUNTAIN_TZ = timezone(timedelta(hours=-7))  # MST


class MountainFormatter(logging.Formatter):
    """Custom formatter that displays timestamps in Mountain Time."""
    
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, MOUNTAIN_TZ)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


# Track if logging has been initialized to prevent duplicate setup
_logging_initialized = False


def setup_logging(log_filename="main_app.log", level=logging.INFO, force=False):
    """
    Configure application-wide logging with rotating file handler.
    
    Args:
        log_filename: Name of the log file (default: main_app.log)
        level: Logging level (default: INFO)
        force: Force re-initialization even if already setup
    
    Returns:
        Configured logger instance
    """
    global _logging_initialized
    
    if _logging_initialized and not force:
        return logging.getLogger()
    
    log_path = os.path.join(LOG_DIR, log_filename)
    
    # Create rotating file handler (rotates at midnight, keeps 14 days)
    handler = logging.handlers.TimedRotatingFileHandler(
        log_path,
        when="midnight",
        interval=1,
        backupCount=14,
        encoding="utf-8"
    )
    handler.suffix = "%Y-%m-%d.log"
    
    # Set custom formatter
    formatter = MountainFormatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    
    # Also log to console in development
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    _logging_initialized = True
    
    # Use print as fallback since logging might not be ready yet
    try:
        logging.info(f"Logging initialized: {log_path}")
    except:
        print(f"Logging initialized: {log_path}")
    
    return root_logger


def get_logger(name):
    """
    Get a logger instance with the given name.
    Ensures logging is initialized before returning logger.
    
    Args:
        name: Logger name (typically __name__ of the module)
    
    Returns:
        Logger instance
    """
    if not _logging_initialized:
        setup_logging()
    return logging.getLogger(name)


# Auto-initialize with default settings when module is imported
# This ensures logging works even if setup_logging() isn't called explicitly
if not _logging_initialized:
    setup_logging()