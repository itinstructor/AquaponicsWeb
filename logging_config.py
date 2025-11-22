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

# Mountain time zone fallback
try:
    from zoneinfo import ZoneInfo
    MOUNTAIN_TZ = ZoneInfo("America/Denver")
except Exception:
    MOUNTAIN_TZ = timezone(timedelta(hours=-7))  # crude fallback


class MountainFormatter(logging.Formatter):
    """Custom formatter that displays timestamps in Mountain Time."""
    
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc).astimezone(MOUNTAIN_TZ)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


# Track if logging has been initialized to prevent duplicate setup
_logging_initialized = False
_current_log_files = set()


def setup_logging(log_filename="main_app.log", level=logging.INFO, force=False):
    """
    Configure application-wide logging with rotating file handler.
    Allows multiple calls to create additional file handlers for different filenames.
    
    Args:
        log_filename: Name of the log file (default: main_app.log)
        level: Logging level (default: INFO)
        force: Force re-initialization even if already setup
    
    Returns:
        Configured logger instance
    """
    global _logging_initialized, _current_log_files
    log_path = os.path.join(LOG_DIR, log_filename)

    # If already initialized and same filename requested and not forcing, return root logger
    if _logging_initialized and (log_filename in _current_log_files) and not force:
        return logging.getLogger()

    # Create rotating file handler for this filename
    handler = logging.handlers.TimedRotatingFileHandler(
        log_path, when="midnight", interval=1, backupCount=14, encoding="utf-8"
    )
    handler.suffix = "%Y-%m-%d.log"
    formatter = MountainFormatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)

    # If this is the first initialization, clear handlers and add console + file
    if not _logging_initialized or force:
        root.handlers.clear()
        root.addHandler(handler)
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        root.addHandler(console)
        _logging_initialized = True
        _current_log_files = {log_filename}
    else:
        # Already initialized with a different filename: just add a new file handler
        root.addHandler(handler)
        _current_log_files.add(log_filename)

    logging.info(f"Logging initialized/updated: {log_path}")
    return root


def get_logger(name):
    """
    Get a logger instance with the given name.
    Does not auto-initialize file handlers; caller should call setup_logging()
    with chosen filename early in startup (e.g. waitress_app.py or main_app.py).
    """
    if not _logging_initialized:
        setup_logging("main_app.log")
    return logging.getLogger(name)