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

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # If this is the first initialization, clear handlers and add console + file
    if not _logging_initialized or force:
        root_logger.handlers.clear()
        root_logger.addHandler(handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        _logging_initialized = True
        _current_log_files = {log_filename}
    else:
        # Already initialized with a different filename: just add a new file handler
        root_logger.addHandler(handler)
        _current_log_files.add(log_filename)

    try:
        logging.info(f"Logging initialized/updated: {log_path}")
    except Exception:
        print(f"Logging initialized/updated: {log_path}")

    return root_logger


def get_logger(name):
    """
    Get a logger instance with the given name.
    Does not auto-initialize file handlers; caller should call setup_logging()
    with chosen filename early in startup (e.g. waitress_app.py or main_app.py).
    """
    if not _logging_initialized:
        # Fallback to console-only basic config so messages are visible even if setup_logging wasn't called.
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
        )
        # Small notice to stderr/console for operators
        print("Warning: Logging not fully initialized; using basic console logging.")
    return logging.getLogger(name)