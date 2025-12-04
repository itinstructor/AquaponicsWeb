"""
Centralized logging configuration for the Aquaponics Flask application.
Uses Loguru for simplified, reliable logging with Mountain Time formatting.
"""

import os
import sys
from datetime import datetime, timezone, timedelta
from loguru import logger

# Determine log directory
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Mountain time zone
try:
    from zoneinfo import ZoneInfo
    MOUNTAIN_TZ = ZoneInfo("America/Denver")
except Exception:
    MOUNTAIN_TZ = timezone(timedelta(hours=-7))  # crude fallback


def mountain_time_formatter(record):
    """Convert timestamp to Mountain Time for log records."""
    dt = datetime.fromtimestamp(record["time"].timestamp(), tz=timezone.utc).astimezone(MOUNTAIN_TZ)
    record["extra"]["mst_time"] = dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    return "{extra[mst_time]} {level} [{name}] {message}\n"


# Track if logging has been initialized
_logging_initialized = False
_current_log_files = set()


def setup_logging(log_filename="main_app.log", level="INFO", force=False):
    """
    Configure application-wide logging with rotating file handler.
    
    Args:
        log_filename: Name of the log file (default: main_app.log)
        level: Logging level string (default: "INFO")
        force: Force re-initialization even if already setup
    
    Returns:
        Configured logger instance
    """
    global _logging_initialized, _current_log_files
    log_path = os.path.join(LOG_DIR, log_filename)

    # If already initialized with same filename and not forcing, return logger
    if _logging_initialized and (log_filename in _current_log_files) and not force:
        return logger

    # First time or forcing: remove default handler and set up fresh
    if not _logging_initialized or force:
        logger.remove()  # Remove default stderr handler
        
        # Add console handler with Mountain Time format
        logger.add(
            sys.stderr,
            format=mountain_time_formatter,
            level=level,
            colorize=True
        )
        _logging_initialized = True
        _current_log_files = set()

    # Add file handler if not already added for this filename
    if log_filename not in _current_log_files:
        logger.add(
            log_path,
            format=mountain_time_formatter,
            level=level,
            rotation="00:00",      # Rotate at midnight
            retention="14 days",   # Keep 14 days of logs
            encoding="utf-8",
            enqueue=True           # Thread-safe async writes
        )
        _current_log_files.add(log_filename)

    logger.info(f"Logging initialized/updated: {log_path}")
    return logger


def get_logger(name):
    """
    Get a logger instance bound with the given name.
    Maintains compatibility with existing code that uses get_logger().
    
    Args:
        name: Logger name (typically __name__ or module name)
    
    Returns:
        Logger instance bound with the name
    """
    if not _logging_initialized:
        setup_logging("main_app.log")
    return logger.bind(name=name)


# Export the logger for direct imports
__all__ = ["logger", "setup_logging", "get_logger", "LOG_DIR"]