"""
Centralized logging configuration for the Aquaponics Flask application.
Bridges Python's built-in logging module with Loguru for rotating log files.
"""

import os
import sys
import logging
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

# Rotate at 11:59 PM Mountain time (end of day) regardless of server timezone
# Note: Loguru's rotation expects time in format "HH:MM" as a string
MOUNTAIN_ROTATION_TIME = "23:59"


def mountain_time_formatter(record):
    """Convert timestamp to Mountain Time for log records."""
    dt = datetime.fromtimestamp(record["time"].timestamp(), tz=timezone.utc).astimezone(MOUNTAIN_TZ)
    record["extra"]["mst_time"] = dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    return "{extra[mst_time]} {level} [{name}] {message}\n"


class LoguruHandler(logging.Handler):
    """
    Bridge handler that sends Python logging messages to Loguru.
    This allows the built-in logging module to work with Loguru's rotating files.
    """
    def emit(self, record):
        # Get the logger function from loguru
        log_function = logger.opt(depth=1)
        
        # Map logging levels to loguru levels
        log_function.log(record.levelname, record.getMessage())


# Track if logging has been initialized
_logging_initialized = False
_current_log_files = set()


def setup_logging(log_filename="main_app.log", level="INFO", force=False):
    """
    Configure application-wide logging with rotating file handler.
    Sets up both Loguru and Python's built-in logging module.
    
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
        # Try to add stderr, but don't fail if stderr is not available (e.g., under IIS)
        try:
            logger.add(
                sys.stderr,
                format=mountain_time_formatter,
                level=level,
                colorize=True
            )
        except Exception as err:
            # If stderr fails (common under IIS), just skip it
            # File logging will handle it
            pass
        
        # Configure Python's built-in logging module to use Loguru
        # Remove all existing handlers from the root logger
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add Loguru bridge handler
        loguru_handler = LoguruHandler()
        root_logger.addHandler(loguru_handler)
        root_logger.setLevel(getattr(logging, level))
        
        _logging_initialized = True
        _current_log_files = set()

    # Add file handler if not already added for this filename
    if log_filename not in _current_log_files:
        logger.add(
            log_path,
            format=mountain_time_formatter,
            level=level,
            rotation=MOUNTAIN_ROTATION_TIME,  # Rotate at 11:59 PM (or at 12:00 AM next day)
            retention="14 days",        # Keep 14 days of logs
            encoding="utf-8",
            enqueue=False                # Disable async to ensure writes complete
        )
        _current_log_files.add(log_filename)

    # Log initialization message via loguru
    logger.info(f"Logging initialized/updated: {log_path}")
    
    # Also log via standard logging to test the bridge
    logging.getLogger("logging_config").info(f"Logging bridge active: {log_path}")
    
    return logger


def get_logger(name):
    """
    Get a logger instance for use with Python's built-in logging module.
    Maintains compatibility with existing code that uses logging.getLogger().
    
    Args:
        name: Logger name (typically __name__ or module name)
    
    Returns:
        Python logging.Logger instance configured to use Loguru
    """
    if not _logging_initialized:
        setup_logging("main_app.log")
    return logging.getLogger(name)


# Export the logger for direct imports
__all__ = ["logger", "setup_logging", "get_logger", "LOG_DIR"]