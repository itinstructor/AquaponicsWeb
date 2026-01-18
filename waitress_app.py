"""
Filename: waitress_app.py
Description: This script sets up and runs a Waitress WSGI server
to serve a Flask web application.
"""

import os
import sys
import traceback

# Ensure working directory is correct
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Write a marker file to indicate the script started (for debugging IIS issues)
_marker_file = os.path.join(os.path.dirname(__file__), 'logs', '.startup_marker.txt')
try:
    with open(_marker_file, 'a') as f:
        from datetime import datetime
        f.write(f"[{datetime.now().isoformat()}] waitress_app.py started, PID={os.getpid()}, CWD={os.getcwd()}\n")
except Exception as write_err:
    pass

try:
    from logging_config import setup_logging, get_logger

    # Initialize logging first
    setup_logging("waitress_app.log")
    logger = get_logger(__name__)

    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, SCRIPT_DIR)

    try:
        import main_app
        app = getattr(main_app, "app", None)
        if app is None:
            raise RuntimeError("Flask app not found (expected main_app.app)")
    except Exception as e:
        logger.critical(f"Failed importing main_app: {e}\n{traceback.format_exc()}")
        raise

    logger.info("=== Waitress WSGI app initializing ===")

except Exception as startup_err:
    # If logging isn't initialized yet, write to marker file
    with open(_marker_file, 'a') as f:
        f.write(f"ERROR: {startup_err}\n{traceback.format_exc()}\n")
    raise


def main():
    from waitress import serve
    port = int(os.environ.get("HTTP_PLATFORM_PORT", 8080))
    logger.info(f"Starting Waitress on 127.0.0.1:{port}")
    try:
        serve(app, host="127.0.0.1", port=port, threads=32)
    except Exception as e:
        logger.critical(f"Waitress serve failed: {e}\n{traceback.format_exc()}")
        raise


# Always run main when this script is executed by HttpPlatformHandler or directly
if __name__ == "__main__":
    main()
else:
    # If imported as a module (shouldn't happen with HttpPlatformHandler), still run main
    main()


